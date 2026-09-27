package warpcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// dohEndpoints are DNS-over-HTTPS resolvers consulted as a second opinion
// when the system resolver is blocked, empty or poisoned. Both are IP
// literals, so the lookup itself needs no working DNS.
var dohEndpoints = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/resolve",
}

const (
	// dohTimeout bounds the whole DoH phase (both query types, both
	// endpoints) so a censorship black hole cannot stall registration.
	dohTimeout = 4 * time.Second
	// dialAttemptTimeout bounds every candidate except the last, so one
	// blackholed address cannot exhaust the request's whole budget.
	dialAttemptTimeout = 5 * time.Second
)

// failoverDialer resolves a host through the system resolver and, when
// that fails or its answers refuse the connection, through
// DNS-over-HTTPS, then dials every candidate address in turn.
// Censored networks commonly poison or firewall a single address; this
// keeps the registration request working as long as any answer is
// reachable.
type failoverDialer struct {
	// Hooks replaced by tests; nil means the real implementation.
	lookupSystem func(ctx context.Context, host string) []net.IP
	lookupDoH    func(ctx context.Context, host string) []net.IP
	dialer       net.Dialer
}

// DialContext implements http.Transport.DialContext.
func (d *failoverDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// Literal addresses (including proxy hosts) need no resolution.
	if net.ParseIP(host) != nil {
		return d.dialer.DialContext(ctx, network, addr)
	}

	candidates := d.systemLookup(ctx, host)
	var collected []error
	if conn, err := d.tryAll(ctx, network, port, candidates); err == nil {
		return conn, nil
	} else if len(candidates) > 0 {
		collected = append(collected, err)
	}

	// The system's answers failed or there were none: ask DoH.
	doh := subtractIPs(d.dohLookup(ctx, host), candidates)
	if conn, err := d.tryAll(ctx, network, port, doh); err == nil {
		return conn, nil
	} else if len(doh) > 0 {
		collected = append(collected, err)
	}

	if len(collected) == 0 {
		return nil, fmt.Errorf("cannot resolve %s", host)
	}
	return nil, fmt.Errorf("all addresses failed: %w", errors.Join(collected...))
}

// tryAll dials each candidate in order and returns the first connection
// that succeeds.
func (d *failoverDialer) tryAll(ctx context.Context, network, port string, ips []net.IP) (net.Conn, error) {
	var errs []error
	for i, ip := range ips {
		attemptCtx := ctx
		var cancel context.CancelFunc
		if i < len(ips)-1 {
			attemptCtx, cancel = context.WithTimeout(ctx, dialAttemptTimeout)
		}
		conn, err := d.dialer.DialContext(attemptCtx, network, net.JoinHostPort(ip.String(), port))
		if cancel != nil {
			cancel()
		}
		if err == nil {
			return conn, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", ip, err))
	}
	if len(errs) == 0 {
		return nil, errors.New("no addresses to dial")
	}
	return nil, errors.Join(errs...)
}

func (d *failoverDialer) systemLookup(ctx context.Context, host string) []net.IP {
	if d.lookupSystem != nil {
		return d.lookupSystem(ctx, host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out
}

func (d *failoverDialer) dohLookup(ctx context.Context, host string) []net.IP {
	if d.lookupDoH != nil {
		return d.lookupDoH(ctx, host)
	}
	return dohLookup(ctx, host)
}

// subtractIPs filters out addresses already tried, preserving order.
func subtractIPs(addrs, tried []net.IP) []net.IP {
	seen := map[string]bool{}
	for _, ip := range tried {
		seen[ip.String()] = true
	}
	out := make([]net.IP, 0, len(addrs))
	for _, ip := range addrs {
		s := ip.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, ip)
		}
	}
	return out
}

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// dohLookup fetches A and AAAA records over DNS-over-HTTPS from the first
// endpoint that answers. Any failure returns nil — the system resolver's
// answers are tried first, so DoH is a fallback, never a requirement.
func dohLookup(ctx context.Context, host string) []net.IP {
	ctx, cancel := context.WithTimeout(ctx, dohTimeout)
	defer cancel()
	// Plain client: the endpoints are IP literals and must not recurse
	// through the failover dialer.
	client := &http.Client{Timeout: dohTimeout}
	for _, endpoint := range dohEndpoints {
		var out []net.IP
		for _, qtype := range []string{"A", "AAAA"} {
			out = append(out, dohQuery(ctx, client, endpoint, host, qtype)...)
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

func dohQuery(ctx context.Context, client *http.Client, endpoint, host, qtype string) []net.IP {
	u := endpoint + "?name=" + url.QueryEscape(host) + "&type=" + qtype
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil
	}
	var parsed dohResponse
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed.Status != 0 {
		return nil
	}
	want := 1 // A
	if qtype == "AAAA" {
		want = 28
	}
	var out []net.IP
	for _, a := range parsed.Answer {
		if a.Type != want {
			continue
		}
		if ip := net.ParseIP(a.Data); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}
