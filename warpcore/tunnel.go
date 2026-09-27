package warpcore

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Tunnel tuning. The tunnel exists only long enough to carry one
// registration request, so every budget here is sized for that: sweep a
// sample of endpoints for a handshake, then POST /reg through whichever
// endpoint answered.
const (
	// tunnelStackAddress is the address of the in-process userspace
	// stack inside the tunnel (the classic WARP client address).
	tunnelStackAddress = "172.16.0.2"
	tunnelDNS          = "1.1.1.1"
	tunnelMTU          = 1280
	tunnelKeepalive    = 25

	// tunnelDiscoverySample is how many random WARP endpoint candidates
	// the sweep considers, tunnelDiscoveryBudget bounds the whole sweep
	// and tunnelConnectTimeout bounds one endpoint's handshake wait.
	tunnelDiscoverySample = 64
	tunnelDiscoveryBudget = 40 * time.Second
	tunnelConnectTimeout  = 1500 * time.Millisecond

	// tunnelRegisterTimeout bounds the registration requests once a
	// tunnel handshake succeeded.
	tunnelRegisterTimeout = 20 * time.Second
)

// tunnelPlaceholderKey is a widely shared placeholder identity used by
// public WARP tooling. Real WARP edges only answer handshake initiations
// from registered keys — a fresh random key is silently dropped (verified
// live against production edges) — and this key is recognized by them, so
// a device that does not own an account yet can still bring a tunnel up
// and register through it. Only the new account's public key travels
// inside that tunnel; no account secrets exist before it does.
const tunnelPlaceholderKey = "4OnO86dDLpqJ2U10ODwX3tarx6xlRGLfkmbSBtMgaHg="

// tunnelPorts are the primary UDP ports Cloudflare WARP edges listen on.
var tunnelPorts = []int{2408, 500, 1701, 4500}

// tunnelPeerKey is the peer the tunnel handshakes with: the well known
// WARP peer key in production, swapped by tests to aim at a local
// responder.
var tunnelPeerKey = warpPeerPublicKey

// tunnelDevice is an in-process WireGuard tunnel: wireguard-go over a
// userspace network stack (gVisor via wireguard-go's netstack). No root,
// no VpnService, no OS routing changes — packets stay inside the app and
// are dialed through the stack explicitly.
type tunnelDevice struct {
	dev     *device.Device
	tnet    *netstack.Net
	peerHex string
}

// openTunnel brings the tunnel up with a device key aimed at peerPubB64
// (the WARP peer key in production, a local responder's key in tests).
// The peer is dialed per endpoint attempt in connect, so nothing is
// routed yet.
func openTunnel(localAddr, privB64, peerPubB64 string) (*tunnelDevice, error) {
	local, err := netip.ParseAddr(localAddr)
	if err != nil {
		return nil, fmt.Errorf("tunnel local address: %w", err)
	}
	peerHex, err := keyToHex(peerPubB64)
	if err != nil {
		return nil, fmt.Errorf("tunnel peer key: %w", err)
	}
	tunDev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{local},
		[]netip.Addr{netip.MustParseAddr(tunnelDNS)},
		tunnelMTU,
	)
	if err != nil {
		return nil, fmt.Errorf("tunnel stack: %w", err)
	}
	privHex, err := keyToHex(privB64)
	if err != nil {
		return nil, fmt.Errorf("tunnel private key: %w", err)
	}
	// A silent logger: registration is a background chore and the app
	// has its own progress channel.
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet("private_key=" + privHex + "\n"); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel config: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel up: %w", err)
	}
	return &tunnelDevice{dev: dev, tnet: tnet, peerHex: peerHex}, nil
}

func (t *tunnelDevice) Close() { t.dev.Close() }

// connect points the peer at endpoint and waits until a real handshake
// completes. The handshake is the only reachability test that survives
// the kind of DPI that made the direct route fail.
func (t *tunnelDevice) connect(ctx context.Context, endpoint string, timeout time.Duration) bool {
	ipc := "replace_peers=true\n" +
		"public_key=" + t.peerHex + "\n" +
		"endpoint=" + endpoint + "\n" +
		"allowed_ip=0.0.0.0/0\n" +
		fmt.Sprintf("persistent_keepalive_interval=%d\n", tunnelKeepalive)
	if err := t.dev.IpcSet(ipc); err != nil {
		return false
	}
	return waitHandshake(ctx, t.dev, timeout)
}

const (
	handshakePollStart = 2 * time.Millisecond
	handshakePollMax   = 50 * time.Millisecond
	handshakeKey       = "last_handshake_time_sec="
)

// waitHandshake polls the device's stats until the peer's last handshake
// timestamp leaves zero. A live endpoint answers in one RTT, so the poll
// starts short and backs off — an already-finished handshake is noticed
// immediately while a dead endpoint keeps being asked cheaply until
// timeout.
func waitHandshake(ctx context.Context, dev *device.Device, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	wait := handshakePollStart
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		if conf, err := dev.IpcGet(); err == nil && handshakeDone(conf) {
			return true
		}
		time.Sleep(wait)
		if wait < handshakePollMax {
			wait *= 2
		}
	}
	return false
}

// handshakeDone reports whether any peer in the device stats has a
// non-zero last handshake time.
func handshakeDone(conf string) bool {
	for i := strings.Index(conf, handshakeKey); i >= 0; {
		v := i + len(handshakeKey)
		if v < len(conf) && conf[v] != '0' {
			return true
		}
		next := strings.Index(conf[v:], handshakeKey)
		if next < 0 {
			return false
		}
		i = v + next
	}
	return false
}

// keyToHex converts a base64 WireGuard key to the hex form the device's
// UAPI expects.
func keyToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key is %d bytes, want 32", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// sampleTunnelEndpoints picks n random host:port candidates from the
// public WARP ranges across the primary ports.
func sampleTunnelEndpoints(n int) ([]string, error) {
	targets, err := buildTargets(ScanConfig{Ranges: defaultRanges, Ports: tunnelPorts, Count: n})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.endpoint())
	}
	return out, nil
}

// tunnelClient returns an HTTP client whose dials go through the tunnel's
// userspace stack, pinned to a resolved IPv4 address of the API host (the
// stack carries v4 for this flow, and a host resolver outside the tunnel
// could answer with an address that only routes outside it). TLS still
// targets the URL's host, so the API sees its expected SNI.
func tunnelClient(ctx context.Context, tnet *netstack.Net, baseURL string, timeout time.Duration) (*http.Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("bad api url %q", baseURL)
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	host := u.Hostname()
	target := net.JoinHostPort(host, port)
	if net.ParseIP(host) == nil {
		ip, err := resolveAPIv4(ctx, host)
		if err != nil {
			return nil, err
		}
		target = net.JoinHostPort(ip, port)
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
				return tnet.DialContext(dialCtx, "tcp", target)
			},
		},
	}, nil
}

// resolveAPIv4 finds an IPv4 address for the API host, preferring
// DNS-over-HTTPS (resistant to a poisoned system resolver) and falling
// back to the system's answers.
func resolveAPIv4(ctx context.Context, host string) (string, error) {
	var candidates []net.IP
	seen := map[string]bool{}
	add := func(ips []net.IP) {
		for _, ip := range ips {
			v4 := ip.To4()
			if v4 == nil || seen[v4.String()] {
				continue
			}
			seen[v4.String()] = true
			candidates = append(candidates, v4)
		}
	}
	add(dohLookup(ctx, host))
	if len(candidates) == 0 {
		if addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host); err == nil {
			for _, a := range addrs {
				add([]net.IP{a.IP})
			}
		}
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("cannot resolve %s (no IPv4 answer)", host)
	}
	return candidates[0].String(), nil
}

// registerTunnelRoute is the fallback path for networks that block the
// WARP API: bring up an in-process WARP tunnel, sweep endpoint candidates
// until one completes a handshake, then register through that tunnel.
func registerTunnelRoute(ctx context.Context, opts RegisterOptions, events RegisterEvents) (*Account, error) {
	endpoints := opts.Targets
	if len(endpoints) == 0 {
		sampled, err := sampleTunnelEndpoints(tunnelDiscoverySample)
		if err != nil {
			return nil, fmt.Errorf("tunnel discovery: %w", err)
		}
		endpoints = sampled
	}

	dev, err := openTunnel(tunnelStackAddress, tunnelPlaceholderKey, tunnelPeerKey)
	if err != nil {
		return nil, err
	}
	defer dev.Close()

	emitStep(events, fmt.Sprintf("Sweeping %d WARP endpoints for a handshake…", len(endpoints)))
	sweepCtx, cancel := context.WithTimeout(ctx, tunnelDiscoveryBudget)
	defer cancel()

	var probed int
	var lastErr error
	for _, ep := range endpoints {
		if sweepCtx.Err() != nil {
			break
		}
		probed++
		if !dev.connect(sweepCtx, ep, tunnelConnectTimeout) {
			continue
		}
		emitStep(events, "Tunnel up — registering through WARP…")
		client, err := tunnelClient(ctx, dev.tnet, apiBase(opts), tunnelRegisterTimeout)
		if err != nil {
			return nil, err
		}
		regCtx, regCancel := context.WithTimeout(ctx, tunnelRegisterTimeout)
		acc, _, err := registerVia(regCtx, client, opts)
		regCancel()
		if err == nil {
			return acc, nil
		}
		// The handshake proved UDP reachability but registration still
		// failed — record it and keep sweeping; another edge may route
		// where this one did not.
		lastErr = fmt.Errorf("%s: %w", ep, err)
	}
	if probed == 0 {
		return nil, fmt.Errorf("tunnel discovery: %w", sweepCtx.Err())
	}
	if lastErr != nil {
		return nil, fmt.Errorf("tunnel reached an endpoint but registration failed (%d probed): %w", probed, lastErr)
	}
	return nil, fmt.Errorf("no WARP endpoint completed a handshake (%d probed)", probed)
}

