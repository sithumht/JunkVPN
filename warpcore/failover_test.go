package warpcore

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// startListener opens a loopback TCP listener and returns its port so a
// test can build candidate lists that share one port.
func startListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("addr: %v", err)
	}
	return port
}

// A refused first answer must not stop the dial when a later one works.
func TestFailoverDialerTriesNextAddress(t *testing.T) {
	port := startListener(t)
	d := &failoverDialer{
		lookupSystem: func(context.Context, string) []net.IP {
			// 127.0.0.2 has no listener on this port: instant refusal.
			return []net.IP{net.ParseIP("127.0.0.2"), net.ParseIP("127.0.0.1")}
		},
		lookupDoH: func(context.Context, string) []net.IP {
			t.Error("DoH must not be consulted when a system answer works")
			return nil
		},
	}
	conn, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort("example.test", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
}

// When the system resolver yields nothing (poisoned/empty), DoH answers
// are still dialed.
func TestFailoverDialerDoHFallback(t *testing.T) {
	port := startListener(t)
	asked := false
	d := &failoverDialer{
		lookupSystem: func(context.Context, string) []net.IP { return nil },
		lookupDoH: func(context.Context, string) []net.IP {
			asked = true
			return []net.IP{net.ParseIP("127.0.0.1")}
		},
	}
	conn, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort("example.test", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
	if !asked {
		t.Error("DoH fallback not used")
	}
}

// Every candidate refusing yields one aggregated, readable error.
func TestFailoverDialerAllAddressesFail(t *testing.T) {
	// Bind then close: this port very likely stays closed for the test.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()
	if err != nil {
		t.Fatalf("addr: %v", err)
	}

	d := &failoverDialer{
		lookupSystem: func(context.Context, string) []net.IP {
			return []net.IP{net.ParseIP("127.0.0.2")}
		},
		lookupDoH: func(context.Context, string) []net.IP {
			return []net.IP{net.ParseIP("127.0.0.3")}
		},
	}
	_, err = d.DialContext(context.Background(), "tcp", net.JoinHostPort("example.test", port))
	if err == nil {
		t.Fatal("dial unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "all addresses failed") {
		t.Errorf("error = %v, want aggregation", err)
	}
}

// Literal addresses skip resolution entirely (proxy hosts, IP URLs).
func TestFailoverDialerLiteralAddress(t *testing.T) {
	port := startListener(t)
	d := &failoverDialer{
		lookupSystem: func(context.Context, string) []net.IP {
			t.Error("literal address must not be resolved")
			return nil
		},
		lookupDoH: func(context.Context, string) []net.IP {
			t.Error("literal address must not be resolved")
			return nil
		},
	}
	conn, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
}

// DoH answers are parsed (A and AAAA), skipping unparsable data.
func TestDohLookupParsesAnswers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("name") != "api.example.test" {
			t.Errorf("name = %q", q.Get("name"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch q.Get("type") {
		case "A":
			_, _ = w.Write([]byte(`{"Status":0,"Answer":[
				{"type":1,"data":"203.0.113.7"},
				{"type":1,"data":"not-an-ip"}]}`))
		case "AAAA":
			_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"type":28,"data":"2001:db8::2"}]}`))
		default:
			t.Errorf("unexpected type %q", q.Get("type"))
		}
	}))
	defer srv.Close()

	orig := dohEndpoints
	dohEndpoints = []string{srv.URL}
	defer func() { dohEndpoints = orig }()

	ips := dohLookup(context.Background(), "api.example.test")
	want := map[string]bool{"203.0.113.7": false, "2001:db8::2": false}
	for _, ip := range ips {
		if _, ok := want[ip.String()]; ok {
			want[ip.String()] = true
			continue
		}
		t.Errorf("unexpected ip %v", ip)
	}
	for s, seen := range want {
		if !seen {
			t.Errorf("missing %s", s)
		}
	}
}

// A SERVFAIL/NXDOMAIN status yields no candidates instead of an error.
func TestDohLookupNegativeStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Status":3,"Answer":[]}`))
	}))
	defer srv.Close()

	orig := dohEndpoints
	dohEndpoints = []string{srv.URL}
	defer func() { dohEndpoints = orig }()

	if ips := dohLookup(context.Background(), "absent.example.test"); len(ips) != 0 {
		t.Errorf("ips = %v, want none", ips)
	}
}
