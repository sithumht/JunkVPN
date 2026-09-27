package warpcore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// startNetResponder boots a wireguard-go device backed by a userspace
// netstack TUN with its own tunnel address, and returns the device's UDP
// endpoint plus the stack. That gives tests an all-userspace WireGuard
// link: the client tunnel under test can dial real HTTP endpoints running
// inside the responder's stack, with no OS routing involved anywhere.
//
// Peer keys in peerPubsHex are hex, matching the device's UAPI.
func startNetResponder(t *testing.T, serverPrivHex, serverLocal, clientAddr string, peerPubsHex ...string) (string, *netstack.Net, func()) {
	t.Helper()

	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	_, portStr, err := net.SplitHostPort(probe.LocalAddr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	_ = probe.Close()

	tunDev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(serverLocal)},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		1420,
	)
	if err != nil {
		t.Fatalf("server stack: %v", err)
	}

	cfg := "private_key=" + serverPrivHex + "\nlisten_port=" + portStr + "\n"
	for _, pub := range peerPubsHex {
		cfg += "public_key=" + pub + "\nallowed_ip=" + clientAddr + "/32\n"
	}

	logger := device.NewLogger(device.LogLevelSilent, "wg-net: ")
	dev := device.NewDevice(tunDev, conn.NewStdNetBind(), logger)
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		t.Fatalf("server ipcset: %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		t.Fatalf("server up: %v", err)
	}
	addr := net.JoinHostPort("127.0.0.1", portStr)
	return addr, tnet, func() { dev.Close() }
}

// serveMockAPI runs the registration endpoints inside a responder stack
// and records whether POST /reg and the warp_enabled PATCH arrived.
func serveMockAPI(t *testing.T, tnet *netstack.Net, listen string, posts, patches *int32) func() {
	t.Helper()
	ln, err := tnet.ListenTCPAddrPort(netip.MustParseAddrPort(listen))
	if err != nil {
		t.Fatalf("listen in stack: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/reg"):
			atomic.AddInt32(posts, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(cannedRegResponse))
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/reg/"):
			atomic.AddInt32(patches, 1)
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"warp_enabled":true`) {
				t.Errorf("PATCH body = %s, want warp_enabled", body)
			}
			if auth := r.Header.Get("Authorization"); auth != "Bearer tok-proxy" {
				t.Errorf("PATCH auth = %q", auth)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ln)
	}()
	return func() {
		_ = srv.Close()
		<-done
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	return string(out)
}

// setupNetPair creates a netstack-backed responder (with its UDP
// endpoint) that accepts the tunnel placeholder key, and returns the
// server identity the client tunnel must aim at.
func setupNetPair(t *testing.T) (*wgIdentity, string, *netstack.Net, func()) {
	t.Helper()
	server, err := newIdentity()
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	placeholder, err := identityFromPrivate(tunnelPlaceholderKey)
	if err != nil {
		t.Fatalf("placeholder key: %v", err)
	}
	endpoint, tnet, stop := startNetResponder(t,
		hex.EncodeToString(server.priv.Bytes()),
		"10.7.0.1", tunnelStackAddress,
		hex.EncodeToString(placeholder.pub))
	// registerTunnelRoute handshakes with tunnelPeerKey; aim it at this
	// responder for the duration of the test.
	oldPeer := tunnelPeerKey
	tunnelPeerKey = base64Of(server.pub)
	return server, endpoint, tnet, func() {
		tunnelPeerKey = oldPeer
		stop()
	}
}

// The tunnel completes a real handshake against a local wireguard-go
// responder that knows the tunnel's identity — and stays silent for a
// key the responder never registered.
func TestTunnelHandshakeAgainstLocalResponder(t *testing.T) {
	server, err := newIdentity()
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	client, err := newIdentity()
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	addr, stop := startLocalResponder(t,
		hex.EncodeToString(server.priv.Bytes()),
		hex.EncodeToString(client.pub))
	defer stop()

	tun, err := openTunnel(tunnelStackAddress, base64Of(client.priv.Bytes()), base64Of(server.pub))
	if err != nil {
		t.Fatalf("openTunnel: %v", err)
	}
	defer tun.Close()
	if !tun.connect(context.Background(), addr, 3*time.Second) {
		t.Fatal("registered identity did not complete a handshake")
	}

	// A device the responder never heard of must get silence.
	server2, err := newIdentity()
	if err != nil {
		t.Fatalf("server2: %v", err)
	}
	known, err := newIdentity()
	if err != nil {
		t.Fatalf("known: %v", err)
	}
	alien, err := newIdentity()
	if err != nil {
		t.Fatalf("alien: %v", err)
	}
	addr2, stop2 := startLocalResponder(t,
		hex.EncodeToString(server2.priv.Bytes()),
		hex.EncodeToString(known.pub))
	defer stop2()

	tun2, err := openTunnel(tunnelStackAddress, base64Of(alien.priv.Bytes()), base64Of(server2.pub))
	if err != nil {
		t.Fatalf("openTunnel 2: %v", err)
	}
	defer tun2.Close()
	if tun2.connect(context.Background(), addr2, 500*time.Millisecond) {
		t.Fatal("responder answered an unregistered tunnel key")
	}
}

// The tunnel's userspace stack carries real TCP: an HTTP request travels
// client-stack -> WireGuard -> responder-stack and back.
func TestTunnelCarriesHTTP(t *testing.T) {
	server, addr, tnet, stop := setupNetPair(t)
	defer stop()

	ln, err := tnet.ListenTCPAddrPort(netip.MustParseAddrPort("10.7.0.1:8080"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("through-the-tunnel"))
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	tun, err := openTunnel(tunnelStackAddress, tunnelPlaceholderKey, base64Of(server.pub))
	if err != nil {
		t.Fatalf("openTunnel: %v", err)
	}
	defer tun.Close()
	if !tun.connect(context.Background(), addr, 3*time.Second) {
		t.Fatal("handshake with the netstack responder failed")
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return tun.tnet.DialContext(ctx, "tcp", "10.7.0.1:8080")
			},
		},
	}
	resp, err := client.Get("http://10.7.0.1:8080/")
	if err != nil {
		t.Fatalf("GET through tunnel: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "through-the-tunnel" {
		t.Errorf("body = %q", body)
	}
}

// The full feature path: route=tunnel registration whose POST and
// warp_enabled PATCH both travel through the WireGuard tunnel to a mock
// API running inside the responder's stack.
func TestRegisterViaTunnelE2E(t *testing.T) {
	_, addr, tnet, stop := setupNetPair(t)
	defer stop()

	var posts, patches int32
	stopAPI := serveMockAPI(t, tnet, "10.7.0.1:8080", &posts, &patches)
	defer stopAPI()

	steps := &stepRecorder{}
	optsJSON := mustJSON(t, RegisterOptions{
		BaseURL: "http://10.7.0.1:8080",
		Route:   "tunnel",
		Targets: []string{addr},
	})
	out, err := RegisterAccount(optsJSON, steps)
	if err != nil {
		t.Fatalf("register via tunnel: %v\nsteps:\n%s", err, steps.all())
	}
	if atomic.LoadInt32(&posts) != 1 {
		t.Errorf("POSTs through tunnel = %d, want 1", posts)
	}
	if atomic.LoadInt32(&patches) != 1 {
		t.Errorf("PATCHes through tunnel = %d, want 1", patches)
	}
	var acc Account
	if err := json.Unmarshal([]byte(out), &acc); err != nil || acc.DeviceID == "" {
		t.Errorf("account = %q (%v)", out, err)
	}
	if !strings.Contains(steps.all(), "Tunnel up") {
		t.Errorf("steps = %q, want tunnel-up progress", steps.all())
	}
}

// The auto chain end to end: the direct attempt cannot reach the mock API
// (it only exists inside the tunnel), so registration falls back to the
// tunnel and succeeds there. The fallback step in the event stream proves
// the direct route ran first and failed.
func TestRegisterAutoFallsBackToTunnel(t *testing.T) {
	old := directRegisterTimeout
	directRegisterTimeout = 1500 * time.Millisecond
	defer func() { directRegisterTimeout = old }()

	_, addr, tnet, stop := setupNetPair(t)
	defer stop()

	var posts, patches int32
	stopAPI := serveMockAPI(t, tnet, "10.7.0.1:8080", &posts, &patches)
	defer stopAPI()

	steps := &stepRecorder{}
	// Same base URL for both routes: reachable only from inside the
	// tunnel, unreachable from the host — exactly the censored-network
	// shape.
	optsJSON := mustJSON(t, RegisterOptions{
		BaseURL: "http://10.7.0.1:8080",
		Route:   "auto",
		Targets: []string{addr},
	})
	out, err := RegisterAccount(optsJSON, steps)
	if err != nil {
		t.Fatalf("auto fallback: %v\nsteps:\n%s", err, steps.all())
	}
	if !strings.Contains(steps.all(), "Direct route blocked") {
		t.Errorf("steps = %q, want the direct-blocked fallback step", steps.all())
	}
	if atomic.LoadInt32(&posts) != 1 || atomic.LoadInt32(&patches) != 1 {
		t.Errorf("posts=%d patches=%d, want 1 each", posts, patches)
	}
	var acc Account
	if err := json.Unmarshal([]byte(out), &acc); err != nil || acc.DeviceID == "" {
		t.Errorf("account = %q (%v)", out, err)
	}
}

// The discovery sample spans the public WARP ranges and primary ports.
func TestSampleTunnelEndpoints(t *testing.T) {
	endpoints, err := sampleTunnelEndpoints(tunnelDiscoverySample)
	if err != nil {
		t.Fatalf("sample: %v", err)
	}
	if len(endpoints) != tunnelDiscoverySample {
		t.Fatalf("got %d endpoints, want %d", len(endpoints), tunnelDiscoverySample)
	}
	portSet := map[int]bool{}
	for _, p := range tunnelPorts {
		portSet[p] = true
	}
	seen := map[string]bool{}
	for _, ep := range endpoints {
		if seen[ep] {
			t.Errorf("duplicate endpoint %s", ep)
		}
		seen[ep] = true
		host, portStr, err := net.SplitHostPort(ep)
		if err != nil {
			t.Fatalf("bad endpoint %q: %v", ep, err)
		}
		if !portSet[mustAtoi(t, portStr)] {
			t.Errorf("endpoint %s uses a non-WARP port", ep)
		}
		if !ipInDefaultRanges(t, host) {
			t.Errorf("endpoint %s is outside the WARP ranges", ep)
		}
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("not a port: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func ipInDefaultRanges(t *testing.T, host string) bool {
	t.Helper()
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range defaultRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("bad default range %q: %v", cidr, err)
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// handshakeDone parses the device stats the way waitHandshake reads them.
func TestHandshakeDoneParsing(t *testing.T) {
	cases := map[string]bool{
		"private_key=abcd\nlast_handshake_time_sec=0\n":   false,
		"last_handshake_time_sec=1758995432\n":            true,
		"public_key=aa\nlast_handshake_time_sec=0\nlast_handshake_time_sec=9\n": true,
		"no handshake keys here":                          false,
		"last_handshake_time_sec=":                        false,
	}
	for conf, want := range cases {
		if got := handshakeDone(conf); got != want {
			t.Errorf("handshakeDone(%q) = %v, want %v", conf, got, want)
		}
	}
}
