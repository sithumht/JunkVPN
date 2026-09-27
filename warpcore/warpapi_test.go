package warpcore

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegisterAccountAgainstMockAPI(t *testing.T) {
	var gotPath, gotUA, gotClientVer string
	var payload registrationPayload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// Record the POST; the follow-up warp_enabled PATCH hits
			// the same server with a different path and body.
			gotPath = r.URL.Path
			gotUA = r.Header.Get("User-Agent")
			gotClientVer = r.Header.Get("CF-Client-Version")
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Errorf("payload: %v", err)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "device-abc",
			"token": "tok-abc",
			"account": {"license": "lic-123"},
			"config": {
				"interface": {"addresses": {"v4": "172.16.0.2/32", "v6": "2606:4700:110::2/128"}},
				"peers": [{"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
					"endpoint": {"v4": "162.159.192.1:0", "host": "engage.cloudflareclient.com:2408"}}]
			}
		}`))
	}))
	defer srv.Close()

	optsJSON, err := json.Marshal(RegisterOptions{
		BaseURL:   srv.URL,
		APIVer:    "v0a4471",
		Model:     "PixelTest",
		Locale:    "en_GB",
		OSVersion: "36",
	})
	if err != nil {
		t.Fatalf("opts: %v", err)
	}
	out, err := RegisterAccount(string(optsJSON), nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if gotPath != "/v0a4471/reg" {
		t.Errorf("path = %q", gotPath)
	}
	if gotUA != defaultUserAgent || gotClientVer != defaultClientVer {
		t.Errorf("headers ua=%q cf=%q", gotUA, gotClientVer)
	}
	if payload.KeyType != "curve25519" || payload.TunnelType != "wireguard" {
		t.Errorf("key/tunnel type = %q/%q", payload.KeyType, payload.TunnelType)
	}
	if payload.Model != "PixelTest" || payload.Locale != "en_GB" || payload.OSVersion != "36" {
		t.Errorf("payload meta = %+v", payload)
	}
	if payload.TOS == "" {
		t.Error("tos timestamp missing")
	}
	if len(payload.Key) == 0 {
		t.Error("public key missing")
	}

	var acc Account
	if err := json.Unmarshal([]byte(out), &acc); err != nil {
		t.Fatalf("account json: %v", err)
	}
	if acc.DeviceID != "device-abc" || acc.Token != "tok-abc" || acc.License != "lic-123" {
		t.Errorf("account = %+v", acc)
	}
	if acc.AddressV4 != "172.16.0.2/32" || acc.AddressV6 != "2606:4700:110::2/128" {
		t.Errorf("addresses = %q/%q", acc.AddressV4, acc.AddressV6)
	}
	if acc.PeerPublicKey != warpPeerPublicKey {
		t.Errorf("peer = %q", acc.PeerPublicKey)
	}
	if acc.PeerEndpoint != "162.159.192.1" {
		t.Errorf("peer endpoint = %q, want placeholder port stripped", acc.PeerEndpoint)
	}
	// The private key must round-trip into a valid identity.
	if _, err := identityFromPrivate(acc.PrivateKey); err != nil {
		t.Errorf("private key unusable: %v", err)
	}
	// The registered public key must be derivable from it.
	id, _ := identityFromPrivate(acc.PrivateKey)
	if base64Of(id.pub) != payload.Key {
		t.Errorf("registered key mismatch")
	}
}

func TestRegisterAccountHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusTooManyRequests)
	}))
	defer srv.Close()

	optsJSON, _ := json.Marshal(RegisterOptions{BaseURL: srv.URL})
	if _, err := RegisterAccount(string(optsJSON), nil); err == nil {
		t.Fatal("HTTP error not surfaced")
	}
}

func TestStripPlaceholderPort(t *testing.T) {
	cases := map[string]string{
		"162.159.192.1:0":               "162.159.192.1",
		"162.159.192.1:2408":            "162.159.192.1:2408",
		"engage.cloudflareclient.com:0": "engage.cloudflareclient.com",
		"garbage":                       "garbage",
	}
	for in, want := range cases {
		if got := stripPlaceholderPort(in); got != want {
			t.Errorf("stripPlaceholderPort(%q) = %q, want %q", in, got, want)
		}
	}
}

const cannedRegResponse = `{
	"id": "device-proxy",
	"token": "tok-proxy",
	"account": {"license": "lic-proxy"},
	"config": {
		"interface": {"addresses": {"v4": "172.16.0.9/32", "v6": "2606:4700:110::9/128"}},
		"peers": [{"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
			"endpoint": {"v4": "162.159.192.1:0"}}]
	}
}`

// forwardProxy is a minimal HTTP forward proxy (absolute-form requests,
// as http.Transport sends for http:// targets when a proxy is set) that
// records whether it carried a request.
func forwardProxy(t *testing.T, used *atomic.Bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		used.Store(true)
		if r.Method == http.MethodConnect {
			http.Error(w, "CONNECT not expected in this test", http.StatusMethodNotAllowed)
			return
		}
		// r.URL is absolute for proxied plain-http requests: forward it.
		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		outReq.Header = r.Header.Clone()
		for _, h := range []string{"Proxy-Connection", "Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
			outReq.Header.Del(h)
		}
		resp, err := http.DefaultClient.Do(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
}

// The registration request must be routed through the configured proxy.
func TestRegisterAccountThroughProxy(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(cannedRegResponse))
	}))
	defer api.Close()

	var used atomic.Bool
	proxy := forwardProxy(t, &used)
	defer proxy.Close()

	optsJSON, err := json.Marshal(RegisterOptions{BaseURL: api.URL, Proxy: proxy.URL})
	if err != nil {
		t.Fatalf("opts: %v", err)
	}
	out, err := RegisterAccount(string(optsJSON), nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !used.Load() {
		t.Fatal("registration bypassed the configured proxy")
	}
	var acc Account
	if err := json.Unmarshal([]byte(out), &acc); err != nil {
		t.Fatalf("account json: %v", err)
	}
	if acc.DeviceID != "device-proxy" || acc.AddressV4 != "172.16.0.9/32" {
		t.Errorf("account = %+v", acc)
	}
}

// Malformed or unsupported proxy settings fail fast with a clear error,
// before any network attempt.
func TestRegisterAccountRejectsBadProxy(t *testing.T) {
	for _, bad := range []string{"://", "not a url", "ftp://host:1080"} {
		optsJSON, err := json.Marshal(RegisterOptions{Proxy: bad})
		if err != nil {
			t.Fatalf("opts: %v", err)
		}
		_, err = RegisterAccount(string(optsJSON), nil)
		if err == nil {
			t.Errorf("proxy %q: error not surfaced", bad)
			continue
		}
		if !strings.Contains(err.Error(), "proxy") {
			t.Errorf("proxy %q: error = %v, want proxy-related message", bad, err)
		}
	}
}

// A syntactically valid proxy whose endpoint refuses connections must
// fail fast (not hang or fall back to a direct connection) with an
// error naming the proxy address.
func TestRegisterAccountRefusedProxyFailsFast(t *testing.T) {
	start := time.Now()
	_, err := RegisterAccount(`{"proxy":"socks5://127.0.0.1:9"}`, nil)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:9") {
		t.Errorf("error = %v, want proxy address", err)
	}
	if elapsed > 10*time.Second {
		t.Errorf("took %v, want fast failure", elapsed)
	}
}

// --- registration route chain + warp_enabled PATCH ---

// stepRecorder captures RegisterEvents progress for assertions.
type stepRecorder struct {
	mu    sync.Mutex
	steps []string
}

func (r *stepRecorder) OnStep(step string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, step)
}

func (r *stepRecorder) all() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.steps, "\n")
}

// Registration must finish with PATCH /reg/{id} {"warp_enabled": true},
// authorized by the token the POST just issued � without it the account
// handshakes but never passes traffic.
func TestRegisterAccountEnablesWARP(t *testing.T) {
	var patchPath, patchAuth string
	var patchBody map[string]bool
	var patches int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			patches++
			patchPath = r.URL.Path
			patchAuth = r.Header.Get("Authorization")
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &patchBody)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(cannedRegResponse))
	}))
	defer srv.Close()

	optsJSON, _ := json.Marshal(RegisterOptions{BaseURL: srv.URL})
	out, err := RegisterAccount(string(optsJSON), nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if patches != 1 {
		t.Fatalf("PATCH count = %d, want 1", patches)
	}
	if want := "/v0a4471/reg/device-proxy"; patchPath != want {
		t.Errorf("patch path = %q, want %q", patchPath, want)
	}
	if want := "Bearer tok-proxy"; patchAuth != want {
		t.Errorf("patch auth = %q, want %q", patchAuth, want)
	}
	if !patchBody["warp_enabled"] {
		t.Errorf("patch body = %v, want warp_enabled=true", patchBody)
	}
	var acc Account
	if err := json.Unmarshal([]byte(out), &acc); err != nil || acc.DeviceID == "" {
		t.Errorf("account = %q (%v)", out, err)
	}
}

// A failed warp_enabled PATCH fails the whole registration instead of
// returning a half-enabled account.
func TestRegisterAccountPatchFailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			http.Error(w, `{"message":"nope"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(cannedRegResponse))
	}))
	defer srv.Close()

	optsJSON, _ := json.Marshal(RegisterOptions{BaseURL: srv.URL})
	_, err := RegisterAccount(string(optsJSON), nil)
	if err == nil {
		t.Fatal("PATCH failure not surfaced")
	}
	if !strings.Contains(err.Error(), "enable WARP") || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error = %v, want enable WARP HTTP 500", err)
	}
}

// route=tunnel must never touch the direct endpoint.
func TestRegisterRouteTunnelSkipsDirect(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	steps := &stepRecorder{}
	optsJSON, _ := json.Marshal(RegisterOptions{
		BaseURL: srv.URL,
		Route:   "tunnel",
		Targets: []string{"127.0.0.1:1"},
	})
	_, err := RegisterAccount(string(optsJSON), steps)
	if err == nil {
		t.Fatal("expected the tunnel sweep to fail against a dead target")
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("direct endpoint hit %d times, want 0", n)
	}
	if !strings.Contains(err.Error(), "handshake") {
		t.Errorf("error = %v, want handshake failure", err)
	}
	if !strings.Contains(steps.all(), "Sweeping") {
		t.Errorf("steps = %q, want sweep progress", steps.all())
	}
}

// In the auto route, a real HTTP answer from the API (even an error)
// proves the endpoint is reachable � the tunnel must not run.
func TestRegisterAutoStopsAtAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	steps := &stepRecorder{}
	optsJSON, _ := json.Marshal(RegisterOptions{
		BaseURL: srv.URL,
		Route:   "auto",
		Targets: []string{"127.0.0.1:1"},
	})
	_, err := RegisterAccount(string(optsJSON), steps)
	if err == nil {
		t.Fatal("expected the HTTP error to surface")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error = %v, want HTTP 500", err)
	}
	if strings.Contains(steps.all(), "Direct route blocked") {
		t.Errorf("tunnel fallback ran despite a reachable API: %q", steps.all())
	}
}

// When the direct route fails at the transport level and the tunnel also
// fails, the error reports both phases.
func TestRegisterAutoReportsBothRouteFailures(t *testing.T) {
	// Bound the direct attempt: 10.7.0.1 is a test-only address that is
	// never routed on the host, but some networks black-hole it instead
	// of refusing fast.
	old := directRegisterTimeout
	directRegisterTimeout = 2 * time.Second
	defer func() { directRegisterTimeout = old }()

	optsJSON, _ := json.Marshal(RegisterOptions{
		BaseURL: "http://10.7.0.1:9",
		Route:   "auto",
		Targets: []string{"127.0.0.1:1"},
	})
	steps := &stepRecorder{}
	_, err := RegisterAccount(string(optsJSON), steps)
	if err == nil {
		t.Fatal("expected both routes to fail")
	}
	msg := err.Error()
	if !strings.Contains(msg, "registration request") {
		t.Errorf("error = %v, want the direct failure included", msg)
	}
	if !strings.Contains(msg, "via WARP tunnel") {
		t.Errorf("error = %v, want the tunnel failure included", msg)
	}
	if !strings.Contains(steps.all(), "Direct route blocked") {
		t.Errorf("steps = %q, want the fallback step", steps.all())
	}
}

// An unknown route is a configuration mistake, reported before any
// network attempt.
func TestRegisterUnknownRouteRejected(t *testing.T) {
	start := time.Now()
	_, err := RegisterAccount(`{"route":"carrier-pigeon"}`, nil)
	if err == nil || !strings.Contains(err.Error(), "route") {
		t.Fatalf("err = %v, want route error", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v, want immediate rejection", elapsed)
	}
}
