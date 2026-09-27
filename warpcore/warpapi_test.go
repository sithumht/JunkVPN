package warpcore

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegisterAccountAgainstMockAPI(t *testing.T) {
	var gotPath, gotUA, gotClientVer string
	var payload registrationPayload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotUA = r.Header.Get("User-Agent")
		gotClientVer = r.Header.Get("CF-Client-Version")
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("payload: %v", err)
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
	out, err := RegisterAccount(string(optsJSON))
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
	if _, err := RegisterAccount(string(optsJSON)); err == nil {
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
	out, err := RegisterAccount(string(optsJSON))
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
		_, err = RegisterAccount(string(optsJSON))
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
	_, err := RegisterAccount(`{"proxy":"socks5://127.0.0.1:9"}`)
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
