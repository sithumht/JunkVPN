package warpcore

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
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
