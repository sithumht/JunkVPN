package warpcore

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func sampleAccount(t *testing.T) Account {
	t.Helper()
	id, err := newIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return Account{
		PrivateKey:    base64.StdEncoding.EncodeToString(id.priv.Bytes()),
		DeviceID:      "device-1",
		Token:         "token-1",
		AddressV4:     "172.16.0.2/32",
		AddressV6:     "2606:4700:110:8f81::1/128",
		PeerPublicKey: warpPeerPublicKey,
		PeerEndpoint:  "engage.cloudflareclient.com:2408",
	}
}

func toJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestBuildWireGuardConfig(t *testing.T) {
	acc := sampleAccount(t)
	out, err := BuildConfig("wireguard", toJSON(t, acc), toJSON(t, ConfigOptions{Endpoint: "162.159.192.1:2408"}))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, want := range []string{
		"[Interface]",
		"PrivateKey = " + acc.PrivateKey,
		"Address = 172.16.0.2/32, 2606:4700:110:8f81::1/128",
		"DNS = 1.1.1.1, 2606:4700:4700::1111",
		"MTU = 1280",
		"[Peer]",
		"PublicKey = " + warpPeerPublicKey,
		"AllowedIPs = 0.0.0.0/0, ::/0",
		"Endpoint = 162.159.192.1:2408",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Jc =") {
		t.Error("wireguard config must not contain amnezia junk params")
	}
}

func TestBuildAmneziaConfig(t *testing.T) {
	acc := sampleAccount(t)
	out, err := BuildConfig("amnezia", toJSON(t, acc), toJSON(t, ConfigOptions{
		Endpoint: "188.114.96.1:2408",
		Jc:       8, Jmin: 60, Jmax: 90, S1: 1, S2: 2,
	}))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, want := range []string{"Jc = 8", "Jmin = 60", "Jmax = 90", "S1 = 1", "S2 = 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestBuildConfigErrors(t *testing.T) {
	acc := sampleAccount(t)
	if _, err := BuildConfig("wireguard", "not json", "{}"); err == nil {
		t.Fatal("bad account accepted")
	}
	if _, err := BuildConfig("bogus", toJSON(t, acc), toJSON(t, ConfigOptions{Endpoint: "1.2.3.4:2408"})); err == nil {
		t.Fatal("unknown kind accepted")
	}
	empty := Account{PrivateKey: "x"}
	if _, err := BuildConfig("wireguard", toJSON(t, empty), "{}"); err == nil {
		t.Fatal("account without peer key accepted")
	}
	// No endpoint given: falls back to the registration endpoint.
	acc.PeerEndpoint = "engage.cloudflareclient.com:2408"
	out, err := BuildConfig("wireguard", toJSON(t, acc), "")
	if err != nil {
		t.Fatalf("fallback: %v", err)
	}
	if !strings.Contains(out, "Endpoint = engage.cloudflareclient.com:2408") {
		t.Fatalf("fallback endpoint missing:\n%s", out)
	}
	// Bare IP fallback gets the standard WireGuard port.
	acc.PeerEndpoint = "162.159.192.1"
	out, err = BuildConfig("wireguard", toJSON(t, acc), "")
	if err != nil {
		t.Fatalf("ip fallback: %v", err)
	}
	if !strings.Contains(out, "Endpoint = 162.159.192.1:2408") {
		t.Fatalf("port not attached:\n%s", out)
	}
	// Endpoint-only export.
	only, err := BuildConfig("endpoint", toJSON(t, acc), toJSON(t, ConfigOptions{Endpoint: "9.9.9.9:2408"}))
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	if only != "9.9.9.9:2408" {
		t.Fatalf("endpoint export = %q", only)
	}
}
