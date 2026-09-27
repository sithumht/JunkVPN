package warpcore

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func verifyAccountJSON(t *testing.T, id *wgIdentity, peerPub string) string {
	t.Helper()
	acc := Account{
		PrivateKey:    base64Of(id.priv.Bytes()),
		DeviceID:      "test-device",
		Token:         "test-token",
		AddressV4:     "172.16.0.2",
		AddressV6:     "2606:4700:110::1",
		PeerPublicKey: peerPub,
		PeerEndpoint:  "192.0.2.1:2408",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	out, err := json.Marshal(acc)
	if err != nil {
		t.Fatalf("marshal account: %v", err)
	}
	return string(out)
}

func parseVerify(t *testing.T, out string) VerifyResult {
	t.Helper()
	var res VerifyResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("bad verify json %q: %v", out, err)
	}
	return res
}

// TestVerifyEndpointAuthenticatedPeer is the feature's core promise: an
// endpoint that accepts a handshake with the account's registered keys
// responds with an authenticator only the real peer private key holder can
// produce.
func TestVerifyEndpointAuthenticatedPeer(t *testing.T) {
	server, err := newIdentity()
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	client, err := newIdentity()
	if err != nil {
		t.Fatalf("client identity: %v", err)
	}
	addr, stop := startLocalResponder(t,
		hex.EncodeToString(server.priv.Bytes()),
		hex.EncodeToString(client.pub))
	defer stop()

	out, err := VerifyEndpoint(addr, verifyAccountJSON(t, client, base64Of(server.pub)), 2000, 3)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	res := parseVerify(t, out)
	if !res.OK || res.Code != VerifyOK {
		t.Fatalf("verify failed: %+v", res)
	}
	if res.RttMs <= 0 || res.RttMs > 2000 {
		t.Errorf("rtt = %v", res.RttMs)
	}
	if res.Attempts == 0 {
		t.Error("no successful attempts counted")
	}
	// wireguard-go fills mac1 on responses keyed by our public key.
	if !res.MAC1OK {
		t.Error("response mac1 did not match our identity")
	}
}

// TestVerifyEndpointUnknownAccountKey proves verification distinguishes a
// recognized identity from a stray one: responders drop initiations from
// keys that were never registered, so no response can authenticate.
func TestVerifyEndpointUnknownAccountKey(t *testing.T) {
	server, err := newIdentity()
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	registered, err := newIdentity()
	if err != nil {
		t.Fatalf("registered identity: %v", err)
	}
	outsider, err := newIdentity()
	if err != nil {
		t.Fatalf("outsider identity: %v", err)
	}
	addr, stop := startLocalResponder(t,
		hex.EncodeToString(server.priv.Bytes()),
		hex.EncodeToString(registered.pub))
	defer stop()

	out, err := VerifyEndpoint(addr, verifyAccountJSON(t, outsider, base64Of(server.pub)), 400, 2)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	res := parseVerify(t, out)
	if res.OK {
		t.Fatalf("unregistered key accepted: %+v", res)
	}
	if res.Code != VerifyNoResponse {
		t.Fatalf("code = %q, want %q (%s)", res.Code, VerifyNoResponse, res.Detail)
	}
}

// TestVerifyEndpointGarbageResponse ensures random UDP chatter cannot be
// mistaken for a peer: packets that fail authentication map to
// bad_response rather than success.
func TestVerifyEndpointGarbageResponse(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_ = n
			// A well sized but meaningless handshake reply.
			_, _ = pc.WriteTo(make([]byte, responseSize), addr)
		}
	}()

	account := verifyAccountJSON(t, mustIdentity(t), warpPeerPublicKey)
	out, err := VerifyEndpoint(pc.LocalAddr().String(), account, 500, 1)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	res := parseVerify(t, out)
	if res.OK {
		t.Fatalf("garbage authenticated: %+v", res)
	}
	if res.Code != VerifyBadResponse {
		t.Fatalf("code = %q, want %q", res.Code, VerifyBadResponse)
	}
}

// TestVerifyEndpointInputErrors covers the structured error codes the UI
// relies on for messaging.
func TestVerifyEndpointInputErrors(t *testing.T) {
	id := mustIdentity(t)

	check := func(name, endpoint, account string, wantCode string) {
		t.Helper()
		out, err := VerifyEndpoint(endpoint, account, 500, 1)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res := parseVerify(t, out); res.Code != wantCode {
			t.Errorf("%s: code = %q, want %q (%s)", name, res.Code, wantCode, res.Detail)
		}
	}

	check("no port", "192.0.2.1", verifyAccountJSON(t, id, warpPeerPublicKey), VerifyBadEndpoint)
	check("no account", "192.0.2.1:2408", "", VerifyNoAccount)
	check("bad account json", "192.0.2.1:2408", "{not json", VerifyNoAccount)
	check("account without key", "192.0.2.1:2408", `{"deviceId":"x"}`, VerifyNoAccount)
}

// TestVerifyEndpointUnreachableHost maps resolution failures to network.
func TestVerifyEndpointUnreachableHost(t *testing.T) {
	out, err := VerifyEndpoint("256.256.256.256:2408",
		verifyAccountJSON(t, mustIdentity(t), warpPeerPublicKey), 300, 1)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res := parseVerify(t, out); res.Code != VerifyNetwork {
		t.Fatalf("code = %q, want %q (%s)", res.Code, VerifyNetwork, res.Detail)
	}
}

// TestScanWithAccountIdentity validates the scan half of the feature:
// handshake probes must use the registered identity so responders that
// only answer registered keys include the target in the results.
func TestScanWithAccountIdentity(t *testing.T) {
	server, err := newIdentity()
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	client, err := newIdentity()
	if err != nil {
		t.Fatalf("client identity: %v", err)
	}
	addr, stop := startLocalResponder(t,
		hex.EncodeToString(server.priv.Bytes()),
		hex.EncodeToString(client.pub))
	defer stop()

	run := func(account string) ScanResult {
		t.Helper()
		cfg := `{"preset":"quick","targets":["` + addr + `"],"timeoutMs":800,"probes":1,"workers":1`
		if account != "" {
			quoted, err := json.Marshal(account)
			if err != nil {
				t.Fatalf("quote account: %v", err)
			}
			cfg += `,"account":` + string(quoted)
		}
		cfg += `}`
		scan, err := NewScan(cfg, nil)
		if err != nil {
			t.Fatalf("new scan: %v", err)
		}
		out, err := scan.Run()
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		var res ScanResult
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("parse: %v", err)
		}
		return res
	}

	with := run(verifyAccountJSON(t, client, base64Of(server.pub)))
	if len(with.Results) != 1 || with.Results[0].Mode != "wg" || with.Handshakes != 1 {
		t.Fatalf("account identity scan: %+v", with)
	}

	// Without an account the throwaway identity is dropped by the
	// responder, exactly like an unregistered client on a real edge.
	without := run("")
	if len(without.Results) != 1 || without.Results[0].Mode == "wg" {
		t.Fatalf("throwaway identity must not authenticate: %+v", without)
	}
}

func mustIdentity(t *testing.T) *wgIdentity {
	t.Helper()
	id, err := newIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return id
}
