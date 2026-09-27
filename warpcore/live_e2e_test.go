package warpcore

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Live tests talk to the real Cloudflare API and mint a real WARP account,
// so they only run when JUNKVPN_LIVE=1 is set.
func liveEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("JUNKVPN_LIVE") == "" {
		t.Skip("set JUNKVPN_LIVE=1 to run against the public WARP API")
	}
}

// TestLiveRegisterDirect registers a fresh account against the public API
// through the direct route and checks that every field the app persists
// comes back populated.
func TestLiveRegisterDirect(t *testing.T) {
	liveEnabled(t)

	out, err := RegisterAccount("", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	var acc Account
	if err := json.Unmarshal([]byte(out), &acc); err != nil {
		t.Fatalf("decode account: %v", err)
	}
	if acc.DeviceID == "" || acc.Token == "" {
		t.Fatalf("missing id/token: %s", out)
	}
	if acc.PrivateKey == "" || acc.PeerPublicKey == "" {
		t.Fatalf("missing key material: %s", out)
	}
	if acc.AddressV4 == "" {
		t.Errorf("missing v4 address: %s", out)
	}
	t.Logf("registered device %s at %s", acc.DeviceID, acc.CreatedAt)
}

// TestLiveIdentityMatrix proves, on a real network, which identities real
// WARP edges answer handshake initiations from: a freshly registered
// account, a random throwaway, and a shared placeholder key.
func TestLiveIdentityMatrix(t *testing.T) {
	liveEnabled(t)
	edges := []string{"162.159.192.1:2408", "188.114.96.1:2408"}

	out, err := RegisterAccount("", nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	var acc Account
	if err := json.Unmarshal([]byte(out), &acc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, edge := range edges {
		res, err := VerifyEndpoint(edge, out, 2000, 3)
		if err != nil {
			t.Fatalf("verify %s: %v", edge, err)
		}
		t.Logf("registered  %-18s -> %s", edge, res)
	}

	throwaway, err := newIdentity()
	if err != nil {
		t.Fatalf("throwaway: %v", err)
	}
	for _, edge := range edges {
		stats, _ := wgProbe(context.Background(), edge, throwaway, 1500*time.Millisecond, 3)
		avg, _, loss, attempts := stats.summary()
		t.Logf("throwaway   %-18s -> rtt=%.1f loss=%.0f%% attempts=%d ok=%v",
			edge, avg, loss*100, attempts, stats.ok())
	}

	// The tunnel fallback identifies with a shared placeholder key, so
	// guard that production edges still answer it.
	placeholder, err := identityFromPrivate(tunnelPlaceholderKey)
	if err != nil {
		t.Fatalf("placeholder key: %v", err)
	}
	for _, edge := range edges {
		stats, _ := wgProbe(context.Background(), edge, placeholder, 1500*time.Millisecond, 3)
		avg, _, loss, attempts := stats.summary()
		if !stats.ok() {
			t.Errorf("placeholder %-18s -> no handshake (rtt=%.1f attempts=%d): the tunnel fallback needs this key recognized",
				edge, avg, attempts)
			continue
		}
		t.Logf("placeholder %-18s -> rtt=%.1f loss=%.0f%% attempts=%d ok=%v",
			edge, avg, loss*100, attempts, stats.ok())
	}
}
