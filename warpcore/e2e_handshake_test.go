package warpcore

import (
	"context"
	"encoding/hex"
	"net"
	"os"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// fakeTun satisfies wireguard-go's tun.Device so a real WireGuard responder
// can run entirely in memory for protocol validation tests.
type fakeTun struct {
	events chan tun.Event
	closed chan struct{}
}

func newFakeTun() *fakeTun {
	return &fakeTun{
		events: make(chan tun.Event, 8),
		closed: make(chan struct{}),
	}
}

func (t *fakeTun) File() *os.File { return nil }

func (t *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-t.closed
	return 0, os.ErrClosed
}

func (t *fakeTun) Write(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }
func (t *fakeTun) MTU() (int, error)                            { return 1420, nil }
func (t *fakeTun) Name() (string, error)                        { return "junk0", nil }
func (t *fakeTun) Events() <-chan tun.Event                     { return t.events }

func (t *fakeTun) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	return nil
}

func (t *fakeTun) BatchSize() int { return 1 }

// startLocalResponder boots a real wireguard-go device on a free UDP
// loopback port. The initiator identities passed in peerPubHex are registered
// as allowed peers; unknown peers are dropped exactly like on a real server.
func startLocalResponder(t *testing.T, privHex string, peerPubHex ...string) (string, func()) {
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

	cfg := "private_key=" + privHex + "\nlisten_port=" + portStr + "\n"
	for _, pub := range peerPubHex {
		cfg += "public_key=" + pub + "\nallowed_ip=10.7.0.2/32\n"
	}

	logger := device.NewLogger(device.LogLevelSilent, "wg-e2e: ")
	dev := device.NewDevice(newFakeTun(), conn.NewStdNetBind(), logger)
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		t.Fatalf("ipcset: %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		t.Fatalf("up: %v", err)
	}
	addr := net.JoinHostPort("127.0.0.1", portStr)
	return addr, func() { dev.Close() }
}

// TestHandshakeAgainstRealWireGuard validates our handcrafted initiation
// messages against wireguard-go itself. If mac1, the noise chain, the AEAD
// nonce convention or the message layout were wrong, the responder would
// silently drop every attempt.
func TestHandshakeAgainstRealWireGuard(t *testing.T) {
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

	stats, _ := wgProbeTo(context.Background(), addr, client, base64Of(server.pub), 2*time.Second, 3)
	if !stats.ok() {
		t.Fatal("real WireGuard responder did not answer our initiation")
	}
	avg, _, loss, attempts := stats.summary()
	if loss != 0 || attempts != 3 {
		t.Errorf("loss=%v attempts=%d", loss, attempts)
	}
	if avg <= 0 || avg > 1500 {
		t.Errorf("avg rtt = %v", avg)
	}
}

// TestHandshakeRejectedForUnknownPeer proves the responder really validates
// key agreement: when a different initiator is registered, our initiation
// must be dropped instead of answered.
func TestHandshakeRejectedForUnknownPeer(t *testing.T) {
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

	stats, _ := wgProbeTo(context.Background(), addr, outsider, base64Of(server.pub), 500*time.Millisecond, 2)
	if stats.ok() {
		t.Fatal("responder answered a peer that was never registered")
	}
}

// TestResponderAcceptsRepeatedHandshakes mirrors how the app scores a target
// with several probes: every attempt must get its own matching response.
func TestResponderAcceptsRepeatedHandshakes(t *testing.T) {
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

	stats, _ := wgProbeTo(context.Background(), addr, client, base64Of(server.pub), time.Second, 4)
	if got := len(stats.rtts); got != 4 {
		t.Fatalf("handshakes = %d, want 4", got)
	}
}
