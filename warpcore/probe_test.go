package warpcore

import (
	"context"
	"encoding/base64"
	"net"
	"testing"
	"time"
)

func base64Of(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestTCPProbeMeasuresLatency(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	rtt, err := tcpProbe(context.Background(), ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if rtt <= 0 || rtt > 2*time.Second {
		t.Fatalf("rtt = %v", rtt)
	}
}

func TestTCPProbeRefusedPort(t *testing.T) {
	// Grab a port then close it so the connect must be refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	if _, err := tcpProbe(context.Background(), addr, 1500*time.Millisecond); err == nil {
		t.Fatal("closed port reported success")
	}
}

func TestProbeStatsSummary(t *testing.T) {
	p := &probeStats{}
	p.add(10*time.Millisecond, nil)
	p.add(30*time.Millisecond, nil)
	p.add(0, context.DeadlineExceeded)
	avg, jitter, loss, attempts := p.summary()
	if avg != 20 {
		t.Errorf("avg = %v, want 20", avg)
	}
	if jitter != 10 {
		t.Errorf("jitter = %v, want 10", jitter)
	}
	if loss < 33 || loss > 34 {
		t.Errorf("loss = %v, want ~33.3", loss)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d", attempts)
	}
	if p.ok() != true {
		t.Error("stats with successes should be ok")
	}

	empty := &probeStats{}
	_, _, loss, attempts = empty.summary()
	if loss != 100 || attempts != 0 {
		t.Errorf("empty summary loss=%v attempts=%d", loss, attempts)
	}
	if empty.ok() {
		t.Error("empty stats must not be ok")
	}
}

func TestParseEndpoint(t *testing.T) {
	host, port, err := parseEndpoint("162.159.192.1:2408")
	if err != nil || host != "162.159.192.1" || port != 2408 {
		t.Fatalf("got %q %d %v", host, port, err)
	}
	if _, _, err := parseEndpoint("no-port"); err == nil {
		t.Fatal("portless endpoint accepted")
	}
	if _, _, err := parseEndpoint("1.2.3.4:99999"); err == nil {
		t.Fatal("out of range port accepted")
	}
}

func TestWGProbeTimesOutAgainstSilentPeer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	// Consume packets but never answer, like a filtered endpoint.
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	id, err := newIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	start := time.Now()
	stats, _ := wgProbe(context.Background(), pc.LocalAddr().String(), id, 300*time.Millisecond, 2)
	if stats.ok() {
		t.Fatal("silent peer reported a handshake")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("probe took %v", elapsed)
	}
	_, _, loss, attempts := stats.summary()
	if attempts != 2 || loss != 100 {
		t.Errorf("attempts=%d loss=%v", attempts, loss)
	}
}
