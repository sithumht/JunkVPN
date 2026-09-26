// Package warpcore is the native core of JunkVPN: WARP endpoint scanning,
// account registration and tunnel configuration generation. It is bound to
// Android through gomobile.
package warpcore

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// tcpProbe measures TCP connect latency to addr ("ip:port").
// It returns the round-trip time of a successful handshake or an error.
func tcpProbe(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
	if timeout <= 0 {
		timeout = time.Second
	}
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	rtt := time.Since(start)
	_ = conn.Close()
	return rtt, ctx.Err()
}

// probeStats aggregates several attempts against a single target.
type probeStats struct {
	mu       sync.Mutex
	rtts     []time.Duration
	failures int
}

func (p *probeStats) add(d time.Duration, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.failures++
		return
	}
	p.rtts = append(p.rtts, d)
}

// summary returns average and jitter (mean absolute deviation) in
// milliseconds plus the loss percentage observed across attempts.
func (p *probeStats) summary() (avgMs, jitterMs, lossPct float64, attempts int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	attempts = len(p.rtts) + p.failures
	if attempts == 0 {
		return 0, 0, 100, 0
	}
	lossPct = float64(p.failures) / float64(attempts) * 100
	if len(p.rtts) == 0 {
		return 0, 0, lossPct, attempts
	}
	var total time.Duration
	for _, r := range p.rtts {
		total += r
	}
	avg := total / time.Duration(len(p.rtts))
	var dev time.Duration
	for _, r := range p.rtts {
		if r > avg {
			dev += r - avg
		} else {
			dev += avg - r
		}
	}
	jitter := dev / time.Duration(len(p.rtts))
	return float64(avg) / float64(time.Millisecond),
		float64(jitter) / float64(time.Millisecond),
		lossPct, attempts
}

func (p *probeStats) ok() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.rtts) > 0
}

// indexLE encodes a uint32 in little endian order.
func indexLE(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// parseEndpoint splits "host:port" tolerating bare IPv6 literals.
func parseEndpoint(ep string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(ep)
	if err != nil {
		return "", 0, fmt.Errorf("bad endpoint %q: %w", ep, err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("bad port in endpoint %q", ep)
	}
	return host, port, nil
}
