package warpcore

import (
	"context"
	"net"
	"time"
)

// LiveResult describes one endpoint probed by ProbeLive.
type LiveResult struct {
	Endpoint string
	WG       float64
	TCP      float64
	OK       bool
	Loss     float64
}

// ProbeLive probes endpoints synchronously and reports both metrics.
// It exists for command line diagnostics outside the Android app.
func ProbeLive(ctx context.Context, endpoints []string, probes int, timeout time.Duration) []LiveResult {
	id, err := newIdentity()
	if err != nil {
		return nil
	}
	out := make([]LiveResult, 0, len(endpoints))
	for _, ep := range endpoints {
		res := LiveResult{Endpoint: ep}
		stats, _ := wgProbe(ctx, ep, id, timeout, probes)
		if stats != nil {
			avg, _, loss, _ := stats.summary()
			res.Loss = loss
			if stats.ok() {
				res.WG = avg
				res.OK = true
			}
		}
		if host, _, err := net.SplitHostPort(ep); err == nil {
			if tcp, err := tcpProbe(ctx, net.JoinHostPort(host, "443"), timeout); err == nil {
				res.TCP = float64(tcp) / float64(time.Millisecond)
				res.OK = true
			}
		}
		out = append(out, res)
	}
	return out
}
