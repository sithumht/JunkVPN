package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"junkvpn/warpcore"
)

// probecheck runs live WireGuard handshake probes against WARP endpoints.
// Usage: go run ./tools/probecheck 162.159.192.1:2408 ...
func main() {
	targets := os.Args[1:]
	if len(targets) == 0 {
		targets = []string{
			"162.159.192.1:2408",
			"162.159.193.1:2408",
			"188.114.96.1:2408",
			"188.114.97.1:2408",
		}
	}
	results := warpcore.ProbeLive(context.Background(), targets, 3, 1500*time.Millisecond)
	for _, r := range results {
		fmt.Printf("%-28s wg=%-8.1f tcp=%-8.1f ok=%v loss=%.0f%%\n",
			r.Endpoint, r.WG, r.TCP, r.OK, r.Loss)
	}
}
