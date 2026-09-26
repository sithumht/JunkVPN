package warpcore

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestResolvePresets(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
	}{
		{"quick", 64},
		{"standard", 256},
		{"deep", 1024},
	} {
		cfg, err := resolveConfig(ScanConfig{Preset: tc.name})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if cfg.Count != tc.count {
			t.Errorf("%s count = %d, want %d", tc.name, cfg.Count, tc.count)
		}
		if len(cfg.Ranges) == 0 {
			t.Errorf("%s has no ranges", tc.name)
		}
		if len(cfg.Ports) == 0 || len(cfg.TCPPorts) == 0 {
			t.Errorf("%s missing ports", tc.name)
		}
	}
	if _, err := resolveConfig(ScanConfig{Preset: "bogus"}); err == nil {
		t.Fatal("unknown preset accepted")
	}
	if _, err := resolveConfig(ScanConfig{Preset: "quick", Count: -5}); err == nil {
		t.Fatal("negative count accepted")
	}
}

func TestBuildTargetsFromRange(t *testing.T) {
	cfg, err := resolveConfig(ScanConfig{
		Preset: "quick",
		Ranges: []string{"162.159.192.0/24"},
		Ports:  []int{2408},
		Count:  16,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	targets, err := buildTargets(cfg)
	if err != nil {
		t.Fatalf("targets: %v", err)
	}
	if len(targets) != 16 {
		t.Fatalf("got %d targets, want 16", len(targets))
	}
	seen := map[string]bool{}
	for _, tg := range targets {
		if !strings.HasPrefix(tg.ip.String(), "162.159.192.") {
			t.Fatalf("ip %s outside range", tg.ip)
		}
		if tg.port != 2408 {
			t.Fatalf("port %d", tg.port)
		}
		if seen[tg.endpoint()] {
			t.Fatalf("duplicate target %s", tg.endpoint())
		}
		seen[tg.endpoint()] = true
	}
}

func TestBuildTargetsExplicit(t *testing.T) {
	cfg, err := resolveConfig(ScanConfig{
		Preset:  "quick",
		Targets: []string{"10.0.0.1", "10.0.0.2:443"},
		Ports:   []int{2408},
		Count:   16,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	targets, err := buildTargets(cfg)
	if err != nil {
		t.Fatalf("targets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
	if _, err := resolveConfig(ScanConfig{Preset: "quick", Targets: []string{"lolcat"}}); err != nil {
		t.Fatal("bad preset rejected")
	} else if _, err := buildTargets(ScanConfig{
		Preset: "quick", Targets: []string{"lolcat"}, Ports: []int{2408}, Count: 4,
		TCPPorts: []int{443}, TimeoutMs: 1000, Probes: 1, Workers: 4,
	}); err == nil {
		t.Fatal("bad target accepted")
	}
}

func TestRandomIPsStayInCIDR(t *testing.T) {
	ips, err := randomIPs("188.114.96.0/24", 64)
	if err != nil {
		t.Fatalf("random: %v", err)
	}
	for _, ip := range ips {
		if !strings.HasPrefix(ip.String(), "188.114.96.") {
			t.Fatalf("%s outside 188.114.96.0/24", ip)
		}
	}
}

func TestSortResultsRanksHandshakesFirst(t *testing.T) {
	slow := 90.0
	fastTCP := 5.0
	fastWG := 20.0
	list := []EndpointResult{
		{Endpoint: "tcp-fast", OK: true, TCPRttMs: &fastTCP},
		{Endpoint: "wg-slow", OK: true, WGRttMs: &slow},
		{Endpoint: "dead"},
		{Endpoint: "wg-fast", OK: true, WGRttMs: &fastWG},
	}
	sortResults(list)
	if list[0].Endpoint != "wg-fast" {
		t.Fatalf("first = %s, want wg-fast", list[0].Endpoint)
	}
	if list[1].Endpoint != "wg-slow" {
		t.Fatalf("second = %s, want wg-slow", list[1].Endpoint)
	}
	if list[2].Endpoint != "tcp-fast" {
		t.Fatalf("third = %s, want tcp-fast", list[2].Endpoint)
	}
	if list[3].Endpoint != "dead" {
		t.Fatalf("last = %s, want dead", list[3].Endpoint)
	}
}

type fakeEvents struct {
	started  int
	progress int
	results  int
	finished bool
	best     string
	reach    int
}

func (f *fakeEvents) OnStart(total int)                      { f.started = total }
func (f *fakeEvents) OnProgress(done, total int, msg string) { f.progress = done }
func (f *fakeEvents) OnResult(ep string, wg, tcp float64, ok bool) {
	f.results++
}
func (f *fakeEvents) OnFinish(best string, reachable, total int) {
	f.finished = true
	f.best = best
	f.reach = reachable
}
func (f *fakeEvents) OnError(message string) {}

// recordingEvents never probes successfully and must not deadlock.
func TestScanRunAgainstClosedUDP(t *testing.T) {
	// Bind a local UDP socket that never answers handshakes.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("addr: %v", err)
	}
	var portNum int
	if _, err := fmt.Sscanf(port, "%d", &portNum); err != nil {
		t.Fatalf("port: %v", err)
	}

	cfgJSON, err := PresetConfig("quick")
	if err != nil {
		t.Fatalf("preset: %v", err)
	}
	var cfg ScanConfig
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cfg.Targets = []string{"127.0.0.1"}
	cfg.Ranges = nil
	cfg.Ports = []int{portNum}
	cfg.TCPPorts = []int{1} // guaranteed closed
	cfg.Count = 1
	cfg.Probes = 1
	cfg.TimeoutMs = 200
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	events := &fakeEvents{}
	s, err := NewScan(string(out), events)
	if err != nil {
		t.Fatalf("new scan: %v", err)
	}
	resJSON, err := s.Run()
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var res ScanResult
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		t.Fatalf("result json: %v", err)
	}
	if res.Total != 1 {
		t.Fatalf("total = %d", res.Total)
	}
	if res.Reachable != 0 {
		t.Fatalf("closed endpoint reported reachable")
	}
	if events.started != 1 || !events.finished {
		t.Fatalf("events: started=%d finished=%v", events.started, events.finished)
	}
	if res.Best != "" {
		t.Fatalf("best should be empty, got %q", res.Best)
	}
}

func TestNewScanRejectsBadConfig(t *testing.T) {
	if _, err := NewScan("{not json", nil); err == nil {
		t.Fatal("bad json accepted")
	}
	if _, err := NewScan(`{"preset":"nope"}`, nil); err == nil {
		t.Fatal("bad preset accepted")
	}
	if _, err := NewScan("", nil); err != nil {
		t.Fatalf("defaults rejected: %v", err)
	}
}

func TestScanCancelEarly(t *testing.T) {
	cfg, err := resolveConfig(ScanConfig{
		Preset: "quick",
		Ranges: []string{"162.159.192.0/24"},
		Count:  64,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	out, _ := json.Marshal(cfg)
	s, err := NewScan(string(out), &fakeEvents{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	s.Cancel()
	done := make(chan struct{})
	go func() {
		_, _ = s.Run()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("canceled scan did not return")
	}
}
