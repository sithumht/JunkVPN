package warpcore

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	randv2 "math/rand/v2"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// defaultRanges are the public IPv4 ranges that host consumer WARP edges.
var defaultRanges = []string{
	"162.159.192.0/24",
	"162.159.193.0/24",
	"162.159.195.0/24",
	"188.114.96.0/24",
	"188.114.97.0/24",
	"188.114.98.0/24",
	"188.114.99.0/24",
}

const defaultWGPorts = "2408,500,4500,1701"

// ScanConfig describes a scan run. Empty fields fall back to the selected
// preset, then to safe defaults.
type ScanConfig struct {
	Preset    string   `json:"preset,omitempty"`
	Ranges    []string `json:"ranges,omitempty"`
	Targets   []string `json:"targets,omitempty"`
	Ports     []int    `json:"ports,omitempty"`
	TCPPorts  []int    `json:"tcpPorts,omitempty"`
	Count     int      `json:"count,omitempty"`
	TimeoutMs int      `json:"timeoutMs,omitempty"`
	Probes    int      `json:"probes,omitempty"`
	Workers   int      `json:"workers,omitempty"`
}

// ScanEvents receives progress from a running scan. Implementations are
// called from native worker threads.
type ScanEvents interface {
	OnStart(total int)
	OnProgress(done int, total int, message string)
	OnResult(endpoint string, wgMs float64, tcpMs float64, ok bool)
	OnFinish(best string, reachable int, total int)
	OnError(message string)
}

// EndpointResult is a single probed target.
type EndpointResult struct {
	Endpoint string   `json:"endpoint"`
	IP       string   `json:"ip"`
	Port     int      `json:"port"`
	Mode     string   `json:"mode"` // "wg" or "tcp"
	WGRttMs  *float64 `json:"wgRttMs,omitempty"`
	TCPRttMs *float64 `json:"tcpRttMs,omitempty"`
	JitterMs float64  `json:"jitterMs"`
	LossPct  float64  `json:"lossPct"`
	Probes   int      `json:"probes"`
	OK       bool     `json:"ok"`
}

// ScanResult is the summary returned by Scan.Run.
type ScanResult struct {
	Preset     string           `json:"preset"`
	StartedAt  time.Time        `json:"startedAt"`
	DurationMs int64            `json:"durationMs"`
	Total      int              `json:"total"`
	Reachable  int              `json:"reachable"`
	Handshakes int              `json:"handshakes"`
	Best       string           `json:"best,omitempty"`
	Canceled   bool             `json:"canceled,omitempty"`
	Results    []EndpointResult `json:"results"`
}

// PresetConfig resolves a preset name ("quick", "standard", "deep") into a
// concrete scan configuration exposed as JSON.
func PresetConfig(name string) (string, error) {
	cfg, err := resolveConfig(ScanConfig{Preset: name})
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func resolveConfig(cfg ScanConfig) (ScanConfig, error) {
	name := strings.ToLower(strings.TrimSpace(cfg.Preset))
	if name == "" {
		name = "standard"
	}
	switch name {
	case "quick":
		applyIfZero(&cfg.Count, 64)
		applyIfZero(&cfg.TimeoutMs, 1000)
		applyIfZero(&cfg.Probes, 1)
		applyIfZero(&cfg.Workers, 32)
	case "standard":
		applyIfZero(&cfg.Count, 256)
		applyIfZero(&cfg.TimeoutMs, 1500)
		applyIfZero(&cfg.Probes, 2)
		applyIfZero(&cfg.Workers, 64)
	case "deep":
		applyIfZero(&cfg.Count, 1024)
		applyIfZero(&cfg.TimeoutMs, 2000)
		applyIfZero(&cfg.Probes, 3)
		applyIfZero(&cfg.Workers, 96)
	default:
		return cfg, fmt.Errorf("unknown preset %q", name)
	}
	cfg.Preset = name

	if len(cfg.Ranges) == 0 && len(cfg.Targets) == 0 {
		cfg.Ranges = append([]string{}, defaultRanges...)
	}
	if len(cfg.Ports) == 0 {
		cfg.Ports = []int{2408, 500, 4500, 1701}
	}
	if len(cfg.TCPPorts) == 0 {
		cfg.TCPPorts = []int{443}
	}
	if cfg.Count <= 0 || cfg.Count > 8192 {
		return cfg, fmt.Errorf("count out of range")
	}
	if cfg.Probes <= 0 || cfg.Probes > 20 {
		return cfg, fmt.Errorf("probes out of range")
	}
	if cfg.Workers <= 0 || cfg.Workers > 512 {
		return cfg, fmt.Errorf("workers out of range")
	}
	if cfg.TimeoutMs < 100 || cfg.TimeoutMs > 30000 {
		return cfg, fmt.Errorf("timeout out of range")
	}
	return cfg, nil
}

func applyIfZero(v *int, def int) {
	if *v == 0 {
		*v = def
	}
}

type target struct {
	ip   net.IP
	port int
}

func (t target) endpoint() string {
	return net.JoinHostPort(t.ip.String(), fmt.Sprintf("%d", t.port))
}

// buildTargets expands explicit targets and CIDR ranges into candidates.
func buildTargets(cfg ScanConfig) ([]target, error) {
	seen := map[string]bool{}
	var out []target
	add := func(ip net.IP, port int) {
		key := ip.String() + "|" + fmt.Sprint(port)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, target{ip: ip, port: port})
	}

	for _, raw := range cfg.Targets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if host, portStr, err := net.SplitHostPort(raw); err == nil {
			ip := net.ParseIP(host)
			if ip == nil {
				return nil, fmt.Errorf("bad target %q", raw)
			}
			var port int
			if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port <= 0 || port > 65535 {
				return nil, fmt.Errorf("bad port in target %q", raw)
			}
			add(ip, port)
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, fmt.Errorf("bad target %q", raw)
		}
		for _, p := range cfg.Ports {
			add(ip, p)
		}
	}

	for _, cidr := range cfg.Ranges {
		ips, err := uniqueRandomIPs(cidr, cfg.Count)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			for _, p := range cfg.Ports {
				add(ip, p)
			}
		}
	}

	randv2.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	if len(out) > cfg.Count {
		out = out[:cfg.Count]
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no targets to scan")
	}
	return out, nil
}

// randomIPs draws up to n random addresses inside a CIDR block.
func randomIPs(cidr string, n int) ([]net.IP, error) {
	return uniqueRandomIPs(cidr, n)
}

// uniqueRandomIPs returns up to n distinct addresses inside a CIDR block.
// Small blocks are enumerated and shuffled so duplicates are impossible;
// large blocks use rejection sampling.
func uniqueRandomIPs(cidr string, n int) ([]net.IP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("bad range %q: %w", cidr, err)
	}
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 0 {
		return nil, fmt.Errorf("range %q has no usable hosts", cidr)
	}
	max := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	ipBytes := ipnet.IP.To4()
	if ipBytes == nil {
		ipBytes = ipnet.IP.To16()
	}
	base := new(big.Int).SetBytes(ipBytes)
	size := len(ipBytes)

	mk := func(offset *big.Int) net.IP {
		val := new(big.Int).Add(base, offset)
		raw := val.Bytes()
		ip := make(net.IP, size)
		copy(ip[size-len(raw):], raw)
		return ip
	}

	// Small spaces: pick a distinct set without replacement.
	if hostBits <= 16 {
		available := int(max.Int64())
		if n > available {
			n = available
		}
		offsets := make([]int, 0, available)
		for i := 0; i < available; i++ {
			offsets = append(offsets, i)
		}
		randv2.Shuffle(len(offsets), func(i, j int) {
			offsets[i], offsets[j] = offsets[j], offsets[i]
		})
		if len(offsets) > n {
			offsets = offsets[:n]
		}
		out := make([]net.IP, 0, len(offsets))
		for _, o := range offsets {
			out = append(out, mk(big.NewInt(int64(o))))
		}
		return out, nil
	}

	// Large spaces: rejection sampling with a safety cap.
	seen := map[string]bool{}
	out := make([]net.IP, 0, n)
	offBytes := make([]byte, (hostBits+7)/8)
	attempts, maxAttempts := 0, n*8+256
	for len(out) < n && attempts < maxAttempts {
		attempts++
		if _, err := rand.Read(offBytes); err != nil {
			return nil, fmt.Errorf("random: %w", err)
		}
		offset := new(big.Int).SetBytes(offBytes)
		offset.Mod(offset, max)
		ip := mk(offset)
		if seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip)
	}
	return out, nil
}

// Scan is a cancellable scan session.
type Scan struct {
	cfg    ScanConfig
	events ScanEvents
	ctx    context.Context
	cancel context.CancelFunc
}

// NewScan prepares a scan session. Call Run (typically on a worker thread)
// to execute it and Cancel to stop early.
func NewScan(cfgJSON string, events ScanEvents) (*Scan, error) {
	var cfg ScanConfig
	if strings.TrimSpace(cfgJSON) != "" {
		if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
			return nil, fmt.Errorf("bad scan config: %w", err)
		}
	}
	resolved, err := resolveConfig(cfg)
	if err != nil {
		return nil, err
	}
	if _, err := buildTargets(resolved); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Scan{cfg: resolved, events: events, ctx: ctx, cancel: cancel}, nil
}

// Cancel stops the scan early; Run then returns partial results.
func (s *Scan) Cancel() {
	if s.cancel != nil {
		s.cancel()
	}
}

type scanOutcome struct {
	res EndpointResult
}

// Run executes the scan and returns a ScanResult as JSON.
func (s *Scan) Run() (string, error) {
	started := time.Now()
	targets, err := buildTargets(s.cfg)
	if err != nil {
		s.emitError(err.Error())
		return "", err
	}
	s.emit(func(e ScanEvents) { e.OnStart(len(targets)) })

	timeout := time.Duration(s.cfg.TimeoutMs) * time.Millisecond
	identity, idErr := newIdentity()
	if idErr != nil {
		s.emitError("identity: " + idErr.Error())
		return "", idErr
	}

	jobs := make(chan target)
	outcomes := make(chan scanOutcome, len(targets))
	var wg sync.WaitGroup
	var doneCount int64
	var mu sync.Mutex

	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				if s.ctx.Err() != nil {
					continue
				}
				res := s.probeTarget(t, identity, timeout)
				outcomes <- scanOutcome{res: res}

				mu.Lock()
				doneCount++
				done := doneCount
				mu.Unlock()
				s.emit(func(e ScanEvents) {
					e.OnProgress(int(done), len(targets), res.Endpoint)
					e.OnResult(res.Endpoint, deref(res.WGRttMs), deref(res.TCPRttMs), res.OK)
				})
			}
		}()
	}

	for _, t := range targets {
		select {
		case <-s.ctx.Done():
		case jobs <- t:
		}
	}
	close(jobs)
	wg.Wait()
	close(outcomes)

	result := ScanResult{
		Preset:    s.cfg.Preset,
		StartedAt: started.UTC(),
		Total:     len(targets),
		Canceled:  s.ctx.Err() != nil,
	}
	for oc := range outcomes {
		result.Results = append(result.Results, oc.res)
		if oc.res.OK {
			result.Reachable++
		}
		if oc.res.WGRttMs != nil {
			result.Handshakes++
		}
	}
	sortResults(result.Results)
	if len(result.Results) > 0 && result.Results[0].OK {
		result.Best = result.Results[0].Endpoint
	}
	result.DurationMs = time.Since(started).Milliseconds()

	out, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	s.emit(func(e ScanEvents) { e.OnFinish(result.Best, result.Reachable, result.Total) })
	return string(out), nil
}

// probeTarget measures one candidate: first with a real WireGuard handshake,
// then with a plain TCP connect as a reachability fallback.
func (s *Scan) probeTarget(t target, identity *wgIdentity, timeout time.Duration) EndpointResult {
	res := EndpointResult{
		Endpoint: t.endpoint(),
		IP:       t.ip.String(),
		Port:     t.port,
	}

	stats, _ := wgProbe(s.ctx, t.endpoint(), identity, timeout, s.cfg.Probes)
	if stats != nil && stats.ok() {
		avg, jitter, loss, attempts := stats.summary()
		res.Mode = "wg"
		res.WGRttMs = &avg
		res.JitterMs = jitter
		res.LossPct = loss
		res.Probes = attempts
		res.OK = true
		return res
	}

	// Fallback: TCP connect to the edge's web port proves the host is alive
	// even when UDP handshakes are filtered.
	for _, tp := range s.cfg.TCPPorts {
		if s.ctx.Err() != nil {
			break
		}
		tcpStats := &probeStats{}
		for i := 0; i < s.cfg.Probes && s.ctx.Err() == nil; i++ {
			rtt, err := tcpProbe(s.ctx, net.JoinHostPort(t.ip.String(), fmt.Sprintf("%d", tp)), timeout)
			tcpStats.add(rtt, err)
		}
		if tcpStats.ok() {
			avg, jitter, loss, attempts := tcpStats.summary()
			res.Mode = "tcp"
			res.TCPRttMs = &avg
			res.JitterMs = jitter
			res.LossPct = loss
			res.Probes = attempts
			res.OK = true
			return res
		}
	}
	if stats != nil {
		_, _, loss, attempts := stats.summary()
		res.LossPct = loss
		res.Probes = attempts
	}
	return res
}

func deref(f *float64) float64 {
	if f == nil {
		return -1
	}
	return *f
}

// sortResults ranks handshake-confirmed endpoints first by latency, then
// TCP-reachable ones by latency.
func sortResults(list []EndpointResult) {
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.OK != b.OK {
			return a.OK
		}
		if (a.WGRttMs != nil) != (b.WGRttMs != nil) {
			return a.WGRttMs != nil
		}
		av, bv := deref(a.WGRttMs), deref(b.WGRttMs)
		if a.WGRttMs == nil {
			av, bv = deref(a.TCPRttMs), deref(b.TCPRttMs)
		}
		return av < bv
	})
}

func (s *Scan) emit(fn func(ScanEvents)) {
	if s.events == nil {
		return
	}
	defer func() { _ = recover() }()
	fn(s.events)
}

func (s *Scan) emitError(msg string) {
	s.emit(func(e ScanEvents) { e.OnError(msg) })
}
