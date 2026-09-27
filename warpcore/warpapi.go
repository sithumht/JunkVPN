package warpcore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Defaults used when talking to the public WARP registration endpoint.
const (
	defaultAPIBase    = "https://api.cloudflareclient.com"
	defaultAPIVersion = "v0a4471"
	defaultClientVer  = "a-6.35-4471"
	defaultUserAgent  = "WARP for Android"
)

// directRegisterTimeout bounds one direct registration attempt. Kept as a
// variable so tests can shrink the wait for a refused endpoint.
var directRegisterTimeout = 20 * time.Second

// RegisterOptions controls the device identity used during registration.
type RegisterOptions struct {
	BaseURL   string `json:"baseUrl,omitempty"`
	APIVer    string `json:"apiVersion,omitempty"`
	Model     string `json:"model,omitempty"`
	Locale    string `json:"locale,omitempty"`
	OSVersion string `json:"osVersion,omitempty"`
	Serial    string `json:"serial,omitempty"`
	// Proxy routes the registration request through a SOCKS5 or HTTP
	// proxy (e.g. "socks5://127.0.0.1:1080") on networks that block the
	// WARP API. Empty means direct.
	Proxy string `json:"proxy,omitempty"`
	// Route selects how registration reaches the API:
	//
	//	"auto"   — direct first, fall back to a WARP tunnel when the
	//	           network blocks the API (default)
	//	"direct" — direct (or proxy) only
	//	"tunnel" — always through a WARP tunnel
	Route string `json:"route,omitempty"`
	// Targets pins the tunnel's endpoint sweep to explicit "host:port"
	// candidates. Empty samples the public WARP ranges.
	Targets []string `json:"targets,omitempty"`
}

// RegisterEvents receives human readable progress steps from a running
// registration. Implementations are called from native worker threads.
type RegisterEvents interface {
	OnStep(step string)
}

// Account is the subset of registration data JunkVPN persists.
type Account struct {
	PrivateKey    string `json:"privateKey"`
	DeviceID      string `json:"deviceId"`
	Token         string `json:"token"`
	License       string `json:"license,omitempty"`
	AddressV4     string `json:"addressV4"`
	AddressV6     string `json:"addressV6"`
	PeerPublicKey string `json:"peerPublicKey"`
	PeerEndpoint  string `json:"peerEndpoint,omitempty"`
	CreatedAt     string `json:"createdAt"`
}

// registrationPayload mirrors what the WARP clients post to /reg.
type registrationPayload struct {
	Key        string `json:"key"`
	InstallID  string `json:"install_id"`
	FCMToken   string `json:"fcm_token"`
	TOS        string `json:"tos"`
	Model      string `json:"model"`
	Serial     string `json:"serial_number"`
	OSVersion  string `json:"os_version"`
	KeyType    string `json:"key_type"`
	TunnelType string `json:"tunnel_type"`
	Locale     string `json:"locale"`
}

// apiResponse is the part of the /reg answer we understand.
type apiResponse struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Key     string `json:"key"`
	Account struct {
		License string `json:"license"`
	} `json:"account"`
	Config struct {
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4   string `json:"v4"`
				V6   string `json:"v6"`
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

func cfTimestamp(t time.Time) string {
	return t.Format("2006-01-02T15:04:05.000-07:00")
}

func randomSerial() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "JUNKVPN0000000000"
	}
	return fmt.Sprintf("%X", b)
}

func apiBase(opts RegisterOptions) string {
	if opts.BaseURL != "" {
		return opts.BaseURL
	}
	return defaultAPIBase
}

func apiVersion(opts RegisterOptions) string {
	if opts.APIVer != "" {
		return opts.APIVer
	}
	return defaultAPIVersion
}

func emitStep(events RegisterEvents, msg string) {
	if events == nil {
		return
	}
	defer func() { _ = recover() }()
	events.OnStep(msg)
}

// RegisterAccount creates a fresh WARP device account and returns the
// generated identity plus peer configuration as JSON. events may be nil;
// when set it receives progress steps while the route chain runs.
func RegisterAccount(optsJSON string, events RegisterEvents) (string, error) {
	var opts RegisterOptions
	if optsJSON != "" {
		if err := json.Unmarshal([]byte(optsJSON), &opts); err != nil {
			return "", fmt.Errorf("bad options: %w", err)
		}
	}
	acc, err := registerRoute(context.Background(), opts, events)
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(acc)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// registerRoute picks the path registration takes to the API.
//
// The auto chain mirrors what censorship-avoidance tooling converges on:
// try the direct route (with multi-address/DoH failover, or a configured
// proxy), and only when the network never answers at the transport level,
// bring up an in-process WARP tunnel and register through it. A real HTTP
// answer from the API — even an error — means the endpoint is reachable,
// so the tunnel is skipped.
func registerRoute(ctx context.Context, opts RegisterOptions, events RegisterEvents) (*Account, error) {
	route := strings.ToLower(strings.TrimSpace(opts.Route))
	if route == "" {
		route = "auto"
	}
	switch route {
	case "direct":
		acc, _, err := registerDirect(ctx, opts, events)
		return acc, err
	case "tunnel":
		return registerTunnelRoute(ctx, opts, events)
	case "auto":
		// An explicit proxy is the user's chosen route: honour it
		// exactly and never quietly swap it out from under them.
		if opts.Proxy != "" {
			acc, _, err := registerDirect(ctx, opts, events)
			return acc, err
		}
		acc, reachable, err := registerDirect(ctx, opts, events)
		if err == nil {
			return acc, nil
		}
		if reachable {
			return nil, err
		}
		emitStep(events, "Direct route blocked — sweeping WARP endpoints for a tunnel…")
		tunnelAcc, tunnelErr := registerTunnelRoute(ctx, opts, events)
		if tunnelErr == nil {
			return tunnelAcc, nil
		}
		return nil, fmt.Errorf("%w\n(via WARP tunnel: %v)", err, tunnelErr)
	default:
		return nil, fmt.Errorf("unknown registration route %q — use auto, direct or tunnel", opts.Route)
	}
}

// registerDirect sends the registration through the normal network stack —
// optionally through a user proxy — and reports whether the API endpoint
// was actually reached (any HTTP response counts). reached lets the caller
// tell a censored network apart from a real API error.
func registerDirect(ctx context.Context, opts RegisterOptions, events RegisterEvents) (*Account, bool, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err != nil || proxyURL.Host == "" {
			return nil, false, fmt.Errorf("bad proxy %q — use socks5://host:port or http://host:port", opts.Proxy)
		}
		switch proxyURL.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return nil, false, fmt.Errorf("unsupported proxy scheme %q — use socks5:// or http://", proxyURL.Scheme)
		}
		tr.Proxy = http.ProxyURL(proxyURL)
		emitStep(events, "Registering through the configured proxy…")
	}
	// Registration must survive censored networks: let the dialer try
	// every system and DNS-over-HTTPS answer for the API host instead of
	// only the first resolved address (a single refused or poisoned IP
	// must not block the request).
	tr.DialContext = (&failoverDialer{}).DialContext

	client := &http.Client{Timeout: directRegisterTimeout, Transport: tr}
	return registerVia(ctx, client, opts)
}

// registerVia runs the two registration requests through client: POST /reg
// creates the device, then PATCH /reg/{id} flips warp_enabled — without the
// second step the account handshakes but never passes traffic, which is why
// wgcf and the official clients do the same pair.
//
// reached reports whether an HTTP response came back from the API; only a
// transport-level failure leaves it false.
func registerVia(ctx context.Context, client *http.Client, opts RegisterOptions) (*Account, bool, error) {
	base := apiBase(opts)
	apiVer := apiVersion(opts)
	model := opts.Model
	if model == "" {
		model = "JunkVPN"
	}
	locale := opts.Locale
	if locale == "" {
		locale = "en_US"
	}
	serial := opts.Serial
	if serial == "" {
		serial = randomSerial()
	}

	// The client keeps its private key; only the public half is registered.
	id, err := newIdentity()
	if err != nil {
		return nil, false, fmt.Errorf("key generation: %w", err)
	}

	payload := registrationPayload{
		Key:        base64.StdEncoding.EncodeToString(id.pub),
		InstallID:  "",
		FCMToken:   "",
		TOS:        cfTimestamp(time.Now()),
		Model:      model,
		Serial:     serial,
		OSVersion:  opts.OSVersion,
		KeyType:    "curve25519",
		TunnelType: "wireguard",
		Locale:     locale,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, false, err
	}

	regURL := fmt.Sprintf("%s/%s/reg", base, apiVer)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, regURL, bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("CF-Client-Version", defaultClientVer)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("registration request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, true, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, true, fmt.Errorf("registration failed (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}

	var parsed apiResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, true, fmt.Errorf("decode response: %w", err)
	}
	if parsed.ID == "" || parsed.Token == "" {
		return nil, true, fmt.Errorf("registration response missing device id/token")
	}

	if err := enableWARP(ctx, client, base, apiVer, parsed.ID, parsed.Token); err != nil {
		return nil, true, err
	}

	acc := &Account{
		PrivateKey:    base64.StdEncoding.EncodeToString(id.priv.Bytes()),
		DeviceID:      parsed.ID,
		Token:         parsed.Token,
		License:       parsed.Account.License,
		AddressV4:     parsed.Config.Interface.Addresses.V4,
		AddressV6:     parsed.Config.Interface.Addresses.V6,
		PeerPublicKey: warpPeerPublicKey,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	if len(parsed.Config.Peers) > 0 {
		acc.PeerPublicKey = parsed.Config.Peers[0].PublicKey
		acc.PeerEndpoint = stripPlaceholderPort(parsed.Config.Peers[0].Endpoint.V4)
	}
	return acc, true, nil
}

// enableWARP performs the second registration request: PATCH /reg/{id}
// with {"warp_enabled": true}, authorized by the device token the POST
// just issued.
func enableWARP(ctx context.Context, client *http.Client, base, apiVer, deviceID, token string) error {
	body, err := json.Marshal(map[string]bool{"warp_enabled": true})
	if err != nil {
		return err
	}
	patchURL := fmt.Sprintf("%s/%s/reg/%s", base, apiVer, deviceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, patchURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("enable WARP: %w", err)
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("CF-Client-Version", defaultClientVer)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("enable WARP: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return fmt.Errorf("enable WARP: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("enable WARP (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	return nil
}

// stripPlaceholderPort removes the ":0" placeholder the API returns
// (e.g. "162.159.192.1:0" -> "162.159.192.1").
func stripPlaceholderPort(ep string) string {
	host, portStr, err := net.SplitHostPort(ep)
	if err != nil {
		return ep
	}
	if portStr == "0" {
		return host
	}
	return ep
}

func snippet(b []byte) string {
	s := string(b)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
