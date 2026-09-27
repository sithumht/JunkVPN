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
	"time"
)

// Defaults used when talking to the public WARP registration endpoint.
const (
	defaultAPIBase    = "https://api.cloudflareclient.com"
	defaultAPIVersion = "v0a4471"
	defaultClientVer  = "a-6.35-4471"
	defaultUserAgent  = "WARP for Android"
)

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

// RegisterAccount creates a fresh WARP device account and returns the
// generated identity plus peer configuration as JSON.
func RegisterAccount(optsJSON string) (string, error) {
	var opts RegisterOptions
	if optsJSON != "" {
		if err := json.Unmarshal([]byte(optsJSON), &opts); err != nil {
			return "", fmt.Errorf("bad options: %w", err)
		}
	}
	acc, err := register(context.Background(), opts)
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(acc)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func register(ctx context.Context, opts RegisterOptions) (*Account, error) {
	base := opts.BaseURL
	if base == "" {
		base = defaultAPIBase
	}
	apiVer := opts.APIVer
	if apiVer == "" {
		apiVer = defaultAPIVersion
	}
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
		return nil, fmt.Errorf("key generation: %w", err)
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
		return nil, err
	}

	regURL := fmt.Sprintf("%s/%s/reg", base, apiVer)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, regURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("CF-Client-Version", defaultClientVer)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	// Registration must survive censored networks: optionally route
	// through a user proxy, and let the dialer try every system and
	// DNS-over-HTTPS answer for the API host instead of only the first
	// resolved address (a single refused or poisoned IP must not block
	// the request).
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err != nil || proxyURL.Host == "" {
			return nil, fmt.Errorf("bad proxy %q — use socks5://host:port or http://host:port", opts.Proxy)
		}
		switch proxyURL.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return nil, fmt.Errorf("unsupported proxy scheme %q — use socks5:// or http://", proxyURL.Scheme)
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}
	tr.DialContext = (&failoverDialer{}).DialContext

	client := &http.Client{Timeout: 20 * time.Second, Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registration request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registration failed (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}

	var parsed apiResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if parsed.ID == "" || parsed.Token == "" {
		return nil, fmt.Errorf("registration response missing device id/token")
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
	return acc, nil
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
