package warpcore

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// ConfigOptions tunes tunnel configuration generation.
type ConfigOptions struct {
	Endpoint string `json:"endpoint,omitempty"`
	DNS      string `json:"dns,omitempty"`
	MTU      int    `json:"mtu,omitempty"`
	Allowed  string `json:"allowedIps,omitempty"`
	// AmneziaWG obfuscation parameters.
	Jc   int `json:"jc,omitempty"`
	Jmin int `json:"jmin,omitempty"`
	Jmax int `json:"jmax,omitempty"`
	S1   int `json:"s1,omitempty"`
	S2   int `json:"s2,omitempty"`
}

const (
	defaultMTU     = 1280
	defaultDNS     = "1.1.1.1, 2606:4700:4700::1111"
	defaultAllowed = "0.0.0.0/0, ::/0"
)

func (o *ConfigOptions) applyDefaults() {
	if o.DNS == "" {
		o.DNS = defaultDNS
	}
	if o.MTU <= 0 {
		o.MTU = defaultMTU
	}
	if o.Allowed == "" {
		o.Allowed = defaultAllowed
	}
	if o.Jc <= 0 {
		o.Jc = 4
	}
	if o.Jmin <= 0 {
		o.Jmin = 40
	}
	if o.Jmax <= 0 {
		o.Jmax = 70
	}
}

// BuildConfig renders a ready-to-import tunnel configuration.
// kind is one of "wireguard", "amnezia" or "endpoint".
func BuildConfig(kind string, accountJSON string, optsJSON string) (string, error) {
	var acc Account
	if err := json.Unmarshal([]byte(accountJSON), &acc); err != nil {
		return "", fmt.Errorf("bad account json: %w", err)
	}
	if acc.PrivateKey == "" || acc.PeerPublicKey == "" {
		return "", fmt.Errorf("account is missing key material")
	}
	var opts ConfigOptions
	if optsJSON != "" {
		if err := json.Unmarshal([]byte(optsJSON), &opts); err != nil {
			return "", fmt.Errorf("bad config options: %w", err)
		}
	}
	opts.applyDefaults()

	if kind == "endpoint" {
		if opts.Endpoint == "" {
			return "", fmt.Errorf("no endpoint selected")
		}
		return opts.Endpoint, nil
	}

	endpoint := opts.Endpoint
	if endpoint == "" {
		endpoint = fallbackEndpoint(acc)
	}
	if endpoint == "" {
		return "", fmt.Errorf("no endpoint available; run a scan first")
	}

	address := acc.AddressV4
	if acc.AddressV6 != "" {
		address += ", " + acc.AddressV6
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", acc.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", address)
	fmt.Fprintf(&b, "DNS = %s\n", opts.DNS)
	fmt.Fprintf(&b, "MTU = %d\n", opts.MTU)

	if kind == "amnezia" {
		fmt.Fprintf(&b, "Jc = %d\n", opts.Jc)
		fmt.Fprintf(&b, "Jmin = %d\n", opts.Jmin)
		fmt.Fprintf(&b, "Jmax = %d\n", opts.Jmax)
		fmt.Fprintf(&b, "S1 = %d\n", opts.S1)
		fmt.Fprintf(&b, "S2 = %d\n", opts.S2)
	} else if kind != "wireguard" {
		return "", fmt.Errorf("unknown config kind %q", kind)
	}

	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", acc.PeerPublicKey)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", opts.Allowed)
	fmt.Fprintf(&b, "Endpoint = %s\n", endpoint)
	return b.String(), nil
}

// fallbackEndpoint prefers the registration endpoint the API handed out.
func fallbackEndpoint(acc Account) string {
	ep := acc.PeerEndpoint
	if ep == "" {
		return ""
	}
	if _, _, err := parseEndpoint(ep); err == nil {
		return ep
	}
	// Bare host: attach the standard WARP WireGuard port.
	if ip := net.ParseIP(ep); ip != nil {
		return net.JoinHostPort(ep, "2408")
	}
	return ""
}
