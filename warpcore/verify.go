package warpcore

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Verify outcome codes carried in the result JSON.
const (
	VerifyOK          = "ok"           // authenticated handshake with the account identity
	VerifyNoResponse  = "no_response"  // nothing came back (filtered UDP, or peer unknown)
	VerifyBadResponse = "bad_response" // packets arrived but did not authenticate
	VerifyNetwork     = "network"      // could not reach the endpoint at all
	VerifyNoAccount   = "no_account"   // no usable WARP account identity
	VerifyBadEndpoint = "bad_endpoint" // endpoint string is malformed
)

// VerifyResult reports whether a WireGuard endpoint completed an
// authenticated handshake with the given account identity.
type VerifyResult struct {
	OK       bool    `json:"ok"`
	Code     string  `json:"code"`
	RttMs    float64 `json:"rttMs"`
	MAC1OK   bool    `json:"mac1"`
	Attempts int     `json:"attempts"`
	Detail   string  `json:"detail,omitempty"`
}

// VerifyEndpoint sends real WireGuard handshakes to endpoint using the
// registered WARP account's keys. A successful result proves the endpoint
// holds the WARP peer private key and recognizes this account: WireGuard
// responders silently drop initiations from keys that were never
// registered, so a valid response is an end-to-end proof of the whole
// chain — network path, peer identity and account membership.
//
// It returns a VerifyResult as JSON. endpoint is "host:port", accountJSON
// is the stored account, timeoutMs bounds each attempt and attempts is how
// many handshakes to try (capped at 10).
func VerifyEndpoint(endpoint, accountJSON string, timeoutMs, attempts int64) (string, error) {
	result := &VerifyResult{Code: VerifyOK}

	fail := func(code, detail string) (string, error) {
		result.OK = false
		result.Code = code
		result.Detail = detail
		out, err := json.Marshal(result)
		if err != nil {
			return "", err
		}
		return string(out), nil
	}

	if _, _, err := parseEndpoint(endpoint); err != nil {
		return fail(VerifyBadEndpoint, err.Error())
	}
	var acc Account
	if accountJSON == "" {
		return fail(VerifyNoAccount, "no WARP account registered yet")
	}
	if err := json.Unmarshal([]byte(accountJSON), &acc); err != nil {
		return fail(VerifyNoAccount, "stored account is unreadable: "+err.Error())
	}
	if acc.PrivateKey == "" {
		return fail(VerifyNoAccount, "account has no private key")
	}
	id, err := identityFromPrivate(acc.PrivateKey)
	if err != nil {
		return fail(VerifyNoAccount, "account key invalid: "+err.Error())
	}
	peerPub := acc.PeerPublicKey
	if peerPub == "" {
		peerPub = warpPeerPublicKey
	}

	if timeoutMs <= 0 {
		timeoutMs = 2000
	}
	if timeoutMs < 100 {
		timeoutMs = 100
	}
	if timeoutMs > 30000 {
		timeoutMs = 30000
	}
	if attempts <= 0 {
		attempts = 2
	}
	if attempts > 10 {
		attempts = 10
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return fail(VerifyNetwork, "cannot resolve "+endpoint+": "+err.Error())
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fail(VerifyNetwork, err.Error())
	}
	defer conn.Close()

	const attemptInterval = 50 * time.Millisecond // above the responder's flood window
	var (
		gotPacket   bool
		lastAuthErr string
		networkErr  string
		rttTotal    time.Duration
		verified    int
	)

	buf := make([]byte, 512)
	for i := int64(0); i < attempts; i++ {
		if i > 0 {
			time.Sleep(attemptInterval)
		}
		var idxBytes [4]byte
		if _, err := rand.Read(idxBytes[:]); err != nil {
			return fail(VerifyNetwork, err.Error())
		}
		senderIndex := binary.LittleEndian.Uint32(idxBytes[:])

		msg, st, err := buildInitiation(id, peerPub, senderIndex, time.Now())
		if err != nil {
			return fail(VerifyNoAccount, err.Error())
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		start := time.Now()
		if _, err := conn.Write(msg); err != nil {
			networkErr = err.Error()
			continue
		}
		n, err := conn.Read(buf)
		if err != nil {
			// Timeouts are the common case: filtered UDP or an endpoint
			// that does not know our key. Connected UDP sockets also
			// surface ICMP errors (closed port on a live host) here.
			if isTimeout(err) {
				continue
			}
			networkErr = err.Error()
			continue
		}
		gotPacket = true
		if err := validateResponse(buf[:n], senderIndex, st); err != nil {
			lastAuthErr = err.Error()
			continue
		}
		rttTotal += time.Since(start)
		verified++
		result.MAC1OK = responseMAC1(buf[:n], id)
	}

	switch {
	case verified > 0:
		result.OK = true
		result.Code = VerifyOK
		result.Attempts = verified
		result.RttMs = float64(rttTotal) / float64(verified) / float64(time.Millisecond)
		result.Detail = "authenticated handshake accepted by peer"
	case gotPacket:
		result.Code = VerifyBadResponse
		result.Detail = "response did not authenticate: " + lastAuthErr
	case networkErr != "":
		result.Code = VerifyNetwork
		result.Detail = networkErr
	default:
		result.Code = VerifyNoResponse
		result.Detail = "no handshake response — UDP may be filtered on this network, " +
			"or the endpoint does not recognize this account's key"
	}

	out, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// isTimeout reports whether err is a deadline expiry rather than a
// transport-level failure such as an ICMP unreachable.
func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// String renders the result for command line diagnostics.
func (r *VerifyResult) String() string {
	return fmt.Sprintf("verify %s: ok=%v rtt=%.1fms mac1=%v attempts=%d (%s)",
		r.Code, r.OK, r.RttMs, r.MAC1OK, r.Attempts, r.Detail)
}
