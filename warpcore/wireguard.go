package warpcore

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// WARP peer identity used by consumer Cloudflare WARP endpoints.
const warpPeerPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

const (
	initiationSize = 148
	responseSize   = 92
	noiseName      = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	noisePrologue  = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	labelMAC1      = "mac1----"
	labelMAC2      = "mac2----"
)

var errHandshakeTimeout = errors.New("no handshake response")

// wgIdentity is the local Curve25519 identity used for handshake probes.
type wgIdentity struct {
	priv *ecdh.PrivateKey
	pub  []byte
}

// newIdentity derives a fresh Curve25519 identity.
func newIdentity() (*wgIdentity, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &wgIdentity{priv: k, pub: k.PublicKey().Bytes()}, nil
}

// identityFromPrivate reconstructs an identity from a base64 private key.
func identityFromPrivate(b64 string) (*wgIdentity, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("invalid private key")
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, err
	}
	return &wgIdentity{priv: k, pub: k.PublicKey().Bytes()}, nil
}

// hmacB2s computes HMAC over BLAKE2s-256, WireGuard's KDF primitive.
func hmacB2s(key []byte, data ...[]byte) []byte {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	for _, d := range data {
		_, _ = mac.Write(d)
	}
	return mac.Sum(nil)
}

// kdf mirrors WireGuard's KDF2: it consumes input into the chain key and
// yields the AEAD key for the next step.
func kdf(ck, input []byte) (nextCK, key []byte, err error) {
	prk := hmacB2s(ck, input)
	nextCK = hmacB2s(prk, []byte{0x01})
	key = hmacB2s(prk, nextCK, []byte{0x02})
	return nextCK, key, nil
}

// kdf1 mirrors WireGuard's single-output KDF (used to mix data such as the
// ephemeral public key into the chain key).
func kdf1(ck, input []byte) []byte {
	return hmacB2s(hmacB2s(ck, input), []byte{0x01})
}

// tai64n renders the 12 byte TAI64N timestamp WireGuard encrypts into the
// initiation message: big endian seconds (with era offset) + nanoseconds
// truncated to a coarse resolution like upstream does.
func tai64n(t time.Time) [12]byte {
	var out [12]byte
	const base = uint64(0x400000000000000a)
	const whitenerMask = uint32(0x1000000 - 1)
	binary.BigEndian.PutUint64(out[0:], base+uint64(t.Unix()))
	binary.BigEndian.PutUint32(out[8:], uint32(t.Nanosecond())&^whitenerMask)
	return out
}

func mixHash(h, data []byte) []byte {
	sum := blake2s.Sum256(append(append([]byte{}, h...), data...))
	return sum[:]
}

// keyedMAC computes keyed BLAKE2s with a 128 bit output, which is what
// WireGuard uses for mac1/mac2 fields.
func keyedMAC(key, data []byte) ([]byte, error) {
	mac, err := blake2s.New128(key)
	if err != nil {
		return nil, err
	}
	if _, err := mac.Write(data); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

// aeadSeal encrypts with WireGuard's nonce convention: a 96 bit little
// endian counter with the upper 32 bits zero.
func aeadSeal(key []byte, counter uint64, ad, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	return aead.Seal(nil, nonce, plaintext, ad), nil
}

// buildInitiation crafts a WireGuard handshake initiation (message type 1)
// for the given identity towards the well known WARP peer key.
func buildInitiation(id *wgIdentity, peerPubB64 string, senderIndex uint32, now time.Time) ([]byte, error) {
	peerRaw, err := base64.StdEncoding.DecodeString(peerPubB64)
	if err != nil || len(peerRaw) != 32 {
		return nil, fmt.Errorf("bad peer public key")
	}
	peerPub, err := ecdh.X25519().NewPublicKey(peerRaw)
	if err != nil {
		return nil, err
	}

	ckSum := blake2s.Sum256([]byte(noiseName))
	ck := ckSum[:]
	h := ck
	h = mixHash(h, []byte(noisePrologue))
	h = mixHash(h, peerRaw)

	// Ephemeral key for this attempt.
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ephPub := eph.PublicKey().Bytes()
	h = mixHash(h, ephPub)
	ck = kdf1(ck[:], ephPub)

	// es: key for the encrypted static public key.
	shared, err := eph.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	ck, k, err := kdf(ck, shared)
	if err != nil {
		return nil, err
	}

	staticEnc, err := aeadSeal(k, 0, h, id.pub)
	if err != nil {
		return nil, err
	}
	h = mixHash(h, staticEnc)

	// ss: fresh key for the encrypted timestamp (nonce restarts at zero).
	sharedStatic, err := id.priv.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	ck, kStatic, err := kdf(ck, sharedStatic)
	if err != nil {
		return nil, err
	}
	ts := tai64n(now)
	tsEnc, err := aeadSeal(kStatic, 0, h, ts[:])
	if err != nil {
		return nil, err
	}
	h = mixHash(h, tsEnc)
	_ = ck // session keys are not needed for latency measurement
	_ = h

	msg := make([]byte, initiationSize)
	binary.LittleEndian.PutUint32(msg[0:], 1) // type: initiation
	binary.LittleEndian.PutUint32(msg[4:], senderIndex)
	copy(msg[8:], ephPub)
	copy(msg[40:], staticEnc)
	copy(msg[88:], tsEnc)

	mac1Key := blake2s.Sum256(append(append([]byte{}, labelMAC1...), peerRaw...))
	mac1, err := keyedMAC(mac1Key[:], msg[0:116])
	if err != nil {
		return nil, err
	}
	copy(msg[116:], mac1)
	// mac2 stays zero; a cookie is only required under heavy load.
	mac2Key := blake2s.Sum256(append(append([]byte{}, labelMAC2...), peerRaw...))
	if _, err := keyedMAC(mac2Key[:], msg[0:132]); err != nil {
		return nil, err
	}
	return msg, nil
}

// parseResponse validates a handshake response (message type 2) and confirms
// it answers the initiation we sent. The response layout is
// type(4) | responder's sender index(4) | our index echoed as receiver(4) | ...
func parseResponse(buf []byte, senderIndex uint32) error {
	if len(buf) < responseSize {
		return fmt.Errorf("short response: %d bytes", len(buf))
	}
	if binary.LittleEndian.Uint32(buf[0:]) != 2 {
		return fmt.Errorf("unexpected message type %d", binary.LittleEndian.Uint32(buf[0:]))
	}
	if binary.LittleEndian.Uint32(buf[8:]) != senderIndex {
		return errors.New("receiver index mismatch")
	}
	return nil
}

// wgProbe performs handshake attempts against a single UDP endpoint and
// returns the aggregate statistics. It proves a live WireGuard peer and
// measures the real round trip time of the tunnel path.
func wgProbe(ctx context.Context, addr string, id *wgIdentity, timeout time.Duration, attempts int) (*probeStats, error) {
	return wgProbeTo(ctx, addr, id, warpPeerPublicKey, timeout, attempts)
}

// wgProbeTo is wgProbe with an explicit responder public key, used by tests
// to validate the handshake against a local WireGuard responder.
func wgProbeTo(ctx context.Context, addr string, id *wgIdentity, peerPubB64 string, timeout time.Duration, attempts int) (*probeStats, error) {
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	if attempts <= 0 {
		attempts = 1
	}
	stats := &probeStats{}

	// Successive attempts need breathing room: WireGuard responders drop
	// initiations arriving faster than their anti-flood window and reject
	// identical coarse-grained timestamps as replays.
	const attemptInterval = 50 * time.Millisecond

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return stats, fmt.Errorf("resolve %s: %w", addr, err)
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return stats, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	buf := make([]byte, 512)
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(attemptInterval):
			}
		}
		if ctx.Err() != nil {
			stats.add(0, ctx.Err())
			break
		}
		senderIndex := uint32(0)
		if _, err := rand.Read(buf[:4]); err != nil {
			stats.add(0, err)
			break
		}
		senderIndex = binary.LittleEndian.Uint32(buf[:4])

		msg, err := buildInitiation(id, peerPubB64, senderIndex, time.Now())
		if err != nil {
			stats.add(0, err)
			break
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		start := time.Now()
		if _, err := conn.Write(msg); err != nil {
			stats.add(0, err)
			continue
		}
		n, err := conn.Read(buf)
		if err != nil {
			stats.add(0, err)
			continue
		}
		rtt := time.Since(start)
		if err := parseResponse(buf[:n], senderIndex); err != nil {
			stats.add(0, err)
			continue
		}
		stats.add(rtt, nil)
	}
	return stats, ctx.Err()
}
