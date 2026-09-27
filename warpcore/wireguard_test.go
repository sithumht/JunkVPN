package warpcore

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestKDFLengths(t *testing.T) {
	ck := make([]byte, 32)
	input := make([]byte, 32)
	next, key, err := kdf(ck, input)
	if err != nil {
		t.Fatalf("kdf: %v", err)
	}
	if len(next) != 32 || len(key) != 32 {
		t.Fatalf("kdf returned %d/%d bytes, want 32/32", len(next), len(key))
	}
	if string(next) == string(key) {
		t.Fatal("chain key and message key must differ")
	}
}

func TestAEADSealSizeAndNonce(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	sealed, err := aeadSeal(key, 1, []byte("ad"), []byte("plaintext-16-bytes!"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(sealed) != len("plaintext-16-bytes!")+chacha20poly1305.Overhead {
		t.Fatalf("sealed length %d", len(sealed))
	}
}

func TestBuildInitiationShape(t *testing.T) {
	id, err := newIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	msg, st, err := buildInitiation(id, warpPeerPublicKey, 0x11223344, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if st == nil || len(st.ck) != 32 || len(st.h) != 32 || st.eph == nil || st.id != id {
		t.Fatal("handshake state not preserved for response validation")
	}
	if len(msg) != initiationSize {
		t.Fatalf("initiation is %d bytes, want %d", len(msg), initiationSize)
	}
	if got := binary.LittleEndian.Uint32(msg[0:]); got != 1 {
		t.Fatalf("type = %d, want 1", got)
	}
	if got := binary.LittleEndian.Uint32(msg[4:]); got != 0x11223344 {
		t.Fatalf("sender index = %#x", got)
	}

	// mac1 must be reproducible with an independent keyed BLAKE2s call.
	peerRaw, err := base64.StdEncoding.DecodeString(warpPeerPublicKey)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	macKey := blake2s.Sum256(append([]byte(labelMAC1), peerRaw...))
	want, err := keyedMAC(macKey[:], msg[0:116])
	if err != nil {
		t.Fatalf("mac: %v", err)
	}
	if string(msg[116:132]) != string(want) {
		t.Fatal("mac1 mismatch")
	}
	if string(msg[132:148]) != strings.Repeat("\x00", 16) {
		t.Fatal("mac2 must be zero without a cookie")
	}

	// A different sender index must change the message.
	other, _, err := buildInitiation(id, warpPeerPublicKey, 0x55667788, time.Now())
	if err != nil {
		t.Fatalf("build 2: %v", err)
	}
	if string(msg) == string(other) {
		t.Fatal("sender index not reflected in message")
	}
}

func TestParseResponse(t *testing.T) {
	sender := uint32(0xaabbccdd)
	ok := make([]byte, responseSize)
	binary.LittleEndian.PutUint32(ok[0:], 2)
	binary.LittleEndian.PutUint32(ok[4:], 0x11223344) // responder's own index
	binary.LittleEndian.PutUint32(ok[8:], sender)     // our index echoed back
	if err := parseResponse(ok, sender); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}

	wrong := append([]byte{}, ok...)
	binary.LittleEndian.PutUint32(wrong[8:], sender+1)
	if err := parseResponse(wrong, sender); err == nil {
		t.Fatal("mismatched index accepted")
	}
	// The responder's own index must not be mistaken for ours.
	atOffset4 := append([]byte{}, ok...)
	binary.LittleEndian.PutUint32(atOffset4[4:], sender)
	binary.LittleEndian.PutUint32(atOffset4[8:], 0xdeadbeef)
	if err := parseResponse(atOffset4, sender); err == nil {
		t.Fatal("index at wrong offset accepted")
	}

	short := ok[:20]
	if err := parseResponse(short, sender); err == nil {
		t.Fatal("short response accepted")
	}

	wrongType := append([]byte{}, ok...)
	binary.LittleEndian.PutUint32(wrongType[0:], 3)
	if err := parseResponse(wrongType, sender); err == nil {
		t.Fatal("cookie reply accepted as handshake")
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	id, err := newIdentity()
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(id.priv.Bytes())
	restored, err := identityFromPrivate(b64)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if string(restored.pub) != string(id.pub) {
		t.Fatal("public key mismatch after restore")
	}
	if _, err := identityFromPrivate("not-base64!!"); err == nil {
		t.Fatal("invalid key accepted")
	}
}
