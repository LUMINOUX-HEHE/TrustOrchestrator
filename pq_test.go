package trustorchestrator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// TestPQHybridChannel: a client/server handshake over wire-form public
// keys — client encapsulate + ciphertext, server decapsulate — derives
// the SAME session key, and sealed frames round-trip while a single
// flipped bit is rejected by AES-GCM auth.
func TestPQHybridChannel(t *testing.T) {
	alice, err := NewPQKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewPQKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	aPub, bPub := alice.Public(), bob.Public()

	ct, aKey, err := PQClientShared(alice, &bPub)
	if err != nil {
		t.Fatal(err)
	}
	bKey, err := PQServerShared(bob, &aPub, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aKey, bKey) {
		t.Fatalf("session keys differ:\n alice=%x\n bob  =%x", aKey, bKey)
	}

	sealed, err := pqSeal(aKey, []byte("vote{epoch:7,index:41}"))
	if err != nil {
		t.Fatal(err)
	}
	open, err := pqOpen(bKey, sealed)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(open) != "vote{epoch:7,index:41}" {
		t.Fatalf("roundtrip changed payload: %q", open)
	}

	sealed[len(sealed)-1] ^= 0x01
	if _, err := pqOpen(bKey, sealed); err == nil {
		t.Fatal("tampered frame opened: AES-GCM auth must reject it")
	}

	if _, _, err := PQClientShared(alice, nil); err == nil {
		t.Fatal("nil peer accepted")
	}
}

// TestMLDSASlotPolicy pins the reserved dual-signature envelope until
// crypto/ml-dsa lands in the public stdlib (absent in Go 1.26.4 — checked
// GOROOT). Wire the moment it's public: sign the second half, put it in
// Sigs.MLDSA, and make Sigs.Verify require BOTH members when MLDSA is set.
// This test then flips from pinning-current-behaviour to proving the wire.
func TestMLDSASlotPolicy(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("epoch-handoff-42")
	var s Sigs
	if err := s.Sign(priv, msg); err != nil {
		t.Fatal(err)
	}
	if len(s.MLDSA) != 0 {
		t.Fatal("ML-DSA slot must be empty while stdlib crypto/ml-dsa is not public")
	}
	if !s.Verify(pub, msg) {
		t.Fatal("ed25519-only envelope must verify today")
	}
	// A filled PQ slot must be rejected, not silently downgraded to
	// ed25519-only (a PQ-only chain is never accepted as verified).
	s.MLDSA = []byte("dirty-slot")
	if s.Verify(pub, msg) {
		t.Fatal("PQ-only chain must never verify without a PQ verifier")
	}
	s.MLDSA = nil
	if s.Verify(pub, []byte("other")) {
		t.Fatal("wrong message verified")
	}
}

// TestPQServerRejectsGarbageCiphertext: a random ciphertext must fail
// decapsulation, not silently produce a wrong key.
func TestPQServerRejectsGarbageCiphertext(t *testing.T) {
	server, err := NewPQKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	evil, err := NewPQKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ePub := evil.Public()
	if _, err := PQServerShared(server, &ePub, []byte("not a real KEM ciphertext")); err == nil {
		t.Fatal("garbage ciphertext accepted")
	}
}
