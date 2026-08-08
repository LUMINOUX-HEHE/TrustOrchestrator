package trustorchestrator

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
)

func hexEnc(b []byte) string { return hex.EncodeToString(b) }

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func mustSplit(t *testing.T, n, k int) []*FrostSigner {
	t.Helper()
	signers, _, err := FrostSplit(make([]byte, 32), n, k)
	if err != nil {
		t.Fatal(err)
	}
	return signers
}

// The whole FROST layer rests on one property: the aggregated signature is
// a plain Ed25519 signature. If the group math, binding factors, or
// aggregation drift, this fails.
func TestFrostSelfCheck(t *testing.T) {
	if err := frostSelfCheck(); err != nil {
		t.Fatal(err)
	}
}

// Known seed -> known pubkey: the group key must be exactly the Ed25519
// public key of the dealer seed (interop with crypto/ed25519).
func TestFrostGroupKeyMatchesSeed(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 42
	signers, groupPub, err := FrostSplit(seed, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	want := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if string(groupPub) != string(want) {
		t.Fatalf("group pub %x != stdlib %x", groupPub, want)
	}
	for _, s := range signers {
		if string(s.GroupPub) != string(want) {
			t.Fatalf("signer %s carries wrong group pub", s.ID)
		}
	}
}

// Share file round-trip: write, load, verify self-consistency, sign.
func TestFrostShareFileRoundTrip(t *testing.T) {
	seed := make([]byte, 32)
	signers, groupPub, err := FrostSplit(seed, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	f := &FrostShareFile{
		ID: signers[0].ID, X: 1, Y: signers[0].Share,
		GroupPub: signers[0].GroupPub, PubShare: signers[0].PubShare,
	}
	for _, c := range signers[0].VK {
		f.VK = append(f.VK, hexEnc(encode(c)))
	}
	raw, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var back FrostShareFile
	if err := jsonUnmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	s, err := back.Signer()
	if err != nil {
		t.Fatal(err)
	}
	// tampered share file must fail load
	bad := back
	bad.Y = new(big.Int).Add(bad.Y, big.NewInt(1))
	if _, err := bad.Signer(); err == nil {
		t.Fatal("tampered share must fail signer load")
	}
	m := []byte("file round-trip")
	sig, err := FrostRound(groupPub, []*FrostSigner{s, signers[1], signers[2]}, m)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(groupPub, m, sig) {
		t.Fatal("signature from loaded share file fails verification")
	}
}

// Two different messages signed in sequence: nonce discipline is per
// signer instance; fresh instances must be used per message.
func TestFrostTwoMessages(t *testing.T) {
	_, groupPub, err := FrostSplit(make([]byte, 32), 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	signers := mustSplit(t, 5, 3)
	sig1, err := FrostRound(groupPub, signers[:3], []byte("msg one"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(groupPub, []byte("msg one"), sig1) {
		t.Fatal("sig1 bad")
	}
	// fresh signers for msg two (reuse would be a nonce-reuse bug)
	sig2, err := FrostRound(groupPub, mustSplit(t, 5, 3)[:3], []byte("msg two"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(groupPub, []byte("msg two"), sig2) {
		t.Fatal("sig2 bad")
	}
	if string(sig1) == string(sig2) {
		t.Fatal("signatures must differ")
	}
}

// Aggregator must reject a share that doesn't match its commitment even
// when the scalar algebra would sum fine.
func TestFrostRejectsLazyShare(t *testing.T) {
	_, groupPub, err := FrostSplit(make([]byte, 32), 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	signers := mustSplit(t, 5, 3)
	agg := NewFrostAggregator(groupPub, map[string]ed25519.PublicKey{})
	for _, s := range signers[:3] {
		p, err := decodePoint(s.PubShare)
		if err != nil {
			t.Fatal(err)
		}
		agg.pubs[s.ID] = p
	}
	m := []byte("audit")
	commits := map[string][]byte{}
	for _, s := range signers[:3] {
		de, err := s.Commit()
		if err != nil {
			t.Fatal(err)
		}
		commits[s.ID] = de
	}
	for id, de := range commits {
		if err := agg.AddCommit(id, de); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := agg.Challenge(m); err != nil {
		t.Fatal(err)
	}
	// fake share from an honest commitment
	if err := agg.AddShare(signers[0].ID, make([]byte, 32)); err == nil {
		t.Fatal("bogus share must be rejected")
	}
}

// DKG group key must be stable across two ceremonies of the same config
// only in length, not value; and its signatures verify (already covered in
// self-check). Here: every DKG participant's share file verifies.
func TestDkgShareFilesVerify(t *testing.T) {
	signers, groupPub, err := DkgCeremony(5, 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range signers {
		f := &FrostShareFile{
			ID: s.ID, X: memberX(s.ID), Y: s.Share,
			GroupPub: s.GroupPub, PubShare: s.PubShare,
		}
		gv := make([]DkgCommitJSON, len(s.GlobalVK))
		copy(gv, s.GlobalVK)
		f.GlobalVK = gv
		raw, err := f.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		var back FrostShareFile
		if err := jsonUnmarshal(raw, &back); err != nil {
			t.Fatal(err)
		}
		signer, err := back.Signer()
		if err != nil {
			t.Fatalf("share %s failed load/verify: %v", s.ID, err)
		}
		if string(signer.GroupPub) != string(groupPub) {
			t.Fatalf("share %s group pub mismatch", s.ID)
		}
	}
}

// TestFrostDifferentSubsets: any 3 of 5 signers produce the same valid
// signature verifiability (not the same bytes — different nonces).
func TestFrostSubsets(t *testing.T) {
	m := []byte("subset test")
	for _, idx := range [][]int{{0, 1, 2}, {0, 2, 4}, {2, 3, 4}} {
		signers, groupPub, err := FrostSplit(make([]byte, 32), 5, 3)
		if err != nil {
			t.Fatal(err)
		}
		var set []*FrostSigner
		for _, i := range idx {
			set = append(set, signers[i])
		}
		sig, err := FrostRound(groupPub, set, m)
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(groupPub, m, sig) {
			t.Fatal("subset signature invalid")
		}
	}
}
