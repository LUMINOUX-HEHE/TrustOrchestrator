package trustorchestrator

// Verified resharing: rotate the council without touching the group key.
// Old holders re-split their shares (Feldman commitments published); a
// rotated-in member sums the verified sub-shares into a point on a fresh
// polynomial with the SAME secret. Removed members' old shares are dead.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestResharedMembership(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	old, group := testSigners(t, seed, 5, 3) // M1..M5, 3-of-5
	oldSet := []int{1, 2, 3}                 // the members who re-share
newSet := []int{1, 2, 3, 6, 7, 8, 9, 10, 11} // rotate out M4, M5; rotate in M6..M11

	commits := map[string]*ReshareCommit{}
	subs := map[string]map[int]*big.Int{}
	for _, o := range old[:3] {
		c, s, err := ReshareSplit(o.ID, o.Share, oldSet, newSet, 3)
		if err != nil {
			t.Fatal(err)
		}
		commits[o.ID] = c
		subs[o.ID] = s
	}
	combine := func(id string, idx int) *FrostSigner {
		t.Helper()
		got := map[string]*big.Int{}
		for from, s := range subs {
			got[from] = s[idx]
		}
		s, err := ReshareCombine(id, idx, commits, got, group)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	m2, m3, m6, m7, m8, m9 := combine("M2", 2), combine("M3", 3), combine("M6", 6),
		combine("M7", 7), combine("M8", 8), combine("M9", 9)
	m10, m11 := combine("M10", 10), combine("M11", 11)

	// The group key is UNCHANGED: a quorum of rotated-in members verifies
	// under the ORIGINAL group key.
	m := []byte("recovery manifest after rotation")
	sig, err := FrostRound(group, []*FrostSigner{m2, m7, m9}, m)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(group, m, sig) {
		t.Fatal("post-rotation signature fails under the unchanged group key")
	}
	// A refreshed old member also signs (disjoint triple: nonces single-use).
	sig2, err := FrostRound(group, []*FrostSigner{m3, m6, m8}, m)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(group, m, sig2) {
		t.Fatal("refreshed old member cannot sign")
	}

	// Removed M4's OLD share lies on the old polynomial — a quorum mixing
	// it with new shares does not produce a verifiable signature.
	gone := old[3] // index 4, pre-rotation share
	sig3, err := FrostRound(group, []*FrostSigner{gone, m10, m11}, m)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(group, m, sig3) {
		t.Fatal("removed member's stale share must not sign the new group")
	}

	// Share file round trip: the summed commitments let the rotated-in
	// member verify its file on load.
	file := FrostShareFile{ID: m6.ID, X: m6.X, Y: m6.Share,
		GroupPub: m6.GroupPub, PubShare: m6.PubShare, VK: hexPts(m6.VK)}
	loaded, err := file.Signer()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.PubShare, m6.PubShare) {
		t.Fatal("rotated-in share file does not round trip")
	}
}

// TestReshareRejectsTamper: one substituted sub-share fails the combine.
func TestReshareRejectsTamper(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 3
	old, group := testSigners(t, seed, 5, 3)
	oldSet := []int{1, 2, 3}
	newSet := []int{1, 2, 3, 6}
	commits := map[string]*ReshareCommit{}
	subs := map[string]map[int]*big.Int{}
	for _, o := range old[:3] {
		c, s, err := ReshareSplit(o.ID, o.Share, oldSet, newSet, 3)
		if err != nil {
			t.Fatal(err)
		}
		commits[o.ID] = c
		subs[o.ID] = s
	}
	subs["M1"][6] = new(big.Int).Add(subs["M1"][6], big.NewInt(1)) // tamper
	got := map[string]*big.Int{}
	for from, s := range subs {
		got[from] = s[6]
	}
	if _, err := ReshareCombine("M6", 6, commits, got, group); err == nil {
		t.Fatal("tampered sub-share must fail verification")
	}
}

func hexPts(pts []point) []string {
	out := make([]string, len(pts))
	for i, p := range pts {
		out[i] = hex.EncodeToString(encode(p))
	}
	return out
}