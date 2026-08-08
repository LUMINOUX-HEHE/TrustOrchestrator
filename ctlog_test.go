package trustorchestrator

// RFC 6962 tree checks: inclusion and consistency proofs round-trip for
// every index and pair of sizes up to a moderate N (brute-force, no
// random flakiness), and both verifiers reject a tampered proof.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestMerkleLogInclusionAll(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17} {
		m := NewMerkleLog()
		leaves := make([][]byte, n)
		for i := 0; i < n; i++ {
			m.Append([]byte{byte(i), 0xaa})
			leaves[i] = LeafHash([]byte{byte(i), 0xaa})
		}
		root := m.Root()
		for idx := 0; idx < n; idx++ {
			_, proof, err := m.InclusionProof(idx, n)
			if err != nil {
				t.Fatalf("n=%d idx=%d: %v", n, idx, err)
			}
			if got := VerifyInclusion(leaves[idx], idx, n, proof); !bytes.Equal(got, root) {
				t.Fatalf("n=%d idx=%d: recomputed root mismatch", n, idx)
			}
			if n > 1 && len(proof) == 0 {
				t.Fatalf("n=%d idx=%d: expected a non-empty proof", n, idx)
			}
		}
	}
}

func TestMerkleLogInclusionStaleSize(t *testing.T) {
	m := NewMerkleLog()
	for i := 0; i < 5; i++ {
		m.Append([]byte{byte(i)})
	}
	leaf := LeafHash([]byte{2})
	_, proof, err := m.InclusionProof(2, 5)
	if err != nil {
		t.Fatal(err)
	}
	// the same proof must verify against the older head too (the tree at
	// size 3 is a prefix of the tree at size 5)
	oldRoot := mth(m.leaves, 0, 3)
	_, proof3, err := m.InclusionProof(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got := VerifyInclusion(leaf, 2, 3, proof3); !bytes.Equal(got, oldRoot) {
		t.Fatal("inclusion at stale size must verify against the old head")
	}
	_ = proof
}

// VerifyInclusion must also work against stale sizes: the proof for
// (idx, size) inside a larger log verifies to that size's own root.
func TestMerkleLogInclusionStaleSize4(t *testing.T) {
	m := NewMerkleLog()
	leaves := make([][]byte, 6)
	for i := 0; i < 6; i++ {
		m.Append([]byte{byte(i), 0xaa})
		leaves[i] = LeafHash([]byte{byte(i), 0xaa})
	}
	if _, _, err := m.InclusionProof(2, 2); err == nil {
		t.Fatal("proof with idx >= size must be rejected")
	}
	for _, size := range []int{3, 4, 5, 6} {
		_, proof, err := m.InclusionProof(2, size)
		if err != nil {
			t.Fatal(err)
		}
		want := mth(leaves, 0, size)
		if got := VerifyInclusion(leaves[2], 2, size, proof); !bytes.Equal(got, want) {
			t.Fatalf("size %d: got %x want %x", size, got, want)
		}
	}
}

func TestMerkleLogConsistencyAll(t *testing.T) {
	for _, n := range []int{2, 3, 4, 5, 7, 8, 9, 15, 16, 17} {
		m := NewMerkleLog()
		for i := 0; i < n; i++ {
			m.Append([]byte{byte(i)})
		}
		newRoot := m.Root()
		for from := 1; from < n; from++ {
			oldRoot := mth(m.leaves, 0, from)
			_, _, proof, err := m.ConsistencyProof(from, n)
			if err != nil {
				t.Fatalf("n=%d from=%d: %v", n, from, err)
			}
			if !VerifyConsistency(oldRoot, newRoot, from, n, proof) {
				t.Fatalf("n=%d from=%d: consistency proof rejected", n, from)
			}
		}
	}
}

func TestMerkleLogRejectsTamperedProofs(t *testing.T) {
	m := NewMerkleLog()
	for i := 0; i < 8; i++ {
		m.Append([]byte{byte(i)})
	}
	root := m.Root()
	_, proof, err := m.InclusionProof(3, 8)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([][]byte(nil), proof...)
	tampered[0] = bytes.Repeat([]byte{0x42}, 32)
	if got := VerifyInclusion(LeafHash([]byte{3}), 3, 8, tampered); bytes.Equal(got, root) {
		t.Fatal("tampered inclusion proof must not recompute the root")
	}
	_, _, cproof, err := m.ConsistencyProof(4, 8)
	if err != nil {
		t.Fatal(err)
	}
	oldRoot := mth(m.leaves, 0, 4)
	ct := append([][]byte(nil), cproof...)
	ct[0][0] ^= 0xff
	if VerifyConsistency(oldRoot, root, 4, 8, ct) {
		t.Fatal("tampered consistency proof must fail")
	}
}

func TestMerkleLogBadArgs(t *testing.T) {
	m := NewMerkleLog()
	for i := 0; i < 4; i++ {
		m.Append([]byte{byte(i)})
	}
	if _, _, err := m.InclusionProof(7, 4); err == nil {
		t.Fatal("out-of-range index must error")
	}
	if _, _, _, err := m.ConsistencyProof(4, 4); err == nil {
		t.Fatal("from >= to must error")
	}
	if m.Root() == nil {
		t.Fatal("non-empty log must have a root")
	}
}

func TestSTHSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sth := SignSTH(priv, []byte("root"), 4, 1234)
	if !sth.Verify(pub) {
		t.Fatal("honest STH must verify")
	}
	sth.Root[0] ^= 0xff
	if sth.Verify(pub) {
		t.Fatal("tampered root must not verify")
	}
	sth.Root[0] ^= 0xff
	sth.TreeSize++
	if sth.Verify(pub) {
		t.Fatal("tampered size must not verify")
	}
	if new(SignedTreeHead).Verify(pub) {
		t.Fatal("unsigned head must fail, not verify")
	}
}

func TestGossipHappyPath(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMerkleLog()
	for i := 0; i < 5; i++ {
		m.Append([]byte{byte(i)})
	}
	ts := time.Now().Unix()
	head3 := SignSTH(priv, mth(m.leaves, 0, 3), 3, ts)
	head5 := SignSTH(priv, mth(m.leaves, 0, 5), 5, ts+1)
	_, _, proof, err := m.ConsistencyProof(3, 5)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGossipNode(pub, head3)
	ok, alarm := g.Observe(head5, proof, 3)
	if !ok || alarm {
		t.Fatalf("honest extension must be accepted (ok=%v alarm=%v)", ok, alarm)
	}
	if g.Trusted() != head5 {
		t.Fatal("trusted head must advance to the newest consistent STH")
	}
	if g.Alarm() != "" {
		t.Fatalf("no alarm expected, got %q", g.Alarm())
	}
}

func TestGossipSplitBrain(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMerkleLog()
	for i := 0; i < 5; i++ {
		m.Append([]byte{byte(i)})
	}
	headA := SignSTH(priv, mth(m.leaves, 0, 5), 5, 1)
	headB := SignSTH(priv, []byte("different root"), 5, 2)
	g := NewGossipNode(pub, headA)
	ok, alarm := g.Observe(headB, nil, 0)
	if ok || !alarm {
		t.Fatalf("same size, different root must raise the split-brain alarm (ok=%v alarm=%v)", ok, alarm)
	}
}

func TestGossipRewrite(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMerkleLog()
	for i := 0; i < 6; i++ {
		m.Append([]byte{byte(i)})
	}
	head3 := SignSTH(priv, mth(m.leaves, 0, 3), 3, 1)
	// a bigger head whose consistency proof is garbage: the log claims
	// history it cannot prove.
	head6 := SignSTH(priv, mth(m.leaves, 0, 6), 6, 2)
	g := NewGossipNode(pub, head3)
	ok, alarm := g.Observe(head6, [][]byte{[]byte("garbage")}, 3)
	if ok || !alarm {
		t.Fatalf("unprovable extension must alarm (ok=%v alarm=%v)", ok, alarm)
	}
	if g.Alarm() == "" {
		t.Fatal("alarm message must be set")
	}
	// a stale report from a peer that is simply behind: no alarm.
	head2 := SignSTH(priv, mth(m.leaves, 0, 2), 2, 3)
	ok, alarm = g.Observe(head2, nil, 0)
	if !ok || alarm {
		t.Fatalf("behind peer must not alarm (ok=%v alarm=%v)", ok, alarm)
	}
	if g.Trusted() != head3 {
		t.Fatal("a behind report must not regress the trusted head")
	}
	// a tampered STH from an attacker with no log key: ignored silently.
	bad := SignSTH(priv, []byte("x"), 9, 9)
	bad.Signature = nil
	if ok, alarm := g.Observe(bad, nil, 0); ok || alarm {
		t.Fatalf("unsigned STH must be ignored (ok=%v alarm=%v)", ok, alarm)
	}
}
