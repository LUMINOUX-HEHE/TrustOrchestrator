package trustorchestrator

// ctlog.go — certificate-transparency-style append-only Merkle log
// (RFC 6962 tree shape, no third-party code). The log is a SHA-256
// binary Merkle tree over submitted entries; the head is a hash of the
// whole history, and anyone holding a leaf + its inclusion proof can
// verify the entry was in the log at that head without trusting us.
// The gateway hosts one log per org and derives it from the org's signed
// timeline: leaves are the event hashes, so the log's integrity rides on
// the same signatures the chain already carries (the events are signed
// before they are ever in the tree).
// ponytail: the tree is rebuilt from the timeline on demand (O(n) per
// read); build an incremental tree when an org outgrows that.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// MerkleLog is the in-memory RFC 6962 tree. Leaves are hashed on Append;
// proofs are computed from the stored leaf hashes.
type MerkleLog struct {
	leaves [][]byte // leaf hashes, in append order
}

// NewMerkleLog starts an empty log.
func NewMerkleLog() *MerkleLog { return &MerkleLog{} }

// LeafHash is the CT leaf hash: sha256(0x00 || entry).
func LeafHash(entry []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(entry)
	return h.Sum(nil)
}

func nodeHash(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// Append logs one raw entry and returns its index.
func (m *MerkleLog) Append(entry []byte) int {
	m.leaves = append(m.leaves, LeafHash(entry))
	return len(m.leaves) - 1
}

// Size is the number of entries.
func (m *MerkleLog) Size() int { return len(m.leaves) }

// Hashes exposes the leaf hashes in order (audit/debug surface).
func (m *MerkleLog) Hashes() [][]byte { return m.leaves }

// Root is the current tree head (empty log → nil).
func (m *MerkleLog) Root() []byte { return mth(m.leaves, 0, len(m.leaves)) }

// mth is RFC 6962 §2.1: the Merkle tree hash of leaves [i, j).
func mth(leaves [][]byte, i, j int) []byte {
	if j <= i {
		return nil // empty log: no tree hash (guards the empty org)
	}
	if j-i == 1 {
		return leaves[i]
	}
	k := splitPoint(j - i)
	return nodeHash(mth(leaves, i, i+k), mth(leaves, i+k, j))
}

// splitPoint returns the largest power of two strictly below n.
func splitPoint(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// InclusionProof returns the sibling hashes along the path from leaf idx
// to the root at the given tree size.
func (m *MerkleLog) InclusionProof(idx, size int) ([]byte, [][]byte, error) {
	if idx < 0 || idx >= size || size > len(m.leaves) {
		return nil, nil, fmt.Errorf("ctlog: inclusion proof out of range (idx %d, size %d, log %d)", idx, size, len(m.leaves))
	}
	if size < 1 {
		return nil, nil, errors.New("ctlog: requested size must be >= 1")
	}
	var path [][]byte
	m.path(0, size, idx, &path)
	return mth(m.leaves, 0, size), path, nil
}

// path appends the sibling hashes on the route from idx to the subtree
// root of leaves [i, j), bottom-up (the verifier climbs leaf → root).
func (m *MerkleLog) path(i, j, idx int, out *[][]byte) {
	if j-i == 1 {
		return
	}
	k := splitPoint(j - i)
	if idx < i+k {
		m.path(i, i+k, idx, out)
		*out = append(*out, mth(m.leaves, i+k, j))
	} else {
		m.path(i+k, j, idx, out)
		*out = append(*out, mth(m.leaves, i, i+k))
	}
}

// ConsistencyProof (RFC 9162 §2.1.4.1, the current CT spec) shows the log
// at size2 is an extension of the log at size1: the old root can be
// recomputed from the path plus the new head. Note the proof format
// changed from the old RFC 6962 draft: the boundary leaf is included
// (RFC 9162 base case SUBPROOF(m, D_m, false) = {MTH(D_m)}).
func (m *MerkleLog) ConsistencyProof(size1, size2 int) ([]byte, []byte, [][]byte, error) {
	if size1 < 1 || size2 < 1 || size1 >= size2 || size2 > len(m.leaves) {
		return nil, nil, nil, fmt.Errorf("ctlog: need 1 <= from < to <= %d", len(m.leaves))
	}
	var path [][]byte
	m.consPath(0, size2, size1, true, &path)
	return mth(m.leaves, 0, size1), mth(m.leaves, 0, size2), path, nil
}

// consPath appends the sibling hashes on the consistency path from the
// old tree of n leaves inside the subtree [i, j), bottom-up. b marks a
// call descending from the original request (b=true): the old tree
// rooted exactly at [i, j) is then a complete known subtree and emits
// nothing; otherwise the leaf-level subtree root is emitted (RFC 9162
// SUBPROOF base case with b=false).
func (m *MerkleLog) consPath(i, j, n int, b bool, out *[][]byte) {
	if n == j-i {
		if b {
			return
		}
		*out = append(*out, mth(m.leaves, i, j))
		return
	}
	k := splitPoint(j - i)
	if n <= k {
		m.consPath(i, i+k, n, b, out)
		*out = append(*out, mth(m.leaves, i+k, j))
	} else {
		m.consPath(i+k, j, n-k, false, out)
		*out = append(*out, mth(m.leaves, i, i+k))
	}
}

// VerifyInclusion recomputes the root from a leaf, its index, and the
// proof — the auditor's side, with no access to the log (RFC 9162
// §2.1.3.2; nil = the proof is invalid). The walk uses fn as the leaf
// frontier and sn as the tree frontier; a sibling is combined on the
// left when the leaf is a right child (or the leaf and tree frontiers
// coincide), otherwise on the right.
func VerifyInclusion(leafHash []byte, idx, size int, proof [][]byte) []byte {
	if idx < 0 || idx >= size {
		return nil
	}
	r := leafHash
	fn, sn := idx, size-1
	for _, p := range proof {
		if sn == 0 {
			return nil
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			if fn&1 == 0 {
				for fn != 0 && fn&1 == 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return nil
	}
	return r
}

// VerifyConsistency (RFC 9162 §2.1.4.2): given the old root at size1 and
// the new root at size2 plus the proof, reports whether the log at size2
// is an extension of the log at size1. When size1 is an exact power of
// two, the old root is prepended to the path per the spec (step 2) — the
// old tree is a complete known subtree.
func VerifyConsistency(oldRoot, newRoot []byte, size1, size2 int, proof [][]byte) bool {
	if size1 == 0 {
		return len(proof) == 0 // empty log: consistent with everything
	}
	if size1 > size2 || len(oldRoot) == 0 || len(newRoot) == 0 {
		return false
	}
	if size1 == size2 {
		return len(proof) == 0 && bytes.Equal(oldRoot, newRoot)
	}
	if len(proof) == 0 {
		return false
	}
	path := proof
	if size1&(size1-1) == 0 { // size1 is an exact power of two
		path = append([][]byte{oldRoot}, proof...)
	}
	fn, sn := size1-1, size2-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = nodeHash(c, fr)
			sr = nodeHash(c, sr)
			if fn&1 == 0 {
				for fn != 0 && fn&1 == 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = nodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(fr, oldRoot) && bytes.Equal(sr, newRoot)
}

// HexLeaf is a convenience for tests and CLI output.
func HexLeaf(entry []byte) string { return hex.EncodeToString(LeafHash(entry)) }

// EncodeSize packs a size into the 8-byte wire form used in API responses.
func EncodeSize(n int) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	return b[:]
}

// SignedTreeHead (RFC 6962 §2.1.3): the log's signed assertion "the tree
// with TreeSize leaves has root Root at Timestamp". The signed bytes are
// sha256(0x00 || timestamp(8b BE) || tree_size(8b BE) || root) — the
// RFC 6962 MerkleTreeHead serialization. Anyone holding the log's public
// key can verify a tree head without trusting the log operator.
type SignedTreeHead struct {
	TreeSize  int64  `json:"tree_size"`
	Timestamp int64  `json:"timestamp"`
	Root      []byte `json:"root"`
	Signature []byte `json:"signature"`
}

func (s *SignedTreeHead) sthBytes() []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(s.Timestamp))
	h.Write(b[:])
	binary.BigEndian.PutUint64(b[:], uint64(s.TreeSize))
	h.Write(b[:])
	h.Write(s.Root)
	return h.Sum(nil)
}

// SignSTH signs a tree head over the given root at the given size.
func SignSTH(key ed25519.PrivateKey, root []byte, size int, ts int64) *SignedTreeHead {
	sth := &SignedTreeHead{TreeSize: int64(size), Timestamp: ts, Root: root}
	sth.Signature = ed25519.Sign(key, sth.sthBytes())
	return sth
}

// Verify checks the log key's signature over this tree head.
func (s *SignedTreeHead) Verify(pub ed25519.PublicKey) bool {
	return s != nil && len(s.Signature) != 0 && ed25519.Verify(pub, s.sthBytes(), s.Signature)
}

// GossipNode is the RFC 6962 gossip half on the OBSERVER side: an auditor
// holds the log's public key and the highest tree head it trusts; a newly
// observed STH is accepted only if it verifies against the log key and is
// CONSISTENT with the trusted one:
//
//	same size  -> the root must match (else: split-brain — the log is
//	              serving two histories at once, the fork alarm)
//	larger size -> the RFC 6962 consistency proof from the trusted size
//	              must recompute the trusted root (else: the log is
//	              rewriting history, the rewrite alarm)
//	smaller size-> the peer is simply behind; no alarm, not adopted
//
// A false alarm here is impossible: every branch is a verifiable
// mismatch, and matching statements are accepted silently.
type GossipNode struct {
	pub     ed25519.PublicKey
	trusted *SignedTreeHead
	alarm   string
}

// NewGossipNode starts an observer with the log key and, optionally, a
// trusted first tree head (nil = trust the first valid STH seen).
func NewGossipNode(pub ed25519.PublicKey, trusted *SignedTreeHead) *GossipNode {
	return &GossipNode{pub: pub, trusted: trusted}
}

// Trusted returns the highest STH accepted so far (nil if none yet).
func (g *GossipNode) Trusted() *SignedTreeHead { return g.trusted }

// Alarm reports the last consistency failure ("" = healthy).
func (g *GossipNode) Alarm() string { return g.alarm }

// Observe ingests an STH reported by another observer (or by the log
// itself). proof is the RFC 6962 consistency proof from proofFrom to
// sth.TreeSize; it is required and verified only when sth is larger than
// the trusted head. Returns whether the statement was consistent (and
// adopted when larger) and whether it raised the alarm.
func (g *GossipNode) Observe(sth *SignedTreeHead, proof [][]byte, proofFrom int) (accepted bool, alarm bool) {
	g.alarm = ""
	if sth == nil || !sth.Verify(g.pub) {
		return false, false // garbage: not a log statement, ignored
	}
	if g.trusted == nil || g.trusted.TreeSize == 0 {
		g.trusted = sth // nothing trusted yet: anchor on the first valid STH
		return true, false
	}
	switch {
	case sth.TreeSize < g.trusted.TreeSize:
		return true, false // peer is behind; their head is consistent with nothing yet claimed
	case sth.TreeSize == g.trusted.TreeSize:
		if !bytes.Equal(sth.Root, g.trusted.Root) {
			g.alarm = fmt.Sprintf("split-brain: two tree heads at size %d with different roots", sth.TreeSize)
			return false, true
		}
		return true, false
	default:
		if proofFrom != int(g.trusted.TreeSize) {
			g.alarm = fmt.Sprintf("inconsistent history: proof starts at %d, trusted head is %d", proofFrom, g.trusted.TreeSize)
			return false, true
		}
		if !VerifyConsistency(g.trusted.Root, sth.Root, int(g.trusted.TreeSize), int(sth.TreeSize), proof) {
			g.alarm = fmt.Sprintf("inconsistent history: %d entries claimed after trusted size %d do not extend it", sth.TreeSize, g.trusted.TreeSize)
			return false, true
		}
		g.trusted = sth
		return true, false
	}
}
