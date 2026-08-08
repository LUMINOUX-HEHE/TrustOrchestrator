package trustorchestrator

// hash.go — hash agility for the trust chain (upgrade layer 1).
//
// The chain's parent links are computed under a per-timeline algorithm,
// stamped into the persisted timeline file ("hash_algo"). Legacy files
// carry no field -> SHA-256, byte-identical to the pre-agility wire format.
// New timelines may use "dual": each link is SHA-256 ‖ SHA3-256 (64 bytes),
// so a historical piece of the chain is only accepted if BOTH digests hold.
// A future collision in one primitive cannot rewrite trust history alone
// — that is the property hash agility exists to buy.
//
// The event's canonical sha256 Hash() is unchanged (wire-format stability:
// SDKs, auditors, the API's "hash" field all keep 32-byte values); dual
// mode changes only the *link* (ParentHash) digest.

import (
	"crypto/sha256"
	"crypto/sha3"
)

type hashAlgo uint8

const (
	algoSHA256 hashAlgo = iota // legacy/opt-out: sha256.Sum256 only
	algoDual                   // sha256 ‖ sha3-256, 64-byte (both must hold)
)

var algoNames = map[hashAlgo]string{algoSHA256: "", algoDual: "dual"}
var algoCodes = map[string]hashAlgo{"": algoSHA256, "sha256": algoSHA256, "dual": algoDual}

// chainDigest hashes b under the timeline's algorithm.
func (t *Timeline) chainDigest(b []byte) []byte {
	return hashWith(t.algo, b)
}

// hashWith computes the chain link digest for a blob.
func hashWith(a hashAlgo, b []byte) []byte {
	switch a {
	case algoSHA256:
		h := sha256.Sum256(b)
		return h[:]
	case algoDual:
		h1 := sha256.Sum256(b)
		h2 := sha3.New256()
		h2.Write(b)
		out := make([]byte, 0, 64)
		out = append(out, h1[:]...)
		out = append(out, h2.Sum(nil)...)
		return out
	}
	panic("unknown hash algo") // construction-time defect, not input data
}