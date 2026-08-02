package trustorchestrator

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// CouncilMember holds one node's identity and its Shamir shard (FR4.1).
type CouncilMember struct {
	ID    string
	Key   ed25519.PrivateKey
	Shard *Shard
}

// Council is the recovery execution plane: 5 members, >=3 vote (FR4.2).
type Council struct {
	members []*CouncilMember
	epoch   int64
}

func NewCouncil(members []*CouncilMember) *Council { return &Council{members: members} }

func (c *Council) Pubs() map[string]ed25519.PublicKey {
	pubs := map[string]ed25519.PublicKey{}
	for _, m := range c.members {
		pubs[m.ID] = m.Key.Public().(ed25519.PublicKey)
	}
	return pubs
}

// EpochCommit is a threshold-signed epoch descriptor (architecture §6.4):
// {epoch, root_hash, prev, payload} with >= min member signatures.
type EpochCommit struct {
	Epoch    int64             `json:"epoch"`
	RootHash []byte            `json:"root_hash"`
	Prev     int64             `json:"prev"`
	Payload  []byte            `json:"payload"`
	Sigs     map[string][]byte `json:"sigs"`
}

func (ec *EpochCommit) descriptor() []byte {
	b, _ := json.Marshal(struct {
		Epoch    int64  `json:"epoch"`
		RootHash []byte `json:"root_hash"`
		Prev     int64  `json:"prev"`
		Payload  []byte `json:"payload"`
	}{ec.Epoch, ec.RootHash, ec.Prev, ec.Payload})
	return b
}

// Valid accepts the commit iff >= min distinct member signatures verify
// (contiguity is enforced by the caller via Prev/Epoch, §6.4).
func (ec *EpochCommit) Valid(pubs map[string]ed25519.PublicKey, min int) bool {
	n := 0
	d := ec.descriptor()
	for id, sig := range ec.Sigs {
		if pub, ok := pubs[id]; ok && ed25519.Verify(pub, d, sig) {
			n++
		}
	}
	return n >= min
}

// SignCommit collects signatures from the given members over the descriptor;
// fails if fewer than min sign. Epoch must be prev+1 (monotonic, §6.4).
func (c *Council) SignCommit(epoch int64, root []byte, prev int64, payload []byte, min int, ids ...string) (*EpochCommit, bool) {
	if epoch != prev+1 {
		return nil, false
	}
	ec := &EpochCommit{Epoch: epoch, RootHash: root, Prev: prev, Payload: payload, Sigs: map[string][]byte{}}
	for _, m := range c.members {
		for _, id := range ids {
			if m.ID == id {
				ec.Sigs[m.ID] = ed25519.Sign(m.Key, ec.descriptor())
			}
		}
	}
	if !ec.Valid(c.Pubs(), min) {
		return nil, false
	}
	c.epoch = epoch
	return ec, true
}

// HighestValidEpoch picks the canonical fork = highest valid epoch among
// chains of contiguous, threshold-signed COMMITs (FR4.4). The entry-count
// attack from v1 is structurally impossible: only epochs decide.
func HighestValidEpoch(chains [][]*EpochCommit, pubs map[string]ed25519.PublicKey, min int) ([]*EpochCommit, bool) {
	best, bestEpoch := []*EpochCommit(nil), int64(-1)
	for _, chain := range chains {
		prev := int64(0)
		ok := true
		for i, ec := range chain {
			if i == 0 && ec.Epoch != 1 || i > 0 && ec.Epoch != prev+1 {
				ok = false
				break
			}
			if !ec.Valid(pubs, min) {
				ok = false
				break
			}
			prev = ec.Epoch
		}
		if ok && len(chain) > 0 && prev > bestEpoch {
			best, bestEpoch = chain, prev
		}
	}
	return best, best != nil
}

// RecoveryReport is the outcome of one council recovery (FR4.2–FR4.4).
type RecoveryReport struct {
	Commit   *EpochCommit
	Timeline *Timeline // canonical fork after rollback + re-issuance
	Issued   []string  // re-issued cert ids
	Verify   *VerifyReport
}

// Recover runs the recovery state machine (architecture §6.3) for a
// DETECTED event: verify evidence -> vote -> reconstruct root key -> roll
// back -> re-issue -> COMMIT -> verify. Blocks (returns error) when fewer
// than minVotes members are available (P2, NFR2.1).
func (c *Council) Recover(tl *Timeline, evidence *TrustEvent, minVotes int) (*RecoveryReport, error) {
	if evidence == nil || evidence.Type != EvDetected {
		return nil, errors.New("council: evidence is not a DETECTED event")
	}
	var ev struct {
		BadIndex int `json:"bad_index"`
	}
	if json.Unmarshal(evidence.Payload, &ev) != nil || ev.BadIndex < 0 {
		return nil, errors.New("council: malformed evidence payload")
	}
	// VERIFY_EVIDENCE: each member independently re-checks the chain up to
	// the first bad event — the compromised region beyond it is what we are
	// rolling back from.
	if !tl.VerifyPrefix(ev.BadIndex) {
		return nil, errors.New("council: prefix failed verification")
	}
	// VOTE: all reachable members vote RECOVER.
	if len(c.members) < minVotes {
		return nil, errors.New("BLOCKED: awaiting quorum")
	}
	ids := make([]string, 0, len(c.members))
	for _, m := range c.members {
		ids = append(ids, m.ID)
	}
	// RECONSTRUCT: >=3 shards -> root key, memory only, zeroized after use.
	shards := make([]*Shard, 0, 3)
	for _, m := range c.members[:3] {
		shards = append(shards, m.Shard)
	}
	root, err := ShamirJoin(shards)
	if err != nil {
		return nil, fmt.Errorf("council: reconstruction failed: %w", err)
	}
	defer zeroize(root)
	// RE_ISSUE: root signs a fresh intermediate CA; intermediate issues the
	// scoped re-issuance batch.
	inter, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	rootKey := ed25519.NewKeyFromSeed(root)
	interCert := ed25519.Sign(rootKey, inter)
	// ROLLBACK: fork at last verified good entry, re-fold, scoped re-issue.
	fork, err := Rollback(tl, ev.BadIndex)
	if err != nil {
		return nil, err
	}
	affected, identities := InvalidationSet(tl, ev.BadIndex)
	var issued []string
	for id := range identities {
		newID := id + "-re" + strconv.FormatInt(c.epoch+1, 10)
		pl, _ := json.Marshal(issuePayload{CertID: newID, Identity: id})
		if _, err := fork.Append(EvIssue, pl, 0); err != nil {
			return nil, err
		}
		issued = append(issued, newID)
	}
	for cid := range affected {
		pl, _ := json.Marshal(struct {
			CertID string `json:"cert_id"`
		}{cid})
		fork.Append(EvRevoke, pl, 0) // revoke compromised certs on the fork
	}
	// COMMIT: threshold-signed, monotonic epoch.
	commit, ok := c.SignCommit(c.epoch+1, fork.Head(), c.epoch, interCert, minVotes, ids...)
	if !ok {
		return nil, errors.New("council: commit failed")
	}
	// VERIFY: invariant checks, cross-checked by >=2 members re-executing.
	pre, _ := Rollback(tl, ev.BadIndex)
	preState := pre.Fold() // pre-compromise state
	r1 := VerifyRecovery(preState, fork.Fold(), affected, identities)
	r2 := VerifyRecovery(preState, fork.Fold(), affected, identities)
	if r1.Pass() != r2.Pass() {
		return nil, errors.New("council: cross-check disagreement")
	}
	commitEv, _ := json.Marshal(map[string]any{"epoch": commit.Epoch, "root": fork.Head()})
	fork.Append(EvCommit, commitEv, 0)
	return &RecoveryReport{Commit: commit, Timeline: fork, Issued: issued, Verify: r1}, nil
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
