package trustorchestrator

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// CouncilMember holds one node's identity key (wire auth) and its FROST
// share. The root key NEVER exists: recovery commits are threshold-signed
// by >= min members (FR4.1, FR4.2).
type CouncilMember struct {
	ID    string
	Key   ed25519.PrivateKey
	Share *FrostSigner // nil = member unavailable
}

// Council is the recovery execution plane: >= min members threshold-sign
// the epoch handoff. No key is ever assembled.
type Council struct {
	members []*CouncilMember
	epoch   int64
	group   ed25519.PublicKey // council FROST group key (from the shares)
}

func NewCouncil(members []*CouncilMember) *Council {
	c := &Council{members: members}
	for _, m := range members {
		if m.Share != nil {
			c.group = m.Share.GroupPub
			break
		}
	}
	return c
}

// GroupPub is the council's FROST group key — the recovery trust anchor
// published out-of-band (deployment config, timeline council_pub).
func (c *Council) GroupPub() ed25519.PublicKey { return c.group }

// shareHolders returns members with a loaded share, in member order.
func (c *Council) shareHolders() []*CouncilMember {
	var out []*CouncilMember
	for _, m := range c.members {
		if m.Share != nil {
			out = append(out, m)
		}
	}
	return out
}

// memberIDs lists the loaded members' share IDs (quorum selection order).
func (c *Council) memberIDs() []string {
	ids := make([]string, 0, len(c.members))
	for _, m := range c.shareHolders() {
		ids = append(ids, m.Share.ID)
	}
	return ids
}

// SignCommit runs the two-round FROST ceremony over the epoch handoff
// descriptor (round 1: nonce commitments; round 2: partial signatures),
// binding the voted checkpoint (round 1) into the descriptor itself, so the
// signature cannot be replayed onto a different rollback point. Epoch must
// be prev+1 (monotonic, §6.4).
func (c *Council) SignCommit(epoch int64, checkpoint []byte, prev int64, newPub []byte, payload []byte, min int, ids ...string) (*FrostCommit, bool) {
	if epoch != prev+1 {
		return nil, false
	}
	fc := &FrostCommit{Epoch: epoch, Checkpoint: checkpoint, Prev: prev,
		NewPub: newPub, Payload: payload}
	holders := c.shareHolders()
	if len(holders) < min {
		return nil, false
	}
	pubs := map[string]ed25519.PublicKey{}
	xs := map[string]int{}
	byID := map[string]*FrostSigner{}
	for _, m := range holders {
		id := m.Share.ID
		for _, want := range ids {
			if id == want {
				pubs[id] = m.Share.PubShare
				xs[id] = memberX(id)
				byID[id] = m.Share
			}
		}
	}
	if len(pubs) < min {
		return nil, false
	}
	desc := fc.descriptor()
	agg := NewFrostAggregator(c.group, pubs)
	agg.SetXs(xs)
	commits := map[string][]byte{}
	for id, s := range byID {
		de, err := s.Commit()
		if err != nil {
			return nil, false
		}
		commits[id] = de
	}
	for id, de := range commits {
		if err := agg.AddCommit(id, de); err != nil {
			return nil, false
		}
	}
	r, cb, err := agg.Challenge(desc)
	if err != nil {
		return nil, false
	}
	trans := &FrostTranscript{M: desc, Commits: commits, Xs: xs, R: r, C: cb}
	for id, s := range byID {
		z, err := s.SignShare(trans)
		if err != nil {
			return nil, false
		}
		if err := agg.AddShare(id, z); err != nil {
			return nil, false
		}
	}
	sig, err := agg.Aggregate()
	if err != nil {
		return nil, false
	}
	fc.Sig = sig
	fc.Members = make([]string, 0, len(byID))
	for id := range byID {
		fc.Members = append(fc.Members, id)
	}
	if !fc.Valid(c.group, min) {
		return nil, false
	}
	c.epoch = epoch
	return fc, true
}

// HighestValidEpoch picks the canonical fork = highest valid epoch among
// chains of contiguous, threshold-signed handoffs (FR4.4). The entry-count
// attack from v1 is structurally impossible: only epochs decide.
func HighestValidEpoch(chains [][]*FrostCommit, groupPub ed25519.PublicKey, min int) ([]*FrostCommit, bool) {
	best, bestEpoch := []*FrostCommit(nil), int64(-1)
	for _, chain := range chains {
		prev := int64(0)
		ok := true
		for i, fc := range chain {
			if i == 0 && fc.Epoch != 1 || i > 0 && fc.Epoch != prev+1 {
				ok = false
				break
			}
			if !fc.Valid(groupPub, min) {
				ok = false
				break
			}
			prev = fc.Epoch
		}
		if ok && len(chain) > 0 && prev > bestEpoch {
			best, bestEpoch = chain, prev
		}
	}
	return best, best != nil
}

// RecoveryReport is the outcome of one council recovery (FR4.2–FR4.4).
type RecoveryReport struct {
	Commit   *FrostCommit
	Timeline *Timeline // canonical fork after rollback + re-issuance
	Issued   []string  // re-issued cert ids
	Verify   *VerifyReport
	RootSeed []byte // new epoch root, coordinator-side only (in-process path)
}

// Recover runs the recovery state machine (architecture §6.3) for a
// DETECTED event: verify evidence -> threshold-sign the handoff -> roll
// back under the new epoch root -> re-issue -> COMMIT -> verify. Blocks
// (returns error) when fewer than minVotes members are available (P2,
// NFR2.1). The networked variant (councilnet.go, RemoteRecover) shares the
// same tail via finishRecovery.
func (c *Council) Recover(tl *Timeline, evidence *TrustEvent, minVotes int) (*RecoveryReport, error) {
	badIdx, err := evidenceBadIndex(evidence)
	if err != nil {
		return nil, err
	}
	// VERIFY_EVIDENCE: each member independently re-checks the chain up to
	// the first bad event — the compromised region beyond it is what we are
	// rolling back from.
	if !tl.VerifyPrefix(badIdx) {
		return nil, errors.New("council: prefix failed verification")
	}
	// VOTE: all reachable members vote RECOVER.
	if len(c.shareHolders()) < minVotes {
		return nil, errors.New("BLOCKED: awaiting quorum")
	}
	ids := make([]string, 0, len(c.members))
	for _, m := range c.members {
		if m.Share != nil {
			ids = append(ids, m.Share.ID)
		}
	}
	return finishRecovery(c, tl, badIdx, minVotes, ids)
}

// evidenceBadIndex parses the DETECTED evidence payload (shared by the
// in-process and networked recovery paths).
func evidenceBadIndex(evidence *TrustEvent) (int, error) {
	if evidence == nil || evidence.Type != EvDetected {
		return -1, errors.New("council: evidence is not a DETECTED event")
	}
	var ev struct {
		BadIndex int `json:"bad_index"`
	}
	if json.Unmarshal(evidence.Payload, &ev) != nil || ev.BadIndex < 0 {
		return -1, errors.New("council: malformed evidence payload")
	}
	return ev.BadIndex, nil
}

// recoverRollback is the shared recovery middle: roll back at the
// checkpoint and adopt a FRESH epoch root (the compromised key is dead;
// the council's threshold signature approves the handoff, root never
// reconstructed). The new root's CA certificate is real X.509
// (NewIdentityCA), issued by the new root for the new epoch. The handoff
// event must be appended before any new-key events (re-issuance), so the
// caller signs it first.
func recoverRollback(tl *Timeline, badIdx int, newRootSeed []byte, epoch int64, now time.Time) (*Timeline, map[string]bool, map[string]bool, []byte, []byte, error) {
	newRoot := ed25519.NewKeyFromSeed(newRootSeed)
	_, certDER, err := NewIdentityCA(newRoot, fmt.Sprintf("to root epoch %d", epoch+1), now, now.AddDate(10, 0, 0))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	fork, err := Rollback(tl, badIdx)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	fork.key = newRoot
	fork.pub = newRoot.Public().(ed25519.PublicKey)
	fork.councilPub = tl.councilPub // the fork stays under the same council trust anchor
	affected, identities := InvalidationSet(tl, badIdx)
	return fork, affected, identities, certDER, fork.pub, nil
}

// reissueOnFork appends the epoch's re-issuance and revocations onto the
// handoff-carrying fork (signed by the new epoch key).
func reissueOnFork(fork *Timeline, affected, identities map[string]bool, epoch int64) []string {
	var issued []string
	for id := range identities {
		newID := id + "-re" + strconv.FormatInt(epoch+1, 10)
		pl, _ := json.Marshal(issuePayload{CertID: newID, Identity: id})
		if _, err := fork.Append(EvIssue, pl, 0); err != nil {
			continue
		}
		issued = append(issued, newID)
	}
	for cid := range affected {
		pl, _ := json.Marshal(struct {
			CertID string `json:"cert_id"`
		}{cid})
		fork.Append(EvRevoke, pl, 0) // revoke compromised certs on the fork
	}
	return issued
}

// finishRecovery is the shared recovery tail: handoff signing -> rollback
// -> re-issue -> COMMIT -> verify (used by Recover and RemoteRecover).
func finishRecovery(c *Council, tl *Timeline, badIdx int, minVotes int, ids []string) (*RecoveryReport, error) {
	// The new epoch root: a fresh seed created by the coordinator (the
	// in-process caller / the operator's machine). It is handed to the
	// coordinator via RootSeed and zeroized there once persisted — the
	// share-holding council members never see it.
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	fork, affected, identities, certDER, newPub, err := recoverRollback(tl, badIdx, seed, c.epoch, time.Now())
	if err != nil {
		return nil, err
	}
	// COMMIT: the FROST handoff, bound to the voted checkpoint (round 1).
	// Members verified the recovery post-conditions before signing; the
	// handoff event itself is signed by the new epoch key — the new epoch's
	// first statement, adopted only after the threshold signature validates.
	prevEpoch := c.epoch // SignCommit bumps c.epoch; re-issuance needs the old one
	checkpoint := rollbackCheckpoint(tl, badIdx)
	commit, ok := c.SignCommit(c.epoch+1, checkpoint, c.epoch, newPub, certDER, minVotes, ids...)
	if !ok {
		return nil, errors.New("council: commit failed")
	}
	fcJSON, _ := json.Marshal(commit)
	if _, err := fork.Append(EvRecovery, fcJSON, 0); err != nil {
		return nil, err
	}
	issued := reissueOnFork(fork, affected, identities, prevEpoch)
	// VERIFY: invariant checks, cross-checked by >=2 members re-executing.
	preState := prefixForCheck(tl, badIdx).Fold()
	r1 := VerifyRecovery(preState, fork.Fold(), affected, identities)
	r2 := VerifyRecovery(preState, fork.Fold(), affected, identities)
	if r1.Pass() != r2.Pass() {
		return nil, errors.New("council: cross-check disagreement")
	}
	commitEv, _ := json.Marshal(map[string]any{
		"epoch": commit.Epoch, "checkpoint": commit.Checkpoint, "new_pub": commit.NewPub,
	})
	if _, err := fork.Append(EvCommit, commitEv, 0); err != nil {
		return nil, err
	}
	return &RecoveryReport{Commit: commit, Timeline: fork, Issued: issued, Verify: r1, RootSeed: seed}, nil
}

// rollbackCheckpoint is the hash the handoff binds to: the head of the
// verified prefix (nil for genesis recovery).
func rollbackCheckpoint(tl *Timeline, badIdx int) []byte {
	if badIdx <= 0 {
		return nil
	}
	return tl.Events()[badIdx-1].Hash()
}

// prefixForCheck is the verified prefix, folded for the P3/P5 checks.
func prefixForCheck(tl *Timeline, badIdx int) *Timeline {
	pre, err := Rollback(tl, badIdx)
	if err != nil {
		return NewTimeline(nil)
	}
	return pre
}

