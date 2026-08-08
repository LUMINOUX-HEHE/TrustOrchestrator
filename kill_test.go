package trustorchestrator

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
)

// Kill-tests (test plan §7). The live K-series needs 5 VMs; these in-process
// equivalents exercise the same behavior on the core (evidence U where the
// plan says K).

// K1: kill 1 watchdog -> no DETECTED; the ensemble keeps working with 4/5.
func TestK1KillOneWatchdog(t *testing.T) {
	scores := []Score{{NodeID: "W1", Score: 100}, {NodeID: "W3", Score: 100}, {NodeID: "W4", Score: 100}, {NodeID: "W5", Score: 100}} // W2 dead
	if Detect(scores, threshold, quorum) {
		t.Fatal("K1: one dead watchdog must not cause DETECTED on clean traffic")
	}
	// The same 4/5 ensemble still detects a genuine attack (3 alarms).
	scores[0].Score, scores[1].Score, scores[2].Score = 0, 0, 0
	if !Detect(scores, threshold, quorum) {
		t.Fatal("K1: surviving ensemble must still reach quorum on real attacks")
	}
}

// K2: kill 2 watchdogs -> detection degrades, but no false-positive storm.
func TestK2KillTwoWatchdogs(t *testing.T) {
	scores := []Score{{NodeID: "W1", Score: 100}, {NodeID: "W3", Score: 100}, {NodeID: "W4", Score: 100}} // W2, W5 dead
	if Detect(scores, threshold, quorum) {
		t.Fatal("K2: 3/3 healthy on clean traffic must not alarm")
	}
}

// K3: kill 1 council member mid-recovery -> recovery continues (quorum intact).
func TestK3KillOneCouncilMember(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	for i := 0; i < 10; i++ {
		tl.Append(EvIssue, issue(fmt.Sprintf("c%d", i), "user", "", int64(i)), int64(i))
	}
	signers, _, err := DkgCeremony(5, quorum)
	if err != nil {
		t.Fatal(err)
	}
	members := make([]*CouncilMember, 4) // C5 killed mid-recovery
	for i := range members {
		members[i] = &CouncilMember{ID: signers[i].ID, Share: signers[i]}
	}
	ev := detectedEvidenceFor(tl, 8)
	rep, err := NewCouncil(members).Recover(tl, ev, quorum)
	if err != nil {
		t.Fatalf("K3: recovery must continue with 4/5: %v", err)
	}
	if !rep.Verify.Pass() {
		t.Fatal("K3: post-conditions must hold after the kill")
	}
}

// K4: kill 3 council members -> recovery blocks cleanly, no partial state.
func TestK4KillThreeCouncilMembers(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	for i := 0; i < 10; i++ {
		tl.Append(EvIssue, issue(fmt.Sprintf("c%d", i), "user", "", int64(i)), int64(i))
	}
	signers, _, err := DkgCeremony(5, quorum)
	if err != nil {
		t.Fatal(err)
	}
	members := make([]*CouncilMember, 2) // 2 remaining < quorum 3
	for i := range members {
		members[i] = &CouncilMember{ID: signers[i].ID, Share: signers[i]}
	}
	ev := detectedEvidenceFor(tl, 8)
	before := len(tl.events)
	if _, err := NewCouncil(members).Recover(tl, ev, quorum); err == nil {
		t.Fatal("K4: 2-member council must block (P2)")
	}
	if len(tl.events) != before {
		t.Fatal("K4: blocked recovery must not corrupt state (no events appended)")
	}
}

// K5: kill the verifier -> its PASS report is not accepted without the
// council cross-check; a failing check rejects recovery outright.
func TestK5VerifierCrossCheck(t *testing.T) {
	pre := &State{Certs: map[string]Cert{"a": {Identity: "user"}, "b": {Identity: "user"}}}
	// A broken verifier would accept a P5 violation: a new cert outside the
	// invalidation set must be rejected by VerifyRecovery.
	badPost := &State{Certs: map[string]Cert{"a": {Identity: "user"}, "b": {Identity: "user"}, "c": {Identity: "rogue"}}}
	if VerifyRecovery(pre, badPost, map[string]bool{"a": true}, map[string]bool{}).Pass() {
		t.Fatal("K5: verifier must reject a change outside the invalidation set (P5)")
	}
	// Re-issuance for an affected identity is the one allowed addition.
	reissue := &State{Certs: map[string]Cert{"a": {Identity: "user"}, "b": {Identity: "user"}, "a-re1": {Identity: "user"}}}
	if !VerifyRecovery(pre, reissue, map[string]bool{"a": true}, map[string]bool{"user": true}).Pass() {
		t.Fatal("K5: scoped re-issuance for an affected identity must pass")
	}
	// P3: resurrecting a revoked cert must be rejected.
	badPost2 := &State{Certs: map[string]Cert{"a": {Identity: "user"}, "b": {Identity: "user"}}}
	if VerifyRecovery(&State{Certs: map[string]Cert{"b": {Identity: "user", Revoked: true}}}, badPost2, map[string]bool{"b": true}, map[string]bool{}).Pass() {
		t.Fatal("K5: verifier must reject resurrection (P3)")
	}
}

// K6: corrupt one auditor log -> mismatch reported (W4 alarms); the
// escalation path is unaffected.
func TestK6CorruptAuditorLog(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	log := &AuditorLog{}
	for i := 0; i < 10; i++ {
		tl.Append(EvIssue, issue(fmt.Sprintf("c%d", i), "user", "", int64(i)), int64(i))
		log.Mirror(tl.events[len(tl.events)-1])
	}
	// Corruption: an event is replaced in the auditor log (attacker rewrite).
	log.events[3].Payload = append([]byte("X"), log.events[3].Payload[1:]...)
	if log.Verify() {
		t.Fatal("K6: corrupted auditor log must fail integrity")
	}
	w := NewWatchdog("W4", WDExternalProbe, 0, 0, 0, tl, log)
	// W4 detects the live chain diverging from the mirror at the head
	// (mirror suppressed for one event, as in S6).
	tl.Append(EvIssue, issue("c10", "user", "", 10), 10)
	if s := w.Score(); s.Score != 0 {
		t.Fatal("K6: W4 must report the mirror mismatch")
	}
	// Escalation still works on W4's alarm (3 distinct auditors).
	esc := Escalation{AuditorIDs: []string{"A1", "A2", "A3"}, Target: "W4"}
	if !DetectEscalated([]Score{{NodeID: "W4", Score: 0}}, esc, 3, threshold, quorum) {
		t.Fatal("K6: escalation path must be unaffected by a corrupt log")
	}
}

func detectedEvidenceFor(tl *Timeline, badIdx int) *TrustEvent {
	pl, _ := json.Marshal(map[string]int{"bad_index": badIdx})
	tl.Append(EvDetected, pl, 999)
	e := tl.events[len(tl.events)-1]
	return &e
}
