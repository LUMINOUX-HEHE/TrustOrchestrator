package trustorchestrator

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// TestConsumerRollbackDelta: FR5.3 — a rollback propagates to consumers as an
// incremental delta; the consumer never restarts (test plan §5, "Consumer
// delta", evidence U).
func TestConsumerRollbackDelta(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	for i := 0; i < 10; i++ {
		pl, _ := json.Marshal(issuePayload{CertID: string(rune('a' + i)), Identity: "user"})
		tl.Append(EvIssue, pl, int64(i))
	}
	// Attack: 3 rogue certs appended after the verified prefix.
	for i := 0; i < 3; i++ {
		pl, _ := json.Marshal(issuePayload{CertID: "rogue" + string(rune('0'+i)), Identity: "rogue"})
		tl.Append(EvIssue, pl, 100+int64(i))
	}

	// A consumer that already saw the attack events holds the poisoned view.
	c := NewConsumer(tl.Fold())
	if c.Restarts != 0 {
		t.Fatal("consumer must start at zero restarts")
	}

	// Recovery: roll back at the attack start (event 10), then re-issue the
	// affected identity on the fork (what Council.Recover does).
	badIdx := 10
	fork, err := Rollback(tl, badIdx)
	if err != nil {
		t.Fatal(err)
	}
	affected, identities := InvalidationSet(tl, badIdx)
	pl, _ := json.Marshal(issuePayload{CertID: "rogue-re1", Identity: "rogue"})
	fork.Append(EvIssue, pl, 200)
	post := fork.Fold()
	if !affected["rogue0"] || !affected["rogue1"] || !affected["rogue2"] {
		t.Fatalf("invalidation set must cover the bad window, got %v", affected)
	}
	if !identities["rogue"] {
		t.Fatal("affected identity must be re-issued")
	}

	// The delta names exactly the change: the three rogue certs revoked, the
	// re-issued cert added. Nothing else touched.
	d := c.Diff(post)
	sort.Strings(d.Revoked)
	if !reflect.DeepEqual(d.Revoked, []string{"rogue0", "rogue1", "rogue2"}) {
		t.Fatalf("revoked = %v, want [rogue0 rogue1 rogue2]", d.Revoked)
	}
	sort.Strings(d.Issued)
	if !reflect.DeepEqual(d.Issued, []string{"rogue-re1"}) {
		t.Fatalf("issued = %v, want [rogue-re1]", d.Issued)
	}

	c.ApplyDiff(post)
	if c.Restarts != 0 {
		t.Fatal("FR5.3: rollback must propagate as a delta, never a restart")
	}
	if !reflect.DeepEqual(c.State.Certs, post.Certs) {
		t.Fatal("consumer view must equal the post-rollback state")
	}
}

// TestConsumerDiffSemantics: Diff names exactly the changed certs.
func TestConsumerDiffSemantics(t *testing.T) {
	c := NewConsumer(&State{Certs: map[string]Cert{
		"a": {Identity: "user"}, "b": {Identity: "user"}, "c": {Identity: "user"},
	}})
	post := &State{Certs: map[string]Cert{
		"a": {Identity: "user"}, "c": {Identity: "user", Revoked: true}, "d": {Identity: "re"},
	}}
	d := c.Diff(post)
	sort.Strings(d.Revoked)
	if !reflect.DeepEqual(d.Revoked, []string{"b", "c"}) {
		t.Fatalf("revoked = %v, want [b c]", d.Revoked)
	}
	sort.Strings(d.Issued)
	if !reflect.DeepEqual(d.Issued, []string{"d"}) {
		t.Fatalf("issued = %v, want [d]", d.Issued)
	}
}
