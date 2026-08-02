package trustorchestrator

import (
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"
)

func TestChainAppendVerify(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	h1, err := tl.Append(EvIssue, []byte(`{"cert_id":"c1","identity":"dev"}`), 1)
	if err != nil {
		t.Fatal(err)
	}
	tl.Append(EvRevoke, []byte(`{"cert_id":"c1"}`), 2)
	if !tl.Verify() {
		t.Fatal("valid chain failed verify")
	}
	if len(h1) != 32 {
		t.Fatalf("bad hash length %d", len(h1))
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	tl.Append(EvIssue, []byte(`{"cert_id":"c1","identity":"dev"}`), 1)
	tl.events[0].Payload[0] = 'X'
	if tl.Verify() {
		t.Fatal("tampered chain passed verify")
	}
}

func TestForkPreservesOriginal(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	ck, _ := tl.Append(EvIssue, []byte(`{"cert_id":"c1","identity":"dev"}`), 1)
	tl.Append(EvIssue, []byte(`{"cert_id":"c2","identity":"ops"}`), 2)
	fork, err := tl.Fork(ck)
	if err != nil {
		t.Fatal(err)
	}
	fork.Append(EvIssue, []byte(`{"cert_id":"c3","identity":"fix"}`), 3)
	if !tl.Verify() || len(tl.events) != 2 {
		t.Fatal("original chain mutated by fork")
	}
	if !fork.Verify() || len(fork.events) != 2 || fork.Fold().Certs["c3"].Identity != "fix" {
		t.Fatal("fork did not branch cleanly")
	}
}

func TestFoldNoResurrection(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	tl.Append(EvIssue, []byte(`{"cert_id":"c1","identity":"dev"}`), 1)
	tl.Append(EvRevoke, []byte(`{"cert_id":"c1"}`), 2)
	tl.Append(EvIssue, []byte(`{"cert_id":"c1","identity":"dev"}`), 3)
	s := tl.Fold()
	if !s.Certs["c1"].Revoked {
		t.Fatal("L3 violated: revoked cert re-validated")
	}
}

func TestFoldDeterministic(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	tl.Append(EvIssue, []byte(`{"cert_id":"c1","identity":"dev"}`), 1)
	tl.Append(EvRevoke, []byte(`{"cert_id":"c1"}`), 2)
	if !reflect.DeepEqual(tl.Fold(), tl.Fold()) {
		t.Fatal("L1 violated: fold not deterministic")
	}
}

func TestCUSUM(t *testing.T) {
	c := NewCUSUM(10, 2, 5)
	for i := 0; i < 50; i++ {
		if c.Observe(10) {
			t.Fatal("false alarm on baseline")
		}
	}
	alarms := 0
	for i := 0; i < 100; i++ {
		if c.Observe(15) {
			alarms++
		}
	}
	if alarms == 0 {
		t.Fatal("no alarm on sustained shift")
	}
}

func TestEnsembleQuorum(t *testing.T) {
	scores := []Score{
		{NodeID: "W1", Score: 10},
		{NodeID: "W2", Score: 20},
		{NodeID: "W3", Score: 30},
		{NodeID: "W4", Score: 40},
		{NodeID: "W5", Score: 50},
	}
	if Detect(scores, 25, 3) {
		t.Fatal("2/5 below threshold must not trigger DETECTED")
	}
	scores[3].Score = 5
	if !Detect(scores, 25, 3) {
		t.Fatal("3/5 below threshold (W1,W2,W4) failed to trigger DETECTED")
	}
	if Detect(scores, 25, 4) {
		t.Fatal("quorum 4 with only 3 below must not trigger")
	}
}

func TestLocateBadEvent(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	tl.Append(EvIssue, []byte(`{"cert_id":"c1","identity":"dev"}`), 1)
	tl.Append(EvIssue, []byte(`{"cert_id":"c2","identity":"ops"}`), 2)
	if tl.LocateBadEvent() != -1 {
		t.Fatal("clean chain flagged")
	}
	tl.events[1].ParentHash = []byte("forged")
	if got := tl.LocateBadEvent(); got != 1 {
		t.Fatalf("gap at index 1, got %d", got)
	}
	tl.events[1].ParentHash = tl.events[0].Hash()
	tl.events[0].ParentHash = []byte("forged")
	if got := tl.LocateBadEvent(); got != 0 {
		t.Fatalf("genesis with parent flagged at %d, want 0", got)
	}
}
