package trustorchestrator

// Hash agility checks (hash.go): dual-mode chains (SHA-256 ‖ SHA3-256
// links) verify, survive roundtrip, detect tampering, and legacy SHA-256
// chains keep the exact pre-agility wire behavior.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestDualTimelineVerify(t *testing.T) {
	k := key(t)
	tl := NewDualTimeline(k)
	if got := tl.HashAlgoName(); got != "dual" {
		t.Fatalf("algo name: want dual, got %q", got)
	}
	if _, err := tl.Append(EvIssue, []byte("one"), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := tl.Append(EvIssue, []byte("two"), 2); err != nil {
		t.Fatal(err)
	}
	if !tl.Verify() {
		t.Fatal("dual chain must verify")
	}
	// 64-byte links (SHA-256 ‖ SHA3-256)
	ev := tl.Events()
	if len(ev[1].ParentHash) != 64 {
		t.Fatalf("dual parent link: want 64 bytes, got %d", len(ev[1].ParentHash))
	}
}

func TestDualTimelineTamper(t *testing.T) {
	k := key(t)
	tl := NewDualTimeline(k)
	tl.Append(EvIssue, []byte("a"), 1)
	tl.Append(EvRevoke, []byte("b"), 2)
	// tamper the payload of event 1: parent link of event 2 must fail
	tl.mu.Lock()
	tl.events[1].Payload = []byte("evil")
	tl.mu.Unlock()
	if tl.Verify() {
		t.Fatal("tampered dual chain must NOT verify")
	}
	if bad := tl.LocateBadEvent(); bad != 1 {
		t.Fatalf("bad event: want 1, got %d", bad)
	}
}

func TestDualTimelineRoundtrip(t *testing.T) {
	k := key(t)
	tl := NewDualTimeline(k)
	tl.Append("ISSUE", []byte("x"), 1)
	tl.Append("REVOKE", []byte("y"), 2)
	b, err := tl.Marshal(false)
	if err != nil {
		t.Fatal(err)
	}
	var f timelineFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.HashAlgo != "dual" {
		t.Fatalf("hash_algo: want dual, got %q", f.HashAlgo)
	}
	rl, err := UnmarshalTimeline(b)
	if err != nil {
		t.Fatal(err)
	}
	if !rl.Verify() {
		t.Fatal("reloaded dual chain must verify")
	}
	if rl.HashAlgoName() != "dual" {
		t.Fatalf("reload algo: %q", rl.HashAlgoName())
	}
}

func TestLegacyTimelineUnchanged(t *testing.T) {
	k := key(t)
	tl := NewTimeline(k)
	tl.Append("ISSUE", []byte("a"), 1)
	tl.Append("REVOKE", []byte("b"), 2)
	ev := tl.Events()
	if len(ev[1].ParentHash) != 32 {
		t.Fatalf("legacy parent hash: want 32 bytes, got %d", len(ev[1].ParentHash))
	}
	// wire format has no hash_algo, still loads, still verifies as our
	// to old benchmark/evidence dumps load cleanly
	b, err := tl.Marshal(false)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("hash_algo")) {
		t.Fatal("legacy marshal must not carry hash_algo")
	}
	rl, err := UnmarshalTimeline(b)
	if err != nil {
		t.Fatal(err)
	}
	if !rl.Verify() {
		t.Fatal("legacy reload must verify")
	}
}

func TestAuditorLogDual(t *testing.T) {
	k := key(t)
	tl := NewDualTimeline(k)
	tl.Append("ISSUE", []byte("a"), 1)
	tl.Append("REVOKE", []byte("b"), 2)
	log := NewAuditorLog(algoDual)
	log.Mirror(tl.Events()[0])
	log.Mirror(tl.Events()[1])
	if !log.Verify() {
		t.Fatal("auditor mirror of dual chain must verify")
	}
	// legacy auditor (default algo sha256) must fail on a dual chain
	legacy := &AuditorLog{}
	legacy.Mirror(tl.Events()[0])
	legacy.Mirror(tl.Events()[1])
	if legacy.Verify() {
		t.Fatal("sha256 auditor must not verify dual links")
	}
}