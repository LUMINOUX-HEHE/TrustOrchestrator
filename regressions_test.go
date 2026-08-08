package trustorchestrator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
)

// Regression: a seed with a leading zero byte must round-trip through
// Shamir at full length (big.Int strips leading zeros; ed25519 seeds are
// length-exact). 1/256 of keys hit this.
func TestShamirLeadingZeroSeed(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)
	seed[0] = 0x00
	shards, err := ShamirSplit(seed, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ShamirJoin(shards[:3])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, seed) {
		t.Fatalf("round-trip: got %d bytes %x, want 32 bytes %x", len(got), got, seed)
	}
	_ = ed25519.NewKeyFromSeed(got) // panics on short seed
}

// Regression: Score() must be idempotent per batch — W2's verify-cadence
// counters must not advance between two calls of the same cycle.
func TestWatchdogScoreIdempotent(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	for i := 0; i < 10; i++ {
		tl.Append(EvIssue, issue(fmt.Sprintf("c%d", i), "user", "", int64(i)), int64(i))
	}
	w := NewWatchdog("W2", WDLogIntegrity, 0, 0, 0, tl, &AuditorLog{})
	s1 := w.Score()
	before := w.cycles
	s2 := w.Score()
	if s1.Score != s2.Score || s1.Evidence == nil != (s2.Evidence == nil) {
		t.Fatalf("Score() not idempotent: %+v vs %+v", s1, s2)
	}
	if w.cycles != before {
		t.Fatalf("Score() advanced W2 cadence counter: %d -> %d", before, w.cycles)
	}
}

// Regression: recovery must work when the first council member is down
// (share missing) — the quorum selection is by available members, not a
// hardcoded prefix.
func TestCouncilRecoversWithoutFirstMember(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	for i := 0; i < 10; i++ {
		tl.Append(EvIssue, issue(fmt.Sprintf("c%d", i), "user", "", int64(i)), int64(i))
	}
	signers, _, err := DkgCeremony(5, quorum)
	if err != nil {
		t.Fatal(err)
	}
	members := []*CouncilMember{{ID: signers[0].ID, Share: nil}} // C1 down mid-recovery
	for i := 1; i < 5; i++ {
		members = append(members, &CouncilMember{ID: signers[i].ID, Share: signers[i]})
	}
	ev := detectedEvidenceFor(tl, 8)
	rep, err := NewCouncil(members).Recover(tl, ev, quorum)
	if err != nil {
		t.Fatalf("recovery must succeed without C1's share: %v", err)
	}
	if !rep.Verify.Pass() {
		t.Fatal("post-conditions must hold")
	}
}

// Concurrent readers/writers must not corrupt the timeline (or deadlock).
// A hang fails via the -timeout; corruption fails the final Verify.
func TestTimelineConcurrentAccess(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	tl.Append(EvKeyGen, nil, 0)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				tl.Append(EvIssue, issue(fmt.Sprintf("g%d-c%d", w, i), "user", "", int64(i)), int64(i))
				tl.Head()
				tl.Verify()
				tl.Events()
				tl.Fold()
			}
		}(w)
	}
	wg.Wait()
	if !tl.Verify() {
		t.Fatal("chain corrupted under concurrency")
	}
}
