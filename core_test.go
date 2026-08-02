package trustorchestrator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestShamirRoundtrip(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)
	shards, err := ShamirSplit(seed, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ShamirJoin(shards[:3])
	if err != nil || string(got) != string(seed) {
		t.Fatalf("3-of-5 reconstruction failed: %x vs %x (%v)", got, seed, err)
	}
	if len(shards) != 5 {
		t.Fatalf("want 5 shards, got %d", len(shards))
	}
}

func TestShamirWrongShard(t *testing.T) {
	seed := make([]byte, 32)
	other := make([]byte, 32)
	rand.Read(seed)
	rand.Read(other)
	shards, _ := ShamirSplit(seed, 5, 3)
	otherShards, _ := ShamirSplit(other, 5, 3)
	bad := []*Shard{shards[0], shards[1], otherShards[2]} // shard from a different secret
	got, err := ShamirJoin(bad)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == string(seed) {
		t.Fatal("a shard from another polynomial must not reconstruct the secret")
	}
}

func TestShamirTooFewShards(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)
	shards, _ := ShamirSplit(seed, 5, 3)
	got, err := ShamirJoin(shards[:2])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == string(seed) {
		t.Fatal("2 shards must not reconstruct a 3-of-5 secret")
	}
}

func TestEpochCommitValidity(t *testing.T) {
	shards, _ := ShamirSplit(make([]byte, 32), 5, 3)
	members := make([]*CouncilMember, 5)
	for i := range members {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		members[i] = &CouncilMember{ID: fmt.Sprintf("C%d", i+1), Key: k, Shard: shards[i]}
	}
	c := NewCouncil(members)
	ec, ok := c.SignCommit(1, []byte("root"), 0, nil, 3, "C1", "C2", "C3")
	if !ok || !ec.Valid(c.Pubs(), 3) {
		t.Fatal("valid commit rejected")
	}
	if ec.Valid(c.Pubs(), 4) {
		t.Fatal("3 signatures must not satisfy quorum 4")
	}
	if _, ok := c.SignCommit(3, []byte("root"), 1, nil, 3, "C1", "C2", "C3"); ok {
		t.Fatal("non-contiguous epoch (jump 1->3) accepted")
	}
	if ec.Valid(map[string]ed25519.PublicKey{}, 3) {
		t.Fatal("commit valid against an empty pubkey set")
	}
}

// TestDoubleVoteRejected (test plan §4, "Vote protocol"): a member voting
// twice (duplicate id) counts once; quorum needs distinct members.
func TestDoubleVoteRejected(t *testing.T) {
	shards, _ := ShamirSplit(make([]byte, 32), 5, 3)
	members := make([]*CouncilMember, 5)
	for i := range members {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		members[i] = &CouncilMember{ID: fmt.Sprintf("C%d", i+1), Key: k, Shard: shards[i]}
	}
	c := NewCouncil(members)
	// C1 listed three times + C2 + C3: only 3 distinct members sign.
	ec, ok := c.SignCommit(1, []byte("root"), 0, nil, 3, "C1", "C1", "C1", "C2", "C3")
	if !ok {
		t.Fatal("commit with 3 distinct members rejected")
	}
	if len(ec.Sigs) != 3 {
		t.Fatalf("duplicate votes must dedupe to 3 signatures, got %d", len(ec.Sigs))
	}
	if ec.Valid(c.Pubs(), 4) {
		t.Fatal("3 distinct signatures must not satisfy quorum 4, even with duplicates listed")
	}
	// Two members, listed repeatedly, can never reach quorum 3.
	if _, ok := c.SignCommit(2, []byte("root"), 1, nil, 3, "C1", "C1", "C1", "C2", "C2"); ok {
		t.Fatal("double-voting must not inflate the quorum count")
	}
}

func TestRecoveryEndToEnd(t *testing.T) {
	// S1-shaped: normal traffic, burst with suppressed mirror, DETECTED,
	// council recovery with P3/P5 post-conditions.
	b := NewBench(30 * time.Second)
	m := b.ScenarioS1()
	if !m.Detected {
		t.Fatal("S1: burst not detected")
	}
	if m.DetectionLatency <= 0 {
		t.Fatalf("S1: latency %v should be > 0", m.DetectionLatency)
	}
	if !m.RollbackCorrect {
		t.Fatal("S1: P3/P5 post-conditions failed")
	}
}

func TestSlowPoisonNeedsAuditors(t *testing.T) {
	b := NewBench(30 * time.Second)
	m := b.ScenarioS2()
	if !m.Detected {
		t.Fatal("S2: slow poison with auditor escalation not detected")
	}
	if m.DetectionGap <= 0 {
		t.Fatal("S2: auditor gap not measured")
	}
	if !m.RollbackCorrect {
		t.Fatal("S2: rollback post-conditions failed")
	}
}

func TestInsiderCantTrigger(t *testing.T) {
	b := NewBench(30 * time.Second)
	m := b.ScenarioS3()
	if m.Detected {
		t.Fatal("S3: single fabricated watchdog must not trigger DETECTED (P4)")
	}
}

func TestPartitionBlocksThenHeals(t *testing.T) {
	b := NewBench(30 * time.Second)
	m := b.ScenarioS4()
	if m.FalsePositive {
		t.Fatal("S4: 2-member council must block (P2)")
	}
	if !m.Detected || !m.RollbackCorrect {
		t.Fatal("S4: recovery after heal failed")
	}
}

func TestForkRaceRejected(t *testing.T) {
	b := NewBench(30 * time.Second)
	m := b.ScenarioS5()
	if !m.CanonicalHighest {
		t.Fatal("S5: forged/gapped chains must lose to the honest epoch chain")
	}
}

func TestCombinedAttack(t *testing.T) {
	b := NewBench(30 * time.Second)
	m := b.ScenarioS6()
	if !m.Detected {
		t.Fatal("S6: combined attack not detected")
	}
	if m.FalsePositive {
		t.Fatal("S6: partitioned recovery must block")
	}
	if !m.RollbackCorrect {
		t.Fatal("S6: rollback post-conditions failed")
	}
}

func TestOmniscientGapMeasured(t *testing.T) {
	b := NewBench(30 * time.Second)
	m := b.ScenarioS7()
	if m.Detected {
		t.Fatal("S7: attacker under all published bounds must stay undetected")
	}
	if m.DetectionGap <= 0 {
		t.Fatal("S7: residual gap not measured")
	}
}

func TestBaselineNoFalsePositive(t *testing.T) {
	b := NewBench(30 * time.Second)
	m := b.ScenarioBaseline()
	if m.FalsePositive {
		t.Fatal("baseline: false positive on clean traffic")
	}
}

// TestWorkloadReissueTarget (NFR3.2): re-issuance of the documented 180
// workload certificates completes within 60s.
func TestWorkloadReissueTarget(t *testing.T) {
	b := NewBench(30 * time.Second)
	m := b.ScenarioWorkloadReissue()
	if m.WorkloadReissued != 180 {
		t.Fatalf("NFR3.2: expected 180 re-issued certs, got %d", m.WorkloadReissued)
	}
	if !m.RollbackCorrect {
		t.Fatalf("NFR3.2: re-issuance took %v, target <= 60s", m.WorkloadTime)
	}
}

// TestVerifyScalesLinearly (NFR3.3): verification time grows ~linearly with
// event count (ratio of 100k/10k runs ~= 10, well under quadratic).
func TestVerifyScalesLinearly(t *testing.T) {
	b := NewBench(30 * time.Second)
	m := b.ScenarioVerifyScaling()
	if m.VerifyEvents != 100_000 {
		t.Fatalf("expected 100k events, got %d", m.VerifyEvents)
	}
	if m.ScalingRatio < 5 || m.ScalingRatio > 25 {
		t.Fatalf("NFR3.3: scaling ratio %.1f suggests non-linear verification (expect ~10)", m.ScalingRatio)
	}
}

func TestAuditorLogAndEscalation(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	log := &AuditorLog{}
	for i := 0; i < 10; i++ {
		tl.Append(EvIssue, issue("c%d", "user", "", int64(i)), 0)
		log.Mirror(tl.events[len(tl.events)-1])
	}
	if !log.Verify() {
		t.Fatal("auditor mirror failed integrity")
	}
	tl.events[2].Payload[0] = 'X'
	if log.Verify() {
		t.Fatal("tamper propagated to auditor mirror must fail integrity")
	}
	v := CheckPolicy(nil, Policy{MaxIssuesPerIdentityPerWindow: 5})
	if v != nil {
		t.Fatalf("empty policy check: %v", v)
	}
	scores := []Score{{NodeID: "W5", Score: 100}}
	esc := Escalation{AuditorIDs: []string{"A1", "A2"}, Target: "W5"}
	if DetectEscalated(scores, esc, 3, threshold, quorum) {
		t.Fatal("2 auditors must not escalate (needs 3, FR3.3)")
	}
	esc.AuditorIDs = []string{"A1", "A2", "A3"}
	if DetectEscalated(scores, esc, 3, threshold, quorum) {
		t.Fatal("escalation must not fire while the target watchdog is healthy")
	}
	scores[0].Score = 0 // W5 genuinely alarmed
	if !DetectEscalated(scores, esc, 3, threshold, quorum) {
		t.Fatal("3 auditors + alarmed watchdog must force DETECTED")
	}
	if DetectEscalated(scores, Escalation{AuditorIDs: []string{"A1", "A1", "A1"}, Target: "W5"}, 3, threshold, quorum) {
		t.Fatal("duplicate auditor IDs must not count as consensus")
	}
}

func TestInvalidationSetScoped(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	tl.Append(EvIssue, issue("dev", "user", "", 1), 1)
	tl.Append(EvIssue, issue("prod", "user", "", 2), 2)
	tl.Append(EvIssue, issue("dev-laptop", "user", "dev", 3), 3)
	tl.Append(EvIssue, issue("rogue", "rogue", "dev-laptop", 4), 4)
	certs, ids := InvalidationSet(tl, 2) // first bad event: dev-laptop issuance
	if !certs["dev-laptop"] || !certs["rogue"] {
		t.Fatalf("P5: pivot+descendants must be invalidated: %v", certs)
	}
	if certs["dev"] || certs["prod"] {
		t.Fatalf("P5: blast radius exceeded, production must be untouched: %v", certs)
	}
	if !ids["user"] || !ids["rogue"] {
		t.Fatalf("re-issuance identities wrong: %v", ids)
	}
}

// Test plan §5, "Gossip": 5 watchdogs exchange scores on the 30s cycle with
// no loss — every cycle yields exactly 5 distinct node scores.
func TestGossipNoLoss(t *testing.T) {
	b := NewBench(30 * time.Second)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	log := &AuditorLog{}
	wd := b.watchdogs(tl, log)
	for cycle := 0; cycle < 10; cycle++ {
		pl := issue(fmt.Sprintf("c%d", cycle), "user", "", int64(cycle))
		ev := TrustEvent{Type: EvIssue, Payload: pl, Timestamp: int64(cycle)}
		tl.Append(ev.Type, ev.Payload, ev.Timestamp)
		log.Mirror(tl.events[len(tl.events)-1])
		for _, w := range wd {
			w.ObserveBatch([]TrustEvent{ev}, cycle)
		}
		ids := map[string]bool{}
		for _, w := range wd {
			ids[w.Score().NodeID] = true
		}
		if len(ids) != 5 {
			t.Fatalf("cycle %d: expected 5 scores, got %d (%v)", cycle, len(ids), ids)
		}
	}
}

// Test plan §5, "End-to-end": attack -> detection -> council recovery ->
// the reconstructed root signs a fresh CA -> a workload certificate issued
// under it verifies (the consumer mTLS path minus the transport).
func TestEndToEndPostRecovery(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	log := &AuditorLog{}
	for i := 0; i < 20; i++ { // normal traffic
		pl := issue(fmt.Sprintf("c%d", i), "user", "", int64(i))
		tl.Append(EvIssue, pl, int64(i))
		log.Mirror(tl.events[len(tl.events)-1])
	}
	attackIdx := len(tl.events)
	for i := 0; i < 10; i++ { // rogue burst at 2/cycle via c0, mirror suppressed
		for j := 0; j < 2; j++ {
			ts := int64(20 + i*2 + j)
			tl.Append(EvIssue, issue(fmt.Sprintf("rogue%d-%d", i, j), "rogue", "c0", ts), ts)
		}
	}
	// Ensemble detects: W4 (mirror suppressed) + W3 (2 edges/cycle) + W5
	// (rogue identity) — 3 of 5, the documented S1 shape.
	wd := NewBench(30*time.Second).watchdogs(tl, log)
	for cycle := 0; cycle < 10; cycle++ {
		batch := tl.events[attackIdx+cycle*2 : attackIdx+cycle*2+2]
		for _, w := range wd {
			w.ObserveBatch(batch, attackIdx+cycle*2)
		}
	}
	scores := make([]Score, len(wd))
	for i, w := range wd {
		scores[i] = w.Score()
	}
	if !Detect(scores, threshold, quorum) {
		t.Fatal("end-to-end: ensemble must detect the burst")
	}
	// Council recovery.
	shards, _ := ShamirSplit(key.Seed(), 5, 3)
	members := make([]*CouncilMember, 5)
	for i := range members {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		members[i] = &CouncilMember{ID: fmt.Sprintf("C%d", i+1), Key: k, Shard: shards[i]}
	}
	evPl, _ := json.Marshal(map[string]int{"bad_index": attackIdx})
	tl.Append(EvDetected, evPl, 100)
	evidence := &tl.events[len(tl.events)-1]
	rep, err := NewCouncil(members).Recover(tl, evidence, quorum)
	if err != nil || !rep.Verify.Pass() {
		t.Fatalf("end-to-end: recovery failed: %v", err)
	}
	// Consumer: the reconstructed root signs a fresh CA; a workload cert
	// issued under it verifies end to end.
	root, err := ShamirJoin(shards[:3])
	if err != nil {
		t.Fatal(err)
	}
	caKey := ed25519.NewKeyFromSeed(root)
	ca, caDER, err := NewIdentityCA(caKey, "post-recovery CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, userKey, _ := ed25519.GenerateKey(rand.Reader)
	leaf, err := IssueWorkloadCert(ca, caKey, userKey.Public().(ed25519.PublicKey), "user", 1, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWorkloadChain(leaf, caDER, time.Now()); err != nil {
		t.Fatalf("end-to-end: post-recovery cert rejected: %v", err)
	}
}

// Regression: the log-integrity watchdog must not panic on an empty
// (e.g. envelope-unmarshalled) timeline.
func TestW2EmptyTimelineNoPanic(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	w := NewWatchdog("W2", WDLogIntegrity, 0, 0, 0, tl, &AuditorLog{})
	for i := 0; i < 12; i++ {
		w.ObserveBatch(nil, i)
	}
	_ = w.Score() // must not panic
}

// Test plan §5 "Mirror": every governance event appears in the auditor log
// — the probe watchdog's external source has no loss.
func TestMirrorNoLoss(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	log := &AuditorLog{}
	for i := 0; i < 40; i++ {
		tl.Append(EvIssue, issue(fmt.Sprintf("c%d", i), "user", "", int64(i)), int64(i))
		log.Mirror(tl.events[len(tl.events)-1])
	}
	if !log.Verify() {
		t.Fatal("mirrored auditor log failed chain integrity")
	}
	if len(log.events) != len(tl.events) || !bytes.Equal(log.Head(), tl.Head()) {
		t.Fatal("mirror dropped events: auditor head diverges from timeline head")
	}
	w := NewWatchdog("W4", WDExternalProbe, 0, 0, 0, tl, log)
	if w.Score().Score != 100 {
		t.Fatal("probe watchdog must see a clean mirror (no alarm)")
	}
}

// Test plan §5 "End-to-end": two nodes complete an authenticated mTLS
// request using workload certs issued post-recovery — the consumer path
// (architecture §5.8) over a real transport.
func TestMutualTLSRequest(t *testing.T) {
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	caKey := root
	ca, caDER, err := NewIdentityCA(caKey, "post-recovery CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	serverLeaf, err := IssueWorkloadCert(ca, caKey, serverKey.Public().(ed25519.PublicKey), "vpn-server", 1, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	clientLeaf, err := IssueWorkloadCert(ca, caKey, clientKey.Public().(ed25519.PublicKey), "vpn-client", 2, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg, err := MutualTLSConfig(caDER, serverLeaf, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := MutualTLSConfig(caDER, clientLeaf, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg.ServerName = "vpn-server" // clients dial the workload cert's CN
	serverCfg.VerifyPeerCertificate = func(_ [][]byte, chains [][]*x509.Certificate) error {
		return VerifyPeerIdentity(chains[0][0], "vpn-client")
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 32)
		n, err := conn.Read(buf)
		if err != nil {
			serverErr <- err
			return
		}
		_, err = conn.Write(buf[:n])
		serverErr <- err
	}()
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("mTLS handshake failed: %v", err)
	}
	if err := VerifyPeerIdentity(conn.ConnectionState().PeerCertificates[0], "vpn-server"); err != nil {
		t.Fatalf("server identity rejected: %v", err)
	}
	msg := "authenticated request"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 32)
	n, err := conn.Read(reply)
	if err != nil {
		t.Fatalf("echo reply: %v", err)
	}
	if string(reply[:n]) != msg {
		t.Fatalf("echo mismatch: %q", reply[:n])
	}
	conn.Close()
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	// A foreign CA must not authenticate either side.
	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	fCA, fDER, _ := NewIdentityCA(foreign, "foreign CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_, fKey, _ := ed25519.GenerateKey(rand.Reader)
	_, impostorKey, _ := ed25519.GenerateKey(rand.Reader)
	fLeaf, _ := IssueWorkloadCert(fCA, foreign, impostorKey.Public().(ed25519.PublicKey), "impostor", 9, time.Minute)
	badCfg, _ := MutualTLSConfig(fDER, fLeaf, fKey)
	ln2, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	go func() {
		conn, err := ln2.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Read(make([]byte, 32)) // drives the handshake; fails on bad client cert
	}()
	if c, err := tls.Dial("tcp", ln2.Addr().String(), badCfg); err == nil {
		c.Close()
		t.Fatal("foreign-issued client cert must be rejected")
	}
}
