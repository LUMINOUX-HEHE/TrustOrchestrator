package trustorchestrator

// councilnet end-to-end: the networked recovery protocol over real mTLS.
// Test plan row "networked council": 3 of 5 members vote, initiator
// reconstructs, members re-verify P3/P5 and sign the COMMIT descriptor —
// the initiator never holds member keys, members never hold the root.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"
)

func testCA(t *testing.T) (*x509.Certificate, ed25519.PrivateKey, []byte) {
	t.Helper()
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	ca, caDER, err := NewIdentityCA(caKey, "council test CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return ca, caKey, caDER
}

func testMemberNode(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey, caDER []byte, id string, serial int64) (ed25519.PrivateKey, *tls.Config) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	leaf, err := IssueWorkloadCert(ca, caKey, key.Public().(ed25519.PublicKey), id, serial, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := MutualTLSConfig(caDER, leaf, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, cfg
}

func TestNetworkedRecovery(t *testing.T) {
	ca, caKey, caDER := testCA(t)
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	seed := root.Seed()
	tl := NewTimeline(root)
	tl.Append(EvKeyGen, nil, 0)
	tl.Append(EvIssue, mustPayload(issuePayload{CertID: "c1", Identity: "alice"}), 0)
	tl.Append(EvIssue, mustPayload(issuePayload{CertID: "c2", Identity: "bob"}), 0)
	tl.Append(EvIssue, mustPayload(issuePayload{CertID: "c3", Identity: "carol"}), 0)

	// Compromise: tamper one event; the detector flags the tampered event
	// itself (its signature no longer verifies).
	tamperIdx := 2
	evs := tl.Events()
	evs[tamperIdx].Signature[0] ^= 0xff
	bad, _ := json.Marshal(&timelineFile{Events: evs, Pub: tl.pub})
	badTL, err := UnmarshalTimeline(bad)
	if err != nil {
		t.Fatal(err)
	}
	badIdx := badTL.LocateBadEvent()
	if badIdx != tamperIdx {
		t.Fatalf("bad index = %d, want %d", badIdx, tamperIdx)
	}

	// 3 of 5 members: shards 1..3, nodes C1..C3.
	shards, err := ShamirSplit(seed, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"C1", "C2", "C3"}
	var endpoints []MemberEndpoint
	for i := 0; i < 3; i++ {
		key, cfg := testMemberNode(t, ca, caKey, caDER, ids[i], int64(i+1))
		srv := NewCouncilMemberServer(ids[i], shards[i], key, cfg)
		ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go srv.Serve(ln)
		endpoints = append(endpoints, MemberEndpoint{Addr: ln.Addr().String(), ServerName: ids[i]})
	}
	// Initiator node: own leaf, never any member key.
	_, initKey, _ := ed25519.GenerateKey(rand.Reader)
	initLeaf, err := IssueWorkloadCert(ca, caKey, initKey.Public().(ed25519.PublicKey), "ceremony", 99, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := MutualTLSConfig(caDER, initLeaf, initKey)
	if err != nil {
		t.Fatal(err)
	}

	evidence := &TrustEvent{Type: EvDetected, Payload: mustPayload(map[string]int{"bad_index": badIdx})}
	rep, err := RemoteRecover(badTL, evidence, endpoints, clientCfg, 3)
	if err != nil {
		t.Fatalf("networked recovery: %v", err)
	}
	if !rep.Verify.Pass() {
		t.Fatalf("post-recovery invariants failed: %v", rep.Verify.Checks)
	}
	// The COMMIT must verify against the members' pinned node keys
	// (obtained from the mTLS leaf at dial time).
	pubs := map[string]ed25519.PublicKey{}
	got := 0
	for _, ep := range endpoints {
		_, pub, err := dialCouncil(ep, clientCfg)
		if err != nil {
			continue
		}
		pubs[ep.ServerName] = pub
		got++
	}
	if got != 3 {
		t.Fatalf("dialed %d/3 members", got)
	}
	if !rep.Commit.Valid(pubs, 3) {
		t.Fatal("commit does not carry 3 valid member signatures")
	}
	// Tampered event index 2 is bob's ISSUE; the bad window starts there,
	// so the invalidation set is {bob, carol}: two certs re-issued.
	if len(rep.Issued) != 2 {
		t.Fatalf("re-issued %d certs, want 2", len(rep.Issued))
	}
	if !rep.Timeline.Verify() {
		t.Fatal("canonical fork fails chain verification")
	}
	want := map[string]bool{"bob-re1": true, "carol-re1": true} // identity+epoch 1
	for _, id := range rep.Issued {
		if !want[id] {
			t.Fatalf("unexpected re-issue %q", id)
		}
	}
}

// TestNetworkedRecoveryBlocks: fewer than minVotes members reachable ->
// BLOCKED (P2's networked half).
func TestNetworkedRecoveryBlocks(t *testing.T) {
	ca, caKey, caDER := testCA(t)
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(root)
	tl.Append(EvKeyGen, nil, 0)
	tl.Append(EvIssue, mustPayload(issuePayload{CertID: "c1", Identity: "alice"}), 0)
	evs := tl.Events()
	evs[1].Signature[0] ^= 0xff
	bad, _ := json.Marshal(&timelineFile{Events: evs, Pub: tl.pub})
	badTL, _ := UnmarshalTimeline(bad)
	badIdx := badTL.LocateBadEvent()

	shards, _ := ShamirSplit(root.Seed(), 5, 3)
	key, cfg := testMemberNode(t, ca, caKey, caDER, "C1", 1)
	srv := NewCouncilMemberServer("C1", shards[0], key, cfg)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)

	_, initKey, _ := ed25519.GenerateKey(rand.Reader)
	initLeaf, _ := IssueWorkloadCert(ca, caKey, initKey.Public().(ed25519.PublicKey), "ceremony", 1, time.Minute)
	clientCfg, _ := MutualTLSConfig(caDER, initLeaf, initKey)

	endpoints := []MemberEndpoint{
		{Addr: ln.Addr().String(), ServerName: "C1"},
		{Addr: "127.0.0.1:1", ServerName: "C2"}, // unreachable
		{Addr: "127.0.0.1:1", ServerName: "C3"}, // unreachable
	}
	evidence := &TrustEvent{Type: EvDetected, Payload: mustPayload(map[string]int{"bad_index": badIdx})}
	_, err = RemoteRecover(badTL, evidence, endpoints, clientCfg, 3)
	if err == nil || err.Error() != "BLOCKED: fewer than minVotes members voted yes" {
		t.Fatalf("want BLOCKED on missing quorum, got %v", err)
	}
}

func mustPayload(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
