package trustorchestrator

// The Go SDK exercised end-to-end against the real gateway mux: full
// lifecycle through the typed client, and a backup/restore round-trip.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientLifecycle(t *testing.T) {
	gw, admin := newTestGateway(t, t.TempDir())
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()

	c := NewClient(srv.URL, admin)
	if _, err := c.CreateOrg("acme", ""); err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	orgs, err := c.Orgs()
	if err != nil || len(orgs) != 1 || orgs[0].ID != "acme" {
		t.Fatalf("Orgs: %v %v", orgs, err)
	}
	if _, err := c.Issue("acme", "c1", "user", "c0"); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := c.Revoke("acme", "c1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	st, err := c.State("acme")
	if err != nil || !st["c1"].Revoked {
		t.Fatalf("State: %v %v", st, err)
	}
	evs, err := c.Timeline("acme", "REVOKE", 10)
	if err != nil || len(evs) != 1 || evs[0].CertID != "c1" {
		t.Fatalf("Timeline: %v %v", evs, err)
	}
	aud, err := c.Audit("acme", "ISSUE", "user", "", 10)
	if err != nil || len(aud) != 1 {
		t.Fatalf("Audit: %v %v", aud, err)
	}
	if _, err := c.Metrics(); err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	// wrong token surfaces a typed error
	bad := NewClient(srv.URL, "nope")
	if _, err := bad.Orgs(); err == nil {
		t.Fatal("bad token must error")
	}
}

func TestClientBackupRestore(t *testing.T) {
	gw1, admin1 := newTestGateway(t, t.TempDir())
	srv1 := httptest.NewServer(gw1.Handler())
	defer srv1.Close()
	c1 := NewClient(srv1.URL, admin1)

	if _, err := c1.CreateOrg("acme", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c1.Issue("acme", "c1", "user", ""); err != nil {
		t.Fatal(err)
	}
	id, err := c1.Backup()
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	bundle, err := c1.DownloadBackup(id)
	if err != nil || len(bundle) == 0 {
		t.Fatalf("Download: %v", err)
	}

	gw2, admin2 := newTestGateway(t, t.TempDir())
	srv2 := httptest.NewServer(gw2.Handler())
	defer srv2.Close()
	c2 := NewClient(srv2.URL, admin2)
	if err := c2.Restore(bundle); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	c2 = NewClient(srv2.URL, admin1) // the bundle carries its own users
	st, err := c2.State("acme")
	if err != nil || st["c1"].Identity != "user" {
		t.Fatalf("restored state: %v %v", st, err)
	}
}

// TestClientCTAudit: the typed client drives the full RFC 9162 audit
// loop — STH, inclusion proof, consistency proof, and gossip — and the
// proofs hold up to the library verifiers.
func TestClientCTAudit(t *testing.T) {
	gw, admin := newTestGateway(t, t.TempDir())
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()
	c := NewClient(srv.URL, admin)

	if _, err := c.CreateOrg("acme", ""); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := c.Issue("acme", fmt.Sprintf("c%d", i), "user", ""); err != nil {
			t.Fatal(err)
		}
	}
	sth, err := c.CTSTH("acme")
	if err != nil || sth.TreeSize != 5 {
		t.Fatalf("CTSTH: %v %v", sth, err)
	}

	// inclusion of event 2 against size 3 (a prefix of the current tree)
	leafHex, rootHex, proof, err := c.CTInclusionProof("acme", 2, 3)
	if err != nil {
		t.Fatalf("inclusion: %v", err)
	}
	leaf, _ := hex.DecodeString(leafHex)
	root, _ := hex.DecodeString(rootHex)
	p := decodeHexProof(t, proof)
	if got := VerifyInclusion(leaf, 2, 3, p); !bytes.Equal(got, root) {
		t.Fatalf("inclusion proof must recompute the served root: %x vs %x", got, root)
	}

	// consistency 3 -> 5 against the signed STH root
	oldRootHex, newRootHex, cproof, err := c.CTConsistencyProof("acme", 3, 5)
	if err != nil {
		t.Fatalf("consistency: %v", err)
	}
	sthRoot, _ := hex.DecodeString(sth.RootHex)
	newRoot, _ := hex.DecodeString(newRootHex)
	if !bytes.Equal(newRoot, sthRoot) {
		t.Fatal("consistency new root must match the STH root")
	}
	cp := decodeHexProof(t, cproof)
	oldRoot, _ := hex.DecodeString(oldRootHex)
	if !VerifyConsistency(oldRoot, sthRoot, 3, 5, cp) {
		t.Fatal("consistency proof must verify")
	}

	// gossip: report the STH with its consistency proof from size 0
	accepted, alarm, _, _, err := c.CTGossip("acme", sth, 0, nil)
	if err != nil || !accepted || alarm != "" {
		t.Fatalf("gossip: %v accepted=%v alarm=%q", err, accepted, alarm)
	}

	// a signed fork at the same size must be rejected with a split-brain alarm
	forge := append([]byte(nil), sthRoot...)
	forge[0] ^= 0xff
	fork := SignSTH(ed25519.NewKeyFromSeed(gw.LogKey), forge, 5, time.Now().Unix())
	forked := STH{LogKeyHex: sth.LogKeyHex, TreeSize: fork.TreeSize, Timestamp: fork.Timestamp,
		RootHex: hex.EncodeToString(fork.Root), SignatureHex: hex.EncodeToString(fork.Signature)}
	accepted, alarm, _, _, err = c.CTGossip("acme", forked, 5, nil)
	if err != nil || accepted || alarm == "" {
		t.Fatalf("fork must be rejected with alarm: %v accepted=%v alarm=%q", err, accepted, alarm)
	}
}

func decodeHexProof(t *testing.T, proof []string) [][]byte {
	t.Helper()
	out := make([][]byte, len(proof))
	for i, h := range proof {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = b
	}
	return out
}
