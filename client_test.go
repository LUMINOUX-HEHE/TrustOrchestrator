package trustorchestrator

// The Go SDK exercised end-to-end against the real gateway mux: full
// lifecycle through the typed client, and a backup/restore round-trip.

import (
	"net/http/httptest"
	"testing"
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
