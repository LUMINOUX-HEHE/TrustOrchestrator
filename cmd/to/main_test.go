package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Test plan §5, "Enrollment": bootstrap ceremony -> bootstrap-signed node
// identity; the enrollment cert verifies against the bootstrap root.
func TestEnroll(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)

	bootstrapPath := filepath.Join(dir, "bootstrap.key")
	if err := genKey(bootstrapPath); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(configPath, []byte("node: W1\nrole: watchdog\ndetector: rate_cusum\ninterval: 30s\n"), 0o644)

	if err := enroll([]string{"--bootstrap", bootstrapPath, "--config", configPath}); err != nil {
		t.Fatal(err)
	}

	var cert struct {
		NodeID       string `json:"node_id"`
		Role         string `json:"role"`
		PublicKey    []byte `json:"public_key"`
		BootstrapSig []byte `json:"bootstrap_signature"`
	}
	raw, err := os.ReadFile("node.cert.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &cert); err != nil {
		t.Fatal(err)
	}
	if cert.NodeID != "W1" || cert.Role != "watchdog" {
		t.Fatalf("enrolled %s/%s, want W1/watchdog", cert.NodeID, cert.Role)
	}
	// The bootstrap root's signature over (node_id, role, public_key) verifies.
	seedRaw, _ := os.ReadFile(bootstrapPath)
	seed, _ := hex.DecodeString(string(seedRaw))
	bootstrap := ed25519.PrivateKey(seed)
	stmt, _ := json.Marshal(map[string]any{
		"node_id":    cert.NodeID,
		"role":       cert.Role,
		"public_key": cert.PublicKey,
	})
	if !ed25519.Verify(bootstrap.Public().(ed25519.PublicKey), stmt, cert.BootstrapSig) {
		t.Fatal("bootstrap signature does not verify")
	}
	// A different bootstrap root must not verify the cert (auditor roots are
	// independent, FR8.3).
	otherPath := filepath.Join(dir, "other.key")
	genKey(otherPath)
	otherRaw, _ := os.ReadFile(otherPath)
	other, _ := hex.DecodeString(string(otherRaw))
	if ed25519.Verify(ed25519.PrivateKey(other).Public().(ed25519.PublicKey), stmt, cert.BootstrapSig) {
		t.Fatal("foreign bootstrap root accepted the enrollment cert")
	}
}

// Test plan §5, "Enrollment": the guide's short form — --node-id/--role
// without a config file (guide §5).
func TestEnrollNodeIDForm(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)

	bootstrapPath := filepath.Join(dir, "bootstrap.key")
	if err := genKey(bootstrapPath); err != nil {
		t.Fatal(err)
	}
	if err := enroll([]string{"--bootstrap", bootstrapPath, "--node-id", "C1", "--role", "council"}); err != nil {
		t.Fatal(err)
	}
	var cert struct {
		NodeID string `json:"node_id"`
		Role   string `json:"role"`
	}
	raw, err := os.ReadFile("node.cert.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &cert); err != nil {
		t.Fatal(err)
	}
	if cert.NodeID != "C1" || cert.Role != "council" {
		t.Fatalf("enrolled %s/%s, want C1/council via --node-id form", cert.NodeID, cert.Role)
	}
}

// Test plan §5, "Enrollment, bootstrap revocation (FR8.2)": after the
// one-time ceremony the bootstrap is revoked; a second enrollment attempt
// with the same key must refuse even though the key still exists.
func TestBootstrapRevokedAfterGenesis(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)

	bootstrapPath := filepath.Join(dir, "bootstrap.key")
	if err := genKey(bootstrapPath); err != nil {
		t.Fatal(err)
	}
	// First enroll succeeds (genesis).
	if err := enroll([]string{"--bootstrap", bootstrapPath, "--node-id", "W1", "--role", "watchdog"}); err != nil {
		t.Fatalf("genesis enroll failed: %v", err)
	}
	// FR8.2: the offline ceremony revokes the bootstrap after genesis.
	if err := revoke([]string{"--bootstrap", bootstrapPath}); err != nil {
		t.Fatal(err)
	}
	// A node that tries to enroll with the now-spent key must be refused.
	if err := enroll([]string{"--bootstrap", bootstrapPath, "--node-id", "W2", "--role", "watchdog"}); err == nil {
		t.Fatal("second enroll succeeded with a revoked bootstrap — FR8.2 violated")
	}
}
