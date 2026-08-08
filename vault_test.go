package trustorchestrator

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func testShares(t *testing.T) []*Shard {
	t.Helper()
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	sh, err := ShareKEK(kek, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	return sh
}

func TestVaultRoundtripTenantIsolation(t *testing.T) {
	v, err := NewVault()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := v.Seal("acme", []byte("tenants/aurora.payload"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Open("acme", blob)
	if err != nil || string(got) != "tenants/aurora.payload" {
		t.Fatalf("roundtrip: %q %v", got, err)
	}
	if _, err := v.Open("globex", blob); err == nil {
		t.Fatal("tenant A opened under tenant B")
	}
	blob[len(blob)-1] ^= 0x01
	if _, err := v.Open("acme", blob); err == nil {
		t.Fatal("tampered blob opened clean")
	}
}

func TestVaultThresholdUnwrap(t *testing.T) {
	sh := testShares(t)
	kek, err := JoinKEK(sh[:3])
	if err != nil || len(kek) != 32 {
		t.Fatalf("3-of-5 join: %v", err)
	}
	if got, err := JoinKEK([]*Shard{sh[1], sh[3], sh[4]}); err != nil || string(got) != string(kek) {
		t.Fatal("any 3 (not just the first 3) must reconstruct")
	}
	// 2 shares interpolate a wrong polynomial silently — the guarantee is
	// enforced where it matters: the wrong KEK cannot open gateway.keys.
	two, err := JoinKEK(sh[:2])
	if err != nil || bytes.Equal(two, kek) {
		t.Fatalf("2-of-5 produced the real KEK (%v)", err)
	}
	dir := t.TempDir()
	if err := writeVaultKeyFile(filepath.Join(dir, "gateway.keys"), kek, &Vault{DEK: make([]byte, 32), Epoch: 1}); err != nil {
		t.Fatal(err)
	}
	if v, err := readVaultKeyFile(filepath.Join(dir, "gateway.keys"), two); err == nil && v != nil {
		t.Fatal("2-of-5 unwrapped a store key")
	}
}

func TestVaultStoreUnlockAndReboot(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateTenant("acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Tenants["acme"].tl.Append(EvIssue, []byte(`{"cert_id":"c1","identity":"dev"}`), 1); err != nil {
		t.Fatal(err)
	}
	sh := testShares(t)
	if err := s.UnlockVault(sh[:3]); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "tenants", "acme", "timeline.json"))
	if err != nil || len(raw) < len(vaultMagic) || string(raw[:len(vaultMagic)]) != vaultMagic {
		t.Fatalf("tenant file not vault-sealed after unlock (%v)", err)
	}

	// reboot without the unwrap session: the vault-sealed tenant is deferred,
	// never loaded (no silent keyless reads)
	s2, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Tenants["acme"].tl != nil {
		t.Fatal("vault-sealed tenant loaded without the unwrap session")
	}
	if err := s2.UnlockVault(sh[:3]); err != nil {
		t.Fatal(err)
	}
	if s2.Tenants["acme"].tl == nil || !s2.Tenants["acme"].tl.Verify() {
		t.Fatal("tenant timeline lost across reboot + unwrap")
	}
}

// RotateVault must retire every pre-rotation key: a snapshot of the old
// DEK (the "leaky file" scenario) can no longer open anything on disk.
func TestVaultRotationKillsOldDEK(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateTenant("acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	s.Tenants["acme"].tl.Append(EvIssue, []byte(`{"cert_id":"c1"}`), 1)
	sh := testShares(t)
	if err := s.UnlockVault(sh[:3]); err != nil {
		t.Fatal(err)
	}
	oldDEK := append([]byte(nil), s.vault.DEK...)
	oldEpoch := s.vault.Epoch
	oldFile, err := os.ReadFile(filepath.Join(dir, "tenants", "acme", "timeline.json"))
	if err != nil {
		t.Fatal(err)
	}

	if err := s.RotateVault(sh[:3]); err != nil {
		t.Fatal(err)
	}
	if s.vault.Epoch != oldEpoch+1 {
		t.Fatalf("epoch not bumped: %d -> %d", oldEpoch, s.vault.Epoch)
	}
	newFile, err := os.ReadFile(filepath.Join(dir, "tenants", "acme", "timeline.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(oldFile) == string(newFile) {
		t.Fatal("rotation rewrote nothing")
	}

	stale := &Vault{DEK: oldDEK, Epoch: oldEpoch}
	if _, err := stale.Open("acme", newFile); err == nil {
		t.Fatal("stolen pre-rotation DEK opened the post-rotation file")
	}
	if got, err := s.vault.Open("acme", newFile); err != nil || !s.Tenants["acme"].tl.Verify() {
		t.Fatalf("current vault cannot read rotated file: %v", err)
	} else if got == nil {
		t.Fatal()
	}
}

func TestVaultRotationKeepsPayloadsPrivateAcrossTenants(t *testing.T) {
	v1, _ := NewVault()
	v2, _ := NewVault()
	a, _ := v1.Seal("one", []byte("secret-one"))
	b, _ := v2.Seal("two", []byte("secret-two"))
	if _, err := v1.Open("two", b); err == nil {
		t.Fatal("cross-vault tenant bleed")
	}
	if _, err := v2.Open("one", a); err == nil {
		t.Fatal("cross-vault tenant bleed (2)")
	}
}