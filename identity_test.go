package trustorchestrator

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

// Test plan §4, "ASN.1 subset": Wycheproof-backed stdlib x509 — the
// auditable claim is rejection of malformed/tampered/expired input.

func TestIdentityIssueAndVerify(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	ca, caDER, err := NewIdentityCA(key, "identity CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, subjectKey, _ := ed25519.GenerateKey(rand.Reader)
	leaf, err := IssueWorkloadCert(ca, key, subjectKey.Public().(ed25519.PublicKey), "user-1", 42, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWorkloadChain(leaf, caDER, time.Now()); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	// Tamper: one flipped byte in the leaf must be rejected.
	leaf[80] ^= 0xff
	if err := VerifyWorkloadChain(leaf, caDER, time.Now()); err == nil {
		t.Fatal("tampered leaf accepted")
	}
	// Malformed DER: garbage must be rejected, not panic.
	if err := VerifyWorkloadChain([]byte{0x30, 0x03, 0xff, 0x00}, caDER, time.Now()); err == nil {
		t.Fatal("malformed DER accepted")
	}
	if err := VerifyWorkloadChain(leaf, []byte{0x00}, time.Now()); err == nil {
		t.Fatal("malformed CA accepted")
	}
	// Wrong root: a cert signed by another CA must not verify.
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	otherCA, _, _ := NewIdentityCA(otherKey, "other CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_, fx, _ := ed25519.GenerateKey(rand.Reader)
	foreign, _ := IssueWorkloadCert(otherCA, otherKey, fx.Public().(ed25519.PublicKey), "x", 1, time.Minute)
	if err := VerifyWorkloadChain(foreign, caDER, time.Now()); err == nil {
		t.Fatal("cert from a foreign root accepted")
	}
}

func TestIdentityExpiryRejected(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	ca, caDER, _ := NewIdentityCA(key, "identity CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	// Issued at ttl=0 -> already expired when checked one minute later.
	_, zKey, _ := ed25519.GenerateKey(rand.Reader)
	leaf, _ := IssueWorkloadCert(ca, key, zKey.Public().(ed25519.PublicKey), "user-1", 1, 0)
	if err := VerifyWorkloadChain(leaf, caDER, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("expired leaf accepted")
	}
	// Expired CA: even a fresh leaf must fail.
	oldCA, oldDER, _ := NewIdentityCA(key, "old CA", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	_, oKey, _ := ed25519.GenerateKey(rand.Reader)
	oldLeaf, _ := IssueWorkloadCert(oldCA, key, oKey.Public().(ed25519.PublicKey), "user-2", 2, time.Hour)
	if err := VerifyWorkloadChain(oldLeaf, oldDER, time.Now()); err == nil {
		t.Fatal("chain under expired CA accepted")
	}
}

func TestIdentityWorkloadReissueTarget(t *testing.T) {
	// NFR3.2 at the X.509 layer: 180 short-lived certs in well under 60s.
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	ca, caDER, err := NewIdentityCA(key, "identity CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i := int64(0); i < 180; i++ {
		_, rKey, _ := ed25519.GenerateKey(rand.Reader)
		leaf, err := IssueWorkloadCert(ca, key, rKey.Public().(ed25519.PublicKey), "user", i, 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyWorkloadChain(leaf, caDER, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 60*time.Second {
		t.Fatalf("180 certs took %v, target <= 60s", d)
	}
}

// CRL lifecycle: create -> verify -> revoke -> append -> rejected checks.

func TestCRLCreateVerify(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	ca, caDER, _ := NewIdentityCA(key, "identity CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	now := time.Now()
	crl, err := NewCRL(ca, key, 1, []RevokedCert{
		{SerialNumber: big.NewInt(42), RevokedAt: now},
	}, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCRL(crl, caDER, now); err != nil {
		t.Fatalf("self-signed CRL must verify: %v", err)
	}
	// Forged: signed by a different CA -> rejected.
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	otherCA, _, _ := NewIdentityCA(otherKey, "other CA", now.Add(-time.Hour), now.Add(time.Hour))
	forged, err := NewCRL(otherCA, otherKey, 1, nil, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCRL(forged, caDER, now); err == nil {
		t.Fatal("foreign-signed CRL must fail verification")
	}
	// Stale: validity window in the past -> rejected.
	old, err := NewCRL(ca, key, 2, nil, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCRL(old, caDER, now); err == nil {
		t.Fatal("expired CRL must fail verification")
	}
	// Garbage -> parse error, not panic.
	if _, err := VerifyCRL([]byte{0x30, 0x03, 0xff}, caDER, now); err == nil {
		t.Fatal("garbage CRL must fail")
	}
}

func TestCRLRevokedCertDetected(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	ca, _, _ := NewIdentityCA(key, "identity CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	now := time.Now()
	_, subj, _ := ed25519.GenerateKey(rand.Reader)
	leaf, err := IssueWorkloadCert(ca, key, subj.Public().(ed25519.PublicKey), "user-1", 42, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := NewCRL(ca, key, 1, []RevokedCert{{SerialNumber: big.NewInt(42), RevokedAt: now}}, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := CheckRevoked(leaf, crl)
	if err != nil || !revoked {
		t.Fatalf("serial 42 must be on the CRL (revoked=%v err=%v)", revoked, err)
	}
	// Serial 43 was never revoked.
	leaf2, _ := IssueWorkloadCert(ca, key, subj.Public().(ed25519.PublicKey), "user-1", 43, 10*time.Minute)
	revoked, err = CheckRevoked(leaf2, crl)
	if err != nil || revoked {
		t.Fatalf("serial 43 must be clean (revoked=%v err=%v)", revoked, err)
	}
	// Garbage inputs fail, not panic.
	if _, err := CheckRevoked([]byte{0x30}, crl); err == nil {
		t.Fatal("garbage leaf must fail")
	}
	if _, err := CheckRevoked(leaf, []byte{0x30}); err == nil {
		t.Fatal("garbage CRL must fail")
	}
}

func TestCRLAppendRevocation(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	ca, caDER, _ := NewIdentityCA(key, "identity CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	now := time.Now()
	crl, err := NewCRL(ca, key, 1, []RevokedCert{{SerialNumber: big.NewInt(1), RevokedAt: now}}, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	crl2, err := AppendRevocation(ca, key, crl, 2,
		[]RevokedCert{{SerialNumber: big.NewInt(2), RevokedAt: now}, {SerialNumber: big.NewInt(1), RevokedAt: now}}, // dup serial 1
		now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	rl, err := VerifyCRL(crl2, caDER, now)
	if err != nil {
		t.Fatalf("appended CRL must verify: %v", err)
	}
	if rl.Number.Int64() != 2 {
		t.Fatalf("CRL number = %d, want 2", rl.Number.Int64())
	}
	if got := len(rl.RevokedCertificateEntries); got != 2 {
		t.Fatalf("CRL carries %d entries, want 2 (dup dropped)", got)
	}
}

func TestIssueWorkloadCertWithDP(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	ca, _, _ := NewIdentityCA(key, "identity CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_, subj, _ := ed25519.GenerateKey(rand.Reader)
	leaf, err := IssueWorkloadCertWithDP(ca, key, subj.Public().(ed25519.PublicKey), "user-1", 1, time.Minute, "http://ca/identity.crl")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.CRLDistributionPoints) != 1 || parsed.CRLDistributionPoints[0] != "http://ca/identity.crl" {
		t.Fatalf("CRL distribution points = %v", parsed.CRLDistributionPoints)
	}
	// Legacy wrapper: no DP stamped.
	plain, _ := IssueWorkloadCert(ca, key, subj.Public().(ed25519.PublicKey), "user-1", 2, time.Minute)
	parsed, _ = x509.ParseCertificate(plain)
	if len(parsed.CRLDistributionPoints) != 0 {
		t.Fatalf("legacy issue must not stamp a DP, got %v", parsed.CRLDistributionPoints)
	}
}
