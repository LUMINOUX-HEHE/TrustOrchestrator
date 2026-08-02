package trustorchestrator

import (
	"crypto/ed25519"
	"crypto/rand"
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
