package trustorchestrator

// identity: the workload issuer consumer (architecture §5.8). Real X.509
// via the standard library — the constraints rule says custom crypto only
// where the surface is constrained and vectors exist; crypto/x509 is the
// reviewed, test-vector-backed path (Wycheproof).

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// NewIdentityCA issues the self-signed root/CA certificate for the identity
// server. The CA key is the council-recovered root or its intermediate.
func NewIdentityCA(key ed25519.PrivateKey, name string, notBefore, notAfter time.Time) (*x509.Certificate, []byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, der, nil
}

// ParseIdentityCA parses the CA certificate from DER (the to-identity
// consumer's --ca path).
func ParseIdentityCA(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}

// IssueWorkloadCert issues a short-lived workload certificate for the
// subject's own key pair, signed by the CA (the recovery test subject:
// 180 certs, <= 60s target).
func IssueWorkloadCert(ca *x509.Certificate, caKey ed25519.PrivateKey, subject ed25519.PublicKey, identity string, serial int64, ttl time.Duration) ([]byte, error) {
	return IssueWorkloadCertWithDP(ca, caKey, subject, identity, serial, ttl, "")
}

// IssueWorkloadCertWithDP additionally stamps the certificate with its CRL
// distribution point (RFC 5280 §4.2.1.13) — verifiers locate the revocations
// list for this CA from the issued cert itself.
func IssueWorkloadCertWithDP(ca *x509.Certificate, caKey ed25519.PrivateKey, subject ed25519.PublicKey, identity string, serial int64, ttl time.Duration, crlDP string) ([]byte, error) {
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: identity},
		DNSNames:     []string{identity}, // modern hostname verification (SANs)
		NotBefore:    now,
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	if crlDP != "" {
		tmpl.CRLDistributionPoints = []string{crlDP}
	}
	return x509.CreateCertificate(rand.Reader, tmpl, ca, subject, caKey)
}

// RevokedCert is one entry on the CA's revocation list (RFC 5280 §3.3).
// ponytail: serial + time only; reason codes arrive with the ledger.
type RevokedCert struct {
	SerialNumber *big.Int
	RevokedAt    time.Time
}

// NewCRL issues an RFC 5280 CRL signed by the CA. Each CRL carries a
// monotonically increasing number; revocations are appended by re-signing
// with the next number (AppendRevocation).
func NewCRL(ca *x509.Certificate, caKey ed25519.PrivateKey, number int64, revoked []RevokedCert, thisUpdate, nextUpdate time.Time) ([]byte, error) {
	entries := make([]x509.RevocationListEntry, len(revoked))
	for i, r := range revoked {
		entries[i] = x509.RevocationListEntry{SerialNumber: r.SerialNumber, RevocationTime: r.RevokedAt}
	}
	tmpl := &x509.RevocationList{
		SignatureAlgorithm:          x509.PureEd25519,
		Issuer:                      ca.Subject,
		Number:                      big.NewInt(number),
		ThisUpdate:                  thisUpdate,
		NextUpdate:                  nextUpdate,
		RevokedCertificateEntries:   entries,
	}
	return x509.CreateRevocationList(rand.Reader, tmpl, ca, caKey)
}

// VerifyCRL parses the CRL and checks its signature against the CA and its
// validity window at `now` — a stale or forged CRL fails cleanly.
func VerifyCRL(crlDER, caDER []byte, now time.Time) (*x509.RevocationList, error) {
	rl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	if err := rl.CheckSignatureFrom(ca); err != nil {
		return nil, err
	}
	if now.Before(rl.ThisUpdate) || now.After(rl.NextUpdate) {
		return nil, fmt.Errorf("CRL validity window (%s .. %s) does not cover %s", rl.ThisUpdate.Format(time.RFC3339), rl.NextUpdate.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	return rl, nil
}

// CheckRevoked reports whether the leaf's serial number is on the CRL
// (RFC 5280 §5.2.6 serial-number match; no reason-code semantics).
func CheckRevoked(leafDER, crlDER []byte) (bool, error) {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return false, err
	}
	rl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return false, err
	}
	for _, e := range rl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			return true, nil
		}
	}
	return false, nil
}

// AppendRevocation re-signs an existing CRL with the added revocations,
// under the next CRL number. Duplicate serials are dropped. The caller owns
// the number sequence (the CLI takes it from the loaded CRL + 1, or 1 for a
// fresh list).
func AppendRevocation(ca *x509.Certificate, caKey ed25519.PrivateKey, oldCRL []byte, number int64, revoked []RevokedCert, thisUpdate, nextUpdate time.Time) ([]byte, error) {
	old, err := x509.ParseRevocationList(oldCRL)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	combined := make([]x509.RevocationListEntry, 0, len(old.RevokedCertificateEntries)+len(revoked))
	for _, e := range old.RevokedCertificateEntries {
		seen[e.SerialNumber.String()] = true
		combined = append(combined, e)
	}
	for _, r := range revoked {
		if seen[r.SerialNumber.String()] {
			continue
		}
		combined = append(combined, x509.RevocationListEntry{SerialNumber: r.SerialNumber, RevocationTime: r.RevokedAt})
	}
	tmpl := &x509.RevocationList{
		SignatureAlgorithm:        x509.PureEd25519,
		Issuer:                    ca.Subject,
		Number:                    big.NewInt(number),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: combined,
	}
	return x509.CreateRevocationList(rand.Reader, tmpl, ca, caKey)
}

// VerifyWorkloadChain parses a DER leaf and verifies it against the CA
// root: signature, validity period, key usage (malformed/tampered/expired
// input is rejected — the auditable claim of the ASN.1 test row).
func VerifyWorkloadChain(leafDER, caDER []byte, now time.Time) error {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now})
	return err
}
