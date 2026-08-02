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
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
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
	return x509.CreateCertificate(rand.Reader, tmpl, ca, subject, caKey)
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
