package trustorchestrator

// mtls: the consumer transport (architecture §5.8; guide §12 "mTLS only
// after enrollment"). Mutual TLS over workload certs issued by the identity
// consumer — the transport the VPN/DNS consumers would carry.
// ponytail: stdlib crypto/tls; loopback-verified unit only, real deployments
// terminate TLS at the service layer.

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
)

// MutualTLSConfig returns a server- or client-side config that requires and
// verifies the peer against the identity CA. Leaf certs come from
// IssueWorkloadCert (ExtKeyUsage client+server auth).
func MutualTLSConfig(caDER, leafDER []byte, key ed25519.PrivateKey) (*tls.Config, error) {
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: key}},
		RootCAs:      pool,
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// VerifyPeerIdentity asserts the peer certificate's common name after the
// handshake — the application-level identity check on top of the CA chain.
func VerifyPeerIdentity(peer *x509.Certificate, want string) error {
	if peer.Subject.CommonName != want {
		return &x509.CertificateInvalidError{Cert: peer, Reason: x509.NameMismatch}
	}
	return nil
}
