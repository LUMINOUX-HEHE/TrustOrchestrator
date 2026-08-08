package trustorchestrator

// pq.go — post-quantum layer for the signing upgrade. The parts the Go
// stdlib ships publicly (Go 1.24+):
//
//	hybrid key agreement = X25519 (crypto/ecdh) ‖ ML-KEM-768
//	                      (crypto/mlkem, FIPS 203) → HKDF-SHA256
//
// Both halves must be broken for the channel key to leak: Shor breaks
// X25519, but ML-KEM-768 holds under Shor — so traffic captured today
// stays confidential even against a quantum computer later ("encrypt
// now, decrypt later" is the kill). Dual ML-DSA (FIPS 204) signatures
// are NOT in public Go stdlib yet (crypto/internal/fips140/mldsa only);
// the envelope type in Sigs reserves the slot with zero wire change.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// PQPublic is the wire form of one peer's hybrid public key.
type PQPublic struct {
	X25519 []byte `json:"x25519"` // 32 bytes
	MLKEM  []byte `json:"mlkem"`  // ML-KEM-768 encapsulation key (1184 b)
}

// PQKeyPair is one side's hybrid key material.
type PQKeyPair struct {
	dh *ecdh.PrivateKey
	ek *mlkem.DecapsulationKey768
}

// NewPQKeyPair generates a fresh hybrid pair.
func NewPQKeyPair() (*PQKeyPair, error) {
	dh, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	dek, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &PQKeyPair{dh: dh, ek: dek}, nil
}

// Public returns the wire form.
func (p *PQKeyPair) Public() PQPublic {
	return PQPublic{X25519: p.dh.PublicKey().Bytes(), MLKEM: p.ek.EncapsulationKey().Bytes()}
}

// PQClientShared is the initiator side of the hybrid handshake:
// X25519 ECDH with the peer's DH half, plus ML-KEM encapsulation to the
// peer's encapsulation key. Returns the ciphertext the initiator must
// send to the peer, and the session key.
func PQClientShared(mine *PQKeyPair, peer *PQPublic) (ciphertext, key []byte, err error) {
	if peer == nil || len(peer.X25519) != 32 || len(peer.MLKEM) == 0 {
		return nil, nil, errors.New("pq: bad peer public key")
	}
	px, err := ecdh.X25519().NewPublicKey(peer.X25519)
	if err != nil {
		return nil, nil, err
	}
	dh, err := mine.dh.ECDH(px)
	if err != nil {
		return nil, nil, err
	}
	ek, err := mlkem.NewEncapsulationKey768(peer.MLKEM)
	if err != nil {
		return nil, nil, err
	}
	ss, ct := ek.Encapsulate()
	if len(ct) == 0 || len(ss) != mlkem.SharedKeySize {
		return nil, nil, errors.New("pq: ML-KEM encapsulate failed")
	}
	key, err = deriveKey(dh, ss)
	if err != nil {
		return nil, nil, err
	}
	return ct, key, nil
}

// PQServerShared is the responder side: X25519 ECDH plus ML-KEM
// decapsulation of the ciphertext the initiator sent. Both sides then
// hold the same key.
func PQServerShared(mine *PQKeyPair, peer *PQPublic, ciphertext []byte) ([]byte, error) {
	if peer == nil || len(peer.X25519) != 32 || len(peer.MLKEM) == 0 {
		return nil, errors.New("pq: bad peer public key")
	}
	px, err := ecdh.X25519().NewPublicKey(peer.X25519)
	if err != nil {
		return nil, err
	}
	dh, err := mine.dh.ECDH(px)
	if err != nil {
		return nil, err
	}
	ss, err := mine.ek.Decapsulate(ciphertext)
	if err != nil {
		return nil, errors.New("pq: ML-KEM decapsulate: " + err.Error())
	}
	return deriveKey(dh, ss)
}

func deriveKey(dh, ss []byte) ([]byte, error) {
	secrets := append(dh, ss...)
	return hkdf.Key(sha256.New, secrets, nil, "trust-orchestrator/hybrid-v1", 32)
}

// PQFrame seal: AES-256-GCM under a hybrid session key (streams).
// Kept in pq.go so the KEM path is one place. Nonce is random; the
// wire format is 12-byte nonce ‖ tag ‖ cipher.
func pqSeal(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("pq: session key must be 32 bytes")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func pqOpen(key, sealed []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("pq: session key must be 32")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := sealed[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, sealed[gcm.NonceSize():], nil)
}

// Sigs: the 2030 story split into the part public Go gives us today.
// Reserve the ML-DSA slot so the wire shape doesn't change when
// crypto/mldsa goes public.
type Sigs struct {
	Ed25519 []byte `json:"ed25519"`         // canonical chain signature (today)
	MLDSA   []byte `json:"mldsa,omitempty"` // FIPS 204, when stdlib exposes it
}

// Sign produces a dual envelope: ed25519 now; the ML-DSA slot stays
// empty (documented ceiling — ML-DSA not public in Go stdlib as of 1.26).
func (s *Sigs) Sign(priv ed25519.PrivateKey, msg []byte) error {
	s.Ed25519 = ed25519.Sign(priv, msg)
	return nil
}

// Verify checks the Ed25519 member and, if a PQ member is present,
// requires a PQVerify from a future implementer (returns "not verified"
// rather than silently accepting PQ-only chains).
func (s *Sigs) Verify(pub ed25519.PublicKey, msg []byte) bool {
	if len(s.MLDSA) != 0 {
		return false // slot reserved: no public PQ verifier yet
	}
	return len(s.Ed25519) != 0 && ed25519.Verify(pub, msg, s.Ed25519)
}
