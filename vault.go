package trustorchestrator

// vault: envelope encryption for at-rest data (key-management plan, "near"
// tier). Two key layers sit above each payload:
//
//	KEK   held by the council as Shamir 3-of-5 shares (src shamir.go) —
//	      "threshold-as-KMS": the group is the key-holder, the KEK itself
//	      only materializes inside an unwrap session, then is zeroed.
//	DEK   data-encryption key, sealed by the KEK in gateway.keys.
//	epoch  bumps on every rotation.
//	subKey HKDF-SHA256(EK, tenant ‖ epoch): per-tenant, per-epoch.
//	dk     per-file 32-byte data key, sealed under the subKey; the payload
//	      sits under dk.
//
// So rotating the EK (RotateVault) re-wraps only the 60-byte dk box per
// tenant file: the payload ciphertext is copied, never re-encrypted, and
// every pre-rotation snapshot (EK or tenant file) can no longer be opened —
// the "leaky file becomes non-recoverable after the next rotation" property.
// ponytail: the dk box lives inside the same file as the payload, so a
// rotation still rewrites the file; split the box into its own file when
// payloads outgrow the rewrite cost.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

const (
	vaultMagic = "TOENC2" // v2 tenant files (legacy: plaintext / TOENC1 store.go)
	keysMagic  = "TOKEYS1" // gateway.keys: EK sealed under the council KEK
)

// Vault is a live EK + epoch. It is the only key state the gateway keeps in
// memory; the sealed form (gateway.keys) is what survives on disk.
type Vault struct {
	DEK   []byte // 32-byte data-encryption key
	Epoch uint64
}

// NewVault mints a fresh vault (epoch 1). Used the first time a store is
// moved to envelope encryption.
func NewVault() (*Vault, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	return &Vault{DEK: dek, Epoch: 1}, nil
}

// ShareKEK wraps the key-encryption key into n Shamir shares; k of them
// (3-of-5 for the council) reconstruct it. No single share file is a key.
func ShareKEK(kek []byte, n, k int) ([]*Shard, error) { return ShamirSplit(kek, n, k) }

// JoinKEK is the unwrap session: any k shares back the KEK, which then
// exists only in the caller's memory (callers zero it with zeroBytes).
func JoinKEK(shares []*Shard) ([]byte, error) { return ShamirJoin(shares) }

// SubKey derives the per-tenant, per-epoch data key via HKDF-SHA256 on the
// EK. A new epoch yields new subkeys for every tenant; tenants are kept
// apart by the info string.
func (v *Vault) SubKey(tenant string) []byte {
	info := make([]byte, 0, len(tenant)+9)
	info = append(info, "vault:"...)
	info = append(info, tenant...)
	info = append(info, 0)
	var ep [8]byte
	binary.BigEndian.PutUint64(ep[:], v.Epoch)
	info = append(info, ep[:]...)
	key, err := hkdf.Key(sha256.New, v.DEK, nil, string(info), 32)
	if err != nil {
		panic(err) // hkdf never fails on a 32-byte key
	}
	return key
}

// Seal encrypts one tenant's payload into the vault envelope:
// [TOENC2][epoch][dkBox: 12+32+16][data: 12+len+16].
func (v *Vault) Seal(tenant string, plain []byte) ([]byte, error) {
	dk := make([]byte, 32)
	if _, err := rand.Read(dk); err != nil {
		return nil, err
	}
	dkBox, err := aesGCMSeal(v.SubKey(tenant), dk)
	if err != nil {
		return nil, err
	}
	data, err := aesGCMSeal(dk, plain)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(vaultMagic)+8+len(dkBox)+len(data))
	out = append(out, vaultMagic...)
	var ep [8]byte
	binary.BigEndian.PutUint64(ep[:], v.Epoch)
	out = append(out, ep[:]...)
	out = append(out, dkBox...)
	return append(out, data...), nil
}

// Open decrypts a vault envelope. It fails on a forged/drifted epoch
// (stale file after rotation), a wrong tenant, or a tamper.
func (v *Vault) Open(tenant string, blob []byte) ([]byte, error) {
	if !bytes.HasPrefix(blob, []byte(vaultMagic)) {
		return nil, errors.New("vault: not a vault-sealed file")
	}
	hdr := len(vaultMagic) + 8
	const dkBoxLen = 60 // 12 nonce + 32 key + 16 tag
	if len(blob) < hdr+dkBoxLen {
		return nil, errors.New("vault: truncated envelope")
	}
	if ep := binary.BigEndian.Uint64(blob[len(vaultMagic):]); ep != v.Epoch {
		return nil, fmt.Errorf("vault: envelope epoch %d != vault epoch %d (stale copy?)", ep, v.Epoch)
	}
	dk, err := aesGCMOpen(v.SubKey(tenant), blob[hdr:hdr+dkBoxLen])
	if err != nil {
		return nil, errors.New("vault: dk unwrap failed (wrong tenant or key)")
	}
	return aesGCMOpen(dk, blob[hdr+dkBoxLen:])
}

// aesGCMSeal is [nonce 12][ciphertext]. aesGCMOpen reverses it.
func aesGCMSeal(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, nil), nil
}

func aesGCMOpen(key, blob []byte) ([]byte, error) {
	if len(key) != 32 || len(blob) < 28 {
		return nil, errors.New("sealed box: bad key or length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, blob[:12], blob[12:], nil)
}

func zeroBytes(b []byte) { for i := range b { b[i] = 0 } }

// writeVaultKeyFile persists the sealed EK: [TOKEYS1][aesGCM(KEK, EK‖epoch)].
// Written only inside an unwrap session — the KEK itself never hits disk.
func writeVaultKeyFile(path string, kek []byte, v *Vault) error {
	body := make([]byte, 0, 40)
	body = append(body, v.DEK...)
	var ep [8]byte
	binary.BigEndian.PutUint64(ep[:], v.Epoch)
	box, err := aesGCMSeal(kek, append(body, ep[:]...))
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append([]byte(keysMagic), box...))
}

// readVaultKeyFile reverses writeVaultKeyFile.
func readVaultKeyFile(path string, kek []byte) (*Vault, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(b, []byte(keysMagic)) || len(b) != len(keysMagic)+68 {
		return nil, errors.New("vault: gateway.keys is not a TOKEYS file")
	}
	sek, err := aesGCMOpen(kek, b[len(keysMagic):])
	if err != nil {
		return nil, errors.New("vault: KEK does not open gateway.keys (wrong shares?)")
	}
	if len(sek) != 40 {
		return nil, errors.New("vault: gateway.keys holds a wrong-sized key")
	}
	return &Vault{DEK: sek[:32], Epoch: binary.BigEndian.Uint64(sek[32:])}, nil
}