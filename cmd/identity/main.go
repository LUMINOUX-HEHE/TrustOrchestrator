// to-identity: the workload issuer consumer (architecture §5.8, guide §3).
// Mints the identity CA from the council-recovered root key and issues
// short-lived X.509 workload certs; the same library the mTLS path uses.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	to "trustorchestrator"
)

func main() {
	args := os.Args[1:]
	if len(args) < 1 {
		usage()
	}
	var err error
	switch args[0] {
	case "ca":
		err = mintCA(args[1:])
	case "issue":
		err = issue(args[1:])
	case "verify":
		err = verify(args[1:])
	case "revoke":
		err = revoke(args[1:])
	case "crl":
		err = crl(args[1:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  to-identity ca --key <recovered-root.key> [--name <cn>] [--out ca.der]
  to-identity issue --ca <ca.der> --key <ca.key> --identity <name> [--serial N] [--ttl 10m] [--crl-url <url>] [--out leaf.der] [--key-out leaf.key]
  to-identity verify --cert <leaf.der> --ca <ca.der> [--crl <crl.der>]
  to-identity revoke --ca <ca.der> --key <ca.key> --crl <crl.der> --serial <N[,N...]> [--out crl.der] [--next-update 24h] [--pem]
  to-identity crl --ca <ca.der> --file <crl.der> [--now <RFC3339>]`)
	os.Exit(1)
}

func flags(args []string) map[string]string {
	f := map[string]string{}
	for i := 0; i < len(args); i++ {
		if i+1 < len(args) && len(args[i]) > 2 && args[i][:2] == "--" {
			f[args[i][2:]] = args[i+1]
			i++
		}
	}
	return f
}

// mintCA: post-recovery bootstrap of the identity server (architecture §5.7
// step 4: council-reconstructed key -> new intermediate CA).
func mintCA(args []string) error {
	f := flags(args)
	if f["key"] == "" {
		return errors.New("usage: ca --key <file> [--name <cn>] [--out ca.der]")
	}
	raw, err := os.ReadFile(f["key"])
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(string(raw))
	if err != nil {
		return err
	}
	key := keyFromFile(seed)
	name := f["name"]
	if name == "" {
		name = "post-recovery CA"
	}
	_, der, err := to.NewIdentityCA(key, name, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if err != nil {
		return err
	}
	out := f["out"]
	if out == "" {
		out = "ca.der"
	}
	return os.WriteFile(out, der, 0o644)
}

// keyFromFile accepts either the genkey format (full 64-byte ed25519 private
// key) or a 32-byte seed (ShamirJoin output) — both hex-encoded.
func keyFromFile(b []byte) ed25519.PrivateKey {
	if len(b) == 64 {
		return ed25519.PrivateKey(b)
	}
	return ed25519.NewKeyFromSeed(b)
}

func issue(args []string) error {
	f := flags(args)
	if f["ca"] == "" || f["key"] == "" || f["identity"] == "" {
		return errors.New("usage: issue --ca <ca.der> --key <ca.key> --identity <name> [--serial N] [--ttl 10m] [--out leaf.der]")
	}
	caDER, err := os.ReadFile(f["ca"])
	if err != nil {
		return err
	}
	ca, err := to.ParseIdentityCA(caDER)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(f["key"])
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(string(raw))
	if err != nil {
		return err
	}
	serial := int64(1)
	if f["serial"] != "" {
		if serial, err = strconv.ParseInt(f["serial"], 10, 64); err != nil {
			return err
		}
	}
	ttl := 10 * time.Minute
	if f["ttl"] != "" {
		if ttl, err = time.ParseDuration(f["ttl"]); err != nil {
			return err
		}
	}
	_, subjKey, _ := ed25519.GenerateKey(rand.Reader)
	leaf, err := to.IssueWorkloadCertWithDP(ca, keyFromFile(seed), subjKey.Public().(ed25519.PublicKey), f["identity"], serial, ttl, f["crl-url"])
	if err != nil {
		return err
	}
	out := f["out"]
	if out == "" {
		out = "leaf.der"
	}
	if err := os.WriteFile(out, leaf, 0o644); err != nil {
		return err
	}
	// The node's private key belongs with the leaf (mTLS handshake); without
	// it the cert is unwieldable. genkey-format hex, 0600.
	if keyOut := f["key-out"]; keyOut != "" {
		if err := os.WriteFile(keyOut, []byte(hex.EncodeToString(subjKey)), 0o600); err != nil {
			return err
		}
		fmt.Printf("  leaf key -> %s (0600)\n", keyOut)
	}
	fmt.Printf("issued %s (serial %d, ttl %s) -> %s\n", f["identity"], serial, ttl, out)
	return nil
}

func verify(args []string) error {
	f := flags(args)
	if f["cert"] == "" || f["ca"] == "" {
		return errors.New("usage: verify --cert <leaf.der> --ca <ca.der> [--crl <crl.der>]")
	}
	leaf, err := os.ReadFile(f["cert"])
	if err != nil {
		return err
	}
	caDER, err := os.ReadFile(f["ca"])
	if err != nil {
		return err
	}
	if err := to.VerifyWorkloadChain(leaf, caDER, time.Now()); err != nil {
		return fmt.Errorf("VERIFY: FAIL (%v)", err)
	}
	if crlPath := f["crl"]; crlPath != "" {
		crlDER, err := os.ReadFile(crlPath)
		if err != nil {
			return err
		}
		if _, err := to.VerifyCRL(crlDER, caDER, time.Now()); err != nil {
			return fmt.Errorf("VERIFY: FAIL (CRL: %v)", err)
		}
		revoked, err := to.CheckRevoked(leaf, crlDER)
		if err != nil {
			return fmt.Errorf("VERIFY: FAIL (%v)", err)
		}
		if revoked {
			return errors.New("VERIFY: FAIL (certificate is REVOKED)")
		}
	}
	fmt.Println("VERIFY: PASS")
	return nil
}

// revoke adds serials to the CRL and re-signs it under the next number.
// Without an existing --crl it mints CRL #1. The serial ledger mapping
// cert_id -> serial lives with the issuer; the operator passes the serials
// from the recovery report's affected set (ledger-backed revocation is the
// upgrade path).
func revoke(args []string) error {
	f := flags(args)
	if f["ca"] == "" || f["key"] == "" || f["serial"] == "" {
		return errors.New("usage: revoke --ca <ca.der> --key <ca.key> --crl <crl.der> --serial <N[,N...]> [--out crl.der] [--next-update 24h] [--pem]")
	}
	caDER, err := os.ReadFile(f["ca"])
	if err != nil {
		return err
	}
	ca, err := to.ParseIdentityCA(caDER)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(f["key"])
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(string(raw))
	if err != nil {
		return err
	}
	caKey := keyFromFile(seed)
	now := time.Now()
	next := now.Add(24 * time.Hour)
	if f["next-update"] != "" {
		d, derr := time.ParseDuration(f["next-update"])
		if derr != nil {
			return derr
		}
		next = now.Add(d)
	}
	var serials []*big.Int
	for _, part := range strings.Split(f["serial"], ",") {
		n, ok := new(big.Int).SetString(strings.TrimSpace(part), 10)
		if !ok {
			return fmt.Errorf("bad serial %q", part)
		}
		serials = append(serials, n)
	}
	revoked := make([]to.RevokedCert, len(serials))
	for i, s := range serials {
		revoked[i] = to.RevokedCert{SerialNumber: s, RevokedAt: now}
	}
	var out []byte
	number := int64(1)
	if f["crl"] != "" {
		old, err := os.ReadFile(f["crl"])
		if err != nil {
			return err
		}
		oldRL, err := to.VerifyCRL(old, caDER, now)
		if err != nil {
			return err
		}
		number = oldRL.Number.Int64() + 1
		out, err = to.AppendRevocation(ca, caKey, old, number, revoked, now, next)
		if err != nil {
			return err
		}
	} else {
		out, err = to.NewCRL(ca, caKey, number, revoked, now, next)
		if err != nil {
			return err
		}
	}
	outPath := f["out"]
	if outPath == "" {
		outPath = f["crl"]
	}
	if outPath == "" {
		outPath = "crl.der"
	}
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		return err
	}
	if f["pem"] != "" {
		pemPath := outPath + ".pem"
		pemB := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: out})
		if err := os.WriteFile(pemPath, pemB, 0o644); err != nil {
			return err
		}
		fmt.Printf("CRL #%d: %d revoked, next update %s -> %s (+ %s)\n", number, len(revoked), next.Format(time.RFC3339), outPath, pemPath)
	} else {
		fmt.Printf("CRL #%d: %d revoked, next update %s -> %s\n", number, len(revoked), next.Format(time.RFC3339), outPath)
	}
	return nil
}

// crl inspects a published CRL: signature, window, and revoked serials.
func crl(args []string) error {
	f := flags(args)
	if f["ca"] == "" || f["file"] == "" {
		return errors.New("usage: crl --ca <ca.der> --file <crl.der> [--now <RFC3339>]")
	}
	caDER, err := os.ReadFile(f["ca"])
	if err != nil {
		return err
	}
	crlDER, err := os.ReadFile(f["file"])
	if err != nil {
		return err
	}
	now := time.Now()
	if f["now"] != "" {
		if now, err = time.Parse(time.RFC3339, f["now"]); err != nil {
			return err
		}
	}
	rl, err := to.VerifyCRL(crlDER, caDER, now)
	if err != nil {
		return fmt.Errorf("CRL: INVALID (%v)", err)
	}
	fmt.Printf("CRL: VALID #%d (this update %s, next %s, %d revoked)\n",
		rl.Number.Int64(), rl.ThisUpdate.Format(time.RFC3339), rl.NextUpdate.Format(time.RFC3339), len(rl.RevokedCertificateEntries))
	for _, e := range rl.RevokedCertificateEntries {
		fmt.Printf("  serial %s revoked %s\n", e.SerialNumber, e.RevocationTime.Format(time.RFC3339))
	}
	return nil
}
