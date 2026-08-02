// to-identity: the workload issuer consumer (architecture §5.8, guide §3).
// Mints the identity CA from the council-recovered root key and issues
// short-lived X.509 workload certs; the same library the mTLS path uses.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
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
  to-identity issue --ca <ca.der> --key <ca.key> --identity <name> [--serial N] [--ttl 10m] [--out leaf.der]
  to-identity verify --cert <leaf.der> --ca <ca.der>`)
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
	leaf, err := to.IssueWorkloadCert(ca, keyFromFile(seed), subjKey.Public().(ed25519.PublicKey), f["identity"], serial, ttl)
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
	fmt.Printf("issued %s (serial %d, ttl %s) -> %s\n", f["identity"], serial, ttl, out)
	return nil
}

func verify(args []string) error {
	f := flags(args)
	if f["cert"] == "" || f["ca"] == "" {
		return errors.New("usage: verify --cert <leaf.der> --ca <ca.der>")
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
	fmt.Println("VERIFY: PASS")
	return nil
}
