package main

// to-council: council member node + manual recovery trigger (deployment
// guide §9). `serve` runs a persistent networked member (councilnet.go)
// holding one Shamir shard; `recover` reconstructs from >=3 shard files
// (from `to-tool shard`) and a DETECTED evidence file (from
// `to-tool bench run --out reports` -> reports/evidence.json).

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	to "trustorchestrator"
)

type evidenceFile struct {
	BadIndex int             `json:"bad_index"`
	Timeline json.RawMessage `json:"timeline"`
}

func main() {
	args := os.Args[1:]
	if len(args) < 1 {
		usage()
	}
	var err error
	switch args[0] {
	case "recover":
		err = recoverCmd(args[1:])
	case "serve":
		err = serveCmd(args[1:])
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
  to-council serve --id <C1> --addr <host:port> --shard <s.json> --ca <ca.der> --cert <leaf.der> --key <node.key>
    persistent networked member: answers VOTE (shard only on clean prefix)
    and COMMIT_REQ (signature only after P3/P5 re-verification) over mTLS
  to-council recover --evidence <file> --shards <s1.json> <s2.json> <s3.json> [--out <dir>]
    <file>: DETECTED evidence (reports/evidence.json from the benchmark)
    <sN.json>: Shamir shard files (>= 3) from 'to-tool shard'`)
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

// serveCmd runs one council member node: mTLS listener, one shard, node key
// from `to-identity issue --key-out` (64-byte hex) or a 32-byte seed.
func serveCmd(args []string) error {
	f := flags(args)
	for _, k := range []string{"id", "addr", "shard", "ca", "cert", "key"} {
		if f[k] == "" {
			return errors.New("usage: serve --id <C1> --addr <host:port> --shard <s.json> --ca <ca.der> --cert <leaf.der> --key <node.key>")
		}
	}
	b, err := os.ReadFile(f["shard"])
	if err != nil {
		return err
	}
	var s to.Shard
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("shard: %w", err)
	}
	raw, err := os.ReadFile(f["key"])
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return err
	}
	key := keyFromFile(seed)
	caDER, err := os.ReadFile(f["ca"])
	if err != nil {
		return err
	}
	leaf, err := os.ReadFile(f["cert"])
	if err != nil {
		return err
	}
	cfg, err := to.MutualTLSConfig(caDER, leaf, key)
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", f["addr"], cfg)
	if err != nil {
		return err
	}
	srv := to.NewCouncilMemberServer(f["id"], &s, key, cfg)
	fmt.Printf("council member %s listening on %s (shard %s, mTLS)\n", f["id"], f["addr"], f["shard"])
	return srv.Serve(ln)
}

// keyFromFile accepts the genkey format (full 64-byte ed25519 private key)
// or a 32-byte seed (ShamirJoin output) — both hex-encoded.
func keyFromFile(b []byte) ed25519.PrivateKey {
	if len(b) == 64 {
		return ed25519.PrivateKey(b)
	}
	return ed25519.NewKeyFromSeed(b)
}

func recoverCmd(args []string) error {
	evidencePath, outDir := "", ""
	var shardPaths []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--evidence":
			if i+1 < len(args) {
				evidencePath = args[i+1]
				i++
			}
		case "--shards":
			for i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				shardPaths = append(shardPaths, args[i+1])
				i++
			}
		case "--out":
			if i+1 < len(args) {
				outDir = args[i+1]
				i++
			}
		}
	}
	if evidencePath == "" || len(shardPaths) < 3 {
		return errors.New("usage: recover --evidence <file> --shards <s1.json> <s2.json> <s3.json> [--out <dir>]")
	}
	return recover(evidencePath, shardPaths, outDir)
}

func recover(evidencePath string, shardPaths []string, outDir string) error {
	raw, err := os.ReadFile(evidencePath)
	if err != nil {
		return err
	}
	var ev evidenceFile
	if err := json.Unmarshal(raw, &ev); err != nil {
		return fmt.Errorf("evidence: %w", err)
	}
	tl, err := to.UnmarshalTimeline(ev.Timeline)
	if err != nil {
		return fmt.Errorf("evidence timeline: %w", err)
	}
	shards := make([]*to.Shard, 0, len(shardPaths))
	for _, p := range shardPaths {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var s to.Shard
		if err := json.Unmarshal(b, &s); err != nil {
			return fmt.Errorf("shard %s: %w", p, err)
		}
		shards = append(shards, &s)
	}
	// RECONSTRUCT path: >=3 council members (P2), one shard each.
	members := make([]*to.CouncilMember, 0, len(shards))
	for i, s := range shards {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		members = append(members, &to.CouncilMember{ID: fmt.Sprintf("C%d", i+1), Key: k, Shard: s})
	}
	evidence := &to.TrustEvent{Type: to.EvDetected, Payload: mustJSON(map[string]int{"bad_index": ev.BadIndex}), Timestamp: 0}
	rep, err := to.NewCouncil(members).Recover(tl, evidence, 3)
	if err != nil {
		return err
	}
	fmt.Printf("RECOVER: %d/%d members voted (shards: %d)\n", len(members), 5, len(shards))
	fmt.Printf("RECONSTRUCT: %d shards -> root key, zeroized after use\n", len(shards))
	fmt.Printf("RE-ISSUE: %d certs re-issued\n", len(rep.Issued))
	for _, id := range rep.Issued {
		fmt.Printf("  issued %s\n", id)
	}
	fmt.Printf("COMMIT epoch %d -> canonical, root=%x\n", rep.Commit.Epoch, rep.Timeline.Head())
	for name, ok := range rep.Verify.Checks {
		verdict := "PASS"
		if !ok {
			verdict = "FAIL"
		}
		fmt.Printf("VERIFY %s: %s\n", name, verdict)
	}
	if !rep.Verify.Pass() {
		return fmt.Errorf("recovery verification failed")
	}
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return err
		}
		if err := rep.Timeline.Save(outDir+"/canonical.json", false); err != nil {
			return err
		}
		fmt.Printf("canonical fork written to %s/canonical.json\n", outDir)
	}
	return nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
