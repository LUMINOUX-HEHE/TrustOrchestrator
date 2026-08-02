package main

// to-council: manual recovery trigger (deployment guide §9). Runs on the
// ceremony machine with >=3 shard files (from `to-tool shard`) and a
// DETECTED evidence file (from `to-tool bench run --out reports` ->
// reports/evidence.json).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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
	if len(args) < 2 || args[0] != "recover" {
		usage()
	}
	evidencePath, outDir := "", ""
	var shardPaths []string
	for i := 1; i < len(args); i++ {
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
		usage()
	}
	if err := recover(evidencePath, shardPaths, outDir); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  to-council recover --evidence <file> --shards <s1.json> <s2.json> <s3.json> [--out <dir>]
    <file>: DETECTED evidence (reports/evidence.json from the benchmark)
    <sN.json>: Shamir shard files (>= 3) from 'to-tool shard'`)
	os.Exit(1)
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
