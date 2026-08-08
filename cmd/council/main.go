package main

// to-council: council member node + manual recovery trigger (deployment
// guide §9). `dkg` runs the one-time ceremony (5 members, threshold 3) and
// writes one FROST share file per member; `serve` runs a persistent
// networked member holding one share; `recover` drives an in-process
// threshold recovery from >=3 share files and a DETECTED evidence file
// (from `to-tool bench run --out reports` -> reports/evidence.json).
// The root key never exists anywhere on this path.

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	case "dkg":
		err = dkgCmd(args[1:])
	case "dkg-net":
		err = dkgNetCmd(args[1:])
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
  to-council dkg --members <n> --threshold <k> --out <dir>
    one-time ceremony: writes share-1.json..share-n.json (FROST shares;
    the root never exists) and prints the council group key (the gateway's
    recovery trust anchor)
  to-council dkg-net --me <M1> --addr <host:port> --members <n> --threshold <k>
      --out <dir> --ca <ca.der> --cert <leaf.der> --key <node.key>
      --peers M1:host1:p1,M2:host2:p2,...
    distrustful ceremony, ONE PROCESS PER MEMBER MACHINE: pairwise,
    no coordinator — every member ends with only its own share file and
    the same group key; no single actor ever holds a polynomial. Run
    this command on all n machines with the same --peers list.
  to-council serve --id <C1> --addr <host:port> --share <s.json> --epoch <f> --ca <ca.der> --cert <leaf.der> --key <node.key>
    persistent networked member: answers VOTE (commitment only on clean
    prefix) and COMMIT_REQ (partial signature only after P3/P5 re-check)
    over mTLS; <f> persists the last committed epoch
  to-council recover --evidence <file> --shares <s1.json> <s2.json> <s3.json> [--out <dir>]
    <file>: DETECTED evidence (reports/evidence.json from the benchmark)
    <sN.json>: FROST share files (>= 3) from 'to-council dkg'`)
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

// dkgCmd runs the one-time FROST ceremony and writes one share file per
// member (mode 0600). The group key is printed for the gateway's
// --council-pub trust anchor.
func dkgCmd(args []string) error {
	f := flags(args)
	if f["members"] == "" || f["threshold"] == "" || f["out"] == "" {
		return errors.New("usage: dkg --members <n> --threshold <k> --out <dir>")
	}
	n := mustInt(f["members"])
	k := mustInt(f["threshold"])
	if k < 2 || k > n {
		return errors.New("need 2 <= threshold <= members")
	}
	signers, groupPub, err := to.DkgCeremony(n, k)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(f["out"], 0o700); err != nil {
		return err
	}
	for _, s := range signers {
		file := to.FrostShareFile{ID: s.ID, X: s.X, Y: s.Share,
			GroupPub: s.GroupPub, PubShare: s.PubShare, GlobalVK: s.GlobalVK}
		b, err := file.Marshal()
		if err != nil {
			return err
		}
		if err := os.WriteFile(fmt.Sprintf("%s/share-%s.json", f["out"], s.ID), b, 0o600); err != nil {
			return err
		}
	}
	fmt.Printf("wrote %d FROST shares to %s (threshold %d of %d)\n", n, f["out"], k, n)
	fmt.Printf("GROUP KEY (gateway --council-pub): %s\n", hex.EncodeToString(groupPub))
	fmt.Println("distribute one share file per council member machine; the root never existed")
	return nil
}

func mustInt(s string) int {
	var n int
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// loadShare reads one FROST share file into a signing participant.
func loadShare(path string) (*to.FrostSigner, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f to.FrostShareFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("share %s: %w", path, err)
	}
	s, err := f.Signer()
	if err != nil {
		return nil, fmt.Errorf("share %s: %w", path, err)
	}
	return s, nil
}

// memberTLS loads the mTLS identity shared by serve and dkg-net; the leaf
// key is also the member's node signing key.
func memberTLS(f map[string]string) (ed25519.PrivateKey, *tls.Config, error) {
	raw, err := os.ReadFile(f["key"])
	if err != nil {
		return nil, nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, nil, err
	}
	key := keyFromFile(seed)
	caDER, err := os.ReadFile(f["ca"])
	if err != nil {
		return nil, nil, err
	}
	leaf, err := os.ReadFile(f["cert"])
	if err != nil {
		return nil, nil, err
	}
	cfg, err := to.MutualTLSConfig(caDER, leaf, key)
	return key, cfg, err
}

// dkgNetCmd runs one member of a distrustful pairwise DKG ceremony: every
// member runs this on its own machine with the same --peers list. Each
// process keeps ONLY its own share; the group key must match across all
// members — every operator compares it out-of-band.
func dkgNetCmd(args []string) error {
	f := flags(args)
	for _, k := range []string{"me", "members", "threshold", "out", "ca", "cert", "key", "peers"} {
		if f[k] == "" {
			return errors.New("usage: dkg-net --me <M1> --members <n> --threshold <k> --out <dir> --ca <ca.der> --cert <leaf.der> --key <node.key> --peers M1:host:p1,M2:host:p2,...")
		}
	}
	n, err := strconv.Atoi(f["members"])
	if err != nil {
		return err
	}
	t, err := strconv.Atoi(f["threshold"])
	if err != nil {
		return err
	}
	peers := map[string]string{}
	for _, p := range strings.Split(f["peers"], ",") {
		ps := strings.SplitN(p, ":", 2)
		if len(ps) != 2 {
			return errors.New("bad --peers entry: " + p)
		}
		peers[ps[0]] = ps[1]
	}
	if len(peers) != n {
		return fmt.Errorf("--members %d != %d peers", n, len(peers))
	}
	_, cfg, err := memberTLS(f)
	if err != nil {
		return err
	}
	node, err := to.NewDkgNode(f["me"], f["addr"], n, t, cfg, peers)
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", f["addr"], cfg)
	if err != nil {
		return err
	}
	fmt.Printf("dkg member %s on %s: pairwise ceremony with %d members...\n", f["me"], f["addr"], n)
	group, err := node.RunOn(ln)
	if err != nil {
		return err
	}
	s := node.Signer()
	file := to.FrostShareFile{
		ID: f["me"], GroupPub: group,
		X: s.X, Y: s.Share, PubShare: s.PubShare, GlobalVK: s.GlobalVK,
	}
	b, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(f["out"], f["me"]+".json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	fmt.Printf("share file written to %s\n", path)
	fmt.Printf("GROUP KEY (verify identical on all %d members):\n%s\n", n, hex.EncodeToString(group))
	return nil
}

// serveCmd runs one council member node: mTLS listener, one FROST share,
// node key from `to-identity issue --key-out` (64-byte hex) or a 32-byte
// seed.
func serveCmd(args []string) error {
	f := flags(args)
	for _, k := range []string{"id", "addr", "share", "ca", "cert", "key"} {
		if f[k] == "" {
			return errors.New("usage: serve --id <C1> --addr <host:port> --share <s.json> --epoch <f> --ca <ca.der> --cert <leaf.der> --key <node.key>")
		}
	}
	signer, err := loadShare(f["share"])
	if err != nil {
		return err
	}
	key, cfg, err := memberTLS(f)
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", f["addr"], cfg)
	if err != nil {
		return err
	}
	srv := to.NewCouncilMemberServer(f["id"], signer, key, cfg, f["epoch"])
	fmt.Printf("council member %s listening on %s (share %s, mTLS)\n", f["id"], f["addr"], f["share"])
	return srv.Serve(ln)
}

// keyFromFile accepts the genkey format (full 64-byte ed25519 private key)
// or a 32-byte seed — both hex-encoded.
func keyFromFile(b []byte) ed25519.PrivateKey {
	if len(b) == 64 {
		return ed25519.PrivateKey(b)
	}
	return ed25519.NewKeyFromSeed(b)
}

func recoverCmd(args []string) error {
	evidencePath, outDir := "", ""
	var sharePaths []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--evidence":
			if i+1 < len(args) {
				evidencePath = args[i+1]
				i++
			}
		case "--shares":
			for i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				sharePaths = append(sharePaths, args[i+1])
				i++
			}
		case "--out":
			if i+1 < len(args) {
				outDir = args[i+1]
				i++
			}
		}
	}
	if evidencePath == "" || len(sharePaths) < 3 {
		return errors.New("usage: recover --evidence <file> --shares <s1.json> <s2.json> <s3.json> [--out <dir>]")
	}
	return recover(evidencePath, sharePaths, outDir)
}

func recover(evidencePath string, sharePaths []string, outDir string) error {
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
	signers := make([]*to.FrostSigner, 0, len(sharePaths))
	for _, p := range sharePaths {
		s, err := loadShare(p)
		if err != nil {
			return err
		}
		signers = append(signers, s)
	}
	// THRESHOLD path: >=3 members (P2), one share each. The root never
	// exists: the recovery fork is signed by the council group key.
	members := make([]*to.CouncilMember, 0, len(signers))
	for _, s := range signers {
		members = append(members, &to.CouncilMember{ID: s.ID, Share: s})
	}
	evidence := &to.TrustEvent{Type: to.EvDetected, Payload: mustJSON(map[string]int{"bad_index": ev.BadIndex}), Timestamp: 0}
	rep, err := to.NewCouncil(members).Recover(tl, evidence, 3)
	if err != nil {
		return err
	}
	fmt.Printf("RECOVER: %d/%d members signed the handoff\n", len(members), 5)
	fmt.Printf("RE-ISSUE: %d certs re-issued\n", len(rep.Issued))
	for _, id := range rep.Issued {
		fmt.Printf("  issued %s\n", id)
	}
	fmt.Printf("COMMIT epoch %d -> canonical, head=%x\n", rep.Commit.Epoch, rep.Timeline.Head())
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
		if err := rep.Timeline.Save(outDir+"/fork.json", false); err != nil {
			return err
		}
		cb, _ := json.MarshalIndent(rep.Commit, "", "  ")
		if err := os.WriteFile(outDir+"/commit.json", cb, 0o600); err != nil {
			return err
		}
		fmt.Printf("fork + handoff written to %s/{fork.json,commit.json} (POST to the gateway recover endpoint)\n", outDir)
	}
	return nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
