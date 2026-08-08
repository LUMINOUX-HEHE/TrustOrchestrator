package main

// to-orchestrator: daily-operation view of the trust state (deployment
// guide §7: status, timeline, verify, graph). Reads a timeline dump
// (reports/evidence.json or any Save dump); without --events it builds the
// built-in demo chain.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	to "trustorchestrator"
)

func main() {
	args := os.Args[1:]
	if len(args) < 1 {
		usage()
	}
	cmd, events := args[0], ""
	tail := 20
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--events":
			if i+1 < len(args) {
				events = args[i+1]
				i++
			}
		case "--tail":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &tail)
				i++
			}
		}
	}
	tl, err := load(events)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	switch cmd {
	case "status":
		err = status(tl)
	case "timeline":
		err = timeline(tl, tail)
	case "verify":
		err = verify(tl, args)
	case "graph":
		err = graph(tl, args)
	case "policy":
		err = policyReload(tl, args)
	case "rollback":
		err = rollbackDryRun(tl, args)
	case "serve":
		err = serve(args)
	case "report":
		err = report(args)
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
  to-orchestrator status [--events <file>]
  to-orchestrator timeline --tail 20 [--events <file>]
  to-orchestrator verify --root <hash> [--events <file>]
  to-orchestrator graph --identity <fingerprint> [--events <file>]
  to-orchestrator policy reload --policy <policy.json> [--events <file>]
  to-orchestrator rollback --dry-run [--to <checkpoint-hash>] [--events <file>]
  to-orchestrator serve --listen <addr> --ca <ca.der> --cert <leaf.der> --key <key.hex>
  to-orchestrator report [--events <file>] [--gateway <gateway.json>] [--audit <audit.json>]
                     [--backup <file>] [--vault-keys <file>] [--policy <policy.json>]
                     [--out <file>]`)
	os.Exit(1)
}

func load(events string) (*to.Timeline, error) {
	if events != "" {
		tl, err := to.LoadTimeline(events)
		if err == nil && len(tl.Events()) > 0 {
			return tl, nil
		}
		// Accept benchmark evidence files ({bad_index, timeline}) — the
		// attack-state view the operator inspects (guide §8). LoadTimeline
		// succeeds on the envelope but yields 0 events, so empty timelines
		// also fall through.
		raw, rerr := os.ReadFile(events)
		if rerr == nil {
			var ev struct {
				Timeline json.RawMessage `json:"timeline"`
			}
			if json.Unmarshal(raw, &ev) == nil && len(ev.Timeline) > 0 {
				if tl, terr := to.UnmarshalTimeline(ev.Timeline); terr == nil {
					return tl, nil
				}
			}
		}
		return nil, err
	}
	// built-in demo chain: genesis + normal issuance
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := to.NewTimeline(key)
	for i := 0; i < 12; i++ {
		pl, _ := json.Marshal(map[string]string{"cert_id": fmt.Sprintf("c%d", i), "identity": "user"})
		tl.Append(to.EvIssue, pl, int64(i))
	}
	return tl, nil
}

// status prints the guide §8 operator view: per-watchdog scores, evidence,
// ensemble verdict, anchor hash.
func status(tl *to.Timeline) error {
	log := &to.AuditorLog{}
	for _, e := range tl.Events() {
		log.Mirror(e)
	}
	wd := []*to.Watchdog{
		to.NewWatchdog("W1", to.WDIssuanceRate, 1, 1, to.DefaultH1(), tl, log),
		to.NewWatchdog("W2", to.WDLogIntegrity, 0, 0, 0, tl, log),
		to.NewWatchdog("W3", to.WDGraphAnomaly, 0.5, 0.5, 3, tl, log),
		to.NewWatchdog("W4", to.WDExternalProbe, 0, 0, 0, tl, log),
		to.NewWatchdogBaseline("W5", to.WDBehaviorBaseline, 1, 0.5, 2, tl, log, map[string]float64{"user": 1}),
	}
	evs := tl.Events()
	scores := make([]to.Score, 0, len(wd))
	for i, e := range evs {
		for _, w := range wd {
			w.ObserveBatch([]to.TrustEvent{e}, i)
		}
	}
	for _, w := range wd {
		s := w.Score()
		scores = append(scores, s)
		fmt.Printf("%s score %.0f (evidence: %s)\n", s.NodeID, s.Score, s.Evidence)
	}
	if to.Detect(scores, 25.0, 3) {
		fmt.Println("ENSEMBLE: DETECTED (3/5 below threshold)")
	} else {
		fmt.Println("ENSEMBLE: healthy")
	}
	fmt.Printf("EPOCH: %d\n", epoch(tl))
	fmt.Printf("ANCHOR: %x\n", tl.Head())
	return nil
}

// epoch is the highest committed epoch on the timeline (guide §7 status).
func epoch(tl *to.Timeline) int64 {
	var e int64
	for _, ev := range tl.Events() {
		if ev.Type != to.EvCommit {
			continue
		}
		var p struct {
			Epoch int64 `json:"epoch"`
		}
		if json.Unmarshal(ev.Payload, &p) == nil && p.Epoch > e {
			e = p.Epoch
		}
	}
	return e
}

func timeline(tl *to.Timeline, tail int) error {
	evs := tl.Events()
	if len(evs) < tail {
		tail = len(evs)
	}
	for i, e := range evs[len(evs)-tail:] {
		var p struct {
			CertID   string `json:"cert_id"`
			Identity string `json:"identity"`
		}
		json.Unmarshal(e.Payload, &p)
		fmt.Printf("#%d %s cert=%s identity=%s ts=%d\n", len(evs)-tail+i, e.Type, p.CertID, p.Identity, e.Timestamp)
	}
	return nil
}

func verify(tl *to.Timeline, args []string) error {
	root := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--root" && i+1 < len(args) {
			root = args[i+1]
		}
	}
	if root == "" {
		return fmt.Errorf("verify requires --root <hash>")
	}
	want, err := hex.DecodeString(root)
	if err != nil {
		return fmt.Errorf("root: %w", err)
	}
	bad := tl.LocateBadEvent()
	if bad >= 0 {
		fmt.Printf("VERIFY: FAIL (chain broken at event #%d)\n", bad)
		return nil
	}
	if !bytesEqual(want, tl.Head()) {
		fmt.Printf("VERIFY: FAIL (root mismatch: chain=%x)\n", tl.Head())
		return nil
	}
	fmt.Println("VERIFY: PASS")
	return nil
}

func graph(tl *to.Timeline, args []string) error {
	id := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--identity" && i+1 < len(args) {
			id = args[i+1]
		}
	}
	if id == "" {
		return fmt.Errorf("graph requires --identity <fingerprint>")
	}
	g := to.BuildGraph(tl)
	for _, n := range g.Reachable("id:" + id) {
		fmt.Println(n)
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// policyReload (guide §7): validate the declared policy file and re-audit
// the current timeline against it. The policy is data in this deployment —
// reload re-reads it and re-decides immediately.
func policyReload(tl *to.Timeline, args []string) error {
	polPath := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--policy" && i+1 < len(args) {
			polPath = args[i+1]
			i++
		}
	}
	if polPath == "" {
		return fmt.Errorf("policy reload requires --policy <file>")
	}
	raw, err := os.ReadFile(polPath)
	if err != nil {
		return err
	}
	var pol to.Policy
	if err := json.Unmarshal(raw, &pol); err != nil {
		return err
	}
	if pol.MaxIssuesPerIdentityPerWindow <= 0 {
		return fmt.Errorf("policy: max_issues_per_identity_per_window must be > 0")
	}
	v := to.CheckPolicy(tl.Events(), pol)
	fmt.Printf("POLICY: LOADED max_issues_per_identity_per_window=%d\n", pol.MaxIssuesPerIdentityPerWindow)
	if len(v) == 0 {
		fmt.Printf("POLICY: CONFORMS (%d events audited)\n", len(tl.Events()))
		return nil
	}
	for _, s := range v {
		fmt.Println("POLICY: VIOLATION", s)
	}
	return nil
}

// rollbackDryRun (guide §9): show the invalidation set and the pre/post
// state sizes for a rollback to a verified checkpoint, without applying it.
func rollbackDryRun(tl *to.Timeline, args []string) error {
	toHash := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--to" && i+1 < len(args) {
			toHash = args[i+1]
			i++
		}
	}
	var want []byte
	if toHash != "" {
		var err error
		if want, err = hex.DecodeString(toHash); err != nil {
			return fmt.Errorf("--to: %w", err)
		}
	}
	bad := tl.LocateBadEvent()
	if bad < 0 {
		// Structural chain is intact; a behavioral anomaly (W1/W3/W5) leaves
		// no gap — use the evidence envelope's bad_index when present.
		evPath := ""
		for i := 1; i < len(args); i++ {
			if args[i] == "--events" && i+1 < len(args) {
				evPath = args[i+1]
			}
		}
		if evPath != "" {
			if raw, e := os.ReadFile(evPath); e == nil {
				var ev struct {
					BadIndex int `json:"bad_index"`
				}
				if json.Unmarshal(raw, &ev) == nil && ev.BadIndex > 0 {
					bad = ev.BadIndex
				}
			}
		}
	}
	if bad < 0 {
		fmt.Println("ROLLBACK DRY-RUN: chain intact, nothing to roll back")
		return nil
	}
	checkpoint := bad - 1 // last verified good event
	for i, e := range tl.Events() {
		if bytesEqual(e.Hash(), want) {
			checkpoint = i
			break
		}
	}
	if checkpoint < 0 || checkpoint >= bad {
		return fmt.Errorf("--to: checkpoint is not before the first bad event (#%d)", bad)
	}
	certs, ids := to.InvalidationSet(tl, checkpoint+1)
	post := tl.Fold()
	fork, err := tl.Fork(tl.Events()[checkpoint].Hash())
	if err != nil {
		return err
	}
	pre := fork.Fold()
	fmt.Printf("ROLLBACK DRY-RUN: checkpoint #%d (verified), first bad event #%d\n", checkpoint, bad)
	fmt.Printf("  would invalidate %d cert(s) across %d identity(ies)\n", len(certs), len(ids))
	for c := range certs {
		fmt.Println("    -", c)
	}
	fmt.Printf("  state: %d certs pre-compromise -> %d certs compromised\n", len(pre.Certs), len(post.Certs))
	return nil
}

// report (compliance.go): evidence-based compliance report over the files
// the operator has — timeline dump, gateway.json, audit export, backup and
// vault-key artifacts. Writes the JSON report to --out and prints a status
// summary. Flags are optional evidence: what is not provided shows up as
// missing/manual in the report, not silently skipped.
func report(args []string) error {
	events, gateway, auditPath, backupPath, vaultPath, policyPath, out := "", "", "", "", "", "", "reports/compliance.json"
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--events":
			if i+1 < len(args) {
				events, i = args[i+1], i+1
			}
		case "--gateway":
			if i+1 < len(args) {
				gateway, i = args[i+1], i+1
			}
		case "--audit":
			if i+1 < len(args) {
				auditPath, i = args[i+1], i+1
			}
		case "--backup":
			if i+1 < len(args) {
				backupPath, i = args[i+1], i+1
			}
		case "--vault-keys":
			if i+1 < len(args) {
				vaultPath, i = args[i+1], i+1
			}
		case "--policy":
			if i+1 < len(args) {
				policyPath, i = args[i+1], i+1
			}
		case "--out":
			if i+1 < len(args) {
				out, i = args[i+1], i+1
			}
		}
	}
	tl, err := load(events)
	if err != nil {
		return err
	}
	ev := &to.ComplianceEvidence{Timeline: tl}
	if gateway != "" {
		raw, err := os.ReadFile(gateway)
		if err != nil {
			return fmt.Errorf("--gateway: %w", err)
		}
		var gw struct {
			Users    map[string]*to.User `json:"users"`
			Webhooks []json.RawMessage   `json:"webhooks"`
		}
		if err := json.Unmarshal(raw, &gw); err != nil {
			return fmt.Errorf("--gateway: %w", err)
		}
		ev.Users = map[string]string{}
		for id, u := range gw.Users {
			ev.Users[id] = u.Role
		}
		ev.Webhooks = len(gw.Webhooks)
	}
	if auditPath != "" {
		raw, err := os.ReadFile(auditPath)
		if err != nil {
			return fmt.Errorf("--audit: %w", err)
		}
		var actions []to.AuditEntry
		if json.Unmarshal(raw, &actions) != nil {
			var wrapped struct {
				Actions []to.AuditEntry `json:"actions"`
			}
			if err := json.Unmarshal(raw, &wrapped); err != nil {
				return fmt.Errorf("--audit: not an audit export (need []AuditEntry or {\"actions\":[...]}): %w", err)
			}
			actions = wrapped.Actions
		}
		ev.AuditEntries = actions
	}
	if backupPath != "" {
		if _, err := os.Stat(backupPath); err != nil {
			return fmt.Errorf("--backup: %w", err)
		}
		ev.HasBackup = true
	}
	if vaultPath != "" {
		if _, err := os.Stat(vaultPath); err != nil {
			return fmt.Errorf("--vault-keys: %w", err)
		}
		ev.HasVault = true
	}
	if policyPath != "" {
		raw, err := os.ReadFile(policyPath)
		if err != nil {
			return fmt.Errorf("--policy: %w", err)
		}
		if err := json.Unmarshal(raw, &ev.Policy); err != nil {
			return fmt.Errorf("--policy: %w", err)
		}
	}
	r := to.BuildComplianceReport(ev)
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, b, 0o600); err != nil {
		return err
	}
	for _, f := range r.Frameworks {
		fmt.Printf("%s: %d pass, %d manual, %d missing\n", f.Name, f.Pass, f.Manual, f.Missing)
	}
	for _, fn := range r.Findings {
		fmt.Println("FINDING:", fn)
	}
	fmt.Printf("report written to %s\n", out)
	return nil
}

// serve runs the live fleet with relay: binds an mTLS listener and prints
// each ensemble verdict. Watchdogs stream per-cycle scores into it.
func serve(args []string) error {
	listen, caPath, certPath, keyPath := "", "", "", ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--listen":
			if i+1 < len(args) {
				listen = args[i+1]
				i++
			}
		case "--ca":
			if i+1 < len(args) {
				caPath = args[i+1]
				i++
			}
		case "--cert":
			if i+1 < len(args) {
				certPath = args[i+1]
				i++
			}
		case "--key":
			if i+1 < len(args) {
				keyPath = args[i+1]
				i++
			}
		}
	}
	if listen == "" || caPath == "" || certPath == "" || keyPath == "" {
		return errors.New("usage: serve --listen <addr> --ca <ca.der> --cert <leaf.der> --key <key.hex>")
	}
	caDER, err := os.ReadFile(caPath)
	if err != nil {
		return err
	}
	leafDER, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	keyRaw, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(string(keyRaw))
	if err != nil {
		return err
	}
	tlsCfg, err := to.MutualTLSConfig(caDER, leafDER, ed25519.PrivateKey(seed))
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", listen, tlsCfg)
	if err != nil {
		return err
	}
	fleet := to.NewFleet(25.0, 3, 5*30*time.Second)
	verds := fleet.Subscribe()
	fmt.Printf("orchestrator listening on %s (mTLS, TLS 1.3)\n", listen)
	go func() {
		for v := range verds {
			status := "healthy"
			if v.Detected {
				status = "DETECTED"
			}
			// count contributing nodes
			names := make([]string, 0, len(v.Scores))
			for _, s := range v.Scores {
				names = append(names, s.NodeID)
			}
			fmt.Printf("ENSEMBLE: %s (contributing=%d/%d nodes %v)\n", status, v.Count, v.Total, names)
		}
	}()
	err = fleet.Serve(ln)
	ln.Close()
	return err
}
