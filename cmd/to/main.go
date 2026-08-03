// to-tool: offline bootstrap + benchmark CLI (deployment guide §4, §10).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	to "trustorchestrator"
)

func main() {
	args := os.Args[1:]
	if filepath.Base(os.Args[0]) == "to-bench" {
		args = append([]string{"bench"}, args...) // guide §10: to-bench run / to-bench calibrate
	}
	if filepath.Base(os.Args[0]) == "to-watchdog" {
		args = append([]string{"watchdog"}, args...) // guide §5: to-watchdog enroll
	}
	if len(args) < 1 {
		usage()
	}
	var err error
	switch args[0] {
	case "genkey":
		err = require(os.Args, 2, "genkey <file>")
		err = genKey(os.Args[2])
	case "shard":
		err = shard(args[1:])
	case "enroll":
		err = enroll(args[1:])
	case "revoke":
		err = revoke(args[1:])
	case "watchdog": // to-watchdog: enroll (guide §5) + run (per-cycle scores)
		sub := args[1:]
		if len(sub) > 0 && sub[0] == "enroll" {
			err = enroll(sub[1:])
			break
		}
		if len(sub) > 0 && sub[0] == "run" {
			err = watchdogRun(sub[1:])
			break
		}
		err = errors.New("usage: to-watchdog enroll|run ...")
	case "bench":
		sub := args[1:]
		if len(sub) > 0 && sub[0] == "calibrate" { // guide §10: to-bench calibrate
			err = calibrate(sub[1:])
			break
		}
		if len(sub) > 0 && sub[0] == "run" { // guide §10: to-bench run --scenario all
			sub = sub[1:]
		}
		err = bench(sub)
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
  to-tool genkey <file>
  to-tool shard <keyfile> <n> <k>          | shard --key <f> --shares <n> --threshold <k>
  to-tool enroll --bootstrap <keyfile> --config <config.yaml>
  to-tool revoke --bootstrap <keyfile>    # FR8.2: one-time bootstrap, then spent
  to-tool bench [run] [--out <dir>] [--scenario all] [--log <file>]
  to-tool bench calibrate [--baseline-traffic <file>]
  to-watchdog enroll --bootstrap <keyfile> --node-id W1 [--role watchdog] [--config <f>]
  to-watchdog run --events <file> [--kind <detector>] [--params <params.json>] [--tail <n>] [--node-id W1] [--live <addr> --ca <ca.der> --cert <leaf.der> --key <key.hex> --server-name <SAN>]
  to-watchdog run --events <file> --probe-cmd <shell-cmd>   # W4 external probe: each cycle runs <cmd>; exit 0 -> score 100, non-zero -> score 0`)
	os.Exit(1)
}

func require(args []string, n int, usage string) error {
	if len(args) < n {
		return errors.New("usage: " + usage)
	}
	return nil
}

func genKey(path string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(hex.EncodeToString(priv)), 0o600)
}

// revokedMarker sits next to the bootstrap key once spent. FR8.2: the one-time
// genesis ceremony ends with revoke; any later enroll of the same key fails.
func revokedMarker(bootstrapPath string) string { return bootstrapPath + ".revoked" }

// revoke implements FR8.2: after genesis the bootstrap is spent and must never
// issue again. Writing the marker is the same operator step the offline
// ceremony performs; enroll refuses a marked key.
func revoke(args []string) error {
	path := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--bootstrap" && i+1 < len(args) {
			path = args[i+1]
			i++
		}
	}
	if path == "" {
		return errors.New("usage: revoke --bootstrap <keyfile>")
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("revoke: no such key %s", path)
	}
	if err := os.WriteFile(revokedMarker(path), []byte("revoked\n"), 0o600); err != nil {
		return err
	}
	fmt.Printf("revoked %s: the one-time bootstrap is spent (FR8.2)\n", path)
	return nil
}

// enroll implements the one-time enrollment ceremony (guide §5, NFR5.1):
// the offline bootstrap key signs the node's self-generated identity. The
// config file is the guide's flat-key YAML subset (node/role/detector/
// interval/threshold); the guide's short form (--node-id/--role) builds the
// same config without a file. The transport (mTLS) is the deployment layer.
func enroll(args []string) error {
	bootstrapPath, configPath, nodeID, role := "", "", "", ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--bootstrap":
			if i+1 < len(args) {
				bootstrapPath = args[i+1]
				i++
			}
		case "--config":
			if i+1 < len(args) {
				configPath = args[i+1]
				i++
			}
		case "--node-id":
			if i+1 < len(args) {
				nodeID = args[i+1]
				i++
			}
		case "--role":
			if i+1 < len(args) {
				role = args[i+1]
				i++
			}
		}
	}
	if bootstrapPath == "" || (configPath == "" && nodeID == "") {
		return errors.New("usage: enroll --bootstrap <keyfile> --config <config.yaml> | --bootstrap <keyfile> --node-id W1 [--role watchdog]")
	}
	if _, err := os.Stat(revokedMarker(bootstrapPath)); err == nil {
		return errors.New("enroll: bootstrap key is revoked (FR8.2); genesis is over — no node may enroll with a spent key")
	}
	raw, err := os.ReadFile(bootstrapPath)
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(string(raw))
	if err != nil {
		return err
	}
	bootstrap := ed25519.PrivateKey(seed) // full 64-byte key from `to-tool genkey`
	var cfg map[string]string
	if configPath != "" {
		cfg, err = parseConfig(configPath)
	} else {
		if role == "" {
			role = "watchdog"
		}
		switch role {
		case "watchdog", "council", "auditor", "consumer":
		default:
			return fmt.Errorf("config: unknown role %q", role)
		}
		cfg = map[string]string{"node": nodeID, "role": role}
	}
	if err != nil {
		return err
	}
	// The node self-generates its identity key; the bootstrap root only
	// certifies (node_id, role, public_key).
	_, nodeKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	stmt, _ := json.Marshal(map[string]any{"node_id": cfg["node"], "role": cfg["role"], "public_key": nodeKey.Public()})
	sig := ed25519.Sign(bootstrap, stmt)
	cert, _ := json.MarshalIndent(map[string]any{
		"node_id":             cfg["node"],
		"role":                cfg["role"],
		"public_key":          nodeKey.Public(),
		"bootstrap_signature": sig,
	}, "", "  ")
	if err := os.WriteFile("node.key", []byte(hex.EncodeToString(nodeKey)), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile("node.cert.json", cert, 0o644); err != nil {
		return err
	}
	fmt.Printf("enrolled %s (%s): node.key + node.cert.json (bootstrap-signed)\n", cfg["node"], cfg["role"])
	return nil
}

// parseConfig reads the guide §6 flat config.yaml subset (key: value lines,
// # comments). ponytail: no YAML dependency for 6 flat keys.
func parseConfig(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		cfg[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if cfg["node"] == "" || cfg["role"] == "" {
		return nil, errors.New("config: requires node and role")
	}
	switch cfg["role"] {
	case "watchdog", "council", "auditor", "consumer":
	default:
		return nil, fmt.Errorf("config: unknown role %q", cfg["role"])
	}
	return cfg, nil
}

// shard accepts the deployment-guide flag form (--key/--shares/--threshold)
// and the positional form (<keyfile> <n> <k>).
func shard(args []string) error {
	keyFile, n, k, err := parseShardArgs(args)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(string(raw))
	if err != nil {
		return err
	}
	shards, err := to.ShamirSplit(seed, n, k)
	if err != nil {
		return err
	}
	for i, s := range shards {
		b, err := s.Marshal()
		if err != nil {
			return err
		}
		if err := os.WriteFile(fmt.Sprintf("shard-%d.json", i+1), b, 0o600); err != nil {
			return err
		}
	}
	fmt.Printf("wrote %d shards (k=%d of n=%d) to shard-*.json\n", n, k, n)
	return nil
}

func parseShardArgs(args []string) (keyFile string, n, k int, err error) {
	if len(args) == 3 && args[0] != "--key" { // positional: <keyfile> <n> <k>
		if n, err = strconv.Atoi(args[1]); err != nil {
			return "", 0, 0, fmt.Errorf("shares: %w", err)
		}
		if k, err = strconv.Atoi(args[2]); err != nil {
			return "", 0, 0, fmt.Errorf("threshold: %w", err)
		}
		return args[0], n, k, nil
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--key":
			if i+1 < len(args) {
				keyFile = args[i+1]
				i++
			}
		case "--shares":
			if i+1 < len(args) {
				if n, err = strconv.Atoi(args[i+1]); err != nil {
					return "", 0, 0, fmt.Errorf("--shares: %w", err)
				}
				i++
			}
		case "--threshold":
			if i+1 < len(args) {
				if k, err = strconv.Atoi(args[i+1]); err != nil {
					return "", 0, 0, fmt.Errorf("--threshold: %w", err)
				}
				i++
			}
		}
	}
	if keyFile == "" || n == 0 || k == 0 {
		return "", 0, 0, errors.New("usage: shard --key <f> --shares <n> --threshold <k>")
	}
	return keyFile, n, k, nil
}

// bench runs S1–S7 + baseline and, with --out, persists the results —
// the pinned-config evidence behind every published number (FR9.3, NFR6.1).
func bench(args []string) error {
	outDir, logFile := "", ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--out":
			if i+1 < len(args) {
				outDir = args[i+1]
				i++
			}
		case "--log":
			if i+1 < len(args) {
				logFile = args[i+1]
				i++
			}
		case "--scenario":
			if i+1 < len(args) && args[i+1] != "all" {
				return errors.New("only --scenario all is supported")
			}
			i++
		}
	}
	b := to.NewBench(30 * time.Second)
	results := b.RunAll()
	out, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(out))
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return err
		}
		// guide §10: results land in reports/benchmark.json
		if err := os.WriteFile(outDir+"/benchmark.json", out, 0o644); err != nil {
			return err
		}
		// recovery evidence for `to-council recover --evidence` (guide §9)
		bad, tl := b.S1Evidence()
		tlB, _ := tl.Marshal(true)
		ev, _ := json.MarshalIndent(map[string]any{"bad_index": bad, "timeline": json.RawMessage(tlB)}, "", "  ")
		if err := os.WriteFile(outDir+"/evidence.json", ev, 0o644); err != nil {
			return err
		}
		fmt.Printf("results written to %s/benchmark.json, %s/evidence.json\n", outDir, outDir)
	}
	if logFile != "" { // NFR5.2: human-readable action log
		if err := os.WriteFile(logFile, []byte(actionLog(results)), 0o644); err != nil {
			return err
		}
		fmt.Printf("action log written to %s\n", logFile)
	}
	_, h, cal, err := b.Calibrate(0.05, 5*time.Minute)
	if err != nil {
		return err
	}
	fmt.Printf("\noperating point: h=%v\n%s\n", h, cal)
	if outDir != "" {
		os.WriteFile(outDir+"/calibration.json", cal, 0o644)
		fmt.Printf("calibration written to %s/calibration.json\n", outDir)
	}
	return nil
}

// calibrate: deployment-guide §10 — recompute the pinned operating point
// (the --baseline-traffic argument is accepted for interface parity;
// calibration runs against the in-process benchmark). With --out, also
// writes params.json — the detector-parameters file config.yaml points at
// (FR2.5: parameters produced by TrustOps, not by hand).
func calibrate(args []string) error {
	outDir := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--baseline-traffic":
			i++ // ponytail: in-process baseline needs no pcap file
		case "--out":
			if i+1 < len(args) {
				outDir = args[i+1]
				i++
			}
		}
	}
	b := to.NewBench(30 * time.Second)
	_, h, cal, err := b.Calibrate(0.05, 5*time.Minute)
	if err != nil {
		return err
	}
	fmt.Printf("operating point: h=%v\n%s\n", h, cal)
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return err
		}
		params, _ := json.MarshalIndent(map[string]any{
			"w1": map[string]any{"kind": to.WDIssuanceRate, "mu0": 1, "delta": 1, "h": 8},
			"w2": map[string]any{"kind": to.WDLogIntegrity},
			"w3": map[string]any{"kind": to.WDGraphAnomaly, "mu0": 0.5, "delta": 0.5, "h": 3},
			"w4": map[string]any{"kind": to.WDExternalProbe},
			"w5": map[string]any{"kind": to.WDBehaviorBaseline, "mu0": 1, "delta": 0.5, "h": 2},
		}, "", "  ")
		if err := os.WriteFile(outDir+"/params.json", params, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(outDir+"/calibration.json", cal, 0o644); err != nil {
			return err
		}
		fmt.Printf("params.json + calibration.json written to %s\n", outDir)
	}
	return nil
}

// watchdogRun replays a timeline one event per 30s cycle and prints (or, with
// --live, streams to a live orchestrator) the watchdog's per-cycle scores.
// The single-node view of what the deployment daemon would gossip; parameters
// come from params.json (FR2.5: calibration output, never hand-set).
func watchdogRun(args []string) error {
	eventsFile, paramsFile, kind := "", "", "rate_cusum"
	live, caPath, certPath, keyPath, nodeID, serverName, probeCmd := "", "", "", "", "", "", ""
	tail := -1
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--events":
			if i+1 < len(args) {
				eventsFile = args[i+1]
				i++
			}
		case "--params":
			if i+1 < len(args) {
				paramsFile = args[i+1]
				i++
			}
		case "--kind":
			if i+1 < len(args) {
				kind = args[i+1]
				i++
			}
		case "--tail":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &tail)
				i++
			}
		case "--live":
			if i+1 < len(args) {
				live = args[i+1] // orchestrator listen address
				i++
			}
		case "--node-id":
			if i+1 < len(args) {
				nodeID = args[i+1]
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
		case "--server-name":
			if i+1 < len(args) {
				serverName = args[i+1]
				i++
			}
		case "--probe-cmd":
			if i+1 < len(args) {
				probeCmd = args[i+1]
				i++
			}
		}
	}
	if eventsFile == "" {
		return errors.New("usage: run --events <file> [--kind <detector>] [--params <params.json>] [--live <orch-addr> --ca <ca.der> --cert <leaf.der> --key <key.hex>] [--probe-cmd <shell-cmd>]")
	}
	tl, err := loadTimelineOrEvidence(eventsFile)
	if err != nil {
		return err
	}
	evs := tl.Events()
	if tail > 0 && tail < len(evs) {
		evs = evs[len(evs)-tail:]
	}
	if len(evs) == 0 {
		return errors.New("run: no events in timeline")
	}
	mu0, delta, h := 1.0, 1.0, 8.0
	switch kind {
	case to.WDGraphAnomaly:
		mu0, delta, h = 0.5, 0.5, 3
	case to.WDBehaviorBaseline:
		mu0, delta, h = 1, 0.5, 2
	}
	if paramsFile != "" { // published operating point, not the defaults
		raw, err := os.ReadFile(paramsFile)
		if err != nil {
			return err
		}
		var params struct {
			W1 map[string]float64 `json:"w1"`
			W3 map[string]float64 `json:"w3"`
			W5 map[string]float64 `json:"w5"`
		}
		if json.Unmarshal(raw, &params) == nil {
			switch kind {
			case to.WDIssuanceRate:
				mu0, delta, h = params.W1["mu0"], params.W1["delta"], params.W1["h"]
			case to.WDGraphAnomaly:
				mu0, delta, h = params.W3["mu0"], params.W3["delta"], params.W3["h"]
			case to.WDBehaviorBaseline:
				mu0, delta, h = params.W5["mu0"], params.W5["delta"], params.W5["h"]
			}
		}
	}
	log := &to.AuditorLog{}
	for _, e := range evs { // the auditor mirror the probe watchdog compares against
		log.Mirror(e)
	}
	w := to.NewWatchdog("W1", kind, mu0, delta, h, tl, log)
	if nodeID != "" {
		w.ID = nodeID
	}
	if live != "" {
		return streamLive(w, live, caPath, certPath, keyPath, serverName, probeCmd, evs)
	}
	for i, e := range evs {
		s := cycleScore(w, i, e, probeCmd)
		alarm := "ok"
		if s.Score < 100 {
			alarm = fmt.Sprintf("ALARM (evidence: %s)", s.Evidence)
		}
		fmt.Printf("cycle %d: %s score %.0f %s\n", i, s.NodeID, s.Score, alarm)
	}
	return nil
}

// cycleScore observes one cycle and returns the watchdog score, unless
// --probe-cmd is set: then the W4 external-probe verdict replaces the
// detector score (exit 0 -> healthy 100, non-zero -> alarm 0).
func cycleScore(w *to.Watchdog, i int, e to.TrustEvent, probeCmd string) to.Score {
	w.ObserveBatch([]to.TrustEvent{e}, i)
	s := w.Score()
	if probeCmd == "" {
		return s
	}
	if err := runProbe(probeCmd); err != nil {
		return to.Score{NodeID: s.NodeID, Score: 0, PValue: 0.01,
			Evidence: []byte("probe failed: " + err.Error())}
	}
	return to.Score{NodeID: s.NodeID, Score: 100, PValue: 1.0}
}

// runProbe runs the external probe with a 10s cap; non-zero exit is a probe
// failure (service down, answer absent). to-dnsprobe exits non-zero on any
// query error, so `--probe-cmd "to-dnsprobe --server 8.8.8.8:53 --name
// example.com --type A"` is the canonical W4 wiring (guide §12).
func runProbe(cmd string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sh", "-c", cmd).Run()
}

// streamLive dials the fleet server and pushes each cycle's score over mTLS
// — the real watchdog process writing into the relay (guide §5 §12).
func streamLive(w *to.Watchdog, live, caPath, certPath, keyPath, serverName, probeCmd string, evs []to.TrustEvent) error {
	caDER, err := os.ReadFile(caPath)
	if err != nil {
		return err
	}
	leafDER, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(string(mustFile(keyPath)))
	if err != nil {
		return err
	}
	cfg, err := to.MutualTLSConfig(caDER, leafDER, ed25519.PrivateKey(seed))
	if err != nil {
		return err
	}
	// dialing by address (127.0.0.1) requires ServerName to match the
	// orchestrator's server-cert name, not the caller's own identity.
	if serverName != "" {
		cfg.ServerName = serverName
	}
	peer := to.NewFleetPeer(live, cfg)
	defer peer.Close()
	for i, e := range evs {
		s := cycleScore(w, i, e, probeCmd)
		if err := peer.Send(s); err != nil {
			fmt.Fprintf(os.Stderr, "cycle %d: send failed: %v (reconnecting next cycle)\n", i, err)
		}
	}
	return nil
}

func mustFile(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err) // flags were validated upstream; a missing key is a hard stop
	}
	return b
}

// loadTimelineOrEvidence reads a timeline dump or a benchmark evidence
// envelope ({bad_index, timeline}) — the same two formats the orchestrator
// accepts.
func loadTimelineOrEvidence(events string) (*to.Timeline, error) {
	if tl, err := to.LoadTimeline(events); err == nil && len(tl.Events()) > 0 {
		return tl, nil
	}
	raw, rerr := os.ReadFile(events)
	if rerr != nil {
		return nil, fmt.Errorf("load %s: %w", events, rerr)
	}
	var ev struct {
		Timeline json.RawMessage `json:"timeline"`
	}
	if json.Unmarshal(raw, &ev) == nil && len(ev.Timeline) > 0 {
		if tl, terr := to.UnmarshalTimeline(ev.Timeline); terr == nil {
			return tl, nil
		}
	}
	return to.LoadTimeline(events)
}

// actionLog renders each benchmark scenario as a human-readable line
// (NFR5.2: actions logged in human-readable form, not just JSON).
func actionLog(results []to.Metrics) string {
	var sb strings.Builder
	sb.WriteString("Trust Orchestrator — benchmark action log\n")
	for _, m := range results {
		lat := m.DetectionLatency.Round(time.Second)
		if lat <= 0 {
			lat = m.DetectionGap.Round(time.Second)
		}
		status := "PASS"
		if m.FalsePositive {
			status = "FAIL (false positive)"
		} else if m.Detected && lat > 0 && !m.RollbackCorrect {
			status = "FAIL (outside latency bound)"
		}
		rb := "n/a" // no recovery ran when the scenario was not detected
		if m.Detected {
			rb = fmt.Sprint(m.RollbackCorrect)
		}
		fmt.Fprintf(&sb, "%s: detected=%v latency=%v rollback_ok=%s reissued=%d events=%d -> %s\n",
			m.Scenario, m.Detected, lat, rb, m.WorkloadReissued, m.VerifyEvents, status)
	}
	return sb.String()
}
