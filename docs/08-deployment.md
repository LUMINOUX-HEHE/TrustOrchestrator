# 08 — Deployment

What ships, what runs where, and what's the deployment layer's real status.

## The 8 binaries (`make build`, output to `bin/`)

| Binary | Purpose | Key commands |
|---|---|---|
| `to-tool` | offline bootstrap, calibration, generic | `genkey`, `shard`, `enroll`, `bench`, `revoke` |
| `to-bench` | benchmark runner (argv0 alias of `to-tool`) | `run --scenario all`, `calibrate` |
| `to-watchdog` | per-node watchdog (argv0 alias) | `enroll`, `run --events --kind --params --tail` |
| `to-orchestrator` | status, timeline, graph, policy, rollback | `status`, `timeline`, `verify --root`, `policy reload`, `rollback --dry-run` |
| `to-council` | recovery council CLI | reads share files, votes |
| `to-auditor` | mirror log checker | `audit --log` |
| `to-identity` | certificate authority | `ca`, `issue`, `verify` |
| `to-pdp` | policy decision point | `check --policy --events` |

All built with the same `cmd/to`/`cmd/orchestrator`… sources. `go build ./...`
exit 0.

## Bootstrap ceremony (guide §5, air-gapped)

1. Offline: `to-tool genkey <root>`
2. `to-tool shard --key <root> --shares 5 --threshold 3` → 5 pieces
3. `to-tool enroll` / `to-watchdog enroll` each node
4. `to-tool revoke --bootstrap <root>` — spent, genesis is over (FR8.2)

## Node config

- Short form (`--node-id C1 --role council`) or a flat `config.yaml`
  (node/role/detector/interval/threshold). One file, one command — NFR5.

## Deployment matrix

| Run mode | Reality today |
|---|---|
| Single binary, in-process (benchmarks) | yes — the entire fleet on one node |
| Two processes over mTLS loopback | yes — `TestWireRealSockets`, `TestFleetLiveVerdict` |
| N live processes on one host | yes — `fleet.go` (`to-orchestrator serve` + `to-watchdog run --live ...`); §5 below |
| systemd units | yes — `deploy/*.service`, run the `bin/linux` ELFs (`make build-linux`) |
| Docker on N hosts | **not shipped** (see 09) |
| Real VPN / eBPF consumers | **docs only** (to-dns stands in: real UDP query) |

## Live fleet on one host

Run the real transport — orchestrator daemon + N watchdog processes talking
over TLS 1.3 mTLS, not in-process calls. Keys are issued by `to-identity`
with its new `--key-out` (the leaf key the handshake needs):

```
to-tool genkey root.key
to-identity ca --key root.key --name fleet-ca --out ca.der
to-identity issue --ca ca.der --key root.key --identity orchestrator --out orch.der --key-out orch.key
to-identity issue --ca ca.der --key root.key --identity w1 --out w1.der --key-out w1.key   # w2, w3 …
to-orchestrator serve --listen 127.0.0.1:8333 --ca ca.der --cert orch.der --key orch.key
to-watchdog  run --events evidence.json --params params.json --node-id W1 --live 127.0.0.1:8333 \
               --ca ca.der --cert w1.der --key w1.key --server-name orchestrator   # repeat per node
```

The orchestrator prints one `ENSEMBLE: healthy|DETECTED (n/m nodes …)` line per
score frame — a real multi-process fan-in with concurrent peer handling
(`fleet.go`, replacing the old sequential-Accept design).
`FleetPeer.Send` redials on socket drops, so a watchdog restart does not tear
down the ensemble.

The whole ceremony above — build, key material, CA + leaves, `serve`, 3
watchdogs `--live`, and an assertion that the log shows both a healthy and a
DETECTED verdict — is one script:

```
make fleet-smoke          # bash deploy/fleet-smoke.sh [evidence.json] [port]
```

A watchdog can score the fleet on a real external probe instead of (or in
addition to) its detector: `--probe-cmd` runs a shell command each cycle and
maps exit 0 → score 100, non-zero → score 0 (W4 wiring, docs/09). The
canonical command is `to-dnsprobe` itself:

```
to-watchdog run --events evidence.json --node-id W4 --live 127.0.0.1:8333 \
  --ca ca.der --cert w4.der --key w4.key --server-name orchestrator \
  --probe-cmd "to-dnsprobe --server 8.8.8.8:53 --name example.com --type A"
```

## The sandbox

`tools/tla2tools.jar` + `specs/*` Java TLC model. Re-generate:

```
make model-check            # base spec P1..P6 → report = tlc.log
make model-check-mutations  # P2/P6 mutants must *fail* (artifact = mutation-*.log)
```

(Requires Java; on Windows `bin/` needs no Java at runtime.)

## No secrets in the zip

Keys and lives only offline/generated: `node.key`, `shard-*.json`, the dev
`bootstrap.key` are git-ignored (`reports/` and `bin/` are gitignored too).