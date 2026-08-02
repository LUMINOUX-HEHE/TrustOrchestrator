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
| Two also-process over mTLS loopback | yes — `TestWireRealSockets` |
| systemd / Docker on N hosts | **docs only, not shipped** (see 09) |
| Real VPN/DNS/eBPF consumers | **docs only** |

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