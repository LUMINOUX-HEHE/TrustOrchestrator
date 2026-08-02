# Trust Orchestrator

Self-hosted PKI trust management with autonomous compromise detection,
council-mediated recovery, and verified time-travel rollback. Design and
requirements live in `docs/` (overview, architecture, requirements, threat
model, cryptography, workflow, testing, deployment, limitations) and
`trust-orchestrator-final-report.md`.

## Layout

- `*.go` — core library (timeline, watchdogs, council, rollback, auditors, consumers, identity)
- `cmd/to/` — CLI: bootstrap key generation, sharding, enrollment, benchmark, or watchdog (to-tool/to-bench/to-watchdog share one CLI)
- `cmd/orchestrator/`, `cmd/council/`, `cmd/auditor/` — daily-operation binaries (guide §7, §9)
- `cmd/identity/`, `cmd/pdp/` — consumer binaries: workload-cert issuer and policy reference (guide §3)
- `specs/` — TLA+ model, TLC model-check configuration, P2/P6 mutation tests
- `docs/` — self-contained documentation set (00 overview … 09 limitations)
- `tools/` — tla2tools.jar pinned for the model check
- `examples/` — policy + config samples
- `scratch/` — generated artifacts (keys, shards, binaries, coverage); git-ignored, never pushed

## Quick start

```bash
make test                  # unit + scenario tests (all green)
make benchmark             # TrustOps S1–S7 + baseline + calibration
make model-check           # TLC on specs/ (requires Java 21+), writes reports/tlc.log
make model-check-mutations # P2/P6 mutation tests — TLC must report a violation
make kill-tests            # kill-test (chaos) suite, writes reports/kill-tests.log
make build                 # to-tool, to-bench, to-watchdog, to-orchestrator, to-council, to-auditor, to-identity, to-pdp
```

Bootstrap + enrollment ceremony (offline machine / per node):

```bash
go run ./cmd/to genkey bootstrap.key
go run ./cmd/to shard --key bootstrap.key --shares 5 --threshold 3   # 5 shard files
go run ./cmd/to enroll --bootstrap bootstrap.key --config config.yaml
go run ./cmd/to enroll --bootstrap bootstrap.key --node-id W1        # guide §5 short form
```

TrustOps benchmark (S1–S7 + baseline + calibration):

```bash
go run ./cmd/to bench run --scenario all --out reports --log reports/action-log.txt
go run ./cmd/to bench calibrate --out reports
# -> reports/benchmark.json, reports/calibration.json (ROC sweep),
#    reports/params.json (detector parameters, FR2.5), reports/action-log.txt,
#    reports/evidence.json (recovery evidence)
```

Manual recovery drill (guide §9), after an attack:

```bash
go run ./cmd/council recover --evidence reports/evidence.json \
    --shards shard-1.json shard-2.json shard-3.json --out reports
# -> RECOVER/RECONSTRUCT/RE-ISSUE/COMMIT/VERIFY report; canonical.json
```

Daily operation (guide §7):

```bash
go run ./cmd/orchestrator status --events reports/canonical.json
go run ./cmd/orchestrator rollback --dry-run --events reports/evidence.json   # guide §9 invalidation set
go run ./cmd/orchestrator policy reload --policy policy.json --events reports/canonical.json
go run ./cmd/orchestrator timeline --tail 20 --events reports/canonical.json
go run ./cmd/orchestrator verify --root <hash> --events reports/canonical.json
go run ./cmd/orchestrator graph --identity user --events reports/canonical.json
go run ./cmd/auditor audit --log reports/canonical.json --policy policy.json
```

Consumers (guide §3): workload-cert issuer + policy reference

```bash
go run ./cmd/identity ca --key <recovered-root.key>                     # mint the identity CA
go run ./cmd/identity issue --ca ca.der --key ca.key --identity server  # issue a workload cert
go run ./cmd/identity verify --cert leaf.der --ca ca.der
go run ./cmd/pdp check --policy policy.json --events reports/canonical.json
```

Formal model check (requires Java 21+):

```bash
cd specs
java -jar ../tools/tla2tools.jar -workers 12 -config TrustOrchestrator.cfg TrustOrchestrator.tla
# -> "Model checking completed. No error has been found." (P1/P2/P3/P4/P6)
```

## Notes

- The core runs scenarios in-process with simulated 30s cycles; the network
  surface (gossip transport, config daemons, systemd units, the VPN/DNS/eBPF
  consumer daemons and SGX enclave) is the documented deployment layer — its
  transport is verified as a real mutual-TLS handshake over issued workload
  certs (`TestMutualTLSRequest`).
- Every published number is produced by `make benchmark` with the parameters
  pinned in `bench.go` (single set for all scenarios).
- P5 (minimal blast) is a graph-level property verified in Go
  (`InvalidationSet` + `VerifyRecovery`); the TLA model covers P1/P2/P3/P4/P6.
