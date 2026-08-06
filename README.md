# Trust Orchestrator

A self-hosted PKI trust-management engine: it **detects its own compromise**,
**recovers via a majority-vote cryptographic council**, and **rolls back to a
verified checkpoint** — re-issuing only the damaged certificates, with every step proved by
tests, a formal model, and a benchmark.

This repository is the **engine**, not the airframe: threshold crypto, the
chain-of-custody timeline, the watchdog ensemble, quorum detection, rollback
math, and the CLIs that run them are real (Ed25519, SHA-256, Shamir secret
sharing, TLS 1.3 — stdlib only, zero third-party dependencies). The
"deployment layer" — a five-machine network, real VPN/DNS/eBPF filters,
hardware enclave — is documented in `docs/09-limitations.md`, not faked here.

## The problem in one line

Certificates spread through trust edges; when one is stolen, *revoking
everything* takes you offline and *revoking too little* leaves the front door
open. This system decides exactly what to roll back and re-issue, without a
single machine deciding anything alone.

- **Detect:** 5 independent watchdogs score every 30s cycle; DETECTED iff
  ≥3/5 fall below the calibrated threshold (P2: one compromised watchdog can
  neither trigger nor block).
- **Recover:** a 5-node council holding Shamir shards of a backup root key —
  ≥3 votes reconstruct the key, roll back to the last verified checkpoint,
  and re-issue only the damaged identities (minimal blast radius, P5).
- **Prove:** the timeline is an append-only signed hash chain; every rollback
  is a verified fork; recovery post-conditions are checked (P3: a revoked cert
  is never resurrected).

| P# | Invariant | Proof |
|---|---|---|
| P1 | A cert is never valid under two canonical anchors at once (fork safety) | TLA+ + `TestForkRaceRejected` |
| P2 | One compromised watchdog can neither trigger nor block detection | `Detect(≥3/5)` + `TestInsiderCan'tTrigger` |
| P3 | Rollback never resurrects a revoked certificate | `TestFoldNoResurrection` |
| P4 | Detection converges on a single canonical timeline | `TestEpochCommitValidity` |
| P5 | Corrupted followers never win / minimal blast radius | TLC `P5MinimalBlast` + `InvalidationSet` + `VerifyRecovery` |
| P6 | Only the council can execute recovery; auditors never can | council-only key |

## Repository layout

- `*.go` — core library: `timeline.go`/`graph.go` (trust chain), `watchdogs.go`
  /`detect.go`/`ensemble.go` (ensemble), `audit.go` (transparency), `council.go`
  /`shamir.go`/`councilnet.go` (threshold + networked recovery), `rollback.go`
  /`consumer.go` (time travel), `fleet.go`/`transport.go`/`mtls.go` (the mTLS
  wire), `identity.go` (real X.509 + CRL), `bench.go` (TrustOps)
- `cmd/to/` — one CLI, three personalities (to-tool / to-bench / to-watchdog by
  basename): genkey, shard, enroll, revoke, bench, watchdog run
- `cmd/orchestrator/`, `cmd/council/`, `cmd/auditor/` — daily-operation binaries
- `cmd/identity/`, `cmd/pdp/` — consumers: workload-cert issuer + policy check
- `cmd/dnsprobe/` — the W4 external-probe helper
- `cmd/gateway/` — the management plane: REST API, RBAC, multi-tenancy,
  webhooks, backup/restore, metrics, and the web dashboard (served at `/`)
- `sdk/python/to_client.py`, `sdk/java/ToClient.java` — thin stdlib-only REST
  clients; the Go SDK is the library itself + `Client` in the root package
- `specs/` — TLA+ model, TLC configs, P2/P6 mutation tests
- `docs/00-overview.md` … `docs/09-limitations.md` — self-contained reference
  (overview, architecture, requirements trace, component map, threat model,
  cryptography, workflow, testing, deployment, honest limitations)
- `deploy/` — systemd units, `fleet-smoke.sh` live-fleet proof, `kubernetes.yaml`
- `tools/` — tla2tools.jar pinned for the model check
- `reports/` — regenerable evidence: benchmark, calibration, params, TLC log,
  kill-test log, canonical/evidence dumps
- `trust-orchestrator-final-report.md` — the full acceptance report

## Requirements

- **Go 1.22+** (no third-party deps; Windows/Linux/macOS)
- **Java 21+** — only for `make model-check` / `make model-check-mutations`
- **bash** — only for `make fleet-smoke`

## Quick start

```bash
make test                  # 51 unit + scenario tests, all green
make benchmark             # TrustOps S1–S7 + baseline + calibration
make model-check           # TLC on specs/ (requires Java 21+), writes reports/tlc.log
make model-check-mutations # P2/P6 mutation tests — TLC must report a violation
make kill-tests            # K1–K6 fault injection (chaos) suite → reports/kill-tests.log
make fleet-smoke           # live fleet: 4 processes, real mTLS, healthy + DETECTED verdicts
make build                 # 10 binaries; make build-linux → static linux/amd64 ELFs
make docker-build          # container image (Dockerfile) for deploy/kubernetes.yaml
```

Bootstrap + enrollment ceremony (one-time, offline / per node):

```bash
go run ./cmd/to genkey bootstrap.key
go run ./cmd/to shard --key bootstrap.key --shares 5 --threshold 3   # 5 shard files
go run ./cmd/to enroll --bootstrap bootstrap.key --config config.yaml
go run ./cmd/to enroll --bootstrap bootstrap.key --node-id W1        # short form
go run ./cmd/to revoke --bootstrap bootstrap.key                    # FR8.2: spent after genesis
```

TrustOps adversary (S1–S7 + baseline + calibration):

```sh
go run ./cmd/to bench run --scenario all --out reports --log reports/action-log.txt
go run ./cmd/to bench calibrate --out reports
# -> reports/benchmark.json, reports/calibration.json, reports/params.json,
#    reports/action-log.txt, reports/evidence.json
```

| Scenario | Attack | Correct behaviour |
|---|---|---|
| S1 burst | cert flood from compromised issuer | DETECTED, correct rollback, no false positive |
| S2 slow poison | gradual cheating over HOURS, below every rate bound | DETECTED-only if auditors escalate; measured gap |
| S3 insider | legitimate (non-alarmed) cert, one watchdog only | NOT detected — correct |
| S4 partition | network partition | detect, no false alarm |
| S5 fork race | malicious competing fork | unique canonical; fork rejected |
| S6 combined | burst + partition simultaneously | DETECTED, rollback correct |
| S7 omniscient | attacker knowing the thresholds | measured detection gap, not an alarm |

Manual recovery drill (after an attack):

```sh
go run ./cmd/council recover --evidence reports/evidence.json \
    --shards shard-1.json shard-2.json shard-3.json --out reports
# -> RECOVER/RECONSTRUCT/RE-ISSUE/COMMIT/VERIFY report; canonical.json
```

Daily operation:

```sh
go run ./cmd/orchestrator status --events reports/canonical.json
go run ./cmd/orchestrator rollback --dry-run --events reports/evidence.json
go run ./cmd/orchestrator policy reload --policy policy.json --events reports/canonical.json
go run ./cmd/orchestrator timeline --tail 20 --events reports/canonical.json
go run ./cmd/orchestrator verify --root <hash> --events reports/canonical.json
go run ./cmd/orchestrator graph --identity user --events reports/canonical.json
go run ./cmd/auditor audit --log reports/canonical.json --policy policy.json
```

Consumers: workload-cert issuer + policy reference

```sh
go run ./cmd/identity ca --key <recovered-root.key>                     # identity CA
go run ./cmd/identity issue --ca ca.der --key ca.key --identity server  # mint a workload cert
go run ./cmd/identity verify --cert leaf.der --ca ca.der
go run ./cmd/pdp check --policy policy.json --events reports/canonical.json
```

Watchdog replay (`--live` streams over real mTLS to an orchestrator; start with
`make fleet-smoke` for a 4-process demo):

```sh
go run ./cmd/to watchdog run --events reports/evidence.json \
    --kind behavior_baseline --params reports/params.json --tail 10
go run ./cmd/to watchdog run --events reports/evidence.json \
    --probe-cmd "go run ./cmd/dnsprobe --server 8.8.8.8:53 --name example.com"
```

Formal model check (requires Java 21+):

```sh
cd specs && java -jar ../tools/tla2tools.jar -workers 12 \
    -config TrustOrchestrator.cfg TrustOrchestrator.tla
# -> "Model checking completed. No error has been found." (P1/P2/P3/P4/P6)
```

## How claims are backed

- Every published number comes from `make benchmark` with parameters pinned in
  `bench.go` (one set for all scenarios); `reports/` contains the generated
  evidence and `reports/audit-round-2.md` the audit that produced them.
- Formal properties P1–P6 are layered: TLA+ model check (P1/P2/P3/P4/P6 and
  P5's identity-scope via `P5MinimalBlast`), Go invariant tests, and a
  cross-checking council.
- P5's graph reachability (the per-window blast radius) is asserted in Go
  (`InvalidationSet` + `VerifyRecovery`); the TLA model covers the scope
  discipline and P1/P2/P3/P4/P6.
- The network surface is exercised live, not just code-reviewed: `make
  fleet-smoke` runs four real processes over mTLS and asserts both a healthy
  and a DETECTED verdict (`fleet.go` + `TestMutualTLSRequest`).
- CI (`.github/workflows/ci.yml`) re-runs vet, all tests, the kill suite, a
  fuzz smoke pass on the three fuzz targets, the full benchmark with the
  calibration-drift check, and a reduced-scale TLC run on every push.

## Management plane (gateway)

One binary, REST + RBAC + multi-tenant orgs + webhooks + backup/restore:

```sh
go run ./cmd/gateway -addr :8080 -data ./data   # first boot prints the admin token
TOKEN=<printed-token>                            # Authorization: Bearer <token>

curl -H "Authorization: Bearer $TOKEN" -X POST localhost:8080/v1/orgs \
     -d '{"name":"acme"}'                        # tenant -> {"id":"acme",...}
curl -H "Authorization: Bearer $TOKEN" -X POST localhost:8080/v1/users \
     -d '{"id":"ops","role":"operator","orgs":["acme"]}'   # -> token (shown once)
curl -H "Authorization: Bearer $TOKEN" -X POST localhost:8080/v1/orgs/acme/issue \
     -d '{"cert_id":"c1","identity":"user","via":"c0"}'
curl -H "Authorization: Bearer $TOKEN" localhost:8080/v1/orgs/acme/state
curl -H "Authorization: Bearer $TOKEN" localhost:8080/v1/audit?identity=user
curl -H "Authorization: Bearer $TOKEN" -X POST localhost:8080/v1/backup   # snapshot
curl -H "Authorization: Bearer $TOKEN" -X POST localhost:8080/v1/restore --data-binary @bundle.json
curl -H "Authorization: Bearer $TOKEN" localhost:8080/v1/metrics           # prometheus text
```

Detection + recovery over the API: post watchdog scores to
`/v1/orgs/{org}/scores` (≥3/5 below threshold → DETECTED event + webhooks),
then `/v1/orgs/{org}/recover` with 3 of the 5 ceremony shards
(`GET /v1/orgs/{org}/keys` → `to shard`). Roles: admin / operator / auditor /
viewer; orgs field on a user scopes them to specific tenants. Full route
table in `api.go`; end-to-end checks in `api_test.go`.

Dashboard: open `http://localhost:8080/`, paste the token, manage orgs,
issue/revoke/recover, audit search, webhooks, users, metrics, backup/restore —
all in one static page, no build tooling.

SDKs (thin REST clients over the same API):

```go
c := to.NewClient("http://localhost:8080", token)
c.CreateOrg("acme", "")
c.Issue("acme", "c1", "user", "c0")
st, _ := c.State("acme")          // map[string]to.Cert
```

```python
from to_client import TOClient
c = TOClient("http://localhost:8080", token)
c.create_org("acme"); c.issue("acme", "c1", "user"); print(c.state("acme"))
```

```java
// java ToClient.java http://localhost:8080 <token>   (or use as a class)
ToClient c = new ToClient("http://localhost:8080", token);
c.createOrg("acme", ""); c.issue("acme", "c1", "user", ""); System.out.println(c.state("acme"));
```

## Full report

For the deep-dive — problem motivation, related work, formal specification,
protocol details, and evaluation — read `trust-orchestrator-final-report.md`,
then follow the index in `docs/README.md`.