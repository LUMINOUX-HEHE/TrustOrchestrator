# 07 — Testing

## How to reproduce everything

```
go test ./... -count=1            # 51 tests
go test -run 'TestK' ./... > reports/kill-tests.log
go test ./... -coverprofile=coverage.out   # then: go tool cover -func=coverage.out
make bench                    # regenerate reports/*.json
make model-check              # TLA P1–P6 (needs java)
make build                    # 9 binaries
```

## Inventory and evidence

| Artifact | What | Verified? |
|---|---|---|
| `reports/verification-results.md` | full verbose run | yes (§1–§10) |
| `reports/audit-round-2.md` | re-audit, 5 bad §9 rows fixed | yes |
| `reports/kill-tests.log` | K1–K6 | yes |
| `reports/benchmark.json` | 10 scenario rows | yes |
| `coverage.out` | 46.1% statements | yes |
| `reports/tlc.log`, `mutation-p2.log`, `mutation-p6.log` | model check | yes |

## Test inventory (51)

| Group | File | # | Covers |
|---|---|---|---|
| Core scenes | `core_test.go` | 22 | quorum, insider, partition, combined, slow attack, workload, escalation, W2, mirror, mTLS, identity, end-to-end |
| Timeline | `timeline_test.go` | 8 | append/verify/fork/fold/CUSUM/search/locate-bad |
| Identity | `identity_test.go` | 3 | issue/verify, expiry, reissue workload |
| Consumer | `consumer_test.go` | 2 | rollback delta, diff stateless |
| Kill | `kill_test.go` | 6 | K1 kill-one … K6 corrupt log |
| Wire | `transport_test.go` | 1 | real-socket mTLS frames |
| Fleet | `fleet_test.go` | 3 | live-verdict, frame-loss reconnect, concurrent fan-in |
| DNS | `cmd/dnsprobe/main_test.go` | 2 | real UDP loop, NXDOMAIN decode |
| CLI | `cmd/to/main_test.go` | 4 | enroll, enroll-node-id, bootstrap-revoked, probe-cmd exit mapping |

**All 51 PASS, exit 0** (`go test ./... -count=1`), 2026-08-03.

## Coverage notes

- total `46.1%` (core crypto/safety ~100%; fleet.go is new code in this round); CLI daemons 0% by design
  (no `_test.go` in `cmd/auditor|council|identity|orchestrator|pdp`; they are
  covered by smoke runs in `06-workflow.md`).
- `fleet.go` is real sockets (TLS 1.3 mTLS on loopback); the servers
  `cmd/orchestrator` + `cmd/to` are exercised by the section below.

## Proof trace: model invariant → code → test

Each TLA+ invariant in `specs/TrustOrchestrator.tla` (`Safety` = P1 ∧ P3 ∧ P4
∧ P2 ∧ P6) has a direct Go counterpart and a test that proves it. Model
checking found no counterexample (`reports/tlc.log`); the P2/P6 mutants are
rejected (`reports/mutation-p2.log`, `mutation-p6.log`).

| P | Invariant | Code | Test |
|---|---|---|---|
| P1 | at most one anchor per epoch / no fork | `timeline.go` `Fork`, `Verify` | `TestForkPreservesOriginal`, `TestForkRaceRejected` |
| P2 | quorum-gated liveness: recovery commits only with ≥3 votes | `council.go` `recover` + `ConsensusVotes` | `TestRecoveryEndToEnd`, `TestK3` |
| P3 | revoked certs never valid again | `rollback.go` `Fold`/revocation | `TestFoldNoResurrection`, `TestInvalidationSetScoped` |
| P4 | every commit needs `>= Quorum` distinct votes (n≥3f+1) | `ensemble.go` `Detect` | `TestEnsembleQuorum`, `TestDoubleVoteRejected` |
| P5 | minimal blast radius (graph-level) | `rollback.go` `InvalidationSet`, `graph.go` | `TestInvalidationSetScoped`, `TestVerifyScalesLinearly` |
| P6 | escalation is detect-only: auditor raises can force DETECTED, never commit | `audit.go` `DetectEscalated` | `TestAuditorLogAndEscalation`, `TestSlowPoisonNeedsAuditors` |

A mutant break in **any** row must be caught by the code test in the same row
— that is the trace's contract.

## Kill test intent (K1–K6)

The fault-injection set proves the system degrades **gracefully**:

| Kill | What survives | PASS |
|---|---|---|
| one watchdog | quorum still reachable | K1 |
| two watchdogs | detection still works (>50%) | K2 |
| one council member | still ≥3 votes | K3 |
| 3 council | recovery never by majority | K4 |
| auditor ignoring | cross-check catches | K5 |
| corrupt audit log | instrumented | K6 |