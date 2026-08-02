# 07 — Testing

## How to reproduce everything

```
go test ./... -count=1            # 45 tests
go test -run 'TestK' ./... > reports/kill-tests.log
go test ./... -coverprofile=coverage.out   # then: go tool cover -func=coverage.out
make bench                    # regenerate reports/*.json
make model-check              # TLA P1–P6 (needs java)
make build                    # 8 binaries
```

## Inventory and evidence

| Artifact | What | Verified? |
|---|---|---|
| `reports/verification-results.md` | full verbose run | yes (§1–§10) |
| `reports/audit-round-2.md` | re-audit, 5 bad §9 rows fixed | yes |
| `reports/kill-tests.log` | K1–K6 | yes |
| `reports/benchmark.json` | 10 scenario rows | yes |
| `coverage.out` | 46.8% statements | yes |
| `reports/tlc.log`, `mutation-p2.log`, `mutation-p6.log` | model check | yes |

## Test inventory (45)

| Group | File | # | Covers |
|---|---|---|---|
| Core scenes | `core_test.go` | 22 | quorum, insider, partition, combined, slow doom, workload, escalation, W2, mirror, mTLS, identity, end-to-end |
| Timeline | `timeline_test.go` | 8 | append/verify/fork/fold/CUSUM/ensemble/locate-bad |
| Identity | `identity_test.go` | 3 | issue/verify, expiry, workloads |
| Consumer | `consumer_test.go` | 2 | rollback delta, diff semantics |
| Kill | `kill_test.go` | 6 | K1 kill-one … K6 corrupt log |
| Wire | `transport_test.go` | 1 | real-socket mTLS frames |
| CLI | `cmd/to/main_test.go` | 3 | enroll, enroll-node-id, bootstrap-revoked |

**All 45 PASS, exit 0** (`go test ./... -count=1`), 2026-08-02.

## Coverage notes

- total `46.8%`; core crypto/safety ~100%; CLI daemons 0% by design
  (no `_test.go` in `cmd/auditor|council|identity|orchestrator|pdp`; they are
  covered by smoke runs in `06-workflow.md`).

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