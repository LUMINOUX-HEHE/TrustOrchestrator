# 01 — Architecture

## Five pillars

| Pillar | File(s) | Key ideas |
|---|---|---|
| Trust timeline | `timeline.go`, `graph.go` | Append-only Merkle chain; every rollback is a **fork** at a verified checkpoint |
| Watchdog ensemble | `watchdogs.go`, `detect.go`, `ensemble.go` | 5 independent detectors → scores → DETECTED iff ≥3/5 below threshold |
| Trust transparency | `audit.go` | Auditor mirror of every event; auditors escalate, never recover |
| Recovery council | `council.go`, `frost.go` | 3-of-5 FROST threshold signatures on the epoch handoff; ≥3 members sign, the root key never exists |
| Time-travel rollback | `rollback.go`, `consumer.go` | Re-fold verified prefix; invalidate reachable set; push delta |

## Data flow (normal cycle)

```
TrustEvent(e) ──▶ Timeline.Append (signed, hashed, parent-linked)
                      │
   each watchdog ──▶ Watchdog.ObserveBatch(cycle events)
                      │
                 Watchdog.Score() ──▶ Score{node, score, p, evidence}
                      │
                 Detect(scores, threshold, quorum=3) ──▶ DETECTED?
                      │
                      ├── yes ──▶ Council recovery ≥3 votes
                      │                └▶ rollback to checkpoint #k
                      │                     └▶ invalidate reachable set
                      │                          └▶ re-issue damaged certs
                      └── no  ──▶ continue
```

## Watchdog kinds (FR2.1, calibrated params in `reports/params.json`)

| ID | Kind | Signal | Params μ0/δ/h |
|---|---|---|---|
| W1 | `rate_cusum` | burst of issuer events per 30s cycle | 1 / 1 / 8 |
| W2 | `log_integrity` | hash-chain gap (erased history) | — (structural) |
| W3 | `graph_anomaly` | relationship edges appearing en masse | 0.5 / 0.5 / 3 |
| W4 | `external_probe` | attacker reconnaissance / probe pattern | — (pattern) |
| W5 | `behavior_baseline` | per-identity deviation from learned mu0 | 1 / 1 / 2/δ 0.5/h2 |

W1 (burst) and W2 (tamper) are the two pickers of choice: W2 alone or W5
alone rarely fire; the ensemble needs 3/5 to act.

## Score fusion

```
DETECTED(A) = #{ nodes : Score < threshold } ≥ quorum
```

- quorum = 3 with n = 5: one Byzantine watchdog can neither toggle nor block.
- Auditors can raise a low score via `Escalation` (FR3.3) but can never execute
  a recovery (P6).

## Recovery flow

1. Council threshold-signs the epoch handoff (≥3 of 5 FROST shares; the
   root key never exists anywhere — `frost.go`, no reconstruction step)
2. Fork at last verified good checkpoint (highest-valid epoch wins, FR4.4)
3. Invalidation set = reachable subgraph from first bad event (BFS over
   `graph.go` edges) — minimal blast radius L4
4. Re-issue only damaged identities; signed into the new fork (`reports/
   canonical` artifacts)

The recovery state machine (council.go) is shared by the in-process path and
the networked protocol (councilnet.go): `to-council serve` members hold the
FROST shares and answer VOTE / COMMIT_REQ over mTLS — the initiator never sees
member secrets, members re-verify P3/P5 before signing the epoch descriptor,
and ≥3 valid partial signatures form the COMMIT.

## Transport

`transport.go` — length-prefixed JSON frames over mTLS (TLS 1.3, mutual cert
verify against identity CA). Verified over real TCP sockets
(`TestWireRealSockets`) and loopback mTLS (`TestMutualTLSRequest`). This is the
wire for the to-watchdog → orchestrator (gateway) connection.

## The TLA+ model

`specs/TrustOrchestrator.tla` is a reduced-fleet model (3 watchdogs/auditors,
small epochs) proving P1–P4/P6. It is **proof-of-concept**, not a 5-node
exhaustive state space — the reduced sizes keep TLC tractable on a laptop while
still exercising the invariant machinery. See `06-testing.md` (model check).