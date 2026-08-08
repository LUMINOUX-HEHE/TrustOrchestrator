# 04 — Threat Model & Scenarios

## Attacker model

We defend against a reasoned adversary that has:
- Compromised **at most one watchdog** (`P2`) and **at most one council member**
  (n ≥ 3f+1 ⟹ Byzantine tolerance with n=5, f=1).
- Ability to send traffic, forge SOME events, and attempt to drive the system
  toward a non-canonical fork.
- **A compromised gateway** (or its operator) that tries to rewrite or
  reorder history *after* it has been witnessed: the signed timeline alone
  can be re-signed by a key holder, but the RFC 9162 transparency log
  (docs/05 §Transparency, `ctlog.go`) fixes the order — a rewritten leaf
  fails its inclusion proof against the signed tree head, and a changed
  root at the same size is a split-brain that gossip alarms on.

We do **not** currently defend against compromise of a majority of watchdogs,
a hardware enclave attacker, or a physical attacker (those are the untouched
deployment gaps, `09-limitations.md`).

## The benchmark scenarios `reports/benchmark.json`

Produced by `bench.go` scenario runner (S1–S7), regenerable with
`make benchmark`. `detected` is whatever the ensemble decides; `fp` (false
positive) must be `false` in the steady state; `rollback_correct` true.

| S# | Name | Setup | Why | Result |
|---|---|---|---|---|
| S1 | burst | 1 rogue cert/cycle for 10 cycles (≥3/5 fire) | The classic compromise | detected=1, no fp |
| S2 | slow doom | gradual cheating over LONG window | don't panic falsely, detect in the end | detected at 1800s |
| S3 | insider | 1 treated but NOT alarmed | a legit employee abusing policy: no quorum | **NOT detected — correct** |
| S4 | partition | network partition | no false alarms on outage | detected, no fp |
| S5 | fork race | malicious competing fork | canonical must be unique | not detected (fork only) |
| S6 | combined | burst + partition simultaneously | stress | detected, correct rollback |
| S7 | omniscient gap | measured detection-gap vs omniscient | report the gap, don't alarm | not detected (measurement) |
| baseline | normal load, no attack | control | **zero false positives** | fp=false |
| load | workload re-issue to 180 | runtime target | 180 in < 60s measured | rollback_correct=true |
| scaling | 100k events verify | linearity | holds | ratio≈10.4 |

## Per-watchdog attacker (FR2.4)

- An insider can only send **low scores on one ID**.
- `Detect` requires `≥3/5`; a single suppressed ID = not detected (S3/insider)
  — checked in `TestInsiderCan'tTrigger`.

## What must NEVER happen

| Outcome | Guard | Test |
|---|---|---|
| FP in steady state | `baseline` zero-FP | `TestBaselineNoFalsePositive` |
| rollback resurrects revoked | P3 law | `TestFoldNoResurrection` |
| two canonical anchors | P5 (fork safety) | `TestForkRaceRejected`, TLA |
| auditors trigger recovery | P6 (council-only) | `TestAuditor…` |
| API / wire flood | token bucket per identity (REST) and per peer (mTLS wire) | `TestLimiter*`, `TestAPIRateLimit429` |
| history rewritten after the fact | RFC 9162 log: signed STH + proofs; same-size root change = split-brain alarm | `TestMerkleLogRejectsTamperedProofs`, `TestGossipSplitBrain`, `TestGossipRewrite`, `TestCTEndpoints` |

## Post-recovery verification (FR6)

Every forcible consumer is checked that its state matches the canonical fork:
`TestEndToEndPostRecovery` runs the CA + consumers + re-verified under a new
epoch, and the smoke test (`bin/to-orchestrator verify --root`) re-visits the
whole chain.