# 00 — Overview

## The problem

You operate services that issue digital certificates — electronic identities for
servers, VPN clients, API workloads. Attackers steal valid certificates. When a
compromise is discovered:

- _Which_ certificates were actually touched? The attacker didn't just reach
  one cert — the compromise spreads along trust edges (one cert signs another).
- _Revoking everything_ is safe but takes the whole organization offline.
- _Revoking too little_ leaves the attacker's front door open.

This system is the decision + recovery _engine_ for exactly that problem.

## The solution in one picture

```
  TrustOps (calibration)          Auditors (mirror + escalate)
        |                                 |
        v                                 v
  5 watchdogs ──score/p/evidence──▶ Orchestrator
   (W1..W5)                          │           │
                                     │   DETECTED │  ≥3/5 quorum
                                     v           v
                               Council (FROST)    Rollback + re-issue
                               3-of-5 signature   (minimal blast radius)
```

## What it guarantees (the proof obligations)

Design invariants, each one a test:

| P# | Invariant | Proof |
|---|---|---|
| P1 | A certificate is never valid under two canonical anchors at once (fork safety) | TLA + `TestForkRaceRejected` |
| P2 | One compromised watchdog can neither trigger nor block detection | `Detect(≥3/5)` + `TestInsiderCan'tTrigger` |
| P3 | Rollback never resurrects a revoked certificate | `TestFoldNoResurrection` |
| P4 | Detection converges to a single canonical timeline | `TestEpochCommitValidity` |
| P5 | Corrupted followers never win | mutation of P6, TLC violation proven |
| P6 | Recovery requires the council; auditors can never execute it | `TestAuditor...`, council-only key |

## Scope (what this repo actually *is*)

It is the **engine**, not the airframe:

- real: threshold crypto, chain of custody, detectors, quorum, rollback math
- deployment layer (documented, deliberately not implemented): real VPN/DNS/
  eBPF filters, five-machine network, hardware enclave

See `09-limitations.md` for the complete, explicit list.