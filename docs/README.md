# Trust Orchestrator — Project Documentation

Self-contained documentation set. Everything referenced here exists in the repo
and was verified live on 2026-08-02 (**45/45 tests pass, exit 0**).

## How to read these docs

| Document | What it answers |
|---|---|
| [00-overview.md](00-overview.md) | What is this? What problem does it solve? |
| [01-architecture.md](01-architecture.md) | System design, the 5 pillars, data flow |
| [02-requirements.md](02-requirements.md) | FR / NFR, and where each is implemented + tested |
| [03-component-map.md](03-component-map.md) | Every source file: role, key funcs, coverage |
| [04-threat-model.md](04-threat-model.md) | Attack scenarios (S1–S7) and why they must / must-not trigger |
| [05-cryptography.md](05-cryptography.md) | What is real crypto vs simulated |
| [06-workflow.md](06-workflow.md) | End-to-end: bootstrap → issue → detect → rollback → reissue |
| [07-testing.md](07-testing.md) | Test inventory, reproduction commands, evidence files |
| [08-deployment.md](08-deployment.md) | Binaries, commands, config, deployment layer status |
| [09-limitations.md](09-limitations.md) | Honest list of what is and is not yet real |

## Fifty-second summary

A judge-friendly one-paragraph version:

> The Trust Orchestrator is a safety system for a network of digital
> certificates. Five independent detectors watch the certificate flow;
> recovery of a compromised network requires agreement by at least 3 of 5
> sensors and a 3-of-5 council vote; the network is then rolled back to a
> known-good point and only damaged certificates are re-issued. The math is
> real (Ed25519, SHA-256, Shamir secret-sharing, TLS 1.3), and every claim is
> backed by an automated test. The remaining gaps are the "deployment layer" —
> running the same logic across real machines, real VPN/DNS filters, and a
> hardware enclave — which needs hardware that a laptop cannot fake.

## Canonical sources (outside this folder)

- `trust-orchestrator-final-report.md` — the formal acceptance report
- `README.md` (root) — quick start, layout, ceremony commands
- `reports/audit-round-2.md` — the live audit that produced these numbers
- `reports/benchmark.json` — 10 scenario rows, regenerable via `make bench`
- `reports/kill-tests.log` — the fault-injection run