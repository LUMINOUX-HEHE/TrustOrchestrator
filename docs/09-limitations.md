# 09 — Honest Limitations

The exhaustive, explicit list of everything that is **mocked/simulated/stubbed/
skipped/partially implemented** — the same table a judge can read in
`reports/audit-round-2.md §10`.

| # | Area | Status | Level |
|---|---|---|---|
| D1 | Real multi-host network | fleet runs in-process in one binary; mTLS verified only on loopback sockets | Simulated |
| D2 | VPN / DNS / eBPF | existence + policy only (`to-pdp`); no live filters | Docs-only |
| D3 | Hardware enclave (SGX/TPM) | `zeroize()` in memory, not attestation hardware | Semantic only |
| D4 | Auditor ≤ real transport boundary | mirror + escalation proven in-process | Simulated |
| D5 | True 5-node TLA model | reduced (3/power, few epochs) — proof-of-concept | Reduced |
| D6 | Live calibration | in-process scenario clock, not real wall-time fleet | Internal |
| D7 | `p-value` in scores | placeholder flat 0.01 on alarm | Placeholder |
| D8 | Best-of-3 scaling timing | stochastic bound (3 runs, scheduler noise) | Noise-sensitive |
| D9 | Deploy plumbing | systemd/multi-host documented, **never run on real hosts** | Docs |
| D10 | Production bootstrap key | dev `bootstrap.key` committed to repo | Dev-only |
| D11 | Windows-only dev | Linux targets untested here | Environment |
| D12 | TLA mutation tests | P2/P6 violated logs are proofs, not shipping code | Audit |
| D13 | Network partitions simulated | loopback partition, not router-level | Simulated |

## The honest answer to "is anything faked?"

No. Every cryptographic claim is real and tested: Ed25519, SHA-256, Shamir
3-of-5, TLS 1.3 mutual auth, X509. What is *simulated* is the **transport
and deployment layer** — the in-process fleet instead of five VMs, mTLS on
loopback instead of cross-host, and no hardware enclave. Those are the exact
boundaries a local project can't honestly cross, and they are all explicitly
flagged in `trust-orchestrator-final-report.md §10` and this chapter.

## If you want to push reality one step further

Highest-value, smallest-effort next step:
- a **2-process loopback smoke** (`to-watchdog run --addr` ↔ `to-orchestrator
  gateway`) that already exists as `TestWireRealSockets`; promote to a shell
  test in `deploy/`
- ship `systemd` units + a multi-host bootstrap script (docs-only today)