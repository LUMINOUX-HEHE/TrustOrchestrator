# Sovereign Internet — Trust Orchestrator
## Final Project Report

**Project:** Autonomous Compromise Detection, Council-Mediated Recovery, and Verified
Time-Travel Rollback for Self-Hosted Public Key Infrastructure

---

## Abstract

The Trust Orchestrator is a self-hosted zero-trust networking stack whose core is a
distributed trust management system: a PKI that detects its own compromise, recovers
autonomously, and can prove that both were done correctly. Detection is performed by an
ensemble of five independent statistical watchdogs whose outputs are fused by quorum
voting; recovery is executed by a five-node council holding Shamir shards of a backup
root key; correctness is established through an event-sourced trust timeline, TLA+
specification, and an adversarial benchmark called TrustOps that turns every system
claim into a measured, reproducible result. A Trust Transparency Layer extends
Certificate Transparency's public-audit idea from certificates to the entire
governance surface — policy changes, key events, and recovery actions — so that
independent third-party operators can detect compromise that internal monitors miss.
This report explains the system in full: requirements, architecture, component design,
protocols, formal properties, threat model, and evaluation methodology.

---

## 1. Introduction

### 1.1 Problem Statement

Public key infrastructure is the trust backbone of everything networked, yet its
weakest property is well documented: **when a CA is compromised, detection is slow,
recovery is manual, and correctness of the recovered state is asserted rather than
proved.**

The historical record is consistent:

- **DigiNotar (2011):** the CA was compromised in June; the compromise was detected in
  July — by Google's Chrome browser team, *not* by the CA's own monitoring. Recovery
  was months of manual, global re-issuance, and the CA was killed.
- **Comodo (2011), TÜRKTRUST (2013), Entrust (2024):** rogue or fraudulently obtained
  certificates issued without immediate detection by the issuing authority.
- **Let's Encrypt (2020):** a mis-issued certificate took days to discover and revoke,
  even with Certificate Transparency as a backstop.

Three systemic failures repeat across all cases:

1. **Detection is reactive and external.** Internal monitoring either does not exist or
   is not trusted to find sophisticated compromise.
2. **Recovery is manual and slow.** Human mediation, key ceremony, global re-issuance —
   measured in days to months.
3. **Correctness is asserted, not verified.** No CA product proves that its post-recovery
   state is consistent with its pre-compromise guarantees.

### 1.2 Thesis

A trust management system can be built in which these three failures are structural
rather than incidental:

- **Detection** is continuous, internal (watchdogs) *and* external (independent
  auditors), with measured detection-latency bounds.
- **Recovery** is autonomous: a cryptographic council, physically distributed, re-issues
  the trust state without human mediation, with a measured recovery-time objective.
- **Correctness** is layered: formal properties (TLA+ model-checked), benchmark tests
  (TrustOps), and invariant checks on the live system.

### 1.3 Goals and Non-Goals

**Goals**
- Autonomous compromise detection via distributed watchdog consensus (no single node
  decides).
- Autonomous recovery via majority-vote council (no single machine executes recovery).
- Time-travel recovery: rollback of trust state to a verified checkpoint via event
  replay.
- External auditability of the entire trust-governance surface.
- All claims quantified: thresholds calibrated by benchmark, not opinion.
- No machine learning; no new cryptography.

**Non-Goals**
- Replacing the global DNS root or BGP.
- Replacing Certificate Transparency (CT remains complementary; this system publishes
  to CT logs).
- Inventing cryptographic primitives (all are standard: Curve25519, AES-256, SHA-256,
  Shamir secret sharing, Merkle trees).

### 1.4 Contribution Summary

1. **A detection ensemble with calibrated statistical detectors** (CUSUM change-point
   analysis, hash-chain verification, graph-anomaly deviation, external-probe
   cross-check, per-identity baseline) fused by quorum voting.
2. **The Trust Transparency Layer:** a public, append-only log of trust-governance
   events audited by independent operators with escalation rights — CT extended from
   certificates to the governance surface.
3. **Autonomous recovery with epoch-based fork resolution,** eliminating the
   entry-count tiebreak attack present in earlier designs.
4. **Event-sourced time-travel rollback** with algebraic correctness laws and formal
   minimal-blast-radius guarantees.
5. **TrustOps:** a public adversarial benchmark for CA-compromise research, including
   an omniscient-attacker scenario that measures the system's fundamental residual
   risk.

---

## 2. Background and Related Work

### 2.1 Certificate Transparency (CT)

Google's CT (2013) provides an immutable, Merkle-verified append-only log of issued
certificates, allowing anyone to detect mis-issuance after the fact. CT solves
**accountability for issuance**; it does not detect ongoing compromise, does not act on
it, and covers only certificates — not policy changes, key events, or recovery actions.

### 2.2 Key Transparency and CONIKS

Key Transparency (Google) and CONIKS (MIT) apply CT-style logging to *user key
directories*: public, verifiable, consistent key attestation. They address lookup
integrity, not CA compromise, and have no recovery machinery.

### 2.3 Threshold CA Schemes

Academic schemes since the late 1990s distribute signing across n parties with
threshold t, so no single key exists in one place. They provide distributed *issuance*
but no detection, no recovery orchestration, and no post-recovery verification.

### 2.4 Commercial and Open-Source CAs

| System | Issuance | Detection | Autonomous recovery | Verified rollback |
|---|---|---|---|---|
| Let's Encrypt + ACME | Automated | None (CT backstop) | No | No |
| HashiCorp Vault PKI | Automated | None | Manual rotation only | No |
| EJBCA | Manual/automated | Audit logs, human review | No | No |
| SPIRE/SPIFFE | Automated | None | Re-issue on restart | No |
| **This project** | **Automated** | **5-watchdog + auditor ensemble** | **Council-mediated** | **Event-sourced, formalized** |

### 2.5 Detection Systems (SIEM/UEBA)

Existing detection tools monitor network and endpoint behavior. None hold authority
over the trust state they monitor; none can autonomously re-issue certificates as a
response. The Trust Orchestrator's novelty is that detection is *coupled* to recovery
in one loop.

### 2.6 Gap Summary

No existing system integrates: (a) continuous compromise detection over the trust
state, (b) autonomous recovery by distributed council, (c) externally auditable
governance, and (d) formally specified, benchmark-verified rollback. The individual
primitives all exist; the orchestration does not.

---

## 3. Requirements and Design Goals

### 3.1 Functional Requirements

- **F1:** Continuous detection of trust-state compromise (rogue issuance, log gaps,
  anomalous identity behavior, policy violations).
- **F2:** Autonomous recovery with no single point of failure in detection or
  execution.
- **F3:** Rollback of trust state to a verified pre-compromise checkpoint.
- **F4:** Scoped re-issuance — only identities affected by the compromise are re-issued.
- **F5:** Public auditability of all trust-governance events.
- **F6:** Post-recovery verification of all system layers, cross-checked by
  independent parties.

### 3.2 Non-Functional Requirements

- **N1 (Safety):** never two valid trust anchors simultaneously (fork safety);
  never resurrect a revoked certificate.
- **N2 (Liveness):** recovery terminates when ≥3 of 5 council members are connected
  and honest; blocks otherwise.
- **N3 (Quantifiability):** every detection threshold and every correctness claim is
  produced by the benchmark, not by hand.
- **N4 (Explainability):** no black-box models; every detector is a statistical test
  with an evidence payload.
- **N5 (Explainability of process):** all decisions — detections, votes, forks — are
  signed, logged, and replayable.

---

## 4. System Architecture

### 4.1 Overview

```
                    ┌───────────────────────────────────────────────┐
                    │              Trust Orchestrator                │
                    │                                               │
                    │  ┌───────────────┐  ┌──────────────────────┐  │
                    │  │ Trust Timeline │  │  Recovery Council    │  │
                    │  │ (Merkle hash   │  │  (5 nodes, ≥3 vote, │  │
                    │  │  chain,        │  │   Shamir shards)     │  │
                    │  │  forkable)     │  └──────────────────────┘  │
                    │  └───────────────┘                             │
                    │  ┌───────────────┐  ┌──────────────────────┐  │
                    │  │ Watchdog      │  │  Security Graph       │  │
                    │  │ Ensemble      │  │  (identity relations) │  │
                    │  │ (5 nodes,     │  └──────────────────────┘  │
                    │  │  quorum 3)    │  ┌──────────────────────┐  │
                    │  └───────────────┘  │  Verifier            │  │
                    │                     │  (invariant checks)  │  │
                    │  └──────────────────────────────────────────┘ │
                    │              TrustOps Benchmark               │
                    │          (attack scenarios + metrics)         │
                    └──────────────────────┬────────────────────────┘
                           ┌───────────────┴───────────────┐
                           ▼                               ▼
              Trust Transparency Layer          Consumers
              (5 independent auditors,      (Identity, Noise VPN, DNS,
               public Merkle logs,           Policy Engine, eBPF)
               escalation rights)
```

### 4.2 Trust Domains and Trust Assumptions

| Domain | Nodes | Assumption |
|---|---|---|
| Watchdogs | 5, separate hardware/software | ≥4 behave honestly (tolerates 1 Byzantine) |
| Council | 5, physically distributed | ≥3 behave honestly for recovery |
| Auditors | 5, different operators | Auditors are independent; escalation only, no execution (≥3 of 5 needed to escalate) |
| Bootstrap | 1 offline key, 5 shards | Physical ceremony security |

### 4.3 Key Distribution Flows

1. Genesis: offline Ed25519 bootstrap key → 5 Shamir shards → council members.
2. Enrollment: each node presents a bootstrap-signed self-signed cert.
3. Operations: council issues intermediate CA; identity server issues workload certs.
4. Recovery: ≥3 shards → enclave → new intermediate (memory only) → zeroized.

---

## 5. Detailed Component Design

### 5.1 Trust Timeline

The timeline is the system's single source of truth: an immutable, forkable, Merkle
hash chain of every trust event.

**Event schema:**

```
TrustEvent {
  type:        "KEY_GEN" | "ISSUE" | "REVOKE" | "POLICY_CHANGE" |
               "RECOVERY" | "COMMIT" | "SHARD_ACTIVITY" | "DETECTED" | ...
  timestamp:   int64 (RFC 3339, monotonic)
  payload_hash: sha256(payload)
  parent_hash:  sha256(previous event)
  signature:   ed25519(header + payload, council key)
}
```

**Verification:** anyone holding the root hash can verify chain integrity by re-hashing
each entry and checking the signature chain. Gaps or re-signs are detected by W2
(§5.2) and by auditors (§5.3).

**Forking (during recovery):**
1. Scan timeline from genesis for the first bad event (via graph anomaly or log gap).
2. Fork at the last verified good entry.
3. Replay trusted prefix events onto the fork.
4. Append recovery events (re-issuance, new COMMIT) to the fork.
5. The fork with the highest valid signed epoch becomes canonical (§6.2); the original
   chain is preserved as evidence.

**Algebraic property:** trust state is a pure function of the timeline:
`state_at(t) = fold(events[0..t])`. Rollback is a re-fold, nothing else.

### 5.2 Watchdog Ensemble (Detection)

Five independent detectors, each on separate hardware with a different detection
method. Each emits a score and an evidence payload every 30 seconds.

| Watchdog | Method | Detects | Blind spot covered |
|---|---|---|---|
| W1 Issuance Rate | CUSUM change-point on issuance rate | Burst attacks | Obvious, fast compromise |
| W2 Log Integrity | Hash-chain gap detection | Attacker covering tracks | Tampering with history |
| W3 Graph Anomaly | Edge-probability deviation on security graph | Lateral movement | Unusual trust relationships |
| W4 External Probe | Cross-check against auditor log | Internal blindness | Compromise invisible inside |
| W5 Behavior Baseline | Per-identity CUSUM on activity | Credential theft | Anomalous identity use |

**CUSUM detector (W1/W5), formally:**

Given a sequence of observations x₁…xₙ with expected mean μ₀ under normal operation,
CUSUM accumulates:

```
S₀ = 0
Sₖ = max(0, Sₖ₋₁ + (xₖ − μ₀) − δ)     # δ = minimal detectable shift
alarm when Sₖ ≥ h                         # h = calibrated decision bound
```

Both h and δ are calibrated on the TrustOps benchmark (§8) — a change-point alarm with
an evidence window attached, not a hand-picked score.

**Fusion:** each watchdog emits `(score, p-value, evidence)`. The ensemble emits
DETECTED iff ≥3 of 5 scores fall below the calibrated threshold. With 5 nodes and
threshold 3, the ensemble tolerates f = 1 Byzantine watchdog (n ≥ 3f+1 → 5 ≥ 4).

### 5.3 Trust Transparency Layer

**Motivation:** all internal detection shares the operator's blind spots (DigiNotar was
caught externally). The Transparency Layer adds eyes that do not belong to the
operator.

**Design:**
- Every trust-governance event (§5.1 schema) is mirrored to **auditor-operated
  Merkle logs** (each auditor runs its own log; append-only, CT-style).
- Each auditor runs automated checks:
  1. **Chain integrity:** full timeline verification (root hash, signatures).
  2. **Policy conformance:** violations of operator-declared rules — "≤ K certs per
     identity per day", "no policy change outside maintenance window", "no shard
     activity without DETECTED". This is the governance surface CT never covers.
  3. **Recovery re-verification:** independent re-execution of post-recovery checks
     (their own DNS lookups, their own mTLS probes).
- **Escalation:** auditor consensus (≥3 of 5 auditor operators, mutually distrusting)
  can *raise* a watchdog score to force DETECTED. Auditors can never execute recovery.

**Property (P6):** auditors detect and escalate; only the council executes.

### 5.4 Recovery Council

**Setup:** 5 physically distributed nodes; each holds one Shamir shard (3-of-5) of the
backup root key; each has a pre-bootstrapped identity (§5.7).

**Recovery state machine:**

```
IDLE ──DETECTED+evidence──▶ VERIFY_EVIDENCE
  ▲                            │ (each member verifies signature chain)
  │                            ▼
  │                         VOTE        (signed RECOVER / ABSTAIN)
  │                            │ ≥3 RECOVER? no → retry, widened evidence window
  │                            │ yes
  │                            ▼
  │                      RECONSTRUCT   (≥3 shards → enclave, memory only)
  │                            │
  │                            ▼
  │                      RE_ISSUE      (new intermediate CA signed)
  │                            │
  │                            ▼
  │                      COMMIT        (signed COMMIT with monotonic epoch)
  │                            │
  │                            ▼
  │                      VERIFY        (invariant checks, §5.6)
  │                            │ PASS
  └───────────────────────────┘ (recovery complete; RECOVERY event logged)
```

**Adversarial requirement:** an attacker must compromise ≥3 watchdogs AND ≥3 council
nodes simultaneously. Each set uses different hardware, software, and detection logic.
A single compromised council member can neither trigger nor block recovery.

### 5.5 Event-Sourced Time-Travel Rollback

**Model:** the trust state is the deterministic fold of the timeline. This gives four
algebraic laws:

| Law | Statement |
|---|---|
| L1 Idempotence | Replaying the same prefix twice yields the same state |
| L2 Uniqueness | `state_at(t)` is identical under any fork resolution |
| L3 No resurrection | A revoked certificate is never re-validated by rollback |
| L4 Minimal blast | The invalidation set equals the graph-reachable set from the first bad event |

**Rollback procedure:**
1. Locate the first bad event (W2 gap index or W3 anomaly start).
2. Compute the last verified good checkpoint hash.
3. Fold the verified prefix → pre-compromise state.
4. Compute the invalidation set via security graph reachability (§5.6).
5. Apply deltas to consumers (VPN, DNS, policy) — consumers observe `state_at(t)`
   and receive only the delta.
6. Append RECOVERY events; the new state's anchor becomes canonical.

**Consumer semantics:** consumers are state observers. They poll the trust anchor and
apply deltas, so rollback propagates as an incremental change, never a restart.

### 5.6 Security Graph and Scoped Recovery

A directed graph over identities: `User → Device → VPN Node → Service → Database`.
Nodes are cert fingerprints; edges carry the exact policy event that created them.

**Scoped recovery (RQ5):** the re-issuance set is *computable*: it is exactly the
reachable subgraph from the first bad event. The verifier asserts that nothing outside
the set changed — minimal blast radius is a checked post-condition, not an aspiration.

**Example:** a compromised developer laptop triggers re-issuance of only
`developer-laptop → dev-vpn → dev-db`. Production services are untouched and their
certificates remain valid.

### 5.7 Bootstrap / Genesis Ceremony

Every PKI has a physical trust-initialization step; this design makes it explicit and
minimal:

1. One Ed25519 keypair generated on an air-gapped machine; the private key never
   touches a networked machine.
2. The key is split into 5 Shamir shards, distributed on hardware tokens.
3. The bootstrap public key is burned into each watchdog/council/auditor node.
4. Nodes enroll once with bootstrap-signed self-signed certs.
5. After genesis (≥3 council members enrolled, first intermediate issued), the
   bootstrap key is revoked and never used again.

Auditors enroll in a **separate ceremony with their own independent roots** — auditors
share no trust ancestry with the operator's chain.

### 5.8 Consumers

| Component | Implementation | Role |
|---|---|---|
| Identity | SPIFFE-style, short-lived X.509 (crypto/x509, SAN subject) | Issues workload certs; the recovery test subject; `to-identity` CLI |
| Mutual TLS | stdlib crypto/tls, TLS 1.3, peer cert + CA-chain + identity checks | Consumer transport, loopback-verified over issued certs |
| Policy engine | Go, JSON policy eval | PDP reference allow/deny checks; `to-pdp` binary |
| DNS / VPN / eBPF | *deployment layer — reference transport (mTLS) verified instead* | Resolution/tunnel/filtering under a product choice |
| Trust Transparency | `to-auditor`: chain integrity + policy conformance + escalation recommendation | Autonomous and independent auditor review (single-operator CLI; the ≥3-of-5 audit conference is the deployment layer) |

Consumers exist so the orchestrator's claims are measured against a real system
(RQ4/RQ5). Libraries are preferred for network-facing code; custom implementations are
used only where the input surface is constrained, the spec unambiguous, and test
vectors exist (per §10 of the design document).

---

## 6. Consensus and Protocols

### 6.1 Watchdog Consensus

Not Raft: no leader election, no log replication. Scores are exchanged over mTLS
(gossip, 30s interval); the quorum rule is pure: ≥3 of 5 below threshold → DETECTED,
with the score vector and each watchdog's evidence payload attached.

### 6.2 Fork Resolution with Epoch View-Change

**The attack (from the v1 design):** choosing the canonical fork by "most verified
recovery entries" can be gamed — an attacker triggering repeated cheap recovery events
inflates their fork's entry count.

**The fix:**
- Every COMMIT record carries a **monotonic epoch number**.
- Fork validity requires a signed COMMIT chain with contiguous, gapless epochs.
- Canonical fork = highest valid epoch.
- Epochs are signed by a council majority; they cannot be forged (crypto) or rewound
  (monotonicity). Entry count is removed from the decision entirely.

**Behavior under partition:** if the council cannot reach ≥3 COMMITs for either fork,
recovery blocks until connectivity is restored — verified behavior, then degraded to
human-mediated resolution, which is documented and acceptable.

### 6.3 Security Properties (formal)

| Property | Statement |
|---|---|
| P1 Fork safety | No certificate is valid under two canonical trust anchors simultaneously |
| P2 Termination | Recovery terminates when ≥3 honest council members are connected; blocks otherwise |
| P3 No resurrection | Rollback never makes a revoked certificate valid again |
| P4 Quorum honesty | 1 compromised watchdog cannot trigger DETECTED; 1 compromised council member cannot trigger or block recovery |
| P5 Minimal blast | Post-rollback invalidation = graph-reachable set from first bad event |
| P6 Escalation only | Auditor consensus escalates detection but cannot execute recovery |

Each property is: (1) specified in TLA+, (2) model-checked with TLC, (3) covered by a
TrustOps benchmark test, (4) exercised in live kill-tests. Four layers of evidence.
**Note on P5:** the TLA+ model has no graph (the model is reduced to the consensus
state), so P5 is verified by the Go verifier (`VerifyRecovery`) and the benchmark
S6 post-condition instead of TLC — its evidence is (V + B), not (M).

---

## 7. Threat Model

| Threat | Mitigation | Residual risk |
|---|---|---|
| 1 watchdog compromised | 5 watchdogs, ≥3 quorum | 2 simultaneous compromises (requires independent exploitation of different detector stacks) |
| 1 council member compromised | 5 members, ≥3 vote, sharded key | 3 simultaneous compromises (physically distributed) |
| Network partition during recovery | Block until ≥3 connected | Extended asymmetric partition stalls (degrades to human) |
| Verifier compromised | Cross-checked by ≥2 council members + auditors re-run checks | All verifier instances compromised (same deployment) |
| Fork race during partition | Epoch monotonicity (attack eliminated) | Partitions with equal valid epochs (blocking, human resolves) |
| Bootstrap key compromise | Used once, revoked, never online | Compromise during ceremony (physical security) |
| Omniscient slow attacker | CUSUM with calibrated bounds | Measured residual gap (published as a limitation) |
| Cryptographic break | Standard algorithms | Quantum adversary (out of scope) |
| Auditor collusion | 5 independent operators, escalation-only (≥3 of 5 required) | All auditors compromised (different trust domains) |

**Byzantine reasoning:** n=5, threshold 3 → f = 1 Byzantine node tolerated
(n ≥ 3f+1). Stated explicitly: the system assumes at most one actively malicious
watchdog or council member.

---

## 8. Evaluation Methodology (TrustOps Benchmark)

### 8.1 The Anti-Theater Principle

Every claim in this report is a line in a benchmark report. The demo is the report —
not a scripted environment where the author knows the answers.

### 8.2 Scenario Generator

| Scenario | Attacker model | Description |
|---|---|---|
| S1 Burst | A1 | 200 rogue certs in 90 minutes |
| S2 Slow poison | A2 | 23 certs over 4 hours, below rate threshold |
| S3 Insider | A3 | One watchdog reports fabricated scores |
| S4 Partition | A4 | Links cut between council members mid-recovery |
| S5 Fork race | A5 | Attacker attempts to create competing recovery entries |
| S6 Combined | A2+A4+A5 | Slow poisoning during partition with fork-race attempt |
| S7 Omniscient | A2+full knowledge | Attacker computes the maximal undetectable rate from detector parameters and stays under it |

### 8.3 Metrics

| Metric | Definition | Target |
|---|---|---|
| Detection latency | time from first malicious event to DETECTED | bounded, published |
| False positive rate | DETECTED with no malicious events, per month | ≤ α (calibrated) |
| Recovery time (RTO) | DETECTED → verified healthy | published |
| Rollback correctness | automated P3/P5 post-condition check | 100% over runs |
| Auditor gap | latency with vs. without auditors | published (RQ2) |

### 8.4 Calibration Procedure

1. Run scenario-free + jittered traffic to establish baselines (μ₀ per detector).
2. Sweep W1's h over 1..16; score each candidate on jittered-baseline FPR and
   marginal-rate (2.5/cycle) latency.
3. Select the operating point: smallest h with FPR ≤ α and latency ≤ L —
   the sweep selects h=3 from data; the scenario default follows it and the
   CLI warns loudly on any drift.
4. **No knob is set by hand.** The ROC curves are the justification.

### 8.5 Verification Results (from reports/benchmark.json)

| Claim | Result |
|---|---|
| "Detects burst attacks" | S1: DETECTED in 60 s (evidence payload valid) |
| "Detects slow poisoning" | S2: DETECTED at the 1800 s CUSUM change point, no FPR on baseline |
| "No false positives on baseline" | baseline: 0 DETECTED |
| "No fabricated single-watchdog trigger" | S3: 1 fabricated watchdog → no DETECTED |
| "Recovery RTO in minutes" | S4 kill-test: recovery completes/terminates per quorum |
| "Fork attack eliminated" | S5: fork-race attempt → no competing canonical fork |
| "Rollback correct" | S6 combined: P3/P5 post-conditions pass |
| "Residual risk is measured" | S7: omniscient-attacker gap published (undetected by design) |
| "RTO/throughput" | workload re-issue: 90 certs < 60 s target; verify: 100k events, linear (ratio ≈ 10) |

ROC operating point: h=3 (W1), h=3 (W3), h=2 (W5) with δ = 1/0.5/0.5 — W1's h is
*selected by the ROC sweep* (FPR ≤ α on jittered traffic, marginal-attack
latency ≤ L), pinned in `reports/params.json` and justified by the sweep in
`reports/calibration.json`.
Current runs are green end to end (unit suite, K1–K6 kill-tests, tlc.log, mutations,
10-row benchmark; test plan §8 regression gate).

---

## 9. Implementation Status and Artifacts

- **Status:** implemented and verified. The reference implementation (Go) builds all
  eight binaries (`to-tool`, `to-bench`, `to-watchdog`, `to-orchestrator`, `to-council`,
  `to-auditor`, `to-identity`, `to-pdp`); the test suite, TLA+ model checks, TrustOps
  benchmark, and kill-tests all pass, and the reports in `reports/` are reproducible
  from a clean clone via `make`.
- **Deliverables:** orchestrator reference implementation (Go, 5 watchdog detectors,
  council recovery, event-sourced rollback, consumer identity + mutual-TLS + policy
  reference), TLA+ specs and TLC results (P1–P4, P6 + P2/P6 mutation tests; P5 is
  checked by the Go verifier — the model has no graph, see §6.3), TrustOps benchmark
  suite (S1–S7 + baseline + calibration), full design documents, this report.
- **Reproducibility:** `make build test benchmark model-check model-check-mutations
  kill-tests` regenerates every number in §8; current output is pinned in `reports/`
  (`benchmark.json`, `calibration.json` with the ROC sweep, `params.json`, `evidence.json`,
  `tlc.log`, `mutation-*.log`, `kill-tests.log`, `action-log.txt`).
- **Deployment layer (documented, not built):** the Noise VPN, DNS, and eBPF consumer
  daemons, SGX/TLS-enclave recovery, and the multi-auditor Merkle-log transport. Their
  surfaces are verified by the identity consumer, a real mutual-TLS handshake over
  issued workload certs, and the policy reference (`to-pdp`); add product-specific
  daemons when a deployment target is chosen.

---

## 10. Discussion and Limitations

1. **The omniscient attacker is unbeatable at the limit.** Any detector with
   published parameters has an adversary who computes the maximal undetectable rate.
   This is measured (S7) and published as the system's fundamental residual risk —
   the honest ceiling.
2. **Auditor incentives are open.** For research, auditors are willing collaborators.
   Real-world deployment requires an incentive design (stake, reputation, regulatory
   pull) — explicitly future work.
3. **Dependency on honest majority of council.** The 3-of-5 threshold is a policy
   choice; it can be raised (e.g., 4-of-7) at the cost of availability.
4. **Partition stalls are by design.** Recovery under extended asymmetric partition
   degrades to human mediation — a documented, verified behavior, not a bug.
5. **No ML by choice.** Statistical tests are explainable, defensible in review, and
   auditable. ML would add opacity without a demonstrated detection benefit for this
   problem.

---

## 11. Future Work

- Auditor incentive and reputation design.
- Deployment against live CT logs as an additional auditor input.
- Extension of the transparency layer to DNS and BGP governance surfaces.
- Longitudinal false-positive measurement under real operator workloads.
- Formalization of consumer-state migration (delta application) in TLA+.

---

## 12. Conclusion

The Trust Orchestrator demonstrates that the three historical failures of PKI —
reactive detection, manual recovery, unverified correctness — can be made structural:
detection by an internally and externally sourced ensemble with calibrated statistical
tests; recovery by a physically distributed cryptographic council with a formally
eliminated fork attack; correctness by event-sourced rollback, model-checked safety
properties, and an adversarial benchmark that converts every claim into a measured,
reproducible result. The system does not invent cryptography; it orchestrates standard
primitives into a detection-recovery-verification loop no shipping CA product
provides, and — unlike prior work — it measures its own residual risk instead of
asserting it away.

---

## References

1. B. Laurie, A. Langley, E. Kasper. *Certificate Transparency*. RFC 6962, 2013.
2. M. van der Sluijs et al. *DigiNotar Certificate Authority breach — operation Black
   Tulip*. Fox-IT, 2011.
3. A. Shamir. *How to share a secret*. Communications of the ACM, 1979.
4. L. Lamport. *Specifying Systems: The TLA+ Language and Tools for Hardware and
   Software Engineers*. Addison-Wesley, 2002.
5. M. Castro, B. Liskov. *Practical Byzantine Fault Tolerance*. OSDI, 1999.
6. E. S. Page. *Continuous Inspection Schemes*. Biometrika, 1954. (CUSUM)
7. Google. *Key Transparency* design documentation.
8. M. Melara et al. *CONIKS: Bringing Key Transparency to End Users*. USENIX
   Security, 2015.
9. HashiCorp. *Vault PKI Secrets Engine* documentation.
10. SPIFFE/SPIRE project documentation.
11. T. Perrin. *The Noise Protocol Framework*. 2018.
12. *Wycheproof* cryptographic test vectors. Google, 2016.
