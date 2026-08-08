# 08 — Research Roadmap: Sequencing, Venues, Milestones

The program is a 3–5 year research arc. This roadmap sequences the layers
by *cost of entry* (what already exists), *publishability*, and
*dependency* — with the rule that every layer ships a reproducible
artifact, and every paper's numbers are regenerable.

## 1. The sequencing logic

| Priority | Layer | Why here | First paper target |
|---|---|---|---|
| 1 | **L2 Private Transparency** | the substrate (L0's CT log) exists; the field is hot; the problem is open | CCS / USENIX Security / PoPETs |
| 2 | **L4 Trust Economics** | no new crypto needed; the witness-network model is already implemented in L0 | WEIS / PETS / econ-crypto venues |
| 3 | **L3 Threat Intelligence** | needs a dataset — L0's simulator produces it; L2's registry feeds it | CCS / NDSS / IEEE S&P |
| 4 | **L1 Consensus** | hardest systems work; benefits from L4 reputation (weights) | DSN / USENIX ATC / SRDS |
| 5 | **L5 Verification** | the long game; builds credibility for everything; scope to the small core | CAV / PLDI / OOPSLA / IEEE S&P |

Dependency graph: L2 → L3; L4 → L1; L5 → (everyone's artifacts).
L2 and L4 are independent of each other — they can proceed in parallel.

## 2. The program year by year

**Year 1 — foundations (L2, L4 start)**

- Q1: L2 M1 — ZK inclusion proof against L0's real logs; L4 M1 —
  witness-network game model.
- Q2: L2 M2 — private revocation + authorized key registry.
- Q3: L4 M2 — strategy-proof key-hygiene score, mapped to L0
  observations.
- Q4: **Paper 1 (L2)** submission; L2 M3 (witness alarms); L4 M3
  (reputation graph + sybil evaluation).

**Year 2 — intelligence and agreement (L3, L1 start)**

- Q1: L3 M1 — labeled dataset from L0 simulator (public release).
- Q2: **Paper 2 (L4)**; L3 M2 — DP-federated detection.
- Q3: L1 M1 — weighted-quorum SMR spec + TLA+ model.
- Q4: **Paper 3 (L3)**; L1 M2 — reference implementation.

**Year 3 — the stack comes together (L1, L5)**

- Q1: L1 M3 — federated recovery; L3 M4 — signed risk feeds into L0
  (proactive rotation demo).
- Q2: **Paper 4 (L1)**; L5 M1 — machine-checked RFC 9162 verifier.
- Q3: L5 M2 — verified timeline/FROST core; L5 M3 — contract framework.
- Q4: **Paper 5 (L5)**; end-to-end demo: all layers running.

**Years 4–5 — the system, not just papers**

- Cross-layer integration: L0 seam additions (key fingerprints, signed
  alerts, trust-edge metadata) shipped and standardized.
- Regulated-buyer validation: compliance evidence produced from L5
  verified claims.
- Thesis consolidation: the full system as the reference implementation
  of "verifiable collective trust".

## 3. Venue strategy

| Layer | Primary venues | Backup |
|---|---|---|
| L2 | CCS, USENIX Security, PoPETs | FC, IEEE EuroS&P |
| L3 | CCS, NDSS, IEEE S&P | AISec, KDD (ML angle) |
| L4 | WEIS, PETS | EC (economics), crypto-econ workshops |
| L1 | DSN, USENIX ATC, SRDS | NSDI, ICDCS |
| L5 | CAV, PLDI, OOPSLA | IEEE S&P, ITP |

Workshop-first strategy for each layer: submit a position paper to the
relevant workshop (e.g. ZKProof workshops, WEIS, SecSoS) in the quarter
*before* the main paper — feedback de-risks the main submission.

## 4. Artifact policy (non-negotiable)

Every paper ships:

1. **Code**: the layer's implementation as an extension of this repo
   (each layer is a package in `research/<layer>/` or a sibling repo).
2. **Dataset**: L3's labeled compromise dataset, regenerated from L0's
   simulator with a pinned version.
3. **Reproduction**: docker-compose / scripts such that a reviewer runs
   one command and regenerates every table.
4. **Formal artifacts**: TLA+ models, proof files, and the checker
   (public, open).

## 5. Team shape (what the program needs)

| Role | When | For |
|---|---|---|
| 1 founding researcher (crypto/systems) | now | L2/L4 first papers |
| ML researcher | Year 2 | L3 |
| Distributed-systems researcher | Year 2–3 | L1 |
| Proof engineer | Year 3 | L5 |
| Students (2–3, MSc → PhD) | Year 1–3 | each owns a sub-problem → thesis |

Funding hooks: the L0 artifact + L2 prototype is a strong fellowship
proposal; L3's dataset is a community contribution (citations);
L4's model is industry-relevant (insurance/GRC partners).

## 6. Risks and mitigations

| Risk | Mitigation |
|---|---|
| ZK circuit effort explodes (L2) | start with the tiny RFC 9162 shape; reuse frameworks |
| DP utility cliff (L3) | event-level DP; measure honestly; publish negative results |
| Game models untestable (L4) | validate every claim in L0 simulation first |
| Weighted consensus subtlety (L1) | weight epochs; explicit reconfiguration; TLA+ first |
| Proof scope creep (L5) | verify the small core; extract, don't reimplement |
| Program sprawl | one paper per layer; the *system* is the year-5 deliverable, not the year-1 plan |

## 7. Definition of done (the program, whole)

1. Five papers in peer-reviewed venues, all with artifacts.
2. All layers running against L0 in one deployment (the TrustFabric
   demo).
3. L5-verified core producing compliance evidence for a regulated pilot.
4. The dataset + verification artifacts used by others (adoption
   evidence: citations, downloads, forks).
5. The honest limitations list (docs/09 pattern) kept current at every
   layer — this program's credibility is its honesty.
