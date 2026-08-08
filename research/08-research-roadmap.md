# 08 — Research Roadmap (Detailed Execution Plan)

The execution plan for the TrustFabric program: priorities, sequencing
with dependency rationale, year-by-year plan with quarterly tasks,
venue strategy, artifact policy, team shape, budget, and definition of
done. The plan is *normative* — a change to it is a decision, not an
edit.

---

## 1. Priority and sequencing (normative)

**Order: L2 → L4 → L3 → L1 → L5.** Rationale (dependency + risk):

1. **L2 first** (private transparency). (a) It is the strongest paper
   (novelty is cleanest: simulation-defined predicate privacy over
   RFC 9162 logs). (b) It upgrades L0 *without touching L0* (claims
   over existing logs) — lowest engineering risk. (c) Every other
   layer consumes its primitives (L3's registry predicates, L4's
   audit story, L1's recovery evidence).
2. **L4 second** (economics). (a) It defines the reputation vector
   that L1's quorums *need*; sequencing it before L1 means L1 is
   built on the right weight semantics from day one. (b) It is the
   second-strongest paper (token-free mechanism design with
   verified-event enrollment).
3. **L3 third** (intelligence). Needs L2's registry predicates and
   L4's weights; its DP-noise-CUSUM result is strongest when the
   weight-filtered pools exist.
4. **L1 fourth** (consensus). The heaviest engineering; its
   reconfiguration story depends on L4's weights; its recovery
   protocol depends on L0's seam. Waiting is free.
5. **L5 last** (verification). It verifies what exists; starting early
   means re-proving. But its **V1–V3 seed** (RFC 9162 verifiers,
   timeline, STH) is doable in parallel from month 1 with one
   part-time proof engineer.

**Hard rule:** no layer ships a production dependency on a layer that
is not yet published-or-demoed. L0 stands alone; L2–L4 are published
as papers with artifacts; L1 and L5 consume published layers.

---

## 2. Year-by-year plan (with quarterly tasks)

### Year 1 — L2 paper + L0 product demo + L5 seed

| Q | Tasks | Deliverable |
|---|---|---|
| Q1 | L2-M1: circuit spec, `INCLUDE`/`EXTENDS` prove/verify, harness green. L5 seed: V1 port (F*), ctlog tests as acceptance. L0: cert-manager integration + 2-host deployment guide. | circuit + harness + benchmark; F* port + proof term; demo |
| Q2 | L2-M2: `NONE_OF`/`COUNT_OF`, witness protocol, registry predicates. L4-M1: game model + `U` spec + score ledger ref impl. L0: witness demo (2 orgs gossiping). | witness demo; ledger spec+impl |
| Q3 | L2-M3: privacy tests (simulator-based), performance tables. L4-M2: simulator + equilibrium/sybil experiments. | evaluation artifacts (both) |
| Q4 | L2-M4–M5: conditional disclosure, PSI v1, write-up, artifact freeze. **Submit L2 (CCS / USENIX Security / PoPETs).** | L2 paper draft + artifact |

### Year 2 — L4 paper + L3 paper + L1 prototype

| Q | Tasks | Deliverable |
|---|---|---|
| Q1 | L4-M3: ablations + adversarial search + recovery mechanism; robustness report. L3-M1: secure aggregation + DP + noise-aware CUSUM (on L2 registry predicates). | reports; pipeline + ε-sweep tables |
| Q2 | L4-M4: write-up, freeze. **Submit L4 (WEIS / PETS).** L3-M2: correlation + RISK_FEED + proactive-rotation gate + poisoning defenses. | L4 paper; end-to-end L3 demo |
| Q3 | L3-M3: dataset freeze S1–S7, model eval, held-out scenario, ROC/ε curves. L1-M1: WQBFT spec + simulator + PBFT baseline. | dataset + eval; L1 simulation + tables |
| Q4 | L3-M4: write-up, freeze. **Submit L3 (CCS / NDSS / S&P).** L1-M2: safety/liveness proofs, weight-cap analysis. | L3 paper; L1 theorems |

### Year 3 — L1 paper + L5 papers + system integration

| Q | Tasks | Deliverable |
|---|---|---|
| Q1 | L1-M3: federated recovery protocol + cross-org FROST prototype; recovery demo (5 orgs). L5-M1–M2 completion: V1–V5 proven + harness green + CI gate. | recovery demo; V1–V5 |
| Q2 | L1-M4: full cluster demo (policy decision + rescue); write-up, freeze. **Submit L1 (DSN / USENIX ATC / SRDS).** | L1 paper |
| Q3 | System integration: all layers wired end-to-end on the demo deployment; L5 seam contract (V8) + property ledger 100% populated. | integrated demo; ledger |
| Q4 | L5-M4: write-up. **Submit L5 (CAV / PLDI / OOPSLA).** Year-3 wrap: reproducibility run (one command regenerates every artifact and table). | L5 paper; full artifact |

### Years 4–5 (optional, strategic)

- V10 (Go bridge, SAW) — the "code meets spec" paper.
- Productization: managed witness network + recovery-as-a-service;
  insurance-grade risk scores; industry whitepapers.
- Extension: fully-asynchronous consensus (DAG-Rider line), dynamic
  accumulator registry, PQ-verification of the whole stack.

---

## 3. Venue strategy (normative)

| Paper | Venues (in order) | Why |
|---|---|---|
| L2 | CCS → USENIX Security → PoPETs | strongest; needs a security/privacy venue with artifact evaluation |
| L4 | WEIS → PETS | economics-of-security is WEIS's home; PETS if more privacy |
| L3 | CCS → NDSS → S&P | systems+privacy+security balance |
| L1 | DSN → USENIX ATC → SRDS | systems/dependability venues fit WQBFT |
| L5 | CAV → PLDI → OOPSLA | verification venues |

**Submission discipline:** one paper per quarter max (two per year),
never two strong submissions in the same window (artifact stress).
Every submission has a frozen artifact ≥ 1 month before the deadline.

---

## 4. Artifact policy (normative)

Every published claim is backed by a pinned artifact:

1. **Code:** the Go repo (L0) at a tagged commit; every other layer's
   code in `research/<layer>/` with pinned dependency versions and a
   one-command regen script.
2. **Dataset:** `bench.go` S1–S7 generator, seed pinned, per-epoch
   versioned releases; held-out scenario S7 never used in training.
3. **Reproduction:** every table/plot regenerable from
   `make research-reproduce` (a CI target).
4. **Formal artifacts:** proof terms, TLA+ models + TLC logs,
   property ledger (status per property), adversarial harness outputs.
5. **The checker:** a public, small, audited binary that replays
   evidence offline.

**Artifact freeze rule:** no submission without freeze; no freeze
without the regen script passing from a clean checkout.

---

## 5. Team shape (honest)

| Role | Year 1 | Year 2 | Year 3 | Notes |
|---|---|---|---|---|
| Research lead (L2/L3) | 1 FTE | 1 | 1 | the named "us" — likely you |
| Systems engineer (L0/L1) | 0.5 | 1 | 1 | the repo owner |
| Proof engineer (L5) | 0.25 | 0.5 | 1 | can be part-time until Year 3 |
| Economics researcher (L4) | 0.25 | 0.5 | 0.25 | or a collaborator |
| Grad-student collaborators | 0–2 | 1–3 | 1–3 | venue currency; university affiliation for CCS/etc. |

**Advisors/co-authors:** one trusted-systems professor (for L1/L5
credibility), one applied-crypto professor (L2). They cost nothing but
must exist — venue acceptance odds change materially.

---

## 6. Budget (normative, USD)

| Item | Year 1 | Notes |
|---|---|---|
| Compute (benchmarks, SNARK proving) | $1–2k | cloud, sporadic bursts |
| Artifact hosting (dataset, VM) | $0.5k | static hosting suffices |
| Conferences (1–2 travels) | $3–6k | if a venue is reached |
| Tools (Coq/F*/SAW licenses are free; hardware) | $1k | laptops; no license costs |
| **Total** | **$6–10k** | years 2–3 similar scale; the cost is *time*, not money |

---

## 7. Risk register (normative)

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| L2 paper rejected twice | medium | high | PoPETs fallback; resubmit with artifact; the venue ladder §3 exists for this |
| SNARK library maturity (pure-Go) | medium | medium | keep circuit spec library-agnostic; Rust-FFI escape hatch |
| Reviewer: "why not just use TLS+cohorts?" | high | medium | the threat-model §5 and DP proofs are the answer; the honest-limits section anticipates it |
| Dataset overfitting (scenario-aware) | medium | medium | held-out S7 + generator randomization; the split is published |
| No university affiliation | medium | medium | industry-track venues (WEIS, S&P industry track), DSN's industry sessions |
| Single-person bus factor | medium | high | artifacts are the documentation; the repo is the knowledge base; grad collaborators from Year 2 |
| L1 simulation reveals safety bug | low | high | TLA+ before simulation; halt > wrong (fail-closed §`01 §8`) |

---

## 8. Definition of done (normative)

The program is *done* when:

1. L2, L3, L4, L1, L5 are each published or accepted (in the order and
   venues of §2–3) **with frozen artifacts**.
2. The integrated demo runs the full loop end-to-end: L0 logs →
   L2 claims → L3 risk feeds → L4 scoring → L1 decision → federated
   recovery — all verifiable offline by the public checker.
3. The property ledger is 100% populated with `PROVEN` or explicitly
   `STATED` entries, and the paper text matches the ledger (no
   unproven claim silently asserted).
4. `make research-reproduce` regenerates every table, plot, dataset,
   and proof term from a clean checkout on a stock machine.
5. The repo remains dependency-free, and every layer is documented in
   the style of this document (spec → protocol → property → evidence).
