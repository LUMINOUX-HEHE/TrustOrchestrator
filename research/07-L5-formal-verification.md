# 07 — L5 Formal Verification: Detailed Specification

L5 makes the network *provable*: the invariants of L0, the safety of
L1, the privacy of L2, the DP bounds of L3, and the incentives of L4
become machine-checked statements about a verified implementation core
— with a public, small checker that anyone can run offline. This
document is the normative L5 design: proof goals (prioritized),
framework selection, the interface-contract architecture, the
adversarial harness, and effort estimates grounded in what already
exists in this repo.

---

## 1. Proof goals (normative, prioritized)

| ID | Goal | Layer | Proof obligation | Why first |
|---|---|---|---|---|
| V1 | RFC 9162 inclusion/consistency verifiers are correct | L0 | functional correctness of `VerifyInclusion`, `VerifyConsistency` vs the RFC's reference semantics | smallest, highest-value, already hand-tested (10 tests) |
| V2 | Timeline append preserves the hash chain | L0 | `append(e)` maintains I1/I2 (§`02 §4`) | the substrate every other proof rests on |
| V3 | STH signing/verification is a valid signature scheme | L0 | `SignSTH`/`Verify` inverse; no forgery under Ed25519 | gates all cross-org verification |
| V4 | WQBFT safety (agreement) | L1 | T1–T3 (§`03 §5`) | the only place "wrong" is a *legal* outcome |
| V5 | Alarm soundness: alarm ⇒ real fork | L0+L2 | `GossipNode.Observe` alarm ⇒ there exist two valid STHs with inconsistent histories | turns alarms into evidence |
| V6 | DP composition accounting | L3 | the published `(ε,δ)` per aggregate is a valid composition bound | auditability of the privacy claim |
| V7 | Reputation update is verification-only | L4 | P1 (§`06 §2`) | the economic claim |
| V8 | Seam contract: every layer message verifies | all | envelope + `cert_refs` validity (§`01 §3`) | cross-layer accountability |
| V9 | Federated recovery correctness | L1 | anchor ⇒ consistency of restored root (§`03 §6`) | the rescue path |

**Prioritization rule:** (value / cost) descending, with V1–V3 as the
*everest* (smallest, doable now in this repo), V4–V5 as the first
*paper-worthy* results, V6–V9 as the long tail.

---

## 2. Framework selection (normative)

| Tool | Role | Choice rationale |
|---|---|---|
| **F\*** (proof assistant, type-driven verification) | verified core: V1–V5 | strongest fit: functional correctness of reference implementations; Everest precedent (TLS) |
| **Coq/Rocq** | fallback for the same goals | standard library breadth; more manual |
| **TLA+ / TLC (already in `specs/`)** | executable *specs* + model-checked safety for V4 | already used; specs must mirror the verified core 1:1 |
| **Foundry/Crucible (SAW)** | bounded verification of the Go *artifact itself* | a pragmatic "the Go code meets the verified spec" bridge (alternative to porting everything) |
| **QED / bespoke checker** | the *public checker* for consumers | a tiny, audited binary that replays proof artifacts |

**The port question.** V1–V5 target the *specification-level* language
(an F* port of the RFC 9162 verifiers + WQBFT state machine), not the
Go code itself. Bridging to the Go artifact is V10 (below) and is
deliberately out of the first-year scope — it is where Everest-style
effort lives.

---

## 3. Interface contracts (the compositional architecture)

Every layer boundary (`01 §3`) gets a *contract*: a pair of
predicates `(Pre, Post)` and an obligation `⊢ Pre ⇒ code ⇒ Post` in
the proof language, plus a *transfer lemma* saying that a message
accepted by layer n+1 satisfies the postcondition layer n+1 relies on.

**Example (seam contract, V8):** a `RISK_FEED` observation accepted by
an L0 gate must satisfy `ValidSignature ∧ cert_refs ⊆ verified
observations ∧ risk_vector ∈ [0,1]^k`. The L3 code that emits feeds is
verified against `Post_RISK_FEED`; the L0 gate's policy is verified to
*accept only* `Post_RISK_FEED` messages; the composition theorem says:
feed ⇒ evidence. This is a **horizontal** contract (same property
across layers) — the *cross-layer transfer* is the novel formal
machinery.

**The property ledger.** A machine-readable registry of every
statement above (id, layer, obligation, proof status, artifact hash)
— the paper's appendix is generated from it.

---

## 4. The adversarial seam harness

A harness that *attempts to break* the properties, standing on the
adversaries of `01 §9`:

```
for each property P:
  generate adversarial inputs (tampered proofs, forked STHs,
  reordered timelines, wrong quorum certificates, budget-lying
  aggregates)
  run the artifact (Go verifier, TLA+ model, or F* code)
  assert P holds or the input is rejected
```

This is the *evidence* the paper cites: not just "we proved it in F*"
but "an automated adversary, given our exact artifacts, cannot produce
a violating input." It doubles as the regression gate for the repo
(CI hook: `make verify`).

---

## 5. Proof-to-artifact pipeline

```
F* spec (V1–V5) ──► extraction of checkable proof term
Go artifact     ──► reproducible build (pinned commit, stdlib only)
TLA+ specs      ──► model-checked safety (TLC, current Makefile targets)
harness         ──► adversarial run (assert or reject) → signed evidence
property ledger ──► generated appendix (status, artifact hashes)
public checker  ──► replays evidence (offline, ~seconds)
```

Every artifact is pinned and regenerable; the paper's reproducibility
statement is a shell command.

---

## 6. Evaluation and acceptance criteria

| Criterion | Gate |
|---|---|
| V1–V3 proof terms exist and compile | F* build green; ported verifiers pass the 10 existing ctlog tests |
| V4 safety theorem | TLA+ model-check over WQBFT; F* (or Coq) proof of T1–T2 |
| V5 alarm-soundness | proof + harness adversarial suite green |
| V8 seam contract | contract check in CI (every merge) |
| Property ledger completeness | 100% of `01 §9` boundary properties have an entry |

**Acceptance for the paper:** every theorem cited in 02–06 has a
ledger entry with status `PROVEN` (not `STATED`). Anything stated but
unproven is labeled `STATED` in the text — the honest rule of the
program.

---

## 7. Research sub-problems (expanded)

1. **Cross-layer contract composition** — the transfer lemmas (§3);
   the machinery itself may be a contribution if it is
   instantiated across 4 layers.
2. **Verifier reference semantics vs RFC 9162** — the RFC has
   *informal* semantics; V1 requires formalizing the RFC's
   consistency proof definition (the old-root-prepend case) into
   checkable axioms. (Novelty: the first machine-checked RFC 9162
   verifier, if none exists at publication time.)
3. **TLA+ ↔ F* mirror** — keeping `specs/` and the verified core in
   1:1 sync; a tooling paper if automated.
4. **The Go bridge (V10)** — SAW/Crucible bounds on the Go code;
   the "the code meets the spec" paper (year 2+).
5. **Adversarial-harness design** — formalizing "adversary cannot
   break it" as a *property of the harness* (coverage of the attack
   space), not a vibe.

---

## 8. Effort estimate (honest)

| Goal | Effort (person-months) | Notes |
|---|---|---|
| V1–V3 (F* port of ctlog + timeline + STH) | 6–9 | porting is mechanical; the RFC formalization is the real work |
| V4 (WQBFT safety) | 4–6 | TLA+ first (already modeled); F* later |
| V5 (alarm soundness) | 2–3 | small state machine |
| V8 (seam contract) | 3–4 | the composition machinery |
| V6–V7, V9 | 4–6 | linear per goal |
| Harness + ledger + checker | 2–3 | mostly build-once |
| **Total** | **21–31** | over 12–18 months with 1 FTE + 1 part-time |

The honest first paper is V1–V5 + the harness; V6–V9 fill later
papers.

---

## 9. Milestones and deliverables

| Milestone | Content | Artifact |
|---|---|---|
| M1 (mo 1–6) | V1–V3 proven; ported verifiers pass ctlog suite; property ledger v1 | proof terms + ledger |
| M2 (mo 7–10) | V4–V5 proven; adversarial harness green; CI gate | theorems + harness + CI |
| M3 (mo 11–14) | V8 seam contract; TLA+ ↔ F* mirror; checker binary | contract + checker |
| M4 (mo 15–18) | V6–V7, V9; write-up | paper draft (CAV / PLDI / OOPSLA) |

**Related work (deep).** seL4 (Klein et al., 2009) — the gold
standard of verified *systems*; we borrow its "verify the kernel, not
the world" philosophy (verify the checker + contracts, not every
service). IronFleet (Hawblitzel et al., 2017) — distributed protocol
verification in Dafny; our WQBFT proof is IronFleet-flavored.
Everest (Bhargavan et al., 2017) — verified TLS in F*; the template
for V1–V3. CompCert (Leroy) — the "verified artifact is usable"
precedent for the checker. The novelty: *a verified transparency
stack with cross-layer accountability contracts* — none of the above
verifies an RFC 9162 log, a reputation economy, or the seam.
