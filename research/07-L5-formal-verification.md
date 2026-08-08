# 07 — L5: Formal Verification of the Stack

**Research problem:** each layer proves properties about itself — L0 has
model-checked P1–P6 invariants, L1 will prove consensus safety, L2 proof
systems have their own soundness, L3's DP guarantee is mathematical, L4's
game model is formal. But **nothing proves the layers compose**. L5 is
the layer whose object of study is the whole system: compositional
verification that the stack's guarantees survive their interaction.

## 1. Why this layer exists

- **Composition is where systems die.** L0's fork-safety is proven;
  L1's consensus is proven; the interaction (an L1 decision triggering an
  L0 recovery) is unproven. Every real incident in distributed trust
  systems lives in the seams.
- **Proofs are a product.** For regulated buyers (banks, healthcare),
  a machine-checked statement "history integrity holds under these
  assumptions" is a procurement requirement, not a nicety.
- **The precedent exists**: seL4, IronFleet, Everest/F* prove that
  end-to-end verification of real infrastructure is possible — but none
  of them covers *threshold crypto + transparency + economics*.

## 2. The research contribution (what is novel)

1. **A compositional framework for trust stacks.** A refinement-based
   method: each layer exposes an *interface contract* (preconditions,
   guarantees, leakage bounds); the framework proves that contracts
   compose. Novelty: contracts must express *probabilistic* and
   *economic* properties (DP bounds, game equilibria), not just safety
   and liveness.
2. **Machine-checked core.** The safety-critical core (timeline append/
   verify, RFC 9162 proofs, FROST aggregation, vault key hierarchy) gets
   machine-checked proofs (Coq/Isabelle/F*) *and* code refinement — the
   L0 artifact is small and stdlib-only, which makes this tractable.
3. **Cross-layer property transfer.** E.g.: L2's privacy proofs must
   hold *given* L0's log format; L1's consensus safety must hold *given*
   reputation feedback from L4 (a feedback loop — new verification
   territory).
4. **Adversarial composition testing.** Beyond proofs: a harness that
   injects adversarial behavior at every seam (drop a witness, reorder
   consensus, poison a pool) and checks each layer's invariants — the
   testing complement to the proofs.

## 3. Related work (anchors)

- seL4 (Klein et al.) — full verification of an OS microkernel; the
  gold standard for "verified substrate".
- IronFleet (Hawblitzel et al.) — distributed systems verification
  (Raft); IronClad — end-to-end in one implementation language.
- Everest (Bhargavan et al., F*) — verified TLS; **the direct
  precedent**: protocol verification composed with an implementation.
- TLA+ (Lamport) — the L0 practice (existing specs/); refinement
  mapping is the natural upgrade path.
- Differential privacy verification: Fuzz (aPPL) / DP frameworks;
  mechanism-design verification is essentially untouched.

## 4. Concrete sub-problems

| # | Problem | Status | Our angle |
|---|---|---|---|
| L5.1 | Machine-checked RFC 9162 proofs (inclusion/consistency) | partial (some CT formalizations exist) | verify L0's exact tree shape + verifier, extract to code |
| L5.2 | Machine-checked FROST aggregation + timeline append | open | threshold signing verified against L0's implementation |
| L5.3 | Interface contracts with DP/economic properties | open | the framework contribution |
| L5.4 | Cross-layer composition (L2-on-L0, L1-under-L4) | open | property transfer theorems |
| L5.5 | Adversarial seam-testing harness | engineering | every layer's invariants under seam attacks |

## 5. Interfaces

- **Down (consumes):** all layers' formal artifacts (L0 TLA+, L1 proofs,
  L2 circuits, L3 DP proofs, L4 game models).
- **Up (serves):** verified claims for productization (compliance
  evidence for L0's `compliance.go` reports), the only component every
  other layer *trusts* — and it is small, public, and open.

## 6. Milestones (6-month units)

| Phase | Deliverable | Success criterion |
|---|---|---|
| M1 | Machine-checked RFC 9162 verifier (Coq or F*) | extraction passes L0's own test corpus |
| M2 | Verified timeline append + FROST aggregation core | code-extracted core passes all L0 safety tests |
| M3 | Interface-contract framework + L2-on-L0 transfer | first cross-layer property theorem |
| M4 | Adversarial seam harness; paper | accepted at CAV / PLDI / OOPSLA / IEEE S&P |

## 7. Risks

- Proof effort is the largest cost in the program (mitigate: target the
  *small* core — L0 is stdlib-only and small by design; extract, don't
  reimplement).
- F* / Coq engineering learning curve (mitigate: Everest-style pipeline,
  F* directly compiles to OCaml/C).
- DP and game-theoretic properties do not fit classic refinement —
  the framework itself is the research; manage scope honestly.

## 8. Validation strategy

- The L0 artifact is the ground truth: extracted code must pass the
  existing 116-test corpus; every theorem is checked, never asserted.
- Public checker: the proof artifacts and the checker are open — any
  reviewer can re-verify (this is what makes L5 the credibility layer
  for regulated buyers).
