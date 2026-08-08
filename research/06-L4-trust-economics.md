# 06 — L4 Trust Economics: Detailed Specification

L4 is the *incentive layer*: why would an org run a witness? why would
it behave honestly? why would it pay for a recovery? L4 prices trust.
Its output is the reputation vector that L1's quorums use, the
enrollment costs that keep L3's signal pools sybil-free, and the
scoring rules that make L0's history auditable *as an economic
statement*. Token-free by design: the currency is *reputation*, and
reputation only changes via verified events (L0/L2/L3 observations).
This document is the normative L4 design: game model (formal), scoring
rules, reputation algorithm, sybil analysis, mechanism design for
recovery, and evaluation.

---

## 1. Problem statement (formal)

**Informal.** A witness network is only as good as its incentives. A
witness who never checks, an org who never rotates, a validator who
votes lazily — all are *free-riders* who collect the same network
benefits as diligent members. L4 must make diligence the dominant
strategy and make *verified* diligence the only way to buy influence
(in L1 weights) or to sell services (recovery, insurance pricing).

**Formal (game).** Players: orgs `O`, witnesses `W`, aggregators `A`,
validators `V`. Each player `i` has a type `θ_i` (honest, lazy,
malicious, sybil-farm) chosen adversarially; a strategy profile
`s`; a reputation trajectory `r_i(t)` governed by a **public,
deterministic update rule** `r_i(t+1) = U(r_i(t), events_i(t))` where
`events_i(t)` are *verified observations only*. Payoffs:
`π_i = benefit_i(service quality) − cost_i(effort) + penalty_i(cheating
detection)`. The mechanism design question: does `U` make honesty a
Nash equilibrium (or better: a **dominant strategy for service
quality**) for all player types?

**Research question.** What is the smallest set of *verifiable* events
such that the truthful-equilibrium result holds — and what is the
cheapest cheating detection that preserves it (the adversarial
verification-efficiency frontier)?

---

## 2. The update rule (normative, versioned)

```
U:  r_i(t+1) = α·r_i(t) + (1−α)·s_i(t)          (0 < α < 1, α versioned)
s_i(t) = quality score from epoch t observations:
   witnesses:  +1 accepted-STH-verifications (signed, L2)
               +1 alarm-correctness (alarm ↔ verified fork)
               −1 false alarm (alarm, no fork)
               −1 silent fork (fork, no alarm)      ← the key free-rider signal
   orgs:       +1 verified rotation on alarm (L0 ROTATION + policy ref)
               +1 consistent-STH extension
               −1 verified compromise without rotation
               −2 verified silent history rewrite (L2 witnesses)
   aggregators:+1 correctly-signed aggregates (cross-check with pair)
               −1 dropped-epoch (missing aggregate)
   validators: +1 proposal/commit participation
               −1 missed view-change (view-change timeout while others commit)
```

**Properties (theorems to state — L5 later):**
- **P1 (Monotone-in-verification).** `s_i(t)` depends only on
  observations verified at the layer that emitted them; unverified
  self-reports cannot move reputation. (Proof: construction of `U`.)
- **P2 (Bounded).** `r ∈ [0,1]`; an org cannot "bank" reputation
  forever (α decay; forgetting rate is a design knob — priced).
- **P3 (No double-spend).** Each observation is consumed at most once
  per epoch (dedup by observation hash in the score ledger).

The score ledger is itself append-only and signed (L4's own L0 log —
the economics are auditable at the same bar as the security).

---

## 3. Scoring rules: proper-scoring theory

A **scoring rule** rewards truthful reporting iff truthfulness
maximizes expected score. L4's alarm score for witnesses is a *proper
scoring rule* in the following sense: for a witness with private belief
`p` that a fork exists, the expected score of reporting `r̂` is
maximized at `r̂ = p` when the score is the **logarithmic rule**
`S = (y)·log(r̂) + (1−y)·log(1−r̂)` (y = outcome). The scale
(`±1`, `±2`) is a *bounded* variant chosen so scores are compatible
with the integer ledger; the paper's question: what is the loss of
boundedness (vs the unbounded log rule) in equilibrium-shaping
efficiency?

---

## 4. Sybil analysis (formal)

An adversary with `m` fake identities aims to control reputation
mass in `V` (validators, the quorum weighers). **Enrollment cost**
`c_enroll` = a burn of *verified honest activity* (time-in-network
with positive score history) — not coins. The adversary must either
(a) run `m` long-lived *honest* identities (cost grows linearly, no
gain: their reputation is honest), or (b) fake activity (cost grows
super-linearly: fake activity must survive scoring, and false signals
are penalized by P1). **Theorem to prove:** under P1–P3 with `c_enroll`
> 0, an adversary controlling a fraction `φ` of weight requires honest
*economic* effort `Ω(φ·T)` over time `T` — the sybil barrier grows
with the network's age. The classic EigenTrust bound (Kamvar et al.)
is our baseline; the novelty is tying *enrollment to verified events*
so there is no way to buy reputation.

---

## 5. Mechanism design for federated recovery

L1's recovery (§`03 §6`) needs neighbors to *volunteer* shares.
Mechanism: **recovery futures** — an org that joins the network
commits (signed) to contribute to up to `κ` recoveries per epoch;
a contributor earns `+g` reputation per completed contribution and
loses `−g·2` for a missed *committed* recovery (commitment is
verifiable: FROST participation is signed). Parameters `(κ, g)` are
priced by the network (v1: fixed, versioned constants; research:
dynamic pricing from capacity). **Theorem to prove:** with `g` ≥
`(opportunity cost of the share)'s worst case`, no rational org
defects from an accepted recovery commitment (a participation-proof
version of the standard volunteer dilemma).

---

## 6. Pricing model (token-free, v1)

| Service | Price (in reputation units) | Why it is priced |
|---|---|---|
| Witness verification (per epoch) | 1 | deterrent to lazy witnessing |
| Enrolling an org | `c_enroll` (time + score history) | sybil barrier (§4) |
| Federated recovery (per event) | `g` paid by the rescued org's reputation | funds the volunteer pool |
| Weight in L1 quorums | `w(o) ∝ r_o` (capped at ⅓ − ε) | makes quorums rep-driven, not count-driven |
| Insurance-style guarantee | `r_o` above threshold + verified history | the commercial output (see `00 §7`) |

**No coins, no tokens.** Rationale (normative): token economies couple
reputation to exchangeable value, which turns reputation attacks into
monetary arbitrage; the reputation ledger is *not transferable*
(bound to org identity via L0 keys).

---

## 7. Evaluation plan

1. **Mechanism simulation.** Agent-based simulation over the event
   generator (S1–S7): population of honest/lazy/malicious/sybil
   types; measure (a) honesty-is-dominant (no strategy profile
   strictly improves long-run payoff over honesty), (b) sybil barrier
   scaling `m` vs `T`, (c) recovery participation rate, (d) weight
   concentration over time (L1's cap enforcement).
2. **Ablations.** (i) no enrollment cost, (ii) no forgetting (α=1),
   (iii) unverifiable self-reports — each must measurably degrade
   equilibrium properties (the paper's "what could go wrong" section).
3. **Adversarial search.** Genetic search over strategy profiles
   against `U` (bounded simulation budget) — look for a profitable
   cheat; if found, it becomes a design bug (fixed before submission).
4. **Reproducible artifact.** `research/l4/` simulator, seeded,
   pinned, one-command regen; every plot from simulation output only.
5. **Field-scale validation (mo 9+).** Deploy the scoring ledger as a
   public service fed by real L0 logs (early adopters); the paper's
   "in the wild" section.

---

## 8. Research sub-problems (expanded)

1. **Bounded proper scoring** — the efficiency gap of integer-bounded
   log-score (§3); novel result if the gap is bounded by a constant.
2. **Verified-event enrollment** — sybil barrier from time-and-score
   (no external stake); novel proof of the `Ω(φT)` bound.
3. **Dynamic κ-pricing** — recovery capacity as a congestion market
   with reputation as the currency; equilibrium analysis.
4. **Reputation-concentration pricing** — the *price* of letting one
   org near the ⅓ weight cap (systemic risk pricing; feeds L1's
   weight-cap and L5's risk statements).
5. **Free-rider detection asymmetry** — the cost of detecting "silent
   fork" (a witness must *prove* a negative); bounding the required
   verification budget (links to L2's `NONE_OF`).

---

## 9. Milestones and deliverables

| Milestone | Content | Artifact |
|---|---|---|
| M1 (mo 1–3) | Game model formalized; `U` specified and versioned; scoring ledger spec | model document + ledger reference impl |
| M2 (mo 4–6) | Simulator + honest/lazy/malicious/sybil types; equilibrium and sybil experiments | simulation + tables |
| M3 (mo 7–9) | Ablations + adversarial search + recovery mechanism | robustness report |
| M4 (mo 10–12) | Write-up + artifact freeze | paper draft (WEIS / PETS) |

**Related work (deep).** EigenTrust (Kamvar et al., 2003) — global
trust propagation; we adopt the bound, reject the need for a global
computation (local, event-driven). SybilGuard/SybilLimit (Yu et al.,
2006/2008) — sybil-resistance via social topology; we add *economic*
resistance via enrollment costs. Mechanism design (Nisan et al.;
Myerson) — the standard frame; proper scoring (Gneiting–Raftery, 2007)
— the alarm-score theory. Reputation systems (eBay-style) — the
naive baseline we improve on by *verification-only* updates. The
novelty: *a token-free, event-verified, provably-sybil-resistant
reputation mechanism purpose-built for a transparency network*.
