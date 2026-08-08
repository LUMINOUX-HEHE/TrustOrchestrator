# 03 — L1 Cross-Org Consensus: Detailed Specification

L1 gives the network *shared decisions*: cross-org policies ("rotate on
alarm X"), federated recovery (rescue a compromised org), and the
legitimate authority to act on another org's behalf — with a signature
any verifier can check. The core invention is **weighted-quorum BFT**
(WQBFT): consensus where vote power is a *reputation weight vector*
owned by L4, not a fixed stake or raw node count. This document is the
normative L1 design: system model, protocol specification with
pseudocode, safety/liveness theorems, the federated recovery protocol,
reconfiguration, and evaluation plan.

---

## 1. Problem statement (formal)

**Informal.** A set of orgs `O = {o1..on}`, each with an L0 engine, wants
to agree on *decisions* `d` (policy actions, recovery anchors) that
apply to subsets of orgs, such that (a) any verifier can check the
decision's validity, (b) agreement is robust to faulty/bribed orgs up to
a weight bound, (c) agreement does not depend on any single operator,
and (d) the weight of each org reflects *verified* behavior (L4), not
self-assertion.

**Formal (partial-synchrony model).** Network is `GST`-stable after
unknown time; message delivery within `Δ` after GST; at most `f` orgs by
weight are Byzantine; weights `w: O → (0,1]`, `Σw = 1`. A decision `d`
is agreed iff a set `S ⊆ O` with `Σ_{o∈S} w(o) > 2/3` signed the
decision digest (weighted quorum). Safety: two valid decisions with the
same sequence number never differ (their quorums intersect). Liveness:
a valid proposal eventually commits if the leader is honest and
`w(leader) + w(honest quorum) > 2/3`.

**Research question.** PBFT-style consensus with heterogeneous
reputation weights: minimum weight threshold for safety under
(weighted) Byzantine faults; how liveness degrades as weight
concentration grows; how reweighting (L4 updates) is made safe without
pausing the protocol.

---

## 2. System model

- **Cluster.** One L1 validator *per org* in a trust cluster (≥ 3 orgs
  by design, up to ~50). Validators are separate processes, separate
  keys, possibly separate operators (deployment topology in `01 §6`).
- **Messages.** All L1 messages are signed with the validator's L1 key
  (distinct from L0 keys — compromise separation), over canonical JSON
  (envelope per `01 §3`).
- **Weight source.** `weights = L4.ReputationVector(epoch)` — a signed
  vector, versioned; L1 *freezes* the epoch weight on entry to a new
  decision round. Reweighting never happens mid-round (safety).
- **Failure modes.** Crash (≤ any number, handled by leader change),
  Byzantine (≤ ⅓ by weight for the safety bound below), silence
  (treated as crash).
- **Channels.** Pairwise authenticated, reliable-in-crash (replay
  buffers), ordered per sender (sequence numbers, no FIFO guarantees
  across senders).

---

## 3. Weighted quorum: formal definitions

- **Decision digest**: `dd = SHA-256(canonical(DECISION message))`.
- **Prepared quorum**: set of `PREPARE` messages with the same `(round,
  dd)` whose total weight `> 2/3`.
- **Committed quorum**: set of `COMMIT` messages with the same `(round,
  dd)` whose total weight `> 2/3`.

**Lemma 1 (quorum intersection).** Any two sets each with total weight
`> 2/3` intersect in weight `> 1/3`. Proof: if `Σw(S), Σw(T) > 2/3`
then `Σw(S∩T) ≥ Σw(S) + Σw(T) − Σw(S∪T) > 2/3 + 2/3 − 1 = 1/3`.

**Lemma 2 (safety).** If Byzantine weight `≤ 1/3`, no honest validator
commits `dd` at `(r, s)` while another commits `dd' ≠ dd` at `(r, s)`.
Proof sketch: both committed sets intersect in honest weight `> 1/3 −
f_w > 0` (Lemma 1), and honest validators never double-sign.

**Lemma 3 (liveness under honest leader).** If `w(leader) > 0` and
`w(honest) > 2/3`, the leader's proposal eventually gets a prepared
quorum and commits. Proof sketch: honest validators always PREPARE a
proposal they have not seen prepared before; leader resends; GST bounds
delivery.

**Contrast with standard PBFT.** PBFT requires `f < n/3` replicas
(unweighted). WQBFT generalizes: `Σ_{byz} w < 1/3`. With uniform
weights this is identical; with skewed weights, *one* high-reputation
org can be the single point of failure — the L4 price: reputation
concentration is priced (see `06 §4`), and L1 enforces a **weight
cap** (`w(o) ≤ 1/3 − ε`) so no single org reaches the Byzantine
threshold alone.

---

## 4. Protocol: WQBFT decision (normative)

One decision round = one sequence slot. Rounds have an epoch and a
leader (leader = org with highest weight among eligible, rotated
round-robin among the top-k to bound concentration).

```
ROUND start (epoch e, slot s, leader L):
  L:   dd = digest(proposal)
       send ⟨PRE-PREPARE, e, s, dd, proposal⟩ to all
  oi:  on PRE-PREPARE:  check dd, check weight epoch frozen
       if valid and not yet PREPAREd this slot:
         send ⟨PREPARE, e, s, dd⟩ to all
  oi:  on prepared-quorum (Σw > 2/3) of PREPARE for dd:
         send ⟨COMMIT, e, s, dd⟩ to all
  oi:  on committed-quorum of COMMIT for dd:
         APPLY(dd); broadcast ⟨DECISION, dd, cert=commits, epoch, weight-hash⟩
```

**View change (leader fault/silence):**

```
  oi:  on TIMEOUT(Δview) without commit:
         send ⟨VIEW-CHANGE, e, s, new_epoch, last_committed, prepared(dd)⟩
  L':  on view-change quorum (Σw > 2/3) at same new_epoch:
         propose dd* = latest prepared dd among the quorum (or new proposal)
         send ⟨PRE-PREPARE, e', s, dd*⟩ — other validators adopt dd*
```

**Correctness obligations (checked by every validator):**
1. Weight snapshot is the frozen epoch's, signed by L4.
2. `dd` covers proposal + epoch + slot.
3. A validator never sends two PREPAREs with different `dd` at the same
   `(e,s)`.
4. View-change adopts the *highest* prepared `dd` (no rollback).

---

## 5. Properties (theorems to prove — L5 targets)

- **T1 (Agreement).** Two honest validators never APPLY different
  `dd` at the same `(e,s)`. (Lemma 2 + obligation 3.)
- **T2 (Total order).** APPLY order is a sequence per cluster; every
  DECISION has a unique slot.
- **T3 (Validity).** Every committed `dd` was proposed by a leader with
  `w > 0` (no arbitrary injection) and is well-formed (schema-checked).
- **T4 (Termination).** Under GST + honest leader with `w(honest) >
  2/3`, every valid proposal eventually commits. (Lemma 3.)
- **T5 (Accountability).** Every committed DECISION carries a commit
  certificate (quorum of COMMIT signatures) verifiable by anyone — a
  decision is as auditable as an L0 event.

---

## 6. Federated recovery protocol (normative)

**Goal.** Org `a` is fully compromised (council keys lost/stolen) but its
history before the compromise is trusted. Neighbors `B ⊂ O \ {a}` with
`Σ_{o∈B} w(o) > 2/3` jointly issue a **recovery anchor** `RA` for `a`.

**Primitive: cross-org FROST.** FROST (threshold Schnorr) with a
round-optimized key setup, run *across* orgs: each `o ∈ B` holds a
share of the cluster's recovery key `K_rec`; any `t = 2/3 · |B|`
shares reconstruct signing. Rationale: no single org can issue a
recovery anchor; recovery is a *quorum action* exactly like a decision.

**Protocol:**
1. **Trigger.** L1 detects: `a`'s STHs stop extending for `Δ_rec`, or
   L2 witnesses a fork, or L4's reputation drop for `a` crosses a
   threshold.
2. **Freeze.** L1 emits `RECOVERY-FREEZE(a, fork_hash, ts)` — a DECISION
   with the same commit machinery as §4. All orgs stop trusting `a`'s
   keys effective `ts`.
3. **Anchor.** `B` runs FROST signing over `anchor = {a, freeze_ts,
   pre_compromise_root = last_STH(a) before freeze}`. The anchor is
   signed under `K_rec`.
4. **Delivery.** Anchor is delivered to `a`'s *restored* L0 via: (i) the
   witness-held backup copy of `a`'s log (public STH data), or (ii) an
   out-of-band channel (email, USB — bootstrapping is human-scale here).
5. **Accept.** `a`'s restored L0 verifies: `RA` valid under `K_rec`,
   `pre_compromise_root` is a prefix of its own log (consistency), and
   enacts `RECOVERY` observations + council re-setup (new council
   members, same root history). Every step is an L0 event.

**Safety.** `a` cannot be recovered to a *different* pre-compromise root:
the anchor binds the root hash; `a`'s verifier checks consistency
against it. A malicious `B` cannot anchor a false root without ⅔+ weight
by quorum. A compromised `a` cannot *choose* its new root: it must
extend the anchored root.

**Research content.** Weighted FROST parameter selection (share
distribution by weight, not count); recovery latency under partial
weight; the "what if `a`'s log is gone entirely" case (recover from
witnesses' STH history + neighbors' import records — a reconstruction
protocol).

---

## 7. Reconfiguration (normative)

- **Weight change** (L4 emits new vector): frozen at epoch boundaries;
  mid-round weights never change (obligation 1).
- **Membership change** (org joins/leaves): requires a DECISION with the
  *current* weights; the new member's first action is a reconfiguration
  epoch; the cluster's decision log is append-only, so membership
  history is auditable.
- **Genesis**: first cluster setup is human-coordinated (org operators
  exchange signed invite observations — L0 events), then a
  RE-CONFIGURE decision bootstraps weights (L4 genesis vector = uniform).

---

## 8. Interfaces

- **Down (to L0):** `DECISION` messages (policy: org set, rule, window)
  delivered as signed observations; L0 *gates* them through org-local
  policy (§7.4 of `01`).
- **Up (to L2/L3/L4):** committed decision log (append-only, signed
  certificates), recovery anchors, freeze/defreeze events.
- **To L5:** the protocol's messages are the proof target (T1–T5); the
  simulator below generates traces.

---

## 9. Evaluation plan

1. **Simulation (months 1–3).** Go simulator over random topologies:
   - Sweep `(f_w, weight skew, Δview, topology)`; measure
     commit latency, failure rate, view-change cost.
   - Compare against PBFT baseline (uniform weights) at equal
     Byzantine weight.
   - Halt-tests: inject fork attempts; assert quorum-intersection
     safety holds (violations = bug in harness, not protocol).
2. **Fault injection.** Crash/omission/duplicate/reorder at message
   level; a corrupted quorum certificate must fail verification.
3. **Reproducible artifact.** `research/l1/` simulation with seeded RNG,
   pinned dependency versions, and a script that regenerates every
   table and plot in the paper.
4. **Formal trace check (L5 later).** Export simulation traces as
   TLA+ `CC` (computation) runs and model-check safety/validity.

**Metrics:** commit latency (p50/p99) vs weight skew; safety-violation
count = 0 (mandatory); liveness time-to-commit under leader churn;
federated recovery end-to-end time (trigger → anchor → restore) with
per-phase breakdown.

---

## 10. Milestones and deliverables

| Milestone | Content | Artifact |
|---|---|---|
| M1 (mo 1–3) | WQBFT spec complete; simulator + PBFT baseline | simulation repo, tables |
| M2 (mo 4–6) | Safety/liveness proofs (L5-assisted); weight-cap analysis | theorem statements + sketches |
| M3 (mo 7–9) | Federated recovery protocol + FROST prototype | cross-org demo |
| M4 (mo 10–12) | Full cluster demo: 5 orgs, policy decision, rescue; write-up | paper draft (DSN/USENIX ATC/SRDS) |

**Related work (deep).** PBFT (Castro–Liskov, 1999) — the base; HotStuff
(Yin et al., 2019) — linear view-change and pipelining, our view-change
is HotStuff-style; Tendermint — validator-weighted voting is *the*
production precedent for weight-based quorums (we differ: weights are
reputation-driven and time-varying, and we do not use stake); DAG-Rider
(Keidar et al., 2021) — DAG-based async consensus as a later extension
(could replace the view-change path for asynchrony); Algorand (Gilad et
al., 2017) — weight-proportional selection of proposers, adopted for
our leader rotation; FROST (Komlo–Goldberg, 2020) — threshold Schnorr
for recovery anchors. None of these combine *reputation-weighted
quorums with verifiable recovery*; that is the novelty.
