# 04 — L2 Private Transparency: Detailed Specification

L2 is the strongest first paper and the privacy heart of the program.
Today, L0 logs are public-by-design: an STH commits to leaf hashes, but
the leaf *contents* are hashed timeline events (`LeafHash(entry)` where
`entry = SHA-256(event)`). The plain event list is still needed for
audit. L2 makes audit **selective**: prove facts about a log *without*
revealing the underlying events — inclusion, prefix-extension, and
aggregate properties, with machine-checkable proofs that reveal
provably-bounded information. This document is the normative L2 design:
privacy definitions (formal), the proof system, protocols with
pseudocode, security analysis, performance budget, and evaluation plan.

---

## 1. Problem statement (formal)

**Informal.** An org's log must remain auditable by anyone (L0
guarantee) while individual entries remain private. A verifier must be
able to ask: "does this log contain an entry with property P?" and get
a *proof* that answers without learning which entry, when, or any other
entry. Additionally, membership in the log itself may be sensitive:
"is this organization enrolled in the witness network?"

**Formal (simulation-based, defined per property).** Let `L` be a log,
`F: entries → {0,1}` a predicate. A proof system `(Prove, Verify)` is
**F-private** if for all verifier strategies `V*` (possibly colluding
with the prover's counter-party), there exists a simulator `S` that, on
input `F(L)` and public data, produces `V*`'s view of `Prove(L)` that
is computationally indistinguishable from the real view. That is:
**the verifier learns nothing beyond `F(L)` and public metadata**
(log size, STH signatures, proof structure).

**Deferred generality.** Full zero-knowledge (ZK-SNARK) for arbitrary
predicates is the target; the MVP is a *non-interactive argument of
knowledge* for a fixed predicate set (inclusion, prefix, none-of,
count-of) with a transparency-compatible setup.

---

## 2. The log model under privacy

- **Public:** `STH = {tree_size, timestamp, root}`; leaf hashes
  (`LeafHash`) are public (they are the Merkle tree).
- **Private:** the events themselves; the mapping leaf-hash → event.
- **Trust boundary:** the prover (org's gateway) knows all events; the
  verifier (anyone, including other orgs, auditors, regulators) knows
  only public data + whatever the proof reveals.
- **Compatibility constraint:** nothing in L0 changes. Proofs are
  *over* the existing `LeafHash` tree — the seam (`01 §2`) defines this
  as a "claims layer" over L0 logs. This is critical: L2 upgrades L0
  without touching L0.

---

## 3. Proof system design (normative)

### 3.1 The circuit: RFC 9162 inclusion as an arithmetic circuit

A ZK proof of inclusion must show, in-circuit:

```
input:  leaf_hash, idx, size, root, path_nodes[]
compute: h = leaf_hash
        for k in 0..depth(size)-1:
            sibling = path_nodes[k]
            if bit_k(idx) == 0: h = H(0x01, h, sibling)
            else:               h = H(0x01, sibling, h)
        assert h == root
```

where `H` is SHA-256 (or the RFC 9162 domain-separated hashing above).
Circuit size: `O(depth × ~12k constraints)` per SHA-256 instance;
realistic tree sizes (depth ≤ 24, i.e., 16M entries) → tens of
thousands of constraints; SNARK proof ≤ a few hundred KB, verification
in milliseconds. **Research content:** a *constant-sized* circuit that
checks the whole path without expanding the tree — standard technique
(path is witness, hash chain is computation); the engineering novelty
is proving inclusion **against the live STH** (root is the public
input, so proofs are instantly invalid if the log rewrites).

### 3.2 Predicate set (v1)

| Predicate | Proof | Leaks |
|---|---|---|
| `INCLUDE(leaf_hash)` | ZK inclusion (§3.1) | nothing beyond "this hash is in the log at size s" |
| `EXTENDS(s1, s2)` | ZK consistency (RFC 9162 §2.1.4.2 as circuit) | nothing beyond "tree s2 extends s1" |
| `NONE_OF(P, s)` | ZK range/bound: no leaf in `[0,s)` satisfies P | nothing beyond P-absence |
| `COUNT_OF(P, s) ∈ [lo, hi]` | ZK count proof | only the range |
| `SIGNED_UNDER(K, artifact)` | ZK Schnorr/EdDSA under a *witnessed* key | nothing beyond "K signed it" |

`NONE_OF` and `COUNT_OF` require *all* leaves to be scanned in-circuit —
O(s) constraints; bounded to `s ≤ 2^20` for v1 with a documented
perf/cost trade-off.

### 3.3 Commitment and opening

Events are committed via `C = LeafHash(entry)` (public) and the event
opens via `Open(C) = entry` (private, only the org). For queries that
must *reveal* a matching entry (e.g., regulator with a court order),
we add **conditional disclosure**: the org reveals the event
alongside a proof that `Hash(event) == C` and that `C` is included.
The verifier re-runs the plain inclusion check; no ZK needed for the
disclosure path.

---

## 4. Protocols (normative)

### 4.1 Witness queries

```
org:      Witness → ⟨CLAIM, org, predicate, params, proof, log_size, root⟩
witness:  verify proof against current STH (sig, size, root)
          → publish signed verdict observation (public, timestamped)
```

The witness's *verdict* is itself an L0 observation → the audit trail
extends to L2: "who claimed what about whose log, when, was it
accepted".

### 4.2 Authorized key-registry predicates

From the seam's fingerprint registry (`01 §2.2`), queries of the form
"is fingerprint `fp` present in the registry?" must not reveal other
entries. Design: registry is itself an append-only Merkle structure
over signed fingerprints; membership proofs are the same circuit
family. **Authorized queries** (a regulatory subpoena) use
conditional disclosure (§3.3).

### 4.3 Privacy-preserving alarms

L0's split-brain/inconsistency alarms are public (they must be — that
is their purpose). But **cross-org correlation must not leak which
alarms correlate**: L2 provides a *private set intersection with
proofs*: two orgs learn `|A ∩ B|` (count only) over alarm sets,
sufficient for L3's correlation without revealing the sets. v1: use
the commitment scheme above with O(n²) pairwise proofs; research
target: O(n log n) with a Merkle-accumulator-based PSI.

---

## 5. Security analysis (normative)

- **Soundness.** A proof accepting an inclusion that is not in the log
  violates SHA-256 collision resistance and the STH signature. Formal:
  the circuit's assertion `h == root` plus public `root = signed STH
  root` (if the STH is inconsistent with the tree, verification fails —
  the verifier checks `VerifyConsistency(STH_old, STH_new)` first).
- **Zero-knowledge.** Defined per predicate (§1); the ZK layer is
  the *only* place the privacy guarantee lives — all other components
  (signatures, hashes) are assumed non-revealing but not privacy-
  certified.
- **Malicious prover.** A prover cannot claim membership of a hash not
  in the log (soundness); cannot claim `NONE_OF` when a match exists
  (soundness of the scan); cannot roll back the log (STH monotonicity +
  witness history).
- **Malicious verifier.** A verifier cannot extract entries from
  proofs (zero-knowledge); cannot distinguish two logs with the same
  public footprint (indistinguishability up to the predicate).
- **Side channels (honest list).** Proof *sizes* vary with tree size
  (public); timing of proof issuance may correlate with events (rate
  limiter); the existence of a proof for `fp` reveals that a query
  happened (acceptable: queries are logged by the witness).

---

## 6. Performance budget (targets, reproducible in benchmark)

| Operation | v1 target | Technique |
|---|---|---|
| Prove inclusion (depth 24) | ≤ 2 s, ~100 MB witness | in-circuit SHA-256, batched proofs |
| Verify inclusion | ≤ 50 ms | SNARK (Gro16) / STARK fallback |
| Witness query end-to-end | ≤ 5 s | single-round protocol |
| Registry membership | ≤ 1 s prove / 20 ms verify | same circuit |
| PSI (n = 1000 alarms) | ≤ 1 min | commitment + pairwise (v1) |

**Crypto choices.** v1: Groth16 over BN254 (fastest verify, trusted
setup per circuit) with a transparent-upgrade path (PLONK/Halo2) for
the "setup-free" narrative; STARK (open, no setup, larger proofs) as
the fallback if trusted setup is rejected by reviewers. Implementation
library: the Rust `arkworks` ecosystem via FFI, or pure-Go SNARK
(engineering risk — keep the circuit spec library-agnostic).

---

## 7. Evaluation plan

1. **Correctness harness.** Random logs (sizes 1..2^20), random
   inclusion indices: prove → verify → assert pass; tampered roots
   and tampered paths → assert fail. (This mirrors the plain-proof
   harness already in `ctlog_test.go`.)
2. **Privacy test (simulation-based).** Implement the simulator for
   `INCLUDE`: given only `F(L)`, produce a view indistinguishable from
   the real proof transcript; run a distinguisher over transcript
   pairs and assert it fails. (This is the *experimental* check; the
   theoretical argument is in the paper.)
3. **Benchmark matrix.** Prove/verify latency and proof size across
   (tree size, circuit choice, machine class). Regenerate tables from
   pinned commits.
4. **Adversarial prover/verifier fuzzing** on the circuit and the
   witness protocol (v1: hypothesis-based; later: property-based with
   proptest/quickcheck).
5. **Reproducible artifact.** `research/l2/` with the circuit source,
   generator, harness, and one-command regen script.

---

## 8. Research sub-problems (expanded)

1. **Circuit for RFC 9162 consistency (§2.1.4.2)** — the old-root-
   prepend case makes the circuit asymmetric; wrong handling
   silently breaks prefix proofs. (Bug class: the exact bug class
   already caught in plain Go — `InclusionProof` out-of-range.)
2. **Batch proofs** — one SNARK over k inclusions (k-SET inclusion) to
   amortize proving cost for witness audits.
3. **Accumulator-based registry** — a *dynamic* accumulator
   (additions over time, no trusted setup; e.g., KZG-based or
   RSA-based) replacing the Merkle registry so that membership proofs
   are constant-sized. Research: adversarial batch-update security.
4. **Private PSI with logarithmic complexity** — Merkle-accumulator
   PSI; security under concurrent re-execution.
5. **Threshold-prover privacy** — a *council-threshold* prover: proof
   generation requires t-of-n orgs to *collaborate* (FROST-style
   circuit proving) so a single compromised gateway cannot emit claims
   about its own log. (Novelty: threshold *computation*, not threshold
   *signing*.)
6. **Predicate language** — a small declarative DSL over events
   compiled to circuits, so regulators can express policy
   ("no expired root keys at size s") without writing circuits.

---

## 9. Milestones and deliverables

| Milestone | Content | Artifact |
|---|---|---|
| M1 (mo 1–3) | Circuit spec + correct prove/verify for `INCLUDE`, `EXTENDS`; harness green | circuit + harness + benchmarks |
| M2 (mo 4–5) | `NONE_OF`/`COUNT_OF` (bounded), witness protocol, registry predicates | witness demo: 3 orgs |
| M3 (mo 6–7) | Simulator-based privacy tests; performance paper-ready tables | evaluation artifact |
| M4 (mo 8–9) | Conditional disclosure + subpoena flow; PSI v1 | end-to-end demo |
| M5 (mo 10–12) | Write-up + artifact freeze | paper draft (CCS / USENIX Security / PoPETs) |

**Related work (deep).** zk-COP (Wust et al., 2021) — ZK for *cross-org*
*attestation*; we extend to *per-log audit predicates* with witnesses
as verifiers, not just attesters. RFC 9162 itself — the plain verifier
we lift to zero-knowledge (the 9162 circuits are the *same* verifier,
in-circuit). MMRs (Todd) — used for the accumulator path. Accumulators
(RSA: Camenisch–Lysyanskaya 2002; KZG: Kate et al. 2010; practical:
Papamanthou et al.) — registry design. Prio (Corrigan-Gibbs–Bonawitz
2017) — count-of-honest aggregation is the statistical cousin of our
`COUNT_OF` predicate (L3 uses Prio-style aggregation; see `05 §4`).
SSE / predicate encryption — the authorized-query design space.
Naturally, none of these combine *auditable witnesses over RFC 9162
logs with simulation-defined predicate privacy*; that is the novelty.
