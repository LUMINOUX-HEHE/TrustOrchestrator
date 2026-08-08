# 04 — L2: Private Transparency

**Research problem:** certificate transparency is public by design — and
that is a feature for public CAs and a liability for enterprises. An
org's CT log reveals *which* events happened and *when* (issuance volume,
revocation patterns, key rotation timing — a real business-intelligence
leak). L2 asks: can an org get all the guarantees of an RFC 9162 log
(append-only, verifiable, witnessed) while proving facts about it
*without revealing which facts*?

## 1. Why this layer exists

L0 already proves history integrity via RFC 9162 logs. But:

- **Leakage**: every event hash is public; an org's activity pattern is
  extractable. Enterprises will not deploy a log that exposes their
  issuance schedule.
- **Witness dependence**: today, detection of a rewrite requires a
  witness watching; with private proofs, any *verifier* can check any
  claim offline.
- **The gap**: CT research (RFC 9162 and its predecessors) never solved
  privacy for the *enterprise* case; the "private CT" problem is open.

## 2. The research contribution (what is novel)

1. **Private membership proofs.** Given a committed log, prove "leaf with
   hash *h* is in the tree at size *n*" *without revealing the leaf's
   position or the sibling path*. This is a zero-knowledge proof of a
   Merkle inclusion statement — the natural next step after CT.
2. **Selective disclosure for revocation.** Prove "certificate *c* was
   revoked" to a specific party without revealing *which* other
   certificates were revoked, or the revocation volume.
3. **Encrypted-key registry.** Key fingerprints stored so that queries
   succeed only under authorized predicates (org-to-org authorization,
   or proof of key knowledge). Powers L3 correlation without leaking the
   key space.
4. **Privacy-preserving alarms.** The witness network can publish "org X
   rewrote history" — an alarm reveals X's failure, which is *intended*;
   the open sub-problem is alarms that reveal a *pattern* (e.g. "some
   org in cluster C") without identifying which.

## 3. Related work (anchors)

- Certificate Transparency (Laurie et al., RFC 6962/9162) — the substrate.
- Zero-knowledge proofs: zk-SNARKs/STARKs (Groth16, Plonk, StarkWare);
  zk-COP (Shinagawa et al.) — zero-knowledge "chain of proofs" (closest
  existing idea, not applied to enterprise CT).
- Merkle Mountain Ranges (Todd) — append-only structure that makes
  proofs compact and updatable; used by CAs/Tor.
- RSA / bilinear accumulators (Camenisch-Lysyanskaya; Nguyen) — compact
  membership without revealing structure.
- Prio (Corrigan-Gibbons et al.) — privacy-preserving aggregation (also
  relevant to L3); Blind Seer (Fisch et al.) — private database queries.
- Encrypted search: SSE (song-wagner-perrig), ORE.

## 4. Concrete sub-problems

| # | Problem | Status | Our angle |
|---|---|---|---|
| L2.1 | ZK inclusion proof for RFC 9162 trees | partial (zk-COP) | concrete efficient circuit for the exact RFC 9162 tree shape, benchmarked against real L0 logs |
| L2.2 | Private revocation claims | open | "revoked" proofs that leak neither identity nor volume |
| L2.3 | Authorization-gated key registry | partial (SSE) | predicate that includes *proof of key possession* |
| L2.4 | Cluster-level alarms | open | alarms about groups that don't identify members |

## 5. Interfaces

- **Down (consumes L0):** the RFC 9162 log (tree shape, STHs) — L2 does
  not change L0; it wraps it. This is the cheapest research layer: the
  substrate already exists.
- **Up (serves):** verified-but-anonymous observations to L3; public
  alarm streams to the witness network; verifiable claims to L4 (e.g.
  "org X can prove compliance without showing its schedule").

## 6. Milestones (6-month units)

| Phase | Deliverable | Success criterion |
|---|---|---|
| M1 | ZK inclusion proof prototype against L0 logs | membership proof verifies in seconds, hides position+siblings; benchmark vs. plain inclusion |
| M2 | Private revocation + authorized key registry | end-to-end demo: auditor verifies a private claim |
| M3 | Witness-network alarms (public + cluster-level) | rewrite detection still works with privacy turned on |
| M4 | Paper + artifact | accepted at CCS / USENIX Security / PoPETs |

## 7. Risks

- ZK circuit engineering is the real cost (mitigate: start with
  existing frameworks — gnark, circom — and a tiny circuit: RFC 9162
  trees have a simple shape).
- Performance: private verification must be fast enough for audit
  tooling (seconds, not minutes).
- Threat of *traffic analysis*: hiding membership is weaker than hiding
  existence — L2 must state its privacy model honestly (it hides *which*,
  not *that*).

## 8. Validation strategy

- Correctness: every private proof's public counterpart verifies; the
  soundness of the circuit is machine-checked (ties into L5).
- Empirical: benchmark against L0's actual logs (real event volumes).
- Privacy: define and measure the leak (entropy of revealed metadata)
  vs. baseline public log.
