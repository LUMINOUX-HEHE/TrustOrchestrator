# 03 — L1: Cross-Org Consensus

**Research problem:** agreement across heterogeneous trust domains — a
network of orgs (each running its own L0 gateway, council, and timeline)
must reach consensus on shared facts (policies, federation decisions,
federated-recovery orders) without any single org holding veto power, and
where validators have *different amounts of trust* (reputation, size,
history).

## 1. Why this layer exists

L0 is single-org by design (one gateway = one trust domain). The moment
two orgs need to agree on anything — "org X is compromised, all
dependents rotate", "this policy applies network-wide", "org A's council
is dead, B/C/D jointly sign its recovery" — we need Byzantine agreement
*whose validators are orgs, not machines*. Off-the-shelf BFT assumes
identical validator weight. Real trust domains are not identical: a
bank's gateway should weigh more than a startup's. Weighting by
reputation is itself a feedback loop with L4.

## 2. The research contribution (what is novel)

1. **Weighted-quorum BFT over a trust graph.** Extend partially
   synchronous SMR (PBFT/HotStuff lineage) so quorums are measured in
   *reputation weight* rather than node count, with weight derived from
   L4's reputation graph. Correctness: safety/liveness proofs must carry
   through weight change.
2. **Composition with L0's own safety.** An L1 decision that touches an
   org (e.g. federated recovery) must be *enforceable by that org's L0*
   — a consensus output that the gateway's council hasn't threshold-signed
   is a recommendation, not an order. The composition question: what is
   the two-phase protocol (consensus + per-org council sign) and where
   are its failure modes?
3. **Federated recovery as a primitive.** Rescue a fully compromised org:
   neighboring councils jointly produce a recovery anchor for it. This is
   threshold signing *across* organizations — the protocol, the trust
   conditions (who may witness), and the sybil conditions are open.

## 3. Related work (anchors)

- PBFT (Castro & Liskov, 1999); HotStuff (Yin et al., 2019); Tendermint
  (Buchman et al., 2018) — partially synchronous BFT SMR.
- DAG-based: DAG-Rider (Kelec et al., 2021), Narwhal/Bullshark —
  asynchronous alternatives.
- Weighted voting: Algorand (pure PoS) — *weight* exists but is stake,
  not earned trust; the trust-graph weighting is our difference.
- FROST (Komlo & Goldberg, 2020) — the per-org threshold primitive we
  compose with (already in L0).
- Quorum systems research (Malkhi & Reiter) — general framework.

## 4. Concrete sub-problems

| # | Problem | Status in literature | Our angle |
|---|---|---|---|
| L1.1 | Weighted-quorum BFT with changing weights | partial (stake-based only) | trust-derived weights, provable safety under reweighting |
| L1.2 | Two-phase "consensus then council-sign" decision commit | open | guarantees per-org enforceability, minimal latency |
| L1.3 | Cross-org threshold recovery | open | who may witness; sybil conditions; recovery anchor format |
| L1.4 | Shared policy language + replication | engineering | policies as signed, versioned, consensus-replicated artifacts |

## 5. Interfaces

- **Down (consumes L0):** signed observations (alerts, STHs) as decision
  inputs; per-org council signatures to *enforce* decisions.
- **Up (serves):** agreed, signed decisions → L3 (posture changes), L4
  (reputation events like "org X failed to respond"), L2 (witnessed
  federation facts).

## 6. Milestones (6-month units)

| Phase | Deliverable | Success criterion |
|---|---|---|
| M1 | Weighted-quorum SMR spec + simulator | safety/liveness holds in TLA+/simulation with weight churn |
| M2 | Reference implementation over L0 SDKs (2–5 orgs) | live cross-org policy replication demo |
| M3 | Federated-recovery protocol + adversarial evaluation | recovery of a "fully compromised" org with 2/3 honest neighbors |
| M4 | Paper + artifact | accepted at DSN / USENIX ATC / SRDS |

## 7. Risks

- Weighted quorums are subtle: weight updates mid-epoch can break safety
  proofs (mitigate: weight epochs + explicit reconfiguration rounds).
- Performance of multi-org SMR at PKI latency expectations (mitigate:
  co-locate validators with gateways; batched decision digests).
- Trust-graph weighting depends on L4 reputation — L1 must define a
  minimal static-weight bootstrap so it is not blocked by L4.

## 8. Validation strategy

- TLA+ model of weighted consensus (extends existing `specs/` practice).
- Adversarial test: any subset of orgs below quorum weight can neither
  block nor fake decisions (mirrors P2's watchdog logic at org scale).
- Reproducible artifact: docker-compose of N gateways + validators.
