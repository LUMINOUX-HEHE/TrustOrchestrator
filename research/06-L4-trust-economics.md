# 06 — L4: Trust Economics

**Research problem:** cryptography makes lying *detectable*; it does not
make honesty *rational*. A corrupted gateway operator can still rewrite
history, abscond, or freeload on the witness network — until someone
checks. L4 asks the economic questions: what incentive structure makes
honest behavior the dominant strategy for every participant (gateways,
witnesses, aggregators, insurers), how is reputation measured and defended
against sybil attacks, and how does trust become *priced*?

## 1. Why this layer exists

- **The witness network is a public good** — everyone benefits, nobody
  pays, so it may not be run at all. L4 must make witnessing
  individually rational.
- **Reputation drives the whole stack's decisions** (L1 quorum weights,
  L3 pooling trust, L2 registry authorization) — if reputation is
  gameable, the layers above inherit the weakness.
- **The market gap**: insurers, auditors, and suppliers need a *price*
  for key-hygiene risk; only a network-wide, verifiable record can
  produce one. L4 turns L0–L3's cryptographic facts into economic facts.

## 2. The research contribution (what is novel)

1. **Incentive analysis of public witness networks.** Formal
   game-theoretic model of a CT-style witness network: costs of
   witnessing, detection payoff, the equilibria, and which scoring rules
   (proper scoring rules) make honest reporting dominant. No published
   analysis exists for enterprise CT-style witness networks.
2. **Sybil-resistant reputation for PKI participants.** EigenTrust-style
   iterative trust with (a) identity costs grounded in L0's cryptographic
   anchors (a sybil must hold real keys and pass real verifications) and
   (b) reputation weight flowing into L1's quorums — closing the loop
   between economics and consensus.
3. **Key-hygiene risk pricing.** From L3's DP statistics, a public,
   reproducible risk score per org (decay curves, rotation discipline,
   response speed to alarms) — designed so that *gaming the score*
   requires *real security improvements* (the score is strategy-proof by
   construction).
4. **Mechanism design for federated recovery.** When can a coalition of
   orgs be trusted to rescue a member (conditions under which the
   rescuing coalition is *better off* rescuing than letting the member
   fail)?

## 3. Related work (anchors)

- EigenTrust (Kamvar et al., 2003); PageRank lineage — trust
  propagation with sybil concerns.
- Sybil defenses: SybilGuard/SybilLimit (Yu et al.), social-graph
  approaches; proof-of-work/stake alternatives.
- Mechanism design (Nisan et al., "Algorithmic Game Theory");
  proper scoring rules (Gneiting & Raftery).
- Economics of information security: Anderson & Moore; WEIS community
  (this is the natural home for the papers).
- CT ecosystem incentives: Vaudenay's analyses of CT transparency
  flaws (gossip-failure attacks) — the closest literature.

## 4. Concrete sub-problems

| # | Problem | Status | Our angle |
|---|---|---|---|
| L4.1 | Witness-network incentive model | open | formal equilibria; minimal subsidy to sustain N witnesses |
| L4.2 | Strategy-proof key-hygiene score | open | score = f(verifiable facts only); gaming requires real improvement |
| L4.3 | Sybil-resistance grounded in cryptographic anchors | partial | identity cost via L0 keys + verifications, not tokens |
| L4.4 | Reputation → L1 quorum weight (closed loop) | open | stability of consensus under reputation feedback |
| L4.5 | Token-free economics | deliberate | registry works without a coin; tokens deferred (documented) |

## 5. Interfaces

- **Down (consumes):** L3 risk statistics, L2 verifiable claims, L0
  observations (response times, alarm handling).
- **Up (serves):** reputation weights → L1 (quorum weights), L3
  (pooling trust, poison resistance); risk prices → insurers, auditors,
  suppliers (L5-verified outputs make the prices auditable).

## 6. Milestones (6-month units)

| Phase | Deliverable | Success criterion |
|---|---|---|
| M1 | Witness-network game model + equilibrium analysis | theorems + simulation validation (n witnesses, attack scenarios) |
| M2 | Key-hygiene score definition + L0-observation mapping | score is strategy-proof; reproduce from L0 logs |
| M3 | Reputation graph prototype (EigenTrust + anchor costs) + sybil evaluation | sybil cost > benefit under stated assumptions |
| M4 | Papers + artifact | accepted at WEIS / PETS / game-theory-security venues |

## 7. Risks

- Game-theoretic models are only as good as their assumptions —
  validate every result in simulation before claiming it (mitigate:
  L0's simulator provides empirical ground truth).
- A reputation system that punishes new orgs chills adoption
  (mitigate: cold-start rules; reputation = capability, not seniority).
- The score must be robust to orgs *hiding* (withdrawing from
  observation) — hiding must itself lower trust.

## 8. Validation strategy

- Simulation: run L0's compromise scenarios under the incentive model;
  verify that rational agents (defined by the model) produce the
  predicted behaviors.
- Case study: price the DigiCert-2025-style incident under the model —
  does the score predict the actual market cost of slow response?
