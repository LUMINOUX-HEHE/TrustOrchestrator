# 05 — L3: Federated Threat Intelligence

**Research problem:** L0 detects compromise *within one org* using that
org's watchdogs. The strongest attack signals are *cross-org* — the same
key fingerprint appearing in several orgs' logs, an anomaly signature
seen in five timelines, a dark-web key dump matching an org's cert — and
no single org can see them. L3 pools signals across orgs *without*
any org revealing its sensitive data, and returns *actionable, signed*
intelligence.

## 1. Why this layer exists

- **Weak per-org, strong pooled**: a suspicious pattern in one org is
  noise; the same pattern in 3 orgs is an incident. Only a network can
  see the difference.
- **Detection lag**: L0 reacts after damage. Pooled signals enable
  *proactive* rotation — the layer's signature capability.
- **The privacy wall**: orgs will not share raw timelines. Any pooling
  scheme must leak provably little (differential privacy) and share
  nothing raw (secure aggregation).

## 2. The research contribution (what is novel)

1. **DP federated detection for key compromise.** Cross-org anomaly
   detection where each org trains/contributes locally (federated
   learning), aggregates through secure aggregation (Bonawitz et al.),
   and the output carries a differential-privacy bound. Detection
   *quality vs. privacy budget* is a genuine measurement problem — there
   is no published benchmark for compromise detection under DP.
2. **The correlation registry.** A privacy-preserving key-fingerprint
   registry (built on L2's authorized predicates): orgs register
   fingerprints; the registry answers "which orgs have seen this key
   fingerprint" under authorization — enabling correlation without
   disclosure.
3. **Signed risk feeds with actionable orders.** L3 outputs are signed,
   versioned artifacts L0 can consume directly ("rotate key K in orgs
   {A, B} by T"); the *enforceability* of a recommendation across orgs
   is L1's problem, the *correctness* of the recommendation is L3's.
4. **Ground-truth dataset.** L0's simulator generates labeled compromise
   traces — the first public benchmark dataset for this problem class
   (a contribution in itself).

## 3. Related work (anchors)

- Federated learning: McMahan et al., 2017; secure aggregation:
  Bonawitz et al., 2017.
- Differential privacy: Dwork et al.; DP-SGD (Abadi et al., 2016);
  zCDP (Bun & Steinke).
- Cross-org threat sharing (industry): MISP, STIX/TAXII — *sharing raw
  IoCs*, no privacy guarantee; the research gap is principled pooling.
- Anomaly detection: CUSUM (already in L0) and its federated variants.
- Prio (Corrigan-Gibbons et al.) — verifiable privacy-preserving
  aggregation; a strong building block.

## 4. Concrete sub-problems

| # | Problem | Status | Our angle |
|---|---|---|---|
| L3.1 | Federated compromise detection with DP guarantee | open | define utility metric (detection lag / FPR) vs. ε; first benchmarks |
| L3.2 | Secure aggregation of anomaly scores | partial (Bonawitz) | adapt to streaming watchdog scores, not batch model updates |
| L3.3 | Authorized fingerprint correlation | open | compose L2's predicate registry with detection |
| L3.4 | Labeled compromise dataset from L0 simulator | new | public benchmark; enables all comparisons |
| L3.5 | Robustness to poisoned orgs | partial | an org feeding garbage must not move the aggregate (robust aggregation + reputation weight from L4) |

## 5. Interfaces

- **Down (consumes L0):** signed observations (alerts, STHs), L0's
  simulator (dataset), L2's authorized registry.
- **Up (serves):** signed risk feeds → L0 (proactive rotation orders),
  L4 (risk statistics for pricing), L1 (input to policy decisions).

## 6. Milestones (6-month units)

| Phase | Deliverable | Success criterion |
|---|---|---|
| M1 | Labeled dataset from L0 simulator + baseline per-org detection | reproducible numbers: detection lag, FPR |
| M2 | DP-federated detection prototype (simulated orgs) | pooled detection beats best single org at reasonable ε; privacy bound proven |
| M3 | Authorized correlation + risk-feed ingestion by L0 | end-to-end: cross-org pattern triggers proactive rotation |
| M4 | Paper + artifact | accepted at CCS / NDSS / IEEE S&P |

## 7. Risks

- DP utility cliff: pooling may not survive tight ε for rare events
  (mitigate: event-level DP for anomalies, not record-level; measure
  honestly).
- Poisoning: a malicious org can bias the pool (mitigate: robust
  aggregation + L4 reputation weighting — the layers are designed to
  compose).
- Adoption: orgs must run L3 clients (mitigate: it is a library + one
  API call; L0 seam already emits observations).

## 8. Validation strategy

- Public dataset + reproducibility kit (docker-compose of simulated
  orgs) — reviewers can regenerate every table.
- Ablation: detection quality vs. privacy budget; robustness under
  poison fraction; comparison against single-org (L0) baseline.
