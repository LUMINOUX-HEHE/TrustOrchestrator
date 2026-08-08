# 01 — TrustFabric: Full System Architecture

This document specifies the system of systems: components per layer, the
data flows between layers, the interfaces each layer exposes, and the
trust model. Everything above L0 is a *stateless consumer* of the layer
below unless stated otherwise — the design rule that keeps the stack
composable.

## 1. Design rules

1. **The gateway is a trust domain.** One org, one gateway, one signed
   timeline, one CT log, one council anchor. All state that must be
   trusted lives inside the domain; everything else is verifiable data.
2. **The timeline is the source of truth.** Every fact the upper layers
   consume must be derivable from signed, queryable observations.
3. **Layers communicate through signatures, not API trust.** A layer
   believes a message iff its signature verifies against a key it knows —
   never because a peer "said so".
4. **Privacy is a first-class property, not an afterthought.** From L2 up,
   the system must work without revealing what it protects.
5. **Fail closed.** If any layer is unavailable, the layers above degrade
   to the layer below (a network with no intelligence is still a
   working engine).

## 2. Layer inventory

### L0 — Trust Engine (this repository, real today)

| Component | Role |
|---|---|
| `Timeline` | per-org signed, hash-chained event ledger (issue/revoke/recover) |
| FROST council + DKG | threshold signing (3-of-5); the root key never exists |
| Watchdog ensemble | 5 detectors, ≥3/5 quorum DETECTED |
| `Rollback` | refold to verified checkpoint, scoped invalidation set |
| RFC 9162 CT log | per-org Merkle tree over event hashes; STH, inclusion/consistency proofs, gossip |
| Vault | AES-GCM envelope; council-held KEK, per-epoch rotation |
| Gateway | REST API, RBAC, multi-tenancy, webhooks, rate limiting, compliance reports |
| TLA+ specs | P1–P6 invariants model-checked |

### L1 — Cross-Org Consensus (research)

| Component | Role |
|---|---|
| Trust-domain weight function | maps org → quorum weight (static or reputation-derived) |
| BFT protocol engine | PBFT-style / DAG-based SMR with weighted quorums |
| Shared-policy store | cross-org policies replicated by consensus (e.g. "if org X is detected, all dependents rotate") |
| Federated recovery coordinator | multi-org threshold signing session to rescue a compromised member |

### L2 — Private Transparency (research)

| Component | Role |
|---|---|
| Private membership proofs | zero-knowledge proofs that a leaf is in the log without revealing which |
| Accumulator / MMR layer | compact, updatable commitment to the log for offline verification |
| Encrypted-key registry | key fingerprints searchable only under authorized predicates |
| Witness network | public watchers verifying STHs; privacy-preserving alarm publication |

### L3 — Threat Intelligence (research)

| Component | Role |
|---|---|
| Secure aggregation | cross-org signal pooling (Bonawitz-style) without raw-data sharing |
| DP anomaly engine | federated, differentially private detection models |
| Correlation registry | cross-org key fingerprints / anomaly signatures |
| Intelligence API | signed risk feeds consumed by L0 (proactive rotation) and L4 (pricing) |

### L4 — Trust Economics (research)

| Component | Role |
|---|---|
| Reputation graph | weighted trust graph over orgs (EigenTrust-style with sybil resistance) |
| Witness incentive model | game-theoretic analysis; scoring rules for honest witnesses |
| Risk/insurance pricing | price key-hygiene risk from L3 feeds |
| Market registry | canonical list of orgs, keys, and their verified status |

### L5 — Formal Verification (research)

| Component | Role |
|---|---|
| Compositional framework | layer-by-layer refinement; invariants per layer composed upward |
| Spec ↔ code refinement | machine-checked correspondence for the safety-critical core |
| Property library | P1–P6 extended: consensus safety, transparency soundness, privacy |

## 3. The L0 seam — primitives the upper layers depend on

Upper-layer power is bounded by what L0 emits. These three primitives are
the contract; L0 already provides most of them, the rest are small API
additions:

| Primitive | Current status in L0 | Needed for |
|---|---|---|
| **Signed observations** — every alert, STH, rotation, and recovery is an Ed25519-signed event | STHs and timeline events signed; alerts partially | L3 correlation (inputs must be attributable) |
| **Cross-org key fingerprints** — a canonical registry mapping cert hashes / key IDs to orgs and timestamps | cert hashes exist per-org; no cross-org registry | L2/L3 correlation, L4 pricing |
| **Trust-edge metadata** — who relies on whose keys (imported certs, cross-org issuance) | `graph.go` scoped reachability per org | L1 shared policy, L4 reputation |

## 4. Data flows

```
             L4 ECONOMICS                     L5 VERIFICATION
          (pricing, reputation)              (proofs of everything)
                 ↑      ↓                          ↑
             risk feeds                        properties
                 ↓      ↑                          ↓
             L3 INTELLIGENCE ←←←→ L2 PRIVATE TRANSPARENCY
         (pooled, DP-anonymized)      (witnesses, private proofs)
                 ↑      ↓                      ↑     ↓
          alerts/proactive                 STHs,  membership
          rotation orders                  proofs, alarms
                 ↓      ↑                      ↓     ↑
             L1 CONSENSUS ←—— federated recovery, shared policy ——→
                 ↓      ↑
        observations, agreed state
                 ↓      ↑
             L0 TRUST ENGINE (per org: timeline, council, detectors, CT log)
```

1. **L0 → L1**: signed observations (alerts, STHs, rotation events).
2. **L1 → L0**: agreed decisions (shared policy, federated recovery orders).
3. **L0 → L2**: STHs, log leaves (public part), key fingerprints.
4. **L2 → L3**: verified-but-anonymized observations; witnesses' alarms.
5. **L3 → L0**: proactive rotation recommendations (signed risk feed).
6. **L3 → L4**: aggregate risk statistics (DP-bounded).
7. **L4 → L3**: reputation weights (feed the correlation trust model).
8. **L5 → all**: machine-checked properties; every other layer is a client.

## 5. Trust model per layer

| Layer | Trusts | Does not trust |
|---|---|---|
| L0 | its own council anchor, its timeline key | other orgs |
| L1 | threshold of weighted validators (e.g. ≥⅔ of *reputation weight*) | any single org |
| L2 | the transparency math (ZK proofs, accumulators) | the log operators (that's the point) |
| L3 | DP guarantee on aggregated outputs | any individual org's raw data |
| L4 | the reputation update rule (public, auditable) | any org's self-report |
| L5 | only the proof checker | everything else |

## 6. Deployment topology

- **Per org**: one gateway (L0) — container, one disk, one key.
- **Per cluster of orgs**: 1–n L1 validator nodes (could be co-located
  with gateways).
- **Public plane**: witness nodes (L2), aggregation nodes (L3) — operated
  by independent parties; no single operator holds power.
- **Verification plane**: L5 proof checker is public and offline-capable.

The trust rules make operators interchangeable: any component can be
replaced by another party's implementation as long as signatures verify.

## 7. Failure modes and degradation

| Failure | Behavior | Degrades to |
|---|---|---|
| L3/L4 down | risk feeds stop; no proactive rotation | L0 still detects/recover/audits |
| L1 down | no cross-org decisions; federated recovery unavailable | per-org recovery via own council |
| L2 witness down | no public alarm publication | private verification still possible |
| L0 gateway down | org cannot issue; history intact on disk | read-only verification via backups |
| Consensus forks | L1 safety violation → L5 property catches, quorum halts | halt > wrong |

## 8. Security boundaries

- **Crypto**: every inter-layer message carries an Ed25519 (later PQ
  dual) signature. No layer trusts another's transport.
- **Privacy**: L2/L3 boundaries are enforced by proofs and DP — an
  operator of the public plane learns nothing beyond the aggregate.
- **Economic**: L4's rules are public and verifiable — reputation cannot
  be bought except by honest behavior (by construction).
- **Verification**: L5's checker is the only truly trusted component, and
  it is small, public, and open-source — the seL4/IronFleet principle.

## 9. What is deliberately NOT in scope (per layer)

- L0: real multi-host networks, hardware enclaves (documented limitations)
- L1: byzantine agreement under *total* asynchrony in production (research
  target, not default)
- L2: fully hiding the log's existence (only hiding *which* entries)
- L3: detection from encrypted traffic content (only key/identity signals)
- L4: tokens/coins (a registry can be honest without a token; tokens are a
  later option)
- L5: verifying the full stack end-to-end in one shot (composition only)
