# 00 — Executive Summary: TrustFabric

> **TrustFabric** (working name) is a research program: a multi-layer system
> for *verifiable collective trust* — trust infrastructure where every
> decision is cryptographically verifiable, made collectively (no single
> point of failure), resilient to active adversaries, and observable at
> network scale. Layer 0 of this program already exists and is this
> repository (`trustorchestrator`). Layers 1–5 are research programs, each
> with a publishable problem, each building on the layer below.

## The thesis in one paragraph

Certificate and key compromise is a live, expensive, recurring problem
(DigiCert's mass revocation 2025; the NIST key leak affecting years of
issued certificates). Existing products either *issue* certificates (CAs),
*store* secrets (vaults), or *inventory* them (discovery tools) — none of
them *decide what to do after a compromise, without a single trusted
machine*, and none of them are *publicly auditable*. TrustFabric is the
missing substrate: an engine that detects compromise, recovers via a
threshold-signing council (the root key never exists), rolls back with
provable blast radius, and exposes every org's history as an RFC 9162
transparency log. On top of that engine, five research layers generalize
it from *one org* to *a network of orgs*.

## The stack

```
L5  FORMAL VERIFICATION        compositional proof of the whole stack
L4  TRUST ECONOMICS            incentives, reputation, sybil resistance
L3  THREAT INTELLIGENCE        pooled, privacy-preserving compromise detection
L2  PRIVATE TRANSPARENCY       privacy-preserving membership proofs
L1  CROSS-ORG CONSENSUS        agreement across heterogeneous trust domains
L0  TRUST ENGINE (this repo)   timelines, FROST council, detection, CT log
```

## What each layer adds (capability, not aggregation)

| Layer | New capability | Single org cannot |
|---|---|---|
| L0 | signed timeline, threshold recovery, detection, transparency log | — |
| L1 | agreement across orgs: shared policy, federated recovery coordination | reach consensus with other orgs |
| L2 | prove history facts *without revealing them* | hide what it does while staying auditable |
| L3 | detect compromise *before* the org knows (cross-org correlation) | see weak signals pooled across orgs |
| L4 | make honesty the rational choice (incentives, reputation, pricing) | force others to be honest |
| L5 | prove the whole system correct, composed | prove itself alone is enough |

## Why now

1. **Compromise is a market event**: mass-revocation incidents are regular
   and expensive; the decision layer is unoccupied.
2. **The crypto is ready**: FROST, DKG, PQ hybrid (X25519 ‖ ML-KEM-768) are
   all already implemented and tested in L0.
3. **The transparency precedent is set**: CT (RFC 9162) proved that
   publicly auditable logs change behavior; enterprise PKI has no
   equivalent.
4. **The combination is absent from the literature**: privacy-preserving
   CT for enterprises, DP-fed compromise detection, incentive analysis of
   witness networks — each is an open problem, and their combination does
   not exist.

## What is real today (L0)

Every cryptographic claim in L0 is implemented and tested (116 tests,
TLA+ models, zero third-party dependencies): Ed25519, SHA-256/SHA3-256
hash agility, FROST 3-of-5 threshold signatures, DKG, hybrid PQ wire,
AES-GCM vault with council-held KEK, watchdog ensemble detection, RFC 9162
Merkle logs with inclusion/consistency proofs and gossip. The deployment
layer (real multi-host networks, hardware enclaves) is documented but
simulated — that is the honest boundary of L0.

## The sequencing truth

- **L2 (private transparency) is the strongest first paper** — the field
  is hot, the problem is open, and L0 already provides a working CT log
  to extend.
- **L4 (trust economics) is the fastest second** — game theory needs no
  new crypto, only the witness-network model L0 already implements.
- **L3 (threat intelligence) third** — needs a dataset; L0's simulator is
  the dataset generator.
- **L1 and L5 last** — hardest; they build on the credibility of the
  first three.

See `08-research-roadmap.md` for the full plan; `01-system-architecture.md`
for the system design; `02`–`07` for each layer in detail.
