# 01 — TrustFabric: Full System Architecture (Detailed Specification)

This document is the normative system specification for the TrustFabric
program: layers, components, interfaces (message formats, signatures,
state machines), data flows, trust model, deployment topology, failure
semantics, and the seam contract that every layer builds on. It is the
design rulebook; each layer's spec (`02`–`07`) is the detailed design.

---

## 1. Design rules

1. **The gateway is a trust domain.** One org = one gateway = one signed
   timeline = one RFC 9162 log = one council anchor. State that must be
   *trusted* lives inside the domain; everything else is *verifiable*
   data.
2. **The timeline is the source of truth.** Every fact the upper layers
   consume must be derivable from signed, queryable observations. No
   layer may invent facts; layers may only *combine, decide, and price*
   facts that verify.
3. **Signatures, not API trust.** A layer believes a message iff its
   signature verifies against a key it knows. Transport security is
   assumed (mTLS), but never the *authority* of a peer.
4. **Privacy is a property, not a feature.** From L2 upward, layers must
   provably leak bounded information. "We don't share raw data" is not a
   guarantee; a DP bound or a ZK proof is.
5. **Fail closed.** If a layer is unavailable, the layers above degrade
   to the layer below: a network with no intelligence is still a working
   engine. No upper-layer dependency may be load-bearing for L0 safety.
6. **Reproducibility.** Every layer ships an artifact that regenerates
   its own evidence (dataset, simulation, proofs) from a pinned commit.

---

## 2. The L0 seam — the normative contract

The upper layers' power is bounded by what L0 emits. This seam is a
**contract**: L0 implements it, layers consume it. It has three parts.

### 2.1 Signed observations (exist today, extended)

Every observation is a signed JSON object with a canonical encoding
(lexicographic key order, fixed field set), Ed25519-signed with the
emitting org's observation key (distinct from the timeline key so a
compromised timeline key does not forge observations, and vice versa).

```json
{
  "obs_type":    "STH | ALERT | ROTATION | RECOVERY | SCORE",
  "org":         "acme",
  "ts":          1750000000,
  "seq":         42,
  "subject":     "https://acme.example/v1/orgs/acme/ct/sth",
  "payload_b64": "<canonical obs bytes>",
  "sig":         "<ed25519 over canonical(obs_type, org, ts, seq, subject, payload)>"
}
```

| Type | Payload fields | Consumed by |
|---|---|---|
| `STH` | tree_size, root, timestamp, log_key | L2 witnesses, L3 correlation, L4 response-time |
| `ALERT` | alarm text, evidence refs (event hashes, STH) | L1 policy decisions, L3 pooling, L4 scoring |
| `ROTATION` | key fingerprint(s), old/new key IDs, cause | L3 correlation, L4 discipline score |
| `RECOVERY` | fork hash, council signature over handoff | L1 federated recovery, L4 response |
| `SCORE` | aggregated org-level health (no raw data) | L3, L4 |

**Canonicalization rule:** `canonical(obj)` = JSON with sorted keys,
no whitespace, fixed field order per type. The signature is over the
canonical bytes; verification is `ed25519.Verify(pub, canonical, sig)`.
This is the same convention L0's timeline already uses (`TrustEvent`).

### 2.2 Cross-org key fingerprint registry (new, small)

A namespace where fingerprints are anchored to orgs and times:

```
fingerprint = SHA-256(cert_hash ‖ first-seen-org ‖ ts)
```

Registered by any org on first observation; entries are signed
observations themselves (so the registry is only an index — the facts
are the signatures). Fields: `fp`, `orgs[]` (org IDs that have seen it),
`first_seen`, `last_seen`, `alarm_count`. **Privacy**: the raw registry
is the public index; authorized predicate queries come from L2.

### 2.3 Trust-edge metadata (new, small)

Export of `graph.go`'s scoped reachability as signed artifacts: "org A
imports/trusts keys of org B" edges, versioned and signed. Format:

```json
{
  "edge_type": "IMPORTS | ISSUES_FOR | WITNESSES",
  "from_org": "acme", "to_org": "globex",
  "subject_key_fp": "<fp>", "since_ts": 1750000000, "revoked_ts": 0,
  "sig": "..."
}
```

Consumed by: L1 (shared policy scope — only edge-connected orgs are
affected by a policy), L4 (reputation propagation — trust flows along
edges), L3 (correlation — patterns across connected orgs weight higher).

---

## 3. Message formats between layers

All inter-layer messages use one envelope (`signed`, canonical JSON,
Ed25519). Layer-specific payloads:

| Message | From → To | Payload | Signature keyed by |
|---|---|---|---|
| `OBS` (observation) | L0 → L1/L2/L3/L4 | one signed observation (§2.1) | org observation key |
| `DECISION` | L1 → L0 | policy id, rule, scope (org set), validity window | L1 quorum aggregate key |
| `CLAIM` | L2 → anyone | private or public claim + proof | log key (public part) / prover key |
| `RISK_FEED` | L3 → L0 | per-org risk vector, recommended actions, confidence | L3 aggregate key (keyed by L4-certified set) |
| `REPUTATION_UPDATE` | L4 → L1/L3 | per-org reputation weights, versioned | L4 key |
| `VERIFIED_PROPERTY` | L5 → anyone | machine-checked statement + proof artifact hash | L5 checker key |

### Envelope

```
{ "layer": "L1", "msg_type": "DECISION", "body": <canonical JSON>,
  "sig": "<ed25519>", "cert_refs": ["<hash of certifying observations>"] }
```

Every message carries `cert_refs` — the hashes of the observations that
justify it — so a verifier can re-derive the decision from the signed
record. This makes every layer's output *accountable* (the L5 property
"no output without attributable input").

---

## 4. Data flows (normative sequence)

### 4.1 Steady state (per org, per epoch)

```
L0 Timeline events → (signed) → L0 CT log (leaves = event hashes)
L0 STH (every append batch, signed) → L2 witness nodes → L4 timestamps
L0 SCORE observations (per cycle) → L3 secure aggregation → L4 stats
L4 → L3: reputation weights (periodic)
L3 → L0: signed RISK_FEED (recommendations only; L0 decides)
L1: no traffic unless a decision is pending
```

### 4.2 Cross-org incident (the money path)

1. Org A's watchdogs DETECTED ≥3/5 → `ALERT` observation (L0).
2. L3 sees `ALERT` + correlation: fingerprint `fp` appears in B's log
   (`STH`/`ROTATION` observations from B, authorized query via L2).
3. L3 emits `RISK_FEED`: "rotate `fp`-related keys in {A, B}; confidence
   0.87; evidence refs = [A's ALERT, B's observation]".
4. B's L0 applies the feed *if* it verifies and *if* org-level policy
   allows proactive rotation (policy is an L0 decision; L1 makes the
   *shared* policy, never per-org ones).
5. L2 witnesses publish alarm(s) if either org's STH history is
   inconsistent — public record for L4 scoring and L5 audit.

### 4.3 Federated recovery (org A fully compromised)

1. L1 detects A's silence/forks (A's STHs stop extending, or a fork is
   witnessed by L2).
2. L1 convenes a *rescue ceremony*: neighbors B/C/D (≥ threshold by
   L4 weight) jointly produce a recovery anchor for A via cross-org
   FROST (protocol in `03-L1.md §6`).
3. B/C/D ship the anchor through A's *witness-held* backup or a
   secondary channel; A's restored L0 verifies the anchor against the
   L1 aggregate key.
4. L4 records response times; L5 verifies post-conditions.

---

## 5. Trust model per layer

| Layer | Trusts (and only this) | Explicitly does NOT trust |
|---|---|---|
| L0 | own council anchor; own timeline/observation keys | any other org, any external party |
| L1 | ≥ ⅔ of *reputation weight* among validators (by L4) | any single org; raw node counts |
| L2 | the mathematics (proof system soundness, accumulator binding) | log operators — that is the point |
| L3 | DP guarantee on aggregates; signatures on observations | any org's raw data; any individual org |
| L4 | the public update rule (auditable, versioned) | any org's self-report |
| L5 | the checker (small, public) | everything else |

Note the deliberate asymmetry: trust only ever flows *upward* from
signatures, and authority only ever flows *downward* as signed
recommendations that the lower layer's own policy gates. No layer can
force another; every layer can be audited by L5.

---

## 6. Deployment topology

```
┌────────────────────────  PUBLIC PLANE (independent operators)  ──────────┐
│  L2 witness nodes          L3 aggregation nodes        L4 registry       │
│  (poll STHs, verify)       (secure aggregation, DP)    (reputation, pricing) │
└───────────────▲───────────────────────▲───────────────────────▲──────────┘
                │ signed obs / proofs  │ risk feeds / stats     │ weights
┌───────────────┴───────────────────────┴───────────────────────┴──────────┐
│  L1 VALIDATOR CLUSTER (per trust cluster; ≥3 independent operators)      │
└───────────────▲──────────────────────────────────────────────────────────┘
                │ decisions (policy, federated recovery)
┌───────────────┴──────────────────────────────────────────────────────────┐
│  L0 PER-ORG GATEWAYS (one per org; container + disk + keys)              │
└───────────────────────────────────────────────────────────────────────────┘

L5: a public, offline-capable proof checker — no deployment, just a binary.
```

- L1 validators can be co-located with gateways but must be *separate
  processes with separate keys*.
- No operator is indispensable: witnesses, validators, and aggregators
  are all replaceable by any party implementing the signature checks.

---

## 7. State machines (normative)

### 7.1 L1 validator (per org)

```
states: IDLE → PROPOSE (leader) / VOTE / COMMIT / RECONFIGURE
transitions:
  IDLE + decision request     → PROPOSE (if leader) else VOTE
  VOTE + ≥⅔ weight PREPAREs  → COMMIT (append decision)
  COMMIT + quorum COMMITs     → APPLY (broadcast signed DECISION) → IDLE
  any + weight-change signal  → RECONFIGURE (freeze epoch, reweight, resume)
safety: no two decision digests at same sequence ≠ (by quorum intersection)
```

### 7.2 L2 witness

```
poll STH(org) → verify sig → verify against previous (consistency proof)
  OK     → store; publish signed observation; notify L4
  FAIL   → publish public ALARM (split-brain / non-extension)
query(memberproof request) → verify ZK or plain proof → answer
```

### 7.3 L3 aggregator

```
collect SCOREs (per epoch) → secure aggregation → DP-noise → aggregate
  → cross-org correlation (authorized fp queries) → RISK_FEED (signed)
  → publish to subscribing orgs + L4
```

### 7.4 L0 proactive-rotation gate

```
receive RISK_FEED → verify signature + cert_refs → policy check (org-local)
  → if allowed: schedule ROTATION observations per org policy → execute
  → always: audit-trail the feed decision (signed ALERT)
```

---

## 8. Failure semantics (normative)

| Failure | Detection | Degradation | Recovery |
|---|---|---|---|
| L0 gateway down | health probe / STH stale | org read-only; witnesses flag staleness | restart; timeline replay |
| L1 cluster down | decision timeout | no shared policy; per-org ops continue | quorum restart (logs durable) |
| L1 fork (safety violation) | L5 property / witnesses | **halt** (halt > wrong) | manual reconfiguration epoch |
| L2 witness down | no public alarms from it | other witnesses cover | replace (stateless) |
| L3 down | feed timeout | L0 per-org detection only | restart (stateless) |
| L4 down | weight staleness | L1 uses last-certified weights | restart |
| L5 absent | — | everything still runs; nothing machine-checked | run checker |

Degradation rule (from §1.5): every layer degrades to its *predecessor*,
never to nothing.

---

## 9. Security boundaries (enumerated)

1. **Crypto**: every message Ed25519-signed; PQ transition via the
   existing dual-signature envelope (`Sigs` in L0's `pq.go`).
2. **Key separation**: timeline key ≠ observation key ≠ log key ≠ L1
   validator key — compromise of one does not forge another's messages.
3. **Privacy**: L2 proofs and L3 DP bounds are the enforcement; a public
   operator learns only aggregates.
4. **Economics**: L4's rules are public; reputation changes only via
   verifiable events.
5. **Verification**: L5 checker is the single trusted component — small,
   public, open-source (seL4 principle).

---

## 10. Out of scope (normative)

- L0: hardware enclaves, real cross-host networks (documented in
  `docs/09-limitations.md`).
- L1: fully asynchronous BFT in production (research target).
- L2: hiding *that* a log exists (only *which* entries).
- L3: detection from encrypted traffic content.
- L4: tokens/coins (deliberately deferred).
- L5: one-shot verification of the whole stack (composition only).
