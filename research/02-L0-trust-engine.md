# 02 — L0: The Trust Engine (this repository)

**Status: implemented and tested (116 tests, TLA+ P1–P6, zero third-party
dependencies).** This document describes L0 as the *component* that the
upper layers consume — what it provides, its trust model, and the honest
limits the upper layers exist to fix.

## 1. What L0 is

A self-hosted PKI trust-management engine: it detects its own compromise,
recovers via a majority-vote cryptographic council (FROST threshold
signing, 3-of-5), rolls back to a verified checkpoint re-issuing only the
damaged identities, and exposes every org's history as an RFC 9162
transparency log that any third party can audit without trusting the
gateway.

## 2. Components (all real, all tested)

| Component | File(s) | Guarantee |
|---|---|---|
| Signed event timeline | `timeline.go` | append-only, parent-chained, Ed25519-signed; forks verified; dual-hash agility (SHA-256 ‖ SHA3-256) |
| Threshold council | `frost.go`, `dkg.go`, `council.go`, `blindfrost.go` | the root key never exists; ≥3/5 threshold signs epoch handoffs; blind FROST unlinkability |
| Detection ensemble | `watchdogs.go`, `detect.go`, `ensemble.go`, `fleet.go` | 5 detector types; DETECTED iff ≥3/5 below calibrated threshold; one compromised watchdog can neither trigger nor block |
| Scoped rollback | `rollback.go`, `graph.go` | refold to verified checkpoint; invalidation set = reachable damaged identities only |
| Transparency log | `ctlog.go` | RFC 9162 Merkle tree over event hashes; signed tree heads; inclusion (§2.1.3.2) and consistency (§2.1.4.2) proofs; gossip observer with split-brain alarm |
| Envelope vault | `vault.go` | KEK (council-held, 3-of-5 Shamir) → DEK → per-tenant HKDF subkey → AES-GCM; per-epoch rotation kills old DEKs |
| Management plane | `api.go`, `store.go`, `auth.go`, `webhooks.go`, `ratelimit.go`, `compliance.go` | REST, RBAC, multi-tenancy, durable outbox, token-bucket rate limiting, compliance reports (ISO 27001/SOC 2/PCI DSS/HIPAA/GDPR) |
| Formal model | `specs/*.tla` | P1–P6 invariants, model-checked, mutation-tested |

## 3. The guarantees L0 gives (and who can check them)

| Guarantee | Checkable by | How |
|---|---|---|
| History was not rewritten | anyone | RFC 9162 proofs against signed STHs; a rewrite fails inclusion or forks the root |
| A revoked cert never comes back | anyone with the log | P3 invariant + CT log |
| Recovery required the council | anyone with the anchor | FROST signature over the handoff verifies against the public group key |
| The gateway never had the root key | auditor (code review) | key split 3-of-5, zeroized after ceremonies |
| Detection needs no single watchdog | auditor | quorum logic + TLA P2 |

## 4. Trust model

L0 trusts: its own timeline key, its council anchor, and (within an org)
its own fleet. It trusts *no other org* and *no external party*. This is
deliberate: it makes L0 safe to deploy as the foundation — the upper
layers never need L0 to trust them.

## 5. The seam L0 exposes upward

These are the exact interfaces the upper layers consume (the "L0 seam",
specified in `01-system-architecture.md` §3):

1. **REST API** (`/v1/orgs/{org}/...`) — timeline, state, STH, proofs,
   gossip, recovery. Auth: bearer tokens with RBAC + org scoping.
2. **Signed observations** — STHs (`/ct/sth`), event hashes, alerts —
   each attributable to a key.
3. **SDKs** — Go (`Client`), Python, Java.
4. **The library itself** — `VerifyInclusion`, `VerifyConsistency`,
   `GossipNode`, `Timeline.Verify` are public, importable, and pure.

**Not yet part of the seam (needed by L2/L3/L4):**
- a cross-org key-fingerprint registry (currently per-org cert hashes)
- signed *alerts* as first-class events (alarms exist but are not yet
  emitted as signed, queryable observations)
- trust-edge metadata export (who imports whose certs)

These are small API additions, not architecture changes — the timeline is
already the right substrate for all three.

## 6. Honest limits (the reasons the upper layers exist)

| Limit | Consequence | Fixed by |
|---|---|---|
| Single-witness gossip | a rewrite could go un-noticed if the only watcher is down | L2 witness network |
| Log reveals which events exist and when | org activity leaks to log readers | L2 private membership proofs |
| Detection is per-org | a cross-org pattern (same key used in 3 orgs) is invisible | L3 pooled intelligence |
| No cross-org agreement | orgs cannot coordinate shared policy or federated recovery | L1 consensus |
| No incentives | nothing makes a *gateway operator* prefer honesty when corrupted | L4 economics |
| Safety proven per invariant, not composed | the *stack* is not proven correct | L5 verification |

## 7. Evaluation baseline for upper layers

L0's simulator and benchmark are the measurement substrate for the whole
program: `bench.go` scenarios (S1–S7) generate compromise events; the
watchdog ensemble and rollback math provide ground truth; the CT log
provides the verifiable record. L3's papers will use L0's simulator as
the dataset generator; L4's game theory will be validated against
L0's gossip behavior; L5's properties will be checked against the
existing TLA+ models.

## 8. Reference

- `README.md`, `docs/00`–`11` — full documentation
- `specs/` — TLA+ models and mutation tests
- `reports/` — benchmark, calibration, kill tests, compliance, SBOM
