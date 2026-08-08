# 05 — Cryptography

What this system uses and — critically — what is **real** vs what is
**simulated**.

> Hash agility landed (upgrade layer 1): dual-mode links
> SHA-256 ‖ SHA3-256, backwards compatible. See "Hash agility" below.
>
> Signatures landing (upgrade layer 2): hybrid PQ key agreement
> X25519 ‖ ML-KEM-768 on the council wire, AES-256-GCM sealed frames.
> See "Post-quantum (upgrade layer 2)" below.

## Real (implemented, stdlib, tested)

| Primitive | Use | Verified by |
|---|---|---|
| **Ed25519** signatures | every trust event, bootstrap cert, workload cert | `TestChainAppendVerify`, `TestVerifyRejectsTampering` |
| **SHA-256 / SHA3-256** | chain links (`Timeline.Hash` legacy; dual `SHA-256 ‖ SHA3-256` in `hash.go`) — hash agility | `TestDualTimelineRoundtrip`, `TestDualTimelineTamper`, `TestFoldDeterministic` |
| **FROST (3-of-5, two-round)** | council threshold-signs the epoch handoff; the root key never exists | `TestEpochCommitValidity`, `TestFrostSelfCheck` |
| **TLS 1.3 mutual** | watchdog↔orchestrator & identity consumer wire | `TestMutualTLSRequest`, `TestWireRealSockets` |
| **X.509** | workload cert CA (`IssueWorkloadCert`) | `TestIdentityIssueAndVerify` |
| **Hybrid X25519 ‖ ML-KEM-768** | council wire session keys (PQ sealed frames) | `TestPQHybridChannel`, `TestNetworkedRecovery` |

All built on **Go stdlib only** — `crypto/ed25519`, `crypto/sha256`,
`crypto/sha3` (Go 1.24+), `crypto/mlkem` (FIPS 203, Go 1.24+),
`crypto/ecdh`, `crypto/hkdf`, `crypto/tls`, `crypto/x509`, `crypto/rand`.
No third-party crypto (nothing in `go.mod` beyond stdlib). That is itself
the NFR4.2 compliance.

## FIPS posture (disclosure)

This codebase is **not** a FIPS 140-2/140-3 validated module and does not
claim to be: none of its crypto carries CAVP certificates, and Go's
`crypto/internal/fips140` (Go 1.24) is internal, not an app surface. What
does hold: every primitive is FIPS-adjacent and stdlib-only — Ed25519
(SP 800-186), SHA-256 / SHA3-256 (FIPS 180-4 / FIPS 202), AES-256-GCM
(FIPS 197 / SP 800-38D), HKDF (SP 800-56C / SP 800-108), TLS 1.3
(SP 800-52r2), ML-KEM-768 (FIPS 203), X.509 (SP 800-57). The library calls
only `crypto/*` — never `crypto/internal/*` — so running it under a
FIPS-validated Go runtime (the BoringCrypto or FIPS-enabled module builds)
swaps the underlying module with no application change.

## Post-quantum (upgrade layer 2, landed)

The council wire runs a per-connection hybrid handshake on top of mTLS:

1. Initiator sends `PQ_HELLO {X25519 pub ‖ ML-KEM-768 encapsulation key}`.
2. Member (if PQ-capable) answers with its own hybrid public half **plus
   an ML-KEM ciphertext**; the initiator decapsulates; both derive
   `HKDF-SHA256(X25519(ECDH) ‖ ML-KEM(shared), info="trust-orchestrator/hybrid-v1")`.
3. Every `VOTE` / `COMMIT_REQ` frame and its response is then
   **AES-256-GCM sealed** under that session key (`pq.go`). Legacy members
   that do not answer `PQ_HELLO` are served plaintext — but RemoteRecover
   always starts with the PQ offer, so the sealed path is the default and
   the downgrade lane only exists for old binaries.

Property: even if a quantum computer later breaks the X25519 half,
ML-KEM-768 (FIPS 203, IND-CCA2, no known Shor attack) protects recorded
traffic — the harvest-now-decrypt-later attack is dead. This is "hybrid
PQ on the wire", not a replacement of the chain signature.

**ML-DSA (FIPS 204) dual signatures are NOT yet in Go's public stdlib**
(`crypto/internal/fips140/mldsa` is internal). The `Sigs` envelope
(`pq.go`) reserves an `mldsa` slot so the chain/frame wire format needs
no change when `crypto/mldsa` goes public; until then every signature is
still Ed25519 and the slot stays empty. Design remains: dual-sign while
Ed25519 is still safe, verified both-or-nothing in `Sigs.Verify`.

## Hash agility (upgrade layer 1, landed)

Links are hashed under a per-timeline algorithm, stamped as `hash_algo` in
the persisted file:

- `""` (legacy) — SHA-256, byte-identical to the pre-agility wire format;
  old dumps and mirrors load unchanged
- `"dual"` — SHA-256 ‖ SHA3-256 (64-byte links); a link is trusted only if
  BOTH digests hold, so a single future collision in one primitive cannot
  rewrite trust history alone

`Timeline.Hash()` (the canonical 32-byte event hash the API shows and forks
checkpoint on) is unchanged in both modes: agility moved the link, not the
event identity. Auditors mirror via `NewAuditorLog(algo)`, the fleet's
integrity watchdog uses the timeline's own digest, so dual chains verify
everywhere. Upgrade path on top: FIPS-205/L1 anchoring is designed but not
implemented (needs an external chain anchor).

## At-rest key hierarchy (vault, landed)

`vault.go` replaces the v1 shared gateway.key with an envelope:
`KEK (council-held) → DEK → per-tenant+epoch HKDF subkey → per-file dk →
payload`. Key properties:

- **Threshold-as-KMS**: the KEK is `ShamirSplit` 3-of-5 (`to-tool vaultkek`);
  it exists in memory only during an unwrap session (`JoinKEK` + `zeroBytes`),
  never on disk. The gateway boots with `-kek-shares <3 files>`; vault-sealed
  tenants are deferred — unreadable — until the shares arrive.
- **Rotation without re-encryption**: `POST /v1/rotate` (or `RotateVault`)
  mints a new DEK + epoch and re-wraps only the 60-byte dk box per tenant;
  payload ciphertext is copied. A stolen pre-rotation DEK opens nothing
  written after (epoch check + HKDF info string), so a leaked file dies at
  the next rotation.
- KMS drop-in: a KMS `WrapKey`/`UnwrapKey` replaces the Shamir session with
  the same wire format — the DEK never changes shape.
- Never: TPM/SGX sealing, Walnut tunnels — hardware, out of scope (see
  `09-limitations.md`).

## Detector math (not cryptographic, but phrased here)

- **CUSUM** monitoring: `S = max(0, S + obs − (mu0+delta))`, alarm when `S > h`.
  Params come from `reports/params.json` (calibrated), never hard-coded —
  FR2.5.
- **Quorum fusion**: `DETECTED = #{low scores} ≥ 3` with n=5 (Byzantine
  assumption f=1, n≥3f+1).

## FROST properties we rely on

- FROST: the seed's public key IS the group key — shares sign exactly what
  the seed would sign (`FrostSplit`), so threshold recovery is verifiable
  against a public anchor the gateway holds.
- Key split into 5 shares, threshold 3 → any 3 sign, any 1–2 gives nothing
  (verified by wrong/too-few share tests); after a ceremony the root never
  exists, and `zeroize()` clears working state (memory-only step, FR3.3 —
  semantic, not a hardware enclave).

## Mutual TLS detail

`mtls.go`:
- server + client both load the identity CA into a pool and require the other
  side's cert to chain to it (`RequireAndVerifyClientCert`)
- **min version TLS 1.3** only
- after handshake, `VerifyPeerIdentity` also checks the CommonName — defense
  in depth over the chain.

## What is simulated (crypto does NOT claim)

| Claim | Real? | Where reality sits |
|---|---|---|
| p-value in `Score` is 0.01 flat on alarm | **placeholder** | real distribution-fit is calibration work |
| hardware (SGX/TPM) protected key reconstruction | no | `zeroize()` in memory only |
| real network the transport | loopback sockets only | 2-machine delta in deploy/ |

Full list: `09-limitations.md`.