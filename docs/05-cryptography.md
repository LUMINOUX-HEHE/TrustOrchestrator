# 05 — Cryptography

What this system uses and — critically — what is **real** vs what is
**simulated**.

## Real (implemented, stdlib, tested)

| Primitive | Use | Verified by |
|---|---|---|
| **Ed25519** signatures | every trust event, bootstrap cert, workload cert | `TestChainAppendVerify`, `TestVerifyRejectsTampering` |
| **SHA-256** | Merkle chain + hash path for `Timeline.Hash()` | `TestFoldDeterministic` |
| **FROST (3-of-5, two-round)** | council threshold-signs the epoch handoff; the root key never exists | `TestEpochCommitValidity`, `TestFrostSelfCheck` |
| **TLS 1.3 mutual** | watchdog↔orchestrator & identity consumer wire | `TestMutualTLSRequest`, `TestWireRealSockets` |
| **X.509** | workload cert CA (`IssueWorkloadCert`) | `TestIdentityIssueAndVerify` |

All built on **Go stdlib only** — `crypto/ed25519`, `crypto/sha256`,
`crypto/tls`, `crypto/x509`, `crypto/rand`. No third-party crypto
(nothing in `go.mod` beyond stdlib). That is itself the NFR4.2 compliance.

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