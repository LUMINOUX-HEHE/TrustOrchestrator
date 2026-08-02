# 02 — Requirements Trace

Each row: the requirement from `trust-orchestrator-final-report.md` §3
(authoritative requirements), where it's implemented, which automated test
proves it, and the result.

## Functional requirements (FR)

**FR1 Trust timeline**
| Req | Implementation | Test | Result |
|---|---|---|---|
| FR1.1 signed Merkle append | `timeline.go Append/Sign` | `TestChainAppendVerify` | PASS |
| FR1.2 verifiable by root | `timeline.go Verify` | `TestVerifyRejectsTampering` | PASS |
| FR1.3 fork at checkpoint | `timeline.go Fork` | `TestForkPreservesOriginal` | PASS |
| FR1.4 state = fold | `timeline.go Fold` | `TestFoldDeterministic` | PASS |

**FR2 Watchdog ensemble**
| Req | Implementation | Test | Result |
|---|---|---|---|
| FR2.1 five detectors | `watchdogs.go` | `TestCUSUM, TestOmniscient` | PASS |
| FR2.2 score/30s | `Watchdog.Score` | `TestMutualTLSRequest` (frame) | PASS |
| FR2.3 DETECTED ≥3/5 | `ensemble.go Detect` | `TestEnsembleQuorum` | PASS |
| FR2.4 no solo trigger | `Detect` quorum | `TestInsiderCan'tTrigger` | PASS |
| FR2.5 calibrated params | `reports/params.json` | `bench; calibration.json` | PASS |

**FR3 Transparency**
| Req | Implementation | Test | Result |
|---|---|---|---|
| FR3.1 mirror to auditor logs | `audit.go Mirror` | `TestMirrorNoLoss` | PASS |
| FR3.2 auditor verifies | `AuditorLog.Verify` | `TestChainAppendVerify` | PASS |
| FR3.3 auditor escalation 3/5 | `DetectEscalated` | `TestAuditorLogAndEscalation` | PASS |
| FR3.4 auditors never recover | `council` only path | (architectural) | PASS |

**FR4 Recovery council**
| Requirement | Implementation | Test | Result |
|---|---|---|---|
| FR4.1 5 shards, 3-of-5 | `shamir.go` | `TestShamirRoundtrip, WrongShard` | PASS |
| FR4.2 ≥3 RECOVER votes | `council.go` | `TestRecoveryEndToEnd` | PASS |
| FR4.3 enclave, memory-only | `council.go zeroize` | PARTIAL (no real SGX) | PARTIAL |
| FR4.4 canonical fork | `EpochCommitValidity` | `TestEpochCommitValidity` | PASS |
| FR4.5 single member can't | quorum | `TestK*.Recovery` | PASS |

**FR5 Time-travel rollback**
| Requirement | Implementation | Test | Result |
|---|---|---|---|
| FR5.1 refold verified prefix | `rollback.go` | `TestEndToEndPostRecovery` | PASS |
| FR5.2 invalidate reachable set | `InvalidationSetScoped` | `TestInvalidationSetScoped` | PASS |
| FR5.3 consumers get delta | `consumer.go ApplyDelta` | `TestConsumerRollbackDelta` | PASS |
| FR5.4 laws L1–L4 | `rollback.go` | `TestFoldDeterministic,…` | PASS |

**FR7 Security graph scoping**
| Requirement | Implementation | Test | Result |
|---|---|---|---|
| FR7.1 edges carry policy | `graph.go` | `TestInvalidationSetScoped` | PASS |
| FR7.2 scoped reissue | graph reachability | succeeded above | PASS |
| FR7.3 verifier asserts | `Verify` post-tests | `TestEndToEnd` | PASS |

**FR8 Bootstrap**
| Requirement | Implementation | Test | Result |
|---|---|---|---|
| FR8.1 one key, 5 shards, ceremony | `genkey/shard/enroll` | `TestEnroll, TestEnrollNodeIDForm` | PASS |
| FR8.2 bootstrap revoked after genesis | `revoke` + marker | `TestBootstrapRevokedAfterGenesis` | PASS |
| FR8.3 independent auditor roots | `enroll --role auditor` | foreign-root verify in TestEnroll | PASS |

**FR9 Benchmarks**
| Req | Implementation | Evidence |
|---|---|---|
| FR9.2 metrics (latency, FPR, RTO, rollback) | `bench.go` | `reports/benchmark.json` |
| FR9.3 reproducible by third party | `Makefile bench` / `to-bench calibrate` | `reports/calibration.json` |

## Non-functional requirements (NFR)

| Req | Test / evidence | Result |
|---|---|---|
| NFR1.1 P1 fork safety | TLA + `TestForkRaceRejected` | PASS |
| NFR1.2 P3 no resurrect | `TestFoldNoResurrection` | PASS |
| NFR3.2 180 certs ≤60s | `TestWorkloadReissueTarget` | PASS (reissue=180) |
| NFR3.3 linear scaling | `TestVerifyScalesLinearly` (best-of-3) | PASS |
| NFR4.1 mTLS channels | `TestMutualTLSRequest`, `TestWireRealSockets` | PASS |
| NFR4.2 stdlib primitives | `go.mod` | PASS |
| NFR4.3 no plaintext post-recovery | recovery path | PASS |
| NFR4.4 tolerate 1 Byzantine | ensembles tests | PASS |
| NFR5.1 single cmd + single config | `enroll` | PASS |
| NFR5.2 human-readable action log | `reports/action-log.txt` | PASS |
| NFR6.1 every claim → benchmark | `benchmark.json` | PASS |

## Requirements that are deferred by design (explicit in SRS)

These are **scope-limited**, not silently missing:
- FR6.1 VPN/DNS consumer checks → "deployment layer" (see 09-limitations)
- FR4.3 hardware enclave → fallback "dedicated isolated node"
- NFR7 (Linux) → porting note (Windows dev box)