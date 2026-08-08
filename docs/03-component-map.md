# 03 — Component Map

Every source file, its job, key functions, and how it's tested.

## Runtime (root package `trustorchestrator`)

| File | Role | Key symbols |
|---|---|---|
| `timeline.go` | append-only signed Merkle chain, fold, fork | `Timeline.Append`, `Verify`, `Fork`, `Fold`, `Hash` |
| `watchdogs.go` | 5 detector types + scoring contract | `Watchdog.ObserveBatch`, `Score` |
| `ensemble.go` | fusion: DETECTED ⇔ ≥quorum low scores | `Detect`, `Score` |
| `detect.go` | threshold/quorum helpers, conditional logic | `Detect`, `Escalation` helpers |
| `audit.go` | auditor mirror, policy check, escalation | `Mirror`, `Verify`, `CheckPolicy`, `DetectEscalated` |
| `council.go` | recovery council, votes, permissions | `Recover`, `SignCommit`, `recoverFork`, `finishRecovery` |
| `councilnet.go` | networked council protocol (two rounds over mTLS) | `RemoteRecover`, `CouncilMemberServer`, `MemberEndpoint` |
| `frost.go` | FROST threshold signing (dealer split + DKG + share files) | `FrostSplit`, `DkgCeremony`, `FrostShareFile`, `FrostAggregator` |
| `shamir.go` | legacy Shamir split/join (shard CLI predecessor) | `ShamirSplit`, `ShamirJoin` |
| `rollback.go` | refold to checkpoint, invalidation set | `Rollback`, `invalidateReachable` |
| `graph.go` | trust graph + scoped reachability | `InvalidationSetScoped` |
| `consumer.go` | consumer rules engine (delta application) | `ApplyDelta`; `consumerState` |
| `identity.go` | workload certificate authority + CRL lifecycle | `NewIdentityCA`, `IssueWorkloadCertWithDP`, `NewCRL`, `AppendRevocation`, `VerifyCRL`, `CheckRevoked` |
| `mtls.go` | mutual TLS configs (stdlib) | `MutualTLSConfig`, `VerifyPeerIdentity` |
| `transport.go` | framed mTLS wire client/server | `DialWire`, `WriteWire`, `ServeWire`, `WireMsg` |
| `ratelimit.go` | token-bucket abuse limiter (API per identity, wire per peer) | `limiter`, `newLimiter`, `allow` |
| `ctlog.go` | RFC 9162 append-only transparency log: per-org Merkle tree over event hashes, proofs, signed tree heads, gossip observer | `MerkleLog.Append/InclusionProof/ConsistencyProof`, `SignSTH`, `VerifyInclusion`, `VerifyConsistency`, `GossipNode.Observe` |
| `compliance.go` | evidence-based compliance reports (ISO 27001/SOC 2/PCI DSS/HIPAA/GDPR) | `BuildReport`, `complianceReport` |
| `bench.go` | scenario runner (S1–S7) | `Bench`, `RunAll`, `Calibrate` |
| `watch` public CLI types | score output | `Score`, `issuePayload` |

## CLIs (`cmd/…`)

| Binary | Command | Notes |
|---|---|---|
| `cmd/to` | `to-tool` (base: genkey,shard,enroll,bench) + `to-bench` + `to-watchdog` (enroll/run) | the Swiss-army CLI, dispatch by argv[0] |
| `cmd/orchestrator` | `to-orchestrator status / timeline / verify / graph / policy reload / rollback --dry-run / report` | reads event files; `report` emits the compliance report |
| `cmd/council` | `to-council serve` (networked member node) + `recover` (share files) + `dkg` / `dkg-net` (ceremonies: in-process vs. distrustful pairwise over mTLS) | member node: FROST share + mTLS; recover: share files |
| `cmd/auditor` | `to-auditor audit --log` | mirror log checker |
| `cmd/identity` | `to-identity ca / issue / revoke / crl / verify` | CA + CRL issuance, revocation, inspection |
| `cmd/pdp` | `to-pdp check --policy --events` | policy decision point |

## Test files

| File | Subject | #tests |
|---|---|---|
| `core_test.go` | timelines, all scopes, quorums, escalations, `TestMutualTLSRequest`, `TestEndToEnd...` | 22 |
| `timeline_test.go` | chain/fork/fold/CUSUM/search/bad-locate, rotation, concurrency | 9 |
| `identity_test.go` | cert CA, expiry, workload reissue, CRL lifecycle | 7 |
| `frost_test.go` | self-check, split/sign, share verification, DKG ceremony | 7 |
| `api_test.go` | RBAC, orgs, recovery fork adoption, idempotency, webhooks, restore, CT endpoints | 9 |
| `ctlog_test.go` | merkle tree + proofs (all sizes, stale sizes, tamper), STH sign/verify, gossip accept/split-brain/rewrite | 10 |
| `kill_test.go` | K1–K6 fault injection | 6 |
| `hash_test.go` | dual-algo chains, legacy-compat, tamper | 5 |
| `vault_test.go` | KEK unwrap, tenant isolation, rotation kills old DEK | 5 |
| `regressions_test.go` | previously fixed defects | 4 |
| `blindfrost_test.go` | unblinded verify, link resistance | 3 |
| `fleet_test.go` | live-verdict, frame-loss reconnect, concurrent fan-in | 3 |
| `ratelimit_test.go` | bucket burst/refill, key isolation, API 429 | 3 |
| `consumer_test.go` | rollback delta, diff stateless | 2 |
| `dkg_test.go` | pairwise ceremony, tamper rejection | 2 |
| `councilnet_test.go` | networked recovery, blocks under quorum | 2 |
| `pq_test.go` | hybrid channel, garbage-ciphertext rejection | 3 |
| `reshare_test.go` | membership rotation, tamper rejection | 2 |
| `client_test.go` | REST client happy path, error mapping, CT audit loop | 3 |
| `transport_test.go` | real-socket mTLS frames | 1 |
| `compliance_test.go` | report statuses, findings, policy violations | 1 |

Root package: 109. `cmd/dnsprobe/main_test.go` 2, `cmd/to/main_test.go` 4,
`cmd/gateway/main_test.go` 1 → **116 total**, plus three fuzz targets
(`fuzz_test.go`). All green: `go test ./... -count=1` (full inventory in
§07).

## Generated artifacts the map depends on

| Artifact | Generated by | Used by |
|---|---|---|
| `reports/params.json` | `to-bench calibrate` | detectors `mu0/delta/h` |
| `reports/benchmark.json` | `Makefile bench` | §08 rows, judges |
| `reports/kill-tests.log` | `go test -run 'TestK'` | §07 |
| `reports/compliance.json` | `to-orchestrator report` | compliance evidence (§07) |
| `reports/sbom.txt` | `make sbom` | per-binary provenance |
| `reports/canonical.json` | `to-orchestrator`/bench | §07, smoke |
| `reports/evidence.json` | bench run w/ compromise | smoke tests |
| `specs/…` TLA | `make model-check` | P1–P6 machines |
| `tools/tla2tools.jar` | pinned dependency | TLC binary |
| `bin/*` | `make build` | all CLIs |