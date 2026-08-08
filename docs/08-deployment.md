# 08 — Deployment

What ships, what runs where, and what's the deployment layer's real status.

## The 10 binaries (`make build`, output to `bin/`)

| Binary | Purpose | Key commands |
|---|---|---|
| `to-tool` | offline bootstrap, calibration, generic | `genkey`, `shard`, `enroll`, `bench`, `revoke` |
| `to-bench` | benchmark runner (argv0 alias of `to-tool`) | `run --scenario all`, `calibrate` |
| `to-watchdog` | per-node watchdog (argv0 alias) | `enroll`, `run --events --kind --params --tail` |
| `to-orchestrator` | status, timeline, graph, policy, rollback | `status`, `timeline`, `verify --root`, `policy reload`, `rollback --dry-run` |
| `to-council` | recovery council: 5 member nodes + ceremony machine | `serve` (networked member, mTLS), `recover` (FROST share files) |
| `to-auditor` | mirror log checker | `audit --log` |
| `to-identity` | certificate authority | `ca`, `issue`, `verify` |
| `to-pdp` | policy decision point | `check --policy --events` |
| `to-dnsprobe` | W4 external probe: real UDP DNS query | `--server --name --type`, `--poll` |
| `to-gateway` | management plane: REST API, RBAC, webhooks, backup | `-addr`, `-council-pub`, `-kek-shares`, `-leader-lock` (see docs/10) |

All built with the same `cmd/to`/`cmd/orchestrator`… sources. `go build ./...`
exit 0. `make sbom` emits per-binary provenance (module, Go toolchain, VCS
revision) to `reports/sbom.txt`.

## Bootstrap ceremony (guide §5, air-gapped)

1. Offline: `to-tool genkey <root>`
2. `to-tool shard --key <root> --shares 5 --threshold 3` → 5 FROST share files
   (`to-cconcouncil dkg` covers a key-free ceremony; the printed GROUP KEY is
   the gateway's council anchor)
3. `to-tool enroll` / `to-watchdog enroll` each node
4. `to-tool revoke --bootstrap <root>` — spent, genesis is over (FR8.2)

## Node config

- Short form (`--node-id C1 --role council`) or a flat `config.yaml`
  (node/role/detector/interval/threshold). One file, one command — NFR5.

## Deployment matrix

| Run mode | Reality today |
|---|---|
| Single binary, in-process (benchmarks) | yes — the entire fleet on one node |
| Two processes over mTLS loopback | yes — `TestWireRealSockets`, `TestFleetLiveVerdict` |
| N live processes on one host | yes — `fleet.go` (`to-orchestrator serve` + `to-watchdog run --live ...`); §5 below |
| systemd units | yes — `deploy/*.service`, run the `bin/linux` ELFs (`make build-linux`) |
| Docker / Kubernetes | yes — `Dockerfile` + `deploy/kubernetes.yaml` (make docker-build); §12 below |
| Real VPN / eBPF consumers | **docs only** (to-dns stands in: real UDP query) |

## Live fleet on one host

Run the real transport — orchestrator daemon + N watchdog processes talking
over TLS 1.3 mTLS, not in-process calls. Keys are issued by `to-identity`
with its new `--key-out` (the leaf key the handshake needs):

```
to-tool genkey root.key
to-identity ca --key root.key --name fleet-ca --out ca.der
to-identity issue --ca ca.der --key root.key --identity orchestrator --out orch.der --key-out orch.key
to-identity issue --ca ca.der --key root.key --identity w1 --out w1.der --key-out w1.key   # w2, w3 …
to-orchestrator serve --listen 127.0.0.1:8333 --ca ca.der --cert orch.der --key orch.key
to-watchdog  run --events evidence.json --params params.json --node-id W1 --live 127.0.0.1:8333 \
               --ca ca.der --cert w1.der --key w1.key --server-name orchestrator   # repeat per node
```

The orchestrator prints one `ENSEMBLE: healthy|DETECTED (n/m nodes …)` line per
score frame — a real multi-process fan-in with concurrent peer handling
(`fleet.go`, replacing the old sequential-Accept design).
`FleetPeer.Send` redials on socket drops, so a watchdog restart does not tear
down the ensemble.

The whole ceremony above — build, key material, CA + leaves, `serve`, 3
watchdogs `--live`, and an assertion that the log shows both a healthy and a
DETECTED verdict — is one script:

```
make fleet-smoke          # bash deploy/fleet-smoke.sh [evidence.json] [port]
```

A watchdog can score the fleet on a real external probe instead of (or in
addition to) its detector: `--probe-cmd` runs a shell command each cycle and
maps exit 0 → score 100, non-zero → score 0 (W4 wiring, docs/09). The
canonical command is `to-dnsprobe` itself:

```
to-watchdog run --events evidence.json --node-id W4 --live 127.0.0.1:8333 \
  --ca ca.der --cert w4.der --key w4.key --server-name orchestrator \
  --probe-cmd "to-dnsprobe --server 8.8.8.8:53 --name example.com --type A"
```

## Production PKI: revocation (CRL)

The issuer is a real X.509 CA: issued certs carry SANs, key usage, expiry —
and now a **CRL distribution point** plus a signed, numbered **CRL**
(`identity.go`: `NewCRL`, `AppendRevocation`, `VerifyCRL`, `CheckRevoked`).

```
to-identity issue --ca ca.der --key ca.key --identity alice --serial 100 \
  --crl-url https://ca.example/identity.crl --out alice.der --key-out alice.key
to-identity revoke --ca ca.der --key ca.key --crl crl.der --serial 100,200 --out crl.der --pem
to-identity crl   --ca ca.der --file crl.der
to-identity verify --cert alice.der --ca ca.der --crl crl.der
```

- `revoke` re-signs the CRL under the next CRL number (fresh list = #1);
  duplicates are dropped. `--pem` also writes the PEM form.
- `crl` reports validity window, number, and revoked serials — the
  operator-facing check that publication actually happened.
- `verify --crl` fails on a revoked, forged, or stale CRL.
- Recovery integration: the canonical fork's REVOKE events name cert IDs;
  the serial ledger (cert_id → serial) lives with the issuer, so the
  operator maps the recovery report's affected set to serials and runs
  `revoke`. Ledger-backed automatic revocation is the upgrade path.

`ponytail:` serial+time entries only — reason codes, delta CRLs, OCSP, and
CRL auto-renewal are the next rungs; the standard library's x509 CRL
machinery is what ships today.

## Kubernetes (guide §12)

`Dockerfile` + `deploy/kubernetes.yaml`: one static image (scratch base,
`CGO_ENABLED=0`, all 10 binaries in `/bin/`), zero OS-level trust — mTLS runs
against the identity CA only.

```
make docker-build                    # trust-orchestrator:latest
kubectl apply -f deploy/kubernetes.yaml
```

What runs where (namespace `trust-orchestrator`):

| Component | Workload | Entrypoint |
|---|---|---|
| orchestrator (fleet server, PVC for evidence) | Deployment ×1 | `to-orchestrator serve --listen 0.0.0.0:8333` |
| council members C1–C5 (one FROST share each) | Deployment ×5 | `to-council serve --id C<N> --addr 0.0.0.0:8443` |
| watchdogs (distinct fleet IDs) | StatefulSet ×5 | `to-watchdog run --live orchestrator:8333 --node-id-file /etc/podinfo/name` |
| identity CA | Secrets only | — |

Bootstrap ceremony first (nothing is hardcoded): genkey/shard offline,
`to-identity ca` + `issue` per node CN (`C1..C5`, `orchestrator`, `watchdog`),
export the timeline for the watchdog StatefulSet, then fill the Secrets and
ConfigMaps (per-`kubectl create secret` commands are in the manifest header).
The watchdog pods hold their fleet identity from their pod name via the
downward API (`--node-id-file`) — the 3/5 ensemble needs five distinct IDs.

NetworkPolicies: default deny; orchestrator:8333 only from watchdog pods;
council:8443 only from council/orchestrator pods. Recovery is initiated
from the orchestrator or a ceremony pod dialing `council-c1..5:8443` over
mTLS (`RemoteRecover`); expose the council Services for an external ceremony
machine only through an ingress/LoadBalancer plus a CIDR-scoped policy —
the cluster-internal policy above is the default posture.

`ponytail:` plain Deployments/StatefulSets, no operator/CRDs/Helm; CRL
hosting inside the cluster is out of scope (serve `crl.der` from any static
file server the certs' DP points at).

## The sandbox

`tools/tla2tools.jar` + `specs/*` Java TLC model. Re-generate:

```
make model-check            # base spec P1..P6 → report = tlc.log
make model-check-mutations  # P2/P6 mutants must *fail* (artifact = mutation-*.log)
```

(Requires Java; on Windows `bin/` needs no Java at runtime.)

## No secrets in the zip

Keys and lives only offline/generated: `node.key`, `share-*.json`, the dev
`bootstrap.key` are git-ignored (`reports/` and `bin/` are gitignored too).