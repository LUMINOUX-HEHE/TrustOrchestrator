# 10 — Gateway: REST API, dashboard, RBAC, webhooks, backup

The gateway (`cmd/gateway`, binary `to-gateway`) is the management plane over
the engine: a REST API with role-based access, multi-tenant orgs (logical
isolation — each org is an independent timeline + detector ensemble), a
single-file web dashboard, outbound webhooks, and snapshot backup/restore.
One binary, one process, zero third-party dependencies.

## Layout

```
data/
  gateway.json                  users, webhooks, tenant meta
  tenants/<org>/timeline.json   per-org signed trust chain (demo tier: key included)
  backups/bk-<ts>.json          snapshots
  trash/<org>-<ts>/             deleted orgs (recoverable)
```

Writes are atomic (tmp + rename), serialized by one mutex. Backup = copy
`data/`; the `/v1/backup` endpoint produces the same state as one JSON bundle.

## Identity model

- **Users**: id + role + orgs list + bearer tokens (SHA-256 hashes; the raw
  token is shown once at creation). No passwords — tokens are 32 random bytes.
- **Roles**: `admin` (everything), `operator` (issue/revoke/scores/recover),
  `auditor` (read + audit search), `viewer` (read-only).
- **Scoping**: `orgs: []` on a user = all orgs; otherwise exactly those orgs.
  The org-scope check runs on every tenant route (403 outside scope).
- First boot seeds `admin`; the token is printed once, or seeded via
  `-token` / `TO_ADMIN_TOKEN`.

## Multi-tenancy

Each org has its own `Timeline`, signing key, and `FleetServer` ensemble.
Detection is per-org: ≥3/5 watchdog scores below threshold on that org's
fleet → a DETECTED event lands on that org's chain and webhooks fire.
Recovery is per-org with that org's shards.

The logical (API-level) isolation is deliberate: tenants share one process
and one key ceremony model. Full per-tenant crypto isolation (separate root
key + shard set per tenant) is a ceremony/ops change, not a code change.

## Webhooks

`POST /v1/webhooks {url, secret, events}` — events: `detected`, `recovery`,
`revoke`, `issue` (empty = all). Deliveries are JSON
`{org, type, ts, event_hash, details}` signed with HMAC-SHA256 in
`X-TO-Signature`, 3 attempts, 2s backoff. The queue is in-memory: a crash
between trigger and delivery drops the notification (ponytail: durable
outbox when delivery guarantees matter).

## Backup & restore

- `POST /v1/backup` → `{id, size, download}`; `GET /v1/backup/{id}/download`
  fetches the bundle. Store it offsite; the bundle includes users and all
  orgs.
- `POST /v1/restore` (raw bundle body) validates first — every timeline must
  pass `Verify()` — then swaps the store in place. A restored gateway trusts
  the bundle's users (its own admin is superseded); keep the bundle's admin
  token safe.

## Recovery over the API

1. `GET /v1/orgs/{org}/keys` → root seed (base64) for the offline ceremony:
   `to shard --key <seed> --shares 5 --threshold 3` → 5 shard files.
2. Watchdogs post scores; ≥3/5 alarm → DETECTED (evidence carries the
   rollback anchor).
3. `POST /v1/orgs/{org}/recover` with ≥3 shards (the JSON from the shard
   files). The council verifies the prefix, reconstructs the root (memory
   only, zeroized), rolls back, re-issues, and checks P3/P5 before the
   threshold-signed COMMIT.

The API path signs the commit with ephemeral member keys — real threshold
signatures run via `cmd/council serve` over mTLS (`councilnet.go`). The
recovery post-conditions (VerifyRecovery) are enforced identically on both
paths.

## Metrics

`GET /v1/metrics` (prometheus text): per-org event/issue/revoke/detection/
recovery counters + uptime/users/orgs. The dashboard renders org cards and
the raw text.

## Deployment

- `deploy/trust-orchestrator-gateway.service` — systemd unit.
- `deploy/kubernetes.yaml` — gateway Deployment + Service + PVC +
  `allow-gateway-api` network policy; terminate TLS at the ingress
  (the API is bearer-token HTTP).
- Container: the image already includes `to-gateway` (Dockerfile).

## Tests

`api_test.go` (root package): auth/RBAC, org lifecycle, detection →
webhook, council recovery via API shards, backup/restore round-trip,
tampered-bundle rejection. `cmd/gateway/main_test.go`: dashboard embed +
API under one handler. `client_test.go`: the Go SDK against the real mux.
