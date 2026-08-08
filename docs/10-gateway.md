# 10 — Gateway: REST API, dashboard, RBAC, webhooks, backup, transparency

The gateway (`cmd/gateway`, binary `to-gateway`) is the management plane over
the engine: a REST API with role-based access, multi-tenant orgs (logical
isolation — each org is an independent timeline + detector ensemble), a
single-file web dashboard, outbound webhooks, and snapshot backup/restore.
One binary, one process, zero third-party dependencies.

## Layout

```
data/
  gateway.json                  users, webhooks, tenant meta, council anchor, CT log key
  gateway.key                   AES key sealing tenant timelines (0600, at rest)
  outbox.json                   pending webhook deliveries (durable queue)
  tenants/<org>/timeline.json   per-org signed trust chain (AES-GCM sealed)
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
  Tokens minted with `POST /v1/users/{id}/tokens {orgs: [...]}` are scoped to
  those orgs only (a second, token-level gate) — least-privilege without a
  second user account.
- **Idempotency**: mutating requests may send `Idempotency-Key`; retries with
  the same key + body + token replay the cached response instead of applying
  twice (24h window, in-memory).
- First boot seeds `admin`; the token is printed once, or seeded via
  `-token` / `TO_ADMIN_TOKEN`.

## Multi-tenancy

Each org has its own `Timeline`, signing key, and `FleetServer` ensemble.
Detection is per-org: ≥3/5 watchdog scores below threshold on that org's
fleet → a DETECTED event lands on that org's chain and webhooks fire.
Recovery is per-org, council-authorized, against the gateway's one trust
anchor.

The logical (API-level) isolation is deliberate: tenants share one process
and one council ceremony model. Full per-tenant crypto isolation (separate
root key + council per tenant) is a ceremony/ops change, not a code change.

## Webhooks

`POST /v1/webhooks {url, secret, events}` — events: `detected`, `recovery`,
`revoke`, `issue` (empty = all). Deliveries are JSON
`{org, type, ts, event_hash, details}` signed with HMAC-SHA256 in
`X-TO-Signature`. URLs must be `https:` (loopback `http:` allowed for local
sinks). Delivery is a **durable outbox** (`outbox.json`): pending jobs
survive restarts, retried with backoff 5s→15s→1m→5m, dropped after 5
attempts (the event itself stays on the org chain). At least-once semantics
— replay one undelivered event, not a dropped one.

## Backup & restore

- `POST /v1/backup` → `{id, size, download}`; `GET /v1/backup/{id}/download`
  fetches the bundle. Store it offsite; the bundle includes users and all
  orgs.
- `POST /v1/restore` (raw bundle body) validates first — every timeline must
  pass `Verify()` — then swaps the store in place. A restored gateway trusts
  the bundle's users (its own admin is superseded); keep the bundle's admin
  token safe.

## Recovery over the API

The gateway holds only the council's FROST **group key** (trust anchor) —
never a root seed, never seals or shards. Recovery material is produced
offline by the council ceremony and shipped to the API as one artifact:

1. `to-council dkg --members 5 --threshold 3` (or `to shard`) → one share
   file per member; the printed group key becomes the gateway's anchor
   (`--council-pub` / `SetCouncilPub` in `gateway.json`).
2. Watchdogs post scores; ≥3/5 alarm → DETECTED (evidence carries the
   rollback anchor).
3. `to-council recover --evidence ... --shares ...` → threshold-signs the
   epoch handoff and writes `{fork.json, commit.json}`.
4. `POST /v1/orgs/{org}/recover {timeline, commit}` — the gateway verifies
   the handoff's FROST signature against its anchor, fork chain integrity,
   and that the fork descends from THIS org's verified prefix (epochs must
   advance) before adopting it. No shards or seeds ever cross this surface.

The networked path signs via `cmd/council serve` over mTLS
(`councilnet.go`); the recovery post-conditions (VerifyRecovery) are
enforced identically on both paths.

## Metrics

`GET /v1/metrics` (prometheus text): per-org event/issue/revoke/detection/
recovery counters + uptime/users/orgs. The dashboard renders org cards and
the raw text.

## Transparency (RFC 9162)

Every org exposes an append-only **transparency log** (`ctlog.go`): the
RFC 9162 Merkle tree whose leaves are the hashes of the org's signed
timeline events, in append order. The tree is rebuilt from the timeline on
demand — the log derives from the same signatures the chain already
carries, so there is no second trusted writer. The log's signing key
(`log_key`, an Ed25519 seed) is generated at first boot and stored in
`gateway.json`.

| Endpoint | Roles | Returns |
|---|---|---|
| `GET /v1/orgs/{org}/ct/sth` | viewer+ | signed tree head: `tree_size`, `timestamp`, `root_hex`, `signature_hex`, `log_key_hex` |
| `GET /v1/orgs/{org}/ct/proof?index=&size=` | viewer+ | inclusion proof of leaf `index` in the tree at `size`: `leaf_hash_hex`, `root_hex`, `proof` (hex siblings, bottom-up) |
| `GET /v1/orgs/{org}/ct/proof?from=&to=` | viewer+ | consistency proof between two sizes: `old_root_hex`, `new_root_hex`, `proof` |
| `POST /v1/orgs/{org}/ct/gossip` | viewer+ | cross-check an observed STH: `accepted`, `alarm`, `trusted_tree_size`, `trusted_root_hex` |

The **audit loop** needs no trust in the gateway:

1. Read the STH (size *n*, signed root *r*), and the org's log key.
2. Fetch any proof and verify it by hand: `VerifyInclusion(leaf, idx,
   size, proof)` must recompute that size's root, `VerifyConsistency(oldRoot,
   newRoot, from, to, proof)` must hold — both are pure, public library
   functions (RFC 9162 §2.1.3.2 / §2.1.4.2).
3. A newer STH must extend the older one: replay its consistency proof
   against the trusted head. A root that changes at the *same* size is a
   split-brain — a rewrite — and gossip raises the alarm.

`POST /v1/orgs/{org}/ct/gossip` is the verifier surface: submit an STH you
observed (signed, base64 root/signature, plus the consistency proof from
your trusted size). The gateway verifies the signature against its log key,
anchors on the first valid STH it has seen, and thereafter accepts a head
only if it consistently extends the trusted one — a rewrite or a wrong
proof answers `accepted:false` with the reason in `alarm`. The gateway's
own `/ct/sth` is served from the same log, so two instances observing each
other's heads cross-check both directions.

`client.go` wraps the whole surface: `CTSTH`, `CTInclusionProof`,
`CTConsistencyProof`, `CTGossip` (see `TestClientCTAudit` for the full
audit loop end-to-end).

## Rate limiting

Every request is budgeted by a **token bucket keyed on the token identity**
(`ratelimit.go`, wired in the route middleware): 20 tokens/s refill, burst
40, one token per request. A drained identity gets `429 Too Many Requests`
with `Retry-After: 1` and is never queued — the bucket *denies*, it does not
delay. `GET /v1/health` is exempt (the liveness probe has no token and must
not be throttled). Buckets are in-memory and per-token: one client's flood
cannot spend another identity's budget, and a restart resets them.

The **mTLS watchdog wire is budgeted per peer** the same way (1 frame/s,
burst 4 — legit nodes send one frame per 30s): a peer that drains its bucket
is dropped from the stream, so the wire path cannot bypass the API's
throttle (there is no unthrottled code path).

## Deployment

- `to-gateway -addr :8443 -tls-cert cert.pem -tls-key key.pem` serves HTTPS
  directly (or terminate TLS at the ingress; the API is bearer-token HTTP).
- `-council-pub <hex>` sets the recovery trust anchor at boot (also
  `TO_COUNCIL_PUB` env); `-leader-lock <file>` enables single-writer HA —
  a second gateway over the same data dir exits, so exactly one active
  replica writes. Failover is manual (remove the lock file); combined with
  the durable outbox and atomic writes, a replaced replica loses nothing
  that was acked.
- `deploy/trust-orchestrator-gateway.service` — systemd unit.
- `deploy/kubernetes.yaml` — gateway Deployment + Service + PVC +
  `allow-gateway-api` network policy; terminate TLS at the ingress
  (the API is bearer-token HTTP).
- Container: the image already includes `to-gateway` (Dockerfile).

## Tests

`api_test.go` (root package): auth/RBAC, org lifecycle, detection →
webhook, token scoping, idempotency, durable outbox, council recovery via
API fork+commit, backup/restore round-trip, tampered-bundle rejection, CT
STH/proof/gossip end-to-end (`TestCTEndpoints`).
`ratelimit_test.go`: bucket burst/refill, per-key isolation, end-to-end 429.
`cmd/gateway/main_test.go`: dashboard embed + API under one handler.
`client_test.go`: the Go SDK against the real mux, including the CT audit
loop (`TestClientCTAudit`).
