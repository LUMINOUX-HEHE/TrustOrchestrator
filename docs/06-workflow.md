# 06 — Workflow

End-to-end walkthrough of a real security event. Commands are the shippable CLIs.

## 1. Bootstrap (one-time, air-gapped)

```
to-tool genkey bootstrap.key                 # offline root (Ed25519)
to-tool shard --key bootstrap.key --shares 5 --threshold 3   → shard-1..5
# enroll each node with bootstrap (short-form or config file):
to-watchdog enroll --bootstrap bootstrap.key --node-id W1 --role watchdog
to-council  enroll --bootstrap bootstrap.key --node-id C1 --role council
```

FR-weight: at some point (after ALL enrollment) — the operator revokes the
bootstrap so it's spent:

```
to-tool revoke --bootstrap bootstrap.key     # FR8.2: genesis is over
```

Any later enroll with that key fails (`TestBootstrapRevokedAfterGenesis`).

## 2. Normal operation

Each `TrustEvent` (issue/revoke/user/enter) is appended to the Merkle
timeline (signed, parent-chained). Each 30-second cycle:

- each usable watchdog runs `ObserveBatch(events)` then `Score()`
- scores stream to the orchestrator over mTLS frames (`transport.go`)

`to-orchestrator status --events canonical.json` → `ENSEMBLE: healthy`.

## 3. DETECTED (compromise)

A combination of low scores (≥3/5) and/or auditor escalation turns the state
alarmed:

```
to-watchdog run --events evidence.json --kind behavior_baseline --params params.json
cycle …  score 0 ALARM
```

The orchestrator's alarm evidence anchors the **first bad event** (`bad_index`).

## 4. Rollback — council votes

```
to-orchestrator rollback --dry-run --events evidence.json
  ROLLBACK DRY-RUN: checkpoint #19 (verified), first bad event #20
  would invalidate 6 cert(s) …
```

Real execute path: council reconstruction (3-of-5 Shamir) + signed RECOVER
votes (`council.go`), then:
1. fork the timeline at the latest **verified good** checkpoint
2. invalidate = reachable subgraph from the first bad event (`graph.go`)
3. re-issue fresh certs for damaged identities onto the new canonical fork
4. consumers receive a **delta**, not a restart (`TestConsumerRollbackDelta`)

## 5. Verification

```
to-orchestrator verify --root <anchor>
to-identity verify --cert server.der --ca ca.der        → VERIFY: PASS
to-pdp    check --policy examples/policy.json --events canonical.json
```

## User-visible status at any time

```
to-orchestrator status --events canonical.json
ENSEMBLE: healthy            EPOCH: 1    ANCHOR: b6776b0b…28f429
```

The anchor is the SHA-256 root of the canonical timeline — anyone can audit it.