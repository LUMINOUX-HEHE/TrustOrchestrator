#!/usr/bin/env bash
# fleet-smoke: the live-fleet proof (docs/08 §5, docs/09 "next step" 1). One
# host, four real processes, real mTLS: to-orchestrator serve + 3
# to-watchdog --live replays. Asserts the server log shows both a healthy
# and a DETECTED ensemble verdict — the transport can't silently pass as a
# no-op. Runs on any host with bash + Go (git-bash included).
# Usage: bash deploy/fleet-smoke.sh [evidence.json] [listen-port]
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
EVIDENCE=${1:-$ROOT/reports/evidence.json}
PORT=${2:-8333}
BIN=$ROOT/bin
WORK=$(mktemp -d) || exit 1
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT

say()  { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

[ -f "$EVIDENCE" ] || fail "evidence not found: $EVIDENCE (run 'make benchmark' first)"

# Build the four binaries from source if missing (to-tool doubles as
# to-watchdog by basename; see cmd/to/main.go).
say "building binaries (if missing)"
(cd "$ROOT" && go build -o bin/to-tool ./cmd/to) || fail "build cmd/to"
cp "$BIN/to-tool" "$BIN/to-watchdog"
(cd "$ROOT" && go build -o bin/to-identity ./cmd/identity) || fail "build cmd/identity"
(cd "$ROOT" && go build -o bin/to-orchestrator ./cmd/orchestrator) || fail "build cmd/orchestrator"

say "materializing CA + leaves"
"$BIN/to-tool" genkey "$WORK/root.key" >/dev/null
"$BIN/to-identity" ca --key "$WORK/root.key" --name fleet-smoke --out "$WORK/ca.der" >/dev/null
"$BIN/to-identity" issue --ca "$WORK/ca.der" --key "$WORK/root.key" --identity orchestrator \
  --out "$WORK/orch.der" --key-out "$WORK/orch.key" >/dev/null
for i in 1 2 3; do
  "$BIN/to-identity" issue --ca "$WORK/ca.der" --key "$WORK/root.key" --identity "w$i" \
    --out "$WORK/w$i.der" --key-out "$WORK/w$i.key" >/dev/null
done

say "starting orchestrator on 127.0.0.1:$PORT"
"$BIN/to-orchestrator" serve --listen "127.0.0.1:$PORT" --ca "$WORK/ca.der" \
  --cert "$WORK/orch.der" --key "$WORK/orch.key" >"$WORK/serve.log" 2>&1 &
PIDS="$PIDS $!"
# wait up to 5s for it to be listening, fail fast on a bind error
for _ in 1 2 3 4 5; do
  grep -q listening "$WORK/serve.log" 2>/dev/null && break
  grep -q 'error:' "$WORK/serve.log" 2>/dev/null && break
  sleep 1
done
grep -q listening "$WORK/serve.log" 2>/dev/null || fail "orchestrator: $(cat "$WORK/serve.log")"

say "starting 3 watchdogs (--live, behavior_baseline)"
for i in 1 2 3; do
  "$BIN/to-watchdog" run --events "$EVIDENCE" --node-id "W$i" --kind behavior_baseline \
    --live "127.0.0.1:$PORT" --ca "$WORK/ca.der" --cert "$WORK/w$i.der" \
    --key "$WORK/w$i.key" --server-name orchestrator >"$WORK/w$i.log" 2>&1 &
  PIDS="$PIDS $!"
done

say "waiting for a DETECTED verdict (30s cap)"
deadline=$((SECONDS + 30))
until grep -q 'ENSEMBLE: DETECTED' "$WORK/serve.log" 2>/dev/null; do
  [ "$SECONDS" -ge "$deadline" ] && break
  sleep 1
done

healthy=$(grep -c 'ENSEMBLE: healthy' "$WORK/serve.log" || true)
detected=$(grep -c 'ENSEMBLE: DETECTED' "$WORK/serve.log" || true)
echo "verdicts: healthy=$healthy detected=$detected"
[ "$healthy" -gt 0 ] || { tail -5 "$WORK/serve.log"; fail "no healthy verdict"; }
[ "$detected" -gt 0 ] || { tail -5 "$WORK/serve.log"; fail "no DETECTED verdict"; }
tail -3 "$WORK/serve.log"
say "PASS: 4 live processes, mTLS fan-in, healthy + DETECTED verdicts"
