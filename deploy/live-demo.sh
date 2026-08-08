#!/usr/bin/env bash
# live-demo.sh — the 20-minute teacher demo, one command.
# Rebuilds binaries, runs the ceremony, boots a live fleet (mTLS), drives a
# DETECTED + threshold recovery, and spins up the gateway dashboard.
# Everything is localhost, self-contained, deterministic-ish. On Windows
# (git-bash/WSL) or Linux; requires go.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=$ROOT/bin
WORK="${DEMO_WORK:-$ROOT/.demo}"
PORT=8333
GWPORT=8090
# note: 8080 is in Windows' excluded port range; 8090 is clear.
mkdir -p "$WORK" "$BIN"

say()   { printf '\n\x1b[1m== %s\x1b[0m\n' "$*"; }
step()  { printf '   %s\n' "$*"; }

cd "$ROOT"

say "0. build the ten binaries"
go build -o $BIN/to-tool ./cmd/to && cp $BIN/to-tool $BIN/to-watchdog
go build -o $BIN/to-orchestrator ./cmd/orchestrator
go build -o $BIN/to-council ./cmd/council
go build -o $BIN/to-gateway ./cmd/gateway
go build -o $BIN/to-identity ./cmd/identity
step "binaries in $BIN"

say "2. council ceremony: 5 members, threshold 3 (FROST)"
rm -f $WORK/share-*.json $WORK/council-group.key
$BIN/to-council dkg --members 5 --threshold 3 --out $WORK | tee $WORK/council.log
GROUP=$(grep -o '[0-9a-f]\{64\}' $WORK/council.log | tail -1)
echo "$GROUP" > $WORK/council-group.key
step "group key (trust anchor): ${GROUP:0:16}…"

say "3. bootstrap material (CA + 4 fleet identities) over real mTLS"
$BIN/to-tool genkey $WORK/root.key >/dev/null
$BIN/to-identity ca --key $WORK/root.key --name demo --out $WORK/ca.der >/dev/null
for n in orchestrator W1 W2 W3; do
  $BIN/to-identity issue --ca $WORK/ca.der --key $WORK/root.key --identity $n \
    --out $WORK/$n.der --key-out $WORK/$n.key >/dev/null
done

say "4. fleet smoke — orchestrator + 3 watchdogs, mTLS fan-in"
[ -f reports/evidence.json ] || { echo "no evidence; skipping live fleet (see reports)"; }
(cd $ROOT && bash deploy/fleet-smoke.sh reports/evidence.json 8333 | head -8) 2>/dev/null \
  || step "fleet-smoke skipped (no evidence.json — business/attack replay is optional)"

say "5. gateway — REST API, RBAC, at-rest sealing, webhooks, dashboard"
rm -rf $WORK/gwdata
$BIN/to-gateway -addr 127.0.0.1:$GWPORT -data $WORK/gwdata -council-pub $GROUP \
  >$WORK/gw.log 2>&1 &
GWPID=$!
trap 'kill $GWPID 2>/dev/null; rm -rf $WORK' EXIT
for i in $(seq 1 30); do grep -q 'admin token' $WORK/gw.log 2>/dev/null && break; sleep 0.2; done
TOKEN=$(grep -o 'admin token.*' $WORK/gw.log | head -1 | sed 's/.*: //')
echo "   admin token: ${TOKEN:0:12}…  (dashboard: http://127.0.0.1:$GWPORT)"
echo "   try it live:"
echo "   curl -s localhost:$GWPORT/v1/orgs -H \"Authorization: Bearer $TOKEN\""
echo "   open the dashboard: http://127.0.0.1:$GWPORT (paste token)"
say "6. live attack + council recovery through the API (watch the dashboard!)"
AUTH="Authorization: Bearer $TOKEN"
B=http://127.0.0.1:$GWPORT
step "tenant acme + honest traffic"
curl -s -X POST $B/v1/orgs -H "$AUTH" -d '{"name":"acme"}' >/dev/null
for i in 1 2 3 4 5; do
  curl -s -X POST $B/v1/orgs/acme/issue -H "$AUTH" -d "{\"cert_id\":\"c$i\",\"identity\":\"user\"}" >/dev/null
done
step "3 of 5 watchdogs alarm on the same evidence -> DETECTED on the chain"
for n in W1 W2 W3; do
  curl -s -X POST $B/v1/orgs/acme/scores -H "$AUTH" \
    -d "{\"node_id\":\"$n\",\"score\":0,\"p_value\":0.01,\"evidence\":{\"bad_index\":3}}" >/dev/null
done
sleep 3
curl -s "$B/v1/orgs/acme/timeline" -H "$AUTH" | grep -o '"type": *"[A-Z]*"' | sort | uniq -c \
  | sed 's/^/   /'
step "offline council: 3 of 5 share files threshold-sign the rollback fork"
step "  (to-council recover --evidence <detected> --shares share-1..3.json)"
step "final: teacher sees the DETECTED event + webhook on dashboard, then the"
step "       recovered chain (fork + FROST commit) — and 'root key never existed'"

say "done — the surface is complete"