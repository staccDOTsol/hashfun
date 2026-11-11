#!/usr/bin/env bash
# Smoke test of the `hashfun` CLI against real binaries: create two launches (one that graduates
# at once, one with a long curve), run their nodes, mine both through the CLI's pool with
# the CPU miner, and check merge mining + automatic sats settlement happened.
#   HASHFUND=/path/hashfund BITCOIND=/path/bitcoind bash contrib/hashfun/cli_smoke.sh
set -euo pipefail
: "${HASHFUND:?}" "${BITCOIND:?}"
export HASHFUND
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
W="$(mktemp -d)"
export HASHFUN_HOME="$W/home"
hf() { python3 -m hashfun.cli "$@"; }
j() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
port() { python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1])"; }
addr() { python3 -c "
import sys; sys.path.insert(0,'.')
from hashfun.ser import segwit_encode, hash160
from hashfun.crypto import pubkey_from_priv, random_priv
print(segwit_encode(sys.argv[1], 0, hash160(pubkey_from_priv(random_priv()))))" "$1"; }
cleanup() { hf node down >/dev/null 2>&1 || true; kill "$BTCPID" 2>/dev/null || true; }
trap cleanup EXIT

BP=$(port)
"$BITCOIND" -regtest -datadir="$W" -server=1 -listen=0 -rpcport="$BP" -fallbackfee=0.0001 -printtoconsole=0 &
BTCPID=$!
BTC="http://127.0.0.1:$BP"; COOKIE="$W/regtest/.cookie"
b() { python3 -c "
import sys, json; sys.path.insert(0,'.')
from hashfun.rpc import RPC
r = RPC(sys.argv[1], cookie_file=sys.argv[2])
if sys.argv[3] == 'w': r = r.wallet('w'); a = sys.argv[4:]
else: a = sys.argv[3:]
def c(x):
    try: return json.loads(x)
    except ValueError: return x
o = r.call(a[0], *[c(x) for x in a[1:]]); print(o if isinstance(o, str) else json.dumps(o))" "$BTC" "$COOKIE" "$@"; }
for _ in $(seq 100); do [ -f "$COOKIE" ] && b getblockcount >/dev/null 2>&1 && break; sleep 0.2; done
b createwallet w >/dev/null
BA=$(b w getnewaddress "" bech32)
b w generatetoaddress 110 "$BA" >/dev/null

hf launch new --name "Grad smoke" --ticker GRD --creator-address "$(addr grd)" --graduation-hashes 30 \
  --pow-limit 207fffff --spacing 10 --window 10 --test -o "$W/grd.json" >/dev/null 2>&1
hf launch new --name "Sats smoke" --ticker STS --creator-address "$(addr sts)" --graduation-hashes 1e9 \
  --pow-limit 207fffff --spacing 10 --window 10 --test --btc-rpc "$BTC" --btc-cookie "$COOKIE" \
  --sats-total 20000 --creator-btc-address "$(b w getnewaddress "" bech32)" --btc-hrp bcrt -o "$W/sts.json" >/dev/null 2>&1
hf node add "$W/grd.json" >/dev/null; hf node add "$W/sts.json" >/dev/null
hf node up | tee "$W/up.json" >/dev/null
[ "$(j "d['GRD']+d['STS']" < "$W/up.json")" = "startedstarted" ]
for t in GRD STS; do hf node rpc $t createwallet w >/dev/null; done
GA=$(hf node rpc GRD getnewaddress "" bech32); SA=$(hf node rpc STS getnewaddress "" bech32)

# 1. mine GRD past graduation with the CLI pool + CPU miner
hf mine GRD --payout "$GA" --btc-rpc "$BTC" --btc-cookie "$COOKIE" --btc-wallet w --btc-hrp bcrt --listen 127.0.0.1:$(port) --difficulty 1e-6 --duration 6 > "$W/mine1.log" 2>&1
hf node ls GRD > "$W/ls1.json"
echo "GRD: height $(j "d[0]['height']" < "$W/ls1.json") graduated $(j "d[0]['graduated']" < "$W/ls1.json")"
[ "$(j "d[0]['graduated']" < "$W/ls1.json")" = "True" ]
G0=$(hf node rpc GRD getblockcount)

# 2. mine STS: must merge-mine GRD and settle its own Bitcoin obligations
( for _ in $(seq 14); do sleep 1; b w generatetoaddress 1 "$BA" >/dev/null 2>&1 || true; done ) &
hf mine STS --payout "$SA" --btc-rpc "$BTC" --btc-cookie "$COOKIE" --btc-wallet w --btc-hrp bcrt \
  --listen 127.0.0.1:$(port) --difficulty 1e-6 --duration 14 > "$W/mine2.log" 2>&1
wait %2 2>/dev/null || true
head -1 "$W/mine2.log"
G1=$(hf node rpc GRD getblockcount); S1=$(hf node rpc STS getblockcount)
SETTLED=$(python3 - "$S1" <<PY
import json, subprocess, sys
n = 0
for h in range(1, min(int(sys.argv[1]), 40) + 1):
    o = json.loads(subprocess.check_output([sys.executable, "-m", "hashfun.cli", "node", "rpc", "STS", "getmintobligation", str(h)]))
    n += bool(o["settled"])
print(n)
PY
)
echo "STS: height $S1, blocks settled by Bitcoin payment: $SETTLED; GRD merge-mined +$((G1-G0)); relay $(hf node rpc STS getbtcrelay | j "d['height']")/$(b getblockcount)"
[ "$S1" -ge 8 ] && [ "$((G1-G0))" -ge 1 ] && [ "$SETTLED" -ge 1 ]
hf node down | j "d['GRD']+d['STS']"
[ "$(hf node ls | j "d[0]['running'] or d[1]['running']")" = "False" ]
echo "CLI SMOKE PASS"
