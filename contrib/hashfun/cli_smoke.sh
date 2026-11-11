#!/usr/bin/env bash
# Smoke test of the `hashfun` CLI against real binaries: create two launches (one that graduates
# at once, one with a long curve), run their nodes, mine both through the CLI's pool with
# the CPU miner, check merge mining + automatic sats settlement happened, and that the site
# (`hashfun web`) serves both launches.
#   BITCOIND=/path/bitcoind bash contrib/hashfun/cli_smoke.sh
# HASHFUND=/path/hashfund picks the node binary; without it the CLI picks its own for this machine.
# HASHFUN_CMD=hashfun runs an installed CLI (npm i -g) instead of this checkout's; PYTHON names the
# Python for the test's own helpers.
set -euo pipefail
: "${BITCOIND:?}"
[ -z "${HASHFUND:-}" ] || export HASHFUND
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"
W="$(mktemp -d)"
export HASHFUN_HOME="$W/home"
hf() { ${HASHFUN_CMD:-"$PY" -m hashfun.cli} "$@"; }
j() { "$PY" -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
port() { "$PY" -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1])"; }
addr() { "$PY" -c "
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
b() { "$PY" -c "
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
# a 1x1 PNG as the coin's picture: its hash goes into the launch id
"$PY" -c "
import struct, sys, zlib
c = lambda t, d: struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d))
open(sys.argv[1], 'wb').write(b'\x89PNG\r\n\x1a\n' + c(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)) + c(b'IDAT', zlib.compress(b'\x00\xff\x9a\x1f')) + c(b'IEND', b''))" "$W/sts.png"
hf launch new --name "Sats smoke" --ticker STS --creator-address "$(addr sts)" --graduation-hashes 1e9 \
  --pow-limit 207fffff --spacing 10 --window 10 --test --btc-rpc "$BTC" --btc-cookie "$COOKIE" \
  --sats-total 20000 --creator-btc-address "$(b w getnewaddress "" bech32)" --btc-hrp bcrt \
  --image "$W/sts.png" --description "smoke test coin" --x https://x.com/smoke -o "$W/sts.json" >/dev/null 2>&1
[ "$(hf launch info "$W/sts.json" | j "d['meta']['verified'] and d['meta']['image_type'] == 'image/png' and d['meta']['x'] == 'https://x.com/smoke'")" = "True" ]
# a launch file whose picture is not the committed one is refused
"$PY" -c "
import json, sys
d = json.load(open(sys.argv[1])); d['metadata']['description'] = 'swapped'; json.dump(d, open(sys.argv[2], 'w'))" "$W/sts.json" "$W/bad.json"
if hf node add "$W/bad.json" >/dev/null 2>&1; then echo "tampered metadata was accepted"; exit 1; fi
hf node add "$W/grd.json" >/dev/null; hf node add "$W/sts.json" >/dev/null
hf node up | tee "$W/up.json" >/dev/null
[ "$(j "d['GRD']+d['STS']" < "$W/up.json")" = "startedstarted" ]
for t in GRD STS; do hf node rpc $t createwallet w >/dev/null; done
GA=$(hf node rpc GRD getnewaddress "" bech32); SA=$(hf node rpc STS getnewaddress "" bech32)

# 1. mine GRD past graduation with the CLI pool + CPU miner
hf mine GRD --payout "$GA" --btc-rpc "$BTC" --btc-cookie "$COOKIE" --btc-wallet w --btc-hrp bcrt --listen 127.0.0.1:$(port) --difficulty 1e-6 --duration 6 --pay-depth 0 > "$W/mine1.log" 2>&1
hf node ls GRD > "$W/ls1.json"
echo "GRD: height $(j "d[0]['height']" < "$W/ls1.json") graduated $(j "d[0]['graduated']" < "$W/ls1.json")"
[ "$(j "d[0]['graduated']" < "$W/ls1.json")" = "True" ]
G0=$(hf node rpc GRD getblockcount)

# 2. mine STS: must merge-mine GRD and settle its own Bitcoin obligations
( for _ in $(seq 14); do sleep 1; b w generatetoaddress 1 "$BA" >/dev/null 2>&1 || true; done ) &
hf mine STS --payout "$SA" --btc-rpc "$BTC" --btc-cookie "$COOKIE" --btc-wallet w --btc-hrp bcrt \
  --listen 127.0.0.1:$(port) --difficulty 1e-6 --duration 14 --pay-depth 0 > "$W/mine2.log" 2>&1
wait %2 2>/dev/null || true
head -1 "$W/mine2.log"
G1=$(hf node rpc GRD getblockcount); S1=$(hf node rpc STS getblockcount)
SETTLED=0
for h in $(seq 1 $(( S1 < 40 ? S1 : 40 ))); do
  if [ "$(hf node rpc STS getmintobligation "$h" | j "d['settled']")" = "True" ]; then SETTLED=$((SETTLED + 1)); fi
done
echo "STS: height $S1, blocks settled by Bitcoin payment: $SETTLED; GRD merge-mined +$((G1-G0)); relay $(hf node rpc STS getbtcrelay | j "d['height']")/$(b getblockcount)"
[ "$S1" -ge 8 ] && [ "$((G1-G0))" -ge 1 ] && [ "$SETTLED" -ge 1 ]

# 3. the site serves both launches from the same registry
WP=$(port)
hf web --btc-rpc "$BTC" --btc-cookie "$COOKIE" --listen "127.0.0.1:$WP" > "$W/web.log" 2>&1 &
WEBPID=$!
for _ in $(seq 100); do [ "$(curl -sf "http://127.0.0.1:$WP/api/board" 2>/dev/null | j "sum('height' in c for c in d)" 2>/dev/null)" = "2" ] && break; sleep 0.2; done
echo "site: $(curl -sf "http://127.0.0.1:$WP/api/board" | j "[(c['ticker'], c['height'], c['graduated']) for c in d]")"
[ "$(curl -sf "http://127.0.0.1:$WP/api/coin/STS" | j "len(d['blocks']) > 5 and d['paid']['holder'] + d['paid']['creator'] + d['paid']['dev'] > 0")" = "True" ]
[ "$(curl -sf "http://127.0.0.1:$WP/api/coin/STS/image" | cmp -s - "$W/sts.png" && echo same)" = "same" ]
[ "$(curl -sf "http://127.0.0.1:$WP/api/book" | j "d['orders']")" = "[]" ]
curl -sf "http://127.0.0.1:$WP/" | grep -q "<title>hashfun</title>"
[ "$(curl -sf "http://127.0.0.1:$WP/app.js" | wc -c)" -gt 20000 ]
kill "$WEBPID" 2>/dev/null || true
hf node down | j "d['GRD']+d['STS']"
[ "$(hf node ls | j "d[0]['running'] or d[1]['running']")" = "False" ]
echo "CLI SMOKE PASS"
