#!/usr/bin/env bash
# Smoke test of the `hashfun` CLI against real binaries: create two launches (one that graduates
# at once, one with a long curve on both its curves), run their nodes, mine both through the CLI's
# pool with the CPU miner (the second launch once on each curve), check merge mining and automatic
# settlement on both chains happened, `hashfun qwork`, and that the site (`hashfun web`) serves both
# launches. A second stock bitcoind on regtest plays the regtest Qwencoin (hashfun/tests/qwenreg.py).
#   BITCOIND=/path/bitcoind bash contrib/hashfun/cli_smoke.sh
# QWORK_TABLE=/path/qwork.bin also checks `hashfun qwork check` on a copy of the real table (it is
# never downloaded here).
# HASHFUND=/path/hashfund picks the node binary; without it the CLI picks its own for this machine.
# HASHFUN_CMD=hashfun runs an installed CLI (npm i -g) instead of this checkout's; PYTHON names the
# Python for the test's own helpers.
set -euo pipefail
trap 'echo "cli_smoke.sh: line $LINENO did not hold: $BASH_COMMAND" >&2' ERR
: "${BITCOIND:?}"
[ -z "${HASHFUND:-}" ] || export HASHFUND
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"
W="$(mktemp -d)"
export HASHFUN_HOME="$W/home"
unset HASHFUN_QWORK   # this test says where the CLI keeps the table: under HASHFUN_HOME, and nowhere the machine names
hf() { ${HASHFUN_CMD:-"$PY" -m hashfun.cli} "$@"; }
j() { "$PY" -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
port() { "$PY" -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1])"; }
addr() { "$PY" -c "
import sys; sys.path.insert(0,'.')
from hashfun.ser import segwit_encode, hash160
from hashfun.crypto import pubkey_from_priv, random_priv
print(segwit_encode(sys.argv[1], 0, hash160(pubkey_from_priv(random_priv()))))" "$1"; }
# a process and everything it started: `hf web &` is a shell (and, installed, a node wrapper) around the Python that serves
killtree() { local c; for c in $(pgrep -P "$1" 2>/dev/null); do killtree "$c"; done; kill "$1" 2>/dev/null || true; }
cleanup() {
  [ -z "${WEBPID:-}" ] || killtree "$WEBPID"
  hf node down >/dev/null 2>&1 || true
  kill "$BTCPID" "$QWPID" 2>/dev/null || true
}
trap cleanup EXIT

BP=$(port)
"$BITCOIND" -regtest -datadir="$W" -server=1 -listen=0 -rpcport="$BP" -fallbackfee=0.0001 -printtoconsole=0 &
BTCPID=$!
BTC="http://127.0.0.1:$BP"; COOKIE="$W/regtest/.cookie"
# the regtest Qwencoin: its own data directory, its own port, no peers
mkdir -p "$W/qwen"; QP=$(port)
"$BITCOIND" -regtest -datadir="$W/qwen" -server=1 -listen=0 -connect=0 -txindex=1 -rpcport="$QP" -fallbackfee=0.0001 -printtoconsole=0 &
QWPID=$!
QW="http://127.0.0.1:$QP"; QCOOKIE="$W/qwen/regtest/.cookie"
rpc() { "$PY" -c "
import sys, json; sys.path.insert(0,'.')
from hashfun.rpc import RPC
r = RPC(sys.argv[1], cookie_file=sys.argv[2])
if sys.argv[3] == 'w': r = r.wallet('w'); a = sys.argv[4:]
else: a = sys.argv[3:]
def c(x):
    try: return json.loads(x)
    except ValueError: return x
o = r.call(a[0], *[c(x) for x in a[1:]]); print(o if isinstance(o, str) else json.dumps(o))" "$@"; }
b() { rpc "$BTC" "$COOKIE" "$@"; }
q() { rpc "$QW" "$QCOOKIE" "$@"; }
for _ in $(seq 100); do [ -f "$COOKIE" ] && b getblockcount >/dev/null 2>&1 && break; sleep 0.2; done
for _ in $(seq 100); do [ -f "$QCOOKIE" ] && q getblockcount >/dev/null 2>&1 && break; sleep 0.2; done
b createwallet w >/dev/null
BA=$(b w getnewaddress "" bech32)
b w generatetoaddress 110 "$BA" >/dev/null
q createwallet w >/dev/null
QA=$(q w getnewaddress "" bech32)
q w generatetoaddress 110 "$QA" >/dev/null

# the Qwencoin work table: where the CLI keeps it, and its check (a copy of the real one, never downloaded here)
[ "$(hf qwork path)" = "$HASHFUN_HOME/qwork.bin" ]
[ "$(HASHFUN_QWORK="$W/elsewhere.bin" hf qwork path)" = "$W/elsewhere.bin" ]
if hf qwork check >/dev/null 2>&1; then echo "qwork check passed with no table"; exit 1; fi
if [ -n "${QWORK_TABLE:-}" ]; then
  mkdir -p "$HASHFUN_HOME"; ln -s "$(cd "$(dirname "$QWORK_TABLE")" && pwd)/$(basename "$QWORK_TABLE")" "$HASHFUN_HOME/qwork.bin"
  hf qwork check | grep -q "8f53884f7727e80b86f3ddf288d3c3f0f998f1c63b8cd4f0bdad182ddd3f2c03"
  echo "qwork: table checked at $(hf qwork path)"
fi

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
  --qwen-rpc "$QW" --qwen-cookie "$QCOOKIE" --qwen-total 60000 --creator-qwen-address "$(q w getnewaddress "" bech32)" \
  --qwen-regtest --image "$W/sts.png" --description "smoke test coin" --x https://x.com/smoke -o "$W/sts.json" >/dev/null 2>&1
[ "$(hf launch info "$W/sts.json" | j "d['meta']['verified'] and d['meta']['image_type'] == 'image/png' and d['meta']['x'] == 'https://x.com/smoke'")" = "True" ]
# the QWEN leg: anchored 6 blocks under the Qwencoin stand-in's tip, regtest, 2 confirmations
[ "$("$PY" -c "
import sys; sys.path.insert(0, '.')
from hashfun import descriptor as D
d = D.load(sys.argv[1])
print(d.qwen_regtest and d.qwen_anchor_height == int(sys.argv[2]) - 6 and d.qwen_confs == 2 and d.qwen_num > 0)" "$W/sts.json" "$(q getblockcount)")" = "True" ]
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

# 1. mine GRD past graduation with the CLI pool + CPU miner. How many blocks six seconds give is a
#    matter of the machine (two on the slowest this runs on, dozens on most): mine until it has graduated.
for round in 1 2 3 4 5 6 7 8 9 10 11 12; do
  hf mine GRD --payout "$GA" --btc-rpc "$BTC" --btc-cookie "$COOKIE" --btc-wallet w --btc-hrp bcrt --listen "127.0.0.1:$(port)" --difficulty 1e-6 --duration 6 --pay-depth 0 > "$W/mine1-$round.log" 2>&1
  hf node ls GRD > "$W/ls1.json"
  [ "$(j "d[0]['graduated']" < "$W/ls1.json")" != "True" ] || break
done
echo "GRD: height $(j "d[0]['height']" < "$W/ls1.json") graduated $(j "d[0]['graduated']" < "$W/ls1.json") (after $round times six seconds of mining)"
[ "$(j "d[0]['graduated']" < "$W/ls1.json")" = "True" ]
G0=$(hf node rpc GRD getblockcount)

# 2. mine STS on each curve: it must merge-mine GRD and settle its own obligations, BTC-curve blocks
#    with Bitcoin payments and QWEN-curve blocks with Qwencoin payments
MINE_STS=(hf mine STS --payout "$SA" --btc-rpc "$BTC" --btc-cookie "$COOKIE" --btc-wallet w --btc-hrp bcrt
          --qwen-rpc "$QW" --qwen-cookie "$QCOOKIE" --qwen-wallet w --difficulty 1e-6 --pay-depth 0)
# both wallets and no --curve: the miner has to say which curve
if "${MINE_STS[@]}" --listen "127.0.0.1:$(port)" --duration 1 > "$W/mine-nocurve.log" 2>&1; then echo "mine without --curve ran"; exit 1; fi
grep -q -- "--curve" "$W/mine-nocurve.log"
# a curve with no wallet of its chain is refused
if hf mine STS --payout "$SA" --btc-rpc "$BTC" --btc-cookie "$COOKIE" --btc-wallet w --curve qwen --listen "127.0.0.1:$(port)" \
  --duration 1 > "$W/mine-nowallet.log" 2>&1; then echo "mine --curve qwen without a Qwencoin wallet ran"; exit 1; fi
# how many of STS's blocks above a height are on a curve and settled: settled HEIGHT CURVE
settled() {
  local n=0 h top
  top=$(hf node rpc STS getblockcount)
  for h in $(seq $(( $1 + 1 )) "$top"); do
    [ "$(hf node rpc STS getmintobligation "$h" | j "d['quote'] if d['settled'] else ''")" != "$2" ] || n=$((n + 1))
  done
  echo "$n"
}
SETTLED_BTC=0; SETTLED_QWEN=0
for curve in btc qwen; do
  H0=$(hf node rpc STS getblockcount)
  # A round is 14 s of mining. What a block owes is known six blocks later; then it has to be paid,
  # confirmed on its chain, relayed into the launch (a Qwencoin header only in a coinbase) and proven
  # there, all within what is mined: on a slow machine a round ends before the first payment is through,
  # and then there is another, until a block of the curve is settled and the curve has four blocks.
  for round in 1 2 3 4 5 6 7 8; do
    ( for _ in $(seq 14); do sleep 1; b w generatetoaddress 1 "$BA" >/dev/null 2>&1 || true; q w generatetoaddress 1 "$QA" >/dev/null 2>&1 || true; done ) &
    TICK=$!
    "${MINE_STS[@]}" --curve "$curve" --listen "127.0.0.1:$(port)" --duration 14 > "$W/mine2-$curve-$round.log" 2>&1
    wait "$TICK" 2>/dev/null || true
    grep -m1 '^{"stratum"' "$W/mine2-$curve-$round.log"
    [ "$(grep -m1 '^{"stratum"' "$W/mine2-$curve-$round.log" | j "d['curve']")" = "$curve" ]
    n=$(settled "$H0" "$curve")
    nb=$(hf node rpc STS getlaunchinfo | j "d['curves']['$curve']['blocks']")
    if [ "$n" -ge 1 ] && [ "$nb" -ge 4 ]; then break; fi
    echo "(round $round on the $curve curve: $nb blocks, $n settled by a payment: another round)"
  done
  if [ "$curve" = btc ]; then SETTLED_BTC=$n; else SETTLED_QWEN=$n; fi
done
G1=$(hf node rpc GRD getblockcount); S1=$(hf node rpc STS getblockcount)
CURVES=$(hf node rpc STS getlaunchinfo | j "(d['curves']['btc']['blocks'], d['curves']['qwen']['blocks'])")
echo "STS: height $S1, blocks per curve (btc, qwen) $CURVES, settled by payment on Bitcoin $SETTLED_BTC, on Qwencoin $SETTLED_QWEN; GRD merge-mined +$((G1-G0)); relay $(hf node rpc STS getbtcrelay | j "d['height']")/$(b getblockcount), Qwencoin relay $(hf node rpc STS getqwenrelay | j "d['height']")/$(q getblockcount)"
[ "$S1" -ge 8 ] && [ "$((G1-G0))" -ge 1 ] && [ "$SETTLED_BTC" -ge 1 ] && [ "$SETTLED_QWEN" -ge 1 ]
[ "$(hf node rpc STS getlaunchinfo | j "d['curves']['btc']['blocks'] > 0 and d['curves']['qwen']['blocks'] > 0")" = "True" ]

# 3. the site serves both launches from the same registry
WP=$(port)
hf web --btc-rpc "$BTC" --btc-cookie "$COOKIE" --qwen-rpc "$QW" --qwen-cookie "$QCOOKIE" --listen "127.0.0.1:$WP" > "$W/web.log" 2>&1 &
WEBPID=$!
for _ in $(seq 300); do [ "$(curl -sf "http://127.0.0.1:$WP/api/board" 2>/dev/null | j "sum('height' in c for c in d)" 2>/dev/null)" = "2" ] && break; sleep 0.2; done
echo "site: $(curl -sf "http://127.0.0.1:$WP/api/board" | j "[(c['ticker'], c['height'], c['graduated']) for c in d]")"
[ "$(curl -sf "http://127.0.0.1:$WP/api/coin/STS" | j "len(d['blocks']) > 5 and all(sum(d['curves'][x]['paid'].values()) > 0 for x in ('btc', 'qwen'))")" = "True" ]
[ "$(curl -sf "http://127.0.0.1:$WP/api/coin/STS/image" | cmp -s - "$W/sts.png" && echo same)" = "same" ]
[ "$(curl -sf "http://127.0.0.1:$WP/api/book" | j "d['orders']")" = "[]" ]
curl -sf "http://127.0.0.1:$WP/" | grep -q "<title>hashfun: "
[ "$(curl -sf "http://127.0.0.1:$WP/app.js" | wc -c)" -gt 20000 ]
killtree "$WEBPID"; WEBPID=
hf node down | j "d['GRD']+d['STS']"
[ "$(hf node ls | j "d[0]['running'] or d[1]['running']")" = "False" ]
echo "CLI SMOKE PASS"
