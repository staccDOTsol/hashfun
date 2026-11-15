#!/usr/bin/env bash
# The regression: every suite, one log file per suite, one line per suite on the terminal.
#
#   bash contrib/hashfun/ci/test.sh [--hashfund PATH] [--bitcoind PATH] [--logs DIR] [suite ...]
#
# suites (default: all of them, in this order):
#   unit    the Python model of the consensus rules, the wallet, the swap contracts, the relay
#   diff    the node's own C++ consensus code against that Python model (builds a small driver),
#           and the node's self-test: the two curves, both relays, and Qwencoin's work function on
#           real headers of its chain (needs Qwencoin's work table: QWORK_TABLE=/path/to/qwork.bin,
#           `hashfun qwork fetch` gets it; without it those checks are skipped)
#   web_js  the page's JavaScript against the Python (hashes, signatures, contracts); bundle; lint
#   doctor  hashfun doctor: which node binary this machine gets, and its self-test. It also mines
#           a short chain into the logs (chain-<target>.json): another machine's node replays it
#           with `hashfun doctor --replay` and must reach the same conclusions
#   core    Bitcoin Core's own unit tests, when dist/build.sh built them (TESTS=1)
#   twin    the two curves of a launch on one real node: what each block mints, templates for
#           either curve, graduation by the QWEN curve, undo and restart
#   e2e     one launch end to end on regtest: curves, graduation, merge mining, sats and qwen owed, swaps
#   btcindex the site's Bitcoin balances from an Electrum index agree with the UTXO-set scan
#   btclight Bitcoin through Electrum servers instead of a node: every call the site and the settlers
#           make, against a real server over a regtest node
#   sitepool the no-install path: the site mines a block for a visitor, they pay its sats themselves, it unlocks
#   yield   the sats leg and the QWEN leg, a real node against the Python model of its rules, block by block
#   fleet   several nodes, miners and a settler talking to each other
#   book    peer-to-peer swaps on the shipped 4 h and 8 h timelocks (the test moves the clock)
#   web     the site in two real browsers (needs Python's playwright with its chromium)
#   smoke   the CLI the way a user runs it: launch, node up, mine, settle, site
#
# hashfund: --hashfund, else $HASHFUND, else what `hashfun` itself picks on this machine.
# bitcoind (a stock Bitcoin Core, for the Bitcoin side; a second one plays the regtest Qwencoin):
# --bitcoind, else $BITCOIND, else PATH.
# A suite whose tools are missing is skipped and says why; with CI set, a skip is a failure.
# RETRY=1 (the default with CI set; RETRY=0 switches it off) runs a suite that failed once more.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT" || exit 1
LOGS="$ROOT/build/test-logs"
DIST="${DIST_WORK:-$ROOT/build/dist}"   # where dist/build.sh keeps its compilers and test binaries
HF="${HASHFUND:-}"
BTC="${BITCOIND:-}"
SUITES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --hashfund) HF="$2"; shift 2 ;;
    --bitcoind) BTC="$2"; shift 2 ;;
    --logs) LOGS="$2"; shift 2 ;;
    -h | --help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) SUITES+=("$1"); shift ;;
  esac
done
[ ${#SUITES[@]} -gt 0 ] || SUITES=(unit diff web_js doctor core twin e2e yield btcindex btclight sitepool fleet book web smoke)
mkdir -p "$LOGS"
LOGS="$(cd "$LOGS" && pwd)"

# The python3 that ships with macOS is 3.9 on LibreSSL (no scrypt for the wallet file): look past it.
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  for c in python3 python3.14 python3.13 python3.12 python3.11 python3.10 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    if command -v "$c" >/dev/null 2>&1 &&
       "$c" -c 'import sys, hashlib; sys.exit(0 if sys.version_info >= (3, 10) and hasattr(hashlib, "scrypt") else 1)' 2>/dev/null; then
      PY="$c"; break
    fi
  done
fi
[ -n "$PY" ] || { echo "Python 3.10+ built with OpenSSL is needed (on a Mac: brew install python)" >&2; exit 1; }
export PYTHON="$PY"

if [ -z "$HF" ]; then HF="$("$PY" -c 'from hashfun.cli import hashfund_choice; print(hashfund_choice()[0])')" || exit 1; fi
[ -x "$HF" ] || { echo "hashfund $HF: not an executable file" >&2; exit 1; }
HF="$(cd "$(dirname "$HF")" && pwd)/$(basename "$HF")"
[ -n "$BTC" ] || BTC="$(command -v bitcoind || true)"
HOST="$("$PY" -c 'from hashfun.cli import platform_target; print(platform_target() or "")')"
JOBS="$(getconf _NPROCESSORS_ONLN)"
echo "hashfund  $HF"
echo "          $("$HF" -version 2>&1 | head -n 1)"
echo "bitcoind  ${BTC:-none}${BTC:+ ($("$BTC" -version 2>&1 | head -n 1))}"
echo "python    $("$PY" --version 2>&1) ($PY)"
echo "logs      $LOGS"
echo

FAILED=0
AGAIN=0
# A suite that fails is run once more where RETRY is 1 (the default where CI is set: a shared
# machine, busy with other people's work, where a check that waits on a clock can miss it once).
# Its first log is kept as <suite>.first.log and the line says so: a suite that needs its second
# run is to be looked at, and one that fails twice has failed.
RETRY="${RETRY:-${CI:+1}}"
skip() {   # name, why
  if [ -n "${CI:-}" ]; then printf 'FAIL  %-7s cannot run here: %s\n' "$1" "$2"; FAILED=$((FAILED + 1)); else printf 'skip  %-7s %s\n' "$1" "$2"; fi
}
run() {    # name, command...
  local name="$1" t0 rc second=""
  shift
  t0=$(date +%s)
  "$@" > "$LOGS/$name.log" 2>&1
  rc=$?
  if [ $rc -ne 0 ] && [ "${RETRY:-0}" = 1 ]; then
    printf 'again %-7s the first run failed (exit %d): its log is kept as %s, and these were its last lines\n' "$name" "$rc" "$LOGS/$name.first.log"
    tail -n 25 "$LOGS/$name.log" | sed 's/^/      | /'
    mv "$LOGS/$name.log" "$LOGS/$name.first.log"
    "$@" > "$LOGS/$name.log" 2>&1
    rc=$?
    second="  (on the second run: see $name.first.log)"
    [ $rc -ne 0 ] || AGAIN=$((AGAIN + 1))
  fi
  local took=$(( $(date +%s) - t0 ))
  local last
  last="$(grep -E 'passed|^OK|^Ran |PASS$|all good|No errors detected' "$LOGS/$name.log" | tail -n 1 | cut -c1-110)"
  if [ $rc -eq 0 ]; then
    printf 'PASS  %-7s %4ds  %s%s\n' "$name" "$took" "$last" "$second"
  else
    printf 'FAIL  %-7s %4ds  exit %d: see %s\n' "$name" "$took" "$rc" "$LOGS/$name.log"
    tail -n 25 "$LOGS/$name.log" | sed 's/^/      | /'
    FAILED=$((FAILED + 1))
  fi
}
need_btc() { [ -n "$BTC" ] && [ -x "$BTC" ]; }

suite_diff() {
  # Compile the consensus sources with the compiler that built the shipped binary when it is here
  # (dist/build.sh leaves it in build/dist/tc), so the arithmetic under test is the shipped one.
  local cxx="${CXX:-}"
  if [ -z "$cxx" ] && [ -x "$DIST/tc/$HOST/c++" ]; then cxx="$DIST/tc/$HOST/c++"; fi
  if [ -z "$cxx" ]; then cxx="$(command -v c++ || command -v g++ || command -v clang++)"; fi
  echo "compiler: $cxx"
  CXX="$cxx" bash contrib/hashfun/difftest/build.sh "$ROOT/build/hfdiff-test" || return 1
  # The node's self-test. The checks that need Qwencoin's table are skipped without it; where a
  # skip is a failure (CI), so is that.
  local out
  out="$(QWEN_VECTORS="${QWEN_VECTORS:-$ROOT/hashfun/tests/data/qwen_headers.json}" "$ROOT/build/hfdiff-test" --selftest)" || { echo "$out"; return 1; }
  echo "$out"
  if [ -n "${CI:-}" ] && ! echo "$out" | tail -n 1 | grep -q ' 0 skipped'; then
    echo "the self-test skipped checks: QWORK_TABLE must name Qwencoin's work table here"
    return 1
  fi
  # The difference test. Its checks against the real table are passed over without the table, and
  # without numpy (the Python pass through it). Where a skip is a failure, a missing table is one;
  # a machine without numpy has said so when it was set up (ci/setup.sh), and the self-test above
  # has already run the real headers through the node's own pass.
  out="$(HFDIFF="$ROOT/build/hfdiff-test" "$PY" -m unittest hashfun.tests.test_diff_cpp 2>&1)" || { echo "$out"; return 1; }
  echo "$out"
  if [ -n "${CI:-}" ] && echo "$out" | tail -n 1 | grep -q 'skipped' && "$PY" -c 'import numpy' 2>/dev/null; then
    echo "the difference test skipped checks: it needs Qwencoin's work table (QWORK_TABLE) here"
    return 1
  fi
}
web_deps() { [ -d hashfun/web/node_modules ] || (cd hashfun/web && npm ci --no-audit --no-fund); }
suite_web_js() { web_deps && "$PY" -m unittest hashfun.tests.test_web_js; }
suite_book() { web_deps && "$PY" -m hashfun.tests.book_regtest --hashfund "$HF" --bitcoind "$BTC"; }
suite_core() {
  # every test suite of test_bitcoin as its own process, as many at a time as there are processors
  local t="$1" out="$LOGS/core" n
  mkdir -p "$out"
  "$t" --list_content 2>&1 | grep -v '^ ' | sed 's/\*$//' > "$out/suites.txt"
  n="$(wc -l < "$out/suites.txt" | tr -d ' ')"
  [ "$n" -gt 50 ] || { echo "test_bitcoin lists only $n suites"; return 1; }
  # shellcheck disable=SC2016
  xargs -P "$JOBS" -I{} sh -c '"$0" --run_test="$2" --catch_system_errors=no > "$1/$2.log" 2>&1 || echo "$2" >> "$1/failed.txt"' "$t" "$out" {} < "$out/suites.txt"
  if [ -s "$out/failed.txt" ]; then
    echo "failed suites: $(tr '\n' ' ' < "$out/failed.txt")"
    while read -r s; do echo "--- $s"; grep -E "error|fatal|assert" "$out/$s.log" | head -n 20; done < "$out/failed.txt"
    return 1
  fi
  echo "$n suites of Bitcoin Core's unit tests: No errors detected"
}

for s in "${SUITES[@]}"; do
  case "$s" in
    unit)   HASHFUND="$HF" run unit "$PY" -W ignore -m unittest hashfun.tests.test_core hashfun.tests.test_yieldstate hashfun.tests.test_stack hashfun.tests.test_book hashfun.tests.test_cli hashfun.tests.test_btclight ;;
    diff)   run diff suite_diff ;;
    web_js) if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then run web_js suite_web_js; else skip web_js "node and npm are not installed"; fi ;;
    doctor) HASHFUND="$HF" run doctor "$PY" -m hashfun.cli doctor --mine "$LOGS/chain-$HOST.json" ;;
    core)   if [ -x "$DIST/tests/$HOST/test_bitcoin" ]; then run core suite_core "$DIST/tests/$HOST/test_bitcoin"
            else printf 'skip  %-7s not built (TESTS=1 bash contrib/hashfun/dist/build.sh)\n' core; fi ;;
    twin)   run twin "$PY" -m hashfun.tests.twin_regtest --hashfund "$HF" ;;
    e2e)    if need_btc; then run e2e "$PY" -m hashfun.tests.e2e_regtest --hashfund "$HF" --bitcoind "$BTC"; else skip e2e "no bitcoind"; fi ;;
    yield)  if need_btc; then run yield "$PY" -m hashfun.tests.yield_regtest --hashfund "$HF" --bitcoind "$BTC"; else skip yield "no bitcoind"; fi ;;
    btcindex) if need_btc; then run btcindex "$PY" -m hashfun.tests.btcindex_regtest --bitcoind "$BTC"; else skip btcindex "no bitcoind"; fi ;;
    btclight) if need_btc; then run btclight "$PY" -m hashfun.tests.btclight_regtest --bitcoind "$BTC"; else skip btclight "no bitcoind"; fi ;;
    sitepool) if ! need_btc; then skip sitepool "no bitcoind"
            elif ! "$PY" -c 'import playwright' 2>/dev/null; then skip sitepool "Python's playwright is not installed (pip install playwright && playwright install chromium)"
            else run sitepool "$PY" -m hashfun.tests.sitepool_regtest --hashfund "$HF" --bitcoind "$BTC"; fi ;;
    fleet)  if need_btc; then run fleet "$PY" -m hashfun.tests.fleet_regtest --hashfund "$HF" --bitcoind "$BTC"; else skip fleet "no bitcoind"; fi ;;
    book)   if ! need_btc; then skip book "no bitcoind"; elif ! command -v node >/dev/null 2>&1; then skip book "node is not installed"
            else run book suite_book; fi ;;
    web)    if ! need_btc; then skip web "no bitcoind"
            elif ! "$PY" -c 'import playwright' 2>/dev/null; then skip web "Python's playwright is not installed (pip install playwright && playwright install chromium)"
            else run web "$PY" -m hashfun.tests.web_regtest --hashfund "$HF" --bitcoind "$BTC" --shots "$LOGS/screenshots"; fi ;;
    smoke)  if need_btc; then HASHFUND="$HF" BITCOIND="$BTC" run smoke bash contrib/hashfun/cli_smoke.sh; else skip smoke "no bitcoind"; fi ;;
    *) echo "unknown suite $s" >&2; FAILED=$((FAILED + 1)) ;;
  esac
done
echo
if [ "$AGAIN" -gt 0 ]; then echo "note: $AGAIN suite(s) passed only on a second run (the lines that start with 'again'); their first logs are in $LOGS"; fi
if [ "$FAILED" -eq 0 ]; then echo "regression: all of it passed"; else echo "regression: $FAILED suite(s) FAILED"; fi
exit $(( FAILED > 0 ))
