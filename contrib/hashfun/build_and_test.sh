#!/usr/bin/env bash
# Build hashfund from the pinned base + hashfun patch, fetch stock Bitcoin Core
# for the merge-mining parent (checksum-pinned), run the Python suite and the
# real-binary e2e harness. Linux (incl. WSL / Cowork VM). Idempotent.
#
#   bash build_and_test.sh <workdir> <path/to/0001-hashfun-*.patch>
set -euo pipefail

WORK="${1:-$HOME/hashfun-work}"
PATCH="$(realpath "${2:?patch path required}")"
BASE_REPO=https://github.com/namecoin/namecoin-core.git
BASE_SHA=70c6b3698ef8357f6c04004e57c06a85856e3f27
BTC_VER=32.1
BTC_TGZ=bitcoin-${BTC_VER}-x86_64-linux-gnu.tar.gz
BTC_SHA256=61545c17c3120fb7412f896d248b11993af04ec8817aad3649c55b2afb044963
JOBS=$(nproc)

log() { printf '\n== %s ==\n' "$*"; }
mkdir -p "$WORK"
cd "$WORK"

log "deps"
need=()
for p in build-essential cmake pkgconf python3 libevent-dev libboost-dev libsqlite3-dev git curl; do
  dpkg -s "$p" >/dev/null 2>&1 || need+=("$p")
done
if ((${#need[@]})); then
  SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO=sudo
  $SUDO apt-get update -qq && DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq "${need[@]}"
fi

log "source @ ${BASE_SHA:0:12} + hashfun patch"
if [ ! -d hashfun-core/.git ]; then
  git init -q hashfun-core
  git -C hashfun-core remote add origin "$BASE_REPO"
  git -C hashfun-core fetch -q --depth 1 origin "$BASE_SHA"
  git -C hashfun-core checkout -q FETCH_HEAD
  git -C hashfun-core -c user.name=hashfun -c user.email=hashfun@localhost am -q "$PATCH"
fi
cd hashfun-core

log "build ($JOBS jobs)"
[ -f build/CMakeCache.txt ] || cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF -DBUILD_BENCH=OFF \
  -DBUILD_GUI=OFF -DENABLE_IPC=OFF -DWITH_ZMQ=OFF -DBUILD_KERNEL_LIB=OFF -DBUILD_BITCOIN_BIN=OFF -DBUILD_TX=OFF \
  -DBUILD_UTIL=OFF -DBUILD_WALLET_TOOL=OFF -DENABLE_EXTERNAL_SIGNER=OFF >/dev/null
cmake --build build -j"$JOBS" 2>&1 | tail -n 5
test -x build/bin/hashfund && test -x build/bin/hashfun-cli

log "stock Bitcoin Core $BTC_VER (parent chain)"
if [ ! -x "$WORK/bitcoin-$BTC_VER/bin/bitcoind" ]; then
  curl -fsSLo "$WORK/$BTC_TGZ" "https://bitcoincore.org/bin/bitcoin-core-$BTC_VER/$BTC_TGZ"
  echo "$BTC_SHA256  $WORK/$BTC_TGZ" | sha256sum -c -
  tar -xzf "$WORK/$BTC_TGZ" -C "$WORK"
fi

log "python unit + simulator tests"
python3 -W ignore -m unittest hashfun.tests.test_core hashfun.tests.test_stack 2>&1 | tail -n 4

log "e2e: hashfund vs Python model, merged mining vs stock bitcoind, swap on real nodes"
python3 -m hashfun.tests.e2e_regtest --hashfund build/bin/hashfund --bitcoind "$WORK/bitcoin-$BTC_VER/bin/bitcoind"
