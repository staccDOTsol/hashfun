#!/usr/bin/env bash
# Build the hashfun differential driver: the node's own consensus sources
# (descriptor/identity, chain params + genesis, the two curves, LWMA, the sats leg and the QWEN
# leg with their header relays, Qwencoin's work function) compiled directly, without CMake or the
# rest of the node. Used by hashfun/tests/test_diff_cpp.py; it also carries the node's own checks
# of rule set 3 (selftest.cpp).
#
#   bash contrib/hashfun/difftest/build.sh [out-binary]      # default build/hfdiff
#   HFDIFF=build/hfdiff python3 -m unittest hashfun.tests.test_diff_cpp -v
#   build/hfdiff --selftest                                  # exit status 1 if a check fails
#   QWORK_TABLE=~/.hashfun/qwork.bin QWEN_VECTORS=hashfun/tests/data/qwen_headers.json build/hfdiff --selftest
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT="${1:-$ROOT/build/hfdiff}"
case "$OUT" in /*) ;; *) OUT="$PWD/$OUT" ;; esac    # absolute, without GNU realpath (macOS has none with -m)
mkdir -p "$(dirname "$OUT")"
OBJ="$OUT-obj"
CXX="${CXX:-g++}"
mkdir -p "$OBJ"
# Objects of another compiler do not link with this one's (libstdc++ against libc++): start over
# when the compiler is not the one that made what is here.
stamp="$CXX | $("$CXX" --version 2>/dev/null | head -1)"
if [ "$(cat "$OBJ/.compiler" 2>/dev/null)" != "$stamp" ]; then
  rm -f "$OBJ"/*.o
  printf '%s\n' "$stamp" > "$OBJ/.compiler"
fi
SRCS=(src/kernel/launch.cpp src/launchcurve.cpp src/launchyield.cpp src/launchyieldstate.cpp src/pow.cpp src/chain.cpp
      src/kernel/chainparams.cpp src/primitives/block.cpp src/primitives/pureheader.cpp src/primitives/transaction.cpp
      src/auxpow.cpp src/consensus/merkle.cpp src/script/script.cpp src/hash.cpp src/crypto/sha256.cpp
      src/crypto/ripemd160.cpp src/crypto/sha512.cpp src/crypto/hmac_sha512.cpp src/crypto/hex_base.cpp
      src/crypto/siphash.cpp src/crypto/qwork.cpp src/uint256.cpp src/arith_uint256.cpp
      src/util/strencodings.cpp src/util/chaintype.cpp src/util/threadnames.cpp src/util/time.cpp
      src/support/cleanse.cpp src/univalue/lib/univalue.cpp src/univalue/lib/univalue_read.cpp
      src/univalue/lib/univalue_write.cpp src/univalue/lib/univalue_get.cpp
      contrib/hashfun/difftest/driver.cpp contrib/hashfun/difftest/selftest.cpp contrib/hashfun/difftest/stubs.cpp)
export ROOT OBJ CXX
compile() {
  local o="$OBJ/$(echo "$1" | tr / _).o"
  local fresh=1 dep
  # Rebuild when the source or any header the fork touches is newer than the object.
  for dep in "$1" src/kernel/launch.h src/launchcurve.h src/launchyield.h src/launchyieldstate.h src/consensus/params.h \
             src/kernel/chainparams.h src/pow.h src/crypto/qwork.h; do
    [ "$o" -nt "$ROOT/$dep" ] || fresh=0
  done
  [ "$fresh" = 1 ] && return 0
  # Qwencoin's work function is a quarter of a billion multiply-adds a pass: it gets the vectorizer,
  # as in the node's own build. Everything else is small and compiles fast at -O1.
  local opt=-O1
  [ "$1" = src/crypto/qwork.cpp ] && opt=-O3
  "$CXX" -std=c++20 "$opt" -DDISABLE_OPTIMIZED_SHA256 -I"$ROOT/src" -I"$ROOT/src/univalue/include" \
    -c "$ROOT/$1" -o "$o.tmp" && mv "$o.tmp" "$o"
}
export -f compile
printf '%s\n' "${SRCS[@]}" | xargs -P "$(getconf _NPROCESSORS_ONLN)" -I{} bash -c 'compile {}'
"$CXX" -o "$OUT" "$OBJ"/*.o
echo "$OUT"
