#!/usr/bin/env bash
# Build the hashfun differential driver: the node's own consensus sources
# (descriptor/identity, chain params + genesis, curve, LWMA) compiled directly,
# without CMake or the rest of the node. Used by hashfun/tests/test_diff_cpp.py.
#
#   bash contrib/hashfun/difftest/build.sh [out-binary]      # default build/hfdiff
#   HFDIFF=build/hfdiff python3 -m unittest hashfun.tests.test_diff_cpp -v
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT="$(realpath -m "${1:-$ROOT/build/hfdiff}")"
OBJ="$OUT-obj"
CXX="${CXX:-g++}"
mkdir -p "$OBJ"
SRCS=(src/kernel/launch.cpp src/launchcurve.cpp src/launchyield.cpp src/pow.cpp src/chain.cpp src/kernel/chainparams.cpp
      src/primitives/block.cpp src/primitives/pureheader.cpp src/primitives/transaction.cpp src/auxpow.cpp
      src/consensus/merkle.cpp src/script/script.cpp src/hash.cpp src/crypto/sha256.cpp src/crypto/ripemd160.cpp
      src/crypto/sha512.cpp src/crypto/hmac_sha512.cpp src/crypto/hex_base.cpp src/uint256.cpp src/arith_uint256.cpp
      src/util/strencodings.cpp src/util/chaintype.cpp src/util/threadnames.cpp src/util/time.cpp
      src/support/cleanse.cpp src/univalue/lib/univalue.cpp src/univalue/lib/univalue_read.cpp
      src/univalue/lib/univalue_write.cpp src/univalue/lib/univalue_get.cpp
      contrib/hashfun/difftest/driver.cpp contrib/hashfun/difftest/stubs.cpp)
export ROOT OBJ CXX
compile() {
  local o="$OBJ/$(echo "$1" | tr / _).o"
  local fresh=1 dep
  # Rebuild when the source or any header the fork touches is newer than the object.
  for dep in "$1" src/kernel/launch.h src/launchcurve.h src/launchyield.h src/consensus/params.h src/kernel/chainparams.h src/pow.h; do
    [ "$o" -nt "$ROOT/$dep" ] || fresh=0
  done
  [ "$fresh" = 1 ] && return 0
  "$CXX" -std=c++20 -O1 -DDISABLE_OPTIMIZED_SHA256 -I"$ROOT/src" -I"$ROOT/src/univalue/include" \
    -c "$ROOT/$1" -o "$o.tmp" && mv "$o.tmp" "$o"
}
export -f compile
printf '%s\n' "${SRCS[@]}" | xargs -P "$(nproc)" -I{} bash -c 'compile {}'
"$CXX" -o "$OUT" "$OBJ"/*.o
echo "$OUT"
