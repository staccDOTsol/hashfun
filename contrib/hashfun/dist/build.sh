#!/usr/bin/env bash
# Build the hashfund that ships in the npm package, for one platform or for all of them.
#
#   bash contrib/hashfun/dist/build.sh [target ...]        default: this machine's own target
#   targets: linux-x64 linux-arm64 darwin-x64 darwin-arm64, or "all"
#   out:     contrib/hashfun/npm/prebuilt/<target>/hashfund    (`hashfun` picks its own at run time)
#
# Two toolchains:
#   zig     zig's clang, which carries the C library and libc++ of every target, so it builds for
#           any of them from any machine with no SDK and no cross packages. This is how the Linux
#           binaries are built: fully static (musl), one file that runs on every distribution.
#           Needs: pip install ziglang (or a zig on PATH).
#   native  this machine's own compiler, for its own system. On a Mac that is Apple's clang, and it
#           is how the macOS binaries are built, in CI (.github/workflows/hashfun.yml) or here.
# TOOLCHAIN=zig|native overrides the default: native for a macOS target on a Mac, zig otherwise.
# A macOS target through zig (from Linux, or on a Mac without Xcode) is wired up and has never
# been built or run: treat its output as untested until `hashfun doctor` has passed on a Mac.
#
# Also needs: cmake, curl, Boost headers (any 1.74+; BOOST_INCLUDE=/dir/that/holds/boost if they
# are not found). SQLite is fetched at the version and hash Bitcoin Core's own depends/ pins and
# linked statically, so the binary depends on nothing but the system itself.
#
#   TESTS=1   also build Bitcoin Core's own unit tests with the same toolchain (bin/test_bitcoin)
#   JOBS=n    parallel compiles (default: every processor)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORK="${DIST_WORK:-$ROOT/build/dist}"
OUT="${DIST_OUT:-$ROOT/contrib/hashfun/npm/prebuilt}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN)}"
TESTS="${TESTS:-0}"
HOST_OS="$(uname -s)"
STACK=8388608   # musl gives a new thread 128 KiB unless the program asks for more; glibc gives 8 MiB

host_target() {
  case "$HOST_OS-$(uname -m)" in
    Linux-x86_64) echo linux-x64 ;;
    Linux-aarch64 | Linux-arm64) echo linux-arm64 ;;
    Darwin-arm64) echo darwin-arm64 ;;
    Darwin-x86_64) if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then echo darwin-arm64; else echo darwin-x64; fi ;;
    *) echo "no target for this machine ($HOST_OS $(uname -m)): name one" >&2; return 1 ;;
  esac
}
sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

[ $# -gt 0 ] || set -- "$(host_target)"
[ "$1" != all ] || set -- linux-x64 linux-arm64 darwin-x64 darwin-arm64
mkdir -p "$WORK/src" "$OUT"

# ---- zig, when a target needs it
ZIG=()
need_zig() {
  [ ${#ZIG[@]} -eq 0 ] || return 0
  local py
  if command -v zig >/dev/null 2>&1; then ZIG=(zig); return 0; fi
  for py in python3 python; do
    if command -v "$py" >/dev/null 2>&1 && "$py" -m ziglang version >/dev/null 2>&1; then ZIG=("$(command -v "$py")" -m ziglang); return 0; fi
  done
  echo "zig not found: pip install ziglang   (or TOOLCHAIN=native for this machine's own compiler)" >&2
  exit 1
}

# ---- Boost: headers only, behind a private prefix so that nothing else of this machine's
# /usr/include is ever on a cross compiler's search path.
if [ -z "${BOOST_INCLUDE:-}" ]; then
  for d in /usr/include "$(brew --prefix boost 2>/dev/null || true)/include" /opt/homebrew/include /usr/local/include; do
    if [ -f "$d/boost/version.hpp" ]; then BOOST_INCLUDE="$d"; break; fi
  done
fi
[ -f "${BOOST_INCLUDE:-}/boost/version.hpp" ] || { echo "Boost headers not found: install them (apt install libboost-dev, brew install boost) or set BOOST_INCLUDE" >&2; exit 1; }
BOOST="$WORK/boost"
mkdir -p "$BOOST/include" "$BOOST/lib/cmake/Boost"
ln -sfn "$BOOST_INCLUDE/boost" "$BOOST/include/boost"
BV="$(sed -n 's/^#define BOOST_LIB_VERSION "\(.*\)"/\1/p' "$BOOST_INCLUDE/boost/version.hpp" | tr _ .)"
cat > "$BOOST/lib/cmake/Boost/BoostConfig.cmake" <<EOF
if(NOT TARGET Boost::headers)
  add_library(Boost::headers INTERFACE IMPORTED)
  set_target_properties(Boost::headers PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "$BOOST/include")
endif()
set(Boost_INCLUDE_DIR "$BOOST/include")
set(Boost_INCLUDE_DIRS "$BOOST/include")
set(Boost_VERSION "$BV.0")
set(Boost_FOUND TRUE)
EOF
cat > "$BOOST/lib/cmake/Boost/BoostConfigVersion.cmake" <<EOF
set(PACKAGE_VERSION "$BV.0")
if(PACKAGE_VERSION VERSION_LESS PACKAGE_FIND_VERSION)
  set(PACKAGE_VERSION_COMPATIBLE FALSE)
else()
  set(PACKAGE_VERSION_COMPATIBLE TRUE)
endif()
EOF

# ---- SQLite, at the version and hash depends/packages/sqlite.mk pins
SQL_VER="$(sed -n 's/^\$(package)_version=//p' "$ROOT/depends/packages/sqlite.mk")"
SQL_SHA="$(sed -n 's/^\$(package)_sha256_hash=//p' "$ROOT/depends/packages/sqlite.mk")"
SQL_URL="$(sed -n 's/^\$(package)_download_path=//p' "$ROOT/depends/packages/sqlite.mk")sqlite-autoconf-$SQL_VER.tar.gz"
TARBALL="${SQLITE_TARBALL:-$WORK/src/sqlite-autoconf-$SQL_VER.tar.gz}"
[ -f "$TARBALL" ] || curl -fsSL --retry 3 -o "$TARBALL" "$SQL_URL"
[ "$(sha256_of "$TARBALL")" = "$SQL_SHA" ] || { echo "sqlite tarball $TARBALL: hash $(sha256_of "$TARBALL") is not the pinned $SQL_SHA" >&2; exit 1; }
[ -f "$WORK/src/sqlite/sqlite3.c" ] || { mkdir -p "$WORK/src/sqlite" && tar -xzf "$TARBALL" -C "$WORK/src/sqlite" --strip-components=1; }
# the options depends/packages/sqlite.mk builds it with
SQL_DEFS="-DSQLITE_DQS=0 -DSQLITE_DEFAULT_MEMSTATUS=0 -DSQLITE_OMIT_DEPRECATED -DSQLITE_OMIT_SHARED_CACHE -DSQLITE_OMIT_JSON
  -DSQLITE_LIKE_DOESNT_MATCH_BLOBS -DSQLITE_OMIT_DECLTYPE -DSQLITE_OMIT_PROGRESS_CALLBACK -DSQLITE_OMIT_AUTOINIT
  -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_THREADSAFE=1"
# the oldest macOS Bitcoin Core itself supports (depends/hosts/darwin.mk)
MACOS_MIN="$(sed -n 's/^OSX_MIN_VERSION=//p' "$ROOT/depends/hosts/darwin.mk")"

build() {
  local name="$1" sys triple sysname proc toolchain
  sys="${name%-*}"
  case "$name" in
    linux-x64)    triple=x86_64-linux-musl;           sysname=Linux;  proc=x86_64 ;;
    linux-arm64)  triple=aarch64-linux-musl;          sysname=Linux;  proc=aarch64 ;;
    darwin-x64)   triple="x86_64-macos.$MACOS_MIN";   sysname=Darwin; proc=x86_64 ;;
    darwin-arm64) triple="aarch64-macos.$MACOS_MIN";  sysname=Darwin; proc=arm64 ;;
    *) echo "unknown target $name (linux-x64 linux-arm64 darwin-x64 darwin-arm64)" >&2; exit 1 ;;
  esac
  toolchain="${TOOLCHAIN:-}"
  if [ -z "$toolchain" ]; then
    if [ "$sys" = darwin ] && [ "$HOST_OS" = Darwin ]; then toolchain=native; else toolchain=zig; fi
  fi
  local tag="$name"
  [ "$toolchain" = zig ] || tag="$name-native"
  local tc="$WORK/tc/$name" deps="$WORK/deps/$tag" bld="$WORK/build/$tag"
  mkdir -p "$tc" "$deps/include" "$deps/lib" "$bld"
  local -a cmake_args sql_cc sql_ar
  cmake_args=(-DCMAKE_BUILD_TYPE=Release -DBoost_DIR="$BOOST/lib/cmake/Boost"
    -DSQLite3_INCLUDE_DIR="$deps/include" -DSQLite3_LIBRARY="$deps/lib/libsqlite3.a"
    -DBUILD_BENCH=OFF -DBUILD_GUI=OFF -DENABLE_IPC=OFF -DWITH_ZMQ=OFF -DBUILD_CLI=OFF -DBUILD_TX=OFF -DBUILD_UTIL=OFF
    -DBUILD_WALLET_TOOL=OFF -DENABLE_EXTERNAL_SIGNER=OFF -DBUILD_KERNEL_LIB=OFF -DBUILD_BITCOIN_BIN=OFF -DBUILD_FUZZ_BINARY=OFF
    -DINSTALL_MAN=OFF)
  if [ "$TESTS" = 1 ]; then cmake_args+=(-DBUILD_TESTS=ON); else cmake_args+=(-DBUILD_TESTS=OFF); fi

  if [ "$toolchain" = zig ]; then
    need_zig
    # One-word compilers for CMake.
    #   -UNDEBUG: zig defines NDEBUG when optimizing, and Bitcoin Core refuses to build without
    #   its assertions (they are consensus checks).
    #   -march=armv8-a+crypto and the like: zig's clang reads -march= as a processor name, not as
    #   GCC's "architecture+extensions", and would fail the probe for the ARM SHA-256 and CRC
    #   instructions (the node would then hash in plain C). Say it in clang's own terms.
    local tool
    for tool in cc c++; do
      cat > "$tc/$tool" <<EOF
#!/bin/sh
export ZIG_GLOBAL_CACHE_DIR="$WORK/zig-global" ZIG_LOCAL_CACHE_DIR="$WORK/zig-local"
n=\$#
for a in "\$@"; do
  case "\$a" in
    -march=armv8-a+*)
      old="\$IFS"; IFS=+
      for f in \${a#-march=armv8-a+}; do
        case "\$f" in
          crypto) set -- "\$@" -Xclang -target-feature -Xclang +sha2 -Xclang -target-feature -Xclang +aes ;;
          *) set -- "\$@" -Xclang -target-feature -Xclang "+\$f" ;;
        esac
      done
      IFS="\$old" ;;
    *) set -- "\$@" "\$a" ;;
  esac
done
shift "\$n"
exec ${ZIG[*]} $tool -target $triple -UNDEBUG "\$@"
EOF
    done
    for tool in ar ranlib; do
      printf '#!/bin/sh\nexport ZIG_GLOBAL_CACHE_DIR="%s/zig-global" ZIG_LOCAL_CACHE_DIR="%s/zig-local"\nexec %s %s "$@"\n' \
        "$WORK" "$WORK" "${ZIG[*]}" "$tool" > "$tc/$tool"
    done
    chmod +x "$tc/cc" "$tc/c++" "$tc/ar" "$tc/ranlib"
    cat > "$tc/toolchain.cmake" <<EOF
set(CMAKE_SYSTEM_NAME $sysname)
set(CMAKE_SYSTEM_PROCESSOR $proc)
set(CMAKE_C_COMPILER "$tc/cc")
set(CMAKE_CXX_COMPILER "$tc/c++")
set(CMAKE_AR "$tc/ar" CACHE FILEPATH "")
set(CMAKE_RANLIB "$tc/ranlib" CACHE FILEPATH "")
set(CMAKE_FIND_ROOT_PATH "$deps;$BOOST")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(CMAKE_OSX_SYSROOT "" CACHE STRING "")              # zig brings its own
set(CMAKE_OSX_DEPLOYMENT_TARGET "" CACHE STRING "")
set(CMAKE_USER_MAKE_RULES_OVERRIDE "$tc/rules.cmake")
EOF
    # CMake learns a compiler's "implicit" libraries by watching it link once (with -v), and for
    # zig those are files in zig's cache, built for that one probe (not position independent).
    # CMake then names the C compiler's set on the command line of every C++ link, where they
    # shadow the ones zig itself picks for that link. zig needs no help: without a verbose flag
    # CMake has nothing to watch and records none.
    cat > "$tc/rules.cmake" <<EOF
set(CMAKE_C_VERBOSE_FLAG "")
set(CMAKE_CXX_VERBOSE_FLAG "")
EOF
    cmake_args+=(-DCMAKE_TOOLCHAIN_FILE="$tc/toolchain.cmake" -DWITH_CCACHE=OFF)
    # -s: the linker leaves out symbols and debug sections (zig's own runtime libraries carry them)
    [ "$sys" != linux ] || cmake_args+=(-DCMAKE_EXE_LINKER_FLAGS="-s -Wl,-z,stack-size=$STACK")
    sql_cc=("$tc/cc"); sql_ar=("$tc/ar")
  else
    case "$sys-$HOST_OS" in
      darwin-Darwin)
        cmake_args+=(-DCMAKE_OSX_ARCHITECTURES="$proc" -DCMAKE_OSX_DEPLOYMENT_TARGET="$MACOS_MIN")
        sql_cc=(cc -arch "$proc" "-mmacosx-version-min=$MACOS_MIN"); sql_ar=(ar) ;;
      linux-Linux)
        [ "$name" = "$(host_target)" ] || { echo "TOOLCHAIN=native builds for this machine only; $name needs TOOLCHAIN=zig" >&2; exit 1; }
        sql_cc=(cc); sql_ar=(ar) ;;
      *) echo "TOOLCHAIN=native cannot build $name on $HOST_OS: use TOOLCHAIN=zig" >&2; exit 1 ;;
    esac
  fi

  if [ ! -f "$deps/lib/libsqlite3.a" ]; then
    echo "== $name: sqlite $SQL_VER"
    # shellcheck disable=SC2086
    "${sql_cc[@]}" -O2 -fPIC -c "$WORK/src/sqlite/sqlite3.c" -o "$deps/sqlite3.o" $SQL_DEFS   # -fPIC: the node links as a PIE
    "${sql_ar[@]}" rcs "$deps/lib/libsqlite3.a" "$deps/sqlite3.o"
    cp "$WORK/src/sqlite/sqlite3.h" "$deps/include/"
  fi

  echo "== $name: configure ($toolchain)"
  cmake -S "$ROOT" -B "$bld" "${cmake_args[@]}" > "$bld.configure.log" 2>&1 || { tail -n 40 "$bld.configure.log" >&2; exit 1; }
  local -a targets
  targets=(bitcoind)
  [ "$TESTS" != 1 ] || targets+=(test_bitcoin)
  echo "== $name: build ${targets[*]} ($JOBS jobs)"
  cmake --build "$bld" -j"$JOBS" --target "${targets[@]}" > "$bld.build.log" 2>&1 ||
    { grep -E "error|Error|undefined" "$bld.build.log" | head -n 40 >&2; tail -n 5 "$bld.build.log" >&2; exit 1; }

  local bin="$OUT/$name/hashfund"
  mkdir -p "$OUT/$name"
  rm -f "$bin"
  cp "$bld/bin/hashfund" "$bin"
  if [ "$sys" = linux ]; then
    [ "$toolchain" = zig ] || strip "$bin"    # zig's link already stripped it
  elif [ "$HOST_OS" = Darwin ]; then
    # Local symbols out; that breaks the linker's signature, and an ARM Mac runs nothing unsigned.
    strip -x "$bin"
    codesign --force --sign - "$bin"
    codesign --verify --strict "$bin"
  fi
  chmod 755 "$bin"
  [ "$TESTS" != 1 ] || { mkdir -p "$WORK/tests/$name" && cp "$bld/bin/test_bitcoin" "$WORK/tests/$name/test_bitcoin"; }
  echo "== $name: $(wc -c < "$bin" | tr -d ' ') bytes, sha256 $(sha256_of "$bin")"
}
for t in "$@"; do build "$t"; done
