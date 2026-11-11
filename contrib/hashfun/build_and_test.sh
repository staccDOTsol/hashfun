#!/usr/bin/env bash
# First run on a machine of your own: get the source, build the node binary for this machine and
# test it. It installs nothing: when a tool is missing it prints the line that installs it.
#
#   bash build_and_test.sh [workdir]          next to make_repo.sh and patches/: clones the pinned
#                                             namecoin-core and applies the patches in
#                                             workdir/hashfun-core (default ~/hashfun-work)
#   bash contrib/hashfun/build_and_test.sh    inside the source tree: builds and tests that tree
#   ... --check                               only check the tools and say what would be done
#
# Either way it then runs the two scripts CI runs (.github/workflows/hashfun.yml):
#   bash contrib/hashfun/dist/build.sh        hashfund for this machine, where the CLI looks for it
#   bash contrib/hashfun/ci/test.sh unit diff doctor e2e
#                                             e2e needs a stock bitcoind: on PATH, or BITCOIND=/path
#
# Linux builds with zig when it is installed (pip install ziglang): that is the static binary the
# npm package ships. Without zig it falls back to this machine's own compiler. A Mac builds with
# Apple's compiler and needs its command line tools at 26.3 or newer (doc/dependencies.md).
# TOOLCHAIN=zig or TOOLCHAIN=native picks one explicitly. zig needs no Xcode at all, but building
# the macOS binary with it has not been tried: on a Mac this script has not been run by its author.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CHECK=0
WORK=""
for arg in "$@"; do
  case "$arg" in
    --check) CHECK=1 ;;
    -h | --help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option $arg (--check, --help)" >&2; exit 1 ;;
    *) WORK="$arg" ;;
  esac
done
OS="$(uname -s)"
log() { printf '\n== %s ==\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

if [ -d "$HERE/patches" ] && [ -f "$HERE/make_repo.sh" ]; then
  MODE=patches
  WORK="${WORK:-$HOME/hashfun-work}"
  ROOT="$WORK/hashfun-core"
elif [ -f "$HERE/dist/build.sh" ] && [ -f "$HERE/../../src/kernel/launch.cpp" ]; then
  MODE=tree
  ROOT="$(cd "$HERE/../.." && pwd)"
else
  echo "run this next to make_repo.sh and patches/, or as contrib/hashfun/build_and_test.sh inside the source tree" >&2
  exit 1
fi

# ---------------------------------------------------------------- tools
log "tools"
MISSING=""    # what the install line has to name
STOP=""       # anything else that has to be fixed first
need() { MISSING="$MISSING $1"; }
have cmake || need cmake
have curl || need curl
if [ "$MODE" = patches ] && ! have git; then need git; fi

BOOST=""
for d in "${BOOST_INCLUDE:-}" /usr/include "$( (brew --prefix boost 2>/dev/null) || true)/include" /opt/homebrew/include /usr/local/include; do
  if [ -n "$d" ] && [ -f "$d/boost/version.hpp" ]; then BOOST="$d"; break; fi
done
[ -n "$BOOST" ] || need boost

# The python3 that ships with macOS is 3.9 on LibreSSL (no scrypt for the wallet file): look past it.
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  for c in python3 python3.14 python3.13 python3.12 python3.11 python3.10 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    if have "$c" && "$c" -c 'import sys, hashlib; sys.exit(0 if sys.version_info >= (3, 10) and hasattr(hashlib, "scrypt") else 1)' 2>/dev/null; then
      PY="$c"; break
    fi
  done
fi
[ -n "$PY" ] || need python

# zig the way dist/build.sh looks for it: on PATH, or as the ziglang module of python3 or python
ZIG=""
if have zig; then ZIG="zig $(zig version 2>/dev/null || true)"
else
  for c in python3 python; do
    if have "$c" && "$c" -m ziglang version >/dev/null 2>&1; then ZIG="$c -m ziglang, zig $("$c" -m ziglang version)"; break; fi
  done
fi

TC="${TOOLCHAIN:-}"
if [ -z "$TC" ]; then
  if [ "$OS" = Darwin ] || [ -z "$ZIG" ]; then TC=native; else TC=zig; fi
fi
case "$TC" in
  zig)
    if [ -z "$ZIG" ]; then STOP="${STOP}zig is not installed: pip install ziglang (in a virtualenv if pip refuses: python3 -m venv ~/zig && ~/zig/bin/pip install ziglang, then put ~/zig/bin first on PATH)
"; fi ;;
  native)
    if [ "$OS" = Darwin ]; then
      # Apple's tools carry the Xcode version: of the selected Xcode, or of the command line tools
      DEV="$(xcode-select -p 2>/dev/null || true)"
      XV=""
      case "$DEV" in
        "") STOP="${STOP}Apple's command line tools are not installed: xcode-select --install
" ;;
        */Xcode*.app/*) XV="$( (xcodebuild -version 2>/dev/null || true) | sed -n 's/^Xcode //p' | head -n 1)" ;;
        *) XV="$( (pkgutil --pkg-info=com.apple.pkg.CLTools_Executables 2>/dev/null || true) | sed -n 's/^version: //p' | head -n 1)" ;;
      esac
      if [ -n "$DEV" ]; then
        XMAJ="${XV%%.*}"; XMIN=0
        case "$XV" in *.*) XREST="${XV#*.}"; XMIN="${XREST%%.*}" ;; esac
        case "$XMAJ.$XMIN" in
          *[!0-9.]* | .* | *.)
            echo "could not read the version of Apple's tools at $DEV (this Bitcoin Core needs 26.3 or newer): trying anyway" ;;
          *)
            if [ "$XMAJ" -lt 26 ] || { [ "$XMAJ" -eq 26 ] && [ "$XMIN" -lt 3 ]; }; then
              STOP="${STOP}Apple's developer tools here are version $XV; this Bitcoin Core needs 26.3 or newer (doc/dependencies.md).
  Update them (System Settings, Software Update), or build with zig, which needs no Xcode but has not
  been tried on a Mac: pip install ziglang and set TOOLCHAIN=zig
"
            fi ;;
        esac
      fi
    else
      CXXBIN="$(command -v c++ || command -v g++ || command -v clang++ || true)"
      if [ -z "$CXXBIN" ]; then need compiler
      else
        CXXV="$("$CXXBIN" -dumpversion 2>/dev/null || true)"; CXXMAJ="${CXXV%%.*}"
        case "$CXXMAJ" in "" | *[!0-9]*) CXXMAJ=0 ;; esac
        if "$CXXBIN" --version 2>/dev/null | head -n 1 | grep -qi clang; then CXXMIN=19; CXXNAME=clang; else CXXMIN=12; CXXNAME=g++; fi
        if [ "$CXXMAJ" -gt 0 ] && [ "$CXXMAJ" -lt "$CXXMIN" ]; then
          STOP="${STOP}$CXXNAME $CXXV is too old for this Bitcoin Core ($CXXNAME $CXXMIN or newer, doc/dependencies.md). zig brings its own
  compiler and builds the static binary the package ships: pip install ziglang
"
        fi
      fi
    fi ;;
  *) echo "TOOLCHAIN=$TC: zig or native" >&2; exit 1 ;;
esac

if [ -n "$MISSING" ]; then
  PKGS=""
  for m in $MISSING; do
    if [ "$OS" = Darwin ]; then
      case "$m" in compiler) ;; *) PKGS="$PKGS $m" ;; esac    # boost, cmake, python, git, curl: brew's names
    else
      case "$m" in boost) PKGS="$PKGS libboost-dev" ;; python) PKGS="$PKGS python3" ;; compiler) PKGS="$PKGS build-essential" ;; *) PKGS="$PKGS $m" ;; esac
    fi
  done
  echo "missing:$MISSING"
  if [ "$OS" = Darwin ]; then echo "  brew install$PKGS"
  elif have apt-get; then echo "  sudo apt-get install -y$PKGS"
  else echo "  install these with your distribution's package manager (Debian's names):$PKGS"; fi
  [ -n "$PY" ] || echo "  (Python has to be 3.10 or newer and built with OpenSSL; PYTHON=/path/to/python names one)"
fi
[ -z "$STOP" ] || printf '%s' "$STOP"
if [ -n "$MISSING" ] || [ -n "$STOP" ]; then echo "then run this again."; exit 1; fi

BTC="${BITCOIND:-$(command -v bitcoind || true)}"
echo "python    $("$PY" --version 2>&1) ($PY)"
echo "cmake     $(cmake --version | head -n 1 | sed 's/^cmake version //')"
echo "boost     $BOOST"
echo "toolchain $TC${ZIG:+ (zig: $ZIG)}"
echo "bitcoind  ${BTC:-none: the end to end test will be left out (BITCOIND=/path/to/bitcoind, a stock Bitcoin Core)}"
echo "source    $ROOT$([ "$MODE" = patches ] && echo " (the pinned namecoin-core + patches/)")"
if [ "$TC" = native ] && [ "$OS" != Darwin ]; then
  echo "note      zig is not installed, so this builds with the machine's own compiler: a binary for this"
  echo "          machine, not the static one the package ships. Do not pack or publish it."
fi
if [ "$CHECK" = 1 ]; then echo; echo "tools are fine. Without --check this would build with the $TC toolchain and run: unit diff doctor${BTC:+ e2e}"; exit 0; fi

# ---------------------------------------------------------------- source
if [ "$MODE" = patches ]; then
  log "source: pinned namecoin-core + patches/"
  WANT=0
  LAST=""
  for f in "$HERE"/patches/*.patch; do
    if [ -f "$f" ]; then WANT=$((WANT + 1)); LAST="$f"; fi
  done
  [ "$WANT" -gt 0 ] || { echo "no patches in $HERE/patches" >&2; exit 1; }
  if [ -d "$ROOT/.git" ]; then
    # an earlier run left a tree: it must be the tree of these patches, not of an older set
    BASE="$(sed -n 's/^BASE=\([0-9a-f]\{40\}\).*/\1/p' "$HERE/make_repo.sh")"
    HAVE="$(git -C "$ROOT" rev-list --count "$BASE"..HEAD 2>/dev/null || echo unknown)"
    TOP="$(git -C "$ROOT" log -1 --format=%s 2>/dev/null || true)"
    SUBJECT="$(sed -n 's/^Subject: \[PATCH[^]]*\] //p' "$LAST" | head -n 1)"
    case "$TOP" in "$SUBJECT"*) SAME=1 ;; *) SAME=0 ;; esac
    if [ "$HAVE" != "$WANT" ] || [ "$SAME" != 1 ]; then
      if [ "$HAVE" != "$WANT" ]; then echo "$ROOT was made from another set of patches ($HAVE commits there, $WANT patches here)." >&2
      else echo "$ROOT was made from another set of patches (its newest commit is \"$TOP\", the newest patch here is \"$SUBJECT\")." >&2; fi
      echo "Move it away, or name another workdir, so that these patches are what gets built: bash $0 <workdir>" >&2
      exit 1
    fi
    echo "using $ROOT ($HAVE commits on the pinned base, same as patches/)"
  else
    mkdir -p "$WORK"
    (cd "$WORK" && bash "$HERE/make_repo.sh" hashfun-core)
  fi
fi

# ---------------------------------------------------------------- build, test
log "build hashfund for this machine ($TC; a first build takes 10 to 40 minutes)"
(cd "$ROOT" && TOOLCHAIN="$TC" bash contrib/hashfun/dist/build.sh)

log "test"
SUITES="unit diff doctor"
if [ -n "$BTC" ]; then SUITES="$SUITES e2e"; export BITCOIND="$BTC"; fi
export PYTHON="$PY"
RC=0
# shellcheck disable=SC2086
(cd "$ROOT" && bash contrib/hashfun/ci/test.sh $SUITES) || RC=$?

if [ "$RC" -eq 0 ]; then
  printf '\nbuilt and tested. The CLI finds this binary by itself:\n'
  printf '  cd %s && %s -m hashfun.cli doctor\n' "$ROOT" "$PY"
  printf 'the rest of the regression (node fleet, swaps, the site in browsers): bash contrib/hashfun/ci/test.sh\n'
fi
exit "$RC"
