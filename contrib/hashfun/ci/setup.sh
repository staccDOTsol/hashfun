#!/usr/bin/env bash
# What a fresh CI machine (GitHub's Ubuntu and macOS runners) needs before dist/build.sh and
# ci/test.sh: build tools and Boost headers, a virtualenv with zig and playwright, the site's npm
# packages, and a stock bitcoind for the Bitcoin side of the tests (the official release, pinned
# by the hash bitcoincore.org publishes for it).
#
#   bash contrib/hashfun/ci/setup.sh [--minimal]
#   --minimal: only a Python and the bitcoind (enough to run an installed `hashfun` and the smoke test)
#   export PATH="$PWD/build/tools/venv/bin:$PWD/build/tools/bin:$PATH" BITCOIND="$PWD/build/tools/bin/bitcoind"
# (under GitHub Actions the script exports those itself, for the steps that follow)
#
# It installs system packages (apt or Homebrew): meant for a CI machine or a throwaway one.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOLS="${HASHFUN_TOOLS:-$ROOT/build/tools}"
ZIG_VERSION="${ZIG_VERSION:-0.17.1}"
BITCOIN_CORE=32.1
MINIMAL=0
[ "${1:-}" != --minimal ] || MINIMAL=1
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  triple=x86_64-linux-gnu;    sha=61545c17c3120fb7412f896d248b11993af04ec8817aad3649c55b2afb044963 ;;
  Linux-aarch64) triple=aarch64-linux-gnu;   sha=7ed37c7373eb6aa3e3f72842596a1afeba1b223717033cade9842b25773e1922 ;;
  Darwin-arm64)  triple=arm64-apple-darwin;  sha=cd3dcdacb4ff861e862b2d7df4786ecef66472e2468dca1673a70dd761e064e7 ;;
  Darwin-x86_64) triple=x86_64-apple-darwin; sha=53b1e6ffd92843ca82ef4a737d7a53cb0a9fab15816a417a41f12fc954071447 ;;
  *) echo "no setup for $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac
sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
mkdir -p "$TOOLS/bin"

if [ "$(uname -s)" = Darwin ]; then
  # This Bitcoin Core wants a recent Apple clang (doc/dependencies.md): take the newest Xcode 26 a
  # runner has, as upstream's own CI does.
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    xcode="$(ls -d /Applications/Xcode_26*.app 2>/dev/null | sort -V | tail -n 1 || true)"
    [ -z "$xcode" ] || sudo xcode-select --switch "$xcode"
  fi
  clang --version | head -n 1
  export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1
  brew install --quiet python@3 || brew link --overwrite python@3
  if [ "$MINIMAL" = 0 ]; then
    command -v cmake >/dev/null 2>&1 || brew install --quiet cmake
    command -v ccache >/dev/null 2>&1 || brew install --quiet ccache
    [ -f "$(brew --prefix)/include/boost/version.hpp" ] || brew install --quiet boost
  fi
else
  sudo apt-get update -qq
  if [ "$MINIMAL" = 0 ]; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      build-essential cmake libboost-dev python3 python3-venv curl ca-certificates git
  else
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends python3 python3-venv curl ca-certificates
  fi
fi

# Python in a virtualenv: zig (the compiler for the Linux binaries) and playwright (the browser test)
[ -x "$TOOLS/venv/bin/python" ] || python3 -m venv "$TOOLS/venv"
if [ "$MINIMAL" = 0 ]; then
  "$TOOLS/venv/bin/python" -m pip install --quiet --upgrade pip
  "$TOOLS/venv/bin/python" -m pip install --quiet "ziglang==$ZIG_VERSION" playwright
  "$TOOLS/venv/bin/python" -m playwright install --with-deps chromium
fi

# bitcoind
if [ ! -x "$TOOLS/bin/bitcoind" ]; then
  tgz="$TOOLS/bitcoin-$BITCOIN_CORE-$triple.tar.gz"
  curl -fsSL --retry 3 -o "$tgz" "https://bitcoincore.org/bin/bitcoin-core-$BITCOIN_CORE/bitcoin-$BITCOIN_CORE-$triple.tar.gz"
  [ "$(sha256_of "$tgz")" = "$sha" ] || { echo "$tgz: hash $(sha256_of "$tgz") is not the pinned $sha" >&2; exit 1; }
  mkdir -p "$TOOLS/bitcoin"
  tar -xzf "$tgz" -C "$TOOLS/bitcoin" --strip-components=1
  ln -sf "$TOOLS/bitcoin/bin/bitcoind" "$TOOLS/bin/bitcoind"
fi
"$TOOLS/bin/bitcoind" -version | head -n 1

# the site's build and test packages
[ "$MINIMAL" = 1 ] || (cd "$ROOT/hashfun/web" && npm ci --no-audit --no-fund)

if [ -n "${GITHUB_PATH:-}" ]; then
  # the virtualenv's own bin directory: a link to its python from elsewhere would not be the virtualenv
  echo "$TOOLS/bin" >> "$GITHUB_PATH"
  echo "$TOOLS/venv/bin" >> "$GITHUB_PATH"
  echo "BITCOIND=$TOOLS/bin/bitcoind" >> "$GITHUB_ENV"
  echo "CCACHE_DIR=$ROOT/build/ccache" >> "$GITHUB_ENV"
fi
echo "tools ready: $TOOLS/venv/bin (python with zig and playwright), $TOOLS/bin/bitcoind"
