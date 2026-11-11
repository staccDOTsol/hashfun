#!/usr/bin/env bash
# Rebuild the hashfun-core repository from the pinned upstream commit plus the patch series,
# and (optionally) publish it:
#
#   bash make_repo.sh [dir]              # clone + apply into ./hashfun-core (or dir)
#   PUSH=owner/name bash make_repo.sh    # also create that GitHub repository (private) and push
#
# Needs git; pushing needs the GitHub CLI (gh) logged in. Run it next to the patches/ folder.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-hashfun-core}"
BASE=70c6b3698ef8357f6c04004e57c06a85856e3f27    # namecoin-core, branch auxpow (Bitcoin Core 32.99 + AuxPoW)
[ -d "$HERE/patches" ] || { echo "patches/ not found next to this script" >&2; exit 1; }
[ -e "$DIR" ] && { echo "$DIR already exists" >&2; exit 1; }
git clone https://github.com/namecoin/namecoin-core.git "$DIR"
cd "$DIR"
git checkout -q -b hashfun "$BASE"
git am --committer-date-is-author-date "$HERE"/patches/*.patch
git remote rename origin upstream
echo "ok: $(git rev-list --count "$BASE"..HEAD) commits on top of $BASE in $DIR (branch hashfun)"
if [ -n "${PUSH:-}" ]; then
  gh repo create "$PUSH" --private --source=. --remote=origin
  git push -u origin hashfun
  echo "pushed to https://github.com/$PUSH (private; change visibility in the repository settings)"
fi
echo "build: cmake -B build -DBUILD_TESTS=OFF -DBUILD_BENCH=OFF -DBUILD_GUI=OFF -DENABLE_IPC=OFF && cmake --build build -j4 --target bitcoind bitcoin-cli"
