#!/usr/bin/env bash
# Rebuild the hashfun-core repository from the pinned upstream commit plus the patch series,
# and (optionally) publish it:
#
#   bash make_repo.sh [dir]              # clone + apply into ./hashfun-core (or dir)
#   PUSH=owner/name bash make_repo.sh    # also create that GitHub repository (private) and push
#   PUSH=owner/name VISIBILITY=public bash make_repo.sh
#
# The push starts the build of the node for every platform (.github/workflows/hashfun.yml).
# GitHub's runners are free for a public repository; on a private one the minutes come out of
# the plan's allowance and a macOS minute counts as about ten.
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
# git am needs a committer; use the configured one, or a placeholder on a machine without one
ID=(); git config user.email >/dev/null || ID=(-c user.name=hashfun -c user.email=hashfun@localhost)
git ${ID[@]+"${ID[@]}"} am --committer-date-is-author-date "$HERE"/patches/*.patch
git remote rename origin upstream
echo "ok: $(git rev-list --count "$BASE"..HEAD) commits on top of $BASE in $DIR (branch hashfun)"
if [ -n "${PUSH:-}" ]; then
  VIS="${VISIBILITY:-private}"
  case "$VIS" in public | private) ;; *) echo "VISIBILITY is public or private, not $VIS" >&2; exit 1 ;; esac
  gh repo create "$PUSH" "--$VIS" --source=. --remote=origin
  git push -u origin hashfun
  echo "pushed to https://github.com/$PUSH ($VIS). The push started the build: https://github.com/$PUSH/actions"
  echo "  watch it:            gh run watch -R $PUSH"
  echo "  the npm tarball:     gh run download -R $PUSH -n npm-package      (when the run is green)"
  echo "  publish from a tag:  gh secret set NPM_TOKEN -R $PUSH < file-with-your-npm-token"
  echo "                       git tag v0.1.0 && git push origin v0.1.0"
fi
echo "build here: bash contrib/hashfun/dist/build.sh    test: bash contrib/hashfun/ci/test.sh"
