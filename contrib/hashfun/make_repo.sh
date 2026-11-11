#!/usr/bin/env bash
# Rebuild the hashfun-core repository from the pinned upstream commit plus the patch series:
#
#   bash make_repo.sh [dir]      # into ./hashfun-core (or dir)
#
# Run it again whenever a new set of patches arrives: it rebuilds the branch `hashfun` in the same
# folder (the first run clones namecoin-core, a few hundred MB; later runs take seconds). The same
# patches give the same commits on every machine, so a rebuild that changes nothing moves nothing.
#
# To put it on GitHub and release it, use deploy.sh next to this script. (PUSH=owner/name still
# works here: it rebuilds, then creates or reuses that repository and pushes through deploy.sh,
# private unless VISIBILITY=public, without tagging a release; deploy.sh asks before it does.)
#
# Needs git. Run it next to the patches/ folder. Written for the bash that macOS ships (3.2).
#
# Settings, all optional:
#   OWN_IDENTITY=1     commit as the git user configured on this machine. By default the commits
#                      are made as "hashfun <hashfun@localhost>": that keeps your name and e-mail
#                      out of a repository you may publish, and makes the commits reproducible.
#   HASHFUN_UPSTREAM, HASHFUN_BASE   another place to clone from, another commit to build on
#                      (for testing this script)
[ -n "${BASH_VERSION:-}" ] || exec bash "$0" "$@"   # started with sh or zsh: this is a bash script
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"
DIR="${1:-hashfun-core}"
# (build_and_test.sh reads the next line: keep it a plain BASE=<40 hex digits>)
BASE=70c6b3698ef8357f6c04004e57c06a85856e3f27    # namecoin-core, branch auxpow (Bitcoin Core 32.99 + AuxPoW)
BASE="${HASHFUN_BASE:-$BASE}"
UPSTREAM="${HASHFUN_UPSTREAM:-https://github.com/namecoin/namecoin-core.git}"
BRANCH=hashfun

die() {
  printf '\nstopped: %s\n' "$1" >&2
  shift
  while [ $# -gt 0 ]; do
    printf '  %s\n' "$1" >&2
    shift
  done
  exit 1
}

command -v git > /dev/null 2>&1 || die "git is not installed" "fix (macOS): xcode-select --install"
[ -d "$HERE/patches" ] || die "patches/ not found next to this script ($HERE)"
set -- "$HERE"/patches/*.patch
[ -f "$1" ] || die "no .patch files in $HERE/patches"
NPATCH=$#
# what this set of patches is, in one id: a rebuild is skipped when nothing changed
SERIES="$(cat "$@" | git hash-object --stdin)"

# ---- the folder: clone once, reuse afterwards ---------------------------------------------------
if [ ! -e "$DIR" ]; then
  # into a side folder first, so that a clone cut short never looks like a finished one
  rm -rf "${DIR:?}.partial"
  echo "cloning $UPSTREAM (a few hundred MB, once) ..."
  git clone "$UPSTREAM" "$DIR.partial" || die "the clone of $UPSTREAM failed (see above)" "check the network and run this again"
  git -C "$DIR.partial" remote rename origin upstream
  mv "$DIR.partial" "$DIR"
elif [ ! -d "$DIR/.git" ]; then
  die "$DIR exists and is not a git repository" "move it away, or name another folder: bash make_repo.sh <dir>"
fi
cd "$DIR"
if ! git cat-file -e "$BASE^{commit}" 2> /dev/null; then
  # an older clone, or upstream moved on: ask for the commit itself
  REMOTE_UP=upstream
  git remote get-url upstream > /dev/null 2>&1 || REMOTE_UP=origin
  git fetch -q "$REMOTE_UP" 2> /dev/null || true
  git cat-file -e "$BASE^{commit}" 2> /dev/null || git fetch -q "$REMOTE_UP" "$BASE" 2> /dev/null || true
  git cat-file -e "$BASE^{commit}" 2> /dev/null ||
    die "$DIR does not contain the commit the patches are made for ($BASE)" "it is not a clone of namecoin-core: move it away and run this again"
fi

# The commits must come out the same whatever this machine's git settings are: a fixed committer,
# no signing, no hooks, no line-ending or whitespace rewriting (and --keep-cr below: without it
# git drops the carriage returns of a file that has them, and the tree is another one). The
# identity is also what lets git abort a half-applied series on a machine that has none set.
CFG=(-c commit.gpgsign=false -c core.hooksPath=/dev/null -c core.autocrlf=false -c advice.detachedHead=false)
if [ "${OWN_IDENTITY:-0}" != 1 ] || ! git config user.email > /dev/null; then
  CFG=("${CFG[@]}" -c user.name=hashfun -c user.email=hashfun@localhost)
fi
stop_am() { git "${CFG[@]}" am --abort > /dev/null 2>&1 || git "${CFG[@]}" am --quit > /dev/null 2>&1 || true; }

# ---- an earlier run that stopped half way ---------------------------------------------------------
if [ -d "$(git rev-parse --git-path rebase-apply)" ]; then
  stop_am
fi

OLD="$(git rev-parse -q --verify "refs/heads/$BRANCH" || true)"
BUILT="$(git config --get hashfun.head || true)"
if [ -n "$OLD" ] && [ "$OLD" = "$BUILT" ] && [ "$(git config --get hashfun.series || true)" = "$SERIES" ]; then
  echo "ok: branch $BRANCH in $DIR is already these $NPATCH patches on $BASE ($(git rev-parse --short=12 "$OLD"))"
else
  if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    die "$DIR has changes that are not committed (git -C \"$DIR\" status)" \
      "commit them or put them aside (git stash), then run this again: the rebuild checks out other commits"
  fi
  # (a branch and a folder are both called hashfun: every checkout below says which it means)
  START="$(git symbolic-ref -q --short HEAD || git rev-parse HEAD)"
  git "${CFG[@]}" checkout -q --detach "$BASE" --
  if ! git "${CFG[@]}" am -q --no-3way --keep-cr --no-scissors --whitespace=nowarn --committer-date-is-author-date "$@"; then
    NEXT="$(cat "$(git rev-parse --git-path rebase-apply/next)" 2> /dev/null || echo "?")"
    stop_am
    git "${CFG[@]}" checkout -q "$START" -- 2> /dev/null || true
    die "patch number $NEXT of $NPATCH does not apply on $BASE (git's message is above)" \
      "the patches/ folder is incomplete or mixed from two deliveries: replace the whole folder and run this again" \
      "$DIR is back where it was"
  fi
  NEW="$(git rev-parse HEAD)"
  if [ -n "$OLD" ] && [ "$OLD" != "$NEW" ] && [ "$OLD" != "$BUILT" ]; then
    # the branch held commits this script did not make: they stay reachable under a name
    KEPT="kept-$(printf '%s' "$OLD" | cut -c1-12)"
    git branch -f "$KEPT" "$OLD" > /dev/null
    echo "note: branch $BRANCH held commits that are not from this script; they are kept as branch $KEPT"
  fi
  git "${CFG[@]}" checkout -q -B "$BRANCH" "$NEW" --
  git config hashfun.series "$SERIES"
  git config hashfun.head "$NEW"
  echo "ok: $(git rev-list --count "$BASE..$NEW") commits on top of $BASE in $DIR (branch $BRANCH, $(git rev-parse --short=12 "$NEW"))"
fi

# ---- the delivery says which tree the patches must give: the one that was built and tested --------
if [ -f "$HERE/patches/TREE" ]; then
  WANT="$(tr -d ' \t\r\n' < "$HERE/patches/TREE")"
  GOT="$(git rev-parse "refs/heads/$BRANCH^{tree}")"
  [ "$WANT" = "$GOT" ] ||
    die "the rebuilt source is not the tested one (tree $GOT, the delivery says $WANT)" \
      "the patches/ folder is incomplete or changed: replace the whole folder and run this again"
  echo "ok: the source is byte for byte the tested one (tree $GOT)"
fi

if [ -n "${PUSH:-}" ]; then
  [ -f "$HERE/deploy.sh" ] || die "PUSH needs deploy.sh next to this script"
  TARGET="$PUSH"
  REPO="$TARGET" VISIBILITY="${VISIBILITY:-private}" DIR="$(pwd -P)" REBUILD=0 TAG=0 NPM=0 PUSH="" bash "$HERE/deploy.sh"
elif [ "${HASHFUN_QUIET:-0}" != 1 ]; then
  echo "build here: bash contrib/hashfun/dist/build.sh    test: bash contrib/hashfun/ci/test.sh    ship: bash $HERE/deploy.sh"
fi
