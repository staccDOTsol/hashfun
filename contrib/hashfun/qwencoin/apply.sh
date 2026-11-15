#!/usr/bin/env bash
# hashfun on the Qwencoin nodes: this folder's patch series, applied to a git working copy of the Qwencoin project.
#
#   bash apply.sh /path/to/qwencoin [--check-only]
#
# In that folder, and nowhere else:
#   1. refuses a folder that is not the project (no tools/pipeline.sh, not a git working copy, no branch main) or that
#      has uncommitted changes to a file the series touches
#   2. makes the branch hashfun from main and applies patches/*.patch with `git am --3way`; a patch that does not apply
#      stops it, the conflicting files named, and main is left as it was
#   3. writes the three one-line files the nodes read and commits them on hashfun:
#        HASHFUN     the site the nodes follow (HASHFUN_SITE, default https://aichat.fyi/fun)
#        FUNBTC      where the site reads Bitcoin (FUN_BTC_SOURCE, default two Electrum servers over TLS)
#        HASHFUNPKG  the hashfun release the nodes run: HASHFUN_REPO (staccDOTsol/hashfun) and HASHFUN_VERSION (v0.2.0),
#                    with the sha256 of hashfun-X.Y.Z.tgz as downloaded from that release, which must be the one the
#                    release's own SHA256SUMS lists (the project's own `python3 tools/fun.py pin`). No release yet: it stops.
#   4. runs the project's quick checks and tests/check_fun.py and prints each result
# --check-only: the same refusals, the series tried on a scratch working tree inside the folder's .git (removed
# afterwards), the release looked for, the checks run there; nothing in the folder changes.
# A second run says what is already done and does only the rest. Nothing here reads or prints a token or a key, and
# nothing is pushed or published: that is the next step of CODEX.md.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SITE="${HASHFUN_SITE:-https://aichat.fyi/fun}"
BTC="${FUN_BTC_SOURCE:-electrums://electrum1.bluewallet.io:443,fortress.qtornado.com:443}"
REPO="${HASHFUN_REPO:-staccDOTsol/hashfun}"
VERSION="${HASHFUN_VERSION:-v0.2.0}"
BRANCH=hashfun

say() { printf '== %s\n' "$*"; }
die() {
  printf 'apply.sh: %s\n' "$*" >&2
  exit 1
}

[ $# -ge 1 ] || die "usage: bash apply.sh /path/to/qwencoin [--check-only]"
CHECK=0
[ "${2:-}" = --check-only ] && CHECK=1
if [ $# -gt 2 ] || { [ $# -eq 2 ] && [ "$CHECK" = 0 ]; }; then die "usage: bash apply.sh /path/to/qwencoin [--check-only]"; fi
[ -d "$1" ] || die "$1 is not a folder"
DEST="$(cd "$1" && pwd -P)"
G() { git -C "$DEST" "$@"; }

# ---- 1. is it the project, and is it clean where the series writes
[ -f "$DEST/tools/pipeline.sh" ] || die "$DEST is not the Qwencoin project (it has no tools/pipeline.sh)"
[ "$(G rev-parse --show-toplevel 2> /dev/null || true)" = "$DEST" ] || die "$DEST is not a git working copy (git clone https://github.com/staccDOTsol/qwencoin first)"
G rev-parse -q --verify refs/heads/main > /dev/null || die "$DEST has no branch main"
case "$SITE" in https://*) ;; *) die "HASHFUN_SITE must be an https address" ;; esac
case "$BTC" in https://* | http://* | electrums://* | electrum://*) ;; *) die "FUN_BTC_SOURCE must be http(s):// or electrum(s)://" ;; esac
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "HASHFUN_VERSION must read vX.Y.Z"
[[ "$REPO" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "HASHFUN_REPO must read OWNER/REPOSITORY"
mapfile -t PATCHES < <(find "$HERE/patches" -maxdepth 1 -name '*.patch' | sort)
[ "${#PATCHES[@]}" -gt 0 ] || die "no patches in $HERE/patches"
# (HASHFUN, HASHFUNPKG and FUNBTC are not among them: this script writes them, whatever they held)
mapfile -t TOUCHED < <(sed -n 's#^diff --git a/\([^ ]*\) b/.*#\1#p' "${PATCHES[@]}" | sort -u)
dirty="$(G status --porcelain -- "${TOUCHED[@]}")"
[ -z "$dirty" ] || die "uncommitted changes to files the series touches (commit or stash them first):
$dirty"
say "the project: $DEST (main at $(G rev-parse --short main); the series was made on $(cut -c1-7 "$HERE/BASE"))"

# the subjects of the series, to tell whether a branch already has it
mapfile -t SUBJECTS < <(for p in "${PATCHES[@]}"; do sed -n 's/^Subject: \[PATCH[^]]*\] //p' "$p" | head -1; done)
has_series() { # has_series REF: every patch of the series is a commit between main and REF
  local s have
  have="$(G log --format=%s "main..$1" 2> /dev/null)" || return 1
  for s in "${SUBJECTS[@]}"; do # (a long subject is folded in a patch file: its first line is enough)
    grep -qF -- "$s" <<< "$have" || return 1
  done
}
identity=()
[ -n "$(G config user.email || true)" ] || identity=(-c user.name="hashfun apply.sh" -c user.email=noreply@anthropic.com)

# ---- the checks: the project's quick ones and check_fun.py, in a folder that has the series
checks() { # checks FOLDER
  local w="$1" rc=0 out
  say "checks in $w"
  if out="$(cd "$w" && find tools rails graph tests hashformer -name '*.py' -print0 | xargs -0 python3 -m py_compile 2>&1)"; then
    echo "   ok    every Python file of tools/ rails/ graph/ tests/ hashformer/ compiles"
  else
    echo "   FAIL  Python files that do not compile:"
    printf '%s\n' "$out" | tail -5
    rc=1
  fi
  if out="$(cd "$w" && for f in tools/*.sh win/go.sh; do bash -n "$f" || echo "$f"; done 2>&1)" && [ -z "$out" ]; then
    echo "   ok    every shell script of tools/ and win/go.sh parses"
  else
    echo "   FAIL  shell scripts that do not parse: $out"
    rc=1
  fi
  if out="$(cd "$w" && FUN=0 timeout 120 python3 tools/fun.py status 2>&1)"; then
    echo "   ok    tools/fun.py status: $(printf '%s' "$out" | head -1)"
  else
    echo "   FAIL  tools/fun.py status: $(printf '%s' "$out" | tail -1)"
    rc=1
  fi
  if out="$(cd "$w" && timeout 120 python3 tools/results.py 2>&1 > /dev/null)"; then
    echo "   ok    tools/results.py assembles RESULTS.md"
  else
    echo "   FAIL  tools/results.py: $(printf '%s' "$out" | tail -1)"
    rc=1
  fi
  local log
  log="$(mktemp)"
  if (cd "$w" && timeout 600 python3 tests/check_fun.py all > "$log" 2>&1); then
    echo "   ok    tests/check_fun.py all: $(tail -1 "$log")"
  else
    echo "   FAIL  tests/check_fun.py all (its last lines):"
    tail -15 "$log"
    rc=1
  fi
  rm -f "$log"
  # check_fun.py writes its log into logs/fun.log, a file of the series: put back as committed
  (cd "$w" && git checkout -q -- logs/fun.log 2> /dev/null) || true
  return $rc
}

release_there() {
  local v="${VERSION#v}" code
  code="$(curl -sS -L -o /dev/null -w '%{http_code}' -r 0-0 --max-time 60 "https://github.com/$REPO/releases/download/$VERSION/hashfun-$v.tgz" 2> /dev/null || echo 000)"
  [ "$code" = 200 ] || [ "$code" = 206 ]
}

# ---- --check-only: everything on a scratch working tree, then gone
if [ "$CHECK" = 1 ]; then
  scratch="$(G rev-parse --absolute-git-dir)/hashfun-check"
  G worktree remove --force "$scratch" > /dev/null 2>&1 || true
  rm -rf "$scratch"
  G worktree add -q --detach "$scratch" main
  trap 'git -C "$DEST" worktree remove --force "$scratch" > /dev/null 2>&1 || rm -rf "$scratch"; git -C "$DEST" worktree prune' EXIT
  if has_series "$BRANCH" 2> /dev/null; then
    say "the branch $BRANCH already has the series"
  fi
  if ! git -C "$scratch" "${identity[@]}" am -q --3way "${PATCHES[@]}" > /dev/null 2>&1; then
    conflict="$(git -C "$scratch" diff --name-only --diff-filter=U || true)"
    git -C "$scratch" am --abort > /dev/null 2>&1 || true
    die "the series does not apply to main: $(printf '%s ' "${conflict:-(see git am)}")"
  fi
  say "the series applies to main ($(G rev-parse --short main)): ${#PATCHES[@]} patches"
  if release_there; then say "the release $REPO $VERSION is there"; else say "the release $REPO $VERSION is NOT there yet: a real run would stop at HASHFUNPKG"; fi
  rc=0
  checks "$scratch" || rc=1
  say "check only: nothing in $DEST was changed"
  exit $rc
fi

# ---- 2. the branch and the series
if G rev-parse -q --verify "refs/heads/$BRANCH" > /dev/null; then
  if has_series "$BRANCH"; then
    say "already done: the branch $BRANCH has the series"
  else
    die "a branch $BRANCH exists without the whole series: rename or delete it (git branch -m $BRANCH $BRANCH-old) and run this again"
  fi
  [ "$(G rev-parse --abbrev-ref HEAD)" = "$BRANCH" ] || G switch -q "$BRANCH"
else
  G switch -q -c "$BRANCH" main
  if ! G "${identity[@]}" am -q --3way "${PATCHES[@]}" > /dev/null 2>&1; then
    conflict="$(G diff --name-only --diff-filter=U || true)"
    G am --abort > /dev/null 2>&1 || true
    G switch -q main
    G branch -q -D "$BRANCH"
    die "the series does not apply to main; conflicting: $(printf '%s ' "${conflict:-(see git am)}"). main is as it was, no branch $BRANCH was left"
  fi
  say "the branch $BRANCH: main and ${#PATCHES[@]} patches ($(G rev-parse --short HEAD))"
fi

# ---- 3. the three files
changed=0
put() { # put FILE LINE
  if [ "$(cat "$DEST/$1" 2> /dev/null || true)" = "$2" ]; then
    say "already done: $1 is $2"
  else
    printf '%s\n' "$2" > "$DEST/$1"
    say "$1: $2"
    changed=1
  fi
}
pin="$(cat "$DEST/HASHFUNPKG" 2> /dev/null || true)"
if [[ "$pin" =~ ^$REPO\ $VERSION\ [0-9a-f]{64}$ ]]; then
  say "already done: HASHFUNPKG is $pin"
else
  # (first, so that a release that is not there yet leaves none of the three files written)
  release_there || die "the release $REPO $VERSION is not on GitHub yet (https://github.com/$REPO/releases/tag/$VERSION): none of HASHFUN, FUNBTC, HASHFUNPKG is written. Run this again once it is"
  say "HASHFUNPKG: downloading hashfun-${VERSION#v}.tgz of $REPO $VERSION and its SHA256SUMS"
  (cd "$DEST" && python3 tools/fun.py pin "$REPO" "$VERSION") || die "the release's package could not be fetched or is not the one its SHA256SUMS lists: HASHFUNPKG is not written"
  changed=1
fi
put HASHFUN "$SITE"
put FUNBTC "$BTC"
if [ -n "$(G status --porcelain -- HASHFUN FUNBTC HASHFUNPKG)" ]; then
  G add HASHFUN FUNBTC HASHFUNPKG
  G "${identity[@]}" commit -q -m "hashfun: the site the nodes follow, the release they run, where the site reads Bitcoin

HASHFUN $(cat "$DEST/HASHFUN")
HASHFUNPKG $(cat "$DEST/HASHFUNPKG")
FUNBTC $(cat "$DEST/FUNBTC")

(written by hashfun's contrib/hashfun/qwencoin/apply.sh)"
  say "committed on $BRANCH: $(G log -1 --format='%h %s')"
elif [ "$changed" = 0 ]; then
  say "already done: the three files are committed"
fi

# ---- 4. the checks
checks "$DEST" || die "a check failed (above): the branch $BRANCH is there to look at; main is as it was"
say "done: branch $BRANCH at $(G rev-parse --short HEAD), $(G rev-list --count main..HEAD) commits over main. Next: CODEX.md step 4"
