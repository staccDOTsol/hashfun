#!/usr/bin/env bash
# hashfun: ship it. Run it in a terminal on your own machine, from anywhere:
#
#   bash deploy.sh           build the source repository from the patches (the first run clones
#                            namecoin-core, a few hundred MB), create or reuse the GitHub
#                            repository, push, hand GitHub the npm token, tag the release.
#                            GitHub Actions then builds the node for macOS and Linux, tests each
#                            binary, checks that all four agree on every block, and on the tag
#                            makes the release and publishes to npm.
#   bash deploy.sh status    how that build is going: three lines here, the details in
#                            ci/status.txt, the last lines of every failed job in ci/failed.log
#   bash deploy.sh wait      the same, once the build has ended (looks every minute)
#   bash deploy.sh logs      also fetch the test and build logs GitHub kept for that build, into
#                            ci/logs/ (larger; for when the last lines are not enough)
#   bash deploy.sh rerun     run the failed jobs of that build again (for a failure that was
#                            GitHub's, not the code's)
#
# Before it changes anything on GitHub it prints what it is about to do (create or reuse the
# repository, push, store the token, tag: the tag is what makes GitHub publish to npm) and asks
# once. YES=1 answers that question in advance.
#
# Safe to run again at any point: every step first looks at what is already there. After a new
# set of patches arrives, the same command rebuilds the source, replaces the branch on GitHub
# and moves the release tag (a version that is on npm already is never moved).
#
# It uses git, the GitHub CLI (gh) logged in as you, and a file holding your npm token. The token
# goes from that file to GitHub's encrypted secret store over a pipe; it is never printed, never
# put on a command line and never written anywhere else.
#
# Settings (environment variables), all optional:
#   REPO=owner/name       the GitHub repository       (default: <your gh login>/hashfun)
#   VISIBILITY=private    used when the repository is created (default: public. GitHub's runners
#                         are free for a public repository; on a private one the minutes are
#                         billed, and a macOS minute counts as about ten)
#   NPM_TOKEN_FILE=path   the npm token (default: ~/.npmnpm123): a bare token, or an .npmrc line
#                         //registry.npmjs.org/:_authToken=...
#   NPM=0                 leave the npm token alone
#   YES=1                 do not ask before changing things on GitHub (needed where there is no
#                         terminal to ask on)
#   TAG=0                 push only: GitHub builds and tests, no release, nothing to npm
#   FORCE=1               replace a hashfun branch on GitHub that this script did not put there
#   KEEP_LINES=3000       status: how many last lines of each failed job to keep
#   DIR=path              where the source repository is built (default: hashfun-core beside this
#                         script)
#
# Written for the bash that macOS ships (3.2).
[ -n "${BASH_VERSION:-}" ] || exec bash "$0" "$@"   # started with sh or zsh: this is a bash script
set -euo pipefail
case "$-" in *x*)
  set +x
  echo "(command tracing switched off: it would print the npm token)" >&2
  ;;
esac

HERE="$(cd "$(dirname "$0")" && pwd -P)"
CMD="${1:-deploy}"
BRANCH=hashfun
NPM_REGISTRY=https://registry.npmjs.org

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
  printf '\nstopped: %s\n' "$1" >&2
  shift
  while [ $# -gt 0 ]; do
    printf '  %s\n' "$1" >&2
    shift
  done
  exit 1
}
have() { command -v "$1" > /dev/null 2>&1; }
first_line() { sed -n '1p' "$1" 2> /dev/null || true; }
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
short() { printf '%s' "$1" | cut -c1-12; }

case "$CMD" in -h | --help | help)
  sed -n '2,/^# Written for/p' "$0" | sed -e 's/^# \{0,1\}//'
  exit 0
  ;;
esac
have git || die "git is not installed" "fix: xcode-select --install"
have gh || die "the GitHub CLI (gh) is not installed" "fix: brew install gh    then: gh auth login"

# ---- where things are -----------------------------------------------------------------------------
# Delivered: this script sits beside make_repo.sh and patches/, and the source repository is built
# next to them. In a checkout: this script is contrib/hashfun/deploy.sh and the checkout is the source.
if [ -d "$HERE/patches" ] && [ -f "$HERE/make_repo.sh" ]; then
  LAYOUT=patches
  SRC="${DIR:-$HERE/hashfun-core}"
  OUT="${CI_OUT:-$HERE/ci}"
else
  TOP="$(git -C "$HERE" rev-parse --show-toplevel 2> /dev/null || true)"
  if [ -n "$TOP" ] && [ -f "$TOP/.github/workflows/hashfun.yml" ]; then
    LAYOUT=checkout
    SRC="$TOP"
    OUT="${CI_OUT:-$TOP/build/ci}"
  else
    die "nothing to ship from $HERE: no patches/ folder with make_repo.sh beside this script, and no hashfun checkout around it" \
      "run the deploy.sh that came with the patches, in the folder it came in"
  fi
fi
case "$SRC" in /*) ;; *) SRC="$PWD/$SRC" ;; esac

TMP="$(mktemp -d "${TMPDIR:-/tmp}/hashfun-deploy.XXXXXX")"
trap 'rm -rf "${TMP:?}"' EXIT

# git for anything that talks to GitHub: gh's own login answers the password question, whatever
# credential helpers this machine has configured, and no personal push hooks run.
ggit() { git -C "$SRC" -c core.hooksPath=/dev/null -c credential.helper= -c 'credential.helper=!gh auth git-credential' "$@"; }

# owner/name out of a GitHub remote URL; nothing for any other URL
slug_of_url() {
  printf '%s\n' "$1" |
    sed -n -E 's#^(https://([^/@]*@)?github\.com/|git@github\.com:|ssh://git@github\.com/)([^/]+)/([^/]+)$#\3/\4#p' |
    sed -e 's/\.git$//'
}

# a "key": "value" line of a small JSON file on stdin (package.json keeps one such line per key)
json_string() { awk -F'"' -v k="$1" '$2 == k && $3 ~ /^[[:space:]]*:[[:space:]]*$/ { print $4; exit }'; }

# ---- GitHub: who, and may the login push workflow files -------------------------------------------
gh_login() {
  local err="$TMP/login.err"
  if ! LOGIN="$(gh api user --jq .login 2> "$err")" || [ -z "$LOGIN" ]; then
    if [ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]; then
      die "GitHub does not accept the token in GH_TOKEN / GITHUB_TOKEN ($(first_line "$err"))" \
        "fix: unset GH_TOKEN GITHUB_TOKEN    then: gh auth login"
    fi
    die "gh is not logged in to GitHub ($(first_line "$err"))" "fix: gh auth login"
  fi
}

# the permissions (scopes) of gh's token, comma separated; empty when GitHub does not list them
token_scopes() {
  gh api -i user 2> /dev/null | tr -d '\r' |
    awk 'tolower($1) == "x-oauth-scopes:" { $1 = ""; gsub(/ /, ""); print; exit }' || true
}
has_scope() { case ",$SCOPES," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

need_workflow_scope() {
  local fix="fix: gh auth refresh -h github.com -s workflow"
  SCOPES="$(token_scopes)"
  if [ -z "$SCOPES" ]; then
    say "   (GitHub does not list this login's permissions. If the push below is refused over a workflow file: $fix)"
    return 0
  fi
  has_scope workflow && return 0
  if [ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]; then
    die "the token in GH_TOKEN / GITHUB_TOKEN may not push workflow files (no 'workflow' permission)" \
      "fix: unset GH_TOKEN GITHUB_TOKEN  (gh then uses your login)    then: ${fix#fix: }"
  fi
  if [ -t 0 ] && [ -t 1 ]; then
    say "   your gh login may not push workflow files yet. Asking GitHub for that permission:"
    say "   gh auth refresh -h github.com -s workflow      (a browser page opens: approve it)"
    gh auth refresh -h github.com -s workflow || die "GitHub did not grant it" "$fix"
    SCOPES="$(token_scopes)"
    has_scope workflow || die "the gh login still may not push workflow files" "$fix"
  else
    die "your gh login may not push workflow files (no 'workflow' permission), and the source contains .github/workflows" "$fix"
  fi
}

# ---- the source -----------------------------------------------------------------------------------
build_source() {
  if [ "$LAYOUT" = patches ] && [ "${REBUILD:-1}" != 0 ]; then
    PUSH="" HASHFUN_QUIET=1 bash "$HERE/make_repo.sh" "$SRC" || die "the source repository was not built (the reason is above)"
  fi
  [ -d "$SRC/.git" ] || [ -f "$SRC/.git" ] || die "$SRC is not a git repository"
  HEAD_SHA="$(git -C "$SRC" rev-parse -q --verify "refs/heads/$BRANCH" || true)"
  [ -n "$HEAD_SHA" ] || die "$SRC has no branch $BRANCH"
  if [ "$(git -C "$SRC" rev-parse --is-shallow-repository 2> /dev/null || echo false)" = true ]; then
    die "$SRC is a shallow clone (its history is cut off), and GitHub refuses a push from one" \
      "fix: git -C \"$SRC\" fetch --unshallow <the namecoin-core remote>"
  fi
  git -C "$SRC" cat-file -e "$HEAD_SHA:.github/workflows/hashfun.yml" 2> /dev/null ||
    die "branch $BRANCH has no .github/workflows/hashfun.yml: GitHub would build nothing"
  PKG="$(git -C "$SRC" show "$HEAD_SHA:contrib/hashfun/npm/package.json" 2> /dev/null | json_string name || true)"
  VERSION="$(git -C "$SRC" show "$HEAD_SHA:contrib/hashfun/npm/package.json" 2> /dev/null | json_string version || true)"
  [ -n "$PKG" ] && [ -n "$VERSION" ] || die "could not read the package name and version from contrib/hashfun/npm/package.json on branch $BRANCH"
  case "$VERSION" in *[!0-9A-Za-z.+-]* | "") die "the version in package.json ($VERSION) is not one a tag can carry" ;; esac
  TAGNAME="v$VERSION"
  if [ "$LAYOUT" = checkout ] && [ -n "$(git -C "$SRC" status --porcelain --untracked-files=no 2> /dev/null)" ]; then
    warn "$SRC has changes that are not committed: they are not part of what is pushed"
  fi
  say "   $PKG $VERSION, branch $BRANCH at $(short "$HEAD_SHA")"
}

# ---- what is there now ----------------------------------------------------------------------------
# Everything from here to `confirm` only looks. The four things that change GitHub (create the
# repository, push, store the secret, tag) happen after the plan was shown and accepted.
look_repo() {
  local err="$TMP/repo.err" info
  if info="$(gh repo view "$REPO" --json visibility --jq '.visibility' 2> "$err" < /dev/null)"; then
    REPO_EXISTS=1
    REPO_VIS="$(lower "$info")"
  elif grep -qiE 'could not resolve to a repository|not found|HTTP 404' "$err"; then
    REPO_EXISTS=0
    REPO_VIS="$VIS"
  else
    die "could not ask GitHub about $REPO ($(first_line "$err"))" "check the network, then: gh auth status"
  fi
}

# Which remote of the source repository is this GitHub repository. `origin` when it is free or
# already this repository; never repoint a remote that names something else. (Local only.)
pick_remote() {
  local url="https://github.com/$REPO.git" cur
  REMOTE=origin
  cur="$(git -C "$SRC" remote get-url origin 2> /dev/null || true)"
  if [ -n "$cur" ] && [ "$(lower "$(slug_of_url "$cur")")" != "$(lower "$REPO")" ]; then
    REMOTE=deploy
    cur="$(git -C "$SRC" remote get-url deploy 2> /dev/null || true)"
  fi
  if [ -z "$cur" ]; then
    git -C "$SRC" remote add "$REMOTE" "$url"
  elif [ "$(lower "$(slug_of_url "$cur")")" != "$(lower "$REPO")" ]; then
    git -C "$SRC" remote set-url "$REMOTE" "$url"
  fi
}

# BR: first (nothing there yet), same, forward (GitHub's head is an ancestor), replace
look_branch() {
  local last
  REMOTE_HEAD=""
  BR=first
  [ "$REPO_EXISTS" = 1 ] || return 0
  REMOTE_HEAD="$(ggit ls-remote "$REMOTE" "refs/heads/$BRANCH" 2> "$TMP/ls.err" | cut -f1)" ||
    die "could not read $REPO over git ($(first_line "$TMP/ls.err"))" "check the network, then: gh auth status"
  if [ -z "$REMOTE_HEAD" ]; then
    BR=first
  elif [ "$REMOTE_HEAD" = "$HEAD_SHA" ]; then
    BR=same
  else
    ggit fetch -q "$REMOTE" "+refs/heads/$BRANCH:refs/remotes/$REMOTE/$BRANCH" 2> "$TMP/fetch.err" ||
      die "could not fetch $BRANCH from $REPO ($(first_line "$TMP/fetch.err"))"
    if git -C "$SRC" merge-base --is-ancestor "$REMOTE_HEAD" "$HEAD_SHA"; then
      BR=forward
    else
      # Rebuilt from a new set of patches: the branch is replaced, not extended. What this script
      # pushed last time is the only thing it replaces without being told to.
      last="$(git -C "$SRC" config --get hashfun.pushed || true)"
      if [ -n "$last" ] && [ "$last" != "$REMOTE_HEAD" ] && [ "${FORCE:-0}" != 1 ]; then
        die "$BRANCH on GitHub ($(short "$REMOTE_HEAD")) is not what this script pushed last ($(short "$last")): someone else pushed to it" \
          "to replace it with the rebuilt source anyway: FORCE=1 bash deploy.sh" \
          "(it would stay in $SRC as branch replaced-$(short "$REMOTE_HEAD"))"
      fi
      BR=replace
    fi
  fi
}

# ---- npm ------------------------------------------------------------------------------------------
# 0: this version is on npm; 1: it is not; 2: could not find out
npm_has_version() {
  local out code
  if have npm; then
    if out="$(npm view "$PKG@$VERSION" version 2> "$TMP/npm.err")"; then
      [ -n "$out" ] && return 0
      return 1 # the package exists, this version does not
    fi
    grep -q 'E404' "$TMP/npm.err" && return 1
  fi
  if have curl; then
    code="$(curl -sS -m 20 -o /dev/null -w '%{http_code}' "$NPM_REGISTRY/$PKG/$VERSION" 2> /dev/null || true)"
    case "$code" in 200) return 0 ;; 404) return 1 ;; esac
  fi
  return 2
}

# The token out of the file, on stdout. Call it only with stdout captured or piped.
#   //registry.npmjs.org/:_authToken=TOKEN      an .npmrc line (npm's own registry first, if there are several)
#   NPM_TOKEN=TOKEN, export NPM_TOKEN="TOKEN"   an environment file
#   TOKEN                                       the token alone
token_of_file() {
  awk -v q="'" '
    function clean(s) {
      gsub(/^[ \t]+|[ \t]+$/, "", s)
      if (s ~ /^".*"$/ || s ~ ("^" q ".*" q "$")) s = substr(s, 2, length(s) - 2)
      return s
    }
    { sub(/\r$/, "") }
    n == "" && /^[ \t]*\/\/registry\.npmjs\.org\/:_authToken[ \t]*=/ { s = $0; sub(/^[^=]*=/, "", s); n = clean(s) }
    a == "" && /^[ \t]*\/\/[^ \t]*:_authToken[ \t]*=/ { s = $0; sub(/^[^=]*=/, "", s); a = clean(s) }
    b == "" && /^[ \t]*(export[ \t]+)?[A-Za-z_]*[Tt][Oo][Kk][Ee][Nn][A-Za-z_]*[ \t]*=/ { s = $0; sub(/^[^=]*=/, "", s); b = clean(s) }
    c == "" && !/^[ \t]*([#;]|$)/ && !/=/ { c = clean($0) }
    END { printf "%s", (n != "" ? n : (a != "" ? a : (b != "" ? b : c))) }
  ' "$1"
}

# Reads the token file and asks npm about the token. Sets NPM_DO (1: store it), TOK, NPM_PLAN, NPM_STATE.
look_token() {
  local file="${NPM_TOKEN_FILE:-${HOME:-}/.npmnpm123}" tok code user=""
  local skip="GitHub will still build, test and make the release; nothing goes to npm until the repository has the secret NPM_TOKEN"
  TOK=""
  NPM_DO=0
  NPM_STATE="not set"
  if [ "${NPM:-1}" = 0 ]; then
    NPM_STATE="left alone (NPM=0)"
    NPM_PLAN="the npm token is left alone (NPM=0)"
    return 0
  fi
  NPM_PLAN="no usable npm token in $file: nothing is stored"
  if [ ! -f "$file" ] || [ ! -r "$file" ]; then
    NPM_PLAN="no npm token file at $file: nothing is stored"
    warn "no npm token file at $file. $skip"
    warn "when you have it: NPM_TOKEN_FILE=/path/to/file bash deploy.sh"
    return 0
  fi
  tok="$(token_of_file "$file")"
  case "$tok" in
    "")
      warn "$file holds no token (it is empty, or only comments and settings). $skip"
      return 0
      ;;
    *'$'*)
      warn "$file holds a placeholder (a \$ variable), not the token itself. $skip"
      return 0
      ;;
    *[[:space:]]*)
      warn "what $file holds does not look like a token (there is a space in it). $skip"
      return 0
      ;;
  esac
  if [ "${#tok}" -lt 20 ]; then
    warn "what $file holds is too short to be an npm token. $skip"
    return 0
  fi
  # Ask npm whether it knows this token before GitHub gets it: the publish is the last step of a
  # long build, a bad time to find out. The token travels in a header read from a pipe.
  if have curl; then
    code="$(printf 'Authorization: Bearer %s\n' "$tok" | curl -sS -m 20 -o "$TMP/whoami" -w '%{http_code}' -H @- "$NPM_REGISTRY/-/whoami" 2> /dev/null || true)"
    case "$code" in
      200)
        user="$(json_string username < "$TMP/whoami" || true)"
        [ -n "$user" ] || user="$(sed -n 's/.*"username"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$TMP/whoami" | sed -n '1p')"
        ;;
      401 | 403)
        NPM_PLAN="npm does not accept the token in $file: nothing is stored"
        warn "npm does not accept the token in $file (HTTP $code): it is expired, revoked or cut short. It will NOT be handed to GitHub. $skip"
        warn "make a new one at npmjs.com (Access Tokens: an Automation token, or a granular one that may publish), put it in that file, run this again"
        return 0
        ;;
      *) say "   (could not ask npm about the token just now; it is handed over as it is)" ;;
    esac
  fi
  TOK="$tok"
  NPM_DO=1
  NPM_PLAN="store the npm token from $file as the secret NPM_TOKEN of $REPO (npm account: ${user:-not checked})"
  tok=""
}

# Does the repository already hold the secret (from an earlier run)?
look_secret() {
  SECRET_THERE=0
  [ "$REPO_EXISTS" = 1 ] || return 0
  if gh secret list --repo "$REPO" 2> /dev/null < /dev/null | awk '$1 == "NPM_TOKEN" { f = 1 } END { exit !f }'; then
    SECRET_THERE=1
  fi
}

# TAG_DO: none, create or move; TAG_PLAN says which and why.
look_tag() {
  local peeled rc=0 after
  TAG_DO=none
  TAG_RAW=""
  TAG_CUR=""
  if [ "${TAG:-1}" = 0 ]; then
    TAG_STATE="not tagged (TAG=0)"
    TAG_PLAN="no tag (TAG=0): GitHub builds and tests the push; no release, nothing to npm"
    return 0
  fi
  if [ "$REPO_EXISTS" = 1 ]; then
    ggit ls-remote "$REMOTE" "refs/tags/$TAGNAME*" > "$TMP/tags" 2> "$TMP/ls.err" ||
      die "could not read the tags of $REPO ($(first_line "$TMP/ls.err"))"
    TAG_RAW="$(awk -v t="refs/tags/$TAGNAME" '$2 == t { print $1 }' "$TMP/tags")"
    peeled="$(awk -v t="refs/tags/$TAGNAME^{}" '$2 == t { print $1 }' "$TMP/tags")"
    TAG_CUR="${peeled:-$TAG_RAW}"
  fi
  if [ "$TAG_CUR" = "$HEAD_SHA" ]; then
    TAG_STATE="$TAGNAME, already on $(short "$HEAD_SHA")"
    TAG_PLAN="tag $TAGNAME is already on this commit: its build ran or is running (bash deploy.sh status; a failed one again: bash deploy.sh rerun)"
    return 0
  fi
  # A published version is final: npm never takes another tarball under the same number.
  npm_has_version || rc=$?
  if [ "$rc" = 0 ]; then
    TAG_STATE="not tagged: $PKG@$VERSION is on npm already"
    TAG_PLAN="no tag: $PKG@$VERSION is on npm already and a published version cannot be replaced. To release this source the version in contrib/hashfun/npm/package.json has to go up (ask for patches with the next version)"
    return 0
  fi
  if [ -n "$TAG_CUR" ] && [ "$rc" = 2 ]; then
    TAG_STATE="not moved: could not ask npm about $PKG@$VERSION"
    TAG_PLAN="tag $TAGNAME stays on $(short "$TAG_CUR"): npm could not be asked whether $PKG@$VERSION is published (run this again when npm answers: npm view $PKG@$VERSION version)"
    return 0
  fi
  if [ "$NPM_DO" = 1 ] || [ "$SECRET_THERE" = 1 ]; then
    after="GitHub publishes $PKG@$VERSION to npm when all four platforms pass; a published version cannot be taken back"
  else
    after="GitHub makes the release (tarball and binaries) when all four platforms pass; nothing goes to npm (the repository has no NPM_TOKEN secret)"
  fi
  if [ -z "$TAG_CUR" ]; then
    TAG_DO=create
    TAG_PLAN="tag $TAGNAME on $(short "$HEAD_SHA"): $after"
  else
    TAG_DO=move
    TAG_PLAN="MOVE tag $TAGNAME: $(short "$TAG_CUR") -> $(short "$HEAD_SHA") (a build still running for the old commit is stopped): $after"
  fi
  TAG_STATE="none"
}

# ---- the plan, and the one question ----------------------------------------------------------------
plan() {
  WRITES=0
  if [ "$REPO_EXISTS" = 1 ]; then
    say "   repository   reuse https://github.com/$REPO ($REPO_VIS)"
    if [ "$REPO_VIS" != public ]; then
      say "                note: it is not public, so GitHub bills its build minutes (a macOS minute counts as about ten);"
      say "                to open it: gh repo edit $REPO --visibility public --accept-visibility-change-consequences"
    fi
  else
    say "   repository   create the $(printf '%s' "$VIS" | tr '[:lower:]' '[:upper:]') repository https://github.com/$REPO"
    WRITES=$((WRITES + 1))
  fi
  case "$BR" in
    same) say "   branch       $BRANCH on GitHub is already at $(short "$HEAD_SHA"): nothing to push" ;;
    first) say "   branch       push $BRANCH at $(short "$HEAD_SHA") (the first push: the whole history, a few minutes)" ;;
    forward) say "   branch       push $BRANCH: $(short "$REMOTE_HEAD") -> $(short "$HEAD_SHA") (fast-forward)" ;;
    replace) say "   branch       REPLACE $BRANCH on GitHub: $(short "$REMOTE_HEAD") -> $(short "$HEAD_SHA") (rebuilt from the patches; the old one stays in $SRC as branch replaced-$(short "$REMOTE_HEAD"))" ;;
  esac
  [ "$BR" = same ] || WRITES=$((WRITES + 1))
  say "   npm token    $NPM_PLAN"
  [ "$NPM_DO" = 0 ] || WRITES=$((WRITES + 1))
  say "   release      $TAG_PLAN"
  [ "$TAG_DO" = none ] || WRITES=$((WRITES + 1))
}

confirm() {
  local ans=""
  if [ "$WRITES" = 0 ]; then
    say "   nothing to change: GitHub already has all of this"
    return 0
  fi
  if [ "${YES:-0}" = 1 ]; then
    say "   (YES=1: going ahead without asking)"
    return 0
  fi
  if [ -t 0 ] && [ -t 1 ]; then
    printf 'Proceed? [y/N] '
    read -r ans || ans=""
    case "$ans" in y | Y | yes | Yes | YES) return 0 ;; esac
    say "stopped: nothing was changed."
    exit 1
  fi
  die "this run would change things on GitHub (the list above), and there is no terminal here to ask you on. Nothing was changed" \
    "to go ahead: YES=1 bash deploy.sh"
}

# ---- the four things that change GitHub -------------------------------------------------------------
do_repo() {
  [ "$REPO_EXISTS" = 0 ] || return 0
  gh repo create "$REPO" "--$VIS" \
    --description "hashfun: every launch is its own Bitcoin-fork chain, mined on a bonding curve" > /dev/null 2> "$TMP/repo.err" < /dev/null ||
    die "GitHub did not create $REPO ($(first_line "$TMP/repo.err"))" "if the name is taken or belongs to an organization you cannot write to: REPO=owner/name bash deploy.sh"
  say "   created https://github.com/$REPO ($VIS)"
}

push_failed() {
  die "GitHub refused the push (its own message is above)" \
    "if it names a workflow file or the 'workflow' scope:  gh auth refresh -h github.com -s workflow" \
    "if it says the repository was not found or permission was denied: you cannot write to $REPO; REPO=owner/name picks another" \
    "if it says the branch or tag moved (stale info): someone pushed since this script looked; run it again" \
    "if it names a secret (push protection): send that message to whoever made the patches" \
    "then run this again: it continues where it stopped"
}

do_push() {
  case "$BR" in
    same) ;;
    first)
      say "   pushing $BRANCH (the whole history the first time: a few minutes) ..."
      ggit push "$REMOTE" "refs/heads/$BRANCH:refs/heads/$BRANCH" || push_failed
      ;;
    forward)
      say "   pushing $BRANCH: $(short "$REMOTE_HEAD") -> $(short "$HEAD_SHA") ..."
      ggit push "$REMOTE" "refs/heads/$BRANCH:refs/heads/$BRANCH" || push_failed
      ;;
    replace)
      git -C "$SRC" branch -f "replaced-$(short "$REMOTE_HEAD")" "$REMOTE_HEAD" > /dev/null
      say "   replacing $BRANCH on GitHub: $(short "$REMOTE_HEAD") -> $(short "$HEAD_SHA") (the old one stays in $SRC as branch replaced-$(short "$REMOTE_HEAD"))"
      # only if GitHub still has what was there when the plan was made
      ggit push "--force-with-lease=refs/heads/$BRANCH:$REMOTE_HEAD" "$REMOTE" "refs/heads/$BRANCH:refs/heads/$BRANCH" || push_failed
      ;;
  esac
  git -C "$SRC" config hashfun.pushed "$HEAD_SHA"
  git -C "$SRC" config "branch.$BRANCH.remote" "$REMOTE"
  git -C "$SRC" config "branch.$BRANCH.merge" "refs/heads/$BRANCH"
  [ "$BR" = same ] || default_branch
}

# The Actions tab offers "Run workflow" only for the default branch, and a new clone checks it out.
default_branch() {
  local cur
  cur="$(gh repo view "$REPO" --json defaultBranchRef --jq '.defaultBranchRef.name // "-"' 2> /dev/null < /dev/null || echo "-")"
  [ "$cur" = "$BRANCH" ] && return 0
  if gh repo edit "$REPO" --default-branch "$BRANCH" > /dev/null 2> "$TMP/edit.err" < /dev/null; then
    say "   default branch of $REPO set to $BRANCH"
  else
    warn "could not make $BRANCH the default branch of $REPO ($(first_line "$TMP/edit.err")). Nothing depends on it: Settings, Default branch, when convenient"
  fi
}

do_secret() {
  [ "$NPM_DO" = 1 ] || return 0
  if printf '%s' "$TOK" | gh secret set NPM_TOKEN --repo "$REPO" > /dev/null 2> "$TMP/secret.err"; then
    NPM_STATE="set from ${NPM_TOKEN_FILE:-${HOME:-}/.npmnpm123}"
    SECRET_THERE=1
    say "   the npm token is now the secret NPM_TOKEN of $REPO (stored encrypted; nobody can read it back)"
    say "   note: if your npm account asks for a one-time code when publishing, the token must be an Automation token"
  else
    warn "GitHub did not store the secret ($(first_line "$TMP/secret.err")). GitHub will still build, test and make the release; nothing goes to npm until the repository has the secret NPM_TOKEN"
  fi
  TOK=""
}

# ---- the release tag ------------------------------------------------------------------------------
# Cancel the builds of this tag that have not ended, and wait (up to a minute) until GitHub says
# they have. Returns 0 when there was one to stop.
stop_tag_builds() {
  local ids id n=0 left
  ids="$(gh run list --repo "$REPO" --limit 30 --json databaseId,status,headBranch \
    --jq '.[] | select(.headBranch == "'"$TAGNAME"'" and .status != "completed") | .databaseId' 2> /dev/null < /dev/null || true)"
  [ -n "$ids" ] || return 1
  for id in $ids; do
    if gh run cancel "$id" --repo "$REPO" > /dev/null 2>&1 < /dev/null; then
      say "   stopped build $id of the commit $TAGNAME is leaving"
    fi
  done
  while [ "$n" -lt 12 ]; do
    left="$(gh run list --repo "$REPO" --limit 30 --json databaseId,status,headBranch \
      --jq '[.[] | select(.headBranch == "'"$TAGNAME"'" and .status != "completed")] | length' 2> /dev/null < /dev/null || echo 0)"
    [ "$left" = 0 ] && break
    n=$((n + 1))
    sleep "${CANCEL_POLL:-5}"
  done
  return 0
}

# One build per commit. The workflow runs for a push to the branch and for a tag, so a branch and
# a tag on the same commit start two full builds; the tag's also releases, so the branch's is
# stopped, once GitHub shows the tag's.
drop_branch_build() {
  local list="$TMP/dup.tsv" ids="" id tagrun=0 n=0
  while :; do
    gh run list --repo "$REPO" --limit 30 --json databaseId,status,event,headBranch,headSha \
      --jq '.[] | [(.databaseId | tostring), .status, .event, (.headBranch // "-"), .headSha] | @tsv' > "$list" 2> /dev/null < /dev/null || : > "$list"
    tagrun="$(awk -F'\t' -v t="$TAGNAME" -v s="$HEAD_SHA" '$4 == t && $5 == s { n++ } END { print n + 0 }' "$list")"
    ids="$(awk -F'\t' -v b="$BRANCH" -v s="$HEAD_SHA" '$3 == "push" && $4 == b && $5 == s && $2 != "completed" { print $1 }' "$list")"
    if [ "$tagrun" != 0 ] && [ -n "$ids" ]; then break; fi
    # nothing was pushed to the branch just now and no build of it is running: nothing to wait for
    if [ "$BR" = same ] && [ -z "$ids" ]; then return 0; fi
    n=$((n + 1))
    if [ "$n" -ge 8 ]; then return 0; fi
    [ "$n" != 1 ] || say "   (waiting up to 40 s for GitHub to list the builds of this commit, to stop the duplicate one)"
    sleep "${CANCEL_POLL:-5}"
  done
  for id in $ids; do
    if gh run cancel "$id" --repo "$REPO" > /dev/null 2>&1 < /dev/null; then
      say "   stopped build $id of the branch push: the build of $TAGNAME covers the same commit (one build per commit)"
    fi
  done
}

do_tag() {
  local rc=0
  [ "$TAG_DO" != none ] || return 0
  if [ "$TAG_DO" = move ]; then
    # The tag is about to leave a commit whose release build may still be running. A release
    # build is never cut short by a newer one (the new one would queue behind it for hours), so
    # stop it here; then ask npm once more, in case it had just published.
    if stop_tag_builds; then
      npm_has_version || rc=$?
      if [ "$rc" = 0 ]; then
        TAG_STATE="not moved: $PKG@$VERSION was published by the build that was running"
        warn "$PKG@$VERSION went to npm from the build that was running, so $TAGNAME stays on $(short "$TAG_CUR"). The new source needs the next version."
        return 0
      fi
    fi
  fi
  git -C "$SRC" tag -f "$TAGNAME" "$HEAD_SHA" > /dev/null
  if [ "$TAG_DO" = create ]; then
    say "   tagging $(short "$HEAD_SHA") as $TAGNAME ..."
    ggit push "$REMOTE" "refs/tags/$TAGNAME:refs/tags/$TAGNAME" || push_failed
    TAG_STATE="$TAGNAME on $(short "$HEAD_SHA")"
  else
    say "   moving $TAGNAME: $(short "$TAG_CUR") -> $(short "$HEAD_SHA") ($PKG@$VERSION is not on npm, so nothing published changes)"
    ggit push "--force-with-lease=refs/tags/$TAGNAME:$TAG_RAW" "$REMOTE" "refs/tags/$TAGNAME:refs/tags/$TAGNAME" || push_failed
    TAG_STATE="$TAGNAME moved to $(short "$HEAD_SHA")"
  fi
  drop_branch_build
}

# ---- which repository, for status and wait --------------------------------------------------------
known_repo() {
  local r=""
  if [ -n "${REPO:-}" ]; then
    printf '%s' "$REPO"
    return 0
  fi
  if [ -d "$SRC/.git" ] || [ -f "$SRC/.git" ]; then
    r="$(slug_of_url "$(git -C "$SRC" remote get-url "$(git -C "$SRC" config --get "branch.$BRANCH.remote" || echo origin)" 2> /dev/null || true)")"
  fi
  [ -n "$r" ] || [ ! -f "$OUT/deploy.txt" ] || r="$(sed -n 's/^repo: //p' "$OUT/deploy.txt" | sed -n '1p')"
  printf '%s' "$r"
}

# ---- status ---------------------------------------------------------------------------------------
# Sets RUN_ID (empty: no run yet), RUN_STATUS, RUN_CONCLUSION, SUMMARY1..3; writes status.txt, and
# failed.log unless called with "light" (the waiting loop looks every minute and fetches the logs
# once, at the end).
status_once() {
  local mode="${1:-full}" keep="${KEEP_LINES:-3000}" runs="$TMP/runs.tsv" jobs="$TMP/jobs.tsv" line now
  case "$keep" in "" | *[!0-9]*) keep=3000 ;; esac
  local n_ok n_bad n_open bad_names rel pub
  mkdir -p "$OUT"
  now="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  gh run list --repo "$REPO" --limit 15 \
    --json databaseId,status,conclusion,event,headBranch,headSha,createdAt,url \
    --jq '.[] | [(.databaseId | tostring), .status, (if (.conclusion // "") == "" then "-" else .conclusion end), .event, (.headBranch // "-"), .headSha, .createdAt, .url] | @tsv' \
    > "$runs" 2> "$TMP/runs.err" < /dev/null || die "could not read the builds of $REPO ($(first_line "$TMP/runs.err"))" "check: gh auth status"
  if [ ! -s "$runs" ]; then
    RUN_ID=""
    RUN_STATUS=none
    RUN_CONCLUSION=-
    {
      say "hashfun build status, written $now by deploy.sh"
      say "repo: $REPO"
      say "run: none yet (GitHub starts one a few seconds after a push)"
    } > "$OUT/status.txt"
    : > "$OUT/failed.log"
    SUMMARY1="no build of $REPO yet (GitHub starts one a few seconds after a push)"
    SUMMARY2="https://github.com/$REPO/actions"
    SUMMARY3="wrote $OUT/status.txt"
    return 0
  fi
  # The run that matters: the newest; when a release tag's run exists for the same commit, that one.
  line="$(awk -F'\t' 'NR == 1 { sha = $6; pick = $0 } $6 == sha && $5 ~ /^v[0-9]/ { pick = $0; exit } END { print pick }' "$runs")"
  RUN_ID="$(printf '%s' "$line" | cut -f1)"
  RUN_STATUS="$(printf '%s' "$line" | cut -f2)"
  RUN_CONCLUSION="$(printf '%s' "$line" | cut -f3)"
  local ev ref sha created url
  ev="$(printf '%s' "$line" | cut -f4)"
  ref="$(printf '%s' "$line" | cut -f5)"
  sha="$(printf '%s' "$line" | cut -f6)"
  created="$(printf '%s' "$line" | cut -f7)"
  url="$(printf '%s' "$line" | cut -f8)"
  gh run view "$RUN_ID" --repo "$REPO" --json jobs \
    --jq '.jobs[] | [(.databaseId | tostring), .status, (if (.conclusion // "") == "" then "-" else .conclusion end), .name, ([.steps[]? | select(.conclusion == "failure") | .name] | join("; ") | if . == "" then "-" else . end)] | @tsv' \
    > "$jobs" 2> "$TMP/jobs.err" < /dev/null || : > "$jobs"
  n_ok="$(awk -F'\t' '$3 == "success" || $3 == "skipped" { n++ } END { print n + 0 }' "$jobs")"
  n_bad="$(awk -F'\t' '$3 == "failure" || $3 == "timed_out" || $3 == "startup_failure" { n++ } END { print n + 0 }' "$jobs")"
  n_open="$(awk -F'\t' '$2 != "completed" { n++ } END { print n + 0 }' "$jobs")"
  bad_names="$(awk -F'\t' '$3 == "failure" || $3 == "timed_out" || $3 == "startup_failure" { s = s (s == "" ? "" : "; ") $4 } END { print s }' "$jobs")"

  # the failed jobs' logs, the last lines of each
  : > "$TMP/failed.log"
  local jid jconc jname jsteps
  while IFS="$(printf '\t')" read -r jid _ jconc jname jsteps; do
    [ "$mode" = full ] || break
    case "$jconc" in failure | timed_out | startup_failure) ;; *) continue ;; esac
    printf '===== %s (job %s): %s; failed steps: %s =====\n' "$jname" "$jid" "$jconc" "$jsteps" >> "$TMP/failed.log"
    if gh run view --repo "$REPO" --job "$jid" --log-failed > "$TMP/job.log" 2> "$TMP/job.err" < /dev/null && [ -s "$TMP/job.log" ]; then
      :
    elif gh api "repos/$REPO/actions/jobs/$jid/logs" > "$TMP/job.log" 2> "$TMP/job.err" < /dev/null && [ -s "$TMP/job.log" ]; then
      printf '(the whole job log: the failed steps alone could not be fetched yet)\n' >> "$TMP/failed.log"
    else
      printf '(no log yet: %s)\n\n' "$(first_line "$TMP/job.err")" >> "$TMP/failed.log"
      continue
    fi
    tail -n "$keep" "$TMP/job.log" >> "$TMP/failed.log"
    printf '\n' >> "$TMP/failed.log"
  done < "$jobs"
  if [ "$mode" = full ]; then
    [ -s "$TMP/failed.log" ] || say "no failed jobs in run $RUN_ID ($RUN_STATUS, $RUN_CONCLUSION) at $now" > "$TMP/failed.log"
    cp "$TMP/failed.log" "$OUT/failed.log"
  fi

  # release and npm, when the version is known
  rel="-"
  pub="-"
  if [ -n "${TAGNAME:-}" ]; then
    rel="$(gh release view "$TAGNAME" --repo "$REPO" --json url --jq .url 2> /dev/null < /dev/null || echo none)"
    local rc=0
    npm_has_version || rc=$?
    case "$rc" in 0) pub="$PKG@$VERSION is published" ;; 1) pub="$PKG@$VERSION is not published" ;; *) pub="$PKG@$VERSION: could not ask npm" ;; esac
  fi
  {
    say "hashfun build status, written $now by deploy.sh"
    say "repo: $REPO"
    say "run: $RUN_ID"
    say "url: $url"
    say "event: $ev"
    say "ref: $ref"
    say "commit: $sha"
    say "created: $created"
    say "status: $RUN_STATUS"
    say "conclusion: $RUN_CONCLUSION"
    say "jobs: $n_ok ok, $n_bad failed, $n_open not finished"
    say "release: $rel"
    say "npm: $pub"
    say ""
    say "jobs (status, conclusion, name, failed steps):"
    awk -F'\t' '{ printf "  %-11s %-10s %s   [%s]\n", $2, $3, $4, $5 }' "$jobs"
    [ -s "$jobs" ] || say "  (GitHub lists no jobs yet: $(first_line "$TMP/jobs.err"))"
    say ""
    say "recent runs (id, status, conclusion, event, ref, commit, created):"
    awk -F'\t' '{ printf "  %s %s %s %s %s %s %s\n", $1, $2, $3, $4, $5, substr($6, 1, 12), $7 }' "$runs"
  } > "$OUT/status.txt"
  SUMMARY1="run $RUN_ID ($ev $ref at $(short "$sha")): $RUN_STATUS, $RUN_CONCLUSION   $url"
  if [ "$n_bad" -gt 0 ]; then
    SUMMARY2="jobs: $n_ok ok, $n_bad failed ($bad_names), $n_open not finished"
  else
    SUMMARY2="jobs: $n_ok ok, 0 failed, $n_open not finished"
  fi
  SUMMARY3="wrote $OUT/status.txt and $OUT/failed.log"
}

version_if_known() {
  # for the release and npm lines of the status; quietly nothing when the source is not there
  PKG=""
  VERSION=""
  TAGNAME=""
  local sha
  sha="$(git -C "$SRC" rev-parse -q --verify "refs/heads/$BRANCH" 2> /dev/null || true)"
  [ -n "$sha" ] || return 0
  PKG="$(git -C "$SRC" show "$sha:contrib/hashfun/npm/package.json" 2> /dev/null | json_string name || true)"
  VERSION="$(git -C "$SRC" show "$sha:contrib/hashfun/npm/package.json" 2> /dev/null | json_string version || true)"
  if [ -n "$PKG" ] && [ -n "$VERSION" ]; then TAGNAME="v$VERSION"; else TAGNAME=""; fi
}

# ---- commands -------------------------------------------------------------------------------------
case "$CMD" in
  status | wait | logs | rerun)
    gh_login
    REPO="$(known_repo)"
    [ -n "$REPO" ] || die "nothing was deployed from here yet, so there is no build to look at" "first: bash deploy.sh    (or name the repository: REPO=owner/name bash deploy.sh $CMD)"
    version_if_known
    if [ "$CMD" = wait ]; then
      say "waiting for the build of $REPO to end (looking every ${POLL:-60} s; Ctrl-C stops the waiting, not the build)"
      tries=0
      last=""
      while :; do
        status_once light
        if [ "$RUN_STATUS" = completed ]; then
          status_once
          break
        fi
        if [ "$SUMMARY2" != "$last" ]; then
          say "  $(date '+%H:%M')  $SUMMARY2"
          last="$SUMMARY2"
        fi
        tries=$((tries + 1))
        if [ "$tries" -ge "${MAX_POLLS:-600}" ]; then
          say "still not finished; giving up the waiting. Look again with: bash deploy.sh status"
          status_once
          break
        fi
        sleep "${POLL:-60}"
      done
    else
      status_once
    fi
    if [ "$CMD" = logs ] && [ -n "$RUN_ID" ]; then
      # what the build jobs kept: every suite's log and the build logs, per platform. Into a new
      # folder each time (nothing is deleted here); ci/logs/latest.txt names the newest.
      KEPT="$OUT/logs/$RUN_ID-$(date -u '+%Y%m%dT%H%M%SZ')"
      mkdir -p "$KEPT"
      if gh run download "$RUN_ID" --repo "$REPO" --pattern 'logs-*' --dir "$KEPT" > /dev/null 2> "$TMP/dl.err" < /dev/null; then
        say "$KEPT" > "$OUT/logs/latest.txt"
        SUMMARY3="$SUMMARY3; the kept logs are in $KEPT/"
      else
        rmdir "$KEPT" 2> /dev/null || true
        SUMMARY3="$SUMMARY3; no kept logs to fetch ($(first_line "$TMP/dl.err"))"
      fi
    fi
    if [ "$CMD" = rerun ] && [ -n "$RUN_ID" ]; then
      if [ "$RUN_STATUS" != completed ]; then
        SUMMARY3="$SUMMARY3; not run again: build $RUN_ID has not ended yet"
      elif [ "$RUN_CONCLUSION" = success ]; then
        SUMMARY3="$SUMMARY3; not run again: build $RUN_ID succeeded"
      elif gh run rerun "$RUN_ID" --failed --repo "$REPO" > /dev/null 2> "$TMP/rerun.err" < /dev/null; then
        SUMMARY3="$SUMMARY3; the failed jobs of build $RUN_ID are running again (bash deploy.sh wait)"
      else
        SUMMARY3="$SUMMARY3; GitHub did not start them again ($(first_line "$TMP/rerun.err"))"
      fi
    fi
    if [ "$RUN_STATUS" = completed ] && [ "$RUN_CONCLUSION" = success ] && [ -n "$PKG" ]; then
      SUMMARY3="$SUMMARY3. Green: once npm has it (a minute after the release job): npm i -g $PKG && hashfun doctor"
    fi
    say "$SUMMARY1"
    say "$SUMMARY2"
    say "$SUMMARY3"
    ;;

  deploy)
    VIS="$(lower "${VISIBILITY:-public}")"
    case "$VIS" in public | private) ;; *) die "VISIBILITY is public or private, not $VIS" ;; esac

    step "1/5 GitHub login"
    gh_login
    REPO="${REPO:-$LOGIN/hashfun}"
    case "$REPO" in */*/* | /* | */ | *[!A-Za-z0-9._/-]*) die "REPO must be owner/name, not $REPO" ;; */*) ;; *) REPO="$LOGIN/$REPO" ;; esac
    say "   logged in as $LOGIN; shipping to https://github.com/$REPO"
    need_workflow_scope

    step "2/5 the source"
    build_source

    step "3/5 looking at what is there (nothing is changed yet)"
    look_repo
    pick_remote
    look_branch
    look_token
    look_secret
    look_tag

    step "4/5 what this run will do"
    plan
    confirm

    step "5/5 doing it"
    do_repo
    do_push
    do_secret
    do_tag

    mkdir -p "$OUT"
    {
      say "hashfun deploy, $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
      say "repo: $REPO"
      say "visibility: $REPO_VIS"
      say "branch: $BRANCH"
      say "commit: $HEAD_SHA"
      say "tree: $(git -C "$SRC" rev-parse "$HEAD_SHA^{tree}")"
      say "package: $PKG@$VERSION"
      say "tag: $TAG_STATE"
      say "npm token: $NPM_STATE"
      say "git: $(git --version)"
      say "gh: $(gh --version 2> /dev/null | sed -n '1p')"
      say "bash: ${BASH_VERSION:-?}"
      say "system: $(uname -sm 2> /dev/null || echo '?')"
    } > "$OUT/deploy.txt"

    step "done"
    say "GitHub is building now: https://github.com/$REPO/actions"
    say "It takes one to two hours the first time (four platforms, each tested; later runs reuse the compiler caches)."
    say ""
    say "  when it has ended:   bash \"$HERE/deploy.sh\" wait      (blocks until then, then writes the result to $OUT/)"
    say "  to look right now:   bash \"$HERE/deploy.sh\" status"
    case "$TAG_STATE" in
      "$TAGNAME"*)
        say "  when it is green:    npm i -g $PKG && hashfun doctor"
        case "$NPM_STATE" in set*) ;; *) say "                       (npm only has it if the repository has the NPM_TOKEN secret; without it the tarball is on https://github.com/$REPO/releases)" ;; esac
        ;;
      *) say "  nothing is released from this run (tag: $TAG_STATE)" ;;
    esac
    ;;

  *)
    die "deploy.sh knows: (nothing), status, wait, logs, rerun, help; not: $CMD"
    ;;
esac
