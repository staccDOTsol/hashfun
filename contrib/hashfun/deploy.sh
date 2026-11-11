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
#   bash deploy.sh kick      for when GitHub has the push and builds nothing: writes what GitHub
#                            says about the workflow to ci/kick.txt, switches Actions on if it
#                            is off, and starts the build (it asks for a run; if GitHub does not
#                            know the workflow, it pushes the release tag again, same commit)
#
# Before it changes anything on GitHub it prints what it is about to do (create or reuse the
# repository, push, store the token, tag: the tag is what makes GitHub publish to npm) and asks
# once. YES=1 answers that question in advance.
#
# A push is supposed to start the build. GitHub has been seen to start nothing for the first
# pushes to a new repository, so after pushing the script looks for the build of this commit,
# asks GitHub to run the workflow when none is listed, and says "building" only about a build it
# has seen. When there is none it says so and ends with a failure.
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
WORKFLOW=hashfun.yml
NPM_REGISTRY=https://registry.npmjs.org
# After a push, GitHub is given LIST_POLLS looks, CANCEL_POLL seconds apart (about 90 s), to list
# the build before the script asks for one itself. WAITED counts the looks spent so far.
LIST_POLLS=18
WAITED=0

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

# owner/name of the GitHub repository that remote $1 of the source points at; nothing when it is
# not a GitHub URL or there is no such remote. Asked both ways: as git resolves it (a machine's
# url.insteadOf rules applied) and as it is written in the configuration.
remote_slug() {
  local u slug
  for u in "$(git -C "$SRC" remote get-url "$1" 2> /dev/null || true)" "$(git -C "$SRC" config --get "remote.$1.url" 2> /dev/null || true)"; do
    slug="$(slug_of_url "$u")"
    if [ -n "$slug" ]; then
      printf '%s' "$slug"
      return 0
    fi
  done
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
  local url="https://github.com/$REPO.git" want
  want="$(lower "$REPO")"
  REMOTE=origin
  if git -C "$SRC" config --get remote.origin.url > /dev/null 2>&1 && [ "$(lower "$(remote_slug origin)")" != "$want" ]; then
    REMOTE=deploy
  fi
  if ! git -C "$SRC" config --get "remote.$REMOTE.url" > /dev/null 2>&1; then
    git -C "$SRC" remote add "$REMOTE" "$url"
  elif [ "$(lower "$(remote_slug "$REMOTE")")" != "$want" ]; then
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
      PUSHED_BRANCH=1
      ;;
    forward)
      say "   pushing $BRANCH: $(short "$REMOTE_HEAD") -> $(short "$HEAD_SHA") ..."
      ggit push "$REMOTE" "refs/heads/$BRANCH:refs/heads/$BRANCH" || push_failed
      PUSHED_BRANCH=1
      ;;
    replace)
      git -C "$SRC" branch -f "replaced-$(short "$REMOTE_HEAD")" "$REMOTE_HEAD" > /dev/null
      say "   replacing $BRANCH on GitHub: $(short "$REMOTE_HEAD") -> $(short "$HEAD_SHA") (the old one stays in $SRC as branch replaced-$(short "$REMOTE_HEAD"))"
      # only if GitHub still has what was there when the plan was made
      ggit push "--force-with-lease=refs/heads/$BRANCH:$REMOTE_HEAD" "$REMOTE" "refs/heads/$BRANCH:refs/heads/$BRANCH" || push_failed
      PUSHED_BRANCH=1
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

# ---- is GitHub building it ------------------------------------------------------------------------
# The newest builds GitHub lists, one per line: id, status, conclusion, event, branch or tag name,
# commit, url. LIST_OK=0 (and an empty list) when GitHub could not be asked: "none listed" and
# "could not ask" are different answers, and only the first is a reason to ask for a build.
list_builds() {
  LIST_OK=1
  if ! gh run list --repo "$REPO" --limit 40 --json databaseId,status,conclusion,event,headBranch,headSha,url \
    --jq '.[] | [(.databaseId | tostring), .status, (if (.conclusion // "") == "" then "-" else .conclusion end), .event, (.headBranch // "-"), .headSha, (.url // "-")] | @tsv' \
    > "$TMP/builds.tsv" 2> "$TMP/builds.err" < /dev/null; then
    LIST_OK=0
    : > "$TMP/builds.tsv"
  fi
}
# Out of the last list: the newest build of this commit on the branch or tag $1 (nothing: there is none).
build_on() { awk -F'\t' -v r="$1" -v s="$HEAD_SHA" '$5 == r && $6 == s { print; exit }' "$TMP/builds.tsv"; }
# The same, counting only a build that is queued, running or has succeeded: not one that failed or was stopped.
good_build_on() {
  awk -F'\t' -v r="$1" -v s="$HEAD_SHA" '$5 == r && $6 == s && ($2 != "completed" || $3 == "success") { print; exit }' "$TMP/builds.tsv"
}
# The page of a build, from its line of the list.
build_url() {
  local url
  url="$(printf '%s' "$1" | cut -f7)"
  case "$url" in
    http*) printf '%s' "$url" ;;
    *) printf 'https://github.com/%s/actions/runs/%s' "$REPO" "$(printf '%s' "$1" | cut -f1)" ;;
  esac
}

# One build per commit. The workflow runs for a push to the branch and for a tag, so a branch and
# a tag on the same commit start two full builds; the tag's also releases, so the branch's is
# stopped, once GitHub shows the tag's. $1: up to which count of WAITED this may wait for the two
# to be listed (its own count: nothing more is waited for).
drop_branch_build() {
  local max="$1" ids="" id tagrun=""
  while :; do
    list_builds
    tagrun="$(build_on "$TAGNAME")"
    ids="$(awk -F'\t' -v b="$BRANCH" -v s="$HEAD_SHA" '$4 == "push" && $5 == b && $6 == s && $2 != "completed" { print $1 }' "$TMP/builds.tsv")"
    if [ -n "$tagrun" ] && [ -n "$ids" ]; then break; fi
    # nothing was pushed to the branch just now and no build of it is running: nothing to wait for
    if [ "$BR" = same ] && [ -z "$ids" ]; then return 0; fi
    if [ "$WAITED" -ge "$max" ]; then return 0; fi
    [ "$WAITED" != 0 ] || say "   (waiting for GitHub to list the builds of this commit: up to a minute and a half)"
    WAITED=$((WAITED + 1))
    sleep "${CANCEL_POLL:-5}"
  done
  for id in $ids; do
    if gh run cancel "$id" --repo "$REPO" > /dev/null 2>&1 < /dev/null; then
      say "   stopped build $id of the branch push: the build of $TAGNAME covers the same commit (one build per commit)"
    fi
  done
}

# Is GitHub building this commit on $1 (the release tag, or the branch)? $2: 1 when this run
# pushed that ref, so that a build may still be on its way and is worth waiting for.
# A push is supposed to start the workflow. On a new repository GitHub has been seen to start
# nothing, for the branch and for the tag, with Actions switched on: no workflow and no build
# listed an hour later; asked to run the workflow, it started at once. So: look, wait for what a
# push may still bring, and when nothing is listed ask for the build. A build of this commit
# that is already listed, in whatever state, is never doubled.
# Returns 0 with BUILD_LINE (its line of the list) and BUILD_HOW (found, or asked: it had to be
# asked for); 1 with DISPATCH_ERR when there is no build, or (BUILD_UNKNOWN=1) when GitHub could
# not be asked which builds there are: then nothing is asked for either.
ensure_build() {
  local ref="$1" pushed="$2" n=0
  BUILD_LINE=""
  BUILD_HOW=""
  BUILD_UNKNOWN=0
  DISPATCH_ERR=""
  while :; do
    list_builds
    BUILD_LINE="$(build_on "$ref")"
    if [ -n "$BUILD_LINE" ]; then
      BUILD_HOW=found
      return 0
    fi
    [ "$pushed" = 1 ] || break
    [ "$WAITED" -lt "$LIST_POLLS" ] || break
    [ "$WAITED" != 0 ] || say "   (waiting for GitHub to list the build of this commit: up to a minute and a half)"
    WAITED=$((WAITED + 1))
    sleep "${CANCEL_POLL:-5}"
  done
  if [ "$LIST_OK" != 1 ]; then
    BUILD_UNKNOWN=1
    DISPATCH_ERR="GitHub could not be asked which builds there are ($(first_line "$TMP/builds.err"))"
    return 1
  fi
  say "   GitHub lists no build of this commit on $ref (it has been seen to ignore the first pushes to a new repository): asking it to run the workflow ..."
  if ! gh workflow run "$WORKFLOW" --repo "$REPO" --ref "$ref" > "$TMP/dispatch.out" 2> "$TMP/dispatch.err" < /dev/null; then
    DISPATCH_ERR="GitHub refused to run the workflow on $ref: $(first_line "$TMP/dispatch.err")"
    return 1
  fi
  while [ "$n" -lt 12 ]; do
    list_builds
    BUILD_LINE="$(build_on "$ref")"
    if [ -n "$BUILD_LINE" ]; then
      BUILD_HOW=asked
      return 0
    fi
    n=$((n + 1))
    sleep "${CANCEL_POLL:-5}"
  done
  DISPATCH_ERR="GitHub took the request to run the workflow on $ref and listed no build within a minute"
  return 1
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
    PUSHED_TAG=1
  else
    say "   moving $TAGNAME: $(short "$TAG_CUR") -> $(short "$HEAD_SHA") ($PKG@$VERSION is not on npm, so nothing published changes)"
    ggit push "--force-with-lease=refs/tags/$TAGNAME:$TAG_RAW" "$REMOTE" "refs/tags/$TAGNAME:refs/tags/$TAGNAME" || push_failed
    TAG_STATE="$TAGNAME moved to $(short "$HEAD_SHA")"
    PUSHED_TAG=1
  fi
  drop_branch_build 8
}

# ---- which repository, for status and wait --------------------------------------------------------
known_repo() {
  local r=""
  if [ -n "${REPO:-}" ]; then
    printf '%s' "$REPO"
    return 0
  fi
  if [ -d "$SRC/.git" ] || [ -f "$SRC/.git" ]; then
    r="$(remote_slug "$(git -C "$SRC" config --get "branch.$BRANCH.remote" || echo origin)")"
  fi
  [ -n "$r" ] || [ ! -f "$OUT/deploy.txt" ] || r="$(sed -n 's/^repo: //p' "$OUT/deploy.txt" | sed -n '1p')"
  printf '%s' "$r"
}

# ---- status ---------------------------------------------------------------------------------------
# The run that matters, out of the list in file $1 (newest first; column 5 the branch or tag,
# column 6 the commit): the newest of the commit the source here is at (when the source is here
# and GitHub lists one), else the newest of all; and of that commit's, a release tag's first.
pick_run() {
  awk -F'\t' -v want="${LOCAL_HEAD:-}" '
    { row[NR] = $0; sh[NR] = $6; rf[NR] = $5 }
    END {
      if (NR == 0) exit
      sha = sh[1]
      if (want != "") for (i = 1; i <= NR; i++) if (sh[i] == want) { sha = want; break }
      pick = ""
      for (i = 1; i <= NR; i++) if (sh[i] == sha) {
        if (pick == "") pick = row[i]
        if (rf[i] ~ /^v[0-9]/) { pick = row[i]; break }
      }
      print pick
    }' "$1"
}

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
    STALE=""
    {
      say "hashfun build status, written $now by deploy.sh"
      say "repo: $REPO"
      say "run: none yet (GitHub lists a build within a minute of a push; when the push is older than that: bash deploy.sh kick)"
      say "local: ${LOCAL_HEAD:--}"
    } > "$OUT/status.txt"
    : > "$OUT/failed.log"
    SUMMARY1="no build of $REPO yet   https://github.com/$REPO/actions"
    SUMMARY2="GitHub lists a build within a minute of a push. When the push is older than that, it is not going to start one by itself: bash \"$HERE/deploy.sh\" kick"
    SUMMARY3="wrote $OUT/status.txt"
    return 0
  fi
  line="$(pick_run "$runs")"
  RUN_ID="$(printf '%s' "$line" | cut -f1)"
  RUN_STATUS="$(printf '%s' "$line" | cut -f2)"
  RUN_CONCLUSION="$(printf '%s' "$line" | cut -f3)"
  local ev ref sha created url
  ev="$(printf '%s' "$line" | cut -f4)"
  ref="$(printf '%s' "$line" | cut -f5)"
  sha="$(printf '%s' "$line" | cut -f6)"
  created="$(printf '%s' "$line" | cut -f7)"
  url="$(printf '%s' "$line" | cut -f8)"
  # a build of some other commit says nothing about the source here: say so before anything else
  STALE=""
  if [ -n "${LOCAL_HEAD:-}" ] && [ "$sha" != "$LOCAL_HEAD" ]; then
    STALE="NOT A BUILD OF THE SOURCE HERE (the source is at $(short "$LOCAL_HEAD"); GitHub lists no build of that commit; start one: bash \"$HERE/deploy.sh\", or if it is pushed already: bash \"$HERE/deploy.sh\" kick). The newest build there is: "
  fi
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
    say "local: ${LOCAL_HEAD:--}"
    if [ -n "$STALE" ]; then say "stale: yes (this build is not of the commit the source here is at)"; else say "stale: no"; fi
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
  SUMMARY1="${STALE}run $RUN_ID ($ev $ref at $(short "$sha")): $RUN_STATUS, $RUN_CONCLUSION   $url"
  if [ "$n_bad" -gt 0 ]; then
    SUMMARY2="jobs: $n_ok ok, $n_bad failed ($bad_names), $n_open not finished"
  else
    SUMMARY2="jobs: $n_ok ok, 0 failed, $n_open not finished"
  fi
  SUMMARY3="wrote $OUT/status.txt and $OUT/failed.log"
}

version_if_known() {
  # for the release and npm lines of the status, and to tell a build of this source from one of
  # another commit; quietly nothing when the source is not there
  PKG=""
  VERSION=""
  TAGNAME=""
  LOCAL_HEAD=""
  local sha
  sha="$(git -C "$SRC" rev-parse -q --verify "refs/heads/$BRANCH" 2> /dev/null || true)"
  [ -n "$sha" ] || return 0
  LOCAL_HEAD="$sha"
  PKG="$(git -C "$SRC" show "$sha:contrib/hashfun/npm/package.json" 2> /dev/null | json_string name || true)"
  VERSION="$(git -C "$SRC" show "$sha:contrib/hashfun/npm/package.json" 2> /dev/null | json_string version || true)"
  if [ -n "$PKG" ] && [ -n "$VERSION" ]; then TAGNAME="v$VERSION"; else TAGNAME=""; fi
}

# ---- kick: what GitHub says, kept in a file --------------------------------------------------------
knote() {
  say "$*"
  say "$*" >> "$KLOG"
}
# one question to GitHub, its answer and its exit status into the file; never stops the script
kask() {
  local title="$1" rc=0
  shift
  say "== $title" >> "$KLOG"
  "$@" >> "$KLOG" 2>&1 < /dev/null || rc=$?
  say "   (exit $rc)" >> "$KLOG"
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
      none=0
      last=""
      while :; do
        status_once light
        if [ "$RUN_STATUS" = completed ]; then
          status_once
          break
        fi
        progress="$SUMMARY2"
        if [ "$RUN_STATUS" = none ]; then
          # two more looks; a build that is not listed by then is not coming (the last lines say what to do)
          none=$((none + 1))
          if [ "$none" -ge 3 ]; then break; fi
          progress="no build listed yet"
        fi
        if [ "$progress" != "$last" ]; then
          say "  $(date '+%H:%M')  $progress"
          last="$progress"
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
      if [ -n "$STALE" ]; then
        SUMMARY3="$SUMMARY3; not run again: build $RUN_ID is of another commit than the source here"
      elif [ "$RUN_STATUS" != completed ]; then
        SUMMARY3="$SUMMARY3; not run again: build $RUN_ID has not ended yet"
      elif [ "$RUN_CONCLUSION" = success ]; then
        SUMMARY3="$SUMMARY3; not run again: build $RUN_ID succeeded"
      elif gh run rerun "$RUN_ID" --failed --repo "$REPO" > /dev/null 2> "$TMP/rerun.err" < /dev/null; then
        SUMMARY3="$SUMMARY3; the failed jobs of build $RUN_ID are running again (bash deploy.sh wait)"
      else
        SUMMARY3="$SUMMARY3; GitHub did not start them again ($(first_line "$TMP/rerun.err"))"
      fi
    fi
    if [ "$RUN_STATUS" = completed ] && [ "$RUN_CONCLUSION" = success ] && [ -n "$PKG" ] && [ -z "${STALE:-}" ]; then
      SUMMARY3="$SUMMARY3. Green: once npm has it (a minute after the release job): npm i -g $PKG && hashfun doctor"
    fi
    say "$SUMMARY1"
    say "$SUMMARY2"
    say "$SUMMARY3"
    ;;

  kick)
    gh_login
    REPO="$(known_repo)"
    [ -n "$REPO" ] || die "nothing was deployed from here yet, so there is no build to start" "first: bash deploy.sh    (or name the repository: REPO=owner/name bash deploy.sh kick)"
    version_if_known
    HEAD_SHA="$LOCAL_HEAD"
    [ -n "$HEAD_SHA" ] && [ -n "$TAGNAME" ] || die "no source repository with a branch $BRANCH at $SRC, so there is no commit to build" "first: bash deploy.sh"
    # the remote of the source repository that is this GitHub repository
    REMOTE=""
    for r in "$(git -C "$SRC" config --get "branch.$BRANCH.remote" || true)" origin deploy; do
      [ -n "$r" ] || continue
      if [ "$(lower "$(remote_slug "$r")")" = "$(lower "$REPO")" ]; then
        REMOTE="$r"
        break
      fi
    done
    [ -n "$REMOTE" ] || die "$SRC has no remote for https://github.com/$REPO" "first: bash deploy.sh"
    ggit ls-remote "$REMOTE" "refs/heads/$BRANCH" "refs/tags/$TAGNAME*" > "$TMP/refs" 2> "$TMP/ls.err" ||
      die "could not read $REPO over git ($(first_line "$TMP/ls.err"))" "check the network, then: gh auth status"
    REMOTE_HEAD="$(awk -v t="refs/heads/$BRANCH" '$2 == t { print $1 }' "$TMP/refs")"
    TAG_RAW="$(awk -v t="refs/tags/$TAGNAME" '$2 == t { print $1 }' "$TMP/refs")"
    TAG_CUR="$(awk -v t="refs/tags/$TAGNAME^{}" '$2 == t { print $1 }' "$TMP/refs")"
    TAG_CUR="${TAG_CUR:-$TAG_RAW}"
    # what to build: the release tag when it is on this commit, else the branch
    if [ "$TAG_CUR" = "$HEAD_SHA" ]; then
      KREF="$TAGNAME"
    elif [ "$REMOTE_HEAD" = "$HEAD_SHA" ]; then
      KREF="$BRANCH"
    else
      die "GitHub has neither $BRANCH nor $TAGNAME on the commit the source here is at ($(short "$HEAD_SHA"))" "push it first: bash deploy.sh"
    fi
    mkdir -p "$OUT"
    KLOG="$OUT/kick.txt"
    {
      say "hashfun kick, $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
      say "repo: $REPO"
      say "commit: $HEAD_SHA"
      say "ref: $KREF"
    } > "$KLOG"

    say "1/4 asking GitHub what it knows about the workflow on $REPO ..."
    kask "login" gh api user --jq '.login'
    kask "repository" gh api "repos/$REPO" --jq '{visibility, fork, disabled, archived, default_branch, size, created_at, pushed_at}'
    kask "actions permissions" gh api "repos/$REPO/actions/permissions"
    kask "workflows GitHub knows" gh api "repos/$REPO/actions/workflows" --jq '.total_count, (.workflows[] | [.name, .path, .state] | @tsv)'
    kask "builds GitHub lists" gh run list --repo "$REPO" --limit 10
    kask "the workflow file on $KREF" gh api "repos/$REPO/contents/.github/workflows/$WORKFLOW?ref=$KREF" --jq '{path, size, sha}'
    kask "check suites of the commit" gh api "repos/$REPO/commits/$HEAD_SHA/check-suites" --jq '.check_suites[] | [.app.slug, .status, (.conclusion // "-"), (.head_branch // "-")] | @tsv'

    # never a second build beside one that is queued, running or has succeeded
    list_builds
    [ "$LIST_OK" = 1 ] || die "could not read the builds of $REPO ($(first_line "$TMP/builds.err")), so nothing was started: a build may be there" "check: gh auth status    then again: bash deploy.sh kick"
    line="$(good_build_on "$KREF")"
    if [ -n "$line" ]; then
      knote "a build of this commit on $KREF is there already ($(printf '%s' "$line" | cut -f2), $(printf '%s' "$line" | cut -f3)): nothing to start.   $(build_url "$line")"
      knote "look at it with: bash \"$HERE/deploy.sh\" status"
      exit 0
    fi
    line="$(build_on "$KREF")"
    [ -z "$line" ] || knote "   (the last build of this commit on $KREF ended as $(printf '%s' "$line" | cut -f3): a new one is started. Only its failed jobs again would be: bash \"$HERE/deploy.sh\" rerun)"

    say "2/4 making sure Actions is switched on for $REPO ..."
    enabled="$(gh api "repos/$REPO/actions/permissions" --jq '.enabled' 2> /dev/null < /dev/null || echo unknown)"
    if [ "$enabled" = true ]; then
      knote "   it is on"
    elif [ "$enabled" = false ]; then
      if gh api -X PUT "repos/$REPO/actions/permissions" -F enabled=true >> "$KLOG" 2>&1 < /dev/null; then
        knote "   Actions was switched off for this repository: switched on"
      else
        knote "   Actions is switched off for this repository and could not be switched on from here (GitHub's answer is in $KLOG): Settings, Actions, General"
      fi
    else
      knote "   (GitHub did not say whether it is on; going on)"
    fi

    say "3/4 starting the build of $(short "$HEAD_SHA") on $KREF ..."
    HOW=""
    if gh workflow run "$WORKFLOW" --repo "$REPO" --ref "$KREF" >> "$KLOG" 2>&1 < /dev/null; then
      HOW="asked GitHub to run the workflow on $KREF"
    elif [ "$KREF" != "$TAGNAME" ]; then
      knote "   GitHub refused to run the workflow on $KREF (its answer is in $KLOG). A branch cannot be pushed again the way a tag can."
    else
      knote "   GitHub refused to run the workflow on $KREF (its answer is in $KLOG). The other trigger is the push of the tag:"
      rc=0
      npm_has_version || rc=$?
      if [ "$rc" = 0 ]; then
        knote "   $TAGNAME is NOT pushed again: $PKG@$VERSION is on npm already, and the tag of a published version is left alone"
      elif [ "$rc" = 2 ]; then
        knote "   $TAGNAME is NOT pushed again: npm could not be asked whether $PKG@$VERSION is published (again when npm answers: npm view $PKG@$VERSION version)"
      elif ggit fetch -q "$REMOTE" "+refs/tags/$TAGNAME:refs/tags/$TAGNAME" >> "$KLOG" 2>&1 &&
        ggit push "--force-with-lease=refs/tags/$TAGNAME:$TAG_RAW" "$REMOTE" ":refs/tags/$TAGNAME" >> "$KLOG" 2>&1; then
        # exactly what GitHub had under that name went away; it comes back unchanged
        if ggit push "$REMOTE" "refs/tags/$TAGNAME:refs/tags/$TAGNAME" >> "$KLOG" 2>&1; then
          HOW="deleted $TAGNAME on GitHub and pushed it again, on the same commit"
        else
          knote "   $TAGNAME was deleted on GitHub and could NOT be pushed again (git's message is in $KLOG). Put it back with: bash \"$HERE/deploy.sh\""
        fi
      else
        knote "   $TAGNAME could not be pushed again (git's message is in $KLOG); it is on GitHub as it was"
      fi
    fi
    found=""
    if [ -n "$HOW" ]; then
      knote "   $HOW"
      say "4/4 waiting up to two minutes for GitHub to list the build ..."
      n=0
      while [ "$n" -lt 24 ]; do
        list_builds
        found="$(good_build_on "$KREF")"
        [ -z "$found" ] || break
        n=$((n + 1))
        sleep "${CANCEL_POLL:-5}"
      done
    fi
    kask "workflows GitHub knows, after" gh api "repos/$REPO/actions/workflows" --jq '.total_count, (.workflows[] | [.name, .path, .state] | @tsv)'
    kask "builds GitHub lists, after" gh run list --repo "$REPO" --limit 10
    if [ -n "$found" ]; then
      if [ "$KREF" = "$TAGNAME" ]; then
        BR=same
        drop_branch_build 0 # one build per commit: a build of the branch push that is running beside it is stopped
      fi
      knote "GitHub is building now: $(build_url "$found")"
      knote "when it has ended:   bash \"$HERE/deploy.sh\" wait"
    else
      knote "no build of this commit was started."
      knote "Open https://github.com/$REPO/actions in a browser, logged in: a notice or a button there about enabling workflows is the answer."
      knote "What GitHub said is in $KLOG"
      exit 1
    fi
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
    PUSHED_BRANCH=0
    PUSHED_TAG=0
    do_repo
    do_push
    do_secret
    do_tag

    # The build to expect: the release tag's when the tag is on this commit now, else the branch's.
    case "$TAG_STATE" in
      "$TAGNAME"*)
        BUILD_REF="$TAGNAME"
        BUILD_PUSHED="$PUSHED_TAG"
        ;;
      *)
        BUILD_REF="$BRANCH"
        BUILD_PUSHED="$PUSHED_BRANCH"
        ;;
    esac
    BUILD_OK=1
    ensure_build "$BUILD_REF" "$BUILD_PUSHED" || BUILD_OK=0
    if [ "$BUILD_OK" = 1 ] && [ "$BUILD_HOW" = asked ] && [ "$BUILD_REF" = "$TAGNAME" ]; then
      drop_branch_build "$WAITED" # GitHub may have started the branch's build and not the tag's: one build per commit
    fi
    B_URL=""
    B_STATUS=""
    B_CONCLUSION=""
    if [ "$BUILD_OK" = 1 ]; then
      B_URL="$(build_url "$BUILD_LINE")"
      B_STATUS="$(printf '%s' "$BUILD_LINE" | cut -f2)"
      B_CONCLUSION="$(printf '%s' "$BUILD_LINE" | cut -f3)"
    fi

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
      if [ "$BUILD_OK" = 1 ]; then
        say "build: $B_URL ($B_STATUS, $B_CONCLUSION; on $BUILD_REF; $BUILD_HOW)"
      else
        say "build: none ($DISPATCH_ERR)"
      fi
      say "git: $(git --version)"
      say "gh: $(gh --version 2> /dev/null | sed -n '1p')"
      say "bash: ${BASH_VERSION:-?}"
      say "system: $(uname -sm 2> /dev/null || echo '?')"
    } > "$OUT/deploy.txt"

    if [ "$BUILD_OK" != 1 ]; then
      case "$TAG_STATE" in
        "$TAGNAME"*) HAS="the branch and the tag $TAGNAME" ;;
        *) HAS="the branch" ;;
      esac
      if [ "$BUILD_UNKNOWN" = 1 ]; then
        step "pushed; whether it is building is not known"
        say "GitHub has $HAS. $DISPATCH_ERR, so no build was asked for either."
        say ""
        say "  to look again:       bash \"$HERE/deploy.sh\" status"
        say "  if none is listed:   bash \"$HERE/deploy.sh\" kick"
        exit 1
      fi
      step "NOT building"
      say "GitHub has $HAS, and it has started no build of this commit."
      say "$DISPATCH_ERR"
      say ""
      say "  to try again:        bash \"$HERE/deploy.sh\" kick      (asks GitHub what it knows about the workflow, into $OUT/kick.txt, and starts the build another way)"
      say "  and look here:       https://github.com/$REPO/actions      (in a browser, logged in: a notice or a button about enabling workflows is the answer)"
      say "  a build that shows up late after all:   bash \"$HERE/deploy.sh\" status"
      exit 1
    fi

    step "done"
    if [ "$B_STATUS" = completed ]; then
      say "GitHub has built this commit already ($B_CONCLUSION): $B_URL"
      [ "$B_CONCLUSION" = success ] || say "(its failed jobs again: bash \"$HERE/deploy.sh\" rerun)"
    else
      say "GitHub is building now: $B_URL"
      [ "$BUILD_HOW" != asked ] || say "(GitHub started nothing for the push itself; this build was started by asking for it, on $BUILD_REF)"
      say "It takes one to two hours the first time (four platforms, each tested; later runs reuse the compiler caches)."
    fi
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
    die "deploy.sh knows: (nothing), status, wait, logs, rerun, kick, help; not: $CMD"
    ;;
esac
