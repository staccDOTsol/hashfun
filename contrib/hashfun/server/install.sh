#!/usr/bin/env bash
# hashfun server: Bitcoin Core (from a UTXO snapshot, usable in hours, not days), every launch's
# node, and the site behind HTTPS, on a fresh Ubuntu 22.04 or 24.04 box (x86_64 or arm64).
#
#   curl -fsSLO https://raw.githubusercontent.com/staccDOTsol/hashfun/hashfun/contrib/hashfun/server/install.sh
#   sudo DOMAIN=hash.fun EMAIL=you@example.com bash install.sh
#
# Knobs:
#   DOMAIN      the site's name; its DNS A/AAAA record must point here (HTTPS from Let's Encrypt
#               via Caddy). Without it the site is served on plain http://<ip>/.
#   EMAIL       for Let's Encrypt notices (optional)
#   PRUNE       MB of Bitcoin blocks to keep (default 20000; 0 = keep all, about 750 GB)
#   SNAPSHOT=0  sync Bitcoin from scratch instead of the 935,000 snapshot (1 to 2 days)
#   INDEX=1|0   a Bitcoin index (Fulcrum) so the site reads any address's sats in milliseconds instead
#               of a UTXO-set scan of about a minute each. Needs every block kept (PRUNE=0, about
#               1.1 TB of disk in all). Default: on when the disk has room, else off (the scan stays).
#   ALLOW_LAUNCH=0   the launch form is off (by default anyone on the site can launch a coin here)
#   HASHFUN_TGZ      install hashfun from this tarball (path or URL) instead of npm
#
# Safe to run again: it changes only what is not as it should be.
#
# Afterwards:
#   hashfun-status            what the box is doing (Bitcoin sync, snapshot, launches, site)
#   journalctl -u hashfun-web -f
set -euo pipefail

# ---- pinned ----------------------------------------------------------------------------------
BTC_VER=32.1
BTC_SHA_x86_64=61545c17c3120fb7412f896d248b11993af04ec8817aad3649c55b2afb044963
BTC_SHA_aarch64=7ed37c7373eb6aa3e3f72842596a1afeba1b223717033cade9842b25773e1922
# assumeutxo: the node itself refuses any file whose contents do not hash to the value compiled
# into this release, so where it is downloaded from does not matter for safety.
SNAP_HEIGHT=935000
SNAP_URL=https://files-vps02.jaonoctus.dev/utxo-935000.dat
SNAP_BLOCK=0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee
FULCRUM_VER=2.1.4
FULCRUM_SHA_x86_64=faf7cb36266c1694c834ad551d9592c0aef357bca66fdb5efdfe0d131c4b38ae
FULCRUM_SHA_aarch64=bc9cda576bf889222e89c7616012e628597e4921f9116eebc759dfc854785b84
RELEASE_TGZ=https://github.com/staccDOTsol/hashfun/releases/download/v0.1.0/hashfun-0.1.0.tgz

DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
PRUNE="${PRUNE:-}"
INDEX="${INDEX:-}"
SNAPSHOT="${SNAPSHOT:-1}"
ALLOW_LAUNCH="${ALLOW_LAUNCH:-1}"
HASHFUN_TGZ="${HASHFUN_TGZ:-}"
ROOT="${ROOT:-}"            # tests: install under this prefix, touch nothing else
DRY="${DRY:-0}"             # tests: print what would run

U=hashfun
HOMEDIR="$ROOT/var/lib/hashfun"
BTCDIR="$HOMEDIR/bitcoin"
OPT="$ROOT/opt/bitcoin-$BTC_VER"
ETC="$ROOT/etc"

say() { printf '\n== %s\n' "$*"; }
run() {
  if [ "$DRY" = 1 ]; then printf '   + %s\n' "$*"; else "$@"; fi
}
die() {
  printf 'stopped: %s\n' "$*" >&2
  exit 1
}

[ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || die "run as root: sudo bash $0"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) BTC_SHA=$BTC_SHA_x86_64 FC_ARCH=x86_64 FC_SHA=$FULCRUM_SHA_x86_64 ;;
  aarch64 | arm64) ARCH=aarch64 BTC_SHA=$BTC_SHA_aarch64 FC_ARCH=arm64 FC_SHA=$FULCRUM_SHA_aarch64 ;;
  *) die "unsupported CPU $ARCH (x86_64 or arm64)" ;;
esac
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:22.04 | ubuntu:24.04 | ubuntu:26.04 | debian:12 | debian:13) ;;
    *) printf 'note: tested for Ubuntu 22.04/24.04; this is %s %s, going on\n' "${ID:-?}" "${VERSION_ID:-?}" ;;
  esac
fi
if [ -n "$DOMAIN" ]; then
  case "$DOMAIN" in *[!A-Za-z0-9.-]* | .* | *. | '') die "DOMAIN=$DOMAIN is not a host name" ;; esac
fi
# the index needs every block; decide it before the prune setting
free_gb="$(df -BG --output=avail "${ROOT:-/}" 2> /dev/null | tail -1 | tr -dc 0-9)"
if [ -z "$INDEX" ]; then
  if [ "${free_gb:-0}" -ge 1100 ] && [ "${PRUNE:-0}" = 0 ]; then INDEX=1; else INDEX=0; fi
  [ "$INDEX" = 1 ] || printf 'note: no Bitcoin index (%s GB free; it needs about 1100 and PRUNE=0): the site scans the UTXO set instead\n' "${free_gb:-?}"
fi
if [ "$INDEX" = 1 ]; then
  [ "${PRUNE:-0}" = 0 ] || die "INDEX=1 needs every block: PRUNE=0"
  PRUNE=0
fi
PRUNE="${PRUNE:-20000}"
case "$PRUNE" in *[!0-9]*) die "PRUNE must be a number of MB" ;; esac
[ "$PRUNE" = 0 ] || [ "$PRUNE" -ge 550 ] || die "PRUNE must be 0 or at least 550"

# ---- 1. packages -----------------------------------------------------------------------------
say "1/7 packages"
export DEBIAN_FRONTEND=noninteractive
run apt-get update -q
run apt-get install -y -q --no-install-recommends ca-certificates curl python3 nodejs npm caddy ufw jq
if [ "$DRY" != 1 ]; then
  python3 -c 'import sys, hashlib; sys.exit(0 if sys.version_info >= (3, 10) and hasattr(hashlib, "scrypt") else 1)' ||
    die "python3 must be 3.10 or newer with hashlib.scrypt"
  nodemajor="$(node -p 'process.versions.node.split(".")[0]')"
  [ "$nodemajor" -ge 18 ] || die "Node.js 18 or newer is needed (this is $(node -v))"
fi

# ---- 2. the user -----------------------------------------------------------------------------
say "2/7 user $U, data in $HOMEDIR"
if [ "$DRY" != 1 ] && ! id "$U" > /dev/null 2>&1; then
  useradd --system --home-dir "$HOMEDIR" --create-home --shell /usr/sbin/nologin "$U"
fi
run mkdir -p "$BTCDIR"
run chown -R "$U:$U" "$HOMEDIR"

# ---- 3. Bitcoin Core -------------------------------------------------------------------------
say "3/7 Bitcoin Core $BTC_VER"
if [ ! -x "$OPT/bin/bitcoind" ]; then
  tgz="bitcoin-$BTC_VER-$ARCH-linux-gnu.tar.gz"
  tmp="$(mktemp -d)"
  run curl -fSL --retry 3 -o "$tmp/$tgz" "https://bitcoincore.org/bin/bitcoin-core-$BTC_VER/$tgz"
  if [ "$DRY" != 1 ]; then
    echo "$BTC_SHA  $tmp/$tgz" | sha256sum -c - > /dev/null || die "$tgz does not match its pinned sha256"
    mkdir -p "$OPT"
    tar -xzf "$tmp/$tgz" -C "$OPT" --strip-components=1
  fi
  rm -rf "$tmp"
fi
for b in bitcoind bitcoin-cli; do run ln -sf "$OPT/bin/$b" "$ROOT/usr/local/bin/$b"; done
conf="$BTCDIR/bitcoin.conf"
want="# written by hashfun install.sh
server=1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
listen=1
prune=$PRUNE
dbcache=2000
maxmempool=300
# the cookie file is the RPC password; hashfun web reads it as the same user
rpccookieperms=owner"
if [ "$DRY" = 1 ]; then
  printf '   + write %s\n' "$conf"
elif [ "$(cat "$conf" 2> /dev/null || true)" != "$want" ]; then
  printf '%s\n' "$want" > "$conf"
  chown "$U:$U" "$conf"
fi

# ---- 4. hashfun --------------------------------------------------------------------------------
say "4/7 hashfun"
if [ -n "$HASHFUN_TGZ" ]; then
  src="$HASHFUN_TGZ"
elif [ "$DRY" = 1 ] || npm view hashfun version > /dev/null 2>&1; then
  src=hashfun
else
  src="$RELEASE_TGZ"   # not on npm (yet): the tested tarball from the GitHub release
fi
run npm install -g --no-fund --no-audit "$src"
if [ "$DRY" != 1 ]; then
  command -v hashfun > /dev/null || die "npm installed hashfun but it is not on PATH"
  sudo -u "$U" -H hashfun doctor --quick || die "hashfun doctor failed (above)"
fi

# ---- 5. services -------------------------------------------------------------------------------
say "5/7 services"
unit() { # name, contents: written only when different
  local f="$ETC/systemd/system/$1"
  if [ "$DRY" = 1 ]; then
    printf '   + write %s\n' "$f"
    return
  fi
  mkdir -p "$(dirname "$f")"
  if [ "$(cat "$f" 2> /dev/null || true)" != "$2" ]; then printf '%s\n' "$2" > "$f"; fi
}
unit bitcoind.service "[Unit]
Description=Bitcoin Core (for hashfun)
After=network-online.target
Wants=network-online.target

[Service]
User=$U
Group=$U
ExecStart=$OPT/bin/bitcoind -datadir=$BTCDIR -conf=$conf -printtoconsole=0
Restart=on-failure
TimeoutStopSec=600
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target"

if [ "$SNAPSHOT" = 1 ]; then
  run install -m 0755 /dev/stdin "$ROOT/usr/local/bin/hashfun-snapshot" << SNAP
#!/usr/bin/env bash
# Load the Bitcoin UTXO snapshot at $SNAP_HEIGHT once: the node is then usable after it catches up
# from there (hours), and checks the history before it in the background.
set -euo pipefail
cli() { $OPT/bin/bitcoin-cli -datadir=$BTCDIR -rpcclienttimeout=0 "\$@"; }
f=$BTCDIR/utxo-$SNAP_HEIGHT.dat
done=$BTCDIR/.snapshot-done
[ -e "\$done" ] && exit 0
until cli getblockchaininfo > /dev/null 2>&1; do sleep 5; done
info="\$(cli getblockchaininfo)"
blocks="\$(echo "\$info" | jq .blocks)"
if [ "\$blocks" -ge $SNAP_HEIGHT ] || [ "\$(cli getchainstates | jq '.chainstates | length')" -gt 1 ]; then
  touch "\$done"; exit 0   # synced past it already, or a snapshot is loaded
fi
echo "downloading the UTXO snapshot (about 9 GB; resumes if interrupted)"
curl -fSL --retry 20 --retry-delay 10 -C - -o "\$f.part" $SNAP_URL
mv "\$f.part" "\$f"
echo "waiting for Bitcoin headers to pass $SNAP_HEIGHT"
until [ "\$(cli getblockchaininfo | jq .headers)" -ge $SNAP_HEIGHT ]; do sleep 20; done
[ "\$(cli getblockhash $SNAP_HEIGHT)" = $SNAP_BLOCK ] || { echo "block $SNAP_HEIGHT is not the expected one"; exit 1; }
echo "loading it (10 to 30 minutes)"
cli loadtxoutset "\$f"
rm -f "\$f"
touch "\$done"
echo "snapshot loaded; the node now catches up to the tip"
SNAP
  unit hashfun-snapshot.service "[Unit]
Description=Load the Bitcoin UTXO snapshot (once)
After=bitcoind.service
Requires=bitcoind.service

[Service]
Type=oneshot
User=$U
ExecStart=/usr/local/bin/hashfun-snapshot
TimeoutStartSec=infinity
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target"
fi

if [ "$INDEX" = 1 ]; then
  FC="$ROOT/opt/fulcrum-$FULCRUM_VER"
  if [ ! -x "$FC/Fulcrum" ]; then
    t="Fulcrum-$FULCRUM_VER-$FC_ARCH-linux.tar.gz"
    tmp="$(mktemp -d)"
    run curl -fSL --retry 3 -o "$tmp/$t" "https://github.com/cculianu/Fulcrum/releases/download/v$FULCRUM_VER/$t"
    if [ "$DRY" != 1 ]; then
      echo "$FC_SHA  $tmp/$t" | sha256sum -c - > /dev/null || die "$t does not match its pinned sha256"
      mkdir -p "$tmp/x" "$FC"
      tar -xzf "$tmp/$t" -C "$tmp/x"
      bin="$(find "$tmp/x" -type f -name Fulcrum | head -1)"
      [ -n "$bin" ] || die "no Fulcrum binary in $t"
      install -m 0755 "$bin" "$FC/Fulcrum"
    fi
    rm -rf "$tmp"
  fi
  run mkdir -p "$HOMEDIR/fulcrum"
  run chown "$U:$U" "$HOMEDIR/fulcrum"
  fcconf="$HOMEDIR/fulcrum.conf"
  if [ "$DRY" = 1 ]; then printf '   + write %s\n' "$fcconf"; else
    printf '%s\n' "datadir = $HOMEDIR/fulcrum" "bitcoind = 127.0.0.1:8332" "rpccookie = $BTCDIR/.cookie" \
      "tcp = 127.0.0.1:50001" "peering = false" "announce = false" "db_mem = 4096" > "$fcconf"
    chown "$U:$U" "$fcconf"
  fi
  run install -m 0755 /dev/stdin "$ROOT/usr/local/bin/hashfun-wait-blocks" << WAIT
#!/usr/bin/env bash
# Returns once Bitcoin has every block: one chainstate (a snapshot's background check is done),
# validated, and not in initial block download.
cli() { $OPT/bin/bitcoin-cli -datadir=$BTCDIR "\$@"; }
until [ "\$(cli getchainstates 2> /dev/null | jq '[.chainstates | length == 1, .chainstates[0].validated] | all')" = true ] &&
  [ "\$(cli getblockchaininfo 2> /dev/null | jq .initialblockdownload)" = false ]; do
  sleep 60
done
WAIT
  unit fulcrum.service "[Unit]
Description=Fulcrum: a Bitcoin index for the hashfun site
After=bitcoind.service
Requires=bitcoind.service

[Service]
User=$U
Group=$U
# It indexes every block, so it starts once Bitcoin has them all: after the snapshot's
# background check of the history before it has finished (a day or two), until then the site
# scans the UTXO set.
ExecStartPre=/usr/local/bin/hashfun-wait-blocks
ExecStart=$FC/Fulcrum $fcconf
Restart=on-failure
RestartSec=30
TimeoutStartSec=infinity
TimeoutStopSec=600
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target"
fi

flags="--btc-rpc http://127.0.0.1:8332 --btc-cookie $BTCDIR/.cookie --listen 127.0.0.1:8080"
[ "$INDEX" = 1 ] && flags="$flags --btc-electrum 127.0.0.1:50001"
[ "$ALLOW_LAUNCH" = 1 ] && flags="$flags --allow-launch"
unit hashfun-web.service "[Unit]
Description=hashfun: every launch's node and the site
After=bitcoind.service
Wants=bitcoind.service

[Service]
User=$U
Group=$U
Environment=HOME=$HOMEDIR
# the launches registered here (also those made from the launch form) come up first; they run in
# this service's group, so a stop shuts them down cleanly too
ExecStartPre=-/usr/bin/env hashfun node up
ExecStart=/usr/bin/env hashfun web $flags
Restart=always
RestartSec=5
TimeoutStopSec=300
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target"

run install -m 0755 /dev/stdin "$ROOT/usr/local/bin/hashfun-status" << 'STATUS'
#!/usr/bin/env bash
cli() { sudo -u hashfun bitcoin-cli -datadir=/var/lib/hashfun/bitcoin "$@"; }
echo "== Bitcoin"
cli getblockchaininfo 2> /dev/null | jq -c '{blocks, headers, progress: .verificationprogress, ibd: .initialblockdownload, pruned}' || echo "not answering yet"
cli getchainstates 2> /dev/null | jq -c '[.chainstates[] | {blocks, snapshot: (.snapshot_blockhash // null), validated}]' || true
systemctl --no-pager --lines=3 status hashfun-snapshot 2> /dev/null | sed -n '1,3p;/Main PID/d' || true
echo "== launches"
sudo -u hashfun -H hashfun node ls 2> /dev/null || echo "none"
echo "== site"
systemctl is-active hashfun-web caddy
curl -fsS -o /dev/null -w 'http %{http_code} from 127.0.0.1:8080\n' http://127.0.0.1:8080/ || true
STATUS

# ---- 6. HTTPS and the firewall ----------------------------------------------------------------
say "6/7 HTTPS (Caddy) and the firewall"
if [ -n "$DOMAIN" ]; then
  site="$DOMAIN"
  [ -n "$EMAIL" ] && site="{
	email $EMAIL
}

$DOMAIN"
else
  site=":80"
fi
caddy="$site {
	encode gzip
	reverse_proxy 127.0.0.1:8080
}"
if [ "$DRY" = 1 ]; then
  printf '   + write %s\n' "$ETC/caddy/Caddyfile"
else
  mkdir -p "$ETC/caddy"
  printf '%s\n' "$caddy" > "$ETC/caddy/Caddyfile"
fi
run ufw allow OpenSSH
run ufw allow 80/tcp
run ufw allow 443/tcp
run ufw allow 8333/tcp
# launch nodes: P2P ports are derived into 20002..31998 (hashfun/descriptor.py)
run ufw allow 20000:32767/tcp
run ufw --force enable

# ---- 7. start ------------------------------------------------------------------------------------
say "7/7 starting"
run systemctl daemon-reload
run systemctl enable --now bitcoind
[ "$SNAPSHOT" = 1 ] && run systemctl enable --now --no-block hashfun-snapshot
[ "$INDEX" = 1 ] && run systemctl enable --now --no-block fulcrum
run systemctl enable --now hashfun-web
run systemctl reload-or-restart caddy

url="http://<this server's IP>/"
[ -n "$DOMAIN" ] && url="https://$DOMAIN/"
sync="Bitcoin is syncing from scratch (1 to 2 days)."
[ "$SNAPSHOT" = 1 ] && sync="Bitcoin is syncing from the $SNAP_HEIGHT snapshot: usable in about 1 to 3 hours."
printf '\ndone.\n  site:    %s\n  status:  hashfun-status\n  logs:    journalctl -u hashfun-web -f; journalctl -u hashfun-snapshot -f\n\n%s\n%s\n' \
  "$url" "$sync" "Until then the site runs and launches wait: a launch is served once its Bitcoin anchor is on this node's chain."
