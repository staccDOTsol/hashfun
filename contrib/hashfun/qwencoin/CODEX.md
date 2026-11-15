# hashfun into Qwencoin: the brief for the agent on the owner's machine

## What this is

hashfun is a launchpad where every coin is its own Bitcoin-derived chain, mined along two curves, one paid in BTC and one in qwen.
This folder holds a patch series for the Qwencoin project (https://github.com/staccDOTsol/qwencoin) that makes every Qwencoin node follow the hashfun site, mine its coins' QWEN curve within the node's spending limits and give its model five functions for it, and makes the public node serve the site at https://aichat.fyi/fun.
You apply it to a git copy of the project, push it to GitHub, publish the project to Hugging Face the way the owner does, and check that the public node and the owner's own nodes took it.

## What is where on this machine

The owner works on Windows with WSL2. Run everything below inside WSL (bash).

- The Windows kit folder: the folder that holds `go.cmd`, `README.txt`, `kit/` (the project's code and `kit/go.sh`), `logs/`,
  and the files `SEEDS`, `WEB` and maybe `HF_TOKEN_FILE`. Find it with
  `find /mnt/c/Users -maxdepth 5 -name go.cmd -path '*qwencoin*' 2>/dev/null`. Below it is called `$KIT_DIR`
  (`KIT_DIR="$(dirname "$(find /mnt/c/Users -maxdepth 5 -name go.cmd -path '*qwencoin*' 2>/dev/null | head -1)")"`).
- The running nodes: `~/qwencoin` in WSL (`$DEST` below; `QWENCOIN_HOME` if the owner set it). `kit/go.sh` copies the kit's
  files into it and runs `tools/pipeline.sh` there. Its settings are in `~/qwencoin/local.env`. The chain and the wallets
  are in `~/qwencoin/run`.
- How code reaches the kit: `bash kit/go.sh update` takes the project's code from the main branch of
  https://github.com/staccDOTsol/qwencoin (the file `kit/GITHUB` names the repository). `go.cmd follow`, if it is running in a
  window, does the same by itself within two minutes of every new commit on main, then publishes and restarts what changed.
- The secrets. Never open, print, copy or move any of them; the project's scripts read them where they are:
  - the Hugging Face token: `$HF_TOKEN`, `~/.hugginface.key`, `~/.huggingface.key`, the same names in the Windows home,
    next to `go.cmd`, the Hugging Face CLI's token file, or the path written in `HF_TOKEN_FILE` (tools/publish.py);
  - the RunPod key: `runpod_key.txt` in Documents, the home folder or next to `go.cmd` (tools/runpod.py);
  - the Cloudflare tunnel: `cloudflare_tunnel.txt` in the same places (its token goes to the pod only when a pod is rented).
- The public node: one RunPod pod running `tools/seed.sh`, serving https://aichat.fyi/ through the Cloudflare tunnel. Every
  ten minutes it downloads `tools/ graph/ rails/ hashformer/ tests/` from https://huggingface.co/staccs/qwencoin and, when the
  code changed, restarts its ord, miner and pages from it (its node keeps running). At that restart the node also reads the
  files `HASHFUN`, `HASHFUNPKG` and `FUNBTC` from the same repository.

This series does NOT need a new pod: `tools/runpod.py` and its `VERSION` (5) are unchanged, and the pod picks the change up
within its ten-minute follow. Do not run `seed down` or rent a pod.

## The steps

1. **The hashfun release must exist first.** The nodes run the hashfun release named in `HASHFUNPKG` (default `v0.2.0`,
   rule set 3). Check:

       curl -sSL -o /dev/null -w '%{http_code}\n' -r 0-0 https://github.com/staccDOTsol/hashfun/releases/download/v0.2.0/hashfun-0.2.0.tgz
       curl -fsSL https://github.com/staccDOTsol/hashfun/releases/download/v0.2.0/SHA256SUMS | grep hashfun-0.2.0.tgz

   Expected: `206` (or `200`), and one line `<64 hex digits>  hashfun-0.2.0.tgz`. Anything else (404): stop here and report
   "the hashfun release v0.2.0 is not published yet". Do not publish it yourself and do not pin an older version.

2. **This folder and a git copy of the project.**

       git clone https://github.com/staccDOTsol/hashfun ~/hashfun-src ||
         { git -C ~/hashfun-src fetch origin && git -C ~/hashfun-src checkout -q --detach origin/hashfun; }
       ls ~/hashfun-src/contrib/hashfun/qwencoin/apply.sh
       git clone https://github.com/staccDOTsol/qwencoin ~/qwencoin-src || git -C ~/qwencoin-src pull --ff-only
       git -C ~/qwencoin-src switch main && git -C ~/qwencoin-src pull --ff-only
       gh auth status

   `~/qwencoin` (the running nodes) is NOT a git copy: never apply anything there. If the owner already has a git copy of
   the project with push rights (`git -C DIR remote -v` shows staccDOTsol/qwencoin), use that instead of `~/qwencoin-src`.
   `gh auth status` must say it is logged in to github.com with push rights to staccDOTsol/qwencoin; if not, stop and report.

3. **Try it, then apply it.**

       bash ~/hashfun-src/contrib/hashfun/qwencoin/apply.sh ~/qwencoin-src --check-only
       bash ~/hashfun-src/contrib/hashfun/qwencoin/apply.sh ~/qwencoin-src

   Expected from the second, at the end:

       == HASHFUNPKG: staccDOTsol/hashfun v0.2.0 <64 hex digits>
       == HASHFUN: https://aichat.fyi/fun
       == FUNBTC: electrums://electrum1.bluewallet.io:443,fortress.qtornado.com:443
       == committed on hashfun: <sha> hashfun: the site the nodes follow, ...
          ok    every Python file of tools/ rails/ graph/ tests/ hashformer/ compiles
          ok    every shell script of tools/ and win/go.sh parses
          ok    tools/fun.py status: ...
          ok    tools/results.py assembles RESULTS.md
          ok    tests/check_fun.py all: OK (20s)
       == done: branch hashfun at <sha>, 7 commits over main. Next: CODEX.md step 4

   Running it again prints `already done` for each part. If it stops with "the series does not apply to main; conflicting:
   FILE", main has moved since the series was made (BASE): report the file and stop; do not resolve it by hand. If a check
   says FAIL, report its lines and stop.

4. **The spending limit on the owner's nodes, before they get the code.** The publisher's nodes may run with no limit
   (`MIND_LIMIT=inf`). hashfun moves qwen only within `FUN_LIMIT` (else `MIND_LIMIT`). Give it one coin unless the owner
   already set one:

       grep -q '^FUN_LIMIT=' ~/qwencoin/local.env 2>/dev/null || echo 'FUN_LIMIT=100000000' >> ~/qwencoin/local.env
       grep '^FUN_LIMIT=' ~/qwencoin/local.env

   Never raise a limit that is there.

5. **Push it to GitHub main.** Only a fast-forward:

       git -C ~/qwencoin-src push origin hashfun:main

   Expected: `<old>..<new>  hashfun -> main`. A rejection (main moved): `git -C ~/qwencoin-src fetch origin`, delete the
   branch (`git -C ~/qwencoin-src switch main && git -C ~/qwencoin-src reset --hard origin/main && git -C ~/qwencoin-src branch -D hashfun`),
   go back to step 3. Never force-push.

6. **Into the kit, the nodes, and Hugging Face.** The kit's `go.sh` that is there now is the one before this series: its
   `update` takes the code but not the three one-line files (the new `go.sh` does, from the next update on). So the code
   comes by `update`, and the three files are copied into the kit by hand this once. First see whether `go.cmd follow`
   is running:

       pgrep -af 'go.sh follow' || echo 'follow is not running'

   - If it is running, it takes the code by itself within two minutes. Wait until the kit has it (up to ten minutes):

         until [ -f "$KIT_DIR/kit/tools/fun.py" ]; do sleep 20; done; echo 'the kit has the code'

   - If it is not running:

         cd "$KIT_DIR" && bash kit/go.sh update

     It prints `kit updated (N files of code)` and then the refresh of the nodes, ending `(exit 0)`.

   Then, in both cases:

       cp ~/qwencoin-src/HASHFUN ~/qwencoin-src/HASHFUNPKG ~/qwencoin-src/FUNBTC "$KIT_DIR/kit/"
       cd "$KIT_DIR" && bash kit/go.sh refresh
       cd "$KIT_DIR" && bash kit/go.sh cards

   `refresh` copies the kit into `~/qwencoin` and starts the miners, agents, ord servers, models and the new `fun` helper
   again from it (the nodes keep running), ending `(exit 0)`. `cards` prints
   `publish: the project -> https://huggingface.co/staccs/qwencoin` and then
   `publish: https://huggingface.co/staccs/qwencoin has the code, the card and the public nodes as they are now`.
   (If follow published before the files were copied, `cards` now publishes them; that is expected.)

   Then confirm the three files are in the kit, in the nodes' folder and on Hugging Face:

       cat "$KIT_DIR/kit/HASHFUN" "$KIT_DIR/kit/HASHFUNPKG" "$KIT_DIR/kit/FUNBTC"
       cat ~/qwencoin/HASHFUN ~/qwencoin/HASHFUNPKG ~/qwencoin/FUNBTC
       for f in HASHFUN HASHFUNPKG FUNBTC; do curl -fsSL "https://huggingface.co/staccs/qwencoin/resolve/main/$f"; done
       curl -fsSL https://huggingface.co/staccs/qwencoin/resolve/main/tools/fun.py | head -1

   Each must print the same three lines; the last must print the first line of tools/fun.py
   (`"""hashfun on a qwencoin node: ...`). `publish: no Hugging Face token found` means the token is not where the
   scripts look: report it; do not look for it yourself.

7. **The public node took it (within its ten minutes, give it fifteen).**

       cd "$KIT_DIR" && bash kit/go.sh seed status
       cd "$KIT_DIR" && bash kit/go.sh seed logs | grep -E '^seed:|fun:' | tail -20

   Expected in the logs: `seed: the project's code has changed: ord, the miner and the pages start again from it (the node keeps running)`,
   then `seed: UP again, from the project's code as it is now`, and lines starting `fun:` such as
   `fun: hashfun v0.2.0 for node 1; the site https://aichat.fyi/fun; this node is the site`. Then from outside:

       curl -s -o /dev/null -w '%{http_code}\n' https://aichat.fyi/fun/
       curl -fsS https://aichat.fyi/fun/ | grep -o '<title>[^<]*</title>'
       curl -fsS https://aichat.fyi/fun/api/board | head -c 300; echo
       curl -fsS https://aichat.fyi/ | grep -o 'fun: the coins these nodes mine' | head -1
       curl -fsS https://aichat.fyi/graph/agents.txt | head -3
       curl -fsS https://aichat.fyi/graph/status.json | head -c 200; echo

   Expected: `200`; `<title>hashfun: Memes quoted in BTC. Mined, not minted.</title>`; a JSON list (empty `[]` is
   fine: no coin launched yet); the header link text; the graph's agents.txt (it says the pages are read-only) and its
   status with a height. If `/fun/` is 404 or 502 after fifteen minutes, collect `seed logs` (the whole `fun:` part) and
   report; do not replace the pod. The explorer and the graph must still answer whatever happens to /fun: if they do
   not, undo (below) at once.

8. **The owner's own nodes.** The `refresh` of step 6 restarted their helpers from the new code, the helper `fun` with them.

       cd "$KIT_DIR" && bash kit/go.sh status 2>&1 | grep -A6 'hashfun:'
       tail -20 ~/qwencoin/run/fun.log

   Expected: `  hashfun: the site https://aichat.fyi/fun; 0 qwen moved into the fun wallet in all (limit 1), ... in it now`,
   then one line per coin the node follows (none while the site has no coin), and in fun.log
   `fun: the site https://aichat.fyi/fun; limit 100,000,000 sats; 0.1 of one core`. The first time, the node fetches the
   hashfun package into `~/qwencoin/fun/v0.2.0/` and checks its sha256 against `HASHFUNPKG`.

## What you must not do

- Print, read, copy, move or send any token or key (Hugging Face, RunPod, Cloudflare, GitHub), or put one in a command line,
  a file, a commit or a report.
- Touch wallets or stakes: no `wallet_send`, `ord wallet send`, `graph_bond`, `graph_vouch`, `graph_leave`, no
  `qwencoin-cli` wallet commands, no `tools/fun.py` mine, send or launch by hand. The nodes and their models spend only
  within the limits the project already has (`MIND_LIMIT`, `MIND_STEP`, `FUN_LIMIT`); never raise one.
- Rent, replace or terminate the pod (`seed`, `seed down`): this series does not need it (VERSION is unchanged). If a step
  here seems to need it, stop and report why.
- Force-push, rewrite main's history, or apply anything in `~/qwencoin` or the kit by hand.
- Run the full pipeline (`go.cmd` with no argument, `publish`, `recheck`): only `update`, `cards`, `status`, `seed status`
  and `seed logs` are part of this.

## When something fails, and how to undo

- Step 1: no release, stop and report. Step 3: conflict or a failed check, stop and report (nothing has left the machine).
- Step 5 rejected: see step 5. Step 6 or 7 failing, or the explorer and the graph not answering: undo.
- Undo (everything goes back to what it was; the chain and the wallets are not touched):

      git -C ~/qwencoin-src switch main && git -C ~/qwencoin-src pull --ff-only
      git -C ~/qwencoin-src revert --no-edit OLD_MAIN..HEAD      # OLD_MAIN: the main before step 5 (BASE, or what step 5 printed)
      git -C ~/qwencoin-src push origin main
      rm -f "$KIT_DIR/kit/HASHFUN" "$KIT_DIR/kit/HASHFUNPKG" "$KIT_DIR/kit/FUNBTC" ~/qwencoin/HASHFUN ~/qwencoin/HASHFUNPKG ~/qwencoin/FUNBTC
      cd "$KIT_DIR" && bash kit/go.sh update && bash kit/go.sh cards

  `cards` removes the three files from Hugging Face when they are gone here (`no hashfun site at the moment`), and the pod
  goes back to the old code at its next ten-minute look. The launches' nodes this machine started stop with
  `python3 ~/qwencoin/tools/fun.py down` only if tools/fun.py is still there; their data stays in `~/qwencoin/run/fun`.
  A quick stop without undoing anything on the owner's nodes: `echo FUN=0 >> ~/qwencoin/local.env`, then
  `cd "$KIT_DIR" && bash kit/go.sh refresh`.

## What to report at the end

1. The hashfun release: version and the sha256 line of its SHA256SUMS (step 1).
2. apply.sh: the main it started from (`git -C ~/qwencoin-src rev-parse main` before step 5), the branch's commits
   (`git -C ~/qwencoin-src log --oneline main..hashfun`), its whole output of the real run, each check's line.
3. The push: the line `<old>..<new>  hashfun -> main`.
4. Publishing: which way (follow or by hand), the two `publish:` lines, and the four `curl` results of step 6.
5. The pod: the `seed:` and `fun:` lines of step 7 with their times, and every URL of step 7 with its HTTP code and the
   first line it returned.
6. The owner's nodes: the `hashfun:` lines of `status` and the last lines of `run/fun.log`.
7. Anything that failed, with the exact command and output, and whether you undid it.
