# hashfun: status, 2026-11-11 (third drop)

34 commits on `namecoin-core@70c6b36` (branch `auxpow`: Bitcoin Core 32.99 + AuxPoW). The node now ships as a binary per platform and the CLI picks its own. Everything in "What passes" ran on Linux x86_64 against **the binary that ships for it** (static, built by `contrib/hashfun/dist/build.sh`, version `v32.99.0-a547b629c95f`: commit 33 of the series; the 34th adds only this file), with stock Bitcoin Core v32.1 as the Bitcoin side.

New since the second drop:

- **A node binary per platform, picked by the CLI.** `npm i -g hashfun`, then `hashfun node up X` runs the `hashfund` for the machine it is on: Linux or macOS, Intel/AMD or ARM. No `HASHFUND=` to set (it stays as an override). `hashfun doctor` shows which one it took and proves it by running it.
- **GitHub Actions builds, tests, packs and releases all four** (`.github/workflows/hashfun.yml`). It has not run yet: it needs a repository. One command below.
- **Swaps tested on the shipped timelocks** (4 h and 8 h 10 min), by moving the clock: the happy path, both sides vanishing, a late taker, a late lock, a dishonest taker, a dishonest maker.
- **`hashfun book`**: the peer-to-peer engine without a browser tab. Offers stay live on a server; swaps finish or refund after a restart.
- **Bids are backed.** The board lists a bid only once it has seen confirmed sats behind it, and no offer can promise the same coins twice.
- **UniSat checked against the extension's own source**, and a guard for what that turned up: Fractal looks like Bitcoin to a page.

## What passes

One command runs all of it and writes one log per suite: `bash contrib/hashfun/ci/test.sh`.

| Suite | Result | What it is |
|---|---|---|
| `unit` | 64 tests | the Python model: vectors, curve, LWMA, descriptor, HTLC, AuxPoW, wallet vault, pool, proxy, electrum, swaps on the simulator, launch metadata, the board's server side; new: which binary the CLI picks on which machine, from a copy laid out like the npm package |
| `diff` | 12 suites | the node's own consensus sources against the Python model, value by value. Now compiled by the compiler that builds the shipped binary (clang 22 with libc++ on musl), not only GCC |
| `web_js` | 13 tests | the browser's code against the Python, byte for byte; the committed bundles are the build of the sources; lint (now also for one name hiding another: see bug 1) |
| `doctor` | pass | `hashfun doctor`: the binary boots a throwaway launch, mines on its curve, and every mint equals the CLI's own copy of the rules |
| `e2e` | 58/58, 29 s | single-node consensus, merged mining against stock bitcoind, swaps, sats leg |
| `fleet` | 41/41, 4.5 min | 4 nodes, 2 competing pools, 2 Bitcoin wallets, production-mode launches, real time |
| `book` | 28/28, 69 s | **new**: peer-to-peer swaps on the shipped defaults with the clock moved by the test, and the headless bot end to end |
| `web` | **45/45, 9 min** | the real site in real Chromium browsers against real nodes: two mined chains, pools, settlers, the house maker, the peer-to-peer book, and now a wallet that is on the wrong chain |
| `smoke` | pass | `hashfun launch / node / mine / web` end to end through the CLI |

Logs are in `logs/`, screenshots of the running site in `screenshots/`.

## Platforms

| Target | How it is built | What has run |
|---|---|---|
| `linux-x64` | zig's clang, fully static (musl): one file, any distribution | everything above |
| `linux-arm64` | the same, cross-compiled from x86_64 | on a real ARM machine (the Linux VM of an Apple silicon Mac): installed from the tarball, picked by the CLI by itself, `hashfun doctor` passed. Not the full regression there: CI runs that |
| `darwin-arm64`, `darwin-x64` | Apple's clang on a Mac (GitHub's macOS runners), macOS 14 or newer | **nothing yet**: no Mac here. The workflow builds them and runs the whole regression on them |

**The binaries agree with each other.** `hashfun doctor --mine` on one machine writes a short chain (up the curve, through graduation, into the tail) with what its node concluded; `hashfun doctor --replay` on another requires the same conclusions. Run here: the ARM binary accepted the x86_64 binary's chain, and both the shipped x86_64 binary and a GCC/glibc build of the same source accepted the ARM binary's: same tip, same UTXO set, same curve state, same sats owed for every block. Three builds from three toolchains, two processors. CI repeats that across all four platforms on every run.

The tarball in this drop (`hashfun-0.1.0.tgz`) carries the two Linux binaries. It installs on a Mac, and `hashfun doctor` there says there is no node binary for it yet. Three ways to get one, fastest first:

1. **GitHub Actions** (builds and tests all four, about an hour, nothing to install):
   ```
   PUSH=<you>/hashfun VISIBILITY=public bash make_repo.sh    # or leave VISIBILITY out for a private repository
   gh run watch -R <you>/hashfun
   gh run download -R <you>/hashfun -n npm-package             # hashfun-0.1.0.tgz with all four binaries
   ```
   A public repository runs free. A private one bills macOS minutes at about ten times Linux minutes: the first run costs a large part of a free plan's month.
2. **On the Mac**, with the Xcode command line tools 26.3 or newer (this Bitcoin Core needs that clang): `bash build_and_test.sh`. It checks the tools first and says what is missing.
3. Tell me the repository name once it exists and I push, watch the runs and fix what the macOS runners turn up.

Publishing: `gh secret set NPM_TOKEN -R <you>/hashfun < ~/.npmnpm123`, then `git tag v0.1.0 && git push origin v0.1.0`. The release job publishes only when that secret exists, and only the tarball the install job tested on all four platforms. I have not opened that file.

## Swaps at the settings that ship

`book_regtest` runs the browser's engine, byte for byte, under node with several traders on one clock, against a real launch chain and a real bitcoind, on the site's defaults (4 h maker lock, 6 confirmations on a coin, 1 on Bitcoin). The test moves the clock of both chains and of every engine.

| | What it proves |
|---|---|
| S1 | the happy path: taker's lock refundable 8 h 10 min from the take, maker's 4 h 10 min; the maker does not lock on an unconfirmed payment; the taker does not claim at 5 confirmations and does at 6; the maker claims with the revealed secret |
| S2 | the maker vanishes after the taker locked: at 8 h Bitcoin itself refuses the refund; past 8 h 10 min the taker's engine takes its sats back by itself. Only fees are gone |
| S3 | the taker vanishes after the maker locked: the maker's coins come back past 4 h 10 min, the taker's sats past 8 h 10 min |
| S4 | the taker shows up 8 minutes before the maker's refund opens: it does not reveal the secret; both locks go home |
| S5 | the taker's lock confirms so late that under half the maker's lock would remain: the maker locks nothing |
| S6 | a bid in sats: listed only after the board has seen the sats; the maker waits for 6 confirmations on the coins |
| S7 | a dishonest taker (shorter timelock, short payment, payment to another script): the maker locks for none of them, and does for the honest version of the same take |
| S8 | a dishonest maker (a lock that refunds early, a short lock): the taker claims neither and takes its own sats back |
| H1 | the headless bot, real clock: encrypted key file, an offer posted from the command line, `hashfun book take` against a running `hashfun book run`, an offer posted while the bot runs, a second engine on the same key refused |

What this does not cover: real hours passing (the clock is moved), and Bitcoin's own ten-minute blocks.

## hashfun book

```
hashfun book key                      # a key in ~/.hashfun/book, encrypted; prints where to send coins and sats
hashfun book post --give CAT --get btc --give-amount 1000 --get-amount 50000
hashfun book run                      # keeps offers live; locks, claims, refunds; resumes after a restart
hashfun book take ID                  # take someone's offer from the key
```

It is the page's engine (`book.js`, the same file) with a key file for the wallet and a JSON file for the browser's storage. It talks to a site over HTTP as the page does, so it needs no node. Everything the key holds is in play: fund it with what is meant to be traded.

## UniSat, from its source

Read: `unisat-wallet/wallet` as published. Not run: the extension itself.

- The four calls the page used exist with the shapes the page assumes; `sendBitcoin` returns the transaction id; the default `signMessage` is deterministic, so the page key derived from it is the same every time.
- **UniSat also runs Fractal, whose addresses are Bitcoin's.** A page that only looks at the address cannot tell. A payment from there would have funded a swap contract on a chain this site does not watch. The page now reads the wallet's chain at connect and before every payment, asks it to switch, and refuses if it does not; it also checks that the account is still the one that signed in. `web_regtest` U1 runs a wallet that starts on Fractal.

## The consensus review: read this before a launch with strangers on it

An independent adversarial read of everything under `src/` that this fork changes (a fresh reviewer with no part in writing it; static reading, nothing run on a node). It found the curve, the difficulty rule, the AuxPoW gate, the launch file's bytes and the determinism of the validity code across compilers sound, and it found **real holes in the sats leg**: the part that makes a curve block owe Bitcoin and draws who is paid. I checked the three critical ones against the code myself: they are real. **None is fixed in this drop.** Normal use does not trigger them (one, M2, needs a hand-made launch file); each needs someone trying. The build, the binaries, CI and a test among friends are unaffected; a launch that strangers can mine or hold is not safe until they are closed.

| | The hole | What it gives an attacker |
|---|---|---|
| C1 | a payment proof is judged against the UTXO set when its block arrives, and without it when a node rebuilds its state at start | a proof that pays the wrong holder is ignored by running nodes and accepted by restarted ones: when that coinbase is spent, the chain splits |
| C2 | one Bitcoin output can be bound to several blocks (several tag lists in one transaction) | one payment settles any number of blocks: the creator, the dev and repeat holders are paid once for many |
| C3 | the holder draw is over every output ever created, not over coins held now | coins sent to oneself many times win the draw, so a miner pays himself; ordinary turnover drifts the holders' 80% to the creator |
| H1 | a coinbase earns holder yield before its own sats are paid | hash that never settles still collects Bitcoin from miners who do |
| H2 | no bound on proof and header work per block | blocks that take seconds to minutes to validate |
| H3 | the sats-leg state lives in memory, forever, and is rebuilt from genesis at start | memory grows without bound; faster under output spam |
| H4 | a reorg can leave a spend of a no-longer-settled coinbase in the mempool | every miner's block template fails until that transaction expires |
| M1 | the draw seed of a merge-mined block is not the hash that carried the work | the last six curve draws can be ground for free |
| M2 | the Bitcoin anchor in a launch file is not checked (`launch new --btc-rpc` and the launch form build it correctly; `--btc-anchor HEIGHT:HEADER` by hand without the period start does not) | such a launch stops settling at the first Bitcoin retarget, for good |
| M3 | Python and the node read a few malformed launch files differently (omitted keys, duplicate keys, values past 2^31) | one hand-written file, two meanings |
| M4 | a yield redirect covers every output of a transaction, including outputs paid to other people | the sender keeps the yield of coins he pays out |

C1, C3 and H1 are one change: the sats-leg state tracks spends itself and draws over the coins that are live at the draw; a curve coinbase starts earning when its block settles; the payee is fixed at the draw. That is the "80% to a holder drawn by bag size" that was specified; what was built approximated it. It changes consensus, so every binary is rebuilt after it. The full report with file and line for each finding is `logs/review-consensus.md`. This is the next piece of work.

## Bugs found this round (all fixed)

1. **The "Deposit from UniSat" button did nothing.** The wallet guard above put every payment through one new function, and the swap view had a local variable of the same name. No unit test reaches a button; the browser test did, on its first run after the change. Lint now refuses one name hiding another, and would have caught it.
2. **The headless bot could lose an offer or a swap record** when two commands used one key directory at once (`post` while `run` was up; `take` beside `run`): each rewrote the whole state file from its own memory. Reads now go to the file, writes merge under a lock, and only one engine (`run` or `take`) may drive swaps per directory. H1 checks both.
3. **A stream of bids from fresh keys could have kept the Bitcoin node scanning** and stalled the site's main loop behind it (a scan of the UTXO set takes about a minute on mainnet). The scan has its own thread now and a pause between scans.
4. **The static binary did not link at first, twice over**: SQLite was not built position independent, and CMake put one of zig's cached runtime libraries on the link line. Both are in the build script now, with the reason. The ARM build would also have shipped without hardware SHA-256 (zig reads `-march=` differently from GCC and the probe failed quietly): the compiler wrapper translates it.
5. A bid could be posted and taken by id before the board had ever seen sats behind it; a taker would have locked coins for nothing and waited out the timelock. The board refuses the take now.
6. Portability, found by building the way a Mac does: the CLI and scripts assumed a Python newer than the one macOS ships and GNU-only shell features (`realpath -m`, `nproc`, empty arrays under `set -u` in bash 3.2). The CLI now finds a usable Python or says exactly what to install.
7. `pip install .` shipped `hashfun book` without its engine (a missing package-data line).

## Still true from the earlier drops

**fleet_regtest covers** gating (old tip is not IBD, no peers means no templates unless `-minewithoutpeers`, no mock clock, no pruning); P2P sync; identical tip, UTXO set, Bitcoin relay and every obligation on every node; late joiner from genesis; restart mid-run and restart with no new blocks; an isolated node that followed a forged Bitcoin header branch reorgs back and forgets it; the pool's own node loses a race to a second pool and its settler pays nothing for the orphaned blocks; a graduated launch merge-mined by another launch's pool, AuxPoW blocks over P2P, late joiner on the mixed chain; unsettled coinbase rejected by every mempool and kept out of wallet coin selection; a settled one relays and confirms everywhere; `verifychain`; two pools settle everything they mined with no wasted payment; stall relief against the wall clock.

**web_regtest covers** the board following the chain; connect deriving the page key from one wallet signature; the coin page; the launch form creating a production-mode chain with a picture the launch id commits to; an instant buy and a larger one after a confirmation; the wallet paying a swap contract, not the site; hold to earn and sweep; a sell; the peer-to-peer book in two browsers (coin for sats, coin for coin, a bid in sats, a maker that disappears and the refund that follows); phone layout; no JavaScript errors in any browser.

The only stand-in is the wallet: a mock `window.unisat` backed by a regtest wallet.

## Make the repo, build, test

```
bash make_repo.sh                           # clone namecoin-core at the pinned commit, apply patches/ -> ./hashfun-core
cd hashfun-core
bash contrib/hashfun/dist/build.sh          # the hashfund for this machine -> contrib/hashfun/npm/prebuilt/<target>/
bash contrib/hashfun/ci/test.sh             # the regression (BITCOIND=/path/to/bitcoind for the suites that need one)
python3 -m hashfun.cli doctor
```

`bash build_and_test.sh` does the first three for a machine of your own and checks its tools first.

## First run with real BTC

Keep it small. Everything here is the tested path except the things marked untested.

1. Bitcoin Core, synced (pruned is fine, no transaction index needed), with a wallet holding a little BTC for the miner: `bitcoin-cli createwallet miner`. Each curve block pays at least 10,000 sats or nothing, so 0.002 BTC covers a tiny curve.
2. `hashfun doctor`, then `hashfun web --btc-rpc http://user:pass@127.0.0.1:8332 --allow-launch` and open http://127.0.0.1:8080. Connect UniSat (**untested: the real extension**). Launch form: drop a picture, preset **CPU test**, **0.001 BTC**. The chain starts; the creator scripts are your page key and your UniSat address.
3. Mine it: `hashfun node rpc TICKER createwallet w`, `hashfun node rpc TICKER getnewaddress "" bech32`, then
   `hashfun mine TICKER --payout <that address> --btc-rpc http://user:pass@127.0.0.1:8332 --btc-wallet miner --max-pay-btc 0.0002`.
   The settler pays each drawn payee from `miner` once the block is 12 deep, waits for one Bitcoin confirmation, publishes the proof. `--max-pay-btc` caps any single payment.
4. Trade peer to peer: open the site in a second browser profile with another UniSat account. In one, **Swap**, post an offer; in the other, take it. Keep the maker's tab open until it says done, or make from a server with `hashfun book`. Sats you offer as a maker come from your hashfun key: use **Deposit from UniSat** first and wait for one confirmation; the bid is listed once the site's next scan has seen them (up to a minute or two on mainnet).
5. For instant small buys, run the house maker: restart the site with `--maker maker.json`:
   `{"btc": {"wallet": "miner", "hrp": "bc"}, "defaults": {"hashprice_sats_per_th": <your number>, "spread": 0.03, "btc_confs": 1, "fork_confs": 6, "init_lock_seconds": 43200, "part_lock_seconds": 14400, "lock_margin_seconds": 7200, "instant_max_sats": 20000, "safety": 0.5}}`.
   Its order cap is the cost of renting enough hash to reorg `fork_confs` blocks, which on a CPU-sized chain at a real hash price is about zero (rightly: such a chain is cheap to reorg). For a test on a CPU chain set `"safety": 1e9` and keep orders small.
6. Second machine: `npm i -g hashfun-0.1.0.tgz && hashfun node add ticker.json --peer <first host>:<p2p port> && hashfun node up TICKER`. The picture travels inside `ticker.json`.

What that run exercises for the first time: **real Bitcoin headers through the relay** (the retarget rule is tested against Core-produced headers and the first historical retarget, not against the live chain), **mainnet fees and 10-minute confirmations**, **real hours on the swap timelocks**, and **UniSat itself**. Reading sats at a hashfun key uses `scantxoutset`: about a minute per lookup on mainnet, cached for two minutes.

## Not done

- **The workflow has never run**, and nothing has run on macOS: not the native build, not the binaries, not the suites. Expect the first run to show something on the macOS runners; that is what it is for.
- Bitcoin Core's own unit tests have not been run on this fork (the workflow can: run it by hand with `core_tests` on).
- A macOS binary through zig (the route that needs no Xcode) is wired into the build script and has never been built.
- A maker's browser tab in the background should keep working (worker timer, Web Lock): **not tested with a really hidden tab**. `hashfun book run` is the answer for anything that matters.
- Reading sats on mainnet goes through `scantxoutset` (about a minute, one at a time). Fine for a first run with a few people, not for a public site: that needs an address index.
- One site, one book. Two sites do not share offers.
- A cheap chain is cheap to reorg: 6 confirmations on a CPU-mined coin protect nothing against someone renting a rig. The page shows the confirmation count; it does not price the risk the way the house maker's cap does.
- Lightning exits. All exits are on-chain atomic swaps.
- A hosted fleet (seed nodes, a public site).
- The page key lives in the browser's localStorage, like any web wallet. A compromised page could take it. The page also trusts the site's view of the chains: run your own.
- Windows, other than through WSL.
- No review by anyone outside this project: the one above is another agent, not a second human.
