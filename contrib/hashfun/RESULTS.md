# hashfun: status, 2026-11-11 (fourth drop)

43 commits on `namecoin-core@70c6b36` (branch `auxpow`: Bitcoin Core 32.99 + AuxPoW). This drop is the consensus fix the third drop's review called for, plus one command to ship.

**Consensus changed. Every binary is rebuilt, and nothing made by an earlier drop is read any more**: launch files are version 2 (version 1 is refused with a message saying to create the launch again), and the chain files under `transfer/` from the third drop are obsolete.

Everything in "What passes" ran on Linux x86_64 against **the binary that ships for it** (static, version `v32.99.0-5b613a5105dc`).

## Ship it: one command, on the Mac

```
bash ~/src/hashfun/deploy.sh
```

It runs on your machine with your own logins (`gh`, and the npm token file); nothing in it can be run from my side. It first looks, then prints what it is about to do and asks once. On yes:

1. **Source.** Rebuilds the repository from `patches/` (the first run clones namecoin-core, a few hundred MB) and checks that the result is byte for byte the tree that was tested (`patches/TREE`).
2. **GitHub.** Creates `github.com/<your gh login>/hashfun`, **public**, or reuses it, and pushes branch `hashfun`. Public because GitHub's runners are free there; `VISIBILITY=private bash deploy.sh` keeps it private, where a macOS minute bills as about ten. The commits carry no name or e-mail of yours.
3. **npm token.** Reads it from `~/.npmnpm123` (a bare token or an `.npmrc` line), asks npm whether it is alive, and pipes it into the repository's encrypted `NPM_TOKEN` secret. It is never printed and never on a command line. I have not opened that file. `NPM=0` skips this.
4. **Release.** Tags `v0.1.0`. GitHub Actions then builds the node on four runners (Linux x64 and arm64, macOS on Apple silicon and Intel), runs the whole regression against each binary, packs, installs the package on all four, has every binary replay every other binary's chain, and only then makes the release and publishes `hashfun@0.1.0` to npm. **A published version cannot be taken back.** `TAG=0` builds and tests without releasing.

Then:

```
bash ~/src/hashfun/deploy.sh wait      # blocks until the build ends; writes ci/status.txt and ci/failed.log
npm i -g hashfun && hashfun doctor     # when it is green
```

The workflow has never run and nothing has ever run on macOS, so expect the first run to fail on something there. `deploy.sh wait` (or `status`) leaves the failing jobs' logs in `~/src/hashfun/ci/`, which is the folder I can read: say so and I fix it, send new patches, and the same command replaces the branch and moves the tag (it never moves a tag whose version is already on npm).

What was tested of the script: every path against stand-ins for `gh`, `npm` and `curl` and a local repository (177 checks: first run, rerun, new patches, a version already published, answering no, no terminal, six token file formats, the token appearing nowhere but on the pipes, a missing permission, someone else's push). What was not: the bash that macOS ships (3.2; the script avoids everything newer and was checked for it by reading), and real GitHub.

## The first build on GitHub

Run 43103032119, 2026-11-11, on GitHub's own machines. The first time this node was built or run on a Mac.

| Platform | Build | Regression |
|---|---|---|
| `linux-arm64` (ubuntu-24.04-arm) | ok | **all of it passed**: unit, diff, web_js, doctor, e2e 67/67, yield 46/46, fleet 41/41, book 28/28, web 45/45, smoke |
| `linux-x64` (ubuntu-24.04) | ok | all passed except `smoke`: the node could not listen on its P2P port |
| `darwin-arm64` (macos-15) | ok | all passed except `yield`: the test ran the machine out of ports |
| `darwin-x64` (macos-15-intel) | ok | the same as `darwin-arm64` |

So on macOS, both architectures: the node builds with Apple's clang, and e2e 67/67, fleet 41/41, the swaps 28/28 and the site in real browsers 45/45 pass. `yield` had made 32 (Intel) and 20 (ARM) checks, with no difference between node and model, when it ran out of ports.

Nothing was released: the release waits for all four. Three bugs of ours came out of it, and one of GitHub's. All fixed in this drop:

1. **A new connection for every RPC call.** The Python RPC client opened and closed a TCP connection per call. `yield_regtest` made 48,242 of them in 27 s. A Mac has about 16,000 outgoing ports and keeps each one unusable for half a minute after its connection closes, so calls began to fail with "Can't assign requested address". A pool, a settler or the site did the same to a production machine, only slower. The client now keeps one connection per thread for calls that only read (the same test: 1,274 connections), and still never sends anything that changes state twice.
2. **Default ports inside the range Linux uses for outgoing connections.** A launch's P2P port was derived into 20000..39998. From 32768 up, Linux hands those numbers to outgoing connections, and a port one of them just used cannot be listened on for a minute. With thousands of connections a minute (bug 1) a node start failed now and then: on GitHub's x64 runner, and once here earlier, which I had put down to two suites running at once. Ports are now derived into 20001..31999, and the tools pick every other listening port from under 32768 too.
3. **A node with default settings could not start at all.** The default RPC port was the P2P port plus one, which is where the node itself listens for incoming Tor connections. The CLI always chose its own RPC port, so nothing ran into it until I made the CLI use the launch's own. RPC is now one under P2P, as in Bitcoin (8332, 8333, 8334), and `hashfund -launch=x.json` with nothing else starts.
4. **GitHub accepted the push and the tag and started no build** (Actions enabled, no workflow registered, no run, for an hour) until the workflow was started by hand. `deploy.sh` now checks that a build of the commit exists, starts one if not, and says so plainly if it cannot (`deploy.sh kick` does the same on demand).

The jobs after the builds (`pack`, `install`, `release`) have still never run on GitHub. They were walked through here step by step instead, with the real Linux binaries and stand-ins for the Mac ones, and that found a fifth bug that would have failed `install` on all four platforms: **the installed `hashfun` command ran whatever `hashfun/` folder was in the current directory** (Python looks there first), so inside a source checkout it ran the checkout's code, which has no node binary. The wrapper now runs its own copy wherever it is typed.

## The review's findings: what was done

The third drop ended with an adversarial review of the sats leg that found it could be split and robbed. All critical, high and medium findings are fixed in consensus; each has a test that holds it.

| | The hole | The rule now | Held by |
|---|---|---|---|
| C1 | a proof was judged with the UTXO set live and without it on replay: restarted nodes disagreed with running ones | the sats-leg state is a pure function of the chain's blocks: no UTXO set, no clock. A block that cannot be read during a rebuild is a fatal error, not a guess | `yield` (four restarts, each compared at every height with the node before the stop and with the model), `e2e` 10 |
| C2 | one Bitcoin output settled many blocks through several tag lists | one tag list per Bitcoin transaction: the first `OP_RETURN "HF"` output and no other | `yield` (one output, two lists; the tag in a second list), `e2e` 10 |
| C3 | the holder draw ran over every output ever created; the payer picked among 64 candidates; the creator was the fallback | one point over the coins **live at the draw**. The payee is fixed there. A spent coin is never drawn again, so sending to yourself buys nothing. No candidates (`proof.candidate` must be 0), no fallback: with nobody holding, the holders' share is owed to no one | `yield` (60 self-transfers move the earning value by the fees only; every live coin of the model is unspent on the node and every dead one spent), `e2e` 10 |
| H1 | a coinbase earned before its own sats were paid | a curve coinbase that owes sats is out of the draw until its block settles (or its draw says nothing is due) | `yield` (nothing earns while every coinbase is held; a block never paid never earns) |
| H2 | unbounded work per proof and per relayed header | the Bitcoin header tree answers confirmations and expected difficulty in O(1); a proof costs its own size; nothing scans | by construction; `diff` on the header rules |
| H3 | the state grew in memory forever and was rebuilt from genesis at every start | **in part**: the leg ends `settle_deadline` blocks after the last curve block. Nothing after that can change what a coinbase may do, so nodes stop tracking there and a starting node replays only that far. See "Still open" for the rest | `yield` (the end of the leg: later spends, headers and proofs change nothing; a reorg across the boundary; a restart after it) |
| H4 | a reorg could leave a spend of a no-longer-settled coinbase in the mempool and break every block template | such spends are evicted on the reorg, and the mempool refuses them while the state is unknown | `e2e` 10 (eviction, then `getblocktemplate`) |
| M1 | a merge-mined block's draw seed could be ground for free | the seed is the hash that carried the work: the parent chain's block hash | `yield`, `e2e` 7 |
| M2 | nobody checked a launch file's Bitcoin anchor | both parsers refuse what can be refuted without a chain (hash against bits, bits against Bitcoin's minimum, the period start); a Bitcoin node is asked the rest before mining (`hashfun mine`), on `node add --btc-rpc`, by the site before it serves a launch, and by `launch info --btc-rpc` | `unit` (12 new tests around the three callers), `diff` |
| M3 | the node and the Python tools read some launch files differently; no model of the sats-leg state existed | both refuse what JSON readers disagree about (bytes that are not strict UTF-8, duplicate keys, 40+ character numbers, deep nesting, NaN), omitted keys get the same defaults, two fields are bounded below 2^31. `hashfun/yieldstate.py` is the state machine written again from the rules | `diff` (both parsers on random, mutated and byte-damaged files), `yield` |
| M4 | a yield redirect covered other people's outputs | a redirect counts only in a coinbase, for its output 0, and only to a script that itself earns | `yield`, `e2e` 10 |
| L1, L2, L5 | unrelayable payout scripts; fail-open on a read error; `ftl` not tied to spacing | `creator_btc_script` and redirect targets must be P2PKH, P2SH or a witness program; fatal error; `ftl` at least 10 s and under `6T` outside test launches | `diff`, `unit` |
| L4 | two launches could contain the same transaction | **new consensus rule: every coinbase names its launch** (height, then 16 bytes of the launch id, `bad-cb-launch-id`). Worse than the review rated it, by the code: the node's own miner and `createauxblock` (the merge-mining path) put only the height in the scriptSig, so two launches with the same preset, creator and payout script had byte-identical coinbases at equal heights whenever both blocks were empty, and a spend of one was valid on the other for anyone to replay | `e2e` 3 (five checks), `unit` (the simulator), `doctor` (every mined block) |

The numbers behind "held by": `yield_regtest` drives a real node and a regtest bitcoind through 274 blocks and compares `getmintobligation` at every height, the earning value and the Bitcoin relay with the model after every block, restart and reorg: about 36,000 obligation comparisons, zero differences. The model is a second implementation, written from the rule text with its own structure (plain lists, one code path: replay). It is not an independent party: the same AI wrote both, so a misreading of the intended rule would be in both. What it rules out is the node disagreeing with the rules as written, and with itself across restarts and reorgs.

## Still open

- **Memory under spam (the rest of H3).** While a curve is open the node keeps every earning coin in RAM (about 190 bytes per live coin; a spent coin keeps its slot until the leg ends). Honest use is small (10,000 transactions: a few MB). An attacker who fills blocks with dust outputs grows it by gigabytes per hour, and a launch that never graduates never closes. The block weight limit is still Bitcoin's 4M regardless of spacing, which is the same lever for disk. The fixes (compacting dead coins, a weight limit scaled to the spacing, a floor on what earns) are designed and not built; the weight limit is consensus and would come as a descriptor version 3.
- **The pool under full blocks.** The pool carries Bitcoin headers and payment proofs in its coinbase; the node reserves 8,000 weight units for a coinbase. When the mempool fills a block and the coinbase carries more than about three proofs, the pool's block is overweight and refused. Not reachable in a quiet first run; start the node with `-blockreservedweight=100000` on a busy launch. To fix in the pool (fit what it carries to the room in the template).
- **L3.** `btc_confs` defaults to 1: a forged Bitcoin block (cost: one block reward) settles what its miner owes. Raise it in the launch file for a launch whose miners owe more than that. Merkle depth is not pinned (the 2^70 inner-node forgery).
- **M1, what remains.** One block seeds each draw, so a miner can still re-roll by withholding a block it found. Inherent to a single-block seed.
- **L4, what remains.** `genesis_nonce` is outside the launch id: two valid nonces are two chains with one id. A confusion, not a theft.
- **L6.** No minimum chain work in the first blocks of a launch; LWMA costs two 256-bit divisions per window block per header; the parser accepts a `settle_deadline` of 110 blocks from a hand-written file (`launch new` and the form set a day).
- **Not run:** the `pack`, `install` and `release` jobs on GitHub (walked through locally instead); Bitcoin Core's own unit tests on this fork; a full green run. The next `deploy.sh` is that run.

## What passes

One command runs all of it and writes one log per suite: `bash contrib/hashfun/ci/test.sh`.

| Suite | Result | What it is |
|---|---|---|
| `unit` | 121 tests | the Python model: vectors, curve, LWMA, descriptor, HTLC, AuxPoW, wallet, pool, proxy, electrum, swaps on the simulator, the board; new: the sats-leg state machine as a model, the anchor checks, the stricter parser |
| `diff` | 17 tests | the node's own consensus sources against the Python model, value by value, compiled by the compiler that builds the shipped binary; new: both launch file parsers on damaged files, the changed sats-leg functions |
| `web_js` | 13 tests | the browser's code against the Python, byte for byte; the committed bundles are the build of the sources; lint |
| `doctor` | pass | the binary boots a throwaway launch, mines on its curve, every mint equals the CLI's own copy of the rules; new: every coinbase names the launch |
| `e2e` | 67/67, 59 s | single-node consensus, merged mining against stock bitcoind, swaps, the sats leg under the new rules, the coinbase rule |
| `yield` | 46/46, 56 s | **new**: the sats leg, a real node against the model, at every height after every block, restart and reorg |
| `fleet` | 41/41, 4.6 min | 4 nodes, 2 competing pools, 2 Bitcoin wallets, production-mode launches, real time |
| `book` | 28/28, 78 s | peer-to-peer swaps on the shipped 4 h and 8 h timelocks with the clock moved by the test, and the headless bot |
| `web` | 45/45, 8 min | the real site in real Chromium browsers against real nodes |
| `smoke` | pass | `hashfun launch / node / mine / web` end to end through the CLI |

Logs are in `logs/`.

## Platforms

| Target | Binary | What has run |
|---|---|---|
| `linux-x64` | static (musl), zig's clang: 15,700,048 bytes, sha256 `26e0ebfae70516aae5c7e7e6b868b22893f9475a4836da1f1cabad981155f68d` | everything above |
| `linux-arm64` | the same, cross-compiled: 14,227,080 bytes, sha256 `3ecc34e028ddfa2102e9cf7463baf8384909af2afb21881a73f5a00d352bee17` | on a real ARM machine (the Linux VM of this Mac): unpacked from the tarball, picked by the CLI by itself, `hashfun doctor` passed, it replayed the x86_64 binary's chain and mined its own. Not the full regression there: CI runs that |
| `darwin-arm64`, `darwin-x64` | built by GitHub's macOS runners (Apple's clang) | built and tested once on GitHub: everything passed except `yield`, for the reason above; see "The first build on GitHub" |

**The binaries agree with each other**, again, on the new rules: the ARM binary accepted the x86_64 binary's 120-block chain (up the curve, through graduation, into the tail), and both the shipped x86_64 binary and a GCC/glibc build of the same source accepted the ARM binary's: same tip, same UTXO set, same curve state, same sats owed for every block. The chains are in `transfer/` (`chain-linux-x64.json`, `chain-linux-arm64.json`); `hashfun doctor --replay FILE` checks any other machine against them.

The tarball in this drop (`hashfun-0.1.0.tgz`) carries the two Linux binaries. The macOS ones come out of the deploy command.

## First run with real BTC

Same path as the third drop, on the new binaries. What differs:

- Create the launch again: version 1 launch files are refused.
- `hashfun mine` asks your Bitcoin node whether the launch's anchor is true before it serves work, and exits with the reason if not. The launch form and `launch new --btc-rpc` build a true one.
- Joining someone else's launch: `hashfun node add ticker.json --btc-rpc http://user:pass@127.0.0.1:8332 --peer host:port`.
- The first blocks of a launch: holder draws with nobody holding yet are owed to no one, so the first coinbases unlock without a payment. From then on the holders are whoever mined first.
- Your own coinbase earns only once you have paid for its block.

The rest is unchanged:

1. Bitcoin Core, synced (pruned is fine), with a wallet holding a little BTC for the miner: `bitcoin-cli createwallet miner`. Each curve block pays at least 10,000 sats or nothing, so 0.002 BTC covers a tiny curve.
2. `hashfun doctor`, then `hashfun web --btc-rpc http://user:pass@127.0.0.1:8332 --allow-launch` and open http://127.0.0.1:8080. Connect UniSat (**untested: the real extension**). Launch form: a picture, preset **CPU test**, **0.001 BTC**.
3. Mine it: `hashfun node rpc TICKER createwallet w`, `hashfun node rpc TICKER getnewaddress "" bech32`, then
   `hashfun mine TICKER --payout <that address> --btc-rpc http://user:pass@127.0.0.1:8332 --btc-wallet miner --max-pay-btc 0.0002`.
4. Trade peer to peer from two browser profiles, or make from a server with `hashfun book`.
5. Second machine: `npm i -g hashfun`, then the `node add` line above and `hashfun node up TICKER`.

What that run exercises for the first time: real Bitcoin headers through the relay, mainnet fees and 10-minute confirmations, real hours on the swap timelocks, UniSat itself, and macOS.

## Unchanged from the third drop, rerun this round

Swaps on the shipped timelocks (`book`, S1 to S8 and H1), `hashfun book`, the UniSat guard against Fractal, bids backed by sats, the binary picked by the CLI per platform, the cross-machine chain replay. `RESULTS.md` of the third drop describes each; it is in the repository's history.

## Not done

- A green run on GitHub. The first one built all four binaries and failed in one suite on three platforms (above); the jobs after the builds have not run there yet. `bash deploy.sh wait` puts the failing logs where I can read them.
- The open items above: memory and block weight under spam, the pool under full blocks, `btc_confs`.
- Bitcoin Core's own unit tests on this fork (the workflow can: run it by hand with `core_tests` on).
- A maker's browser tab in the background, not tested with a really hidden tab (`hashfun book run` is the answer for anything that matters).
- Reading sats on mainnet goes through `scantxoutset` (about a minute, one at a time): fine for a first run, not for a public site.
- One site, one book. Lightning exits. A hosted fleet. Windows other than through WSL.
- No review by anyone outside this project: the review above is another agent, and so is the model the node is now tested against.
