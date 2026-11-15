# hashfun: status, 2026-11-14 (fifth drop)

58 commits on `namecoin-core@70c6b36` (branch `auxpow`: Bitcoin Core 32.99 + AuxPoW). This drop is rule set 3: **every coin has two curves and two prices, one in BTC and one in QWEN** (Qwencoin, https://github.com/staccDOTsol/qwencoin). With it: the Qwencoin nodes run the launches and mine them, the site moves under https://aichat.fyi/fun, Bitcoin can be read without a Bitcoin node, and the site says what this is to someone who has never heard of it.

**Consensus changed. Version 0.2.0.** Launch files are version 3; versions 1 and 2 are refused with the message that says to create the launch again. A launch made with 0.1.0 keeps running on 0.1.0 and is not read by 0.2.0.

The specification of the new rules is `contrib/hashfun/TWIN.md`. The whole system as it now stands is `HASHFUN.md`. The words the site, the packages and the Qwencoin pages use are `contrib/hashfun/PITCH.md`.

Everything in "What passes" ran on Linux x86_64, twice: in the working tree on a GCC build, and from a clean clone of the patches on a static binary built the way the release's is. Nothing of this drop has run on macOS or ARM yet: the push below is that run (the fourth drop's last build passed on all four platforms, and `hashfun@0.1.0` came out of it).

## Ship it: two machines, in this order

**1. The Mac.** Rebuilds the repository from `patches/`, pushes branch `hashfun` to `github.com/staccDOTsol/hashfun`, sets the repository's description, tags `v0.2.0`. GitHub then builds the node on four runners, runs the whole regression against each binary, has every binary replay every other binary's chain, makes the release and publishes `hashfun@0.2.0` to npm. A published version cannot be taken back.

```
env YES=1 bash ~/src/hashfun/deploy.sh
bash ~/src/hashfun/deploy.sh wait
```

The second line ends when the build has ended and leaves `ci/status.txt` and `ci/failed.log` in `~/src/hashfun/ci/`, which is the folder I can read. If a job failed, say so: I fix it and send new patches, and the same two lines run again (a tag whose version is already on npm is never moved; until then it is).

**2. The AMD machine (Codex), after the release exists.** The Qwencoin side is a patch series inside the hashfun repository, with its own brief. Give Codex this:

```
Clone https://github.com/staccDOTsol/hashfun (branch hashfun) into ~/hashfun-src and follow contrib/hashfun/qwencoin/CODEX.md exactly, step by step. Stop and report at the first check that fails.
```

The brief has it check that the release is there (step 1), apply the series to a git copy of Qwencoin and run its checks, give the owner's nodes a spending limit for hashfun if none is set (`FUN_LIMIT`, one coin), push to Qwencoin's main (fast-forward only), publish to Hugging Face with the project's own command, and confirm that the pod serves https://aichat.fyi/fun and that the explorer and the graph still answer. It never touches a token, a wallet or the pod itself, and it says how to undo.

After step 2 the site is public and every Qwencoin node follows it. Nothing is launched by any of this: the first coin is whoever fills in the form.

## The first build of this drop on GitHub

Run 43665033590 (`v0.2.0` on commit `d4993ddcb8ad`) ended red, and nothing was released from it. linux-arm64 and darwin-arm64 passed every suite. linux-x64 failed `unit` and `yield`; darwin-x64 (the Intel runner, the slowest of the four) failed `yield`, `sitepool` and `smoke` and passed the other ten. All four causes were in the tests: nothing in the node or the rules changed for them. Looking for them turned up one fault in a tool (`hashfun mine`, below the table), which is fixed too.

| Suite | Where | Cause | Now |
|---|---|---|---|
| `unit` | linux-x64 | `test_weighted_split` asked that the work two pools accepted from a proxied miner be split 3 to 1 within 0.15, and got 0.59. What the proxy decides is the miner's time (0.747 on every run here, loaded or not); the work the pools then accept follows it only roughly on a test chain (0.60 to 0.81 over thirteen runs here) | the test measures the time, and the proxy's statistics give it |
| `yield` | linux-x64, darwin-x64 | the scenario follows one coin by hand, and the wallet transfer made right after could take that coin as an input: coin selection is random, and it did on two of the four runners, after 39 of the 76 checks | the transfer comes first, and the coin is locked in the wallet while it is followed; so is the second coin followed that way |
| `sitepool` | darwin-x64 | an outside miner mined for 25 seconds and the test took the difficulty to be high enough by then for a block to owe more than the launch's least payment. On that runner it was not (15 blocks in 33 seconds): every block owed nothing, and the dues the test waits for could not come, on a second try either | the miner stays until the launch says its next block owes four times the least payment, and the test waits for the draw of a block, not for a span of time |
| `smoke` | darwin-x64 | six seconds of mining gave two blocks; the launch needs about ten to graduate | it mines until the launch has graduated, and until each curve has four blocks and one settled by a payment |

Why that runner is so slow at exactly this: on a test chain at the lowest difficulty nearly every hash is a share, and the CPU miner (`hashfun/miner.py`) sends its pool every share of a batch of 20,000 hashes and waits for each answer, thousands of them a block. That, not the hashing, is what a block costs there: a fifth of a second here, two to four seconds on that runner. A launch made on the site starts at 32,768 hashes a block at the least (its "CPU test" preset; the others at Bitcoin's difficulty 1), where a batch holds one share or none, so none of this is on a real chain. The cause is under "Still open": a pool session's share difficulty only ever falls.

The changed tests ran here plain and with every core taken by other work (eight busy loops on two cores), the nearest thing to that runner this machine has: `yield` 76/76 five times plain and once loaded; `sitepool` 26/26 in 2 minutes plain (5 before) and in under 3 loaded.

The loaded smoke test found one more thing, and this one is in a tool. `hashfun mine` started its pool, waited half a second and connected its CPU miner; the pool opens its port only once its node has given it a first template, and on a machine busy enough that takes longer: the miner was refused and the command ended with a traceback. `hashfun mine` now waits until its pool listens, and the miner tries a refused connection again for 20 seconds (`test_a_miner_started_before_its_pool_listens_waits_for_it`). With that the smoke test passed three loaded runs of three (it had failed the first one before), and the pool's unit tests passed loaded.

With them, from before the push: where `CI` is set the runner tries a suite that failed once more, keeps the first log and says so in its output (on a shared machine a check that waits on a clock can miss it once; a suite that fails twice has failed). None of the four failures above was of that kind, and none would have passed on a second try except by the coin landing the other way.

## Rule set 3, and what holds each rule

| Rule | Held by |
|---|---|
| A launch has two curves of the same shape. Header version bit 9 says which one a block is on; the bit is refused after graduation, in the genesis block and on a merge-mined block (`bad-curve-version`) | `twin` (both curves on one node, templates for either, the refusals), `e2e` 2 and 13, the node's self-test, `diff` |
| A block mints from its own curve by its own work: `S(Wx + work) - S(Wx)`. One chain, one difficulty | `twin`, `yield` (subsidy of every block against the model), `doctor` |
| The first curve to sell out graduates the launch. The block that crosses mints only what is left; what the other curve has not sold is never minted (presale supply between G and 2G; the parsers bound `2G + tail`) | `twin`, `e2e` 6 (BTC curve first) and 13 (QWEN curve first), `yield` (a fork where each branch graduates by a different curve) |
| A block owes its own curve's asset: sats on Bitcoin or qwen on Qwencoin, with that curve's minimum, creator script and confirmations. 80% to a holder drawn by bag, 10% creator, 10% dev, as before | `yield`, `e2e` 12, `fleet` |
| A second header relay follows Qwencoin: its retarget, its work function (a pass through its 528 MB table, not a hash), its two timestamp rules at the edges of a difficulty period | the self-test and `diff` on 189 real headers of the live chain across its first three retargets, in three implementations (the node's, the Qwencoin project's reference values, a Python pass); a real qwencoind (below) |
| A proof settles only a block of its own chain's curve (`HFP1` Bitcoin, `HFP2` Qwencoin) | `yield` (a real payment on the wrong chain, each way; a right payment under another block's tag, each way), `e2e` 12 |
| Qwencoin headers count in a block's coinbase only, and a block checks the work of at most 8 | `yield` (nine in one coinbase; known, unconnected and wrong-bits headers cost no check; a header outside the coinbase), the self-test, a real qwencoind |
| A launch on a real Qwencoin does not start without the table, and its anchor's work is checked at start | `diff` (wrong and missing tables), `smoke`, a real qwencoind |
| A launch whose deadline cannot cover its confirmations is refused by both parsers | `diff` (both parsers on the same files), `unit` |
| The site, the pool, the settler and the book speak both: `ADDRESS/btc` and `ADDRESS/qwen` on the stratum, a settler per chain, three pairs on one HTLC book (coin/BTC, coin/QWEN, BTC/QWEN) | `fleet` (two pools, one per curve, each settler leaving the other curve's blocks alone), `book` (37), `web` (53), `sitepool` (26) |

The QWEN price is nowhere in consensus. A coin has two price points, each moved only by what is mined through it; the site shows what they imply (sats per QWEN) and says whether it is a two-sided price (both curves being mined) or only a bound.

`yield_regtest` is the strongest check: a real node, a regtest Bitcoin and a regtest Qwencoin, 442 blocks, compared with a second implementation of the rules after every block, restart and reorg: 53,143 obligations, both relays, both curves, zero differences. The comparison was itself tested by breaking the model twice on purpose (nine header checks a block; a proof that settles under any tag): both are caught, the second only after two cases were added for it. The model is not an independent party: the same AI wrote both.

## Review

An independent reviewer (another model, read only) went through the consensus diff. It found no chain split, no wrong mint and no wrong unlock, and five things, all changed since:

| | Finding | Now |
|---|---|---|
| 1 | Anyone paying a fee could make every node spend 8 passes (about 0.4 s) per block on junk Qwencoin headers, again at every restart, and crowd out a settler's real ones | Qwencoin headers count in the coinbase only (a miner's own block). Every work value a node has computed is kept in `qwork_values.dat`: a restart costs no pass (measured: 0 passes with the file, 11 after deleting it) |
| 2 | The relay did not have two of Qwencoin's header rules (the timestamp rules at the edges of a difficulty period), so it would have followed branches no Qwencoin node accepts | both rules, confirmed active on the real qwencoind with `getdeploymentinfo`; self-test cases for each |
| 3 | The list of graduation blocks dropped its oldest entry first, which after 17 competing graduations is the main chain's | a block that is looked up moves to the back |
| 4 | The two launch file parsers named a different first error on a file with several | same order: 4,697 files with one fault each, 785 differed before, 0 after |
| 5 | A launch could ask for more confirmations than its deadline leaves time for, and every block that owed would lose its coins | refused by both parsers (the deadline must last twice as long as the confirmations take) |

## The QWEN leg against a real Qwencoin

The regression plays Qwencoin with a second stock bitcoind on regtest. Separately, twice (the second time on the node as changed by the review), the leg ran against the Qwencoin project's own `qwencoind` on its main-network rules with the real table, on a private two-node network:

- a launch anchored on that chain; the node checked the anchor's work through the table at start;
- 252 launch blocks on the QWEN curve over the two runs, mined through the pool the Qwencoin helper starts (`tools/fun.py`). What they owed was paid in qwen on Qwencoin by its settler (17 payments in the first run), the headers relayed, the payments proven, and a coinbase followed to the end: locked, settled, spendable once mature. No payment was lost;
- refused, as they must be: spending a coinbase before its payment is proven (`bad-txns-unsettled-coinbase`), a proof one confirmation short, a real header with its nonce changed (no work), a header outside the coinbase;
- the five functions a Qwencoin model gets (`fun_coins`, `fun_quote`, `fun_mine`, `fun_send`, `fun_launch`) on the real nodes, and the spending limit (`FUN_LIMIT`) refusing the step that would cross it.

It found two faults, both in the Qwencoin helper and both fixed (sending a coin from a launch's node needed a fee rate and a change address type). The log is in the Qwencoin series (`logs/fun-real.log`).

Not run: the leg against the public Qwencoin chain, with qwen that is worth something.

## A rehearsal of the public site

Once, on this machine, with the parts that will really run: the npm package as GitHub will build it for Linux (its own CLI, its own static node), started the way the pod starts it (the Qwencoin helper with `FUN_SERVE=1`, the project's own pages in front of it), Bitcoin read from the real chain through the two Electrum servers, Qwencoin from the private two-node network.

- The site answered under `/fun` behind the Qwencoin pages: the page with the pitch in its title, the share picture, an empty board; the project's own front page links to it.
- A coin made through the form's API in under a second: a version 3 launch anchored at block 975,848 of the real Bitcoin chain and in the Qwencoin chain, its node started by the site.
- A second node with a folder of its own, as another machine has, found the coin on the site, started its node of it, reached the site's node through the pages (`/fun/p2p/TICKER`: on the real pod there is no other way in), mined 186 blocks on the QWEN curve with the package's own miner and paid what they owed in qwen.
- The payments reached their six Qwencoin confirmations, were relayed and proven, and the site showed them as paid.
- The site's own pool mined a block on the QWEN curve for a visitor's address and listed what it owes.

Twenty checks, all passed, after one fault: a node did not start when one of its launch's ports was already taken on the machine (here the site's node and the follower's on one machine; on anyone's machine, any program that has the port). `hashfun node add` now gives such a node a free port.

What it was not: the pod, a public address, a browser, qwen that is worth something.

## What the QWEN side rests on

A payment on the QWEN curve is proven the same way as one on the BTC curve: a transaction in a block of a header chain the launch's nodes check for work. So it is as hard to fake as that work is to do. On Bitcoin that is the hardest thing there is. **On Qwencoin today it is not hard**: a block is about 16,000 passes through the table, a pass takes about 50 ms on one core here, the whole network is a handful of machines.

What that means: someone with more processors than Qwencoin's miners can mine a private branch that says they paid, relay it in their own blocks, and unlock coins mined on the QWEN curve without paying the holders, the creator or the dev. They cannot touch the BTC curve, mint more than the curve allows, or take anyone's coins. What they get is the QWEN curve at the cost of its hashes alone.

What is done about it: a launch's confirmations are sized to its QWEN leg (`qwen_confs`, up to 1008; `launch new` and the form ask for as many blocks as pay out 1.25 times everything the leg collects), so that for one launch, faking the payments means giving up more qwen in block rewards than paying them costs. That argument does not hold across launches (one private branch can carry the fake payments of several), nor against someone who simply has most of Qwencoin's hash power. It gets better exactly as Qwencoin gets mined by more machines, which is what this drop is for. Until then: the BTC price point of a coin is backed by Bitcoin's work, the QWEN one by Qwencoin's, and the site shows them apart.

## What passes

One command runs all of it and writes one log per suite: `bash contrib/hashfun/ci/test.sh`.

| Suite | Result | What it is |
|---|---|---|
| `unit` | 230 tests | the Python model and the tools: both curves, both legs and both relays as a model, version 3 launch files, the pool on either curve, the settlers, the book's server side, the page over stand-in nodes, the CLI, and Bitcoin through Electrum servers that lie, disagree, hang and cut the line |
| `diff` | 26 tests, and the self-test's 22 checks | the node's own consensus sources against the Python model, value by value: the curves, both relays, both launch file parsers on damaged files, Qwencoin's work function on real headers |
| `web_js` | 18 tests | the browser's code against the Python, byte for byte; the committed bundles are the build of the sources; lint |
| `doctor` | pass | the binary boots a throwaway launch, mines on both curves, every mint and every debt equals the CLI's own copy of the rules; it also mines the 120-block chain the other platforms replay |
| `twin` | 30/30 | **new**: the two curves on one node by raw RPC |
| `e2e` | 97/97 (was 67) | single-node consensus, both curves, graduation by either, merged mining against stock bitcoind, both legs, swaps |
| `yield` | 76/76 (was 46) | both legs, a real node against the model, at every height after every block, restart and reorg |
| `btcindex` | pass | balances on both chains from an index agree with the scan |
| `btclight` | 110 checks | **new**: every call the site and the settlers make on Bitcoin, through a real Electrum server over a regtest node, a reorganisation, a settler, the site |
| `sitepool` | 26/26 (was 16) | the site mines a block for a visitor on either curve; the page pays what it owes on that chain; it unlocks |
| `fleet` | 51/51 (was 41), 5 min | 4 nodes, 2 competing pools (one per curve), a settler per chain, production-mode launches, real time, a Qwencoin reorg under a payment |
| `book` | 37/37 (was 28) | peer-to-peer swaps of all three pairs on the shipped 4 h and 8 h timelocks with the clock moved by the test, and the headless engine |
| `web` | 53/53 (was 45), 8 min | the real site under `/fun` in real Chromium browsers against real nodes |
| `smoke` | pass | `hashfun launch / node / mine / web` end to end through the CLI, on both curves |

The unit tests, the end-to-end suite and the CLI smoke test also pass on Python 3.10, the oldest the CLI takes (the page tests are passed over there: no browser). Logs are in `logs/`. Screenshots of the site (board on a desktop and a phone, a coin with its two curves, mining a block on the QWEN curve, the book with BTC/QWEN, the launch form) are in `screenshots/`.

## Platforms

| Target | What has run |
|---|---|
| `linux-x64` | everything above, on a GCC build of this tree, and again from a clean clone made of the patches, on the static binary built the way the release's is (zig's clang, musl), in the environment the GitHub jobs set up |
| `linux-arm64`, `darwin-arm64` | every suite above, on GitHub, in the first build (run 43665033590: the tree before the four test changes above), with the table (fetched once from Hugging Face, checked by its sha256, cached) |
| `darwin-x64` | in that build: ten suites passed, three did not (above). The changed tests have not run on that runner: the next push is that run |

The work function is whole-number arithmetic only (16-bit weights, sums that cannot overflow 32 bits), so there is no rounding for two compilers or two processors to disagree about. Each platform's build runs the self-test on the real headers, and the install job has each binary replay the chains the other three mined: that is where a disagreement would show.

## The site, and Bitcoin without a node

`https://aichat.fyi/fun`, on the machine that serves aichat.fyi, started by the Qwencoin helper there: `hashfun web --base-path /fun`, its Qwencoin side read from that machine's own node, launching and mining a block for a visitor switched on. That machine cannot hold a Bitcoin node, so Bitcoin is read through two Electrum servers (`hashfun/btclight.py`, any `--btc-rpc electrums://HOST:PORT,HOST:PORT`): the tool keeps its own chain of headers and checks every proof against it, asks both servers anything a single one could lie about, and treats a disagreement as an error. Two servers that agree on a lie can hide a payment from the site (a balance shown wrong, a settler that does not see a payment in time); they cannot make the launch accept one that was not made, because the launch's nodes check every header and proof again. `HASHFUN.md` has the table of what is trusted for what.

The pitch is the first thing on the board ("Memes quoted in BTC. Mined, not minted."), one line on every page after the first visit, and in the link preview of the site and of each coin (`/c/TICKER`). The number of machines running a node and a model comes from the Qwencoin graph and is shown only when it could be read.

## The Qwencoin side

Six commits for Qwencoin (`contrib/hashfun/qwencoin/patches/`), applied and published by `apply.sh` and `CODEX.md`:

- every node follows the site's newest launches that are still on their curves (two at most, `FUN_COINS`): it runs each launch's node, mines its QWEN curve with a tenth of one core (`FUN_CPU`) and pays what its blocks owe from a second wallet that holds only what the node moved into it, never beyond `FUN_LIMIT`;
- its model gets five functions: what coins there are, what one costs on each curve, mine some, send some, launch one;
- the public node serves the site under `/fun`, and carries the launches' peer-to-peer connections over the same HTTPS name (`/fun/p2p/TICKER`), because that machine can be reached no other way;
- the nodes fetch hashfun from the GitHub release named in one file (`HASHFUNPKG`: version and sha256), which is why the release comes first.

Tested: the helper against stand-ins with no network (`tests/check_fun.py`), on the real two-node network, and in the rehearsal above. Not tested: `CODEX.md` itself, which was written from the project's scripts and has never been followed on that machine; and the pod, which nothing here can reach.

## Still open

- **The QWEN leg is as strong as Qwencoin's work** (above).
- **Memory under spam.** While a curve is open the node keeps every earning coin in RAM (about 190 bytes per live coin). An attacker who fills blocks with dust outputs grows it by gigabytes per hour, and a launch that never graduates never closes. The block weight limit is still Bitcoin's 4M whatever the spacing. The fixes (compacting dead coins, a weight limit scaled to the spacing, a floor on what earns) are designed and not built; the weight limit is consensus and needs another rule set.
- **The pool under full blocks.** The pool's coinbase carries headers of two chains and payment proofs; the node reserves 8,000 weight units for a coinbase. A full mempool with more than about three proofs in the coinbase makes the pool's block overweight. Start the node with `-blockreservedweight=100000` on a busy launch.
- **`btc_confs` defaults to 1**: a forged Bitcoin block (cost: one block reward) settles what its miner owes. Raise it for a launch whose miners owe more than that. Merkle depth is not pinned (the 2^70 inner-node forgery), on either chain.
- **One block seeds each draw**, so a miner can re-roll a draw by withholding a block it found.
- **Small ones, unchanged from the fourth drop:** `genesis_nonce` is outside the launch id (two valid nonces are two chains with one id: a confusion, not a theft); no minimum chain work in the first blocks of a launch; LWMA costs two 256-bit divisions per window block per header.
- **The table has one source** (Hugging Face) and is 528 MB: `hashfun qwork fetch` resumes and checks the sha256, the node checks its checksum at every start. If Qwencoin changes its table or its rules, launches made before keep following the old ones.
- **Two Electrum servers that agree on a lie** can hide a payment from the public site (above). An operator with a Bitcoin node gives its RPC URL instead.
- **The pool has no variable share difficulty.** A session's share difficulty starts at the pool's and only falls, to the block's when that is lower; a miner that wants another has to ask (`mining.suggest_difficulty`). On a launch that starts at Bitcoin's difficulty 1 a CPU sends a share an hour and nothing is wrong; a rented rig pointed at a young launch's public stratum is held to a share per 4 billion hashes, thousands a second, more than a pool written in Python takes. The public site's stratum listens on its own machine only. On test launches this is what makes the slowest runner slow (above).

## Not run

- The four changed tests on GitHub's runners, and the jobs after the builds (`pack`, `install`, `release`) for 0.2.0, which the first build never reached: the next push is that run.
- `CODEX.md` on the AMD machine; the pod; the public site.
- The QWEN leg on the public Qwencoin chain. A first coin with real BTC and real qwen.
- Bitcoin Core's own unit tests on this fork (the workflow can: run it by hand with `core_tests` on).
- UniSat itself (the page is tested with a stand-in for the extension). A maker's browser tab that is really hidden (`hashfun book run` is the answer for anything that matters).
- Not built: Lightning exits, more than one site sharing a book, Windows other than through WSL.
- No review by anyone outside this project: the review above is another model, and so is the model the node is tested against.
