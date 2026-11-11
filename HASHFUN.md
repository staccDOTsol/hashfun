# hashfun

PoW launchpad on a Bitcoin Core fork. Every launch is its own chain, defined by a descriptor file; one universal node binary (`hashfund`) runs any of them. Coins are mined, not minted: issuance is a consensus function of cumulative work, shaped like pump.fun's constant-product curve. At graduation the chain opens to Bitcoin merged mining (AuxPoW). Exits are trustless HTLC swaps against BTC.

Base: Bitcoin Core master (32.99) + Namecoin's `auxpow` branch (AuxPoW only, no name ops), pinned at `70c6b3698ef8357f6c04004e57c06a85856e3f27`.

## Consensus (launch chains only)

| Rule | Definition |
|---|---|
| Relative work | `W = chainwork(tip) - chainwork(genesis)`, expected hashes |
| Curve supply | `S(W) = floor(T0 * W / (V0 + W))`, clamped to `G` |
| Block subsidy (presale) | `S(W_prev + work(nBits)) - S(W_prev)`: path independent, timestamp independent |
| Price | `(V0+W)^2 / (T0*V0)` hashes per satoshi; ratio end/start = `(T0/(T0-G))^2` (14.7x with pump.fun proportions) |
| Graduation | `W >= W_g = ceil(G*V0/(T0-G))`; crossing block mints only up to `G` |
| Tail | after graduation: `tail_reward >> (height / tail_halving_interval)` per block |
| Creator fee | coinbase must pay `floor(subsidy * creator_fee_bps / 10000)` to `creator_script` (`bad-cb-creator-fee`) |
| AuxPoW | valid only if the parent block's `W >= W_g` (`auxpow-before-graduation`); chain ID from the launch id, kept in `[1, 0x1FFE]` so a BIP9/version-rolled BTC parent never collides |
| Difficulty | LWMA-1 every block, window N, solvetimes capped at 6T, monotonic-forced timestamps, overflow-guarded. Block times are whole seconds and every solvetime counts as at least 1 s, so `target_spacing >= 2` (with T = 1 difficulty could never rise). A hash surge raises difficulty a few percent per block; until it catches up blocks arrive as fast as timestamps allow (about 6 per second, pinned at the future limit), each minting only what its work is worth |
| Stall relief | the target doubles for every full 6T a block's own timestamp sits past its parent's, up to the pow limit, so an abandoned chain decays to CPU-minable in minutes. Safe because issuance is priced by work. nBits is a function of (ancestors, own nTime): no nTime rolling. `getblocktemplate` and `createauxblock` rebuild their cached template when the clock enters the next relief step (a cached one would be invalid, or would keep a stalled chain stalled) |
| BTC anchor | mandatory `btc_anchor_height` / `btc_anchor_header` / `btc_anchor_period_time`, hashed into the launch id: no block of the launch can predate that Bitcoin block, and the in-chain Bitcoin header relay starts from it. The parser refuses what it can refute without a chain: the header's hash must meet its own bits, the bits may be no easier than Bitcoin's minimum, the period start must be set, not later than the anchor allows, and the anchor's own time when `height % 2016 == 0` (`btc_regtest` launches skip this). Whether the header really is the block at that height is a question for a Bitcoin node: see "Checking a launch file" below |
| FTL | per-descriptor future time limit. Default `min(6T - 1, 7200, max(10, N*T/20))`: 22 s at T = 5, N = 90. Outside test launches it must be at least 10 s and less than `6T`: a stamp that may run 6T ahead buys a stall-relief step (or a capped solvetime) with no time passing, and a limit of a few seconds makes honest clock skew reject blocks |
| Coinbase | `scriptSig` starts with the block height (BIP34), then a push of the first 16 bytes of the launch id (`bad-cb-launch-id`). A coinbase names its launch and every other transaction descends from coinbases, so no transaction can exist on two launches: nothing spent on one can be replayed on another, even when two launches share a preset, a creator and a miner (without the rule their empty blocks at equal heights had byte-identical coinbases). `getblocktemplate` gives the exact bytes as `launchcoinbase`; the node's own miner, `createauxblock` and the pool follow it |
| Genesis | coinbase `scriptSig = PUSH32(launch_id)`, one zero-value `OP_RETURN` output, `nVersion=1`, must meet `pow_limit_bits` |

Sniping does nothing: a low-difficulty block pays exactly its work at the curve price. Merge-mining pools cannot touch presale issuance because auxpow is invalid until graduation; after it, exahash secures the tail.

All arithmetic is 256-bit integer. Validation bounds (`V0 <= 2^160`, `G <= 99.9% T0`, `T0 <= MAX_MONEY`) keep every product below 2^256.

## One command

```
npm i -g hashfun                                # the CLI and the hashfund for this machine (macOS or Linux, Intel/AMD or ARM)
hashfun doctor                                  # which hashfund this machine runs, proven by running it
hashfun launch new --name "My Coin" --ticker MYC --creator-address myc1... -o myc.json \
        --btc-rpc URL --sats-total 0.7 --creator-btc-address bc1...        # Bitcoin anchor + sats leg (required)
hashfun node add myc.json && hashfun node up    # one hashfund per registered launch, state in ~/.hashfun
hashfun node ls                                 # height, curve %, graduated, peers
hashfun mine MYC --payout myc1... --btc-rpc URL --btc-wallet NAME     # pool + CPU miner (or --no-cpu for ASICs)
hashfun wallet yield | claim-yield              # BTC earned by holding, paid at your launch keys on Bitcoin
hashfun wallet buy|sell ..., hashfun swap ..., hashfun electrum ..., hashfun board ...
hashfun web --btc-rpc URL                       # the site
hashfun book ...                                # peer-to-peer offers and swaps without a browser tab
```

`hashfun mine` merge-mines every other registered launch that has graduated and runs the settler (relay Bitcoin headers, pay the drawn payee, publish the proof). `contrib/hashfun/cli_smoke.sh` drives all of this against real binaries.

In a source checkout the same CLI is `python3 -m hashfun.cli` (or `pip install -e .`). Which `hashfund` it runs: see Platforms and the node binary.

## Running more than one node

Launch chains are production chains: `test: false` descriptors cannot mock the clock and gate mining on peers. What differs from Bitcoin Core:

| Behaviour | Why |
|---|---|
| An old tip is not "initial block download" (`-maxtipage` defaults to 100 years) | a launch only gets blocks while minting pays; a quiet chain must still relay transactions and let anyone mine the block that revives it |
| `getblocktemplate` / `createauxblock` need a peer, or `-minewithoutpeers` | the first node of a launch has nobody to connect to; any other miner cut off from the network would mint, and pay Bitcoin for, blocks nobody sees |
| The pool refuses to hand out work while the node's headers are ahead of its blocks | with no IBD flag, this is what stops hashing on a stale tip |
| `-prune` is refused | sats-leg state is rebuilt from full blocks |
| `btc_regtest` in the descriptor (part of the launch id) | which Bitcoin the sats leg follows, independent of `test`: a production-mode launch can run against a regtest Bitcoin for fleet tests |

`hashfun node add x.json --peer host:port [--p2p-port N]`, `hashfun node up X --first` (the first node: `-minewithoutpeers`).

The settler (`hashfun mine`) pays a block only once it is `--pay-depth` deep (default 12, so its draw block is 6 deep), writes the signed payment to disk before broadcasting it, republishes a proof whose block was reorged out, and reports a payment as lost only if a reorg changed the draw after it was made. `python -m hashfun.tests.fleet_regtest` runs all of this with four nodes, two pools and two Bitcoin wallets.

## Sats leg

Every launch has one; there is a single kind of coin. A curve block owes real BTC on top of its hash: `owed = (work * sats_num) >> sats_shift` (`hashfun launch new --sats-total` sizes it as total BTC over the curve). No bridge and no reserve: the miner pays a drawn payee directly on Bitcoin and proves it on the launch chain.

| Step | Rule |
|---|---|
| Draw | block `h+6` seeds block `h`'s draw with the hash that carried its work: its own hash, or for a merge-mined block the parent chain's block hash (a merge-mined block's own hash can be re-rolled for free). Debts under `sats_min_payment` pay the minimum with probability owed/min. Payee class: 80% holder, 10% creator (`creator_btc_script`), 10% dev (compiled-in script, `bc1pctxxt9z57ypwrvdws45hgpgkx922e39gj3hkqe0hsgv3863f4ffsu7p7x3`) |
| Holder | hold and you earn, no opt-in. One point into the value of the coins that are **live at the draw** (every unspent P2PKH / P2SH / witness-program output, as of the end of block `h+5`): the coin holding the point wins and is paid at its own scriptPubKey on Bitcoin (same key, since a launch is a Bitcoin fork). The payee is fixed there: moving the coin afterwards changes nothing for that draw, and a spent coin is never drawn again, so sending coins to yourself buys no weight. Nobody holds yet (the first blocks of a launch): the holders' share is owed to no one |
| Earning starts | a curve coinbase that owes sats is not in the draw until its own block has settled (or its draw said nothing is due): hash that never pays never earns. Every other output earns from the block it is in |
| Redirect | a coinbase may send its output 0's yield to another Bitcoin script with `OP_RETURN "HFY1"<btc scriptPubKey>` (the miner's own output; the first such tag, and only if that script is itself P2PKH / P2SH / a witness program). No other transaction can redirect: its author does not own every output it creates |
| Pay | a Bitcoin tx whose output `i` pays the payee and whose `OP_RETURN "HF"<20-byte tags>` has `SHA256("hashfun-pay"||launch_id||block_hash)[:20]` at position `i`. One tag list per transaction: the first such output and no other, so one output settles one block |
| Bitcoin view | `OP_RETURN "HFH1"<80-byte headers>` relays Bitcoin headers; the node keeps a validating header tree from `btc_anchor_header` (PoW, retarget, median time), so its view of Bitcoin is a function of launch blocks only |
| Prove | `OP_RETURN "HFP1"<proof>`: merkle proof of the payment in a relayed Bitcoin block with `btc_confs` confirmations. Invalid proofs and headers are ignored, never block-invalidating; so whether a proof counts is itself consensus state, and it is decided from the chain's blocks alone (no UTXO set, no clock): a node that replays the chain at start reaches the same answer as one that saw the blocks arrive |
| Lock | a curve coinbase cannot be spent until settled (`bad-txns-unsettled-coinbase`, mempool and consensus); unsettled `settle_deadline` blocks after minting, it never can. A reorg that removes a settlement also removes spends of that coinbase from the mempool |
| End | the sats leg is over `settle_deadline` blocks after the last curve block: no draw and no proof can count after that height, so nodes stop there. Later blocks are not looked at for coins, headers or proofs, a starting node replays the chain only that far, and `getlaunchinfo.earning` is 0. No rule changes (nothing after that height could have changed what a coinbase may do); it bounds the work and the memory of a graduated launch. A reorg below that height reopens the state and reconnecting closes it with the same contents |

`settle_deadline` defaults to 720 blocks in the descriptor format; `hashfun launch new` and the launch form set it to one day of blocks when the sats leg follows real Bitcoin, where a confirmation can take an hour.

HFH1/HFP1 outputs are honoured in coinbases too, so a miner with no spendable coins can relay headers and settle from its own next block. RPCs: `getmintobligation <height>` (owed, payee class, tag, and once the draw is made: `pay`, the `pay_script` to pay, the `coin` that won a holder draw, `earning`: the value the draw was over), `getlaunchinfo` (`earning`: the value of live coins now), `getbtcrelay`. State lives in memory (`src/launchyieldstate.cpp`: the coin list with a Fenwick tree over live values, so a draw, a spend and a proof each cost O(log n)) and is rebuilt from blocks; pruned nodes are not supported with a sats leg.

## Descriptor

JSON. The launch id is `SHA256d` of a canonical binary serialization of every consensus field (everything except `genesis_nonce`, ports and seeds):

```
"hashfun-launch" || u32 version || str name || str ticker || str hrp
|| u8 pubkey_prefix || u8 script_prefix || u8 secret_prefix
|| u32 genesis_time || u32 pow_limit_bits || u32 target_spacing || u32 lwma_window || u32 ftl
|| 32B virtual_work (big-endian) || i64 virtual_tokens || i64 graduation_tokens
|| i64 tail_reward || u32 tail_halving_interval || bytes creator_script || u16 creator_fee_bps || u8 test
|| u32 btc_anchor_height || 80B btc_anchor_header || u32 btc_anchor_period_time
|| i64 sats_num || u32 sats_shift || i64 sats_min_payment || u32 settle_deadline || u32 btc_confs
|| bytes creator_btc_script || u8 btc_regtest || [32B meta, only when set]
```

(`str`/`bytes` = CompactSize length + data; integers little-endian.) Derived from the id: P2P magic (`SHA256("hashfun-magic"||id)[:4] | 0x80` per byte), auxpow chain ID, default ports, datadir `launch_<ticker>_<id8>`.

`test: true` launches allow `setmocktime` and nonstandard txs.

`version` is 2. It is hashed into the id and names the rule set, so a file made for one rule set is never read under another. Version 1 was the pre-release set (the first sats leg, and a parser that took anchors, payout scripts and time limits it should have refused): both parsers refuse it and say to create the launch again.

Two parsers read launch files: the node's (C++, `src/kernel/launch.cpp`) and the tools' (Python, `hashfun/descriptor.py`). A file that meant one launch to the node and another to the pool, the wallet or the site would be a split, so both refuse whatever JSON readers disagree about, with the same message: bytes that are not strict UTF-8, a key twice in one object (one reader takes the first, the other the last), a number of more than 40 characters, nesting deeper than 64, `NaN` and `Infinity`. Keys left out get the same default in both (`target_spacing` 5, `lwma_window` 90, `ftl` from the formula above). `tail_halving_interval` and `btc_anchor_height` are below 2^31. `creator_btc_script` must be P2PKH, P2SH or a witness program: every miner whose block draws the creator has to get a Bitcoin payment to it relayed. `test_diff_cpp` holds the two parsers together on random, mutated and byte-damaged files.

### Checking a launch file

The parser can tell that an anchor is a Bitcoin header; it cannot tell that it is the block at that height, or that the period start is right, and a launch with either wrong refuses real Bitcoin headers at the first retarget after the anchor (two weeks at most), after which nothing on it can settle. A Bitcoin node can tell, and is asked (`descriptor.check_anchor`):

- `hashfun launch new --btc-rpc URL` takes the anchor from the node; with `--btc-anchor HEIGHT:HEADER[:PERIODTIME]` as well it checks the given one. `PERIODTIME` may be left out only when `HEIGHT` is a multiple of 2016.
- `hashfun launch info X.json --btc-rpc URL` checks someone else's file.
- `hashfun mine` checks before it serves work (it holds the Bitcoin RPC the settler pays through) and exits with the reason.
- `hashfun node add X.json --btc-rpc URL [--btc-cookie FILE]` checks before registering; without `--btc-rpc` it says in one line that the anchor was not checked.
- The site asks once per registered launch before serving it. Denied: the launch is off the board and the book and its page shows the reason. Bitcoin node not answering or still behind the anchor: not served yet, asked again every 30 s.

## Platforms and the node binary

The npm package carries one `hashfund` per system and processor, and the CLI runs the one for the machine it is on.

| Target | Machine | The binary |
|---|---|---|
| `linux-x64`, `linux-arm64` | Linux on Intel/AMD or ARM, any distribution (on Windows: WSL, which is Linux) | fully static against musl, built with zig's clang: one file, no library of the system is used |
| `darwin-arm64`, `darwin-x64` | macOS 14 or newer, Apple silicon or Intel | built on a Mac with Apple's clang, local symbols stripped, ad hoc signed |

How the CLI picks (`hashfund_choice` in `hashfun/cli.py`); the first that exists wins:

| Order | Where | When it applies |
|---|---|---|
| 1 | `$HASHFUND` | an order, not a hint: if it is set and the file is missing the CLI stops, nothing else is tried |
| 2 | `prebuilt/<target>/hashfund` beside the CLI | installed from npm |
| 3 | `contrib/hashfun/npm/prebuilt/<target>/hashfund` | a source checkout where `dist/build.sh` has run |
| 4 | `build/bin/hashfund` | a source checkout with a plain cmake build |
| 5 | `hashfund` on `PATH` | anything else, for example `pip install .`, which installs the Python only |

`<target>` is `sys.platform` plus `platform.machine()`. An Intel build of Python on Apple silicon runs translated and reports x86_64; the CLI asks `sysctl.proc_translated` and takes the ARM binary. A file that lost its executable bit in unpacking gets it back. With nothing found the CLI exits saying which way out applies: install the package, build one, or set `$HASHFUND`.

`hashfun doctor` prints the choice and proves it by running it: target, Python (version, scrypt), node (only `hashfun book` needs it), the chosen `hashfund` and why, its `-version`, then a self-test (`--quick` skips it). The self-test writes a throwaway test launch into a temporary directory, starts the node on it, requires the node's genesis hash to be the one the descriptor commits to, mines 5 blocks, and holds every block's mint (the sum of its coinbase outputs) to `Launch.subsidy` in the CLI's own Python copy of the rules, block by block. It then reads `getmintobligation` for block 1 (on the curve, sats owed) and stops the node. A binary for another kind of machine, a node that cannot start and curve arithmetic that differs from the model all fail here, in seconds, before a real launch depends on that binary. Exit status 1 on any failure.

Two machines can check that their nodes agree, which is what matters once the node comes from four compilers: `hashfun doctor --mine FILE` mines a short test chain (up the curve, through graduation, into the tail), holds every mint against the CLI's own rules, and writes the blocks down with what the node concluded from them: tip, UTXO set hash, curve state, and the sats owed and drawn for every block. `hashfun doctor --replay FILE` on another machine feeds those blocks to its own node and requires the same conclusions, naming the first difference. A changed block is rejected by the node itself; a changed conclusion is reported as a disagreement.

Python: 3.10 or newer, built against OpenSSL (the wallet vault needs `hashlib.scrypt`). The `python3` that comes with macOS is 3.9 on LibreSSL, has no scrypt and does not qualify. The npm wrapper looks past it: `$HASHFUN_PYTHON`, `python3`, `python3.14` down to `python3.10`, Homebrew's two usual paths, `python`; the first one that is new enough and has scrypt runs the CLI. On a Mac: `brew install python`.

## Build the node

```
cmake -B build -DBUILD_TESTS=OFF -DBUILD_GUI=OFF -DENABLE_IPC=OFF -DBUILD_KERNEL_LIB=OFF -DBUILD_BITCOIN_BIN=OFF
cmake --build build -j$(nproc)
# -> build/bin/hashfund, build/bin/hashfun-cli
```

That is a developer build: this machine's compiler against this machine's libraries. It needs what this Bitcoin Core needs (`doc/dependencies.md`: Clang 19, GCC 12.1 or the Xcode command line tools 26.3); Boost headers and SQLite are the only outside libraries. The CLI finds `build/bin/hashfund` by itself.

The binaries the package ships come from one script:

```
bash contrib/hashfun/dist/build.sh [target ...]     # default: this machine's own target; "all" for the four
# -> contrib/hashfun/npm/prebuilt/<target>/hashfund, stripped; prints size and SHA256
```

| Piece | How |
|---|---|
| `TOOLCHAIN=zig` | zig's clang carries the C library and libc++ of every target: any target from any machine, no SDK, no cross packages (`pip install ziglang`, or a `zig` on `PATH`). Linux targets link statically against musl; the binary asks for 8 MiB thread stacks because musl's default is 128 KiB. The compiler wrappers the script writes do three things CMake and zig do not agree on by themselves: pass `-UNDEBUG` (zig defines `NDEBUG` when optimizing, and Bitcoin Core refuses to build without its assertions); turn `-march=armv8-a+crypto` and the like into clang's own feature flags (zig reads `-march=` as a processor name, and the probe for the ARM SHA-256 and CRC instructions would otherwise fail and leave the node hashing in plain C); and keep CMake from recording zig's cached runtime libraries as "implicit" link libraries (it would name a non position independent copy on the link line of a position independent executable). The link itself strips the binary |
| `TOOLCHAIN=native` | this machine's own compiler, for this machine's own system. On a Mac that is Apple's clang with the deployment target `depends/hosts/darwin.mk` names (14.0), then `strip -x` and an ad hoc signature, verified (an ARM Mac runs nothing unsigned) |
| Default | native for a macOS target on a Mac, zig for everything else. The script also accepts a macOS target through zig (from Linux, or on a Mac without Xcode); that combination has never been built |
| SQLite | the version and SHA256 that Bitcoin Core's own `depends/packages/sqlite.mk` pins: fetched, hash checked, compiled with the options `depends` uses, linked statically |
| Boost | headers only (1.74 or newer, taken from the machine; `BOOST_INCLUDE` if they are somewhere unusual), shown to CMake through a private prefix so that nothing else under the machine's include directory reaches a cross compiler |
| Options | wallet on; GUI, IPC, ZMQ, external signer and the other executables off. `TESTS=1` also builds Bitcoin Core's unit tests (`test_bitcoin`) with the same toolchain; `JOBS=n` sets the parallelism |

`contrib/hashfun/build_and_test.sh` is the first run on a machine of one's own, from the patch series (next to `make_repo.sh` and `patches/`) or inside the tree: it checks the tools and installs nothing (`--check` stops there), runs `dist/build.sh` for this machine, then `ci/test.sh unit diff doctor`, with `e2e` added when a stock bitcoind is on `PATH` or named by `$BITCOIND`.

`hashfund` refuses to run without `-launch` (its auxpow code is not a valid Bitcoin node). Use stock Bitcoin Core for BTC. Default datadir `~/.hashfun`, config `hashfun.conf`.

## Python tooling (stdlib only, Python >= 3.10)

```
pip install -e .            # or run as python -m hashfun.<module>
hashfun-launch new --name "Cinder Hash" --ticker CNDH --creator-address cndh1... --graduation-hashes 1e22 -o cndh.json
hashfun-launch conf cndh.json > ~/.hashfun/hashfun.conf
hashfund -launch=cndh.json
```

| Tool | What it does |
|---|---|
| `hashfun-launch` | create descriptor + mine genesis, inspect (`info --curve`), write node config |
| `hashfun-pool` | stratum v1: `launch` mode (solo, non-custodial, coinbase pays the miner's username address + creator output) or `merged` mode (BTC parent GBT with aux commitments to every graduated launch; submits `submitauxblock`/`submitblock`) |
| `hashfun-proxy` | strata set: one miner, many launches, weighted deficit time-slicing, per-upstream delivered-work accounting |
| `hashfun-miner` | reference CPU stratum miner (tests, regtest) |
| `hashfun-swap` | HTLC verbs (`initiate participate audit redeem refund extractsecret`) against any Core-RPC node; `maker` runs the maker bot + order relay |
| `hashfun-electrum` | Electrum 1.4 server per chain (auxpow-aware, mempool, reorg undo) |
| `hashfun-wallet` | one BIP39 seed, BIP84 per chain (launch coin type `0x484600 + chain_id`); `buy`/`sell` run the taker side of a swap end to end |
| `hashfun-board` | indexer + JSON API + UI: curve position, graduation progress, hashrate, blocks |

Version rolling is refused by the pool (`mining.configure`): ASICs rolling bits 13-28 would overwrite the auxpow chain ID.

## The site

`hashfun web --btc-rpc URL [--maker maker.json] [--allow-launch] [--listen 127.0.0.1:8080]` serves the board, coin pages, the launch form and Bags for every launch registered on the machine. Source in `hashfun/web/src` (`npm install && npm run build` writes `hashfun/web/static/app.js` and the headless engine `hashfun/web/maker.cjs`; both built files and the fonts are committed, so running the site needs no Node).

| Piece | How it works |
|---|---|
| Keys | the page asks the wallet (UniSat: `requestAccounts`, `signMessage`) for one signature over a fixed message and derives its own key from it (`SHA256("hashfun-key-v1" \|\| signature)`), kept in the browser. That key holds launch coins (P2WPKH on every launch) and receives BTC yield (the same script on Bitcoin). The server never sees a key. What the page checks about the wallet before it asks for a payment: next section |
| Buy | atomic swap in the page: quote, HTLC built and checked in the browser, BTC paid into it with `sendBitcoin`, the maker locks coins on the launch chain, the page audits that contract (script, amount, confirmations, timelocks) and claims with the secret. Swap state is saved before any money moves; Bags can resume or, after the timelock, refund |
| Instant | `instant_max_sats` in the maker config: buys up to that size are filled on the unconfirmed Bitcoin lock. The maker carries the double-spend risk; larger buys wait for `btc_confs` |
| Sell | the page locks coins on the launch chain (it signs the P2WPKH spend), the maker locks BTC, the page claims it to the wallet address after one Bitcoin confirmation |
| Yield | Bags reads the Bitcoin outputs at the page key's script and sweeps them to the wallet address |
| Launch | the form posts name, ticker, curve size, BTC total, the creator's scripts and the optional picture and blurb (see Pictures and metadata); the server builds the descriptor, grinds genesis, starts the node (`--allow-launch`) |
| API | `/api/board`, `/api/coin/T`, `/api/coin/T/address/A`, `/api/chain/<btc\|T>/{time,txout,tx,spender,address}`, `/api/quote`, `/api/orders`, `/api/launch`, `/api/book/...`. Reads, broadcasts and signed messages between traders only |

`hashfun/tests/test_web_js.py` holds the browser's Bitcoin code to the Python byte for byte (addresses, HTLC scripts, signed redeem, refund and P2WPKH transactions). `hashfun/tests/web_regtest.py` drives the real site in Chromium against real nodes, pool, settler and maker; only the wallet is a stand-in (a mock `window.unisat` backed by a regtest wallet).

The maker quotes `hashes_per_coin x (hashprice + sats owed per hash) x (1 +/- spread)` and refuses a quote it cannot fill from its wallet. The node wallet treats curve coinbases that are not settled as immature, so they stay out of its balance and coin selection.

## The wallet (UniSat)

The page asks the wallet for three things: accounts, one signature (the page key), and payments. Every payment it requests (a buy from the house maker, a deposit to the page key, a taker's lock in the book) goes through one function, `pay` in `hashfun/web/src/app.js`, and that function checks the wallet first.

| Check | When | Rule |
|---|---|---|
| Network | at connect, and again before every payment | `getChain().enum` must be the site's Bitcoin network (`BITCOIN_MAINNET`, `BITCOIN_TESTNET`, `BITCOIN_TESTNET4`, `BITCOIN_SIGNET`). If it is not, the page asks the wallet to switch (`switchChain`) and refuses when it does not. UniSat also runs Fractal, whose addresses look exactly like Bitcoin's: a payment from there would fund a swap contract on a chain this site never reads. An older extension without `getChain` is held to `getNetwork` (livenet or not). A regtest site checks nothing: no real wallet runs there |
| Account | before every payment | `getAccounts()[0]` must still be the address the page connected with |
| Address | at connect | the wallet's address must parse as an address of the site's network |
| Change | any time | `accountsChanged` to another account, `networkChanged` or `chainChanged` reload the page: another account is another page key, and offers, swap records and spent outputs are stored per key, so one account never sees or moves another's swaps |

All of this was written against the extension's published source (`unisat-wallet/wallet`: method names, return shapes, chain enums, events), not against a running extension; the tests drive a stand-in `window.unisat`, which `web_regtest` also sets to Fractal to see the page refuse it. One more thing read there: the default `signMessage` is deterministic ECDSA (RFC 6979), so the same account signing the same fixed message derives the same page key in any browser. The key cached in a browser's storage is a convenience, not the only copy.

## Pictures and metadata

A launch can carry a picture (PNG, JPEG, GIF or WebP, at most 64 KB), a description (500 bytes) and three links. None of it is consensus data and the node never reads it. The descriptor commits to it with one field: `meta` = SHA256 of

    "hashfun-meta\x01" || vs(description) || vs(image_type) || vs(image) || vs(website) || vs(x) || vs(telegram)

`meta` is hashed into the launch id (appended to the canonical bytes when set, so a launch without metadata keeps the id it would always have had), and the genesis coinbase pushes the launch id. So the genesis block pins the picture: it cannot be changed after launch, by the creator or by a site showing it. The bytes ride in the launch file under `metadata` (every node needs that file to join the chain, so everyone on the chain has them); `hashfun/meta.py` `check()` verifies them against the hash, `hashfun node add` refuses a file where they differ, and the site only shows what verifies.

| Where | What |
|---|---|
| CLI | `hashfun launch new ... --image FILE --description TEXT --website URL --x URL --telegram URL` |
| Launch form | drop a picture: small files go in untouched (animations survive), larger ones are cropped to the middle and re-encoded in the browser to under 48 KB before anything is hashed. The page recomputes the hash and refuses the launch if the server committed to anything else |
| Site | `/api/coin/T/image` serves the committed bytes with the type the bytes themselves declare, cacheable forever; SVG is refused (it can carry script) |
| C++ | `LaunchDescriptor::meta` in `src/kernel/launch.{h,cpp}`; `test_diff_cpp` holds parser and id to the Python |

## The peer-to-peer book

`hashfun/book.py` (the board) and `hashfun/web/src/book.js` (a trader's engine, in the page or under node): holders trade with each other, any pair of chains the site follows (Bitcoin and every launch; they run the same script engine, so the same HTLC works on all of them). The server is a bulletin board and a mailbox. Orders, takes and every later message are short texts signed with the traders' keys; contracts are built, checked and funded by the two traders' own engines: the page in a browser tab, or the same code under node (`hashfun book`, next section).

    maker   posts an order     give 1,000 CAT, want 50,000 sats (any pair, either direction)
    taker   takes part of it   picks a secret, sends its hash and the timelock of its own lock
    maker   accepts            its engine reserves that part of the order
    taker   locks              HTLC on the chain the maker wants, to the maker's key, refund at T
    maker   locks              HTLC on the chain it gives, to the taker's key, refund at T - lock
    taker   claims             reveals the secret on the maker's chain
    maker   claims             uses the revealed secret on the taker's chain

| Rule | Why |
|---|---|
| Both contracts are fully determined by the signed take (keys, hash, timelocks) | each engine rebuilds the other side's contract itself and accepts only that exact script, amount and confirmation count |
| Taker locks first | a maker is never out of pocket for an order nobody completes |
| Only live, backed orders are listed, and only those can be taken | a maker must be online to lock its side: its engine sends a signed heartbeat, and it counts as live for 20 s after the last one. The board also checks what stands behind every order at the maker's key: spendable coins on a launch chain, confirmed sats on Bitcoin. The sats come from one UTXO-set scan for all bidders, on its own thread so that the board never waits for it: soon after a key the site has not seen posts a bid, otherwise at most every 5 minutes on a real network, and never less than a minute after the previous scan ended (a stream of bids from fresh keys cannot keep the Bitcoin node scanning). A new bid is accepted but neither listed nor takeable until a scan has seen its sats |
| An offer cannot promise the same coins twice | the engine refuses to post unless the key's spendable balance covers this offer plus what is left of its other open offers from the same chain, and the board applies the same sum: an order is backed only while the balance covers all of that maker's open orders giving that chain |
| The maker locks only for the exact lock the take defines, confirmed, with time to spare | a contract with another timelock, a short payment or a payment to another script is answered by locking nothing. The maker also declines when the taker's lock confirms so late that less than half of the maker's own lock would be left: the taker needs that time to claim |
| The taker claims only while `MTP + margin < maker locktime` | a claim confirming after the maker's refund would hand the maker both sides |
| Records before broadcasts | every swap is a stored record advanced one step at a time, written before the transaction it describes is broadcast: a reload or a closed tab loses nothing, and a lock whose other side stopped is refunded by the engine after its timelock. Records, offers and spent outputs are kept per key |
| Chains are named `btc:<net>` or by launch id in everything signed | no replay on another network or against another coin with the same ticker |
| One tab runs the engine (a Web Lock held for the tab's life), ticking every 2.5 s from a worker timer | two tabs answering the same take would lock twice; a second tab waits and takes over when the first closes. Browsers slow a hidden tab's own timers to as little as one a minute, which would take a maker off the board; a worker's timers are not slowed (the mechanism as browsers document it: no tab has been left hidden for hours under test). The page warns before it is closed while a lock of its own is out |

The numbers, as the code computes them (`lock` is `hashfun web --book-lock`, default 14400 s; confirmations are `--book-confs`, default 6):

| What | Value |
|---|---|
| Maker's lock | `lock`: 4 h. The board accepts orders asking between 10 min and 24 h |
| Taker's locktime | `max(now, MTP of the chain it pays on) + 2*lock + min(600, lock/2)`: 8 h 10 min from the take. The board refuses less than `now + 2*lock`; the maker's engine refuses anything outside `now + 2*lock` to `now + 3*lock + 600` |
| Maker's locktime | the taker's minus `lock`: 4 h 10 min from the take |
| Confirmations before the other side acts | 1 on a Bitcoin lock, 6 on a launch-chain lock |
| The maker locks only if | `maker locktime - now >= lock/2` once the taker's lock has its confirmations: 2 h |
| The taker claims only while | `MTP + margin < maker locktime`, with `margin = min(max(600 s, 6 blocks of that chain), lock/4)`: 10 min on a launch chain (blocks up to 100 s apart), 1 h on Bitcoin |
| Refund | by the owner's engine once the chain's MTP is past the lock's own locktime (MTP runs about 6 blocks behind the clock) |
| Handshake | a take the maker has not answered expires within 45 s. An accepted take must be locked within 120 s (300 s when the taker pays on Bitcoin); the maker frees the reservation 20 s after that |
| Sizes | both sides of an order and of every take at least 2,000 base units, and a lock must be worth at least 4 times its own claim fee at the current feerate |
| Pair guard | on a real network the engine refuses to post when `lock < 12 blocks of the chain it gives + 6 blocks of the chain it gets` (Bitcoin: 600 s a block): the taker may claim right up to the maker's timelock as that chain's MTP sees it, and the maker then still has to claim the other side |
| Board limits | 50 open orders per maker; an order lives at most 7 days (the page posts for 24 h) |

Sats offered by a maker are paid from its page key on Bitcoin (deposit from the wallet first: a page cannot ask the wallet to sign unattended); a taker paying sats in the page pays from the wallet, through the checks in The wallet (UniSat). The site proposes the numbers; each engine enforces its own. The house maker (`--maker`) is unchanged and remains the instant path for small buys.

API: `GET /api/book[?maker=PUB]` (with `maker`: that maker's own open orders, each with `backed`), `POST /api/book/{order,cancel,alive,take}`, `GET|POST /api/book/fill/ID`.

## Without a browser tab: `hashfun book`

The same engine hosted by node instead of a tab. `hashfun/web/src/maker.mjs` wraps `book.js` with a key in a file where the page has a wallet, a JSON file where the page has the browser's storage, and a loop where the page has a tab that must stay open. It talks to a hashfun site over HTTP exactly as the page does, so it needs no chain node of its own and works against anyone's site. It ships bundled as `hashfun/web/maker.cjs` (committed like the site's bundle; `test_web_js` fails when either is stale) and needs node 18 or newer; from npm the wrapper runs it directly, from a checkout `python3 -m hashfun.cli book` hands over to node.

```
hashfun book key                          # first run: create the key; prints where to send coins and sats
hashfun book balances
hashfun book post --give CAT --get btc --give-amount 1000 --get-amount 50000 [--hours 24]
hashfun book offers | cancel ID | swaps
hashfun book take ID [--pay AMOUNT]       # take someone's offer, paying from the key
hashfun book run                          # keep offers live: answer takes, lock, claim, refund
    --site URL             the hashfun site (default http://127.0.0.1:8080, or $HASHFUN_SITE)
    --dir DIR              the key and the swap records (default ~/.hashfun/book, or $HASHFUN_BOOK_DIR)
    --btc-payout ADDRESS   sats claimed or refunded go there instead of staying at the key
```

Amounts are sats for Bitcoin and whole coins (decimals allowed) for launch coins.

| Piece | How it works |
|---|---|
| Key | `key.json` in the directory, mode 600: a fresh random key (no wallet is involved), encrypted under a password (`$HASHFUN_BOOK_PASSWORD`, or asked for on the terminal) with the wallet file's construction: scrypt (N=2^15, r=8, p=1) into ChaCha20-Poly1305. `--no-encrypt` on first use stores it in the clear. That file is the only copy of the key |
| Funds | `key` prints the key's address on Bitcoin and on every launch the site follows. Everything the key holds is in play: the engine funds its locks from whatever is there, so fund it with what is meant to be traded |
| Offers | `post` signs and posts. An offer is listed only while `run` is up (the heartbeat), and a bid only once the site has seen its sats; `offers` marks one the site has not seen coins behind |
| `run` | one engine per key directory: `run.lock` holds the process id and the command (`run` or `take`), and a lock left by a dead process is taken over. About every 2.5 s it beats, answers takes on its offers and moves every swap one step: lock, claim, or refund once a timelock has passed. On Ctrl-C it first finishes any swap that has a lock out; a second Ctrl-C leaves anyway |
| `take` | the id may be a prefix. It pays what is left of the offer, or `--pay`, from the key, and stays until the swap is over: exit status 0 when done, 2 when it failed or was refunded |
| Restarts | the records live in `state.json`, written (temporary file, then rename) before the transaction they describe is broadcast. `run` picks every unfinished swap up where it stopped: a lock that was signed is broadcast again, a locked swap is claimed when the secret appears or refunded after its timelock, a take interrupted before anything was locked is dropped. Nothing is claimed or refunded while `run` is down: a maker whose lock has been claimed must be running again before the taker's own timelock, about `lock` (4 h) after that claim at the earliest, or the taker can take its payment back as well |
| Several commands, one directory | `state.json` is shared by every command run on the directory, also at the same time. A read goes to the file; a write takes a lock file, reads again and changes only what that command itself changed since it last read, so an offer posted or cancelled while `run` is up is seen by the running process at its next beat and nothing is written over. Driving swaps is exclusive: `run` and `take` both hold `run.lock`, and a second one on the same directory stops with "this key is busy" (two engines would lock coins for the same swap twice). To make and take at once, give the taker its own key directory |

## Wallet file

`hashfun wallet init` asks for a password (or reads `$HASHFUN_WALLET_PASSWORD`). The seed phrase, BIP39 passphrase and swap secrets are kept in a vault inside the wallet file: ChaCha20-Poly1305 (RFC 8439) under a key from scrypt (N=2^15, r=8, p=1). `hashfun wallet encrypt` sets or changes the password of an existing file; `--no-encrypt` is for throwaway wallets.

## npm

`contrib/hashfun/npm` is the `hashfun` npm package: a Node wrapper (`bin/hashfun.js`), the Python CLI (standard library only) with the built site and the bundled swap engine under `py/`, and the four node binaries under `prebuilt/<target>/`. The wrapper finds a usable Python and runs the CLI on it; `hashfun book` it runs itself, under node. `os` and `cpu` in `package.json` make npm refuse the install anywhere but macOS and Linux on x64 or arm64.

`cd contrib/hashfun/npm && npm pack` first runs `scripts/copy-py.js`, which copies the Python package, the site and the engine in and refuses to pack unless all four binaries are there (a package without one does not work on that platform) and each file's own header says it is what its directory claims: the right system and processor, and for Linux statically linked. `HASHFUN_PACK_PARTIAL=1 npm pack` packs whatever `dist/build.sh` has built on this machine, for this machine; such a tarball is never for publishing.

## CI and releases

`.github/workflows/hashfun.yml` runs on a push to `hashfun`, `main` or `master`, on a `v*` tag, and by hand. It only calls scripts that also run on a developer's machine.

| Job | Where | What |
|---|---|---|
| `build` | one runner per target: `ubuntu-24.04`, `ubuntu-24.04-arm`, `macos-15`, `macos-15-intel` | `ci/setup.sh`, then `dist/build.sh <target>` (zig on the Linux runners, Apple's clang on the macOS ones), then the whole regression (`ci/test.sh`) against that exact file. The binary, the logs and the short chain the regression's doctor step mined with it are kept; compiler caches (zig's own, ccache) shorten every run after the first |
| `pack` | Linux | collects the four binaries, rebuilds the site bundle and the swap engine and requires both to equal the committed ones, runs `npm pack` (which refuses an incomplete set) and writes `SHA256SUMS` |
| `install` | the same four runners | `ci/setup.sh --minimal` (a Python and the pinned bitcoind, nothing to build with), then `npm i -g` the tarball. `hashfun doctor` must show that the CLI took the packaged binary of that platform by itself, and pass its self-test; then that node replays the chains all four build jobs mined (`hashfun doctor --replay`) and must agree with each on every block, the UTXO set, the curve state and the sats owed; then `cli_smoke.sh` runs through the installed command |
| `release` | Linux, only for a tag | the tag must be `v` plus the package's version. A GitHub release gets the tarball, the four binaries and their SHA256 sums. `npm publish` follows only if the repository has a secret named `NPM_TOKEN` (`gh secret set NPM_TOKEN < file-with-the-token`); without one the job ends at the release page. Both steps can be run again |

Run by hand with `core_tests` on, the build jobs also build and run Bitcoin Core's own unit tests with the shipping toolchain. On a private repository the macOS jobs are most of the bill (a macOS minute counts as about ten Linux minutes); on a public one the runners are free.

What has never run: this workflow (it needs a repository), anything on macOS (the native build, the macOS binaries, the suites on a Mac), and Bitcoin Core's own unit tests on this fork.

## Swaps

HTLC (P2WSH): `IF SIZE 32 EQUALVERIFY SHA256 <H> EQUALVERIFY <recipient> ELSE <locktime> CLTV DROP <refund> ENDIF CHECKSIG`. The size check pins the secret to 32 bytes on both chains.

Maker rules: quote `= hashes_per_coin x (hashprice + sats owed per hash) x (1 +/- spread)` (the curve is the fair-value anchor); quotes carry an id and a TTL so price movement between quote and lock cannot strand the taker; order size capped at the cost of renting enough hash to reorg `fork_confs` blocks; participates only after `btc_confs`/`fork_confs` on the initiator lock and only if the initiator's lock outlives its own by a margin; redeems as soon as the secret appears; refunds after its locktime.

Taker rules (wallet): reveals the secret only after `N` confirmations on the maker's lock, only while `now + margin < maker_locktime` (otherwise the maker could refund and still claim with the revealed secret), refunds at its own locktime.

## Tests

The regression is one command:

```
bash contrib/hashfun/ci/test.sh [--hashfund PATH] [--bitcoind PATH] [--logs DIR] [suite ...]
```

One line per suite on the terminal (PASS or FAIL, seconds, the suite's own last line), one log per suite (`build/test-logs/` unless `--logs`), exit status nonzero if any suite failed. `hashfund` is `--hashfund`, else `$HASHFUND`, else the one the CLI itself picks on this machine; `bitcoind` (a stock Bitcoin Core, for the Bitcoin side) is `--bitcoind`, else `$BITCOIND`, else the one on `PATH`. A suite whose tools are missing is skipped and says why; with `CI` set a skip counts as a failure.

| Suite | What it runs | Needs |
|---|---|---|
| `unit` | `test_core`, `test_yieldstate`, `test_stack`, `test_book`, `test_cli` | Python |
| `diff` | builds the differential driver and runs `test_diff_cpp`. When `dist/build.sh` has left its compiler in `build/dist/tc`, the driver is compiled with that one, so the arithmetic under test is the shipped binary's (`CXX` overrides) | a C++ compiler |
| `web_js` | `test_web_js` | node, npm |
| `doctor` | `hashfun doctor` on the binary under test; it also mines the short chain for the cross-machine check into the log directory (`chain-<target>.json`) | the binary |
| `core` | Bitcoin Core's own unit tests, one process per test suite, in parallel | a `TESTS=1` build; passed over, not failed, without one |
| `e2e`, `fleet` | `e2e_regtest`, `fleet_regtest` | bitcoind |
| `yield` | `yield_regtest`: the sats leg on a real node against the Python model of its rules, at every height after every block, restart and reorg | bitcoind |
| `book` | `book_regtest` | bitcoind, node |
| `web` | `web_regtest`, screenshots into the log directory | bitcoind, Python's playwright with its chromium |
| `smoke` | `contrib/hashfun/cli_smoke.sh` | bitcoind |

`contrib/hashfun/ci/setup.sh` prepares a CI or throwaway machine for all of it (it installs system packages): build tools and Boost headers, a virtualenv with zig and playwright, the site's npm packages, and the official `bitcoind` of Bitcoin Core 32.1, pinned by the hash bitcoincore.org publishes for it.

The suites one by one:

```
python -m unittest hashfun.tests.test_core      # vectors (BIP32/39/143/173), curve, LWMA, descriptor, HTLC, AuxPoW
python -m unittest hashfun.tests.test_yieldstate  # the sats-leg state machine as a model: draws over live coins, held coinbases, one tag list, undo, the end of the leg
python -m unittest hashfun.tests.test_stack     # pool+miner, merged mining gate, proxy split, electrum+wallet+reorg, swaps buy/sell/refund (simulator)
python -m unittest hashfun.tests.test_book      # launch metadata; the peer-to-peer book's server side (signatures, reservations, backing, expiry)
python -m unittest hashfun.tests.test_cli       # which node binary the CLI runs on which machine (the npm layout with stand-in binaries, $HASHFUND, the translated-Python case)
bash contrib/hashfun/difftest/build.sh build/hfdiff && HFDIFF=build/hfdiff python -m unittest hashfun.tests.test_diff_cpp
python -m hashfun.tests.e2e_regtest --hashfund build/bin/hashfund --bitcoind /path/to/stock/bitcoind
python -m hashfun.tests.yield_regtest --hashfund build/bin/hashfund --bitcoind /path/to/stock/bitcoind   # ~30 s: node vs model, 270 blocks, every obligation at every height
python -m hashfun.tests.fleet_regtest --hashfund build/bin/hashfund --bitcoind /path/to/stock/bitcoind   # ~4.5 min, real time
python -m unittest hashfun.tests.test_web_js    # browser code vs Python, the site bundle and the swap engine bundle are current, lint (needs node; cd hashfun/web && npm install)
python -m hashfun.tests.web_regtest --hashfund build/bin/hashfund --bitcoind /path/to/stock/bitcoind     # ~9 min, two browsers, needs playwright
python -m hashfun.tests.book_regtest --hashfund build/bin/hashfund --bitcoind /path/to/stock/bitcoind    # the swap engine on its shipped timelocks, clock moved by the test; needs node
```

`test_stack` runs against an in-process simulator whose consensus is the Python model, not the C++ node. `test_diff_cpp` compiles the node's own consensus sources (descriptor parser and identity, `CLaunchParams` + genesis, curve, LWMA, tail) without the rest of the node, in ~20 s, and compares them value by value with the Python model on random descriptors and adversarial header sequences (zero, negative and >6T solvetimes, off-schedule nBits, graduation crossings); it also requires both parsers to accept and reject exactly the same descriptor JSON. `e2e_regtest` covers what needs a running node: block acceptance (creator output, excess coinbase, nBits), the auxpow gate, GBT, merged mining against stock bitcoind and a swap over real nodes. With `--workdir` its phases can run in separate processes (`--phases 1-6`, `7-8`, `9`). `fleet_regtest` is the multi-node test: production-mode launches, P2P on localhost, real time; gating, state agreement (tip, UTXO set, Bitcoin relay, every obligation) across nodes, late joiner, restarts, partitions and reorgs in both directions including a forged Bitcoin header branch, two competing pools, AuxPoW blocks over P2P, the settlement lock in the mempool, transaction relay, `verifychain`, stall relief against the wall clock.

`hashfun/yieldstate.py` is the sats-leg state machine written again from the rules, not from the node's code: the coin list, held coinbases, the draw over live coins, one tag list per payment, the settlement deadline, undo, the end of the leg. `test_yieldstate` exercises it alone. `yield_regtest` runs a real node and a regtest bitcoind through a scripted chain (the first blocks with nobody holding, five kinds of proof that must be ignored, a Bitcoin reorg, redirects, 60 self-transfers, a competing branch, the deadline, graduation, merge-mined blocks, the end of the leg) and compares `getmintobligation` at every height, `getlaunchinfo.earning` and the Bitcoin relay with the model after every block, after each of four restarts and after every reorg: 274 blocks, about 36,000 obligation comparisons, the first difference stops the run. The review's critical findings each have a named check there (C1: a restarted node against a live one; C2: one Bitcoin output with two tag lists; C3: self-transfers and the UTXO set against the live coins).

`book_regtest` is the timelock test. `web_regtest` runs the swap engine in browsers on locks of 40 s to 4 min because it cannot wait hours; here the same engine (`book.js`, hosted by node through `tests/enginehost.mjs`) runs on the shipped numbers against a stock bitcoind and a hashfund test launch, with one clock for both nodes, the board and both traders, moved by the test. Every transaction goes through the nodes, so a refund tried before its timelock is refused by consensus, not by the engine. H1 drives `hashfun book` itself on the real clock (encrypted key file, post, run, take). S1 and S6 are the two directions done honestly: both contracts must carry exactly the timelocks and confirmation counts of the table in The peer-to-peer book. S2 to S5 are the stops (maker gone after the taker locked, taker gone after the maker locked, taker arriving too close to the maker's refund, taker's lock confirming too late): each lock goes back to its owner when its timelock says and not before, and nobody is out more than fees. S7 and S8 are dishonest counterparties: a taker's contract with a shorter timelock, an underfunded lock, a lock on another script; a maker's contract that refunds early or is short. The honest engine locks for none of the first, claims none of the second, and takes its own lock back.

## Files changed in the node

`src/kernel/launch.{h,cpp}` (descriptor), `src/launchcurve.{h,cpp}` (curve), `src/launchyield.{h,cpp}` + `src/launchyieldstate.{h,cpp}` (sats leg), `src/kernel/chainparams.cpp` (`CLaunchParams`, genesis), `src/pow.cpp` (LWMA), `src/validation.cpp` (subsidy, creator fee, auxpow gate, FTL), `src/node/miner.cpp` (template subsidy + creator output), `src/rpc/mining.cpp` (GBT `creatorfee`, genesis IBD exception), `src/rpc/blockchain.cpp` (`getlaunchinfo`, `getblockstats`), `src/rpc/auxpow_miner.cpp` (graduation gate), `src/index/coinstatsindex.cpp`, chain-type plumbing (`-launch`), `src/init.cpp` (BTC-chain guard), branding (datadir, conf, binary names).
