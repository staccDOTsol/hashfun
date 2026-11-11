# hashfun: status, 2026-11-11 (second drop)

27 commits on `namecoin-core@70c6b36` (branch `auxpow`: Bitcoin Core 32.99 + AuxPoW). Everything below ran on Linux x86_64 (GCC 13.3) with `hashfund` built from this tree and **stock Bitcoin Core v32.1** built from its release tag as the Bitcoin side.

New since the first drop: **pictures** (a launch's picture, blurb and links, pinned by its genesis block) and the **peer-to-peer book** (any coin for sats, any coin for any other coin, browser to browser, no house maker).

## What passes

| Suite | Result | What it is |
|---|---|---|
| `test_core` + `test_stack` + `test_book` | 55 tests | vectors, curve, LWMA, descriptor, HTLC, AuxPoW, wallet vault; pool, proxy, electrum, swaps on the simulator; launch metadata; the order book's server side |
| `test_diff_cpp` | 12 suites | the node's own consensus sources against the Python model, value by value; includes the new `meta` field and 2,017 mainnet-rule headers produced by Bitcoin Core itself |
| `test_web_js` | 13 tests | the browser's code against the Python, byte for byte: addresses, HTLC scripts, signed transactions, the metadata hash, signed order texts (the page signs and Python verifies, and the reverse); that the committed bundle is the build of the sources; lint |
| `e2e_regtest` | 58/58, 30 s | single-node consensus, merged mining against stock bitcoind, swaps, sats leg |
| `fleet_regtest` | 41/41, 4.5 min | 4 nodes + 2 competing pools + 2 Bitcoin wallets, production-mode launches, real time |
| `web_regtest` | **42/42, 8 min** | the real site in **two** Chromium browsers against real nodes, two mined chains, pools, settlers and the house maker |
| `cli_smoke.sh` | pass | `hashfun launch / node / mine / web` end to end through the CLI, now with a picture |

Logs are in `logs/`, screenshots of the running site in `screenshots/` (`swap.png`, `book.png`, `swapped.png` and `launch.png` are new).

## Pictures: how a coin gets one

Not base64 in a block. The descriptor has one new consensus field, `meta`: SHA256 of the launch's metadata (picture up to 64 KB, description, three links). It is hashed into the launch id and the genesis coinbase pushes the launch id, so **the genesis block pins the picture**: nobody can swap it after launch, the creator and any site included. The bytes ride in the launch file next to the descriptor. Every node needs that file to join the chain, so everyone on the chain has them, and anyone can check them against the hash. A launch without metadata hashes exactly as before.

- `hashfun launch new ... --image FILE --description TEXT --x URL --telegram URL --website URL`
- The launch form: drop a picture. Small files go in untouched (animations survive); bigger ones are cropped square and re-encoded in the browser to under 48 KB. The page recomputes the hash and refuses the launch if the server committed to anything else.
- The site shows only bytes that match the hash, serves them with the type the bytes themselves declare, and refuses SVG (it can carry script). `hashfun node add` refuses a launch file whose picture is not the committed one.

Tested: C++ and Python agree on parsing and on the id with and without `meta` (`test_diff_cpp`); JS and Python agree on the hash (`test_web_js`); in the browser test the first launch's committed picture is served byte for byte and shown on the board and coin page, and the form takes a 900 KB noise PNG, shrinks it to 38 KB, and the new chain's launch id commits to exactly that.

## The peer-to-peer book

Every launch is a Bitcoin fork with the same script engine, so the HTLC used for coin/BTC works between any two of them unchanged. Anyone posts a signed offer from the page (give X, want Y, any pair of sats and launch coins, either direction); anyone takes all or part of it. The site is a bulletin board and a mailbox: it never holds a key or a coin.

1. **Take**: the taker picks an offer; the maker's page answers in seconds and reserves that part.
2. **Taker locks** on the chain the maker wants (sats from UniSat, coins from the hashfun key).
3. **Maker's page locks** the other side by itself once the taker's lock has its confirmations.
4. **Taker claims**, which reveals the secret; **the maker's page claims** with it.

Either lock goes back to its owner after its timelock if the other side stops; the page does that by itself. Offers are live while the maker has the site open in a tab (a maker must be online to lock its side); the board lists only makers it has heard from in the last 20 seconds, and only offers backed by coins it can see at the maker's key. Where to find it: **Swap** in the nav (any pair, take or post), and the **Book** tab on every coin page (that coin against sats).

`web_regtest` P1 to P4, all in real browsers with no house maker involved:

| | What happened |
|---|---|
| P1 | holder A offers 40% of its bag for 60,000 sats; holder B (second browser) finds it on the Book tab and takes half. B's wallet pays 30,000 sats into a contract; A's page locks the coins; B claims; A's page claims the sats to its wallet. 7 to 23 s over three runs. The other half of the offer stays up |
| P2 | coin for coin: B offers 5 of a second chain's coin for 3 of the first; A takes. No Bitcoin moves. 10 to 11 s |
| P3 | a bid in sats: B deposits sats to its hashfun key and bids for coins; A takes it with coins and is paid on Bitcoin. The page refuses to offer the same sats twice |
| P4 | B's browser is closed right after A locked. A's page takes its coins back by itself after the timelock (lock 40 s for the test, refund about 2 minutes after the take): only fees are gone |

Those times are with 2-second blocks on both chains. On real chains a swap takes the confirmations it waits for: 1 on Bitcoin, 6 on a launch chain by default (`--book-confs`), one after the other.

## Bugs found this round (all fixed)

1. **The page could lose track of a lock the wallet had just sent.** It looked the payment up by transaction id, which only works while the transaction is unconfirmed unless the Bitcoin node keeps a transaction index (most do not). If a block arrived first, a buy stalled until refund. The page now probes the outputs directly. This was in the first drop's buy flow too. The fix is exercised by the browser test only when a block happens to arrive in that window; there is no test that forces it.
2. JS and Python disagreed on whether a 12-byte WebP header is a WebP (the parity test caught it before any run).
3. Sats at the hashfun key were read through a one-minute cache, so a fresh deposit could not back an offer for up to a minute; and the page let the same sats be offered twice. Both fixed; P3 checks the second.
4. Two of my own slips, both caught before this drop and both now guarded. The first browser run of this round served a bundle built before two engine fixes: it passed, but it was not testing the sources. And the fix for 3 introduced a name used before its declaration in the offer form, which no unit test reaches: the next full browser run failed on it (nobody could post an offer). `test_web_js` now fails when `static/app.js` is not the build of `src/` and lints the sources for that class of error. The numbers above are from the run after both.

## From the first drop (unchanged, still passing)

**fleet_regtest covers** gating (old tip is not IBD, no peers means no templates unless `-minewithoutpeers`, no mock clock, no pruning); P2P sync; identical tip, UTXO set, Bitcoin relay and every obligation on every node; late joiner from genesis; restart mid-run and restart with no new blocks; an isolated node that followed a forged Bitcoin header branch reorgs back and forgets it; the pool's own node loses a race to a second pool and its settler pays nothing for the orphaned blocks; a graduated launch merge-mined by another launch's pool, AuxPoW blocks over P2P, late joiner on the mixed chain; unsettled coinbase rejected by every mempool and kept out of wallet coin selection; a settled one relays and confirms everywhere; `verifychain`; two pools settle everything they mined with no wasted payment; stall relief against the wall clock for `getblocktemplate` and `createauxblock`.

**web_regtest W1 to W9 cover** the board following the chain; connect deriving the page key from one wallet signature; the coin page showing blocks and settled payouts; the launch form creating a production-mode chain with the creator's scripts from the page; a buy filled on the unconfirmed Bitcoin lock (instant) and a larger one after a confirmation; the wallet paying a swap contract, not the site; bag and odds; a later block's draw paying the buyer's key on Bitcoin, Bags showing it, sweep moving it to the wallet address; a sell with BTC landing at the wallet address; phone layout; the house maker redeeming its side of every swap; no JavaScript errors in either browser.

The only stand-in is the wallet: a mock `window.unisat` (the four calls the page uses) backed by a regtest wallet. The real UniSat extension has not been run against the site.

Bugs the first drop's tests found, all fixed then: a stalled chain could not restart (`getblocktemplate` / `createauxblock` cached a template across a stall-relief step); `target_spacing = 1` accepted though difficulty could never rise; the node wallet spending unsettled coinbases; the settler paying one block deep, forgetting reorged proofs and able to pay twice after a crash; the maker quoting below cost, beyond its inventory and at zero size; `launch new --help` crashing; a 1-hour settlement deadline on mainnet launches; a Buy click during a quote refresh starting a swap with no quote.

## Make the repo

```
bash make_repo.sh                        # clone namecoin-core at the pinned commit, apply patches/ -> ./hashfun-core
PUSH=<you>/hashfun-core bash make_repo.sh    # same, then gh repo create (private) and push
```

## Run it locally (regtest)

```
cmake -B build -DBUILD_TESTS=OFF -DBUILD_BENCH=OFF -DBUILD_GUI=OFF -DENABLE_IPC=OFF && cmake --build build -j4 --target bitcoind bitcoin-cli
export HASHFUND=$PWD/build/bin/hashfund
python3 -m hashfun.tests.fleet_regtest --hashfund $HASHFUND --bitcoind /path/to/bitcoind
pip install playwright && playwright install chromium
python3 -m hashfun.tests.web_regtest   --hashfund $HASHFUND --bitcoind /path/to/bitcoind --shots shots/
```

## First run with real BTC

Keep it small. Everything here is the tested path except the things marked untested.

1. Bitcoin Core, synced (pruned is fine, no transaction index needed), with a wallet holding a little BTC for the miner: `bitcoin-cli createwallet miner`. Each curve block pays at least 10,000 sats or nothing, so 0.002 BTC covers a tiny curve.
2. `hashfun web --btc-rpc http://user:pass@127.0.0.1:8332 --allow-launch` and open http://127.0.0.1:8080. Connect UniSat (**untested: the real extension**; the page uses four calls: `requestAccounts`, `getAccounts`, `signMessage`, `sendBitcoin`). Launch form: drop a picture, preset **CPU test**, **0.001 BTC**. The chain starts; the creator scripts are your page key and your UniSat address.
3. Mine it: `hashfun node rpc TICKER createwallet w`, `hashfun node rpc TICKER getnewaddress "" bech32`, then
   `hashfun mine TICKER --payout <that address> --btc-rpc http://user:pass@127.0.0.1:8332 --btc-wallet miner --max-pay-btc 0.0002`.
   The settler pays each drawn payee from `miner` once the block is 12 deep, waits for one Bitcoin confirmation, publishes the proof. `--max-pay-btc` caps any single payment.
4. Trade peer to peer: open the site in a second browser profile with another UniSat account. In one, **Swap**, post an offer; in the other, take it. Keep the maker's tab open until it says done. Sats you offer as a maker come from your hashfun key: use **Deposit from UniSat** first and wait for one confirmation.
5. For instant small buys, run the house maker: restart the site with `--maker maker.json`:
   `{"btc": {"wallet": "miner", "hrp": "bc"}, "defaults": {"hashprice_sats_per_th": <your number>, "spread": 0.03, "btc_confs": 1, "fork_confs": 6, "init_lock_seconds": 43200, "part_lock_seconds": 14400, "lock_margin_seconds": 7200, "instant_max_sats": 20000, "safety": 0.5}}`.
   Its order cap is the cost of renting enough hash to reorg `fork_confs` blocks, which on a CPU-sized chain at a real hash price is about zero (rightly: such a chain is cheap to reorg). For a test on a CPU chain set `"safety": 1e9` and keep orders small.
6. Second machine: `hashfun node add ticker.json --peer <first host>:<p2p port> && hashfun node up TICKER`. The picture travels inside `ticker.json`.

What that run exercises for the first time: **real Bitcoin headers through the relay** (the retarget rule is tested against Core-produced headers and the first historical retarget, not against the live chain), **mainnet fees and 10-minute confirmations**, **4-hour and 8-hour swap timelocks** (tests use 40 s to 4 min), and **UniSat itself**. Reading sats at a hashfun key uses `scantxoutset`: about a minute per lookup on mainnet, cached for two minutes.

## Not done

- A maker has to keep a tab open until its swaps are done (the page warns before closing mid-swap). A background tab should do: the engine's clock runs in a worker, which browsers do not slow down in hidden tabs, and the page holds a Web Lock, which keeps it from being frozen. **Not tested with a really hidden tab**, and a browser can still discard a tab under memory pressure. There is no headless peer-to-peer maker yet (the CLI's house maker is a different bot trading from a node wallet).
- The board cannot cheaply check the sats behind a bid (it would need a UTXO-set scan per offer), so a bid can be listed without sats behind it. A taker who locks coins for such a bid gets them back after the timelock and loses only time and fees. Coin offers are checked.
- One site, one book. Two sites do not share offers.
- A cheap chain is cheap to reorg: 6 confirmations on a CPU-mined coin protect nothing against someone renting a rig. The page shows the confirmation count; it does not price the risk the way the house maker's cap does.
- Lightning exits. All exits are on-chain atomic swaps.
- A hosted fleet (seed nodes, a public site). The site and the nodes run wherever you start them.
- The page key lives in the browser's localStorage, like any web wallet. Bags can back it up; a compromised page could take it. The page also trusts the site's view of the chains: run your own.
- macOS native build of `hashfund` has not been tried here (built and tested on Linux).
- No external review of the consensus changes.
