# hashfun: status, 2026-11-11

24 commits on `namecoin-core@70c6b36` (branch `auxpow`: Bitcoin Core 32.99 + AuxPoW). Everything below ran on Linux x86_64 (GCC 13.3) with `hashfund` built from this tree and **stock Bitcoin Core v32.1** built from its release tag as the Bitcoin side.

## What passes

| Suite | Result | What it is |
|---|---|---|
| `test_core` + `test_stack` | 41 tests | vectors, curve, LWMA, descriptor, HTLC, AuxPoW, wallet vault; pool, proxy, electrum, swaps on the simulator |
| `test_diff_cpp` | 12 suites | the node's own consensus sources against the Python model, value by value; now includes 2,017 mainnet-rule headers **produced by Bitcoin Core itself** (retarget at 2016) |
| `test_web_js` | 8 tests | the browser's Bitcoin code against the Python, byte for byte (addresses, HTLC scripts, signed redeem / refund / P2WPKH transactions) |
| `e2e_regtest` | 58/58, 30 s | single-node consensus, merged mining against stock bitcoind, swaps, sats leg |
| `fleet_regtest` | **41/41, 4.5 min** | 4 nodes + 2 competing pools + 2 Bitcoin wallets, production-mode launches, real time |
| `web_regtest` | **24/24, 5 min** | the real site in Chromium against real nodes, pool, settler and maker |
| `cli_smoke.sh` | pass | `hashfun launch / node / mine / web` end to end through the CLI |

Logs are in `logs/`, screenshots of the running site in `screenshots/`.

### fleet_regtest covers

gating (old tip is not IBD, no peers means no templates unless `-minewithoutpeers`, no mock clock, no pruning); P2P sync; identical tip, UTXO set, Bitcoin relay and every obligation on every node; late joiner from genesis; restart mid-run and restart with no new blocks; an isolated node that followed a forged Bitcoin header branch reorgs back and forgets it; the pool's own node loses a race to a second pool and its settler pays nothing for the orphaned blocks; a graduated launch merge-mined by another launch's pool, AuxPoW blocks over P2P, late joiner on the mixed chain; unsettled coinbase rejected by every mempool and kept out of wallet coin selection; a settled one relays and confirms everywhere; `verifychain`; two pools settle everything they mined with no wasted payment; stall relief against the wall clock for `getblocktemplate` and `createauxblock`.

### web_regtest covers

board follows the chain; connect derives the page key from one wallet signature; coin page shows blocks and settled payouts; **the launch form creates a production-mode chain** with the creator's scripts from the page; **buy in the browser** filled on the unconfirmed Bitcoin lock (instant), and a larger one after a confirmation; the wallet paid a swap contract, not the site; bag and odds on the page; **a later block's draw paid the buyer's key on Bitcoin**, Bags shows it, sweep moves it to the wallet address; **sell in the browser**, BTC lands at the wallet address; phone layout; the maker redeemed its side of every swap; no JavaScript errors.

The only stand-in is the wallet: a mock `window.unisat` (same four calls the page uses: `requestAccounts`, `getAccounts`, `signMessage`, `sendBitcoin`) backed by a regtest wallet. The real UniSat extension has not been run against the site.

## Bugs the new tests found (all fixed)

1. **A stalled chain could not restart.** `getblocktemplate` and `createauxblock` cached a template across a stall-relief step: the template's time moved on, its nBits did not (`bad-diffbits`), and a cached aux block never got easier. Any gap longer than 6 block times broke every miner using the RPCs until something else invalidated the cache.
2. `target_spacing = 1` was accepted, and at 1 s difficulty can never rise (whole-second timestamps, 1 s minimum solvetime). Now `>= 2`.
3. The node wallet counted unsettled coinbases as spendable and picked them, so sends failed at random with `bad-txns-unsettled-coinbase`. They are immature until settled now.
4. Settler: paid a block the moment its draw was known (a 1-block reorg could burn the payment), forgot a settlement whose proof block was reorged out, and could pay twice after a crash between signing and saving. Now pays at depth 12, saves the signed payment before broadcasting, republishes proofs, detects a draw changed by a reorg.
5. Maker: quotes ignored the sats each minted coin owes (it would have sold below cost), quoted more than it held, accepted zero-size orders.
6. `hashfun launch new --help` crashed (unescaped `%`).
7. Mainnet launches got a 1-hour settlement deadline, too tight for 10-minute Bitcoin blocks (about 1 in 400 coinbases would have been lost to a slow block alone). Launch tooling now sets one day.

## New in this drop

- `hashfun web`: the site (board, coin page, launch form, Bags) + JSON API. Swaps are built, checked and signed in the browser; the server only reads chains and broadcasts.
- `instant_max_sats` in the maker config: small buys filled on the unconfirmed Bitcoin lock.
- Wallet seed encrypted at rest (ChaCha20-Poly1305 under scrypt); `hashfun wallet init` asks for a password.
- `hashfun node add --peer`, `node up --first`, `mine --pay-depth`.
- `contrib/hashfun/npm`: the `hashfun` npm package (the name is free on npm today). `npm i -g ./hashfun-0.1.0.tgz` works; `cd contrib/hashfun/npm && npm publish` publishes it.
- `make_repo.sh` + `patches/`: rebuilds the repository from upstream and pushes it.

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

Keep it small. Everything here is the tested path except the two things marked untested.

1. Bitcoin Core, synced (pruned is fine), with a wallet holding a little BTC for the miner: `bitcoin-cli createwallet miner`. Each curve block pays at least 10,000 sats or nothing, so 0.002 BTC covers a tiny curve.
2. `hashfun web --btc-rpc http://user:pass@127.0.0.1:8332 --allow-launch` and open http://127.0.0.1:8080. Connect UniSat (**untested: the real extension**; the page uses only the four calls above). Launch form: preset **CPU test**, **0.001 BTC**. The chain starts; the creator scripts are your page key and your UniSat address.
3. Mine it: `hashfun node rpc TICKER createwallet w`, `hashfun node rpc TICKER getnewaddress "" bech32`, then
   `hashfun mine TICKER --payout <that address> --btc-rpc http://user:pass@127.0.0.1:8332 --btc-wallet miner --max-pay-btc 0.0002`.
   The settler pays each drawn payee from `miner` once the block is 12 deep, waits for one Bitcoin confirmation, publishes the proof. `--max-pay-btc` caps any single payment.
4. To trade in the browser, run a maker: restart the site with `--maker maker.json`:
   `{"btc": {"wallet": "miner", "hrp": "bc"}, "defaults": {"hashprice_sats_per_th": <your number>, "spread": 0.03, "btc_confs": 1, "fork_confs": 6, "init_lock_seconds": 43200, "part_lock_seconds": 14400, "lock_margin_seconds": 7200, "instant_max_sats": 20000, "safety": 0.5}}`.
   It sells coins the miner wallet holds (matured, settled) and buys with its BTC. Its order cap is the cost of renting enough hash to reorg `fork_confs` blocks, which on a CPU-sized chain at a real hash price is about zero (rightly: such a chain is cheap to reorg). For a test on a CPU chain set `"safety": 1e9` and keep orders small.
5. Second machine: `hashfun node add ticker.json --peer <first host>:<p2p port> && hashfun node up TICKER`.

What that run exercises for the first time: **real Bitcoin headers through the relay** (the retarget rule is tested against Core-produced headers and the first historical retarget, not against the live chain), **mainnet fees and 10-minute confirmations**, and **UniSat itself**. Bags reads payouts with `scantxoutset`, about a minute per lookup on mainnet.

## Not done

- Lightning exits. Exits are on-chain atomic swaps: instant only for small buys the maker fronts, one Bitcoin confirmation otherwise.
- A hosted fleet (seed nodes, a public site). The site and the nodes run wherever you start them.
- The page key lives in the browser's localStorage, like any web wallet. Bags can back it up; a compromised page could take it.
- macOS native build of `hashfund` has not been tried here (built and tested on Linux).
- No external review of the consensus changes.
