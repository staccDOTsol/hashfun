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
| BTC anchor | optional `btc_anchor_height` / `btc_anchor_hash` in the descriptor, hashed into the launch id: no block of the launch can predate that Bitcoin block |
| FTL | per-descriptor future time limit (default 60 s with the 5 s / N=90 defaults) |
| Genesis | coinbase `scriptSig = PUSH32(launch_id)`, one zero-value `OP_RETURN` output, `nVersion=1`, must meet `pow_limit_bits` |

Sniping does nothing: a low-difficulty block pays exactly its work at the curve price. Merge-mining pools cannot touch presale issuance because auxpow is invalid until graduation; after it, exahash secures the tail.

All arithmetic is 256-bit integer. Validation bounds (`V0 <= 2^160`, `G <= 99.9% T0`, `T0 <= MAX_MONEY`) keep every product below 2^256.

## One command

```
pip install .                                   # provides `hashfun`; HASHFUND=/path/to/hashfund or hashfund on PATH
hashfun launch new --name "My Coin" --ticker MYC --creator-address myc1... -o myc.json \
        --btc-rpc URL --sats-total 0.7 --creator-btc-address bc1...        # Bitcoin anchor + sats leg (required)
hashfun node add myc.json && hashfun node up    # one hashfund per registered launch, state in ~/.hashfun
hashfun node ls                                 # height, curve %, graduated, peers
hashfun mine MYC --payout myc1... --btc-rpc URL --btc-wallet NAME     # pool + CPU miner (or --no-cpu for ASICs)
hashfun wallet yield | claim-yield              # BTC earned by holding, paid at your launch keys on Bitcoin
hashfun wallet buy|sell ..., hashfun swap ..., hashfun electrum ..., hashfun board ...
```

`hashfun mine` merge-mines every other registered launch that has graduated and runs the settler (relay Bitcoin headers, pay the drawn payee, publish the proof). `contrib/hashfun/cli_smoke.sh` drives all of this against real binaries.

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
| Draw | the hash of block `h+6` seeds block `h`'s draw. Debts under `sats_min_payment` pay the minimum with probability owed/min. Payee class: 80% holder, 10% creator (`creator_btc_script`), 10% dev (compiled-in script, `bc1pctxxt9z57ypwrvdws45hgpgkx922e39gj3hkqe0hsgv3863f4ffsu7p7x3`) |
| Holder | hold and you earn, no opt-in. 64 candidate points into the value of every P2PKH / P2SH / witness-program output created before block `h`; the payee is the first candidate still unspent (coin-weighted over current holders), paid at that output's own scriptPubKey on Bitcoin (same key, since a launch is a Bitcoin fork). All spent or none yet: creator |
| Redirect | optional: a tx with `OP_RETURN "HFY1"<btc scriptPubKey>` sends its outputs' yield to that script instead (coinbase: vout 0 only) |
| Pay | a Bitcoin tx whose output `i` pays the payee and whose `OP_RETURN "HF"<20-byte tags>` has `SHA256("hashfun-pay"||launch_id||block_hash)[:20]` at position `i` |
| Bitcoin view | `OP_RETURN "HFH1"<80-byte headers>` relays Bitcoin headers; the node keeps a validating header tree from `btc_anchor_header` (PoW, retarget, median time), so its view of Bitcoin is a function of launch blocks only |
| Prove | `OP_RETURN "HFP1"<proof>`: merkle proof of the payment in a relayed Bitcoin block with `btc_confs` confirmations. Invalid proofs and headers are ignored, never block-invalidating |
| Lock | a curve coinbase cannot be spent until settled (`bad-txns-unsettled-coinbase`, mempool and consensus); unsettled `settle_deadline` blocks after minting, it never can |

`settle_deadline` defaults to 720 blocks in the descriptor format; `hashfun launch new` and the launch form set it to one day of blocks when the sats leg follows real Bitcoin, where a confirmation can take an hour.

HFH1/HFP1/HFY1 outputs are honoured in coinbases too, so a miner with no spendable coins can relay headers and settle from its own next block. RPCs: `getmintobligation <height>` (owed, payee, tag, candidates, script to pay), `getbtcrelay`. State lives in memory (`src/launchyieldstate.cpp`) and is rebuilt from blocks; pruned nodes are not supported with a sats leg.

## Descriptor

JSON. The launch id is `SHA256d` of a canonical binary serialization of every consensus field (everything except `genesis_nonce`, ports and seeds):

```
"hashfun-launch" || u32 version || str name || str ticker || str hrp
|| u8 pubkey_prefix || u8 script_prefix || u8 secret_prefix
|| u32 genesis_time || u32 pow_limit_bits || u32 target_spacing || u32 lwma_window || u32 ftl
|| 32B virtual_work (big-endian) || i64 virtual_tokens || i64 graduation_tokens
|| i64 tail_reward || u32 tail_halving_interval || bytes creator_script || u16 creator_fee_bps || u8 test
|| u32 btc_anchor_height || 32B btc_anchor_hash (as displayed)
```

(`str`/`bytes` = CompactSize length + data; integers little-endian.) Derived from the id: P2P magic (`SHA256("hashfun-magic"||id)[:4] | 0x80` per byte), auxpow chain ID, default ports, datadir `launch_<ticker>_<id8>`.

`test: true` launches allow `setmocktime` and nonstandard txs.

## Build the node

```
cmake -B build -DBUILD_TESTS=OFF -DBUILD_GUI=OFF -DENABLE_IPC=OFF -DBUILD_KERNEL_LIB=OFF -DBUILD_BITCOIN_BIN=OFF
cmake --build build -j$(nproc)
# -> build/bin/hashfund, build/bin/hashfun-cli
```

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

`hashfun web --btc-rpc URL [--maker maker.json] [--allow-launch] [--listen 127.0.0.1:8080]` serves the board, coin pages, the launch form and Bags for every launch registered on the machine. Source in `hashfun/web/src` (`npm install && npm run build` writes `hashfun/web/static/app.js`; the built file and the fonts are committed, so running the site needs no Node).

| Piece | How it works |
|---|---|
| Keys | the page asks the wallet (UniSat: `requestAccounts`, `signMessage`) for one signature over a fixed message and derives its own key from it (`SHA256("hashfun-key-v1" \|\| signature)`), kept in the browser. That key holds launch coins (P2WPKH on every launch) and receives BTC yield (the same script on Bitcoin). The server never sees a key |
| Buy | atomic swap in the page: quote, HTLC built and checked in the browser, BTC paid into it with `sendBitcoin`, the maker locks coins on the launch chain, the page audits that contract (script, amount, confirmations, timelocks) and claims with the secret. Swap state is saved before any money moves; Bags can resume or, after the timelock, refund |
| Instant | `instant_max_sats` in the maker config: buys up to that size are filled on the unconfirmed Bitcoin lock. The maker carries the double-spend risk; larger buys wait for `btc_confs` |
| Sell | the page locks coins on the launch chain (it signs the P2WPKH spend), the maker locks BTC, the page claims it to the wallet address after one Bitcoin confirmation |
| Yield | Bags reads the Bitcoin outputs at the page key's script and sweeps them to the wallet address |
| Launch | the form posts name, ticker, curve size, BTC total and the creator's scripts; the server builds the descriptor, grinds genesis, starts the node (`--allow-launch`) |
| API | `/api/board`, `/api/coin/T`, `/api/coin/T/address/A`, `/api/chain/<btc\|T>/{time,txout,tx,spender,address}`, `/api/quote`, `/api/orders`, `/api/launch`. Reads and broadcasts only |

`hashfun/tests/test_web_js.py` holds the browser's Bitcoin code to the Python byte for byte (addresses, HTLC scripts, signed redeem, refund and P2WPKH transactions). `hashfun/tests/web_regtest.py` drives the real site in Chromium against real nodes, pool, settler and maker; only the wallet is a stand-in (a mock `window.unisat` backed by a regtest wallet).

The maker quotes `hashes_per_coin x (hashprice + sats owed per hash) x (1 +/- spread)` and refuses a quote it cannot fill from its wallet. The node wallet treats curve coinbases that are not settled as immature, so they stay out of its balance and coin selection.

## Wallet file

`hashfun wallet init` asks for a password (or reads `$HASHFUN_WALLET_PASSWORD`). The seed phrase, BIP39 passphrase and swap secrets are kept in a vault inside the wallet file: ChaCha20-Poly1305 (RFC 8439) under a key from scrypt (N=2^15, r=8, p=1). `hashfun wallet encrypt` sets or changes the password of an existing file; `--no-encrypt` is for throwaway wallets.

## npm

`contrib/hashfun/npm` is the `hashfun` npm package: a small Node wrapper that runs the Python CLI shipped inside it (Python >= 3.10, standard library only). `cd contrib/hashfun/npm && npm pack` (or `npm publish`) copies the package and the built site in first. The node binary stays separate (`HASHFUND=/path/to/hashfund`).

## Swaps

HTLC (P2WSH): `IF SIZE 32 EQUALVERIFY SHA256 <H> EQUALVERIFY <recipient> ELSE <locktime> CLTV DROP <refund> ENDIF CHECKSIG`. The size check pins the secret to 32 bytes on both chains.

Maker rules: quote `= hashes_per_coin x (hashprice + sats owed per hash) x (1 +/- spread)` (the curve is the fair-value anchor); quotes carry an id and a TTL so price movement between quote and lock cannot strand the taker; order size capped at the cost of renting enough hash to reorg `fork_confs` blocks; participates only after `btc_confs`/`fork_confs` on the initiator lock and only if the initiator's lock outlives its own by a margin; redeems as soon as the secret appears; refunds after its locktime.

Taker rules (wallet): reveals the secret only after `N` confirmations on the maker's lock, only while `now + margin < maker_locktime` (otherwise the maker could refund and still claim with the revealed secret), refunds at its own locktime.

## Tests

```
python -m unittest hashfun.tests.test_core      # vectors (BIP32/39/143/173), curve, LWMA, descriptor, HTLC, AuxPoW
python -m unittest hashfun.tests.test_stack     # pool+miner, merged mining gate, proxy split, electrum+wallet+reorg, swaps buy/sell/refund (simulator)
bash contrib/hashfun/difftest/build.sh build/hfdiff && HFDIFF=build/hfdiff python -m unittest hashfun.tests.test_diff_cpp
python -m hashfun.tests.e2e_regtest --hashfund build/bin/hashfund --bitcoind /path/to/stock/bitcoind
python -m hashfun.tests.fleet_regtest --hashfund build/bin/hashfund --bitcoind /path/to/stock/bitcoind   # ~4.5 min, real time
python -m unittest hashfun.tests.test_web_js    # browser Bitcoin code vs Python (needs node; cd hashfun/web && npm install)
python -m hashfun.tests.web_regtest --hashfund build/bin/hashfund --bitcoind /path/to/stock/bitcoind     # ~6 min, needs playwright
```

`test_stack` runs against an in-process simulator whose consensus is the Python model, not the C++ node. `test_diff_cpp` compiles the node's own consensus sources (descriptor parser and identity, `CLaunchParams` + genesis, curve, LWMA, tail) without the rest of the node, in ~20 s, and compares them value by value with the Python model on random descriptors and adversarial header sequences (zero, negative and >6T solvetimes, off-schedule nBits, graduation crossings); it also requires both parsers to accept and reject exactly the same descriptor JSON. `e2e_regtest` covers what needs a running node: block acceptance (creator output, excess coinbase, nBits), the auxpow gate, GBT, merged mining against stock bitcoind and a swap over real nodes. With `--workdir` its phases can run in separate processes (`--phases 1-6`, `7-8`, `9`). `fleet_regtest` is the multi-node test: production-mode launches, P2P on localhost, real time; gating, state agreement (tip, UTXO set, Bitcoin relay, every obligation) across nodes, late joiner, restarts, partitions and reorgs in both directions including a forged Bitcoin header branch, two competing pools, AuxPoW blocks over P2P, the settlement lock in the mempool, transaction relay, `verifychain`, stall relief against the wall clock.

## Files changed in the node

`src/kernel/launch.{h,cpp}` (descriptor), `src/launchcurve.{h,cpp}` (curve), `src/launchyield.{h,cpp}` + `src/launchyieldstate.{h,cpp}` (sats leg), `src/kernel/chainparams.cpp` (`CLaunchParams`, genesis), `src/pow.cpp` (LWMA), `src/validation.cpp` (subsidy, creator fee, auxpow gate, FTL), `src/node/miner.cpp` (template subsidy + creator output), `src/rpc/mining.cpp` (GBT `creatorfee`, genesis IBD exception), `src/rpc/blockchain.cpp` (`getlaunchinfo`, `getblockstats`), `src/rpc/auxpow_miner.cpp` (graduation gate), `src/index/coinstatsindex.cpp`, chain-type plumbing (`-launch`), `src/init.cpp` (BTC-chain guard), branding (datadir, conf, binary names).
