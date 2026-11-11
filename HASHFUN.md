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
| Difficulty | LWMA-1 every block, window N, solvetimes capped at 6T, monotonic-forced timestamps, overflow-guarded |
| Stall relief | the target doubles for every full 6T a block's own timestamp sits past its parent's, up to the pow limit, so an abandoned chain decays to CPU-minable in minutes. Safe because issuance is priced by work. nBits is a function of (ancestors, own nTime): no nTime rolling, templates refresh every few seconds |
| BTC anchor | optional `btc_anchor_height` / `btc_anchor_hash` in the descriptor, hashed into the launch id: no block of the launch can predate that Bitcoin block |
| FTL | per-descriptor future time limit (default 60 s with the 5 s / N=90 defaults) |
| Genesis | coinbase `scriptSig = PUSH32(launch_id)`, one zero-value `OP_RETURN` output, `nVersion=1`, must meet `pow_limit_bits` |

Sniping does nothing: a low-difficulty block pays exactly its work at the curve price. Merge-mining pools cannot touch presale issuance because auxpow is invalid until graduation; after it, exahash secures the tail.

All arithmetic is 256-bit integer. Validation bounds (`V0 <= 2^160`, `G <= 99.9% T0`, `T0 <= MAX_MONEY`) keep every product below 2^256.

## Sats leg (optional per launch)

With `sats_num > 0` a curve block owes real BTC on top of its hash: `owed = (work * sats_num) >> sats_shift`. No bridge and no reserve: the miner pays a drawn payee directly on Bitcoin and proves it on the launch chain.

| Step | Rule |
|---|---|
| Draw | the hash of block `h+6` seeds block `h`'s draw. Debts under `sats_min_payment` pay the minimum with probability owed/min. Payee class: 80% holder, 10% creator (`creator_btc_script`), 10% dev (compiled-in script, currently a placeholder nobody can spend) |
| Holder | hold and you earn, no opt-in. 64 candidate points into the value of every P2PKH / P2SH / witness-program output created before block `h`; the payee is the first candidate still unspent (coin-weighted over current holders), paid at that output's own scriptPubKey on Bitcoin (same key, since a launch is a Bitcoin fork). All spent or none yet: creator |
| Redirect | optional: a tx with `OP_RETURN "HFY1"<btc scriptPubKey>` sends its outputs' yield to that script instead (coinbase: vout 0 only) |
| Pay | a Bitcoin tx whose output `i` pays the payee and whose `OP_RETURN "HF"<20-byte tags>` has `SHA256("hashfun-pay"||launch_id||block_hash)[:20]` at position `i` |
| Bitcoin view | `OP_RETURN "HFH1"<80-byte headers>` relays Bitcoin headers; the node keeps a validating header tree from `btc_anchor_header` (PoW, retarget, median time), so its view of Bitcoin is a function of launch blocks only |
| Prove | `OP_RETURN "HFP1"<proof>`: merkle proof of the payment in a relayed Bitcoin block with `btc_confs` confirmations. Invalid proofs and headers are ignored, never block-invalidating |
| Lock | a curve coinbase cannot be spent until settled (`bad-txns-unsettled-coinbase`, mempool and consensus); unsettled `settle_deadline` blocks after minting, it never can |

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

## Swaps

HTLC (P2WSH): `IF SIZE 32 EQUALVERIFY SHA256 <H> EQUALVERIFY <recipient> ELSE <locktime> CLTV DROP <refund> ENDIF CHECKSIG`. The size check pins the secret to 32 bytes on both chains.

Maker rules: quote `= hashes_per_coin x hashprice x (1 +/- spread)` (the curve is the fair-value anchor); quotes carry an id and a TTL so price movement between quote and lock cannot strand the taker; order size capped at the cost of renting enough hash to reorg `fork_confs` blocks; participates only after `btc_confs`/`fork_confs` on the initiator lock and only if the initiator's lock outlives its own by a margin; redeems as soon as the secret appears; refunds after its locktime.

Taker rules (wallet): reveals the secret only after `N` confirmations on the maker's lock, only while `now + margin < maker_locktime` (otherwise the maker could refund and still claim with the revealed secret), refunds at its own locktime.

## Tests

```
python -m unittest hashfun.tests.test_core      # vectors (BIP32/39/143/173), curve, LWMA, descriptor, HTLC, AuxPoW
python -m unittest hashfun.tests.test_stack     # pool+miner, merged mining gate, proxy split, electrum+wallet+reorg, swaps buy/sell/refund (simulator)
bash contrib/hashfun/difftest/build.sh build/hfdiff && HFDIFF=build/hfdiff python -m unittest hashfun.tests.test_diff_cpp
python -m hashfun.tests.e2e_regtest --hashfund build/bin/hashfund --bitcoind /path/to/stock/bitcoind
```

`test_stack` runs against an in-process simulator whose consensus is the Python model, not the C++ node. `test_diff_cpp` compiles the node's own consensus sources (descriptor parser and identity, `CLaunchParams` + genesis, curve, LWMA, tail) without the rest of the node, in ~20 s, and compares them value by value with the Python model on random descriptors and adversarial header sequences (zero, negative and >6T solvetimes, off-schedule nBits, graduation crossings); it also requires both parsers to accept and reject exactly the same descriptor JSON. `e2e_regtest` covers what needs a running node: block acceptance (creator output, excess coinbase, nBits), the auxpow gate, GBT, merged mining against stock bitcoind and a swap over real nodes. With `--workdir` its phases can run in separate processes (`--phases 1-6`, `7-8`, `9`).

## Files changed in the node

`src/kernel/launch.{h,cpp}` (descriptor), `src/launchcurve.{h,cpp}` (curve), `src/launchyield.{h,cpp}` + `src/launchyieldstate.{h,cpp}` (sats leg), `src/kernel/chainparams.cpp` (`CLaunchParams`, genesis), `src/pow.cpp` (LWMA), `src/validation.cpp` (subsidy, creator fee, auxpow gate, FTL), `src/node/miner.cpp` (template subsidy + creator output), `src/rpc/mining.cpp` (GBT `creatorfee`, genesis IBD exception), `src/rpc/blockchain.cpp` (`getlaunchinfo`, `getblockstats`), `src/rpc/auxpow_miner.cpp` (graduation gate), `src/index/coinstatsindex.cpp`, chain-type plumbing (`-launch`), `src/init.cpp` (BTC-chain guard), branding (datadir, conf, binary names).
