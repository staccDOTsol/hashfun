# Two curves: every launch is quoted in BTC and in QWEN (rule set 3)

Working specification. Every layer (node, Python model, tools, site, Qwencoin node) follows this
file; where it and the code disagree, fix one of them and say so.

A launch has two bonding curves over the same coin: the BTC curve and the QWEN curve. A block mined
before graduation is on exactly one of them. It mints from that curve and owes that curve's asset:
sats on Bitcoin, or qwen on Qwencoin (https://github.com/staccDOTsol/qwencoin). Two price points per
coin, each moved only by what is bought through it. Nothing ties them together in consensus: whoever
mints picks the cheaper one, and the peer-to-peer book trades all three pairs (coin/BTC, coin/QWEN,
BTC/QWEN) with the same HTLC. The QWEN price is what the two price points of a coin imply.

Qwencoin facts this relies on (qwencoin commit 444dfff, patches/bitcoin-v29.4-inq-qwencoin.patch):
Bitcoin Inquisition v29.4; 80-byte headers; block id = SHA256d(header); txids, merkle trees, script
and signatures are Bitcoin's (its SHA-256 is the standard function); main network uses hrp `bc` and
Bitcoin's base58 prefixes (an address is the same string as the Bitcoin address of the same key);
regtest is unchanged Bitcoin regtest (SHA256d work, `bcrt`); RPC is bitcoin-cli's. Proof of work on
the main network is not the hash: value = SHA256(fold(net(seed, nonce)) XOR seed), seed =
SHA256d(header with nNonce = 0), net = exec/qwork.c over the table qwork.bin (528,482,328 bytes,
sha256 8f53884f7727e80b86f3ddf288d3c3f0f998f1c63b8cd4f0bdad182ddd3f2c03, fnv64 0x33a548a33925d201);
limit 0x2000ffff; retarget Bitcoin's (2016 blocks, two weeks, 4x clamp) computed as
MulDiv(target, timespan, T) = q*num + (r*num)/den with target = q*den + r.

## 1. Descriptor (version 3)

`version` is 3. Versions 1 and 2 are refused by both parsers with the existing "create the launch
again" message. New keys, all consensus, all mandatory (there is one kind of launch):

| key | type | rule |
|---|---|---|
| `qwen_anchor_height` | u32 | < 2^31 |
| `qwen_anchor_header` | 80 bytes hex | a Qwencoin header |
| `qwen_anchor_period_time` | u32 | time of the first block of the anchor's 2016-block period |
| `qwen_num` | u64 | > 0, at most 2^62 (same bounds as `sats_num`) |
| `qwen_shift` | u32 | same bounds as `sats_shift` |
| `qwen_min_payment` | i64 | same bounds as `sats_min_payment`; default 10000 |
| `qwen_confs` | u32 | 1..1008 (`btc_confs` stays 1..100): a proof is as hard to fake as that many Qwencoin blocks are to mine, and a large leg needs more than a hundred; default 6 |
| `creator_qwen_script` | script hex | P2PKH, P2SH or a witness program (same rule as `creator_btc_script`) |
| `qwen_regtest` | bool | the QWEN leg follows a regtest Qwencoin (default false) |

Canonical bytes: the version 2 serialization with `u32 version = 3`, and after `u8 btc_regtest`:

    u32 qwen_anchor_height || 80B qwen_anchor_header || u32 qwen_anchor_period_time
    || i64 qwen_num || u32 qwen_shift || i64 qwen_min_payment || u32 qwen_confs
    || bytes creator_qwen_script || u8 qwen_regtest || [32B meta, only when set]

Parser checks on the Qwencoin anchor unless `qwen_regtest` (both parsers, same messages): the bits
decode to a positive target no easier than 0x2000ffff; `qwen_anchor_period_time` is set, is not later
than the anchor allows (the Bitcoin anchor's rule) and is the anchor's own time when
`height % 2016 == 0`. Neither parser can check the anchor's work (it needs the table). The node
checks it at start (section 5); `descriptor.check_anchor` asks a Qwencoin node, as it asks a Bitcoin
node about the Bitcoin anchor.

Deadline against confirmations (both parsers, the last check of the QWEN block): with
`deadline_seconds = settle_deadline * target_spacing`, a launch is refused when a leg that is not on
regtest has `deadline_seconds < 1200 * confs` ("settle_deadline: too short for btc_confs: the
deadline must last at least twice as long as the confirmations take (ten minutes each)", and the same
sentence with `qwen_confs`). Otherwise a payment could never reach its confirmations in time and
every block that owes one would lose its coins whatever its miner did. A launch file therefore names its
deadline: the parsers' default of 720 blocks is for regtest legs, and at the default spacing it does
not cover the default 6 confirmations of a real Qwencoin leg (`hashfun launch new` always writes a
deadline that does).

Both curves have the same shape: `virtual_work` (V0), `virtual_tokens` (T0), `graduation_tokens` (G)
describe each of them.

## 2. Which curve a block is on

Bit 9 of the header's nVersion (`0x200`, `LAUNCH_VERSION_QWEN`): set = QWEN curve, clear = BTC curve.
The bit does not touch the base version (low 8 bits), the auxpow flag (bit 8) or the chain id (bits
16 and up).

Rule `bad-curve-version` (header, contextual): the bit may be set only if the parent has not
graduated. After graduation, in the genesis block and in every auxpow block it is clear.

## 3. Work, supply, graduation

For a block index p (genesis excluded from both sums):

    Wq(p) = sum of GetBlockProof(b) over the blocks b of p's chain with the bit set
    Wb(p) = (nChainWork(p) - genesis work) - Wq(p)

(On a header chain that breaks the rule of section 2 the node counts a block into Wq only if its
parent has not graduated: `Wq(b) = Wq(parent) + (bit set and parent not graduated ? work(b) : 0)`.
No such header enters a node; the definition matters to the difference test only.)

    S(W)  = min(G, floor(T0 * W / (V0 + W)))            unchanged
    W_g   = ceil(G * V0 / (T0 - G))                     unchanged
    graduated(p)  <=>  Wb(p) >= W_g  or  Wq(p) >= W_g

The first curve to sell out graduates the launch; what the other curve has not sold is never minted.
Presale supply is therefore between G and 2G, and the parsers bound the whole supply accordingly:
`2 * graduation_tokens + tail_reward * tail_halving_interval * 2 <= MAX_MONEY`. Graduated is monotone
along a chain.

Subsidy of block B on parent p: if graduated(p), the tail reward (unchanged). Otherwise, with x the
curve of B: `S(Wx(p) + work(B)) - S(Wx(p))`. Creator fee, tail, AuxPoW (valid only on a graduated
parent), LWMA difficulty and stall relief are unchanged and shared: one chain, one difficulty.

Curve supply minted as of p: with g the first graduated block on p's chain (or p if none),
`S(Wb(g)) + S(Wq(g))`. After graduation Wb keeps growing with tail blocks; nothing reads it then.

Wq is not stored in the block index. `launchcurve.cpp` keeps a cache by block hash under its own
mutex: one sum every 64 blocks below graduation, found by walking down to the nearest one, and the
first graduated block of each chain it has seen (nothing above that block is on a curve, so a
graduated chain costs one ancestor lookup and no memory per block).

## 4. What a curve block owes

    owed = (work * num_x) >> shift_x          x = btc: sats_num / sats_shift, x = qwen: qwen_num / qwen_shift

in base units of asset x. Draw, payee classes (80 / 10 / 10), the holder draw over live coins, the
lock on the coinbase, the deadline and the end of the leg are unchanged and shared. Per quote:

| | BTC curve | QWEN curve |
|---|---|---|
| minimum payment | `sats_min_payment` | `qwen_min_payment` |
| creator's script | `creator_btc_script` | `creator_qwen_script` |
| dev's script | the compiled-in script | the same script bytes (on Qwencoin the same address string) |
| holder's script | the coin's script | the same script |
| header relay output | `OP_RETURN "HFH1" <n * 80 bytes>` | `OP_RETURN "HFH2" <n * 80 bytes>` |
| proof output | `OP_RETURN "HFP1" <proof>` | `OP_RETURN "HFP2" <proof>` (same payload format) |
| confirmations | `btc_confs` on the Bitcoin relay | `qwen_confs` on the Qwencoin relay |

A payment is a transaction on the block's own quote chain whose output i pays the drawn script at
least `pay` and whose first `OP_RETURN "HF"` tag list has the block's tag at position i (tag
unchanged: `SHA256("hashfun-pay" || launch_id || block_hash)[:20]`). An HFP1 proof never settles a
QWEN-curve block and an HFP2 proof never settles a BTC-curve block.

## 5. The Qwencoin relay

The same header tree as the Bitcoin relay (anchor, most work wins, ties to the lowest hash, median
time enforced once 11 timestamps are known), with Qwencoin's rules:

- `qwen_regtest`: bits 0x207fffff, work = SHA256d hash, as Bitcoin regtest.
- otherwise: expected bits = the parent's inside a period; at `height % 2016 == 0`,
  `MulDiv(target(parent bits), clamp(parent time - period time, T/4, 4T), T)` capped at 0x2000ffff
  and compacted; the header's work value (above) must not exceed its target, compared as a
  little-endian 256-bit number exactly as Bitcoin compares a block hash.
- otherwise, also Qwencoin's own two rules at the edges of a difficulty period (Bitcoin Inquisition's
  consensus cleanup, active on Qwencoin from its first block, with BIP94's limit): a header at
  `height % 2016 == 0` is refused when its time is under its parent's time minus 600 s, and a header
  at `height % 2016 == 2015` when its time is under the time of the first block of its period. A
  regtest Qwencoin is not followed this closely, and the Bitcoin relay has neither rule.
- Order of checks: already known, does not connect, wrong bits, (pass limit), work, median time,
  the two rules at the edges of a period.
- Coinbase only: `HFH2` counts in a launch block's coinbase and nowhere else; in any other
  transaction it is ignored (no header looked at). Checking a Qwencoin header costs every node a
  pass, and a header that fails costs its relayer nothing: in any transaction, eight a block could be
  bought for a fee and put ahead of a miner's own. `HFH1`, `HFP1` and `HFP2` count in any transaction,
  as before.
- Pass limit: a launch block evaluates at most 8 Qwencoin headers' work. Headers of that block that
  would reach the work check after the eighth are skipped as if absent (order: the coinbase's
  outputs in order, headers in payload order). Same limit in both modes.
- The node keeps every work value it has computed in `qwork_values.dat` in the launch's data
  directory (header hash, value, a check): the leg's state is rebuilt from blocks at every start,
  and a header seen before costs no pass again. A record that fails its check is not believed.

The node maps the table at start: `-qwork=<file>` (default `qwork.bin`, relative to the base data
directory). A launch without `qwen_regtest` does not start without it: the file must be a QWRK1 table
of 24 layers of 3584 x 1024 with fnv64 0x33a548a33925d201, and the Qwencoin anchor's work value must
meet its own bits; the error names the file, where to get it and `hashfun qwork fetch`.
`src/crypto/qwork.{h,cpp}` are qwencoin's exec/qwork.{h,c} unchanged (Apache-2.0, commit 444dfff).

## 6. RPC

- `getlaunchinfo`: adds `curves: {"btc": C, "qwen": C}` and `graduated_by: "btc" | "qwen" | null`.
  C = `{work (hex), supply, progress (0..1), hashes_per_coin, owed_num, owed_shift, owed_per_coin
  (base units of the quote per whole coin at the margin, a double), min_payment, confs,
  creator_script (hex), blocks (curve blocks mined on it), last_height (0: none)}`.
  Top level: `curve_supply` = both curves' minted sum; `progress` = the larger of the two.
- `getmintobligation <height>`: adds `quote: "btc" | "qwen"`.
- `getqwenrelay`: the Qwencoin relay, same fields as `getbtcrelay`.
- `getblocktemplate`: before graduation adds
  `launchcurves: {"btc": {"version", "coinbasevalue", "creatorfee"?}, "qwen": {...}}`; the top level
  is the node's mining curve.
- `setminecurve "btc" | "qwen"` (and `-minecurve=`, default btc): the curve the node's own miner and
  the top level of `getblocktemplate` use. Returns the previous value.

## 7. Tools

- Addresses on Qwencoin use the Bitcoin hrp of the network the launch follows (`bc` / `bcrt`).
- Stratum username: `ADDRESS` (the pool's default curve), `ADDRESS/btc` or `ADDRESS/qwen`.
- `hashfun launch new`: `--qwen-rpc URL [--qwen-cookie FILE] --qwen-total COINS
  --creator-qwen-address ADDR [--qwen-anchor HEIGHT:HEADER[:PERIODTIME]] [--qwen-regtest]`.
- `hashfun mine`: `--curve btc|qwen` (default: the one a wallet was given for; both given: required),
  `--qwen-rpc URL --qwen-cookie FILE --qwen-wallet NAME`. The settler relays the headers of every
  chain it has an RPC for and pays a block from the wallet of the block's quote.
- `hashfun qwork fetch|check|path`: the table at `~/.hashfun/qwork.bin` (fetched from
  https://huggingface.co/staccs/qwencoin/resolve/main/qwork.bin, resumed, sha256 checked);
  `hashfun node up` passes `-qwork`.
- Site: `hashfun web --qwen-rpc URL [--qwen-cookie FILE]`; book chain name `qwen:<net>`; queue
  `POST /api/coin/T/queue {address, blocks, curve}`; a due carries `quote`.
- Prices (marginal, hash cost left out): `price_x = hashes_per_coin_x * num_x / 2^shift_x` base units
  of x per whole coin. Implied QWEN price in sats per QWEN: `price_btc / price_qwen * 1e8`. It is a
  two-sided price only while both curves are being mined; otherwise it is a bound, and the site says
  which.
