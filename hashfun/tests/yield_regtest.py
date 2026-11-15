"""Both legs of a launch, a real node against the model, block by block.

  python3 -m hashfun.tests.yield_regtest --hashfund build/bin/hashfund --bitcoind /path/to/bitcoind

One launch chain on a real hashfund with two curves (contrib/hashfun/TWIN.md), real Bitcoin payments on
a regtest bitcoind and real Qwencoin payments on a second one that plays the regtest Qwencoin
(hashfun/tests/qwenreg.py). After every block, and after every restart and every block a reorg takes
off or puts back, the model (hashfun/yieldstate.py) is fed the node's own serialized blocks and the two
are compared: `getmintobligation` at EVERY height, field by field, `getlaunchinfo.earning`, both curves
of `getlaunchinfo` (work, supply, blocks, last height, what the next block owes and mints, graduation),
the Bitcoin relay (`getbtcrelay`) and the Qwencoin relay (`getqwenrelay`). The first difference stops
the run and prints both values. The model is written from the rules, not from the node's code, and has
one code path: the state of a chain is what replaying its blocks gives.

What the chain goes through (heights are fixed where a rule depends on them; blocks are on the BTC
curve unless said, and from 63 on every height that is 4 modulo 5 is a QWEN-curve block the Settler
pays on Qwencoin):

  1-19     the first blocks of a launch. Every coinbase is held, so nothing earns. Block 1's draw
           (made by block 7, steered to the holder class) finds nobody holding: owed to no one, its
           coinbase is free. The holder draws of blocks 2-4 then all fall on block 1's coinbase,
           the only coins live; once those blocks settle (the Settler pays on Bitcoin), their
           coinbases share the draws. The blocks the later steps need get their draws here too.
  20       ONE Bitcoin output with TWO tag lists, offered as the proof for two blocks.
  21-26    five proofs that must be ignored, one per block: the wrong script, one sat short, a named
           candidate, the tag in a second list, another holder's script with candidate 1. A restart.
           Then the same payment with candidate 0, which settles.
  27-32    a payment in a Bitcoin block that is then reorged out, the right Bitcoin payment proven
           under the Qwencoin tag (HFP2), and Bitcoin headers with rubbish between them.
  32-...   coinbases that redirect their yield (HFY1), draws steered onto their outputs.
  57-62    six QWEN-curve blocks this script settles itself (the node mines them on `setminecurve
           qwen`); their draws (63-68) are steered: two owe the creator the same, three owe something,
           one owes nothing and is released at its draw. A QWEN-curve holder draw for block 64 (70).
  71-72    Qwencoin headers in coinbases (HFH2): twelve new ones with a known header, one that does
           not connect, one with the wrong bits and a repeat among them (only eight are taken; the
           others cost no check), then a header without work ahead of ten (it costs one of the eight).
  74-84    proofs on Qwencoin (HFP2): payments on the other chain (HFP1 for a QWEN-curve block, HFP2
           for a BTC-curve block), another block's tag, one confirmation too few, the right payment
           under the Bitcoin tag (HFP1), then the right proof, one
           Qwencoin output with two tag lists, and a Qwencoin reorg that drops a payment's block. A
           restart.
  96-103   two more QWEN-curve blocks for the settlement deadline, their draws steered.
  103-111  ordinary transfers; a proof of each chain, an HFY1 and an HFH2 carried by ordinary
           transactions (the HFH2 is ignored); 60 self-transfers.
  112-115  a block with a settlement on each chain, a spend and relayed headers of both chains is
           invalidated and reconsidered, then taken off one block at a time with two blocks on top
           and replaced for good by a competing branch (other draws for the same blocks).
  120,123  the settlement deadline: the last block that may carry a proof, and the first that may not.
  124      a restart; then on to graduation by the BTC curve (block g), eight merge-mined blocks, a
           restart, the settlement deadline of the two QWEN-curve blocks (206, 208).
  g+110    the end of both legs: the last block the node looks at. It carries the proof for the last
           curve block, g, in the last block that may. Blocks after it carry spends, headers of both
           chains and proofs of both chains that change nothing. A reorg from three blocks before the
           end and back, a reorg entirely past the end, a last restart.
  QGR      a second launch: blocks on both curves until each curve is one block from selling out.
           One branch graduates on the BTC curve; it is taken off block by block and the other
           branch graduates on the QWEN curve. A restart, then the end of that launch's legs with an
           HFP2 proof of its last curve block in the last block that may.

The review's findings, and the checks here that would have caught them:

  C1 (a replayed node and a live one disagree). "restart": the main node is stopped and started five
     times (with ignored proofs in its blocks, with the QWEN leg under way, after the reorgs, past
     graduation, and after the legs are over, when it replays only up to the last tracked block), the
     second launch's once. Each time it rebuilds the state from its blocks, and every obligation, both
     relays, both curves and the earning value must equal both what it said before the stop and the
     model. The comparison runs after every invalidateblock / reconsiderblock too, so the undo path
     is held to the replay.
  C2 (one payment settles many blocks). "one Bitcoin output, two tag lists" (block 20), "the tag in a
     second list" (block 24) and "one Qwencoin output, two tag lists": only the first list binds.
  C3 (every output ever made stays in the holder draw; churn buys weight). "60 self-transfers"
     (the earning value moves by the fees and nothing else), `earning` at every block and at every
     draw against the model, which counts live coins only, and "the UTXO set" (one block before
     the legs end): each coin the model has live is unspent on the node, each dead one spent,
     and live + held is the whole set.
  H1 (unsettled coinbases earn). "nothing earns while every coinbase is held", "never settled,
     never earning" (block 5 is never paid: it is in no draw and not in the earning value at the
     end) and the same `earning` equalities.
  Also: M1, the seed of a merge-mined block is its parent's hash ("merge-mined"); M4, a redirect
  covers only a miner's own coinbase output ("HFY1").

Not here: mempool and wallet policy for unsettled coinbases (e2e_regtest phase 10), several nodes
(fleet_regtest), a Qwencoin on its main-network rules (the work table: test_diff_cpp)."""
import argparse
import hashlib
import os
import struct
import sys
import tempfile
import time
import traceback
from types import SimpleNamespace

from hashfun import descriptor as D
from hashfun import yieldmodel as Y
from hashfun import yieldstate as S
from hashfun.auxpow import AuxTree, check_auxpow, serialize_auxpow
from hashfun.crypto import hash160, sha256d
from hashfun.ser import Tx, TxIn, TxOut, bits_to_target, header_bytes, push_int, work_from_bits
from hashfun.settler import Settler, merkle_branch
from hashfun.tests.e2e_regtest import RESULTS, Node, block_from_gbt, check, free_port, mk_launch, open_wallet, ser_block
from hashfun.tests.qwenreg import QwenNode

COIN = 100_000_000
DAY = 86400
SPACING = 10
GRAD_BLOCKS = 140   # the BTC curve sells out after this many of its blocks (2 hashes a block at the regtest limit)
QGR_BLOCKS = 8      # the second launch: each curve sells out after about this many of its blocks
DEADLINE = 110      # settle_deadline: the smallest a launch may have
# Blocks the Settler is not told about: this script pays (or does not pay) for them itself.
U, A, B, W, E, L, R, V = 5, 6, 8, 9, 10, 12, 13, 50              # on the BTC curve
QA, QB, QX, QR, QP, QN, QE, QL = 57, 58, 59, 60, 61, 62, 96, 97  # on the QWEN curve
QH = 64             # a QWEN-curve block the Settler pays: its draw is steered to a holder
QRES = {QA, QB, QX, QR, QP, QN, QE, QL}
RESERVED = {U, A, B, W, E, L, R, V} | QRES
NOWHERE = hashlib.sha256(b"hashfun yield regtest: a block nobody has").digest()


def main_curve(h: int) -> str:
    """The curve the main chain's block at height h is mined on (while there is a curve)."""
    return "qwen" if h in QRES or (h >= 63 and h % 5 == 4) else "btc"


class Mismatch(Exception):
    def __init__(self, where, diffs):
        super().__init__(where)
        self.where, self.diffs = where, diffs


def raw(hexhash: str) -> bytes:
    return bytes.fromhex(hexhash)[::-1]


def amount(sats: int) -> str:
    """An amount for the node's RPC, exact (a float could round)."""
    return f"{sats // COIN}.{sats % COIN:08d}"


def to_sats(value) -> int:
    return round(value * COIN)


def solve_where(header76: bytes, target: int, want, limit: int = 4_000_000) -> bytes:
    """A nonce whose hash meets the target and that want(hash) accepts."""
    for n in range(limit):
        h = header76 + struct.pack("<I", n)
        hash_ = sha256d(h)
        if int.from_bytes(hash_, "little") <= target and want(hash_):
            return h
    raise RuntimeError("no nonce gives the draw this step needs")


class Run:
    def __init__(self, a):
        self.a = a
        self.dir = os.path.abspath(a.workdir) if a.workdir else tempfile.mkdtemp(prefix="hashfun-yield-")
        os.makedirs(self.dir, exist_ok=True)
        self.path = os.path.join(self.dir, "YLD.json")
        if os.path.exists(self.path):
            raise SystemExit(f"{self.dir} holds an earlier run: this test needs a fresh --workdir")
        self.nodes, self.f, self.sent = [], None, 0
        self.node_name, self.settler_name = "node", "settler.json"
        self.curve_of, self.reserved = main_curve, RESERVED
        self.stats = {"blocks compared": 0, "obligations compared": 0, "blocks undone": 0, "proofs ignored": 0, "restarts": 0}

    # ------------------------------------------------------------ nodes
    def start(self):
        a = self.a
        self.btc = Node(a.bitcoind, os.path.join(self.dir, "btc"), ["-regtest"], free_port())
        self.nodes.append(self.btc)
        self.wb = open_wallet(self.btc.rpc)
        self.btc_addr = self.wb.getnewaddress("", "bech32")
        self.wb.generatetoaddress(101, self.btc_addr)
        # The regtest Qwencoin: a second stock bitcoind, no peers, its own blocks.
        self.qn = QwenNode(a.bitcoind, os.path.join(self.dir, "qwen"))
        self.nodes.append(self.qn)
        self.wq = self.qn.funded_wallet()
        self.qaddr = self.wq.getnewaddress("", "bech32")
        self.creator_spk = b"\x00\x14" + hash160(b"hashfun yield regtest: nobody holds the creator's key")
        d = mk_launch("YLD", self.creator_spk, GRAD_BLOCKS, int(time.time()) - DAY)
        d.btc_anchor_header = bytes.fromhex(self.btc.rpc.getblockheader(self.btc.rpc.getblockhash(0), False))
        d.btc_anchor_height = 0
        d.btc_anchor_period_time = struct.unpack("<I", d.btc_anchor_header[68:72])[0]
        # The Qwencoin anchor is the regtest genesis block (mk_launch's test leg): 110 headers to catch up.
        # 2 hashes a block at the limit owe 4,000 sats (6,000 qwen-sats), under the 10,000 minimum: each draw
        # is a lottery, 10,000 due with probability 0.4 (0.6) and nothing due otherwise.
        d.sats_num, d.sats_shift, d.settle_deadline = 2000, 0, DEADLINE
        d.qwen_num, d.qwen_shift = 3000, 0
        d.creator_btc_script = self.btc_spk()
        d.creator_qwen_script = self.qwen_spk()
        D.validate(d)
        d.grind_genesis()
        with open(self.path, "w") as f:
            f.write(d.dumps())
        self.d = D.load(self.path)
        if self.d.qwen_confs != 2 or not self.d.qwen_regtest or self.d.btc_confs != 1:
            raise RuntimeError(f"the plan expects 1 Bitcoin and 2 Qwencoin confirmations: {self.d.btc_confs} {self.d.qwen_confs}")
        self.args = [f"-launch={self.path}", "-datacarriersize=1000000"]
        self.T = d.genesis_time + 100
        self.boot()
        self.addrs = [self.w.getnewaddress("", kind) for kind in ("legacy", "p2sh-segwit", "bech32", "bech32m")]
        self.spks = [bytes.fromhex(self.w.getaddressinfo(x)["scriptPubKey"]) for x in self.addrs]
        self.f = S.Follower(self.d, self.rpc)
        self.compare("the genesis block")

    def boot(self):
        """Start the launch node (again) on its data directory."""
        self.node = Node(self.a.hashfund, os.path.join(self.dir, self.node_name), self.args, free_port())
        self.nodes.append(self.node)
        self.rpc = self.node.rpc
        self.rpc.setmocktime(self.T)  # before the wallet exists: its birth time has to be the chain's
        self.w = open_wallet(self.rpc)
        self.settler = Settler(self.rpc, self.wb, os.path.join(self.dir, self.settler_name), pay_depth=0, qwen_wallet=self.wq)
        if self.f:
            self.f.rpc = self.rpc

    def stop(self):
        for n in self.nodes:
            n.stop()

    def said(self, tip: int):
        """What the node says that a restart must not change."""
        info = self.rpc.getlaunchinfo()
        return ([self.ob(h) for h in range(tip + 1)], self.rpc.getbtcrelay(), self.rpc.getqwenrelay(), info["earning"],
                info["curves"], info["graduated_by"], info["graduation_height"], info["curve_supply"])

    def restart(self, label: str):
        tip = self.tip
        before = self.said(tip)
        self.node.stop()
        self.nodes.remove(self.node)
        self.boot()
        after = self.said(tip)
        self.stats["restarts"] += 1
        check(f"restart {label}: the node rebuilt from its blocks says what it said before (every obligation, both relays, "
              f"both curves, earning)", after == before,
              f"{sum(1 for x, y in zip(before[0], after[0]) if x != y)} obligations differ; "
              f"fields {[i for i in range(1, len(before)) if before[i] != after[i]]} differ")
        self.compare(f"the restart {label}")

    # ------------------------------------------------------------ reading the node
    @property
    def tip(self) -> int:
        return self.rpc.getblockcount()

    def ob(self, h: int) -> dict:
        return self.rpc.getmintobligation(h)

    def earning(self) -> int:
        return self.rpc.getlaunchinfo()["earning"]

    def cb_txid(self, h: int) -> str:
        return self.f.blocks[h].txs[0].txid[::-1].hex()

    def cb_coins(self, h: int):
        """The coins of block h's coinbase, read from the node's block: [(vout, value, yield script)]."""
        outs = self.f.blocks[h].txs[0].outputs
        return Y.registered_outputs(SimpleNamespace(vout=[TxOut(v, s) for v, s in outs]), True)

    def cb_value(self, h: int) -> int:
        return sum(v for _n, v, _s in self.cb_coins(h))

    def held(self, h: int) -> bool:
        o = self.ob(h)
        return o["curve"] and o["owed"] > 0

    def btc_spk(self) -> bytes:
        return bytes.fromhex(self.wb.getaddressinfo(self.wb.getnewaddress("", "bech32"))["scriptPubKey"])

    def qwen_spk(self) -> bytes:
        return bytes.fromhex(self.wq.getaddressinfo(self.wq.getnewaddress("", "bech32"))["scriptPubKey"])

    def model_curves(self):
        """getlaunchinfo's curves and graduation as the model's blocks give them."""
        f, d = self.f, self.d
        tip = len(f.blocks) - 1
        g = next((h for h in range(1, tip + 1) if d.graduated(*f.work[h])), None)
        wb, wq = f.work[g if g is not None else tip]
        curves = {}
        for qi, q in enumerate(S.QUOTE_NAMES):
            hs = [b.height for b in f.blocks if b.curve and b.quote == qi]
            w = (wb, wq)[qi]
            curves[q] = {"work": w, "supply": d.curve_supply(w), "blocks": len(hs), "last_height": hs[-1] if hs else 0}
        top = {"graduated": g is not None, "graduated_by": S.QUOTE_NAMES[f.blocks[g].quote] if g is not None else None,
               "graduation_height": g if g is not None else -1,
               "curve_supply": sum(c["supply"] for c in curves.values())}
        return curves, top, (wb, wq)

    def compare(self, where: str):
        """The node against the model fed from the node's own blocks: every height, every field."""
        undone, _done = self.f.sync()
        self.stats["blocks undone"] += undone
        st, tip, diffs = self.f.state, self.tip, []
        if st.height() != tip:
            diffs.append(f"height: node {tip}, model {st.height()}")
        for h in range(min(tip, st.height()) + 1):
            diffs += [f"getmintobligation {h}: {x}" for x in S.differences(self.ob(h), st.obligation(h))]
        info = self.rpc.getlaunchinfo()
        if info.get("earning") != st.earning():
            diffs.append(f"getlaunchinfo earning: node {info.get('earning')!r}, model {st.earning()!r}")
        for name, rpc_relay, model_relay in (("getbtcrelay", self.rpc.getbtcrelay(), st.relay),
                                             ("getqwenrelay", self.rpc.getqwenrelay(), st.qrelay)):
            for k, v in (("best", model_relay.best()[::-1].hex()), ("height", model_relay.best_height()),
                         ("headers", model_relay.size())):
                if rpc_relay.get(k) != v:
                    diffs.append(f"{name} {k}: node {rpc_relay.get(k)!r}, model {v!r}")
        curves, top, (wb, wq) = self.model_curves()
        for k, v in top.items():
            if info.get(k) != v:
                diffs.append(f"getlaunchinfo {k}: node {info.get(k)!r}, model {v!r}")
        bits = int(info["next"]["bits"], 16)
        for q, c in curves.items():
            node_c = dict(info["curves"][q])
            node_c["work"] = int(node_c["work"], 16)
            c = dict(c, next_owed=0 if top["graduated"] else self.d.owed(work_from_bits(bits), q),
                     next_subsidy=0 if top["graduated"] else self.d.subsidy(wb, wq, q, bits, tip + 1))
            for k, v in c.items():
                if node_c.get(k) != v:
                    diffs.append(f"getlaunchinfo curves.{q}.{k}: node {node_c.get(k)!r}, model {v!r}")
        self.stats["blocks compared"] += 1
        self.stats["obligations compared"] += tip + 1
        if diffs:
            raise Mismatch(where, diffs)

    # ------------------------------------------------------------ mining
    def steer(self, m: int, cls=None, due=None, coin=None, beyond=None):
        """A predicate on the hash of the next block, which makes the draw of block m: the class it
        gives, whether anything is due, and for a holder draw where the point falls (on the coin
        (txid, vout), or at or past the value `beyond` in the list of live coins)."""
        st = self.f.state
        if self.tip + 1 != m + Y.DRAW_DELAY:
            raise RuntimeError(f"block {self.tip + 1} does not draw for block {m}")
        owed, total, lo, hi = st.info[m].owed, st.live_value(), None, None
        minimum = st.p.min_pay(st.info[m].quote)  # of the block's own curve
        if coin is not None:
            acc = 0
            for c in st.coins:
                if c.live and (c.txid, c.vout) == coin:
                    lo, hi = acc, acc + c.value
                    break
                acc += c.value if c.live else 0
            if lo is None:
                raise RuntimeError("the coin to draw is not live")
        elif beyond is not None:
            if total <= beyond:
                raise RuntimeError(f"nothing is live past {beyond} (live value {total})")
            lo, hi = beyond, total

        def want(hash_: bytes) -> bool:
            seed = Y.draw_seed(self.d.id, hash_)
            pay, c = Y.compute_draw(owed, minimum, seed)
            if cls is not None and c != cls:
                return False
            if due is not None and (pay > 0) != due:
                return False
            return lo is None or lo <= Y.candidate_point(seed, 0, total) < hi
        return want

    def mine(self, extra_outs=(), *, settle=True, want=None, own=False, curve=None, top=None) -> int:
        """One block from the node's template, paid to the next of the wallet's four address types.
        settle: the Settler pays what is due and adds its headers and proofs. want: steer().
        own: do not tell the Settler about this block (the caller settles it, or not).
        curve: "btc" or "qwen" (default: the plan's). top: take the curve from the template's top level
        after `setminecurve` (default: for the blocks this script settles itself), not from `launchcurves`."""
        h = self.tip + 1
        curve = curve or self.curve_of(h)
        top = (h in self.reserved) if top is None else top
        outs = list(self.settler.coinbase_outputs()) if settle else []
        if settle:
            self.wb.generatetoaddress(1, self.btc_addr)  # confirms what the Settler just paid
            self.qn.mine(1, self.qaddr)                   # ... on either chain
        self.T += SPACING
        self.rpc.setmocktime(self.T)
        if top:
            self.rpc.setminecurve(curve)
        t = self.rpc.getblocktemplate({"rules": ["segwit"]})
        if top:
            self.rpc.setminecurve("btc")
            if "launchcurves" in t and bool(t["version"] & Y.LAUNCH_VERSION_QWEN) != (curve == "qwen"):
                raise RuntimeError(f"block {h}: setminecurve {curve} gave a template of version {t['version']:#x}")
        if t["height"] != h:
            raise RuntimeError(f"the template is for height {t['height']}, not {h}")
        hdr, txs = block_from_gbt(t, self.spks[h % len(self.spks)], extra_outs=outs + list(extra_outs),
                                  curve=None if top else curve)
        if want is not None:
            hdr = solve_where(hdr[:76], bits_to_target(int(t["bits"], 16)), want)
        r = self.rpc.submitblock(ser_block(hdr, txs))
        if r is not None:
            raise RuntimeError(f"block {h}: submitblock said {r!r}")
        if h not in self.reserved and not own:
            self.settler.add_block(h, sha256d(hdr)[::-1].hex())
        self.compare(f"block {h}")
        return h

    def until(self, height: int, transfers: int = 0):
        """Plain blocks up to this height."""
        if self.tip > height:
            raise RuntimeError(f"the plan is off: at {self.tip}, past {height}")
        while self.tip < height:
            if transfers:
                self.transfer(transfers)
            self.mine()

    def mine_merged(self, steer=None):
        """One merge-mined block: the node's own aux block, with a proof of work made here on a
        parent header. steer(the aux block's own hash) gives a predicate on the PARENT header's
        hash. Returns (height, the block's own hash)."""
        self.T += SPACING
        self.rpc.setmocktime(self.T)
        ab = self.rpc.createauxblock(self.addrs[2])
        aux_hash = raw(ab["hash"])
        want = steer(aux_hash) if steer else None
        tree = AuxTree({ab["chainid"]: aux_hash})
        pcb = Tx(version=1, vin=[TxIn(b"\0" * 32, 0xFFFFFFFF, push_int(1) + tree.commitment_push(), 0xFFFFFFFF)],
                 vout=[TxOut(0, b"\x6a")])
        target = bits_to_target(int(ab["bits"], 16))
        head = header_bytes(0x20000000, b"\x11" * 32, pcb.txid(), self.T, 0x207FFFFF, 0)[:76]
        parent = solve_where(head, target, want or (lambda _hash: True))
        branch, index = tree.branch(ab["chainid"])
        apow = serialize_auxpow(pcb, [], branch, index, parent)
        ok, why = check_auxpow(aux_hash, ab["chainid"], apow)
        if not ok:
            raise RuntimeError(f"auxpow built here does not check: {why}")
        if self.rpc.submitauxblock(ab["hash"], apow.hex()) is not True:
            raise RuntimeError("submitauxblock refused the block")
        h = self.tip
        self.settler.add_block(h, ab["hash"])
        self.compare(f"merge-mined block {h}")
        return h, aux_hash

    # ------------------------------------------------------------ Bitcoin and Qwencoin
    def chain(self, name: str):
        """(node RPC, wallet RPC, an address of the wallet) of "btc" or "qwen"."""
        return (self.btc.rpc, self.wb, self.btc_addr) if name == "btc" else (self.qn.rpc, self.wq, self.qaddr)

    def relayed(self, name: str) -> dict:
        return self.rpc.getbtcrelay() if name == "btc" else self.rpc.getqwenrelay()

    def header(self, name: str, height: int) -> bytes:
        node = self.chain(name)[0]
        return bytes.fromhex(node.getblockheader(node.getblockhash(height), False))

    def relay_out(self, name: str = "btc", start=None, limit=None):
        """An HFH1 (HFH2) output with the Bitcoin (Qwencoin) headers the launch has not seen (or all
        from a height), at most `limit` of them (Qwencoin: 8 by default, what one block may check)."""
        node = self.chain(name)[0]
        first = self.relayed(name)["height"] + 1 if start is None else start
        if limit is None and name == "qwen":
            limit = Y.MAX_QWEN_PASSES
        last = node.getblockcount() if limit is None else min(node.getblockcount(), first + limit - 1)
        hdrs = b"".join(self.header(name, h) for h in range(first, last + 1))
        return [TxOut(0, Y.op_return(Y.HEADER_TAG[name] + hdrs))] if hdrs else []

    def caught_up(self, name: str) -> bool:
        node, r = self.chain(name)[0], self.relayed(name)
        return r["best"] == node.getbestblockhash() and r["height"] == node.getblockcount()

    def catch_up(self, name: str = "qwen"):
        for _ in range(20):
            if self.caught_up(name):
                return
            self.mine(self.relay_out(name), settle=False)
        raise RuntimeError(f"the {name} relay did not catch up")

    def chain_pay(self, pays, lists, name: str = "btc", confirm: int = 1):
        """A transaction on Bitcoin ("btc") or Qwencoin ("qwen") with outputs pays = [(script, base units)]
        and then its tag lists, confirmed by `confirm` blocks there at once. Returns (txid, its block's hash)."""
        _node, wallet, addr = self.chain(name)
        tx = Tx(version=2, vin=[], vout=[TxOut(s, script) for script, s in pays] +
                [TxOut(0, Y.payment_outputs_tag(tags)) for tags in lists])
        funded = wallet.fundrawtransaction(tx.serialize(witness=False).hex(), {"changePosition": len(tx.vout)}, False)
        txid = wallet.sendrawtransaction(wallet.signrawtransactionwithwallet(funded["hex"])["hex"])
        mined = wallet.generatetoaddress(confirm, addr) if confirm else []
        return txid, (mined[0] if mined else None)

    def btc_pay(self, pays, lists):
        return self.chain_pay(pays, lists, "btc")

    def pay(self, m: int, tag=None, confirm=None):
        """The payment block m's draw asks for, on the chain of its quote, confirmed as that leg needs.
        Returns (txid, block hash)."""
        o = self.ob(m)
        name = o["quote"]
        return self.chain_pay([(bytes.fromhex(o["pay_script"]), o["pay"])], [[bytes.fromhex(tag or o["tag"])]], name,
                              self.d.confs(name) if confirm is None else confirm)

    def proof_payload(self, m: int, txid: str, block: str, vout: int = 0, candidate: int = 0,
                      chain: str = "btc", tag: str = None) -> bytes:
        """The SPV proof of payment txid in `block` on `chain`, as HFP1 (tag "btc") or HFP2 (tag "qwen");
        the tag is the chain's own unless said."""
        node = self.chain(chain)[0]
        txids = node.getblock(block, 1)["tx"]
        pos = txids.index(txid)
        nowit = Tx.parse(bytes.fromhex(node.getrawtransaction(txid, False, block))).serialize(witness=False)
        return Y.PaymentProof(m, raw(block), pos, merkle_branch([raw(x) for x in txids], pos), vout, candidate,
                              nowit).payload(tag or chain)

    def proof(self, m: int, txid: str, block: str, vout: int = 0, candidate: int = 0, chain: str = "btc", tag: str = None) -> TxOut:
        return TxOut(0, Y.op_return(self.proof_payload(m, txid, block, vout, candidate, chain, tag)))

    # ------------------------------------------------------------ the launch wallet
    def transfer(self, n: int = 2):
        """n ordinary payments between the wallet's address types: inputs die, outputs and change appear."""
        each = to_sats(self.w.getbalance()) // 40
        if each <= 0:
            raise RuntimeError("the launch wallet has nothing to spend")
        for _ in range(n):
            self.sent += 1
            self.w.sendtoaddress(self.addrs[self.sent % len(self.addrs)], amount(each))

    def send_data(self, payload: bytes, first=None) -> str:
        """An ordinary launch transaction: [first], an OP_RETURN carrying payload (one push), change."""
        outs = ([first] if first else []) + [{"data": payload.hex()}]
        funded = self.w.fundrawtransaction(self.w.createrawtransaction([], outs), {"changePosition": len(outs)}, False)
        return self.rpc.sendrawtransaction(self.w.signrawtransactionwithwallet(funded["hex"])["hex"])

    def steer_onto(self, coin, what: str) -> dict:
        """Mine the next block so that its holder draw falls on this coin; returns that obligation."""
        m = self.tip + 1 - Y.DRAW_DELAY
        if m in self.reserved or not self.held(m):
            raise RuntimeError(f"block {m} cannot take a steered draw ({what})")
        self.mine(want=self.steer(m, cls=Y.HOLDER, due=True, coin=coin))
        o = self.ob(m)
        if (o.get("coin") or {}).get("txid") != coin[0][::-1].hex() or o["coin"]["vout"] != coin[1]:
            raise RuntimeError(f"the steered draw of block {m} did not land on the coin ({what}): {o}")
        return o

    def settled(self, *heights) -> bool:
        return all(self.ob(h)["settled"] and self.ob(h)["spendable"] for h in heights)

    def unsettled(self, *heights) -> bool:
        return all(not self.ob(h)["settled"] and not self.ob(h)["spendable"] for h in heights)

    # ------------------------------------------------------------ the QWEN leg on the main chain
    def qwen_leg(self):
        """Heights 57-84: QWEN-curve blocks, their draws, Qwencoin headers and proofs. Returns the
        payments the later steps prove: {block: (txid, Qwencoin block hash)}."""
        d, st = self.d, self.f.state
        for _ in sorted(x for x in QRES if x < 63):                                                     # 57-62
            self.mine()
        self.mine(want=self.steer(QA, cls=Y.CREATOR, due=True))                                         # 63
        self.mine(want=self.steer(QB, cls=Y.CREATOR, due=True))                                         # 64
        self.mine(want=self.steer(QX, due=True))                                                        # 65
        self.mine(want=self.steer(QR, due=True))                                                        # 66
        self.mine(want=self.steer(QP, due=True))                                                        # 67
        self.mine(want=self.steer(QN, due=False))                                                       # 68
        self.mine()                                                                                     # 69
        self.mine(want=self.steer(QH, cls=Y.HOLDER, due=True))                                          # 70
        obs = {h: self.ob(h) for h in sorted(QRES | {QH}) if h < 63 or h == QH}
        version = lambda hash_hex: self.rpc.getblockheader(hash_hex)["version"]  # noqa: E731
        check("QWEN curve: a block mined on `setminecurve qwen` or from launchcurves.qwen has bit 0x200 and owes qwen "
              "at qwen_num / qwen_shift for its work; a BTC-curve block has the bit clear",
              all(o["curve"] and o["quote"] == "qwen" and o["owed"] == d.owed(work_from_bits(int(
                  self.rpc.getblockheader(o["hash"])["bits"], 16)), "qwen") and version(o["hash"]) & Y.LAUNCH_VERSION_QWEN
                  for o in obs.values())
              and not any(version(self.rpc.getblockhash(h)) & Y.LAUNCH_VERSION_QWEN or self.ob(h)["quote"] != "btc"
                          for h in (63, 65, 66)),
              str(obs))
        oa, ob_ = obs[QA], obs[QB]
        check("QWEN curve: a creator draw pays the creator's Qwencoin script, qwen_min_payment when the work owes less",
              all(o["payee"] == "creator" and o["pay_script"] == d.creator_qwen_script.hex() != d.creator_btc_script.hex()
                  and o["pay"] == d.qwen_min_payment for o in (oa, ob_)), f"{oa} {ob_}")
        on = obs[QN]
        check("QWEN curve: a draw with nothing due releases the coinbase at once (spendable, earning)",
              on["pay"] == 0 and on["spendable"] and not on["settled"] and st.info[QN].released
              and all(st.info[h].held and not st.info[h].released for h in (QA, QB, QX, QR, QP)), str(on))
        check("QWEN curve: a draw with something due holds the coinbase until a proof on Qwencoin",
              self.unsettled(QA, QB, QX, QR, QP) and all(obs[h]["pay"] > 0 for h in (QA, QB, QX, QR, QP)), "")
        oh = obs[QH]
        live_scripts = {c.script.hex() for c in st.coins if c.live}
        check("QWEN curve: a holder draw falls on a coin of the launch, to be paid at the coin's own script on Qwencoin",
              oh["payee"] == "holder" and oh["pay"] > 0 and oh.get("coin") and oh["pay_script"] in live_scripts, str(oh))

        # ---- Qwencoin headers in coinbases: at most 8 work checks a block
        self.catch_up("qwen")
        rh = self.relayed("qwen")["height"]
        self.qn.mine(rh + 18 - self.qn.rpc.getblockcount(), self.qaddr)
        hs = [self.header("qwen", rh + i) for i in range(1, 19)]  # hs[i] is at height rh + 1 + i
        known = self.header("qwen", rh)
        loose = hs[0][:4] + NOWHERE + hs[0][36:]                              # its parent is nowhere
        wrong_bits = hs[0][:72] + struct.pack("<I", 0x207FFFFE) + hs[0][76:]  # connects, wrong difficulty
        self.mine([TxOut(0, Y.op_return(b"HFH2" + known + hs[0] + loose + hs[1] + hs[0] + wrong_bits + hs[2] + hs[3])),
                   TxOut(0, Y.op_return(b"HFH2" + b"".join(hs[4:12]))),
                   TxOut(0, Y.op_return(b"HFH2" + hs[12][:79]))], settle=False)                         # 71
        r = self.relayed("qwen")
        check("HFH2: twelve new Qwencoin headers in a coinbase, eight are taken; a known header, one that does not "
              "connect, one with the wrong bits and a repeat cost no check",
              r["height"] == rh + 8 and r["best"] == sha256d(hs[7])[::-1].hex(), f"{r} from {rh}")
        t = bits_to_target(0x207FFFFF)
        no_work = next(x for x in (hs[8][:76] + struct.pack("<I", n) for n in range(1000))
                       if int.from_bytes(sha256d(x), "little") > t)
        self.mine([TxOut(0, Y.op_return(b"HFH2" + no_work + b"".join(hs[8:18])))], settle=False)       # 72
        r = self.relayed("qwen")
        check("HFH2: a header without work costs one of the eight checks (seven of the ten after it are taken)",
              r["height"] == rh + 15 and r["best"] == sha256d(hs[14])[::-1].hex(), f"{r} from {rh}")
        self.catch_up("qwen")                                                                           # 73

        # ---- proofs of the other chain, each with a real confirmed tagged payment there
        ox, ol = self.ob(QX), self.ob(L)
        txb, bhb = self.chain_pay([(bytes.fromhex(ox["pay_script"]), ox["pay"])], [[bytes.fromhex(ox["tag"])]], "btc", 1)
        txq, bhq = self.chain_pay([(bytes.fromhex(ol["pay_script"]), ol["pay"])], [[bytes.fromhex(ol["tag"])]], "qwen", 2)
        self.mine(self.relay_out("btc") + self.relay_out("qwen") +
                  [self.proof(QX, txb, bhb, chain="btc"), self.proof(QX, txb, bhb, chain="btc", tag="qwen"),
                   self.proof(L, txq, bhq, chain="qwen"), self.proof(L, txq, bhq, chain="qwen", tag="btc")],
                  settle=False)                                                                         # 74
        self.stats["proofs ignored"] += 4
        check("a payment on Bitcoin does not settle a QWEN-curve block (HFP1 against the Bitcoin relay, nor as HFP2), "
              "and one on Qwencoin does not settle a BTC-curve block (HFP2 against the Qwencoin relay, nor as HFP1)",
              self.unsettled(QX, L) and self.caught_up("btc") and self.caught_up("qwen"), f"{self.ob(QX)} {self.ob(L)}")

        # ---- another block's tag
        tx, bh = self.chain_pay([(bytes.fromhex(ox["pay_script"]), ox["pay"])], [[bytes.fromhex(self.ob(QR)["tag"])]], "qwen", 2)
        self.mine(self.relay_out("qwen") + [self.proof(QX, tx, bh, chain="qwen")], settle=False)        # 75
        self.stats["proofs ignored"] += 1
        check("HFP2: a payment on Qwencoin to the right script carrying another block's tag does not settle",
              self.unsettled(QX), str(self.ob(QX)))

        # ---- confirmations: one too few, then enough
        tx, bh = self.pay(QX, confirm=1)
        self.mine(self.relay_out("qwen") + [self.proof(QX, tx, bh, chain="qwen")], settle=False)        # 76
        self.stats["proofs ignored"] += 1
        one_conf = self.unsettled(QX) and self.caught_up("qwen")
        self.qn.mine(1, self.qaddr)
        self.mine(self.relay_out("qwen") + [self.proof(QX, tx, bh, chain="qwen", tag="btc")], settle=False)  # 77
        self.stats["proofs ignored"] += 1
        check("HFP1: the right payment on Qwencoin, confirmed enough, proven under the Bitcoin tag does not settle the "
              "QWEN-curve block", self.unsettled(QX) and self.caught_up("qwen"), str(self.ob(QX)))
        self.mine([self.proof(QX, tx, bh, chain="qwen")], settle=False)                                  # 78
        check("HFP2: the right payment on Qwencoin does not settle at 1 confirmation and settles at qwen_confs (2)",
              one_conf and self.settled(QX) and QX in st.info[-1].settled_here, str(self.ob(QX)))

        # ---- one Qwencoin output, two tag lists
        tx, bh = self.chain_pay([(d.creator_qwen_script, oa["pay"])], [[bytes.fromhex(oa["tag"])], [bytes.fromhex(ob_["tag"])]],
                                "qwen", 2)
        self.mine(self.relay_out("qwen") + [self.proof(QB, tx, bh, chain="qwen"), self.proof(QA, tx, bh, chain="qwen")],
                  settle=False)                                                                         # 79
        self.stats["proofs ignored"] += 1
        check("one Qwencoin output, two tag lists: it settles the block the first list names and no other (C2)",
              self.settled(QA) and self.unsettled(QB), f"{self.ob(QA)} {self.ob(QB)}")
        paid = {QB: self.pay(QB)}  # its own payment: proven later, by an ordinary launch transaction

        # ---- a reorg on Qwencoin drops the block a payment was in
        tx, stale = self.pay(QR)  # in a block with one on top: confirmed enough
        self.mine(self.relay_out("qwen"), settle=False)                                                 # 80
        before = self.relayed("qwen")
        fork_height = self.qn.rpc.getblockheader(stale)["height"]
        self.qn.rpc.invalidateblock(stale)
        self.qn.rpc.generatetoaddress(3, self.wq.getnewaddress("", "bech32"))
        now_in = self.wq.gettransaction(tx).get("blockhash")
        if not now_in or now_in == stale or self.qn.rpc.getblockhash(fork_height) == stale:
            raise RuntimeError("the Qwencoin reorg did not move the payment to another block")
        self.mine(self.relay_out("qwen", start=fork_height), settle=False)                              # 81
        r = self.relayed("qwen")
        check("Qwencoin reorg: the relay had the payment's block confirmed twice, then follows the branch with more work",
              before["height"] == fork_height + 1 and self.caught_up("qwen"), f"{before} -> {r}")
        self.mine([self.proof(QR, tx, stale, chain="qwen")], settle=False)                              # 82
        self.stats["proofs ignored"] += 1
        check("ignored: a payment proven in a Qwencoin block that left the best chain", self.unsettled(QR), str(self.ob(QR)))
        self.mine([self.proof(QR, tx, now_in, chain="qwen")], settle=False)                             # 83
        check("the same payment proven in the Qwencoin block that replaced it settles", self.settled(QR), str(self.ob(QR)))

        paid[QP] = self.pay(QP)  # proven in the block that the launch's reorg takes away and puts back (112)
        self.catch_up("qwen")                                                                           # 84
        self.restart("with the QWEN leg under way (coinbases held and released, Qwencoin headers relayed, HFP2 settlements)")
        return paid

    # ------------------------------------------------------------ the chain
    def scenario(self):
        d, MIN = self.d, self.d.sats_min_payment

        # ---- the first blocks of a launch
        for _ in range(6):
            self.mine()
        check("first blocks: nothing earns while every coinbase is held (H1)",
              self.earning() == 0 and all(self.held(h) and not self.ob(h)["spendable"] and not self.ob(h)["draw_known"]
                                          for h in range(1, 7)), f"earning {self.earning()}")
        self.mine(want=self.steer(1, cls=Y.HOLDER))
        o1, v1 = self.ob(1), self.cb_value(1)
        check("first blocks: block 1's holder draw finds nobody holding: owed to no one, its coinbase is free from block 7",
              (o1["payee"], o1["pay"], o1["earning"], o1["spendable"], o1["settled"]) == ("holder", 0, 0, True, False)
              and "pay_script" not in o1 and "coin" not in o1 and self.earning() == v1 > 0, f"{o1} earning {self.earning()} vs {v1}")
        obs = []
        for m in (2, 3, 4):
            self.mine(want=self.steer(m, cls=Y.HOLDER, due=True))
            obs.append(self.ob(m))  # as its draw is made: unpaid, so its own coinbase is still held
        scripts1 = {s.hex() for _n, _v, s in self.cb_coins(1)}
        check("first blocks: the holder draws of blocks 2-4 all fall on block 1's coinbase, the only coins live",
              all(o["payee"] == "holder" and o["pay"] == MIN and o["earning"] == v1 and o["coin"]["txid"] == self.cb_txid(1)
                  and o["pay_script"] in scripts1 and not o["spendable"] and not o["settled"] for o in obs), str(obs))
        self.mine(want=self.steer(U, cls=Y.CREATOR, due=True))            # 11
        self.mine(want=self.steer(A, cls=Y.CREATOR, due=True))            # 12
        self.mine(want=self.steer(7, cls=Y.HOLDER, due=True, beyond=v1))  # 13: blocks 2-4 have settled by now
        o7 = self.ob(7)
        check("first blocks: once other blocks settle, their coinbases share the draws",
              o7["earning"] > v1 and o7["coin"]["txid"] in {self.cb_txid(h) for h in (2, 3, 4)}
              and all(self.ob(h)["settled"] for h in (2, 3, 4)), str(o7))
        self.mine(want=self.steer(B, cls=Y.CREATOR, due=True))            # 14
        self.mine(want=self.steer(W, cls=Y.HOLDER, due=True))             # 15
        self.mine(want=self.steer(E, due=True))                           # 16
        paid_e = self.pay(E)
        self.mine()                                                       # 17
        self.mine(want=self.steer(L, due=True))                           # 18
        paid_l = self.pay(L)
        self.mine(want=self.steer(R, due=True))                           # 19

        # ---- C2: one Bitcoin output, two tag lists, offered as the proof for two blocks
        oa, ob_ = self.ob(A), self.ob(B)
        if (oa["pay_script"], oa["pay"]) != (ob_["pay_script"], ob_["pay"]) or oa["pay_script"] != d.creator_btc_script.hex():
            raise RuntimeError(f"blocks {A} and {B} should both owe the creator the same: {oa} {ob_}")
        txid, bh = self.btc_pay([(d.creator_btc_script, oa["pay"])], [[bytes.fromhex(oa["tag"])], [bytes.fromhex(ob_["tag"])]])
        self.mine(self.relay_out() + [self.proof(B, txid, bh), self.proof(A, txid, bh)], settle=False)  # 20
        check("one Bitcoin output, two tag lists: it settles the block the first list names and no other (C2)",
              self.ob(A)["settled"] and self.ob(A)["spendable"] and not self.ob(B)["settled"] and not self.ob(B)["spendable"],
              f"{self.ob(A)} {self.ob(B)}")

        # ---- proofs that must be ignored, one per block
        ow = self.ob(W)
        w_script, w_pay, w_tag = bytes.fromhex(ow["pay_script"]), ow["pay"], bytes.fromhex(ow["tag"])
        other = next(c.script for c in self.f.state.coins if c.live and c.script != w_script)  # another holder's script
        good = None
        for name, pays, lists, candidate in (
                ("the wrong script", [(self.btc_spk(), w_pay)], [[w_tag]], 0),
                ("one sat short", [(w_script, w_pay - 1)], [[w_tag]], 0),
                ("a named candidate (the payment itself is right)", [(w_script, w_pay)], [[w_tag]], 1),
                ("the tag in a second list (C2)", [(w_script, w_pay)], [[bytes.fromhex(self.ob(U)["tag"])], [w_tag]], 0),
                ("another holder's script with candidate 1", [(other, w_pay)], [[w_tag]], 1)):
            txid, bh = self.btc_pay(pays, lists)
            if name.startswith("a named candidate"):
                good = (txid, bh)
            self.mine(self.relay_out() + [self.proof(W, txid, bh, candidate=candidate)], settle=False)  # 21-25
            self.stats["proofs ignored"] += 1
            check(f"ignored: {name}", not self.ob(W)["settled"] and not self.ob(W)["spendable"], str(self.ob(W)))
        self.restart("with five ignored proofs in its blocks")
        check("ignored proofs stay ignored when the node replays its blocks (C1)", not self.ob(W)["settled"], str(self.ob(W)))
        self.mine(self.relay_out() + [self.proof(W, *good)], settle=False)                               # 26
        check("the same payment with candidate 0 settles", self.ob(W)["settled"] and self.ob(W)["spendable"], str(self.ob(W)))

        # ---- a payment in a Bitcoin block that leaves the best chain
        txid, stale = self.pay(R)
        self.mine(self.relay_out(), settle=False)                                                        # 27
        fork_height = self.btc.rpc.getblockcount()
        self.btc.rpc.invalidateblock(stale)
        # To another address: with the same one the first new block would be the invalidated block again
        # (same parent, same transactions, same coinbase, same second), and bitcoind refuses it.
        self.wb.generatetoaddress(2, self.wb.getnewaddress())
        now_in = self.wb.gettransaction(txid).get("blockhash")
        if not now_in or now_in == stale or self.btc.rpc.getblockhash(fork_height) == stale:
            raise RuntimeError("the Bitcoin reorg did not move the payment to another block")
        self.mine(self.relay_out(start=fork_height), settle=False)                                       # 28
        relay = self.rpc.getbtcrelay()
        check("Bitcoin reorg: the relay follows the branch with more work",
              relay["best"] == self.btc.rpc.getbestblockhash() and relay["height"] == self.btc.rpc.getblockcount(), str(relay))
        self.mine([self.proof(R, txid, stale)], settle=False)                                            # 29
        self.stats["proofs ignored"] += 1
        check("ignored: a payment proven in a Bitcoin block that left the best chain", not self.ob(R)["settled"], str(self.ob(R)))
        self.mine([self.proof(R, txid, now_in, tag="qwen")], settle=False)                               # 30
        self.stats["proofs ignored"] += 1
        check("ignored: the right payment on Bitcoin proven under the Qwencoin tag (HFP2) for a BTC-curve block",
              not self.ob(R)["settled"], str(self.ob(R)))
        self.mine([self.proof(R, txid, now_in)], settle=False)                                           # 31
        check("the same payment proven in the block that replaced it settles", self.ob(R)["settled"], str(self.ob(R)))
        # Bitcoin headers with rubbish between them, a header twice, and a payload that is no header list
        b1, b2 = (bytes.fromhex(self.btc.rpc.getblockheader(x, False)) for x in self.wb.generatetoaddress(2, self.btc_addr))
        junk = b1[:76] + struct.pack("<I", struct.unpack("<I", b1[76:])[0] ^ 0x5A5A5A5A)  # b1 with another nonce
        self.mine([TxOut(0, Y.op_return(b"HFH1" + b1 + junk + b"\xee" * 80 + b1 + b2)),
                   TxOut(0, Y.op_return(b"HFH1" + b2[:79])), TxOut(0, Y.op_return(b"HFH1"))], settle=False)  # 32
        relay = self.rpc.getbtcrelay()
        check("Bitcoin headers: each header of an output is taken on its own (rubbish between two good ones stops nothing)",
              relay["best"] == self.btc.rpc.getbestblockhash() and relay["height"] == self.btc.rpc.getblockcount(), str(relay))

        # ---- redirects: a coinbase may name another Bitcoin script for its output 0, with its first HFY1 output
        x1, x2 = self.btc_spk(), self.btc_spk()
        red = self.mine([TxOut(0, Y.yield_tag_script(x1))])                                             # 33
        bad = self.mine([TxOut(0, Y.yield_tag_script(b"\x51")), TxOut(0, Y.yield_tag_script(x2))])       # 34
        for _ in range(14):
            if self.f.state.info[red].released and self.f.state.info[bad].released:
                break
            self.mine()
        else:
            raise RuntimeError("the redirecting coinbases were not released in time")
        coins_red = self.cb_coins(red)
        if [c[0] for c in coins_red[:2]] != [0, 1] or coins_red[1][2] != self.creator_spk:
            raise RuntimeError(f"coinbase {red} should have a miner output and the creator's: {coins_red}")
        o = self.steer_onto((raw(self.cb_txid(red)), 0), "redirected output")
        check("HFY1 in a coinbase: its output 0 is paid at the script it names", o["pay_script"] == x1.hex(), str(o))
        o = self.steer_onto((raw(self.cb_txid(red)), 1), "the creator's output of the same coinbase")
        check("HFY1 in a coinbase: its other outputs keep their own script (M4)", o["pay_script"] == self.creator_spk.hex(), str(o))
        o = self.steer_onto((raw(self.cb_txid(bad)), 0), "first HFY1 names no earning script")
        check("HFY1 in a coinbase: a first one that names no earning script redirects nothing, and a second is not looked at",
              o["pay_script"] == self.spks[bad % len(self.spks)].hex() != x2.hex(), str(o))

        # ---- on to the first spendable coinbases, with the QWEN leg on the way
        self.until(V + Y.DRAW_DELAY - 1)
        self.mine(want=self.steer(V, due=True))                                                          # 56
        paid_v = self.pay(V)
        qpaid = self.qwen_leg()                                                                          # 57-84
        self.until(QE + Y.DRAW_DELAY - 1)
        self.mine(want=self.steer(QE, due=True))                                                         # 102
        if to_sats(self.w.getbalance()) <= 0:
            raise RuntimeError("no coinbase is spendable at height 102")
        check("the Settler paid a QWEN-curve holder draw on Qwencoin and proved it with HFP2",
              self.settled(QH) and self.ob(QH)["quote"] == "qwen", str(self.ob(QH)))

        # ---- ordinary transactions: transfers, proofs, an HFY1 and an HFH2 that are not in a coinbase
        self.transfer(3)
        self.mine(want=self.steer(QL, due=True))                                                         # 103
        qpaid[QE], qpaid[QL] = self.pay(QE), self.pay(QL)  # proven at their deadlines, after graduation
        txid, bh = self.pay(B)
        for _ in range(2):  # the launch has to know those blocks before the proofs arrive
            self.mine()                                                                                  # 104, 105
        x3 = self.btc_spk()
        own = self.addrs[0]
        self.send_data(self.proof_payload(B, txid, bh))
        self.send_data(self.proof_payload(QB, *qpaid[QB], chain="qwen"))
        self.transfer(2)
        # The last thing the wallet sends before the block, and its output 0 is locked in the wallet:
        # the next draw is steered onto that coin, and a payment made after it could pick it as an
        # input (the wallet chooses its inputs at random), which would leave nothing to draw.
        plain = self.send_data(b"HFY1" + x3, first={own: amount(to_sats(self.w.getbalance()) // 3)})
        self.w.lockunspent(False, [{"txid": plain, "vout": 0}])
        self.mine()                                                                                      # 106
        check("a proof carried by an ordinary transaction settles too (HFP1 and HFP2)", self.settled(B, QB),
              f"{self.ob(B)} {self.ob(QB)}")
        o = self.steer_onto((raw(plain), 0), "an output of an ordinary transaction that carries an HFY1")  # 107
        check("HFY1 in an ordinary transaction is ignored: the coin is paid at its own script (M4)",
              o["pay_script"] == self.spks[0].hex() != x3.hex(), str(o))
        self.w.lockunspent(True, [{"txid": plain, "vout": 0}])

        # ---- C3: 60 self-transfers of one coin; and Qwencoin headers in an ordinary transaction
        churn_txid = self.w.sendtoaddress(self.addrs[2], amount(to_sats(self.w.getbalance()) // 10))
        tx = self.rpc.getrawtransaction(churn_txid, True)
        vout = next(o["n"] for o in tx["vout"] if o["scriptPubKey"]["hex"] == self.spks[2].hex())
        # that output is spent by hand below, sixty times over: the wallet must not pick it (or what it
        # becomes) as an input of anything it funds itself in between
        self.w.lockunspent(False, [{"txid": churn_txid, "vout": vout}])
        self.qn.mine(2, self.qaddr)
        qbefore = self.relayed("qwen")
        self.send_data(b"HFH2" + self.header("qwen", qbefore["height"] + 1) + self.header("qwen", qbefore["height"] + 2))
        self.mine(settle=False)                                                                          # 108
        check("HFH2 in a transaction that is not the coinbase is ignored (two new Qwencoin headers, none taken)",
              self.relayed("qwen") == qbefore and any(Y.tagged_return(s, b"HFH2") is not None
                                                       for t_ in self.f.blocks[-1].txs[1:] for _v, s in t_.outputs),
              str(self.relayed("qwen")))
        value, fee, ok, detail = to_sats(tx["vout"][vout]["value"]), 2000, True, ""
        prev = (churn_txid, vout)
        for _ in range(3):                                                                               # 109, 110, 111
            before = self.earning()
            for _ in range(20):
                value -= fee
                rawtx = self.w.createrawtransaction([{"txid": prev[0], "vout": prev[1]}], [{self.addrs[2]: amount(value)}])
                prev = (self.rpc.sendrawtransaction(self.w.signrawtransactionwithwallet(rawtx)["hex"]), 0)
            h = self.mine(settle=False)
            m = h - Y.DRAW_DELAY
            freed = self.cb_value(m) if self.held(m) and self.ob(m)["pay"] == 0 else 0  # what this block's own draw released
            mined = 0 if self.held(h) else self.cb_value(h)
            if self.earning() != before - 20 * fee + freed + mined or len(self.f.blocks[h].txs) != 21:
                ok, detail = False, f"block {h}: {before} -> {self.earning()}, fees {20 * fee}, freed {freed}, mined {mined}"
        live_churn = [c for c in self.f.state.coins if c.live and c.txid == raw(prev[0])]
        check("60 self-transfers: the earning value moves by the fees and nothing else, and one coin is left of them (C3)",
              ok and len(live_churn) == 1 and live_churn[0].value == value, detail)
        self.w.lockunspent(True)

        # ---- a block with a settlement on each chain, a spend and relayed headers of both chains, undone and redone
        self.until(111)
        known = bytes.fromhex(self.btc.rpc.getblockheader(self.btc.rpc.getblockhash(self.rpc.getbtcrelay()["height"]), False))
        self.transfer(1)
        relays = lambda: (self.rpc.getbtcrelay()["height"], self.rpc.getqwenrelay()["height"])  # noqa: E731
        before = (self.earning(), relays(), self.f.state.snapshot())
        x = self.mine([TxOut(0, Y.op_return(b"HFH1" + known)), self.proof(V, *paid_v),
                       self.proof(QP, *qpaid[QP], chain="qwen")])                                        # 112
        xi, xhash = self.f.state.info[x], self.rpc.getblockhash(x)
        if not (V in xi.settled_here and QP in xi.settled_here and xi.killed and xi.relayed and xi.qrelayed
                and len(self.f.blocks[x].txs) > 1):
            raise RuntimeError(f"block {x} should settle on both chains, spend and relay both chains' headers: {xi}")
        during = (self.earning(), relays())
        self.rpc.invalidateblock(xhash)
        self.compare(f"invalidateblock {x}")
        undone = ((self.earning(), relays(), self.f.state.snapshot()) == before
                  and not self.ob(V)["settled"] and not self.ob(QP)["settled"])
        self.rpc.reconsiderblock(xhash)
        self.compare(f"reconsiderblock {x}")
        check("reorg: settlements on both chains, a spend and relayed headers of both chains are undone with their block "
              "and come back with it",
              undone and during[0] != before[0] and during[1][0] > before[1][0] and during[1][1] > before[1][1]
              and (self.earning(), relays()) == during and self.settled(V, QP), f"before {before[:2]} during {during}")
        self.until(114, transfers=1)
        draws_then = [(self.ob(m).get("pay"), self.ob(m).get("payee"), self.ob(m).get("pay_script")) for m in (106, 107, 108)]
        for hh in (114, 113, 112):  # for good, one block at a time: another branch takes over from 111
            self.rpc.invalidateblock(self.rpc.getblockhash(hh))
            self.compare(f"invalidateblock {hh} (the tip)")
        check("reorg: three blocks back, the draws they made are gone and the settlements with them",
              self.tip == 111 and not self.ob(V)["settled"] and not self.ob(QP)["settled"]
              and not any(self.ob(m)["draw_known"] for m in (106, 107, 108)))
        self.transfer(1)
        self.mine(self.relay_out() + self.relay_out("qwen"), settle=False)                               # 112'
        self.until(114)
        self.mine([self.proof(V, *paid_v), self.proof(QP, *qpaid[QP], chain="qwen")])                   # 115'
        draws_now = [(self.ob(m).get("pay"), self.ob(m).get("payee"), self.ob(m).get("pay_script")) for m in (106, 107, 108)]
        check("reorg: the competing branch made its own draws for the same blocks, and the model's undo equals a replay",
              self.rpc.getblockhash(x) != xhash and self.settled(V, QP) and all(self.ob(m)["draw_known"] for m in (106, 107, 108))
              and self.f.state.snapshot() == self.f.rebuilt().snapshot(), f"{draws_then} -> {draws_now}")

        # ---- the settlement deadline
        self.until(E + DEADLINE - 1)
        oe = self.ob(E)
        self.mine([self.proof(E, *paid_e)])                                                              # 120
        check("deadline: a proof in the last block that may carry it settles",
              oe["deadline_height"] == self.tip == E + DEADLINE and not oe["settled"] and self.ob(E)["settled"], str(self.ob(E)))
        self.until(L + DEADLINE)
        self.mine([self.proof(L, *paid_l)])                                                              # 123
        self.stats["proofs ignored"] += 1
        check("deadline: one block later the same kind of proof is ignored, for good",
              self.tip == L + DEADLINE + 1 and not self.ob(L)["settled"] and not self.ob(L)["spendable"], str(self.ob(L)))
        self.mine()                                                                                      # 124
        self.restart("after the reorgs")

        # ---- graduation by the BTC curve, and merge-mined blocks
        info = self.rpc.getlaunchinfo()
        if info["graduated"]:
            raise RuntimeError(f"the launch graduated at {info['graduation_height']}, before the plan expects it")
        for _ in range(120):
            self.transfer(1)
            h = self.mine(own=True)
            if self.rpc.getlaunchinfo()["graduated"]:
                break
            self.settler.add_block(h, self.rpc.getblockhash(h))
        info = self.rpc.getlaunchinfo()
        g = info["graduation_height"]  # the last block on the curve; the Settler does not know it: its proof comes at the very end
        if not info["graduated"] or g != self.tip:
            raise RuntimeError(f"expected to stand on the graduation block: {info['graduated']} {g} {self.tip}")
        check("graduation: the BTC curve sold out first; the QWEN curve's unsold part is never minted",
              info["graduated_by"] == "btc" and info["curves"]["btc"]["supply"] == d.graduation_tokens
              and 0 < info["curves"]["qwen"]["supply"] < d.graduation_tokens and info["curves"]["qwen"]["blocks"] >= 20
              and info["curve_supply"] == d.graduation_tokens + info["curves"]["qwen"]["supply"], str(info["curves"]))
        differ, paid_g = 0, None
        for _ in range(8):
            m = self.tip + 1 - Y.DRAW_DELAY
            oblig = self.ob(m)
            minimum = d.min_payment(oblig["quote"])

            def steer(own_hash, owed=oblig["owed"], must_be_due=(m == g), minimum=minimum):
                """The parent's hash has to give a draw the block's own hash would not have given."""
                own = Y.compute_draw(owed, minimum, Y.draw_seed(d.id, own_hash))

                def want(parent_hash):
                    got = Y.compute_draw(owed, minimum, Y.draw_seed(d.id, parent_hash))
                    return got != own and (got[0] > 0 or not must_be_due)
                return want
            h, own_hash = self.mine_merged(steer)
            blk = self.f.blocks[h]
            if blk.hash != own_hash or blk.work_hash == blk.hash:
                raise RuntimeError(f"block {h} is not the merge-mined block that was asked for")
            if oblig["curve"]:
                o = self.ob(m)
                own_draw = Y.compute_draw(oblig["owed"], minimum, Y.draw_seed(d.id, blk.hash))
                parent_draw = Y.compute_draw(oblig["owed"], minimum, Y.draw_seed(d.id, blk.work_hash))
                if (o["pay"], S.PAYEE_NAMES.index(o["payee"])) == parent_draw != own_draw and o["earning"] > 0:
                    differ += 1
            if m == g:
                paid_g = self.pay(g)
        check("graduation: the block that crosses is the last on the curve; later blocks owe nothing and earn at once",
              self.ob(g)["curve"] and self.ob(g)["owed"] > 0 and not self.ob(g + 1)["curve"] and self.ob(g + 1)["owed"] == 0
              and self.ob(g + 1)["spendable"] and "pay" not in self.ob(g + 2), f"{self.ob(g)} {self.ob(g + 1)}")
        check("merge-mined: the draw's seed is the hash of the parent header, the hash that carried the work (M1)",
              differ == 6, f"{differ} of the 6 draws made by merge-mined blocks for curve blocks follow the parent's hash")
        self.until(self.tip + 6, transfers=1)
        self.restart("past graduation")

        # ---- the settlement deadline of a QWEN-curve block (the QWEN leg stays open after graduation)
        self.until(QE + DEADLINE - 1)
        oe = self.ob(QE)
        self.mine([self.proof(QE, *qpaid[QE], chain="qwen")])                                            # 206
        check("QWEN deadline: an HFP2 proof in the last block that may carry it settles, past graduation",
              oe["quote"] == "qwen" and oe["deadline_height"] == self.tip == QE + DEADLINE and not oe["settled"]
              and self.settled(QE), str(self.ob(QE)))
        self.until(QL + DEADLINE)
        self.mine([self.proof(QL, *qpaid[QL], chain="qwen")])                                            # 208
        self.stats["proofs ignored"] += 1
        check("QWEN deadline: one block later the same kind of proof is ignored, for good",
              self.tip == QL + DEADLINE + 1 and self.unsettled(QL), str(self.ob(QL)))

        # ---- the end of both legs: settle_deadline blocks after the last curve block
        close = g + DEADLINE
        while self.tip < close - 1:
            if self.tip % 4 == 0:
                self.transfer(1)
            self.mine()
        st = self.f.state
        held = sum(v for i in st.info if i.held and not i.released for _t, _n, v, _s in i.held)
        utxo = to_sats(self.rpc.gettxoutsetinfo("none")["total_amount"])
        wrong = [c for c in st.coins if (self.rpc.gettxout(c.txid[::-1].hex(), c.vout, False) is not None) != c.live]
        open_earning = self.earning()
        check("the UTXO set: every coin the model has live is unspent on the node, every dead one spent, and live + held is all there is (C3)",
              not wrong and len(st.coins) > 300 and utxo == st.live_value() + held == open_earning + held and open_earning > 0,
              f"{len(wrong)} of {len(st.coins)} coins disagree; utxo {utxo}, live {st.live_value()}, held {held}, node earning {open_earning}")
        check("the Settler keeps relaying while the legs are open", not self.settler.sats_leg_over() and not st.closed())
        og = self.ob(g)
        self.transfer(1)
        self.mine([self.proof(g, *paid_g)])                                                              # g + 110
        last = st.info[-1]
        check("the end: the block at the last curve block's deadline is still looked at (its proof settles, its spend and "
              "both chains' headers count)",
              self.tip == close == og["deadline_height"] and og["pay"] > 0 and not og["settled"] and self.ob(g)["settled"]
              and g in last.settled_here and last.killed and last.relayed and last.qrelayed and st.tracked() == close,
              f"{self.ob(g)}")
        check("the end: from that block on nothing earns", st.closed() and self.earning() == 0 and st.live_value() > 0, str(self.earning()))
        at_close = ([self.ob(h) for h in range(close + 1)], self.rpc.getbtcrelay(), self.rpc.getqwenrelay(), len(st.coins),
                    st.live_value())
        btc_then, qwen_then = self.btc.rpc.getblockcount(), self.qn.rpc.getblockcount()
        for _ in range(6):  # spends, new headers of both chains and proofs of both, in blocks nobody looks at any more
            self.wb.generatetoaddress(1, self.btc_addr)
            self.qn.mine(1, self.qaddr)
            self.transfer(1)
            self.mine(self.relay_out() + self.relay_out("qwen") + [self.proof(L, *paid_l),
                                                                   self.proof(QL, *qpaid[QL], chain="qwen")], settle=False)
        tip = self.tip
        beyond = [self.ob(h) for h in range(close + 1, tip + 1)]
        now = ([self.ob(h) for h in range(close + 1)], self.rpc.getbtcrelay(), self.rpc.getqwenrelay(), len(st.coins),
               st.live_value())
        check("past the end: spends, headers and proofs of both chains in later blocks change nothing (obligations, the relays, the coins)",
              now == at_close
              and self.btc.rpc.getblockcount() == btc_then + 6 and now[1]["height"] <= btc_then
              and self.qn.rpc.getblockcount() == qwen_then + 6 and now[2]["height"] <= qwen_then and self.earning() == 0
              and st.tracked() == close and len(st.above) == 6 and all(len(b_.txs) > 1 for b_ in self.f.blocks[close + 1:]),
              f"same obligations {now[0] == at_close[0]}; relays {at_close[1:3]} -> {now[1:3]}; coins {at_close[3:]} -> {now[3:]}; "
              f"bitcoin at {self.btc.rpc.getblockcount()}, qwencoin at {self.qn.rpc.getblockcount()}; earning {self.earning()}; "
              f"tracked {st.tracked()} of {close}; above {len(st.above)}; "
              f"txs per later block {[len(b_.txs) for b_ in self.f.blocks[close + 1:]]}")
        check("past the end: a later block owes nothing, is spendable, has no draw, and answers with its own hash",
              all(o == {"height": h, "hash": self.rpc.getblockhash(h), "curve": False, "quote": "btc", "owed": 0,
                        "draw_known": False, "draw_height": h + Y.DRAW_DELAY, "settled": False, "spendable": True,
                        "deadline_height": h + DEADLINE, "tag": Y.pay_tag(d.id, raw(self.rpc.getblockhash(h))).hex()}
                  for h, o in enumerate(beyond, close + 1)),
              str(beyond[0]))
        check("the Settler stops relaying headers once the legs are over",
              self.settler.sats_leg_over() and self.settler.relay_outputs() == [])
        whole = [self.ob(h) for h in range(tip + 1)]
        back = self.rpc.getblockhash(close - 3)
        self.rpc.invalidateblock(back)
        self.compare(f"invalidateblock {close - 3}, three blocks before the end")
        reopened = (self.tip == close - 4 and not st.closed() and self.earning() > 0 and not self.ob(g)["settled"]
                    and self.rpc.getbtcrelay()["height"] < at_close[1]["height"])
        self.rpc.reconsiderblock(back)
        self.compare(f"reconsiderblock {close - 3}")
        check("a reorg from below the end reopens the state, and connecting the blocks again closes it with the same contents",
              reopened and self.tip == tip and [self.ob(h) for h in range(tip + 1)] == whole and self.earning() == 0
              and self.rpc.getbtcrelay() == at_close[1] and self.rpc.getqwenrelay() == at_close[2]
              and st.snapshot() == self.f.rebuilt().snapshot(), f"reopened {reopened}")
        self.rpc.invalidateblock(self.rpc.getblockhash(tip - 2))
        self.compare("a reorg entirely past the end")
        for _ in range(5):
            self.mine(self.relay_out() + self.relay_out("qwen"), settle=False)
        check("a reorg entirely past the end changes nothing that is tracked",
              self.tip == tip + 2 and [self.ob(h) for h in range(close + 1)] == at_close[0] and self.rpc.getbtcrelay() == at_close[1]
              and self.rpc.getqwenrelay() == at_close[2] and self.rpc.getblockhash(tip) != whole[tip]["hash"] and self.earning() == 0)
        self.restart("after the legs are over")

        # ---- what the whole chain adds up to
        ou = self.ob(U)
        drawn = {self.ob(h).get("coin", {}).get("txid") for h in range(1, close + 1)}
        check("never settled, never earning: block 5 was never paid, is in no draw and never entered the earning value (H1)",
              ou["draw_known"] and ou["pay"] > 0 and not ou["settled"] and not ou["spendable"] and self.tip > ou["deadline_height"]
              and self.cb_txid(U) not in drawn and not st.info[U].released and all(c.txid != raw(self.cb_txid(U)) for c in st.coins)
              and all(self.rpc.gettxout(self.cb_txid(U), n) is not None for n, _v, _s in self.cb_coins(U)), str(ou))
        check("the model's own undo equals a replay of the node's chain from nothing", st.snapshot() == self.f.rebuilt().snapshot())
        q = S.QWEN
        cover = {
            "holder draws on a coin": sum(1 for i in st.info if i.coin is not None),
            "holder draws with nobody holding": sum(1 for i in st.info if i.draw_known and i.payee == Y.HOLDER and i.earning == 0),
            "coinbases released by a draw with nothing due": sum(1 for i in st.info if i.drew >= 0 and i.drew in i.released_here),
            "coinbases released by a settlement": sum(len(i.settled_here) for i in st.info),
            "coinbases still held at the end": sum(1 for i in st.info if i.held and not i.released),
            "coins spent": sum(len(i.killed) for i in st.info),
            "coins": len(st.coins),
            "Bitcoin headers relayed": sum(len(i.relayed) for i in st.info),
            "Qwencoin headers relayed": sum(len(i.qrelayed) for i in st.info),
            "QWEN-curve blocks": sum(1 for i in st.info if i.curve and i.quote == q),
            "QWEN-curve draws with something due": sum(1 for i in st.info if i.curve and i.quote == q and i.pay > 0),
            "QWEN-curve draws with nothing due": sum(1 for i in st.info if i.curve and i.quote == q and i.draw_known and i.pay == 0),
            "QWEN-curve blocks settled by HFP2": sum(1 for i in st.info if i.curve and i.quote == q and i.settled),
            "draws made by merge-mined blocks": sum(1 for b_, i in zip(self.f.blocks, st.info) if i.drew >= 0 and b_.work_hash != b_.hash),
            "blocks past the end": len(st.above),
            **self.stats, "settler": self.settler.status()}
        print("   " + ", ".join(f"{k}: {v}" for k, v in cover.items()), flush=True)
        check("coverage: every path of the rules was taken at least once",
              all(v > 0 for k, v in cover.items() if k != "settler") and self.stats["proofs ignored"] >= 18
              and self.stats["restarts"] == 5 and self.stats["blocks undone"] >= 7, str(cover))

    # ------------------------------------------------------------ a second launch: graduation by either curve
    def second_launch(self):
        """QGR: both curves are mined until each is one block from selling out. The BTC curve sells out on
        one branch, which is then taken off block by block; the QWEN curve sells out on the other. Its
        legs end settle_deadline blocks later, with an HFP2 proof of the QWEN-curve block that crossed."""
        self.node.stop()
        self.nodes.remove(self.node)
        self.path = os.path.join(self.dir, "QGR.json")
        d = mk_launch("QGR", self.creator_spk, QGR_BLOCKS, int(time.time()) - DAY)
        for name in ("btc", "qwen"):  # anchored at today's tips: few headers to catch up
            height = self.chain(name)[0].getblockcount()
            setattr(d, f"{name}_anchor_header", self.header(name, height))
            setattr(d, f"{name}_anchor_height", height)
            setattr(d, f"{name}_anchor_period_time", struct.unpack("<I", self.header(name, height - height % 2016)[68:72])[0])
        d.settle_deadline = DEADLINE
        d.creator_btc_script, d.creator_qwen_script = self.btc_spk(), self.qwen_spk()
        D.validate(d)
        d.grind_genesis()
        with open(self.path, "w") as f:
            f.write(d.dumps())
        self.d = d = D.load(self.path)
        self.args = [f"-launch={self.path}", "-datacarriersize=1000000"]
        self.node_name, self.settler_name, self.reserved = "node-qgr", "settler-qgr.json", set()
        self.curve_of = lambda h: "qwen" if h % 2 else "btc"
        self.f, self.T = None, d.genesis_time + 100
        self.boot()
        self.addrs = [self.w.getnewaddress("", kind) for kind in ("legacy", "p2sh-segwit", "bech32", "bech32m")]
        self.spks = [bytes.fromhex(self.w.getaddressinfo(x)["scriptPubKey"]) for x in self.addrs]
        self.f = S.Follower(d, self.rpc)
        self.compare("QGR: the genesis block")
        gw = d.graduation_work
        for _ in range(4 * QGR_BLOCKS + 4):
            wb, wq = self.f.work[self.tip]
            w = int(self.rpc.getlaunchinfo()["next"]["work"], 16)
            by_btc, by_qwen = wb + w >= gw, wq + w >= gw
            if by_btc and by_qwen:
                break
            self.mine(curve="qwen" if by_btc else "btc" if by_qwen else None)
        else:
            raise RuntimeError("QGR: the curves did not both come within a block of selling out")
        fork = self.tip
        before = self.rpc.getlaunchinfo()
        check("QGR: both curves are mined and each is one block from selling out; nothing has graduated",
              not before["graduated"] and before["graduated_by"] is None and before["graduation_height"] == -1
              and before["curves"]["btc"]["blocks"] >= 3 and before["curves"]["qwen"]["blocks"] >= 3, str(before["curves"]))
        x1 = self.mine(curve="btc")
        info = self.rpc.getlaunchinfo()
        btc_branch = (info["graduated_by"] == "btc" and info["graduation_height"] == x1
                      and info["curves"]["btc"]["supply"] == d.graduation_tokens
                      and info["curve_supply"] == d.graduation_tokens + before["curves"]["qwen"]["supply"])
        self.mine()
        self.mine()
        for hh in (x1 + 2, x1 + 1, x1):
            self.rpc.invalidateblock(self.rpc.getblockhash(hh))
            self.compare(f"QGR: invalidateblock {hh} (the tip)")
        info = self.rpc.getlaunchinfo()
        check("QGR: graduation by the BTC curve on one branch, taken off block by block: not graduated again",
              btc_branch and self.tip == fork and not info["graduated"] and info["graduated_by"] is None
              and info["curves"] == before["curves"], str(info["curves"]))
        g = self.mine(curve="qwen", own=True, top=True)
        info = self.rpc.getlaunchinfo()
        check("QGR: graduation by the QWEN curve on the other branch: the BTC curve's unsold part is never minted",
              info["graduated_by"] == "qwen" and info["graduation_height"] == g == fork + 1
              and info["curves"]["qwen"]["supply"] == d.graduation_tokens
              and info["curves"]["btc"]["supply"] == before["curves"]["btc"]["supply"] < d.graduation_tokens
              and info["curve_supply"] == d.graduation_tokens + before["curves"]["btc"]["supply"]
              and self.ob(g)["quote"] == "qwen", f"{info['graduated_by']} {info['curves']}")
        self.until(g + Y.DRAW_DELAY)
        og = self.ob(g)
        if not og["pay"]:
            raise RuntimeError(f"QGR: the crossing block should owe something: {og}")
        paid_g = self.pay(g)
        self.until(g + Y.DRAW_DELAY + 2)
        self.restart("of the second launch, after it graduated on the QWEN curve")
        close = g + DEADLINE
        self.until(close - 1)
        st = self.f.state
        check("QGR: the legs stay open up to the last curve block's deadline", not st.closed() and self.earning() > 0
              and not self.settler.sats_leg_over() and self.unsettled(g))
        self.mine([self.proof(g, *paid_g, chain="qwen")])
        check("QGR: the end: an HFP2 proof of the QWEN-curve block that crossed, in the last block that may, settles; "
              "from that block on nothing earns",
              self.tip == close == og["deadline_height"] and self.settled(g) and st.closed() and self.earning() == 0
              and g in st.info[-1].settled_here, str(self.ob(g)))
        at_close = ([self.ob(h) for h in range(close + 1)], self.rpc.getbtcrelay(), self.rpc.getqwenrelay())
        for _ in range(3):
            self.wb.generatetoaddress(1, self.btc_addr)
            self.qn.mine(1, self.qaddr)
            self.mine(self.relay_out() + self.relay_out("qwen") + [self.proof(g, *paid_g, chain="qwen")], settle=False)
        check("QGR: past the end, headers of both chains and proofs change nothing; the Settler stops relaying",
              ([self.ob(h) for h in range(close + 1)], self.rpc.getbtcrelay(), self.rpc.getqwenrelay()) == at_close
              and len(st.above) == 3 and self.settler.relay_outputs() == [])
        check("QGR: the model's own undo equals a replay of the node's chain from nothing",
              st.snapshot() == self.f.rebuilt().snapshot())


ALL_AGREE = ("the node equals the model after every block, restart and reorg: getmintobligation at every height, earning, "
             "both curves, the Bitcoin and the Qwencoin relay")


def main():
    ap = argparse.ArgumentParser(description="Both legs of a launch: a real node against the model, block by block.")
    ap.add_argument("--hashfund", required=True, help="path to hashfund")
    ap.add_argument("--bitcoind", required=True, help="path to Bitcoin Core's bitcoind (regtest; it plays Qwencoin too)")
    ap.add_argument("--workdir", help="where to keep chains and wallets (must be fresh; default: a temporary directory)")
    a = ap.parse_args()
    run, t0, crashed = Run(a), time.time(), False
    try:
        run.start()
        run.scenario()
        run.second_launch()
        check(ALL_AGREE, True, "")
    except Mismatch as e:
        check(ALL_AGREE, False, f"after {e.where}: {len(e.diffs)} differences")
        for line in e.diffs[:40]:
            print("        " + line, flush=True)
        if len(e.diffs) > 40:
            print(f"        ... and {len(e.diffs) - 40} more", flush=True)
    except Exception:  # noqa: BLE001
        crashed = True
        traceback.print_exc()
    finally:
        run.stop()
    failed = [k for k, v in RESULTS.items() if not v]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed in {time.time() - t0:.0f} s; {run.stats}; data in {run.dir}")
    for k in failed:
        print(f"FAILED: {k}")
    if crashed:
        print("STOPPED by an error before the end (see the traceback above)")
    sys.exit(1 if failed or crashed or not RESULTS else 0)


if __name__ == "__main__":
    main()
