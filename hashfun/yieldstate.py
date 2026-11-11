"""The sats leg's state machine, as a plain model.

The node keeps this state in src/launchyieldstate.cpp. This file is written from the rules, not
from that code, and it is the reference the node is compared with (hashfun/tests/yield_regtest.py):
lists and linear scans, nothing clever, nothing cached.

The rules it implements:

  Coins. A coin is a transaction output with a positive value and an earning script. Its yield
  script is its own script (a coinbase may redirect its output 0: yieldmodel.registered_outputs).
  Coins are kept in the order they are appended. A coin is live from the moment it is appended
  until a transaction input spends its outpoint; then it is dead and stays in the list, weight 0.

  Held coinbases. The coins of the coinbase of a block that is on the curve and owes sats are not
  appended when the block is connected. They are appended later, all at once: at that block's draw
  if the draw says nothing is due, or when a payment proof for that block is accepted. Never
  otherwise.

  Connecting block B at height h:
    1. the draw of block m = h - 6, if m >= 1 and m is on the curve. Seed from the hash that
       carried B's work (B's hash, or the parent block's hash when B is merge-mined). A holder
       draw is one point into the value of the coins that are live right now, that is at the end
       of block h - 1; with nothing live, the holders' share is owed to no one (pay becomes 0, it
       does not go to the creator). Who is paid is decided only when something is due, it is
       fixed here, and nothing later changes it.
    2. B's transactions in order: inputs kill coins; HFH1 outputs relay Bitcoin headers and HFP1
       outputs settle, in output order; then the transaction's own coins are appended (or held).

  The end. Let c be the height of the last block on the curve and D the settlement deadline. The
  last draw happens at c + 6 and no proof counts above c + D, so once the tip is not a curve block
  and stands at c + D or higher the sats leg is over: the state is closed. Blocks above that
  height are not looked at (their coins, spends, headers and proofs change nothing; only their
  hashes are kept, to answer for them). Nothing earns any more. A reorg that goes back below c + D
  reopens the state by the ordinary undo.

  The state is a pure function of the chain's blocks: replay(blocks) is the definition, and
  connect() followed by disconnect() has to be the identity.
"""
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Callable, Dict, List, Optional, Tuple

from . import yieldmodel as Y
from .crypto import sha256d
from .ser import Reader, Tx, TxOut, work_from_bits

DRAW_DELAY = Y.DRAW_DELAY
PAYEE_NAMES = ("holder", "creator", "dev")
Outpoint = Tuple[bytes, int]  # (txid in internal byte order, output index)


@dataclass(frozen=True)
class Params:
    launch_id: bytes  # internal byte order
    min_payment: int
    settle_deadline: int
    btc_confs: int
    creator_btc_script: bytes
    dev_btc_script: bytes = Y.DEV_BTC_SCRIPT

    @classmethod
    def from_launch(cls, d) -> "Params":
        return cls(d.id, d.sats_min_payment, d.settle_deadline, d.btc_confs, d.creator_btc_script)


@dataclass
class StateTx:
    txid: bytes  # internal byte order
    coinbase: bool
    inputs: List[Outpoint]            # empty for a coinbase
    outputs: List[Tuple[int, bytes]]  # (value, scriptPubKey), in output order


@dataclass
class Block:
    height: int
    hash: bytes       # internal byte order
    work_hash: bytes  # the hash that carried the work: the block's own, or its auxpow parent's
    curve: bool
    owed: int
    txs: List[StateTx]


# ---------------------------------------------------------------- the Bitcoin header relay
class Relay:
    """What the state asks of the Bitcoin header relay."""

    def accept(self, header: bytes) -> bool:  # True if the header was added (and must be undone)
        raise NotImplementedError

    def remove(self, hash_: bytes) -> None:
        raise NotImplementedError

    def confirmations(self, hash_: bytes) -> int:  # 0: unknown, or not on the best chain
        raise NotImplementedError

    def merkle_root(self, hash_: bytes) -> Optional[bytes]:
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError


class HeaderRelay(Relay):
    """The real rules: yieldmodel.BtcChain from the launch's anchor."""

    def __init__(self, anchor_header: bytes, anchor_height: int, anchor_period_time: int, regtest: bool):
        self.chain = Y.BtcChain(anchor_header, anchor_height, anchor_period_time, regtest)

    @classmethod
    def from_launch(cls, d) -> "HeaderRelay":
        return cls(d.btc_anchor_header, d.btc_anchor_height, d.btc_anchor_period_time, d.btc_regtest)

    def accept(self, header: bytes) -> bool:
        return self.chain.accept(header)[0]

    def remove(self, hash_: bytes) -> None:
        self.chain.remove(hash_)

    def confirmations(self, hash_: bytes) -> int:
        return self.chain.confirmations(hash_)

    def merkle_root(self, hash_: bytes) -> Optional[bytes]:
        n = self.chain.nodes.get(hash_)
        return n.merkle_root if n else None

    def best(self) -> bytes:
        return self.chain.best

    def best_height(self) -> int:
        return self.chain.nodes[self.chain.best].height

    def size(self) -> int:
        return len(self.chain.nodes)

    def snapshot(self):
        return self.chain.best, tuple(sorted(self.chain.nodes))


class StubRelay(Relay):
    """For tests: Bitcoin blocks are what the test says they are. blocks: hash -> (confirmations,
    merkle root). Relayed headers are counted (and undone) but mean nothing."""

    def __init__(self, blocks: Optional[Dict[bytes, Tuple[int, bytes]]] = None):
        self.blocks = blocks if blocks is not None else {}  # shared with the test, which may add to it
        self.headers: List[bytes] = []

    def accept(self, header: bytes) -> bool:
        h = sha256d(header)
        if h in self.headers:
            return False
        self.headers.append(h)
        return True

    def remove(self, hash_: bytes) -> None:
        self.headers.remove(hash_)

    def confirmations(self, hash_: bytes) -> int:
        return self.blocks.get(hash_, (0, b""))[0]

    def merkle_root(self, hash_: bytes) -> Optional[bytes]:
        return self.blocks[hash_][1] if hash_ in self.blocks else None

    def snapshot(self):
        return tuple(self.headers)


# ---------------------------------------------------------------- the state
@dataclass
class Coin:
    txid: bytes
    vout: int
    value: int
    script: bytes  # where its yield is paid on Bitcoin
    live: bool = True


@dataclass
class Info:
    """One per height: what the block is, its draw, and what connecting it did (for undo)."""
    hash: bytes
    curve: bool
    owed: int
    held: Optional[List[Tuple[bytes, int, int, bytes]]] = None  # this block's coinbase coins, if they have to wait
    released: bool = False                                     # ... and whether they have been appended since
    draw_known: bool = False
    seed: bytes = b""
    pay: int = 0                                   # sats due (0 also when a holder draw found nobody holding)
    payee: int = Y.HOLDER                          # the class the draw gave, also when nothing is due
    pay_script: bytes = b""                        # the Bitcoin script to pay; empty when nothing is due
    coin: Optional[Tuple[bytes, int, int]] = None  # the payee coin of a holder draw: (txid, vout, value)
    earning: int = 0                               # live value at the draw
    settled: bool = False
    # what connecting this block did
    coins_before: int = 0
    killed: List[int] = field(default_factory=list)        # indexes of coins its inputs spent
    released_here: List[int] = field(default_factory=list)  # mint heights whose held coins it appended
    settled_here: List[int] = field(default_factory=list)   # mint heights it settled
    relayed: List[bytes] = field(default_factory=list)      # Bitcoin headers it added
    drew: int = -1                                         # the mint height whose draw it made


class State:
    def __init__(self, params: Params, relay: Relay):
        self.p, self.relay = params, relay
        self.coins: List[Coin] = []
        self.info: List[Info] = []    # one per tracked height, from genesis
        self.above: List[bytes] = []  # hashes of the blocks past the end of the sats leg: nothing else of them is kept

    @classmethod
    def replay(cls, params: Params, relay_factory: Callable[[], Relay], blocks: List[Block]) -> "State":
        """The state of a chain, from nothing: the definition everything else must equal."""
        s = cls(params, relay_factory())
        for b in blocks:
            s.connect(b)
        return s

    # ---- queries
    def height(self) -> int:
        """The height of the chain's tip."""
        return len(self.info) - 1 + len(self.above)

    def tracked(self) -> int:
        """The last height whose block was looked at."""
        return len(self.info) - 1

    def last_curve(self) -> int:
        """The height of the last block on the curve (0: none)."""
        return max((h for h, i in enumerate(self.info) if i.curve), default=0)

    def closed(self) -> bool:
        """The sats leg is over: the tip is off the curve and settle_deadline blocks past the last
        curve block, so nothing can be drawn or settled any more."""
        return (bool(self.info) and not self.info[-1].curve
                and self.tracked() >= self.last_curve() + self.p.settle_deadline)

    def live_value(self) -> int:
        """The sum of the values of all live coins: what a draw is taken over."""
        return sum(c.value for c in self.coins if c.live)

    def earning(self) -> int:
        """What a node reports as earning: the live value, and 0 once the sats leg is over."""
        return 0 if self.closed() else self.live_value()

    def spendable(self, height: int) -> bool:
        if not 0 <= height < len(self.info):
            return True
        i = self.info[height]
        if not i.curve or i.owed == 0:
            return True
        if not i.draw_known:
            return False
        return i.pay == 0 or i.settled

    def obligation(self, height: int) -> dict:
        """What the node reports as `getmintobligation HEIGHT`."""
        if height > self.tracked():  # a block past the end of the sats leg: it owes nothing and never did
            hash_ = self.above[height - len(self.info)]
            return {"height": height, "hash": hash_[::-1].hex(), "curve": False, "owed": 0, "draw_known": False,
                    "draw_height": height + DRAW_DELAY, "settled": False, "spendable": True,
                    "deadline_height": height + self.p.settle_deadline, "tag": Y.pay_tag(self.p.launch_id, hash_).hex()}
        i = self.info[height]
        r = {"height": height, "hash": i.hash[::-1].hex(), "curve": i.curve, "owed": i.owed, "draw_known": i.draw_known,
             "draw_height": height + DRAW_DELAY, "settled": i.settled, "spendable": self.spendable(height),
             "deadline_height": height + self.p.settle_deadline, "tag": Y.pay_tag(self.p.launch_id, i.hash).hex()}
        if i.draw_known:
            r.update(pay=i.pay, payee=PAYEE_NAMES[i.payee], earning=i.earning)
            if i.pay > 0:
                r["pay_script"] = i.pay_script.hex()
            if i.coin is not None:
                r["coin"] = {"txid": i.coin[0][::-1].hex(), "vout": i.coin[1], "value": i.coin[2]}
        return r

    def snapshot(self):
        """Everything, in a form that compares with ==."""
        coins = tuple((c.txid, c.vout, c.value, c.script, c.live) for c in self.coins)
        info = tuple((i.hash, i.curve, i.owed, None if i.held is None else tuple(i.held), i.released, i.draw_known, i.seed,
                      i.pay, i.payee, i.pay_script, i.coin, i.earning, i.settled, i.coins_before, tuple(i.killed),
                      tuple(i.released_here), tuple(i.settled_here), tuple(i.relayed), i.drew) for i in self.info)
        return coins, info, tuple(self.above), self.relay.snapshot()

    # ---- connect
    def connect(self, b: Block) -> bool:
        """The next block of the chain. Returns False if the sats leg was over already: then the
        block is not looked at."""
        if b.height != self.height() + 1:
            raise ValueError(f"block {b.height} does not follow height {self.height()}")
        if self.closed():
            self.above.append(b.hash)
            return False
        h = len(self.info)
        cur = Info(hash=b.hash, curve=b.curve, owed=b.owed if b.curve else 0, coins_before=len(self.coins))

        # 1. The draw of block h - 6, over the coins that are live at the end of block h - 1.
        m = h - DRAW_DELAY
        if m >= 1 and self.info[m].curve:
            d = self.info[m]
            seed = Y.draw_seed(self.p.launch_id, b.work_hash)
            pay, payee = Y.compute_draw(d.owed, self.p.min_payment, seed)
            total = self.live_value()
            if payee == Y.HOLDER and total == 0:
                pay = 0  # nobody holds yet: the holders' share is owed to no one
            script, coin = self._payee(payee, seed, total) if pay > 0 else (b"", None)
            d.draw_known, d.seed, d.pay, d.payee, d.pay_script, d.coin, d.earning = True, seed, pay, payee, script, coin, total
            cur.drew = m
            if pay == 0:
                self._release(m, cur)

        # 2. The transactions.
        self.info.append(cur)
        for tx in b.txs:
            if not tx.coinbase:
                for outpoint in tx.inputs:
                    i = self._live_index(outpoint)
                    if i is not None:
                        self.coins[i].live = False
                        cur.killed.append(i)
            for _value, script in tx.outputs:
                data = Y.tagged_return(script, b"HFH1")
                if data is not None:
                    for header in Y.parse_btc_headers(data) or []:
                        if self.relay.accept(header):
                            cur.relayed.append(sha256d(header))
                    continue
                data = Y.tagged_return(script, b"HFP1")
                if data is not None:
                    proof = Y.PaymentProof.parse(data)
                    if proof is not None and self._try_settle(proof, h):
                        cur.settled_here.append(proof.mint_height)
                        self._release(proof.mint_height, cur)
            coins = Y.registered_outputs(SimpleNamespace(vout=[TxOut(v, s) for v, s in tx.outputs]), tx.coinbase)
            if tx.coinbase and cur.curve and cur.owed > 0:
                cur.held = [(tx.txid, vout, value, script) for vout, value, script in coins]
            else:
                self.coins.extend(Coin(tx.txid, vout, value, script) for vout, value, script in coins)
        return True

    def _payee(self, payee: int, seed: bytes, total: int) -> Tuple[bytes, Optional[Tuple[bytes, int, int]]]:
        """Who a draw with something due pays: (Bitcoin script, the payee coin of a holder draw)."""
        if payee == Y.DEV:
            return self.p.dev_btc_script, None
        if payee == Y.CREATOR:
            return self.p.creator_btc_script, None
        x = Y.candidate_point(seed, 0, total)  # total > 0: a holder draw over nothing is not due
        acc = 0
        for c in self.coins:
            if c.live:
                acc += c.value
                if acc > x:
                    return c.script, (c.txid, c.vout, c.value)
        raise AssertionError("a point below the live total must fall on a live coin")

    def _live_index(self, outpoint: Outpoint) -> Optional[int]:
        """The live coin with this outpoint. (Two live coins cannot share one on a valid chain; if
        they did, an input would spend the later one, as it does in the UTXO set.)"""
        for i in range(len(self.coins) - 1, -1, -1):
            c = self.coins[i]
            if c.live and (c.txid, c.vout) == outpoint:
                return i
        return None

    def _release(self, mint_height: int, cur: Info) -> None:
        d = self.info[mint_height]
        if d.held is None or d.released:
            return
        self.coins.extend(Coin(*c) for c in d.held)
        d.released = True
        cur.released_here.append(mint_height)

    def _try_settle(self, proof: Y.PaymentProof, h: int) -> bool:
        m = proof.mint_height
        if m < 1 or h <= m + DRAW_DELAY or h > m + self.p.settle_deadline:
            return False
        d = self.info[m]  # exists: m < h
        if not d.curve or not d.draw_known or d.pay == 0 or d.settled:
            return False
        if proof.candidate != 0:
            return False
        if self.relay.confirmations(proof.btc_block) < self.p.btc_confs:
            return False
        root = self.relay.merkle_root(proof.btc_block)
        if root is None:
            return False
        ok, _why = Y.verify_btc_payment(proof, root, Y.pay_tag(self.p.launch_id, d.hash), d.pay_script, d.pay)
        if not ok:
            return False
        d.settled = True
        return True

    # ---- undo
    def disconnect(self) -> None:
        """Take the tip block off again: exactly the state before it was connected."""
        if self.above:  # a block past the end of the sats leg: it changed nothing
            self.above.pop()
            return
        cur = self.info.pop()
        for hash_ in reversed(cur.relayed):  # children before parents
            self.relay.remove(hash_)
        for m in cur.settled_here:
            self.info[m].settled = False
        for m in cur.released_here:
            self.info[m].released = False
        del self.coins[cur.coins_before:]  # everything appended during this block is the tail
        for i in cur.killed:
            if i < cur.coins_before:
                self.coins[i].live = True
        if cur.drew >= 0:
            d = self.info[cur.drew]
            d.draw_known, d.seed, d.pay, d.payee, d.pay_script, d.coin, d.earning = False, b"", 0, Y.HOLDER, b"", None, 0


# ---------------------------------------------------------------- blocks from a node
def _on_curve_and_owed(d, height: int, bits: int, work_before: int) -> Tuple[bool, int]:
    """work_before: the chain's work above genesis at the parent. A block is on the curve while its
    parent has not graduated; a curve block owes sats for its own work."""
    curve = height >= 1 and work_before < d.graduation_work
    return curve, (Y.owed(work_from_bits(bits), d.sats_num, d.sats_shift) if curve else 0)


def _state_tx(tx: Tx) -> StateTx:
    coinbase = Y.is_coinbase(tx)
    return StateTx(tx.txid(), coinbase, [] if coinbase else [(i.prev_txid, i.prev_vout) for i in tx.vin],
                   [(o.value, o.script_pubkey) for o in tx.vout])


def block_from_raw(d, raw: bytes, height: int, work_before: int) -> Tuple[Block, int]:
    """A node's serialized block (`getblock HASH 0`) as the model's block, with nothing taken on
    trust: amounts are the integers in the block, and the hash that carried the work is computed
    here. Returns (block, the block's own work)."""
    r = Reader(raw)
    header = r.read(80)
    version = int.from_bytes(header[:4], "little", signed=True)
    bits = int.from_bytes(header[72:76], "little")
    work_hash = sha256d(header)
    if version & 0x100:  # merge-mined: the header is followed by its auxpow
        Tx._parse(r)     # the parent block's coinbase
        r.read(32)       # (a hash field the format carries and nobody reads)
        for _ in range(r.varint()):
            r.read(32)
        r.i32()
        for _ in range(r.varint()):
            r.read(32)
        r.i32()
        work_hash = sha256d(r.read(80))  # the parent header: its hash is the one that met the target
    txs = [Tx._parse(r) for _ in range(r.varint())]
    if not r.done():
        raise ValueError("trailing bytes after the block")
    curve, owed = _on_curve_and_owed(d, height, bits, work_before)
    return Block(height, sha256d(header), work_hash, curve, owed, [_state_tx(t) for t in txs]), work_from_bits(bits)


def block_from_json(d, blk: dict, work_before: int) -> Tuple[Block, int]:
    """The same from `getblock HASH 2`. Amounts come as decimal coins: exact once rounded to units."""
    height, bits = blk["height"], int(blk["bits"], 16)
    hash_ = bytes.fromhex(blk["hash"])[::-1]
    work_hash = hash_
    aux = blk.get("auxpow")
    if aux:
        parent = aux["parentblock"]
        if isinstance(parent, dict):
            work_hash = bytes.fromhex(parent["hash"])[::-1]
        else:
            work_hash = sha256d(bytes.fromhex(parent)[:80])
    txs = []
    for t in blk["tx"]:
        coinbase = "coinbase" in t["vin"][0]
        txs.append(StateTx(bytes.fromhex(t["txid"])[::-1], coinbase,
                           [] if coinbase else [(bytes.fromhex(i["txid"])[::-1], i["vout"]) for i in t["vin"]],
                           [(round(o["value"] * 100_000_000), bytes.fromhex(o["scriptPubKey"]["hex"])) for o in t["vout"]]))
    curve, owed = _on_curve_and_owed(d, height, bits, work_before)
    return Block(height, hash_, work_hash, curve, owed, txs), work_from_bits(bits)


class Follower:
    """A State kept in step with a node's active chain, built from the node's own blocks.

    sync() follows whatever the node did: new blocks are connected, and after a reorg the model
    disconnects down to the fork first. rebuilt() is the same chain replayed from nothing."""

    def __init__(self, d, rpc, check_json: bool = True):
        self.d, self.rpc, self.check_json = d, rpc, check_json
        self.state = State(Params.from_launch(d), HeaderRelay.from_launch(d))
        self.blocks: List[Block] = []
        self.work: List[int] = []  # work above genesis at each height

    def _read(self, height: int) -> Tuple[Block, int]:
        hash_hex = self.rpc.getblockhash(height)
        before = self.work[height - 1] if height >= 1 else 0
        block, own = block_from_raw(self.d, bytes.fromhex(self.rpc.getblock(hash_hex, 0)), height, before)
        if block.hash[::-1].hex() != hash_hex:
            raise AssertionError(f"block {height}: the node calls it {hash_hex}, its header hashes to {block.hash[::-1].hex()}")
        if self.check_json:
            other, _ = block_from_json(self.d, self.rpc.getblock(hash_hex, 2), before)
            if other != block:
                raise AssertionError(f"block {height}: the serialized block and the node's JSON describe different blocks")
        return block, (own if height >= 1 else 0)

    def sync(self) -> Tuple[int, int]:
        """Returns (blocks disconnected, blocks connected)."""
        tip, undone, done = self.rpc.getblockcount(), 0, 0
        while self.blocks and (len(self.blocks) - 1 > tip or
                               self.rpc.getblockhash(len(self.blocks) - 1) != self.blocks[-1].hash[::-1].hex()):
            self.state.disconnect()
            self.blocks.pop()
            self.work.pop()
            undone += 1
        for height in range(len(self.blocks), tip + 1):
            block, own = self._read(height)
            self.state.connect(block)
            self.blocks.append(block)
            self.work.append((self.work[-1] if self.work else 0) + own)
            done += 1
        return undone, done

    def rebuilt(self) -> State:
        return State.replay(Params.from_launch(self.d), lambda: HeaderRelay.from_launch(self.d), self.blocks)


def differences(node: dict, model: dict) -> List[str]:
    """Field by field: what a node's getmintobligation says against the model's obligation()."""
    out = []
    for k in sorted(set(node) | set(model)):
        a, b = node.get(k), model.get(k)
        if a != b:
            out.append(f"{k}: node {a!r}, model {b!r}")
    return out
