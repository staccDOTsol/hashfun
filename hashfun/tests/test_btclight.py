"""hashfun.btclight against Electrum servers written here: honest ones, and ones that lie, disagree,
hold answers back or hang. No node and no network.

    python -m unittest hashfun.tests.test_btclight
"""
import copy
import json
import logging
import os
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest

from hashfun import btclight as L
from hashfun.crypto import ecdsa_verify, parse_der, pubkey_from_priv, sha256, sha256d
from hashfun.rpc import RPCError
from hashfun.ser import (Tx, TxIn, TxOut, b58check_encode, bip143_sighash, bits_to_target, header_bytes, merkle_branch,
                         merkle_root, p2wpkh_script, p2wpkh_script_code, push, root_from_branch, target_to_bits)

COIN = 100_000_000
REGTEST_BITS = 0x207FFFFF
logging.getLogger("hashfun.btclight").setLevel(logging.CRITICAL)  # the liars below are loud by design


def sh(script: bytes) -> str:
    return sha256(script)[::-1].hex()


def script_of(n: int) -> bytes:
    """A P2WPKH script that is nobody's, one per number."""
    return bytes([0, 20]) + sha256(b"script %d" % n)[:20]


def mine(prev_le: bytes, root_le: bytes, t: int, bits: int, bad_pow: bool = False) -> bytes:
    target = bits_to_target(bits)
    for nonce in range(1 << 32):
        h = header_bytes(0x20000000, prev_le, root_le, t, bits, nonce)
        if (int.from_bytes(sha256d(h), "little") <= target) != bad_pow:
            return h
    raise AssertionError


class Chain:
    """A small Bitcoin-shaped chain with real proof of work at regtest's limit, and a mempool."""

    def __init__(self, retarget=False, interval=8, timespan=8 * 600, spacing=600, length=0, seed=0):
        self.retarget, self.interval, self.timespan, self.spacing = retarget, interval, timespan, spacing
        self.lock = threading.RLock()
        self.headers, self.txs = [], []           # per height: header bytes, list of Tx
        self.mempool = {}                         # txid -> Tx
        self.t0 = int(time.time()) - 400 * spacing
        self.salt = seed                          # two chains with one seed are the same chain
        self.add()                                # the first block
        for _ in range(length):
            self.add()

    # -- building
    def expected_bits(self, h: int) -> int:
        if not self.retarget or h == 0:
            return REGTEST_BITS
        if h % self.interval:
            return struct.unpack_from("<I", self.headers[h - 1], 72)[0]
        first, last = self.headers[h - self.interval], self.headers[h - 1]
        span = struct.unpack_from("<I", last, 68)[0] - struct.unpack_from("<I", first, 68)[0]
        span = min(max(span, self.timespan // 4), self.timespan * 4)
        old = bits_to_target(struct.unpack_from("<I", last, 72)[0])
        return target_to_bits(min(old * span // self.timespan, bits_to_target(REGTEST_BITS)))

    def add(self, txs=(), bits=None, prev=None, bad_pow=False, t=None) -> int:
        with self.lock:
            h = len(self.headers)
            self.salt += 1
            cb = Tx(2, [TxIn(b"\0" * 32, 0xFFFFFFFF, push(struct.pack("<I", h)) + push(struct.pack("<I", self.salt)))],
                    [TxOut(50 * COIN, script_of(1_000_000 + h))])
            body = [cb] + list(txs)
            for tx in txs:
                self.mempool.pop(tx.txid_hex(), None)
            root = merkle_root([x.txid() for x in body])
            prev_le = prev if prev is not None else (sha256d(self.headers[-1]) if h else b"\0" * 32)
            t = t if t is not None else self.t0 + h * self.spacing
            hdr = mine(prev_le, root, t, self.expected_bits(h) if bits is None else bits, bad_pow)
            self.headers.append(hdr)
            self.txs.append(body)
            return h

    def fork(self, height: int) -> "Chain":
        """A copy of this chain up to `height`, to grow another way."""
        with self.lock:
            c = copy.copy(self)
            c.lock = threading.RLock()
            c.headers, c.txs, c.mempool = self.headers[:height + 1], [list(b) for b in self.txs[:height + 1]], {}
            c.salt = self.salt + 1000
            return c

    # -- asking
    @property
    def tip(self) -> int:
        return len(self.headers) - 1

    def hash(self, h: int) -> str:
        return sha256d(self.headers[h])[::-1].hex()

    def find(self, txid: str):
        """(height, Tx): height 0 for the mempool. None when unknown."""
        with self.lock:
            for h, body in enumerate(self.txs):
                for tx in body:
                    if tx.txid_hex() == txid:
                        return h, tx
            return (0, self.mempool[txid]) if txid in self.mempool else None

    def _all(self):
        for h, body in enumerate(self.txs):
            for tx in body:
                yield h, tx
        for tx in self.mempool.values():
            yield 0, tx

    def history(self, scripthash: str):
        with self.lock:
            outs = {}
            for h, tx in self._all():
                for n, o in enumerate(tx.vout):
                    outs[(tx.txid(), n)] = sh(o.script_pubkey)
            rows = []
            for h, tx in self._all():
                if any(sh(o.script_pubkey) == scripthash for o in tx.vout) or \
                        any(outs.get((i.prev_txid, i.prev_vout)) == scripthash for i in tx.vin):
                    rows.append({"tx_hash": tx.txid_hex(), "height": h} if h else {"tx_hash": tx.txid_hex(), "height": 0, "fee": 1})
            return rows

    def unspent(self, scripthash: str):
        with self.lock:
            spent = {(i.prev_txid, i.prev_vout) for _h, tx in self._all() for i in tx.vin}
            return [{"tx_hash": tx.txid_hex(), "tx_pos": n, "height": h, "value": o.value}
                    for h, tx in self._all() for n, o in enumerate(tx.vout)
                    if sh(o.script_pubkey) == scripthash and (tx.txid(), n) not in spent]

    def pay(self, script: bytes, value: int, spend=None, extra=()) -> Tx:
        """A transaction paying a script (spending `spend` = (Tx, n), or an input that exists nowhere)."""
        self.salt += 1
        vin = [TxIn(spend[0].txid(), spend[1])] if spend else [TxIn(sha256(b"nowhere %d" % self.salt), 0)]
        return Tx(2, vin, [TxOut(value, script)] + list(extra))


class Fake(threading.Thread):
    """An Electrum server over a Chain. What it does wrong is set on it by the tests."""

    def __init__(self, chain: Chain, tls=None):
        super().__init__(daemon=True)
        self.chain, self.tls = chain, tls
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.hang = False                 # take the connection and never answer
        self.drop = False                 # send half of each answer and close the connection
        self.lie_tx = {}                  # txid -> bytes handed out instead
        self.lie_merkle = False           # a branch that leads elsewhere
        self.hide_unspent = set()         # (txid, n) left out of listunspent
        self.extra_unspent = {}           # scripthash -> rows added to listunspent
        self.value_lie = {}               # (txid, n) -> value listed instead
        self.hide_history = set()         # txids left out of histories
        self.extra_history = {}           # scripthash -> rows added
        self.refuse = None                # the reason a broadcast is refused with
        self.fee = 0.0002
        self.get_height = False           # does it have blockchain.transaction.get_height
        self.calls = {}
        self.stopped = False
        self.start()

    def stop(self):
        self.stopped = True
        try:
            self.sock.close()
        except OSError:
            pass

    def run(self):
        while not self.stopped:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn):
        try:
            if self.tls:
                conn = self.tls.wrap_socket(conn, server_side=True)
            f = conn.makefile("rwb")
            for line in f:
                if self.hang:
                    time.sleep(30)
                    return
                req = json.loads(line)
                self.calls[req["method"]] = self.calls.get(req["method"], 0) + 1
                try:
                    out = {"jsonrpc": "2.0", "id": req["id"], "result": self.answer(req["method"], req.get("params") or [])}
                except Exception as e:  # noqa: BLE001
                    out = {"jsonrpc": "2.0", "id": req["id"], "error": {"code": 1, "message": str(e)}}
                line = json.dumps(out).encode() + b"\n"
                if self.drop and req["method"] != "server.version":
                    f.write(line[:len(line) // 2])
                    f.flush()
                    return
                f.write(line)
                f.flush()
        except (OSError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def answer(self, m, p):
        c = self.chain
        if m == "server.version":
            return ["Fake 1.0", "1.4"]
        if m == "blockchain.headers.subscribe":
            with c.lock:
                return {"height": c.tip, "hex": c.headers[-1].hex()}
        if m == "blockchain.block.header":
            return c.headers[int(p[0])].hex()
        if m == "blockchain.block.headers":
            hs = c.headers[int(p[0]):int(p[0]) + min(int(p[1]), 2016)]
            return {"count": len(hs), "hex": b"".join(hs).hex(), "max": 2016}
        if m == "blockchain.estimatefee":
            return self.fee
        if m == "blockchain.transaction.get":
            if p[0] in self.lie_tx:
                return self.lie_tx[p[0]].hex()
            got = c.find(p[0])
            if got is None:
                raise ValueError("No such mempool or blockchain transaction. Use gettransaction for wallet transactions.")
            return got[1].serialize().hex()
        if m == "blockchain.transaction.get_height":
            if not self.get_height:
                raise ValueError("unknown method")
            got = c.find(p[0])
            if got is None:
                raise ValueError("transaction not found")
            return got[0]
        if m == "blockchain.transaction.get_merkle":
            body = c.txs[int(p[1])]
            ids = [x.txid() for x in body]
            pos = [x.txid_hex() for x in body].index(p[0])
            br = merkle_branch(ids, pos)
            if self.lie_merkle:
                br = [sha256(b) for b in br] or [b"\x11" * 32]
            return {"block_height": int(p[1]), "merkle": [b[::-1].hex() for b in br], "pos": pos}
        if m == "blockchain.transaction.id_from_pos":
            return c.txs[int(p[0])][int(p[1])].txid_hex()
        if m == "blockchain.scripthash.get_history":
            return [r for r in c.history(p[0]) if r["tx_hash"] not in self.hide_history] + self.extra_history.get(p[0], [])
        if m == "blockchain.scripthash.listunspent":
            rows = [dict(r, value=self.value_lie.get((r["tx_hash"], r["tx_pos"]), r["value"])) for r in c.unspent(p[0])
                    if (r["tx_hash"], r["tx_pos"]) not in self.hide_unspent]
            return rows + self.extra_unspent.get(p[0], [])
        if m == "blockchain.transaction.broadcast":
            if self.refuse:
                raise ValueError(f"the transaction was rejected by network rules.\n\n{self.refuse}\n[{p[0]}]")
            tx = Tx.parse(bytes.fromhex(p[0]))
            with c.lock:
                if c.find(tx.txid_hex()) is None:
                    c.mempool[tx.txid_hex()] = tx
            return tx.txid_hex()
        raise ValueError(f"unknown method {m}")


def rules_for(chain: Chain, checkpoint: int = 0) -> L.Rules:
    return L.Rules("regtest", "bcrt", REGTEST_BITS, checkpoint=(checkpoint, chain.hash(checkpoint)), retarget=chain.retarget,
                   interval=chain.interval, timespan=chain.timespan)


class Base(unittest.TestCase):
    def setUp(self):
        self.fakes, self.lights = [], []

    def tearDown(self):
        for x in self.lights:
            x.close()
        for f in self.fakes:
            f.stop()

    def fake(self, chain, **kw) -> Fake:
        f = Fake(chain, **kw)
        self.fakes.append(f)
        return f

    def light(self, fakes, rules, agree=None, timeout=3.0, **kw) -> L.BtcLight:
        x = L.BtcLight([("127.0.0.1", f.port, bool(f.tls)) for f in fakes], rules, agree=agree or len(fakes), timeout=timeout,
                       poll=0, **kw)
        self.lights.append(x)
        return x


class Headers(Base):
    def test_the_chain_as_a_node_reports_it(self):
        c = Chain(length=30)
        b = self.light([self.fake(c)], rules_for(c))
        self.assertEqual(b.getblockcount(), 30)
        for h in (0, 1, 17, 30):
            self.assertEqual(b.getblockhash(h), c.hash(h))
            self.assertEqual(b.getblockheader(c.hash(h), False), c.headers[h].hex())
        v = b.getblockheader(c.hash(17))
        self.assertEqual((v["confirmations"], v["height"], v["previousblockhash"], v["nextblockhash"]),
                         (14, 17, c.hash(16), c.hash(18)))
        self.assertEqual(v["time"], c.t0 + 17 * 600)
        self.assertEqual(v["merkleroot"], c.headers[17][36:68][::-1].hex())
        info = b.getblockchaininfo()
        self.assertEqual((info["chain"], info["blocks"], info["bestblockhash"]), ("regtest", 30, c.hash(30)))
        self.assertEqual(info["mediantime"], c.t0 + 25 * 600)  # the median of blocks 20..30
        self.assertEqual(b.getbestblockhash(), c.hash(30))
        with self.assertRaises(RPCError) as e:
            b.getblockhash(31)
        self.assertEqual(e.exception.code, -8)
        with self.assertRaises(RPCError) as e:
            b.getblockheader("00" * 32)
        self.assertEqual(e.exception.code, -5)
        c.add()
        self.assertEqual(b.getblockcount(), 31)

    def test_retargets_are_checked(self):
        c = Chain(retarget=True, spacing=300, length=40)
        self.assertNotEqual(c.expected_bits(16), c.expected_bits(8))  # the difficulty really moves
        b = self.light([self.fake(c)], rules_for(c))
        self.assertEqual(b.getblockcount(), 40)
        self.assertEqual(b.getblockhash(40), c.hash(40))
        # a chain whose block 16 keeps the old bits: valid work, wrong difficulty
        bad = c.fork(15)
        bad.add(bits=struct.unpack_from("<I", bad.headers[15], 72)[0])
        for _ in range(30):
            bad.add()
        liar = self.fake(bad)
        alone = self.light([liar], rules_for(bad))
        with self.assertRaises(L.Unreachable) as e:
            alone.getblockcount()
        self.assertIn("header 16 has bits", str(e.exception))
        self.assertFalse(alone.servers[0].alive())
        # beside an honest server the liar's longer chain changes nothing
        both = self.light([liar, self.fake(c)], rules_for(c))
        self.assertEqual((both.getblockcount(), both.getblockhash(40)), (40, c.hash(40)))

    def test_a_header_that_does_not_link(self):
        c = Chain(length=20)
        bad = c.fork(9)
        bad.add(prev=sha256(b"not the block below"))
        for _ in range(15):
            bad.add()
        alone = self.light([self.fake(bad)], rules_for(c))
        with self.assertRaises(L.Unreachable) as e:
            alone.getblockcount()
        self.assertIn("header 10 does not link", str(e.exception))
        liar, honest = self.fake(bad), self.fake(c)
        both = self.light([liar, honest], rules_for(c))
        self.assertEqual(both.getblockcount(), 20)
        self.assertFalse(both.servers[0].alive())
        self.assertTrue(both.servers[1].alive())

    def test_a_header_without_work_or_ahead_of_the_clock(self):
        c = Chain(length=12)
        bad = c.fork(11)
        bad.add(bad_pow=True)
        with self.assertRaises(L.Unreachable) as e:
            self.light([self.fake(bad)], rules_for(c)).getblockcount()
        self.assertIn("header 12 does not meet its own bits", str(e.exception))
        late = c.fork(11)
        late.add(t=int(time.time()) + 3 * 3600)
        with self.assertRaises(L.Unreachable) as e:
            self.light([self.fake(late)], rules_for(c)).getblockcount()
        self.assertIn("two hours ahead", str(e.exception))
        old = c.fork(11)
        old.add(t=c.t0 + 600)
        with self.assertRaises(L.Unreachable) as e:
            self.light([self.fake(old)], rules_for(c)).getblockcount()
        self.assertIn("median", str(e.exception))

    def test_another_network(self):
        c, other = Chain(length=5), Chain(length=9, seed=500)
        with self.assertRaises(L.Unreachable) as e:
            self.light([self.fake(other)], rules_for(c)).getblockcount()
        self.assertIn("another network", str(e.exception))

    def test_reorg(self):
        c = Chain(length=20)
        f = self.fake(c)
        b = self.light([f], rules_for(c))
        self.assertEqual(b.getblockcount(), 20)
        gone = c.hash(18)
        longer = c.fork(15)
        for _ in range(8):
            longer.add()
        f.chain = longer
        self.assertEqual(b.getblockcount(), 23)
        self.assertEqual(b.getblockhash(18), longer.hash(18))
        self.assertEqual(b.getblockheader(gone)["confirmations"], -1)
        self.assertEqual(b.getblockheader(longer.hash(18))["confirmations"], 6)
        self.assertEqual(b.getblockheader(c.hash(15))["confirmations"], 9)  # below the fork: still there

    def test_less_work_is_not_followed(self):
        c = Chain(length=20)
        short = c.fork(15)
        for _ in range(3):
            short.add()
        b = self.light([self.fake(c), self.fake(short)], rules_for(c))
        self.assertEqual((b.getblockcount(), b.getblockhash(18)), (20, c.hash(18)))
        b2 = self.light([self.fake(short), self.fake(c)], rules_for(c))  # whichever is asked first
        self.assertEqual((b2.getblockcount(), b2.getblockhash(18)), (20, c.hash(18)))
        # equal height on another branch: the one held stays
        same = c.fork(15)
        for _ in range(5):
            same.add()
        f = self.fake(c)
        b3 = self.light([f], rules_for(c))
        self.assertEqual(b3.getblockhash(20), c.hash(20))
        f.chain = same
        self.assertEqual(b3.getblockhash(20), c.hash(20))

    def test_headers_below_the_checkpoint(self):
        c = Chain(retarget=True, length=40)
        f = self.fake(c)
        b = self.light([f], rules_for(c, checkpoint=20))
        self.assertEqual(b.getblockcount(), 40)
        self.assertEqual(b.chain.base, 9)  # eleven timestamps and the start of the checkpoint's period (16)
        # what descriptor.check_anchor and btc_anchor_from_rpc ask, for an anchor at 21 and one at 5
        for anchor in (21, 5):
            self.assertEqual(b.getblockhash(anchor), c.hash(anchor))
            self.assertEqual(b.getblockheader(b.getblockhash(anchor), False), c.headers[anchor].hex())
            first = anchor - anchor % 8
            self.assertEqual(b.getblockheader(b.getblockhash(first))["time"], c.t0 + first * 600)
        self.assertEqual(b.chain.base, 0)
        # a server whose lower headers are not the ones the checkpoint hangs from
        other = Chain(retarget=True, length=40, seed=500)
        mixed = c.fork(40)
        mixed.headers[3] = other.headers[3]
        b2 = self.light([self.fake(mixed)], rules_for(c, checkpoint=20))
        self.assertEqual(b2.getblockcount(), 40)
        with self.assertRaises(L.Unreachable) as e:
            b2.getblockhash(2)
        self.assertIn("is not the block the one above it names", str(e.exception))
        hint = self.light([f], rules_for(c, checkpoint=20), low_hint=5)
        hint.getblockcount()
        self.assertEqual(hint.chain.base, 0)  # the hint's period start, fetched at the start

    def test_a_server_that_hangs(self):
        c = Chain(length=10)
        slow, quick = self.fake(c), self.fake(c)
        slow.hang = True
        b = self.light([slow, quick], rules_for(c), agree=1, timeout=1.0)
        t = time.time()
        self.assertEqual(b.getblockcount(), 10)
        self.assertLess(time.time() - t, 5.0)  # one wait of a second for the one that hangs, not a wait without end
        self.assertFalse(b.servers[0].alive())
        t = time.time()
        self.assertEqual(b.getblockhash(10), c.hash(10))  # it is not waited for again:
        self.assertLess(time.time() - t, 0.9)             # that wait alone would be a second
        strict = self.light([slow, quick], rules_for(c), agree=2, timeout=1.0)
        self.assertEqual(strict.getblockcount(), 10)  # headers are proven: one server will do
        with self.assertRaises(L.Unreachable) as e:
            strict.unspent([script_of(1).hex()])        # what is unspent is not: both are needed
        self.assertIn("1 of the 2 answers needed", str(e.exception))


    def test_a_server_that_drops_the_connection_mid_answer(self):
        c = Chain(length=30)
        bad, good = self.fake(c), self.fake(c)
        bad.drop = True
        b = self.light([bad, good], rules_for(c), agree=1)
        self.assertEqual(b.getblockcount(), 30)               # the headers come from the other one
        self.assertEqual(b.getblockhash(17), c.hash(17))
        self.assertFalse(b.servers[0].alive())
        self.assertGreaterEqual(bad.calls.get("blockchain.headers.subscribe", 0) + bad.calls.get("blockchain.block.header", 0), 1)
        alone = self.light([bad], rules_for(c))
        with self.assertRaises(L.Unreachable) as e:
            alone.getblockcount()                               # half an answer is no answer
        self.assertIn("closed the connection", str(e.exception))
        strict = self.light([bad, good], rules_for(c), agree=2)
        with self.assertRaises(L.Unreachable):
            strict.unspent([script_of(1).hex()])                # and it does not count towards a quorum
        with self.assertRaises(L.Unreachable) as e:
            strict.getrawtransaction("ab" * 32)                 # nor towards "it does not exist"
        self.assertIn("1 of the 2 servers needed say it does not exist", str(e.exception))
        bad.drop = False
        bad_back = self.light([bad, good], rules_for(c), agree=2)
        with self.assertRaises(RPCError) as e:
            bad_back.getrawtransaction("ab" * 32)               # both say so: then it is "not found"
        self.assertEqual(e.exception.code, -5)


class Transactions(Base):
    def setUp(self):
        super().setUp()
        c = self.c = Chain(length=5)
        self.a, self.b_ = script_of(1), script_of(2)
        self.pay1 = c.pay(self.a, 70_000, extra=[TxOut(0, bytes([0x6A, 4]) + b"HFxx")])
        self.pay2 = c.pay(self.a, 30_000)
        self.h1 = c.add([c.pay(script_of(9), 5), self.pay1, c.pay(script_of(8), 6), self.pay2])   # height 6
        self.spend = c.pay(self.b_, 69_000, spend=(self.pay1, 0))
        self.h2 = c.add([self.spend])                                                             # height 7
        for _ in range(3):
            c.add()
        self.f1, self.f2 = self.fake(c), self.fake(c)
        self.x = self.light([self.f1, self.f2], rules_for(c))

    def test_bytes_are_hashed(self):
        txid = self.pay1.txid_hex()
        self.assertEqual(self.x.getrawtransaction(txid), self.pay1.serialize().hex())
        self.f1.lie_tx[self.pay2.txid_hex()] = self.pay1.serialize()
        self.assertEqual(self.x.getrawtransaction(self.pay2.txid_hex()), self.pay2.serialize().hex())  # from the other one
        self.assertFalse(self.x.servers[0].alive())
        alone = self.light([self.f1], rules_for(self.c))
        with self.assertRaises(L.Unreachable) as e:
            alone.getrawtransaction(self.pay2.txid_hex())
        self.assertIn("do not hash", str(e.exception))
        with self.assertRaises(RPCError) as e:
            self.light([self.f2], rules_for(self.c)).getrawtransaction("ab" * 32)
        self.assertEqual(e.exception.code, -5)

    def test_verbose_transaction(self):
        t = self.x.getrawtransaction(self.pay1.txid_hex(), True)
        self.assertEqual((t["txid"], t["confirmations"], t["blockhash"]), (self.pay1.txid_hex(), 5, self.c.hash(6)))
        self.assertEqual([(o["n"], round(o["value"] * 1e8), o["scriptPubKey"]["hex"]) for o in t["vout"]],
                         [(0, 70_000, self.a.hex()), (1, 0, "6a0448467878")])
        self.assertEqual(t["vin"][0]["txid"], self.pay1.vin[0].prev_txid[::-1].hex())
        waiting = self.c.pay(self.a, 1234)
        self.c.mempool[waiting.txid_hex()] = waiting
        self.assertNotIn("confirmations", self.x.getrawtransaction(waiting.txid_hex(), True))
        f3, f4 = self.fake(self.c), self.fake(self.c)  # servers that say the height in one call
        f3.get_height = f4.get_height = True
        y = self.light([f3, f4], rules_for(self.c))
        self.assertEqual(y.getrawtransaction(self.spend.txid_hex(), True)["confirmations"], 4)
        self.assertNotIn("blockchain.scripthash.get_history", set(f3.calls) | set(f4.calls))
        self.assertNotIn("confirmations", y.getrawtransaction(waiting.txid_hex(), True))

    def test_merkle_branches_are_folded(self):
        txid = self.pay2.txid_hex()
        p = self.x.txproof(txid)
        self.assertEqual((p["height"], p["blockhash"], p["pos"], p["confirmations"]), (6, self.c.hash(6), 4, 5))
        self.assertEqual(root_from_branch(self.pay2.txid(), p["branch"], p["pos"]), self.c.headers[6][36:68])
        self.assertEqual(p["hex"], self.pay2.serialize().hex())
        self.assertEqual(self.x.txproof(txid, self.c.hash(6))["pos"], 4)
        with self.assertRaises(RPCError):
            self.x.txproof(txid, "00" * 32)
        self.f1.lie_merkle = True
        y = self.light([self.f1, self.f2], rules_for(self.c))
        self.assertEqual(root_from_branch(self.pay1.txid(), y.txproof(self.pay1.txid_hex())["branch"], 2), self.c.headers[6][36:68])
        alone = self.light([self.f1], rules_for(self.c))
        with self.assertRaises(RPCError) as e:
            alone.txproof(self.pay1.txid_hex())  # no proof is better than that one
        self.assertEqual(e.exception.code, -5)
        with self.assertRaises(L.NotProven):
            alone.gettxout(self.pay2.txid_hex(), 0)  # and no confirmations are made up
        self.assertNotIn("confirmations", alone.getrawtransaction(self.pay2.txid_hex(), True))
        # the same branch against the wrong block: a transaction said to be one block higher
        self.f2.extra_history[sh(self.a)] = []
        with self.assertRaises(RPCError):
            self.x.txproof(self.pay2.txid_hex(), self.c.hash(7))

    def test_unspent_outputs(self):
        tip, res = self.x.unspent([self.a.hex(), self.b_.hex(), script_of(77).hex()])
        self.assertEqual(tip, 10)
        self.assertEqual(res[self.a.hex()], [{"tx_hash": self.pay2.txid_hex(), "tx_pos": 0, "value": 30_000, "height": 6,
                                             "proven": True}])
        self.assertEqual([(u["tx_hash"], u["value"], u["height"]) for u in res[self.b_.hex()]],
                         [(self.spend.txid_hex(), 69_000, 7)])
        self.assertEqual(res[script_of(77).hex()], [])
        scan = self.x.scantxoutset("start", [f"raw({self.a.hex()})", {"desc": f"raw({self.b_.hex()})"}])
        self.assertEqual((scan["height"], round(scan["total_amount"] * 1e8), len(scan["unspents"])), (10, 99_000, 2))
        self.assertEqual({(u["txid"], u["vout"], u["scriptPubKey"], round(u["amount"] * 1e8), u["height"]) for u in scan["unspents"]},
                         {(self.pay2.txid_hex(), 0, self.a.hex(), 30_000, 6), (self.spend.txid_hex(), 0, self.b_.hex(), 69_000, 7)})
        with self.assertRaises(L.NotAvailable):
            self.x.scantxoutset("start", ["addr(bc1qxyz)"])

    def test_servers_that_disagree_on_what_is_unspent(self):
        key = (self.pay2.txid_hex(), 0)
        self.f2.hide_unspent.add(key)
        t = time.time()
        with self.assertRaises(L.Disagreement) as e:
            self.x.unspent([self.a.hex()])
        self.assertIn(self.pay2.txid_hex(), str(e.exception))
        self.assertGreater(time.time() - t, 1.0)  # it was asked again before giving up
        with self.assertRaises(L.Disagreement):
            self.x.scantxoutset("start", [f"raw({self.a.hex()})"])
        with self.assertRaises(L.Disagreement):
            self.x.gettxout(*key)
        self.f2.hide_unspent.clear()
        # one of them adds an output that is spent
        self.f1.extra_unspent[sh(self.a)] = [{"tx_hash": self.pay1.txid_hex(), "tx_pos": 0, "height": 6, "value": 70_000}]
        with self.assertRaises(L.Disagreement):
            self.x.unspent([self.a.hex()])
        self.f1.extra_unspent.clear()
        # both list a value the transaction does not have
        self.f1.value_lie[key] = self.f2.value_lie[key] = 31_000_000
        with self.assertRaises(L.Disagreement) as e:
            self.x.unspent([self.a.hex()])
        self.assertIn("the transaction itself says otherwise", str(e.exception))
        self.f1.value_lie.clear()
        self.f2.value_lie.clear()
        # what only one of them has in its mempool is no disagreement: it is listed, unconfirmed
        new = self.c.pay(self.a, 555)
        self.f1.extra_unspent[sh(self.a)] = [{"tx_hash": new.txid_hex(), "tx_pos": 0, "height": 0, "value": 555}]
        _tip, res = self.x.unspent([self.a.hex()])
        self.assertEqual([(u["value"], u["height"]) for u in res[self.a.hex()]], [(30_000, 6), (555, 0)])
        self.assertEqual(len(self.x.scantxoutset("start", [f"raw({self.a.hex()})"])["unspents"]), 1)  # confirmed only
        # a single server, asked to stand alone, is taken at its word
        self.f2.hide_unspent.add(key)
        one = self.light([self.f2], rules_for(self.c))
        self.assertEqual(one.unspent([self.a.hex()])[1][self.a.hex()], [])

    def test_gettxout(self):
        o = self.x.gettxout(self.pay2.txid_hex(), 0)
        self.assertEqual((round(o["value"] * 1e8), o["scriptPubKey"]["hex"], o["confirmations"], o["bestblock"]),
                         (30_000, self.a.hex(), 5, self.c.hash(10)))
        self.assertIsNone(self.x.gettxout(self.pay1.txid_hex(), 0))    # spent
        self.assertIsNone(self.x.gettxout(self.pay2.txid_hex(), 5))    # no such output
        self.assertIsNone(self.x.gettxout("cd" * 32, 0))               # no such transaction
        waiting = self.c.pay(self.a, 4321)
        self.c.mempool[waiting.txid_hex()] = waiting
        self.assertEqual(self.x.gettxout(waiting.txid_hex(), 0)["confirmations"], 0)
        self.assertIsNone(self.x.gettxout(waiting.txid_hex(), 0, False))
        self.c.add([waiting])
        self.assertEqual(self.x.gettxout(waiting.txid_hex(), 0)["confirmations"], 1)

    def test_payments_to_a_script(self):
        got = self.x.payments_to(self.a.hex())
        self.assertEqual([(d["txid"], d["height"], d["blockhash"], d["pos"], d["confirmations"]) for d in got],
                         [(self.pay1.txid_hex(), 6, self.c.hash(6), 2, 5), (self.pay2.txid_hex(), 6, self.c.hash(6), 4, 5)])
        d = got[0]  # what the settler's _match reads of a transaction
        self.assertEqual(d["hex"], self.pay1.serialize().hex())
        self.assertEqual([(round(o["value"] * 1e8), o["scriptPubKey"]["hex"]) for o in d["vout"]],
                         [(70_000, self.a.hex()), (0, "6a0448467878")])
        self.assertEqual(root_from_branch(self.pay1.txid(), d["branch"], d["pos"]), self.c.headers[6][36:68])
        self.assertEqual(self.x.payments_to(self.a.hex(), min_height=7), [])   # the spend at 7 pays it nothing
        self.assertEqual(self.x.payments_to(script_of(55).hex()), [])
        later = self.c.pay(self.a, 999)
        self.c.mempool[later.txid_hex()] = later
        self.assertEqual(len(self.x.payments_to(self.a.hex())), 2)            # not in a block: not a payment yet
        self.c.add([later])
        self.assertEqual([d["txid"] for d in self.x.payments_to(self.a.hex(), min_height=7)], [later.txid_hex()])
        # one server leaves it out: the other's entry is proven, so it counts
        self.f1.hide_history.add(later.txid_hex())
        self.assertEqual(len(self.x.payments_to(self.a.hex())), 3)
        # a server lists a transaction in a block it is not in: it is left out, the rest stays
        self.f2.extra_history[sh(self.a)] = [{"tx_hash": self.spend.txid_hex(), "height": 5},
                                             {"tx_hash": "ee" * 32, "height": 6}]
        self.assertEqual(len(self.x.payments_to(self.a.hex())), 3)
        # with a liar's branches only its own word is left, and that is nothing
        self.f1.lie_merkle = self.f2.lie_merkle = True
        fresh = self.light([self.f1, self.f2], rules_for(self.c))
        self.assertEqual(fresh.payments_to(self.a.hex()), [])

    def test_find_spend(self):
        s = self.x.find_spend(self.pay1.txid_hex(), 0)
        self.assertEqual(s.txid_hex(), self.spend.txid_hex())
        self.assertIsNone(self.x.find_spend(self.pay2.txid_hex(), 0))
        claim = self.c.pay(script_of(3), 29_000, spend=(self.pay2, 0))
        claim.vin[0].witness = [b"sig", b"\x07" * 32, b"script"]
        self.c.mempool[claim.txid_hex()] = claim
        got = self.x.find_spend(self.pay2.txid_hex(), 0)
        self.assertEqual((got.txid_hex(), got.vin[0].witness[1]), (claim.txid_hex(), b"\x07" * 32))
        with self.assertRaises(RPCError):
            self.x.find_spend("cd" * 32, 0)

    def test_broadcast(self):
        tx = self.c.pay(self.a, 2222)
        self.assertEqual(self.x.sendrawtransaction(tx.serialize().hex()), tx.txid_hex())
        self.assertIn(tx.txid_hex(), self.c.mempool)
        self.assertEqual(self.f1.calls["blockchain.transaction.broadcast"], 1)
        self.assertEqual(self.f2.calls["blockchain.transaction.broadcast"], 1)
        # refused: the server's reason reaches the caller
        self.f1.refuse = self.f2.refuse = "min relay fee not met, 100 < 141"
        with self.assertRaises(RPCError) as e:
            self.x.sendrawtransaction(self.c.pay(self.a, 3333).serialize().hex())
        self.assertEqual(e.exception.code, -26)
        self.assertIn("min relay fee not met, 100 < 141", str(e.exception))
        self.assertNotIn(tx.serialize().hex()[:60], str(e.exception))
        # refused because it is already there: that is a transaction that was sent
        self.f1.refuse = self.f2.refuse = "Transaction already in block chain"
        self.assertEqual(self.x.sendrawtransaction(self.pay2.serialize().hex()), self.pay2.txid_hex())
        # refused for inputs that are gone, and it is the transaction that spent them
        self.f1.refuse = self.f2.refuse = "bad-txns-inputs-missingorspent"
        self.assertEqual(self.x.sendrawtransaction(self.spend.serialize().hex()), self.spend.txid_hex())
        t = time.time()
        with self.assertRaises(RPCError) as e:
            self.x.sendrawtransaction(self.c.pay(self.b_, 1, spend=(self.pay1, 0)).serialize().hex())  # a real double spend
        self.assertIn("missingorspent", str(e.exception))
        self.assertGreater(time.time() - t, 4.0)  # it was looked for again before it was called refused
        self.assertEqual(self.x.decoderawtransaction(tx.serialize().hex())["txid"], tx.txid_hex())
        with self.assertRaises(RPCError):
            self.x.sendrawtransaction("00")

    def test_fees_and_what_is_not_there(self):
        self.f1.fee, self.f2.fee = 0.00012, 0.00030
        self.assertAlmostEqual(self.x.estimatesmartfee(2)["feerate"], 0.00030)
        self.f2.fee = 5.0  # 500,000 sat/vB: one server cannot make a payment cost that
        self.assertAlmostEqual(self.x.estimatesmartfee(2)["feerate"], 0.003)
        self.f1.fee = self.f2.fee = -1
        self.assertNotIn("feerate", self.x.estimatesmartfee(2))
        for call in (lambda: self.x.getblock(self.c.hash(6), 2), lambda: self.x.getrawmempool(), lambda: self.x.getbalances(),
                     lambda: self.x.sendtoaddress("x", 1), lambda: self.x.fundrawtransaction("00"),
                     lambda: self.x.call("listunspent")):
            with self.assertRaises(L.NotAvailable) as e:
                call()
            self.assertNotIsInstance(e.exception, RPCError)
        self.assertEqual(self.x.call("getblockhash", 6), self.c.hash(6))

    def test_many_threads(self):
        errors, done = [], []

        def work(i):
            try:
                for _ in range(15):
                    self.assertEqual(self.x.getblockhash(6), self.c.hash(6))
                    self.assertEqual(self.x.unspent([self.a.hex()])[1][self.a.hex()][0]["value"], 30_000)
                    self.assertEqual(self.x.txproof(self.pay1.txid_hex())["pos"], 2)
                    self.assertEqual(len(self.x.payments_to(self.a.hex())), 2)
                    self.assertEqual(self.x.getblockchaininfo()["blocks"], self.x.getblockcount())
                done.append(i)
            except Exception as e:  # noqa: BLE001
                errors.append(e)
        threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        grow = [self.c.add() for _ in range(5)]
        for t in threads:
            t.join(60)
        self.assertEqual((errors, len(done)), ([], 8))
        self.assertEqual(self.x.getblockcount(), grow[-1])


class Wallet(Base):
    KEY = 0x1F3A5C7E9B2D4F60718293A4B5C6D7E8F9010203040506070809A0B0C0D0E0F1

    def setUp(self):
        super().setUp()
        c = self.c = Chain(length=3)
        self.pub = pubkey_from_priv(self.KEY)
        self.mine = p2wpkh_script(self.pub)
        self.coin1, self.coin2 = c.pay(self.mine, 200_000), c.pay(self.mine, 50_000)
        c.add([self.coin1, self.coin2])     # height 4
        c.add()
        self.f1, self.f2 = self.fake(c), self.fake(c)
        self.dir = tempfile.mkdtemp()
        with open(os.path.join(self.dir, "key"), "w") as f:
            f.write(f"{self.KEY:064x}\n")
        self.w = self.light([self.f1, self.f2], rules_for(c)).wallet(os.path.join(self.dir, "key"))
        self.payee = script_of(42)

    def tearDown(self):
        super().tearDown()
        shutil.rmtree(self.dir, ignore_errors=True)

    def payment(self, sats):
        """What Settler._pay builds: outputs only, the tag list last."""
        return Tx(2, [], [TxOut(sats, self.payee), TxOut(0, bytes([0x6A, 22]) + b"HF" + b"\x05" * 20)]).serialize(witness=False).hex()

    def check_signed(self, hexs):
        tx = Tx.parse(bytes.fromhex(hexs))
        for idx, i in enumerate(tx.vin):
            prev = self.c.find(i.prev_txid[::-1].hex())[1]
            sig, pub = i.witness
            self.assertEqual(pub, self.pub)
            digest = bip143_sighash(tx, idx, p2wpkh_script_code(pub), prev.vout[i.prev_vout].value)
            self.assertTrue(ecdsa_verify(pub, digest, *parse_der(sig[:-1])))
            self.assertEqual(sig[-1], 1)
        return tx

    def test_keys(self):
        wif = b58check_encode(b"\xef" + self.KEY.to_bytes(32, "big") + b"\x01")
        with open(os.path.join(self.dir, "wif"), "w") as f:
            f.write(wif)
        plain = self.light([self.f1], rules_for(self.c))
        self.assertEqual(plain.wallet(os.path.join(self.dir, "wif")).address, self.w.address)
        self.assertTrue(self.w.address.startswith("bcrt1q"))
        self.assertEqual(self.w.getnewaddress(), self.w.address)
        self.assertIsNone(plain.address)
        with self.assertRaises(L.NotAvailable):
            plain.wallet(os.path.join(self.dir, "nothing"))
        with open(os.path.join(self.dir, "bad"), "w") as f:
            f.write("zz" * 32)
        with self.assertRaises(ValueError):
            plain.wallet(os.path.join(self.dir, "bad"))
        self.assertAlmostEqual(self.w.getbalance(), 0.0025)
        self.assertIs(self.w.with_key(5).chain, self.w.chain)  # one chain of headers behind every key

    def test_pay_as_the_settler_does(self):
        self.f1.fee = self.f2.fee = 0.00005  # 5 sat/vB
        funded = self.w.fundrawtransaction(self.payment(60_000), {"changePosition": 2}, False)
        signed = self.w.signrawtransactionwithwallet(funded["hex"])
        self.assertTrue(signed["complete"])
        tx = self.check_signed(signed["hex"])
        self.assertEqual([(o.value, o.script_pubkey) for o in tx.vout[:2]],
                         [(60_000, self.payee), (0, bytes([0x6A, 22]) + b"HF" + b"\x05" * 20)])
        self.assertEqual((len(tx.vin), tx.vin[0].prev_txid, tx.vout[2].script_pubkey), (1, self.coin1.txid(), self.mine))
        fee = 200_000 - sum(o.value for o in tx.vout)
        self.assertEqual(funded["changepos"], 2)
        self.assertAlmostEqual(funded["fee"], fee / 1e8)
        self.assertTrue(5 * tx.vsize() <= fee <= 5 * (tx.vsize() + 2), (fee, tx.vsize()))
        txid = self.w.decoderawtransaction(signed["hex"])["txid"]
        self.assertEqual(txid, tx.txid_hex())
        self.assertEqual(self.w.sendrawtransaction(signed["hex"]), txid)
        self.assertEqual(self.w.gettransaction(txid)["confirmations"], 0)
        # the next payment does not take the same coin, and may take the change of the first
        second = self.w.signrawtransactionwithwallet(self.w.fundrawtransaction(self.payment(150_000), {"changePosition": 2}, False)["hex"])
        tx2 = Tx.parse(bytes.fromhex(second["hex"]))
        self.assertTrue(second["complete"])
        self.assertEqual({(i.prev_txid, i.prev_vout) for i in tx2.vin}, {(tx.txid(), 2), (self.coin2.txid(), 0)})
        self.w.sendrawtransaction(second["hex"])
        left = 250_000 - 210_000 - (200_000 - sum(o.value for o in tx.vout)) - (sum(o.value for o in tx.vout[2:]) + 50_000 - sum(o.value for o in tx2.vout))
        self.assertAlmostEqual(self.w.getbalance(), left / 1e8)  # the second change, in no block yet
        with self.assertRaises(RPCError) as e:
            self.w.fundrawtransaction(self.payment(left), {"changePosition": 2}, False)
        self.assertEqual(e.exception.code, -4)
        self.assertIn("Insufficient funds", str(e.exception))
        self.c.add([tx, tx2])
        t = self.w.gettransaction(txid)
        self.assertEqual((t["confirmations"], t["blockhash"], t["hex"]), (1, self.c.hash(6), signed["hex"]))
        self.c.add()
        self.assertEqual(self.w.gettransaction(txid)["confirmations"], 2)
        self.assertEqual(self.w.txproof(txid, t["blockhash"])["pos"], 1)

    def test_change_too_small_goes_to_the_fee(self):
        self.f1.fee = self.f2.fee = 0.00001
        funded = self.w.fundrawtransaction(self.payment(199_700), None, False)
        tx = Tx.parse(bytes.fromhex(self.w.signrawtransactionwithwallet(funded["hex"])["hex"]))
        self.assertEqual((funded["changepos"], len(tx.vout), len(tx.vin)), (-1, 2, 1))
        self.assertAlmostEqual(funded["fee"], 300 / 1e8)

    def test_a_payment_no_server_shows(self):
        funded = self.w.fundrawtransaction(self.payment(10_000), {"changePosition": 2}, False)
        signed = self.w.signrawtransactionwithwallet(funded["hex"])
        txid = Tx.parse(bytes.fromhex(signed["hex"])).txid_hex()
        self.w.sendrawtransaction(signed["hex"])
        self.c.mempool.clear()  # every server lost it
        self.assertEqual(self.w.gettransaction(txid)["confirmations"], 0)
        self.assertIn(txid, self.c.mempool)  # and it was sent again
        # another process (the settler after a restart) knows the id only
        again = self.light([self.f1, self.f2], rules_for(self.c)).wallet(os.path.join(self.dir, "key"))
        self.assertEqual(again.gettransaction(txid)["confirmations"], 0)
        self.c.mempool.clear()
        with self.assertRaises(RPCError) as e:
            again.gettransaction(txid)
        self.assertEqual(e.exception.code, -5)
        self.assertEqual(again.sendrawtransaction(signed["hex"]), txid)  # what the settler does next: send what it stored
        self.c.add([Tx.parse(bytes.fromhex(signed["hex"]))])
        self.assertEqual(again.gettransaction(txid)["confirmations"], 1)
        # sent long ago, in a block, its outputs spent: a node refuses it for missing inputs, and it is still a payment made
        self.f1.refuse = self.f2.refuse = "bad-txns-inputs-missingorspent"
        self.assertEqual(again.sendrawtransaction(signed["hex"]), txid)

    def test_not_knowing_is_never_a_refusal(self):
        """The settler writes a payment off when sending it again raises RPCError. With one of the
        two servers gone, whether a payment exists cannot be asked: that must not look like "no"."""
        signed = self.w.signrawtransactionwithwallet(self.w.fundrawtransaction(self.payment(10_000), {"changePosition": 2}, False)["hex"])
        tx = Tx.parse(bytes.fromhex(signed["hex"]))
        self.w.sendrawtransaction(signed["hex"])
        self.c.add([tx])
        self.c.add([self.c.pay(script_of(5), 1, spend=(tx, 0)), self.c.pay(script_of(6), 1, spend=(tx, 2))])  # its outputs spent
        again = self.light([self.f1, self.f2], rules_for(self.c), timeout=1.0).wallet(os.path.join(self.dir, "key"))
        self.assertEqual(again.gettransaction(tx.txid_hex())["confirmations"], 2)
        self.f2.hang = True
        self.f1.refuse = "bad-txns-inputs-missingorspent"
        blind = self.light([self.f1, self.f2], rules_for(self.c), timeout=1.0).wallet(os.path.join(self.dir, "key"))
        for call in (lambda: blind.gettransaction(tx.txid_hex()), lambda: blind.sendrawtransaction(signed["hex"])):
            with self.assertRaises(L.Unreachable) as e:
                call()
            self.assertNotIsInstance(e.exception, RPCError)
        with self.assertRaises(L.Unreachable):
            blind.payments_to(self.payee.hex())
        self.f2.hang = False
        blind.servers[1].good()
        self.assertEqual(blind.sendrawtransaction(signed["hex"]), tx.txid_hex())  # asked again, both there: it is a payment made
        self.assertEqual(blind.gettransaction(tx.txid_hex())["confirmations"], 2)

    def test_someone_elses_inputs_are_not_signed(self):
        other = Tx(2, [TxIn(self.c.txs[1][0].txid(), 0)], [TxOut(1, self.payee)])
        r = self.w.signrawtransactionwithwallet(other.serialize().hex())
        self.assertFalse(r["complete"])
        with self.assertRaises(L.NotAvailable):
            self.w.fundrawtransaction(other.serialize().hex())
        plain = self.light([self.f1], rules_for(self.c))
        for call in (plain.fundrawtransaction, plain.signrawtransactionwithwallet):
            with self.assertRaises(L.NotAvailable):
                call(self.payment(1))

    def test_a_value_only_the_servers_claim(self):
        key = (self.coin1.txid_hex(), 0)
        self.f1.value_lie[key] = self.f2.value_lie[key] = 9 * COIN
        with self.assertRaises(L.Disagreement):
            self.w.fundrawtransaction(self.payment(8 * COIN), {"changePosition": 2}, False)


class Connect(Base):
    def test_urls(self):
        b = L.connect("electrums://a.example:50002,b.example,[::1]:7?net=regtest&agree=1&timeout=4")
        self.assertEqual([(s.host, s.port, s.tls, s.timeout) for s in b.servers],
                         [("a.example", 50002, True, 4.0), ("b.example", 50002, True, 4.0), ("::1", 7, True, 4.0)])
        self.assertEqual((b.rules.chain, b.agree), ("regtest", 1))
        b = L.connect("electrum://h1:50001,h2", anchor=(1234, "00" * 80, 5))
        self.assertEqual([(s.host, s.port, s.tls) for s in b.servers], [("h1", 50001, False), ("h2", 50001, False)])
        self.assertEqual((b.rules.chain, b.agree, b._low_hint, b.rules.checkpoint[0]), ("main", 2, 1234, 965_000))
        for bad in ("http://x:1", "electrum://", "electrum://a:b", "electrum://a:1?net=testnet", "127.0.0.1:50001"):
            with self.assertRaises(ValueError):
                L.connect(bad)
        self.assertTrue(L.is_light_url("electrums://x:1"))
        self.assertFalse(L.is_light_url("http://user:pass@127.0.0.1:8332"))
        self.assertFalse(L.is_light_url(None))

    def test_through_a_url(self):
        c = Chain(length=6)
        f = self.fake(c)
        b = L.connect(f"electrum://127.0.0.1:{f.port}", net=rules_for(c), poll=0)
        self.lights.append(b)
        self.assertEqual((b.getblockcount(), b.agree, b._quorum()), (6, 2, 1))

    def test_nobody_there(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        c = Chain(length=2)
        b = L.connect(f"electrum://127.0.0.1:{port}", net=rules_for(c), timeout=1)
        with self.assertRaises(L.Unreachable):
            b.getblockcount()
        with self.assertRaises(ConnectionError):  # what a caller that expects a node that is down catches
            b.getblockchaininfo()

    def test_tls(self):
        if not shutil.which("openssl"):
            self.skipTest("no openssl to make a certificate with")
        d = tempfile.mkdtemp()
        try:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{d}/k", "-out", f"{d}/c",
                            "-days", "2", "-subj", "/CN=localhost"], check=True, capture_output=True)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(f"{d}/c", f"{d}/k")
        finally:
            pass
        c = Chain(length=4)
        f = self.fake(c, tls=ctx)
        b = L.connect(f"electrums://127.0.0.1:{f.port}", net=rules_for(c))
        self.lights.append(b)
        self.assertEqual(b.getblockcount(), 4)
        strict = L.connect(f"electrums://127.0.0.1:{f.port}?verify=1", net=rules_for(c), timeout=2)
        with self.assertRaises(L.Unreachable):  # a certificate it signed itself, where checking was asked for
            strict.getblockcount()
        shutil.rmtree(d, ignore_errors=True)

    def test_through_a_proxy(self):
        c = Chain(length=4)
        f = self.fake(c)
        seen = []
        px = socket.socket()
        px.bind(("127.0.0.1", 0))
        px.listen(8)

        def pipe(a, b):
            try:
                while True:
                    d = a.recv(65536)
                    if not d:
                        break
                    b.sendall(d)
            except OSError:
                pass

        def proxy():
            while True:
                try:
                    conn, _ = px.accept()
                except OSError:
                    return
                head = b""
                while b"\r\n\r\n" not in head:
                    head += conn.recv(4096)
                line = head.split(b"\r\n")[0].decode()
                seen.append(line)
                if "refuse.me" in line:
                    conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                    conn.close()
                    continue
                up = socket.create_connection(("127.0.0.1", int(line.split()[1].rsplit(":", 1)[1])))
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                threading.Thread(target=pipe, args=(conn, up), daemon=True).start()
                threading.Thread(target=pipe, args=(up, conn), daemon=True).start()
        threading.Thread(target=proxy, daemon=True).start()
        b = L.connect(f"electrum://localhost:{f.port}?proxy=http://127.0.0.1:{px.getsockname()[1]}", net=rules_for(c))
        self.lights.append(b)
        self.assertEqual(b.getblockcount(), 4)
        self.assertEqual(seen, [f"CONNECT localhost:{f.port} HTTP/1.1"])
        no = L.connect(f"electrum://refuse.me:1?proxy=127.0.0.1:{px.getsockname()[1]}", net=rules_for(c))
        with self.assertRaises(L.Unreachable) as e:
            no.getblockcount()
        self.assertIn("403", str(e.exception))
        px.close()


if __name__ == "__main__":
    unittest.main()
