"""In-process chain simulator speaking the Bitcoin Core / hashfund RPC surface the
Python stack uses. Consensus comes from the independent Python model
(hashfun.descriptor) plus hashfun.interp for scripts, so the pool, merged-mining
coordinator, Electrum server, wallet, swap engine and maker can be exercised
end to end without binaries. It is a test double, not a node: the real-node
harness is tests/e2e_regtest.py."""
import struct
import threading
from typing import Dict, List, Optional

from hashfun import descriptor as D
from hashfun.auxpow import check_auxpow, parse_auxpow
from hashfun.crypto import sha256d, pubkey_from_priv, ecdsa_sign, der_sig, random_priv, hash160
from hashfun.interp import verify_input, ScriptError
from hashfun.rpc import RPCError
from hashfun.ser import (Tx, TxIn, TxOut, Reader, varint, header_bytes, merkle_root, bits_to_target, work_from_bits,
                         witness_commitment_script, segwit_encode, address_to_script, p2wpkh_script,
                         p2wpkh_script_code, bip143_sighash, push_int, push, WITNESS_MAGIC)

COIN = 100_000_000


def err(code, msg):
    raise RPCError({"code": code, "message": msg})


class Block:
    def __init__(self, header: bytes, txs: List[Tx], auxpow: bytes = b""):
        self.header, self.txs, self.auxpow = header, txs, auxpow

    @property
    def hash(self) -> bytes:
        return sha256d(self.header)

    @property
    def hash_hex(self):
        return self.hash[::-1].hex()

    @property
    def version(self):
        return struct.unpack("<i", self.header[:4])[0]

    @property
    def time(self):
        return struct.unpack("<I", self.header[68:72])[0]

    @property
    def bits(self):
        return struct.unpack("<I", self.header[72:76])[0]

    def serialize(self) -> bytes:
        return self.header + self.auxpow + varint(len(self.txs)) + b"".join(t.serialize() for t in self.txs)

    @classmethod
    def parse(cls, raw: bytes) -> "Block":
        r = Reader(raw)
        hdr = r.read(80)
        aux = b""
        if struct.unpack("<i", hdr[:4])[0] & 0x100:
            start = r.i
            Tx._parse(r)
            r.read(32)
            for _ in range(r.varint()):
                r.read(32)
            r.read(4)
            for _ in range(r.varint()):
                r.read(32)
            r.read(4)
            r.read(80)
            aux = raw[start:r.i]
        txs = [Tx._parse(r) for _ in range(r.varint())]
        if not r.done():
            raise ValueError("trailing block bytes")
        return cls(hdr, txs, aux)


class Clock:
    """Shared wall clock so several simulated chains agree on time."""

    def __init__(self, t=1_800_000_000):
        self.t = t


class SimChain:
    """launch=None simulates the BTC regtest parent (fixed bits, 50 BTC halving every 150)."""

    def __init__(self, name: str, launch: Optional[D.Launch] = None, hrp: str = "bcrt", start_time=1_800_000_000,
                 maturity=1, clock: "Clock" = None):
        self.name, self.launch = name, launch
        self.hrp = launch.hrp if launch else hrp
        self.lock = threading.RLock()
        self.maturity = maturity
        self._clock = clock or Clock(start_time)
        self.blocks: List[Block] = []
        self.index: Dict[bytes, int] = {}
        self.utxos: Dict[tuple, tuple] = {}  # (txid_le, n) -> (TxOut, height, coinbase)
        self.mempool: Dict[bytes, Tx] = {}
        self.txloc: Dict[bytes, int] = {}
        self.wallet_keys: Dict[bytes, int] = {}  # spk -> priv
        self.aux_blocks: Dict[bytes, Block] = {}
        if launch:
            if not launch.genesis_valid():
                launch.grind_genesis()
            cb = launch.genesis_coinbase()
            g = Block(launch.genesis_header(), [cb])
        else:
            cb = Tx(version=1, vin=[TxIn(b"\0" * 32, 0xFFFFFFFF, push(b"sim btc genesis"), 0xFFFFFFFF)],
                    vout=[TxOut(50 * COIN, b"\x6a")])
            g = Block(header_bytes(1, b"\0" * 32, cb.txid(), self.clock, 0x207FFFFF, 0), [cb])
        self.blocks.append(g)
        self.index[g.hash] = 0
        self.txloc[cb.txid()] = 0
        self.works = [work_from_bits(g.bits)]

    # ------------------------------------------------------------ consensus model
    @property
    def height(self):
        return len(self.blocks) - 1

    def rel_work(self, height=None) -> int:
        h = self.height if height is None else height
        return sum(self.works[1:h + 1])

    def next_bits(self) -> int:
        if not self.launch:
            return 0x207FFFFF
        return self.launch.lwma_next_bits([b.time for b in self.blocks], [b.bits for b in self.blocks])

    def subsidy(self, height: int, bits: int) -> int:
        if not self.launch:
            return (50 * COIN) >> (height // 150)
        return self.launch.subsidy(self.rel_work(height - 1), bits, height)

    def graduated(self, height=None) -> bool:
        return bool(self.launch) and self.rel_work(height) >= self.launch.graduation_work

    def version(self) -> int:
        return (4 | (self.launch.chain_id << 16)) if self.launch else 0x20000000

    def mtp(self, height=None) -> int:
        h = self.height if height is None else height
        ts = sorted(b.time for b in self.blocks[max(0, h - 10):h + 1])
        return ts[len(ts) // 2]

    def _final(self, tx: Tx, height: int, mtp: int) -> bool:
        if tx.locktime == 0 or all(i.sequence == 0xFFFFFFFF for i in tx.vin):
            return True
        cutoff = height if tx.locktime < 500_000_000 else mtp
        return tx.locktime < cutoff

    def _check_tx(self, tx: Tx, view: dict, height: int, mtp: int) -> int:
        if not self._final(tx, height, mtp):
            err(-26, "non-final")
        total_in = 0
        for idx, i in enumerate(tx.vin):
            key = (i.prev_txid, i.prev_vout)
            if key not in view:
                err(-25, "bad-txns-inputs-missingorspent")
            out, h, is_cb = view[key]
            if is_cb and height - h < self.maturity:
                err(-26, "bad-txns-premature-spend-of-coinbase")
            try:
                verify_input(tx, idx, out.script_pubkey, out.value)
            except ScriptError as e:
                err(-26, f"mandatory-script-verify-flag-failed ({e})")
            total_in += out.value
        total_out = sum(o.value for o in tx.vout)
        if total_out > total_in:
            err(-26, "bad-txns-in-belowout")
        return total_in - total_out

    def _apply(self, tx: Tx, view: dict, height: int, is_cb=False):
        for i in tx.vin:
            if not is_cb:
                del view[(i.prev_txid, i.prev_vout)]
        for n, o in enumerate(tx.vout):
            if o.script_pubkey[:1] != b"\x6a":
                view[(tx.txid(), n)] = (o, height, is_cb)

    def connect(self, blk: Block):
        with self.lock:
            prev = blk.header[4:36]
            if prev != self.blocks[-1].hash:
                return "inconclusive" if prev in self.index else "prev-blk-not-found"
            height = self.height + 1
            if blk.bits != self.next_bits():
                return "bad-diffbits"
            target = bits_to_target(blk.bits)
            if blk.auxpow:
                if not self.launch:
                    return "auxpow-on-btc"
                if not self.graduated():
                    return "auxpow-before-graduation"
                if not blk.version & 0x100:
                    return "auxpow-flag"
                ok, why = check_auxpow(blk.hash, blk.version >> 16, blk.auxpow)
                if not ok:
                    return why
                parent_hdr = parse_auxpow(blk.auxpow)[4]
                if int.from_bytes(sha256d(parent_hdr), "little") > target:
                    return "high-hash (aux)"
            else:
                if blk.version & 0x100:
                    return "auxpow-flag"
                if int.from_bytes(blk.hash, "little") > target:
                    return "high-hash"
            if self.launch and (blk.version >> 16) != self.launch.chain_id:
                return "bad-chainid"
            if blk.time <= self.mtp():
                return "time-too-old"
            txids = [t.txid() for t in blk.txs]
            if merkle_root(txids) != blk.header[36:68]:
                return "bad-txnmrklroot"
            cb = blk.txs[0]
            if not cb.vin[0].script_sig.startswith(push_int(height)):
                return "bad-cb-height"
            # witness commitment
            if any(t.has_witness() for t in blk.txs[1:]) or any(o.script_pubkey[2:6] == WITNESS_MAGIC for o in cb.vout):
                wt = [b"\0" * 32] + [t.wtxid() for t in blk.txs[1:]]
                reserved = cb.vin[0].witness[0] if cb.vin[0].witness else None
                if reserved is None or len(reserved) != 32:
                    return "bad-witness-nonce-size"
                commits = [o.script_pubkey for o in cb.vout if o.script_pubkey[2:6] == WITNESS_MAGIC]
                if not commits or commits[-1] != witness_commitment_script(wt, reserved):
                    return "bad-witness-merkle-match"
            view = dict(self.utxos)
            mtp = self.mtp()
            fees = 0
            for t in blk.txs[1:]:
                try:
                    fees += self._check_tx(t, view, height, mtp)
                except RPCError as e:
                    return e.message
                self._apply(t, view, height)
            sub = self.subsidy(height, blk.bits)
            if sum(o.value for o in cb.vout) > sub + fees:
                return "bad-cb-amount"
            if self.launch and self.launch.creator_fee_bps:
                need = self.launch.creator_fee(sub)
                paid = sum(o.value for o in cb.vout if o.script_pubkey == self.launch.creator_script)
                if paid < need:
                    return "bad-cb-creator-fee"
            self._apply(cb, view, height, is_cb=True)
            self.utxos = view
            self.blocks.append(blk)
            self.index[blk.hash] = height
            self.works.append(work_from_bits(blk.bits))
            for t in blk.txs:
                self.txloc[t.txid()] = height
                self.mempool.pop(t.txid(), None)
            # evict mempool txs that conflict now
            for txid, t in list(self.mempool.items()):
                if any((i.prev_txid, i.prev_vout) not in self.utxos and i.prev_txid not in self.mempool for i in t.vin):
                    self.mempool.pop(txid)
            self.clock = max(self.clock, blk.time) + (self.launch.target_spacing if self.launch else 600)
            return None

    # ------------------------------------------------------------ templates
    def template(self, payout_spk: bytes = None):
        with self.lock:
            height = self.height + 1
            bits = self.next_bits()
            sub = self.subsidy(height, bits)
            fee = self.launch.creator_fee(sub) if self.launch else 0
            txs = list(self.mempool.values())
            view = dict(self.utxos)
            fees = 0
            ok = []
            for t in txs:
                try:
                    fees += self._check_tx(t, view, height, self.mtp())
                    self._apply(t, view, height)
                    ok.append(t)
                except RPCError:
                    continue
            wt = [b"\0" * 32] + [t.wtxid() for t in ok]
            return {"height": height, "bits": bits, "subsidy": sub, "creator_fee": fee, "fees": fees, "txs": ok,
                    "commitment": witness_commitment_script(wt), "time": max(self.clock, self.mtp() + 1)}

    def build_block(self, payout_spk: bytes, en: bytes = b"", aux=False) -> Block:
        t = self.template()
        outs = [TxOut(t["subsidy"] - t["creator_fee"] + t["fees"], payout_spk)]
        if t["creator_fee"]:
            outs.append(TxOut(t["creator_fee"], self.launch.creator_script))
        outs.append(TxOut(0, t["commitment"]))
        cb = Tx(version=2, vin=[TxIn(b"\0" * 32, 0xFFFFFFFF, push_int(t["height"]) + push(en or b"\x00\x00"), 0xFFFFFFFF,
                                     [b"\0" * 32])], vout=outs)
        txs = [cb] + t["txs"]
        version = self.version() | (0x100 if aux else 0)
        hdr = header_bytes(version, self.blocks[-1].hash, merkle_root([x.txid() for x in txs]), t["time"], t["bits"], 0)
        return Block(hdr, txs)

    def mine(self, n=1, payout_spk: bytes = None) -> List[str]:
        out = []
        for _ in range(n):
            spk = payout_spk or self.wallet_spk()
            b = self.build_block(spk, en=struct.pack("<I", len(self.blocks)))
            target = bits_to_target(b.bits)
            nonce = 0
            while True:
                hdr = b.header[:76] + struct.pack("<I", nonce)
                if int.from_bytes(sha256d(hdr), "little") <= target:
                    break
                nonce += 1
            b.header = hdr
            r = self.connect(b)
            assert r is None, r
            out.append(b.hash_hex)
        return out

    @property
    def clock(self):
        return self._clock.t

    @clock.setter
    def clock(self, v):
        self._clock.t = v

    def advance(self, seconds: int):
        self.clock += seconds

    def rewind_to(self, height: int):
        """Disconnect blocks above `height` (replays from genesis) to simulate a reorg."""
        with self.lock:
            keep = self.blocks[1:height + 1]
            dropped = [t for b in self.blocks[height + 1:] for t in b.txs[1:]]
            g = self.blocks[0]
            clock = self.clock
            self.blocks, self.index, self.works = [g], {g.hash: 0}, [work_from_bits(g.bits)]
            self.utxos, self.txloc = {}, {g.txs[0].txid(): 0}
            mem = {t.txid(): t for t in dropped}  # disconnected txs go back to the mempool first
            mem.update(self.mempool)
            self.mempool = {}
            for b in keep:
                r = self.connect(b)
                assert r is None, r
            self.clock = clock
            for t in mem.values():
                try:
                    self.accept(t)
                except RPCError:
                    pass

    # ------------------------------------------------------------ wallet
    def wallet_spk(self) -> bytes:
        k = random_priv()
        spk = p2wpkh_script(pubkey_from_priv(k))
        self.wallet_keys[spk] = k
        return spk

    def wallet_utxos(self):
        spent = {(i.prev_txid, i.prev_vout) for t in self.mempool.values() for i in t.vin}
        out = []
        for key, (o, h, is_cb) in self.utxos.items():
            if o.script_pubkey in self.wallet_keys and key not in spent:
                if is_cb and self.height + 1 - h < self.maturity:
                    continue
                out.append((key, o))
        for txid, t in self.mempool.items():
            for n, o in enumerate(t.vout):
                if o.script_pubkey in self.wallet_keys and (txid, n) not in spent:
                    out.append(((txid, n), o))
        return out

    def wallet_send(self, spk: bytes, amount: int, feerate=2) -> Tx:
        utxos = sorted(self.wallet_utxos(), key=lambda u: -u[1].value)
        sel, total = [], 0
        for u in utxos:
            sel.append(u)
            total += u[1].value
            if total >= amount + feerate * (11 + 68 * len(sel) + 31 * 2 + len(spk)):
                break
        else:
            err(-6, "Insufficient funds")
        fee = feerate * (11 + 68 * len(sel) + 31 * 2 + len(spk))
        tx = Tx(version=2, vin=[TxIn(k[0], k[1], b"", 0xFFFFFFFD) for k, _ in sel], vout=[TxOut(amount, spk)])
        if total - amount - fee > 546:
            tx.vout.append(TxOut(total - amount - fee, self.wallet_spk()))
        for idx, (_, o) in enumerate(sel):
            k = self.wallet_keys[o.script_pubkey]
            pub = pubkey_from_priv(k)
            sig = der_sig(*ecdsa_sign(k, bip143_sighash(tx, idx, p2wpkh_script_code(pub), o.value))) + b"\x01"
            tx.vin[idx].witness = [sig, pub]
        self.accept(tx)
        return tx

    def accept(self, tx: Tx) -> str:
        with self.lock:
            view = dict(self.utxos)
            for t in self.mempool.values():
                for i in t.vin:
                    view.pop((i.prev_txid, i.prev_vout), None)
                for n, o in enumerate(t.vout):
                    view[(t.txid(), n)] = (o, self.height + 1, False)
            self._check_tx(tx, view, self.height + 1, self.mtp())
            self.mempool[tx.txid()] = tx
            return tx.txid_hex()

    def find_tx(self, txid_le: bytes) -> Optional[Tx]:
        if txid_le in self.mempool:
            return self.mempool[txid_le]
        h = self.txloc.get(txid_le)
        if h is None:
            return None
        return next(t for t in self.blocks[h].txs if t.txid() == txid_le)

    # ------------------------------------------------------------ RPC surface
    def __getattr__(self, name):
        if name.startswith("_") or name not in RPC_METHODS:
            raise AttributeError(name)
        fn = RPC_METHODS[name]
        return lambda *a: fn(self, *a)

    def wallet(self, _name):
        return self


def _hex_be(n: int) -> str:
    return f"{n:064x}"


def r_getbestblockhash(c):
    return c.blocks[-1].hash_hex


def r_getblockcount(c):
    return c.height


def r_getblockhash(c, h):
    if not 0 <= h <= c.height:
        err(-8, "Block height out of range")
    return c.blocks[h].hash_hex


def _blk(c, h):
    i = c.index.get(bytes.fromhex(h)[::-1])
    if i is None:
        err(-5, "Block not found")
    return i, c.blocks[i]


def r_getblock(c, h, verbosity=1):
    i, b = _blk(c, h)
    if verbosity == 0:
        return b.serialize().hex()
    return {"hash": b.hash_hex, "height": i, "tx": [t.txid_hex() for t in b.txs], "time": b.time,
            "bits": f"{b.bits:08x}"}


def r_getblockheader(c, h, verbose=True):
    i, b = _blk(c, h)
    return {"hash": b.hash_hex, "height": i, "time": b.time, "bits": f"{b.bits:08x}", "nTx": len(b.txs),
            "version": b.version}


def r_getblockchaininfo(c):
    return {"chain": "sim", "blocks": c.height, "bestblockhash": c.blocks[-1].hash_hex, "mediantime": c.mtp()}


def r_getblocktemplate(c, req=None):
    t = c.template()
    out = {"version": c.version(), "previousblockhash": c.blocks[-1].hash_hex, "height": t["height"],
           "bits": f"{t['bits']:08x}", "target": _hex_be(bits_to_target(t["bits"])), "curtime": t["time"],
           "mintime": c.mtp() + 1, "coinbasevalue": t["subsidy"] - t["creator_fee"] + t["fees"],
           "transactions": [{"data": x.serialize().hex(), "txid": x.txid_hex(), "hash": x.wtxid()[::-1].hex()}
                            for x in t["txs"]],
           "default_witness_commitment": t["commitment"].hex()}
    if t["creator_fee"]:
        out["creatorfee"] = {"script": c.launch.creator_script.hex(), "amount": t["creator_fee"]}
    return out


def r_submitblock(c, hexdata):
    return c.connect(Block.parse(bytes.fromhex(hexdata)))


def r_getlaunchinfo(c):
    if not c.launch:
        err(-1, "not a hashfun launch chain")
    d = c.launch
    w = c.rel_work()
    cs = d.curve_supply(w)
    grad = w >= d.graduation_work
    gh = -1
    if grad:
        gh = next(h for h in range(1, c.height + 1) if c.rel_work(h) >= d.graduation_work)
    tail = sum(d.tail_reward_at(h) for h in range(gh + 1, c.height + 1)) if grad else 0
    nb = c.next_bits()
    ns = c.subsidy(c.height + 1, nb)
    return {"launch_id": d.id_hex, "name": d.name, "ticker": d.ticker, "hrp": d.hrp, "genesis_hash": d.genesis_hash,
            "chain_id": d.chain_id, "height": c.height, "work": _hex_be(w), "curve_supply": cs, "tail_minted": tail,
            "supply": cs + tail, "progress": cs / d.graduation_tokens, "graduated": grad, "graduation_height": gh,
            "hashes_per_coin": d.hashes_per_coin(w),
            "curve": {"virtual_work": _hex_be(d.virtual_work), "virtual_tokens": d.virtual_tokens,
                      "graduation_tokens": d.graduation_tokens, "graduation_work": _hex_be(d.graduation_work),
                      "tail_reward": d.tail_reward, "tail_halving_interval": d.tail_halving_interval},
            "creator": {"script": d.creator_script.hex(), "fee_bps": d.creator_fee_bps},
            "next": {"bits": f"{nb:08x}", "work": _hex_be(work_from_bits(nb)), "subsidy": ns,
                     "creator_fee": d.creator_fee(ns), "auxpow_allowed": grad},
            "descriptor": d.to_json()}


def r_createauxblock(c, address):
    if not c.graduated():
        err(-1, "merge-mining is not available before the launch graduates")
    b = c.build_block(address_to_script(address, c.hrp), aux=True)
    c.aux_blocks[b.hash] = b
    t = c.template()
    return {"hash": b.hash_hex, "chainid": c.launch.chain_id, "previousblockhash": c.blocks[-1].hash_hex,
            "coinbasevalue": b.txs[0].vout[0].value, "bits": f"{b.bits:08x}", "height": t["height"],
            "_target": bits_to_target(b.bits).to_bytes(32, "little").hex()}


def r_submitauxblock(c, h, auxpow_hex):
    b = c.aux_blocks.get(bytes.fromhex(h)[::-1])
    if b is None:
        err(-8, "block hash unknown")
    blk = Block(b.header, b.txs, bytes.fromhex(auxpow_hex))
    return c.connect(blk) is None


def r_getrawmempool(c):
    return [t[::-1].hex() for t in c.mempool]


def r_getrawtransaction(c, txid, verbose=False, blockhash=None):
    t = c.find_tx(bytes.fromhex(txid)[::-1])
    if t is None:
        err(-5, "No such mempool or blockchain transaction")
    return t.serialize().hex()


def r_sendrawtransaction(c, hexdata):
    return c.accept(Tx.parse(bytes.fromhex(hexdata)))


def r_gettxout(c, txid, n, include_mempool=True):
    key = (bytes.fromhex(txid)[::-1], n)
    if include_mempool:
        for t in c.mempool.values():
            if any((i.prev_txid, i.prev_vout) == key for i in t.vin):
                return None
        mt = c.mempool.get(key[0])
        if mt is not None and n < len(mt.vout):
            o = mt.vout[n]
            return {"value": o.value / COIN, "scriptPubKey": {"hex": o.script_pubkey.hex()}, "confirmations": 0}
    u = c.utxos.get(key)
    if not u:
        return None
    o, h, _ = u
    return {"value": o.value / COIN, "scriptPubKey": {"hex": o.script_pubkey.hex()}, "confirmations": c.height - h + 1}


def r_estimatesmartfee(c, n, mode=None):
    return {"errors": ["Insufficient data or no feerate found"], "blocks": n}


def r_getnetworkinfo(c):
    return {"relayfee": 0.00001}


def r_getnewaddress(c, label="", typ="bech32"):
    return segwit_encode(c.hrp, 0, c.wallet_spk()[2:])


def r_sendtoaddress(c, address, amount):
    from decimal import Decimal
    tx = c.wallet_send(address_to_script(address, c.hrp), int(Decimal(str(amount)) * COIN))
    return tx.txid_hex()


def r_gettransaction(c, txid):
    t = c.find_tx(bytes.fromhex(txid)[::-1])
    if t is None:
        err(-5, "Invalid or non-wallet transaction id")
    return {"hex": t.serialize().hex(), "txid": txid}


def r_decoderawtransaction(c, hexdata):
    t = Tx.parse(bytes.fromhex(hexdata))
    return {"txid": t.txid_hex(), "vout": [{"value": o.value / COIN, "n": i} for i, o in enumerate(t.vout)]}


RPC_METHODS = {k[2:]: v for k, v in globals().items() if k.startswith("r_")}
