"""Python model of the sats leg (mirrors src/launchyield.{h,cpp}; test_diff_cpp compares them).

A curve block owes real BTC on top of its hash. Six blocks later the draw fixes how much is
due and to whom (80% a holder who has not moved, 10% creator, 10% dev). The miner pays on
Bitcoin with a tagged transaction and proves it on the launch chain by SPV against Bitcoin
headers relayed inside launch blocks."""
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .crypto import sha256, sha256d
from .ser import Tx, bits_to_target, target_to_bits

MAX_MONEY = 21_000_000 * 100_000_000
DRAW_DELAY = 6
MAX_CANDIDATES = 16
HOLDER_BPS, CREATOR_BPS = 8000, 1000
HOLDER, CREATOR, DEV = 0, 1, 2
OP_RETURN = 0x6A


def owed(work: int, num: int, shift: int) -> int:
    if num == 0 or work == 0 or shift >= 256:
        return 0
    if work > (2**256 - 1) >> 63:
        return MAX_MONEY
    return min((work * num) >> shift, MAX_MONEY)


def draw_seed(launch_id: bytes, seed_block_hash: bytes) -> bytes:
    """Both arguments in raw (internal) byte order."""
    return sha256d(b"hashfun-draw" + launch_id + seed_block_hash)


def compute_draw(owed_sats: int, min_payment: int, seed: bytes) -> Tuple[int, int]:
    """(sats due, payee class). 0 due = the block settles itself."""
    pay = 0
    if owed_sats > 0:
        if owed_sats >= min_payment:
            pay = owed_sats
        elif int.from_bytes(seed[:8], "little") % min_payment < owed_sats:
            pay = min_payment
    r = int.from_bytes(seed[8:16], "little") % 10000
    return pay, (HOLDER if r < HOLDER_BPS else CREATOR if r < HOLDER_BPS + CREATOR_BPS else DEV)


def candidate_point(seed: bytes, i: int, registered_total: int) -> int:
    return int.from_bytes(sha256(seed + b"c" + struct.pack("<I", i)), "little") % registered_total


def pay_tag(launch_id: bytes, mint_block_hash: bytes) -> bytes:
    return sha256(b"hashfun-pay" + launch_id + mint_block_hash)[:20]


def push_data(data: bytes) -> bytes:
    if len(data) < 0x4C:
        return bytes([len(data)]) + data
    if len(data) < 0x100:
        return b"\x4c" + bytes([len(data)]) + data
    if len(data) < 0x10000:
        return b"\x4d" + struct.pack("<H", len(data)) + data
    return b"\x4e" + struct.pack("<I", len(data)) + data


def op_return(data: bytes) -> bytes:
    return bytes([OP_RETURN]) + push_data(data)


def tagged_return(script: bytes, tag: bytes) -> Optional[bytes]:
    """Data of a script that is OP_RETURN <exactly one push starting with tag>."""
    if not script or script[0] != OP_RETURN or len(script) < 2:
        return None
    op, rest = script[1], script[2:]
    if op < 0x4C:
        n = op
    elif op == 0x4C and len(rest) >= 1:
        n, rest = rest[0], rest[1:]
    elif op == 0x4D and len(rest) >= 2:
        n, rest = struct.unpack("<H", rest[:2])[0], rest[2:]
    elif op == 0x4E and len(rest) >= 4:
        n, rest = struct.unpack("<I", rest[:4])[0], rest[4:]
    else:
        return None
    if len(rest) != n or not rest.startswith(tag):
        return None
    return rest


def registered_outputs(tx: Tx, coinbase: bool) -> List[Tuple[int, int, bytes]]:
    """[(vout, value, btc_script)] of outputs that earn yield (see launchyield.h)."""
    btc_script = b""
    for o in tx.vout:
        data = tagged_return(o.script_pubkey, b"HFY1")
        if data is not None:
            if not 5 <= len(data) <= 84:
                return []
            btc_script = data[4:]
            break
    if not btc_script:
        return []
    out = []
    for i, o in enumerate(tx.vout):
        if coinbase and i > 0:
            break
        if o.value <= 0 or o.script_pubkey[:1] == bytes([OP_RETURN]):
            continue
        out.append((i, o.value, btc_script))
    return out


def yield_tag_script(btc_script: bytes) -> bytes:
    return op_return(b"HFY1" + btc_script)


# ------------------------------------------------------------ payment proofs
@dataclass
class PaymentProof:
    mint_height: int
    btc_block: bytes  # raw byte order
    tx_index: int
    branch: List[bytes]
    pay_vout: int
    candidate: int
    raw_tx: bytes

    def payload(self) -> bytes:
        return (b"HFP1" + struct.pack("<I", self.mint_height) + self.btc_block + struct.pack("<I", self.tx_index) +
                bytes([len(self.branch)]) + b"".join(self.branch) + struct.pack("<I", self.pay_vout) +
                bytes([self.candidate]) + self.raw_tx)

    @classmethod
    def parse(cls, p: bytes) -> Optional["PaymentProof"]:
        if len(p) < 45:
            return None
        n = p[44]
        if n > 32 or len(p) < 45 + 32 * n + 5:
            return None
        off = 45 + 32 * n
        return cls(struct.unpack("<I", p[4:8])[0], p[8:40], struct.unpack("<I", p[40:44])[0],
                   [p[45 + 32 * i:77 + 32 * i] for i in range(n)], struct.unpack("<I", p[off:off + 4])[0], p[off + 4],
                   p[off + 5:])


def payment_outputs_tag(tags: List[bytes]) -> bytes:
    """OP_RETURN script binding output i of a Bitcoin tx to tags[i]."""
    return op_return(b"HF" + b"".join(tags))


def verify_btc_payment(proof: PaymentProof, merkle_root: bytes, tag: bytes, recipient_script: bytes,
                       pay: int) -> Tuple[bool, str]:
    raw = proof.raw_tx
    if len(raw) < 60 or len(raw) == 64 or len(raw) > 100000:
        return False, "btc tx size"
    try:
        tx = Tx.parse(raw)
        if tx.serialize(witness=False) != raw:
            raise ValueError
    except Exception:
        return False, "btc tx does not parse (must be serialized without witness)"
    if not tx.vin or not tx.vout:
        return False, "btc tx has no inputs or outputs"
    if len(proof.branch) < 32 and proof.tx_index >> len(proof.branch):
        return False, "btc tx index outside the merkle tree"
    h, idx = sha256d(raw), proof.tx_index
    for sib in proof.branch:
        h = sha256d(sib + h) if idx & 1 else sha256d(h + sib)
        idx >>= 1
    if h != merkle_root:
        return False, "btc merkle proof does not match the block"
    if proof.pay_vout >= len(tx.vout):
        return False, "btc pay output missing"
    out = tx.vout[proof.pay_vout]
    if out.value < pay or out.script_pubkey != recipient_script:
        return False, "btc output does not pay the drawn recipient enough"
    for o in tx.vout:
        data = tagged_return(o.script_pubkey, b"HF")
        if data is None or (len(data) - 2) % 20:
            continue
        pos = 2 + 20 * proof.pay_vout
        if data[pos:pos + 20] == tag and len(data) >= pos + 20:
            return True, ""
    return False, "btc tx does not bind this output to the mint block"


# ------------------------------------------------------------ Bitcoin headers
BTC_POW_LIMIT_BITS = 0x1D00FFFF
BTC_REGTEST_BITS = 0x207FFFFF
BTC_TIMESPAN = 14 * 24 * 3600
BTC_INTERVAL = 2016


@dataclass
class BtcNode:
    prev: bytes
    merkle_root: bytes
    time: int
    bits: int
    height: int
    work: int


@dataclass
class BtcChain:
    """Bitcoin header tree from the anchor; best = most work, ties to the lowest hash."""
    anchor_header: bytes
    anchor_height: int
    anchor_period_time: int
    regtest: bool
    nodes: Dict[bytes, BtcNode] = field(default_factory=dict)
    children: Dict[bytes, int] = field(default_factory=dict)

    def __post_init__(self):
        h = self.anchor_header
        self.anchor = sha256d(h)
        self.nodes[self.anchor] = BtcNode(h[4:36], h[36:68], struct.unpack("<I", h[68:72])[0],
                                          struct.unpack("<I", h[72:76])[0], self.anchor_height, 0)
        self.best = self.anchor

    @staticmethod
    def _key(hash_: bytes) -> int:
        return int.from_bytes(hash_, "little")

    def expected_bits(self, prev: BtcNode) -> int:
        if self.regtest:
            return BTC_REGTEST_BITS
        height = prev.height + 1
        if height % BTC_INTERVAL:
            return prev.bits
        first_height, first_time, n = height - BTC_INTERVAL, self.anchor_period_time, prev
        while n.height > first_height:
            p = self.nodes.get(n.prev)
            if p is None:
                break
            n = p
        if n.height == first_height:
            first_time = n.time
        span = min(max(prev.time - first_time, BTC_TIMESPAN // 4), BTC_TIMESPAN * 4)
        target = min(bits_to_target(prev.bits) * span // BTC_TIMESPAN, bits_to_target(BTC_POW_LIMIT_BITS))
        return target_to_bits(target)

    def accept(self, header: bytes) -> Tuple[bool, str]:
        hash_ = sha256d(header)
        if hash_ in self.nodes:
            return False, "btc header already known"
        prev = self.nodes.get(header[4:36])
        if prev is None:
            return False, "btc header does not connect"
        time_, bits = struct.unpack("<II", header[68:76])
        if bits != self.expected_bits(prev):
            return False, "btc header has wrong difficulty"
        target = bits_to_target(bits)
        if target == 0 or self._key(hash_) > target:
            return False, "btc header lacks proof of work"
        times, n = [], prev
        while n is not None and len(times) < 11:
            times.append(n.time)
            n = self.nodes.get(n.prev)
        if time_ <= sorted(times)[len(times) // 2]:
            return False, "btc header time is not past the median"
        work = prev.work + 2**256 // (target + 1)
        b = self.nodes[self.best]
        better = work > b.work or (work == b.work and self._key(hash_) < self._key(self.best))
        self.nodes[hash_] = BtcNode(header[4:36], header[36:68], time_, bits, prev.height + 1, work)
        self.children[header[4:36]] = self.children.get(header[4:36], 0) + 1
        if better:
            self.best = hash_
        return True, ""

    def remove(self, hash_: bytes):
        if hash_ not in self.nodes or hash_ == self.anchor or hash_ in self.children:
            return
        prev = self.nodes.pop(hash_).prev
        self.children[prev] -= 1
        if not self.children[prev]:
            del self.children[prev]
        if hash_ == self.best:
            self.best = min(self.nodes, key=lambda k: (-self.nodes[k].work, self._key(k)))

    def confirmations(self, hash_: bytes) -> int:
        t = self.nodes.get(hash_)
        if t is None:
            return 0
        cur, n = self.best, self.nodes[self.best]
        while n is not None and n.height > t.height:
            cur = n.prev
            n = self.nodes.get(cur)
        if n is None or cur != hash_:
            return 0
        return self.nodes[self.best].height - t.height + 1
