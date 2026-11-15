"""Python model of the two legs' pure functions (mirrors src/launchyield.{h,cpp}; test_diff_cpp
compares them). The state machine built on them is hashfun/yieldstate.py.

A curve block owes its curve's asset on top of its hash: real BTC on the BTC curve, real QWEN on
the QWEN curve. Six blocks later the draw fixes how much is due and to whom: 80% a holder, drawn
by value over the coins that are live at the draw, 10% the creator, 10% the dev. The miner pays on
that asset's own chain with a tagged transaction and proves it on the launch chain by SPV against
that chain's headers, relayed inside launch blocks (contrib/hashfun/TWIN.md)."""
import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .crypto import sha256, sha256d
from .ser import Tx, bits_to_target, target_to_bits

MAX_MONEY = 21_000_000 * 100_000_000
DRAW_DELAY = 6
HOLDER_BPS, CREATOR_BPS = 8000, 1000
HOLDER, CREATOR, DEV = 0, 1, 2
OP_RETURN = 0x6A
# The dev's 10% of the sats leg: bc1pctxxt9z57ypwrvdws45hgpgkx922e39gj3hkqe0hsgv3863f4ffsu7p7x3 (P2TR).
# Consensus-critical; the node's copy is HASHFUN_DEV_BTC_SCRIPT in src/kernel/chainparams.cpp.
DEV_BTC_SCRIPT = bytes.fromhex("5120c2cc659454f102e1b1ae85697405163154acc4a8946f6065f7821913ea29aa53")


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


def candidate_point(seed: bytes, i: int, total: int) -> int:
    """A point in [0, total). The holder draw uses i = 0 over the live value at the draw."""
    return int.from_bytes(sha256(seed + b"c" + struct.pack("<I", i)), "little") % total


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


def earns_yield(script: bytes) -> bool:
    """P2PKH, P2SH or a witness program: a script that means the same thing on Bitcoin."""
    n = len(script)
    if n == 25 and script[:3] == b"\x76\xa9\x14" and script[23:] == b"\x88\xac":
        return True
    if n == 23 and script[:2] == b"\xa9\x14" and script[22] == 0x87:
        return True
    return 4 <= n <= 42 and (script[0] == 0 or 0x51 <= script[0] <= 0x60) and script[1] == n - 2


def is_coinbase(tx: Tx) -> bool:
    return len(tx.vin) == 1 and tx.vin[0].prev_txid == bytes(32) and tx.vin[0].prev_vout == 0xFFFFFFFF


def registered_outputs(tx: Tx, coinbase: bool) -> List[Tuple[int, int, bytes]]:
    """The coins of a transaction: [(vout, value, yield script)]. Every output with a positive value
    and an earning script is a coin, and its yield is paid at its own script on Bitcoin.

    One exception: a coinbase may redirect its output 0. The first output of the coinbase that is
    OP_RETURN "HFY1"<payload> counts, and only if the payload is itself an earning script; then
    output 0's yield script is the payload. A first HFY1 with any other payload redirects nothing,
    and later HFY1 outputs are never looked at. HFY1 in any other transaction is ignored: whoever
    pays coins to someone does not get to name where their yield goes."""
    redirect = b""
    if coinbase:
        for o in tx.vout:
            data = tagged_return(o.script_pubkey, b"HFY1")
            if data is not None:
                if earns_yield(data[4:]):
                    redirect = data[4:]
                break
    out = []
    for i, o in enumerate(tx.vout):
        if o.value <= 0 or not earns_yield(o.script_pubkey):
            continue
        out.append((i, o.value, redirect if (redirect and i == 0) else o.script_pubkey))
    return out


def yield_tag_script(btc_script: bytes) -> bytes:
    return op_return(b"HFY1" + btc_script)


# ------------------------------------------------------------ payment proofs
# The two quote chains, by index (0: Bitcoin, 1: Qwencoin) and by name.
BTC, QWEN = 0, 1
QUOTE_NAMES = ("btc", "qwen")
HEADER_TAG = {"btc": b"HFH1", "qwen": b"HFH2"}  # OP_RETURN <tag><n * 80-byte headers of that chain>
PROOF_TAG = {"btc": b"HFP1", "qwen": b"HFP2"}   # OP_RETURN <tag><payment proof against that chain's relay>
LAUNCH_VERSION_QWEN = 0x200                     # bit 9 of a launch block's version: the block is on the QWEN curve


@dataclass
class PaymentProof:
    mint_height: int
    btc_block: bytes  # raw byte order
    tx_index: int
    branch: List[bytes]
    pay_vout: int
    candidate: int
    raw_tx: bytes

    def payload(self, quote: str = "btc") -> bytes:
        """The proof as it rides in OP_RETURN: "HFP1" for a payment on Bitcoin, "HFP2" for one on
        Qwencoin, then the same fields."""
        return (PROOF_TAG[quote] + struct.pack("<I", self.mint_height) + self.btc_block + struct.pack("<I", self.tx_index) +
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
    # Only the first tag list of the transaction counts. If every list counted, a transaction
    # with several lists could bind one paying output to several mint blocks, and one payment
    # would settle them all.
    for o in tx.vout:
        data = tagged_return(o.script_pubkey, b"HF")
        if data is None:
            continue
        pos = 2 + 20 * proof.pay_vout
        if (len(data) - 2) % 20 == 0 and len(data) >= pos + 20 and data[pos:pos + 20] == tag:
            return True, ""
        break
    return False, "btc tx does not bind this output to the mint block"


def parse_btc_headers(payload: bytes) -> Optional[List[bytes]]:
    """Payload of OP_RETURN "HFH1" (Bitcoin) or "HFH2" (Qwencoin): the tag, then n >= 1 headers of 80 bytes."""
    if len(payload) < 4 + 80 or (len(payload) - 4) % 80:
        return None
    return [payload[i:i + 80] for i in range(4, len(payload), 80)]


parse_headers = parse_btc_headers


# ------------------------------------------------------------ headers of the two quote chains
BTC_POW_LIMIT_BITS = 0x1D00FFFF
BTC_REGTEST_BITS = 0x207FFFFF
BTC_TIMESPAN = 14 * 24 * 3600
BTC_INTERVAL = 2016
QWEN_POW_LIMIT_BITS = 0x2000FFFF  # 256 expected passes through the weights per block
MAX_QWEN_PASSES = 8               # Qwencoin headers whose work one launch block may have evaluated
QWEN_MAX_TIMEWARP = 600           # Qwencoin: how far before its parent the first block of a period may be stamped


def muldiv(a: int, num: int, den: int) -> int:
    """floor(a * num / den) the way qwencoin's pow.cpp computes a retarget: without forming a * num,
    which near that chain's limit (2^248) does not fit in 256 bits. Exact, so the same number as
    Bitcoin's `a *= num; a /= den` wherever that is defined."""
    q, r = divmod(a, den)
    return q * num + (r * num) // den


def sha256d_work(header: bytes) -> int:
    """A header's work value where it is its hash: Bitcoin, and a regtest Qwencoin."""
    return int.from_bytes(sha256d(header), "little")


def compact_target(bits: int) -> Optional[int]:
    """The target a header's difficulty bits stand for, or None where the node (arith_uint256's
    SetCompact) calls them negative, overflowing 256 bits, or zero: no header can meet such a target."""
    exp, mant = bits >> 24, bits & 0x7FFFFF
    if mant == 0 or bits & 0x800000:
        return None
    if exp > 34 or (mant > 0xFF and exp > 33) or (mant > 0xFFFF and exp > 32):
        return None
    return (mant >> (8 * (3 - exp)) if exp <= 3 else mant << (8 * (exp - 3))) or None


@dataclass
class BtcNode:
    prev: bytes
    merkle_root: bytes
    time: int
    bits: int
    height: int
    work: int
    period_time: int = 0  # the time of the first block of this block's difficulty period


@dataclass
class BtcChain:
    """Header tree of a quote chain from the launch's anchor; best = most work, ties to the lowest
    hash. With the defaults it follows Bitcoin; QwenChain below follows Qwencoin with the same tree.

    work_value: a header's proof-of-work value as a little-endian number, or None if it cannot be
    told (then the header lacks proof of work). Unused on regtest, where the value is the hash.
    period_edges: Qwencoin's two timestamp rules at the edges of a difficulty period (not on regtest)."""
    anchor_header: bytes
    anchor_height: int
    anchor_period_time: int
    regtest: bool
    nodes: Dict[bytes, BtcNode] = field(default_factory=dict)
    children: Dict[bytes, int] = field(default_factory=dict)
    limit_bits: int = BTC_POW_LIMIT_BITS
    label: str = "btc"
    work_value: Callable[[bytes], Optional[int]] = sha256d_work
    period_edges: bool = False

    def __post_init__(self):
        h = self.anchor_header
        self.anchor = sha256d(h)
        time_ = struct.unpack("<I", h[68:72])[0]
        # An anchor that opens a difficulty period is its own period start; otherwise the first block
        # of its period is below it and the launch file supplies that block's time.
        self.nodes[self.anchor] = BtcNode(h[4:36], h[36:68], time_, struct.unpack("<I", h[72:76])[0], self.anchor_height, 0,
                                          time_ if self.anchor_height % BTC_INTERVAL == 0 else self.anchor_period_time)
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
        # prev closes its period, and every header carries the time of its period's first block
        span = min(max(prev.time - prev.period_time, BTC_TIMESPAN // 4), BTC_TIMESPAN * 4)
        target = min(muldiv(bits_to_target(prev.bits), span, BTC_TIMESPAN), bits_to_target(self.limit_bits))
        return target_to_bits(target)

    def accept(self, header: bytes, budget: Optional[List[int]] = None) -> Tuple[bool, str]:
        """Add a header. budget: [work evaluations left in this launch block] where they are limited
        (Qwencoin); a header that would need one when none is left is skipped as if it were absent."""
        L = self.label
        hash_ = sha256d(header)
        if hash_ in self.nodes:
            return False, f"{L} header already known"
        prev = self.nodes.get(header[4:36])
        if prev is None:
            return False, f"{L} header does not connect"
        time_, bits = struct.unpack("<II", header[68:76])
        if bits != self.expected_bits(prev):
            return False, f"{L} header has wrong difficulty"
        target = compact_target(bits)
        if target is None:  # bits no header can meet: refused before any work is looked at
            return False, f"{L} header lacks proof of work"
        # From here on the header costs its work check.
        if budget is not None:
            if budget[0] <= 0:
                return False, f"{L} header not looked at: this block has had its share of work checks"
            budget[0] -= 1
        if not self.regtest and self.work_value is no_qwork:
            return False, f"{L} header cannot be checked: Qwencoin's work table is not loaded"
        value = sha256d_work(header) if self.regtest else self.work_value(header)
        if value is None or value > target:
            return False, f"{L} header lacks proof of work"
        times, n = [], prev
        while n is not None and len(times) < 11:
            times.append(n.time)
            n = self.nodes.get(n.prev)
        if len(times) == 11 and time_ <= sorted(times)[5]:  # unknowable within 11 blocks of the anchor
            return False, f"{L} header time is not past the median"
        height = prev.height + 1
        if self.period_edges and not self.regtest:
            # Qwencoin's two rules at the edges of a difficulty period (Bitcoin Inquisition's consensus
            # cleanup, with BIP94's limit): the first block of a period is not stamped more than ten
            # minutes before its parent, and the last one is not stamped before the period's first.
            if height % BTC_INTERVAL == 0 and time_ < prev.time - QWEN_MAX_TIMEWARP:
                return False, f"{L} header opens a difficulty period too long before its parent's time"
            if height % BTC_INTERVAL == BTC_INTERVAL - 1 and time_ < prev.period_time:
                return False, f"{L} header closes a difficulty period before the time the period opened"
        work = prev.work + 2**256 // (target + 1)
        b = self.nodes[self.best]
        better = work > b.work or (work == b.work and self._key(hash_) < self._key(self.best))
        self.nodes[hash_] = BtcNode(header[4:36], header[36:68], time_, bits, height, work,
                                    time_ if height % BTC_INTERVAL == 0 else prev.period_time)
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


def no_qwork(_header: bytes) -> Optional[int]:
    """The work function of a model that has none: on a real Qwencoin a header's work is a pass
    through the chain's table (hashfun/qwork.py can evaluate it with numpy), and without it no
    header can be shown to have any."""
    return None


def QwenChain(anchor_header: bytes, anchor_height: int, anchor_period_time: int, regtest: bool,
              work_value: Callable[[bytes], Optional[int]] = no_qwork) -> BtcChain:
    """The Qwencoin header tree (TWIN.md section 5): the same tree with Qwencoin's limit, its exact
    retarget, its work function, and its two timestamp rules at the edges of a difficulty period. On
    regtest it is a Bitcoin regtest in everything."""
    return BtcChain(anchor_header, anchor_height, anchor_period_time, regtest, limit_bits=QWEN_POW_LIMIT_BITS,
                    label="qwen", work_value=work_value, period_edges=True)
