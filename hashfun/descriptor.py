"""Launch descriptors, genesis construction, and an independent Python model of
the consensus rules (curve, graduation, tail, LWMA). Mirrors src/kernel/launch.cpp,
src/launchcurve.cpp, src/pow.cpp and CLaunchParams byte for byte."""
import json
import re
import struct
import time
from dataclasses import dataclass, field
from typing import List, Optional

from .crypto import sha256, sha256d
from .ser import Tx, TxIn, TxOut, header_bytes, push, push_int, bits_to_target, work_from_bits, OP_RETURN

COIN = 100_000_000
MAX_MONEY = 21_000_000 * COIN
RESERVED_HRPS = {"bc", "tb", "bcrt", "ltc", "tltc", "rltc", "nc", "tn", "ncrt"}
BTC_PREFIXES = {0, 5, 111, 196}
# The descriptor format (LAUNCH_DESCRIPTOR_VERSION in src/kernel/launch.h). It is hashed into the
# launch id and names the rule set: 1 = the pre-release rules, 2 = the sats leg drawn over live coins,
# 3 = two curves: every launch is quoted in BTC and in QWEN (contrib/hashfun/TWIN.md).
VERSION = 3
# A launch that is not a test launch: MIN_FTL <= ftl < 6 * target_spacing (why: launch.h).
MIN_FTL = 10
MAX_FTL = 7200
BTC_POW_LIMIT_BITS = 0x1D00FFFF  # Bitcoin's easiest difficulty: no mainnet header is easier
QWEN_POW_LIMIT_BITS = 0x2000FFFF  # Qwencoin's: 256 expected passes through the weights per block
# The two quotes of a launch. A block mined before graduation is on exactly one curve: bit 9 of its
# header's version says which (set: the QWEN curve), and it owes that curve's asset.
QUOTES = ("btc", "qwen")
LAUNCH_VERSION_QWEN = 0x200
MAX_QWEN_CONFS = 1008             # qwen_confs: 1..1008 (a week of Qwencoin blocks); btc_confs stays 1..100
QWEN_BLOCK_REWARD = 50 * COIN     # what a Qwencoin block mints
QWEN_BLOCK_SECONDS = 600
INT_MAX = 2**31 - 1              # fields the node holds as a C++ int
# Two limits on the file itself that the node applies as well (DocumentProblem in src/kernel/launch.cpp):
# no launch file comes near either, and past them JSON readers stop agreeing with each other.
MAX_NESTING = 64                 # objects and arrays inside each other, the outer object counted
MAX_NUMBER_CHARS = 40            # characters of one number


class DescriptorError(ValueError):
    pass


def default_ftl(target_spacing: int, lwma_window: int) -> int:
    """The ftl of a launch that names none (LaunchDefaultFtl in src/kernel/launch.cpp): what LWMA
    tolerates (1/20 of its window), at least MIN_FTL, below one stall-relief step (6T) and MAX_FTL."""
    return min(max(0, 6 * target_spacing - 1), MAX_FTL, max(MIN_FTL, lwma_window * target_spacing // 20))


@dataclass
class Launch:
    name: str
    ticker: str
    genesis_time: int
    virtual_work: int
    virtual_tokens: int
    graduation_tokens: int
    version: int = VERSION
    hrp: str = ""
    pubkey_prefix: int = 40
    script_prefix: int = 100
    secret_prefix: int = 168
    genesis_nonce: int = 0
    pow_limit_bits: int = 0x1D00FFFF
    target_spacing: int = 5
    lwma_window: int = 90
    ftl: int = 22  # default_ftl(5, 90)
    tail_reward: int = 0
    tail_halving_interval: int = 0
    creator_script: bytes = b""
    creator_fee_bps: int = 0
    test: bool = False
    # Bitcoin anchor header (hashed into the id: the chain cannot predate it; also the checkpoint
    # for the in-chain BTC header relay). period_time = time of the first block of its 2016-period.
    btc_anchor_height: int = 0
    btc_anchor_header: bytes = bytes(80)
    btc_anchor_period_time: int = 0
    # Sats leg: a curve block owes (work * sats_num) >> sats_shift sats of real BTC. 0 = hash only.
    sats_num: int = 0
    sats_shift: int = 0
    sats_min_payment: int = 10_000
    settle_deadline: int = 720
    btc_confs: int = 1
    creator_btc_script: bytes = b""
    btc_regtest: bool = False  # sats leg follows regtest Bitcoin (test fleets); independent of `test`
    # The QWEN leg, field for field what the sats leg has: the Qwencoin anchor (the checkpoint of the
    # in-chain Qwencoin header relay), what a QWEN-curve block owes ((work * qwen_num) >> qwen_shift
    # base units of QWEN), the smallest payment, the confirmations a payment needs on the Qwencoin
    # relay, where the creator's share is paid on Qwencoin, and whether the leg follows a regtest
    # Qwencoin. Both curves have the shape virtual_work / virtual_tokens / graduation_tokens describe.
    qwen_anchor_height: int = 0
    qwen_anchor_header: bytes = bytes(80)
    qwen_anchor_period_time: int = 0
    qwen_num: int = 0
    qwen_shift: int = 0
    qwen_min_payment: int = 10_000
    qwen_confs: int = 6
    creator_qwen_script: bytes = b""
    qwen_regtest: bool = False
    # SHA256 of the launch's metadata (picture, blurb, links: see meta.py). Hashed into the id only
    # when set, so a launch without metadata keeps the id it always had. The bytes ride in the
    # launch file as `metadata`; they are not consensus data and the node never reads them.
    meta: bytes = bytes(32)
    p2p_port: int = 0
    rpc_port: int = 0
    seeds: List[str] = field(default_factory=list)
    metadata: Optional[dict] = None  # not part of the id; verified against `meta` by meta.check()

    # ------------------------------------------------------------ identity
    def canonical_bytes(self) -> bytes:
        def u32(x):
            return struct.pack("<I", x)

        def vs(b: bytes):
            from .ser import varint
            return varint(len(b)) + b
        return (b"hashfun-launch" + u32(self.version) + vs(self.name.encode()) + vs(self.ticker.encode()) +
                vs(self.hrp.encode()) + bytes([self.pubkey_prefix, self.script_prefix, self.secret_prefix]) +
                u32(self.genesis_time) + u32(self.pow_limit_bits) + u32(self.target_spacing) + u32(self.lwma_window) +
                u32(self.ftl) + self.virtual_work.to_bytes(32, "big") + struct.pack("<q", self.virtual_tokens) +
                struct.pack("<q", self.graduation_tokens) + struct.pack("<q", self.tail_reward) +
                u32(self.tail_halving_interval) + vs(self.creator_script) + struct.pack("<H", self.creator_fee_bps) +
                bytes([1 if self.test else 0]) + u32(self.btc_anchor_height) + self.btc_anchor_header +
                u32(self.btc_anchor_period_time) + struct.pack("<q", self.sats_num) + u32(self.sats_shift) +
                struct.pack("<q", self.sats_min_payment) + u32(self.settle_deadline) + u32(self.btc_confs) +
                vs(self.creator_btc_script) + bytes([1 if self.btc_regtest else 0]) +
                u32(self.qwen_anchor_height) + self.qwen_anchor_header + u32(self.qwen_anchor_period_time) +
                struct.pack("<q", self.qwen_num) + u32(self.qwen_shift) + struct.pack("<q", self.qwen_min_payment) +
                u32(self.qwen_confs) + vs(self.creator_qwen_script) + bytes([1 if self.qwen_regtest else 0]) +
                (self.meta if any(self.meta) else b""))

    @property
    def id(self) -> bytes:
        return sha256d(self.canonical_bytes())

    @property
    def id_hex(self) -> str:
        return self.id.hex()

    def _derive(self, tag: bytes) -> bytes:
        return sha256(tag + self.id)

    @property
    def magic(self) -> bytes:
        h = self._derive(b"hashfun-magic")
        return bytes(x | 0x80 for x in h[:4])

    @property
    def chain_id(self) -> int:
        h = self._derive(b"hashfun-chainid")
        cid = (h[0] | (h[1] << 8)) % 0x1FFE + 1
        if cid in (1, 98, 4096):
            cid += 1
        return cid

    @property
    def p2p(self) -> int:
        if self.p2p_port:
            return self.p2p_port
        # Three ports in a row per launch, as Bitcoin has them (8332, 8333, 8334): RPC, P2P, and
        # the one above P2P, where the node itself listens for incoming Tor connections. All under
        # the range systems hand out to outgoing connections (Linux from 32768, macOS from 49152):
        # a port in that range can be held by a connection made a moment ago, and a node cannot
        # listen on it then. 20002..31998 in steps of 4.
        h = self._derive(b"hashfun-port")
        return 20002 + ((h[0] | (h[1] << 8)) % 3000) * 4

    @property
    def rpc(self) -> int:
        # one under the P2P port; one above is the node's own Tor listener, and a node told to
        # serve RPC there cannot start
        return self.rpc_port or self.p2p - 1

    @property
    def datadir_name(self) -> str:
        return f"launch_{self.ticker.lower()}_{self.id_hex[:8]}"

    # ------------------------------------------------------------ genesis
    def coinbase_prefix(self, height: int) -> bytes:
        """What the scriptSig of the coinbase at `height` must start with (consensus, bad-cb-launch-id):
        the height, then the first 16 bytes of the launch id. A coinbase names its launch, so no
        transaction can exist on two launches and nothing spent on one can be replayed on another."""
        return push_int(height) + push(self.id[:16])

    def genesis_coinbase(self) -> Tx:
        return Tx(version=1, vin=[TxIn(b"\0" * 32, 0xFFFFFFFF, push(self.id), 0xFFFFFFFF)],
                  vout=[TxOut(0, bytes([OP_RETURN]))], locktime=0)

    def genesis_header(self, nonce: Optional[int] = None) -> bytes:
        cb = self.genesis_coinbase()
        return header_bytes(1, b"\0" * 32, cb.txid(), self.genesis_time, self.pow_limit_bits,
                            self.genesis_nonce if nonce is None else nonce)

    @property
    def genesis_hash(self) -> str:
        return sha256d(self.genesis_header())[::-1].hex()

    def genesis_valid(self) -> bool:
        return int.from_bytes(sha256d(self.genesis_header()), "little") <= bits_to_target(self.pow_limit_bits)

    def grind_genesis(self, progress=None) -> int:
        target = bits_to_target(self.pow_limit_bits)
        base = self.genesis_header(0)[:76]
        import hashlib
        prefix = hashlib.sha256(base[:64])
        for nonce in range(2**32):
            h = prefix.copy()
            h.update(base[64:] + struct.pack("<I", nonce))
            d = hashlib.sha256(h.digest()).digest()
            if int.from_bytes(d, "little") <= target:
                self.genesis_nonce = nonce
                return nonce
            if progress and nonce % 1_000_000 == 0:
                progress(nonce)
        raise RuntimeError("nonce space exhausted; change genesis_time")

    # ------------------------------------------------------------ curve model
    # Two curves of one shape (contrib/hashfun/TWIN.md section 3). Wb and Wq are the work mined on the
    # BTC and on the QWEN curve: of the blocks above genesis, those without and those with bit 9 of the
    # version. The first curve to sell out graduates the launch; what the other has not sold is never minted.
    @property
    def graduation_work(self) -> int:
        num = self.graduation_tokens * self.virtual_work
        den = self.virtual_tokens - self.graduation_tokens
        return -(-num // den)

    @property
    def genesis_work(self) -> int:
        return work_from_bits(self.pow_limit_bits)

    def curve_supply(self, w: int) -> int:
        """What one curve has minted at work w on it."""
        if w >= self.graduation_work:
            return self.graduation_tokens
        return min(self.virtual_tokens * w // (self.virtual_work + w), self.graduation_tokens)

    def graduated(self, wb: int, wq: int = 0) -> bool:
        return wb >= self.graduation_work or wq >= self.graduation_work

    def curve_minted(self, wb: int, wq: int) -> int:
        """Both curves' mints together, for works taken at or before the graduation block (after it the
        BTC side's work keeps growing with the tail and means nothing)."""
        return self.curve_supply(wb) + self.curve_supply(wq)

    def tail_reward_at(self, height: int) -> int:
        if self.tail_reward <= 0 or self.tail_halving_interval <= 0:
            return 0
        h = height // self.tail_halving_interval
        return 0 if h >= 63 else self.tail_reward >> h

    def subsidy(self, wb: int, wq: int, quote: str, bits: int, height: int) -> int:
        """What the block at `height` with difficulty `bits` mints on a parent whose curves stand at wb
        and wq. quote: the curve the block is on ("btc" or "qwen"); once the parent has graduated the
        block is on neither and gets the tail reward."""
        if self.graduated(wb, wq):
            return self.tail_reward_at(height)
        w = wq if quote == "qwen" else wb
        return self.curve_supply(w + work_from_bits(bits)) - self.curve_supply(w)

    def creator_fee(self, subsidy: int) -> int:
        if self.creator_fee_bps <= 0 or subsidy <= 0:
            return 0
        return subsidy * self.creator_fee_bps // 10000

    def hashes_per_coin(self, w: int) -> float:
        """Hashes per whole coin at the margin of a curve that stands at work w."""
        w = min(w, self.graduation_work)
        v0 = float(self.virtual_work)
        return (v0 + w) ** 2 / (self.virtual_tokens * v0) * COIN

    # ------------------------------------------------------------ the two quotes
    def owed_rate(self, quote: str) -> tuple:
        """(num, shift): a block on that curve owes (work * num) >> shift base units of its asset."""
        return (self.qwen_num, self.qwen_shift) if quote == "qwen" else (self.sats_num, self.sats_shift)

    def owed(self, work: int, quote: str = "btc") -> int:
        from .yieldmodel import owed
        return owed(work, *self.owed_rate(quote))

    def min_payment(self, quote: str) -> int:
        return self.qwen_min_payment if quote == "qwen" else self.sats_min_payment

    def confs(self, quote: str) -> int:
        return self.qwen_confs if quote == "qwen" else self.btc_confs

    def creator_quote_script(self, quote: str) -> bytes:
        return self.creator_qwen_script if quote == "qwen" else self.creator_btc_script

    def quote_regtest(self, quote: str) -> bool:
        return self.qwen_regtest if quote == "qwen" else self.btc_regtest

    def anchor(self, quote: str) -> tuple:
        """(height, header, period start time) of the Bitcoin or the Qwencoin anchor."""
        if quote == "qwen":
            return self.qwen_anchor_height, self.qwen_anchor_header, self.qwen_anchor_period_time
        return self.btc_anchor_height, self.btc_anchor_header, self.btc_anchor_period_time

    def leg_total(self, quote: str) -> int:
        """What the whole curve of that quote owes if it sells out: graduation work times its rate."""
        num, shift = self.owed_rate(quote)
        return self.graduation_work * num >> shift

    def price_per_coin(self, w: int, quote: str = "btc") -> float:
        """Base units of the quote owed per whole coin at the margin of its curve, standing at work w.
        The price point of that curve. The hash itself is not in it."""
        num, shift = self.owed_rate(quote)
        return self.hashes_per_coin(w) * num / 2 ** shift

    def implied_qwen_sats(self, wb: int, wq: int) -> Optional[float]:
        """Sats per whole QWEN that this coin's two price points imply: price_btc / price_qwen * 1e8."""
        pq = self.price_per_coin(wq, "qwen")
        return self.price_per_coin(wb, "btc") / pq * COIN if pq > 0 else None

    def lwma_next_bits(self, timestamps: List[int], bits: List[int]) -> int:
        """timestamps/bits for heights 0..tip (genesis first). Mirrors LwmaNextWorkRequired."""
        from .ser import target_to_bits
        pow_limit = bits_to_target(self.pow_limit_bits)
        T = self.target_spacing
        height = len(timestamps) - 1
        n = min(self.lwma_window, height)
        if n < 1:
            return target_to_bits(pow_limit)
        k = n * (n + 1) * T // 2
        avg = 0
        sw = 0
        prev_ts = timestamps[height - n]
        j = 0
        for i in range(height - n + 1, height + 1):
            ts = timestamps[i] if timestamps[i] > prev_ts else prev_ts + 1
            st = min(6 * T, ts - prev_ts)
            prev_ts = ts
            j += 1
            sw += st * j
            avg += bits_to_target(bits[i]) // n // k
        sw = max(sw, 1)
        if avg > pow_limit // sw:
            return target_to_bits(pow_limit)
        nxt = min(avg * sw, pow_limit) or 1
        return target_to_bits(nxt)

    def next_bits(self, timestamps: List[int], bits: List[int], block_time: Optional[int] = None) -> int:
        """Consensus nBits for a block stamped block_time on top of the given chain: the LWMA
        base, doubled in target for every full 6T since the parent (stall relief, mirrors
        LaunchStallRelief). block_time=None gives the base."""
        from .ser import target_to_bits
        base = self.lwma_next_bits(timestamps, bits)
        if block_time is None:
            return base
        n = (block_time - timestamps[-1]) // (6 * self.target_spacing)
        if n <= 0:
            return base
        pow_limit = bits_to_target(self.pow_limit_bits)
        target = bits_to_target(base)
        for _ in range(n):
            if target > pow_limit >> 1:
                return target_to_bits(pow_limit)
            target <<= 1
        return target_to_bits(target)

    # ------------------------------------------------------------ json
    def to_json(self) -> dict:
        return {
            "version": self.version, "name": self.name, "ticker": self.ticker, "hrp": self.hrp,
            "pubkey_prefix": self.pubkey_prefix, "script_prefix": self.script_prefix, "secret_prefix": self.secret_prefix,
            "genesis_time": self.genesis_time, "genesis_nonce": self.genesis_nonce,
            "pow_limit_bits": f"0x{self.pow_limit_bits:08x}", "target_spacing": self.target_spacing,
            "lwma_window": self.lwma_window, "ftl": self.ftl, "virtual_work": str(self.virtual_work),
            "virtual_tokens": self.virtual_tokens, "graduation_tokens": self.graduation_tokens,
            "tail_reward": self.tail_reward, "tail_halving_interval": self.tail_halving_interval,
            "creator_script": self.creator_script.hex(), "creator_fee_bps": self.creator_fee_bps,
            "test": self.test, "btc_anchor_height": self.btc_anchor_height,
            "btc_anchor_header": self.btc_anchor_header.hex(), "btc_anchor_period_time": self.btc_anchor_period_time,
            "sats_num": self.sats_num, "sats_shift": self.sats_shift, "sats_min_payment": self.sats_min_payment,
            "settle_deadline": self.settle_deadline, "btc_confs": self.btc_confs,
            **({"creator_btc_script": self.creator_btc_script.hex()} if self.creator_btc_script else {}),
            "btc_regtest": self.btc_regtest,
            "qwen_anchor_height": self.qwen_anchor_height, "qwen_anchor_header": self.qwen_anchor_header.hex(),
            "qwen_anchor_period_time": self.qwen_anchor_period_time, "qwen_num": self.qwen_num,
            "qwen_shift": self.qwen_shift, "qwen_min_payment": self.qwen_min_payment, "qwen_confs": self.qwen_confs,
            **({"creator_qwen_script": self.creator_qwen_script.hex()} if self.creator_qwen_script else {}),
            "qwen_regtest": self.qwen_regtest,
            **({"meta": self.meta.hex()} if any(self.meta) else {}),
            **({"p2p_port": self.p2p_port} if self.p2p_port else {}),
            **({"rpc_port": self.rpc_port} if self.rpc_port else {}), "seeds": self.seeds,
            **({"metadata": self.metadata} if self.metadata else {}),
        }

    def dumps(self) -> str:
        return json.dumps(self.to_json(), indent=2) + "\n"


_DEC = re.compile(r"-?[0-9]+")
_HEX = re.compile(r"0x[0-9a-fA-F]+")
_V0 = re.compile(r"0[xX][0-9a-fA-F]{1,64}|[0-9]+")


def _decimal(s: str) -> int:
    """int(s) for a string of decimal digits of any length, with an optional '-'. int() itself gives up
    past 4300 digits, zeros in front included, while the node reads such a string digit by digit:
    zeros in front mean nothing there, and a value this long is out of every field's range."""
    neg, digits = s.startswith("-"), s.lstrip("-").lstrip("0")
    if len(digits) > 100:
        return -(10**100) if neg else 10**100  # the caller refuses it as out of range
    return -int(digits or "0") if neg else int(digits or "0")


INT64_MIN, INT64_MAX = -2**63, 2**63 - 1


def _int(o: dict, key: str, maxv: int, default: int = 0, required: bool = False) -> int:
    """launch.cpp GetUInt, with its words: a JSON integer, or a string of decimal digits
    (std::from_chars, so an optional '-' and nothing else) or lowercase-0x hex. null/missing keeps the
    default. The node holds what it reads in 64 bits before it looks at the field's own range, and
    says which of the two a value fell out of: so does this."""
    v = o.get(key)
    if v is None:
        if required:
            raise DescriptorError(f"{key}: required")
        return default
    if isinstance(v, str):
        if v.startswith("0x"):
            digits = v[2:]
            # no digits, something that is not one, or more than 64 bits of them
            if not re.fullmatch(r"[0-9a-fA-F]+", digits) or len(digits.lstrip("0")) > 16:
                raise DescriptorError(f"{key}: invalid hex")
            v = int(digits, 16)
            if v > INT64_MAX:
                raise DescriptorError(f"{key}: out of range")
        elif _DEC.fullmatch(v):
            v = _decimal(v)
            if not INT64_MIN <= v <= INT64_MAX:  # from_chars gives up on it
                raise DescriptorError(f"{key}: not an integer")
        else:
            raise DescriptorError(f"{key}: not an integer")
    elif isinstance(v, bool) or not isinstance(v, int) or not INT64_MIN <= v <= INT64_MAX:
        # a fraction, an exponent, a number past 64 bits, or not a number at all
        raise DescriptorError(f"{key}: expected integer")
    if v < 0 or v > maxv:
        raise DescriptorError(f"{key}: out of range")
    return v


def _bool(o: dict, key: str) -> bool:
    """launch.cpp GetBool: true or false; null/missing is false."""
    v = o.get(key)
    if v is not None and not isinstance(v, bool):
        raise DescriptorError(f"{key}: expected bool")
    return bool(v)


def _hexbytes(o: dict, key: str, min_len: int, max_len: int, default: bytes) -> bytes:
    """launch.cpp GetHexBytes: strict hex, min_len..max_len bytes; null/missing keeps the default."""
    v = o.get(key)
    if v is None:
        return default
    if not isinstance(v, str) or len(v) % 2 or not (2 * min_len <= len(v) <= 2 * max_len) or \
            not re.fullmatch(r"[0-9a-fA-F]*", v):
        raise DescriptorError(f"{key}: expected {min_len}..{max_len} bytes of hex")
    return bytes.fromhex(v)


def _str(o: dict, key: str, default: Optional[str] = None) -> str:
    """launch.cpp GetStr: null/missing is an error unless there is a default."""
    v = o.get(key)
    if v is None:
        if default is None:
            raise DescriptorError(f"{key}: required")
        return default
    if not isinstance(v, str):
        raise DescriptorError(f"{key}: expected string")
    return v


class _Object(dict):
    """A JSON object as it was written: the dict (the first of two equal keys kept, as the node's
    reader keeps it), the first key that came a second time, and every value, kept or not."""
    twice: Optional[str] = None
    written: list = []


def _pairs(pairs):
    out = _Object()
    out.written = [v for _, v in pairs]
    for k, v in pairs:
        if k not in out:
            out[k] = v
        elif out.twice is None:
            out.twice = k
    return out


class _LongNumber:
    """A number of more than MAX_NUMBER_CHARS characters: kept as a mark until the document is looked
    over in the node's order."""


def _constant(token):
    # NaN, Infinity, -Infinity: Python's json reads them, JSON has no such thing and the node refuses them
    raise DescriptorError(f"descriptor is not a JSON object: {token} is not a JSON value")


def _number(convert):
    def read(literal: str):
        return _LongNumber() if len(literal) > MAX_NUMBER_CHARS else convert(literal)
    return read


MAX_READ_NESTING = 512  # what the node's JSON reader reads at all: deeper is not JSON to it


def _loads(text):
    """JSON as the node reads it (ParseLaunchDescriptor: strict UTF-8, UniValue, DocumentProblem), and
    refused in the node's order with the node's words, so that a file with several things wrong is
    told about the same one by both. Python's json is more forgiving than the node's reader in ways
    that would let one file mean two things, or be a launch here and garbage there: duplicate keys,
    NaN and Infinity, unpaired surrogates in strings, numbers and nesting of any size. `text` is a
    str, or the bytes of a file. Returns the object."""
    if isinstance(text, (bytes, bytearray)):
        try:
            text = bytes(text).decode("utf-8")  # strict: shortest forms, no surrogates, nothing past U+10FFFF
        except UnicodeDecodeError:
            raise DescriptorError("descriptor is not valid UTF-8")
    try:
        o = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant,
                       parse_int=_number(int), parse_float=_number(float))
    except DescriptorError:
        raise
    except RecursionError:
        raise DescriptorError("descriptor is not a JSON object: nested too deep to read")
    except ValueError as e:
        raise DescriptorError(f"descriptor is not a JSON object: {e}")
    # 1. What the node's reader does not read at all, wherever it is in the text: half a surrogate
    #    pair written as a \u escape, and more than 512 levels.
    todo = [(o, 1)]
    while todo:  # no recursion here: how deep to go is the file's choice
        v, depth = todo.pop()
        if isinstance(v, str):
            try:
                v.encode("utf-8")
            except UnicodeEncodeError:
                raise DescriptorError("descriptor is not a JSON object: a string is not valid UTF-8")
        elif isinstance(v, (dict, list)):
            if depth > MAX_READ_NESTING:
                raise DescriptorError("descriptor is not a JSON object: nested too deep to read")
            if isinstance(v, dict):
                todo.extend((k, depth + 1) for k in v)
                todo.extend((x, depth + 1) for x in v.written)
            else:
                todo.extend((x, depth + 1) for x in v)
    if not isinstance(o, dict):
        raise DescriptorError("descriptor is not a JSON object")
    # 2. DocumentProblem, as launch.cpp walks it: a value before what is inside it, and of an object or
    #    array first its depth, then (an object) its keys, then its members in the order written.
    todo = [(o, 1)]
    while todo:
        v, depth = todo.pop()
        if isinstance(v, _LongNumber):
            raise DescriptorError(f"descriptor: a number of more than {MAX_NUMBER_CHARS} characters")
        if not isinstance(v, (dict, list)):
            continue
        if depth > MAX_NESTING:
            raise DescriptorError(f"descriptor: nested more than {MAX_NESTING} levels")
        if isinstance(v, dict) and v.twice is not None:
            # Python keeps the last of two equal keys, the node's reader the first: one file, two launches
            raise DescriptorError(f"{v.twice}: the key appears twice in one object")
        todo.extend((x, depth + 1) for x in reversed(v.written if isinstance(v, dict) else v))
    return o


def _earns_yield(script: bytes) -> bool:
    """P2PKH, P2SH or a witness program. The same rule as launchyield::EarnsYield (src/launchyield.cpp),
    EarningScript in src/kernel/launch.cpp and yieldmodel.earns_yield; kept here too so that reading a
    launch file depends on nothing else (the tests hold the four together)."""
    n = len(script)
    if n == 25 and script[:3] == b"\x76\xa9\x14" and script[23:] == b"\x88\xac":
        return True
    if n == 23 and script[:2] == b"\xa9\x14" and script[22] == 0x87:
        return True
    return 4 <= n <= 42 and (script[0] == 0 or 0x51 <= script[0] <= 0x60) and script[1] == n - 2


def _check_version(version: int):
    if version == 1:
        raise DescriptorError("version: 1 is the earlier, pre-release rule set. This launch file must be created "
                              "again (hashfun launch new)")
    if version == 2:
        raise DescriptorError("version: 2 is the earlier rule set with one curve, quoted in BTC only. This launch file "
                              "must be created again (hashfun launch new)")
    if version != VERSION:
        raise DescriptorError("unsupported descriptor version")


def _compact_target(bits: int) -> Optional[int]:
    """The target a header's bits stand for, or None where Bitcoin's own decoding calls them invalid
    (negative, overflowing, zero)."""
    mant, exp = bits & 0x7FFFFF, bits >> 24
    target = mant >> (8 * (3 - exp)) if exp <= 3 else mant << (8 * (exp - 3))
    if (mant and bits & 0x800000) or target >= 2**256 or target == 0:
        return None
    return target


def _check_btc_anchor(d: "Launch"):
    """CheckBtcAnchor in launch.cpp: what can be said about a Bitcoin anchor without a Bitcoin chain to
    look at. check_anchor() below asks a Bitcoin node for the rest."""
    h = d.btc_anchor_header
    time_, bits = struct.unpack("<II", h[68:76])
    target = _compact_target(bits)
    if target is None:
        raise DescriptorError("btc_anchor_header: its difficulty bits are not a valid target")
    if target > bits_to_target(BTC_POW_LIMIT_BITS):
        raise DescriptorError("btc_anchor_header: easier than Bitcoin's minimum difficulty (not a Bitcoin mainnet "
                              "header; a regtest anchor needs btc_regtest)")
    if int.from_bytes(sha256d(h), "little") > target:
        raise DescriptorError("btc_anchor_header: its hash does not meet its own difficulty (not a Bitcoin block header)")
    if d.btc_anchor_period_time == 0:
        raise DescriptorError("btc_anchor_period_time: required (the time of the first block of the anchor's "
                              "2016-block difficulty period)")
    if d.btc_anchor_height % 2016 == 0:
        if d.btc_anchor_period_time != time_:
            raise DescriptorError("btc_anchor_period_time: the anchor opens a difficulty period (height is a multiple "
                                  "of 2016), so it must be the anchor header's own time")
    elif d.btc_anchor_period_time > time_ + 7200:
        raise DescriptorError("btc_anchor_period_time: later than the anchor block itself")


def _check_qwen_anchor(d: "Launch"):
    """CheckQwenAnchor in launch.cpp: the same for the Qwencoin anchor, except its work. A Qwencoin
    header's proof of work is not its hash but a pass through the chain's work table (528 MB), which
    no parser carries: the node checks the anchor's work when it starts, and check_anchor() asks a
    Qwencoin node whether the header is the block at that height."""
    h = d.qwen_anchor_header
    time_, bits = struct.unpack("<II", h[68:76])
    target = _compact_target(bits)
    if target is None:
        raise DescriptorError("qwen_anchor_header: its difficulty bits are not a valid target")
    if target > bits_to_target(QWEN_POW_LIMIT_BITS):
        raise DescriptorError("qwen_anchor_header: easier than Qwencoin's minimum difficulty (not a Qwencoin mainnet "
                              "header; a regtest anchor needs qwen_regtest)")
    if d.qwen_anchor_period_time == 0:
        raise DescriptorError("qwen_anchor_period_time: required (the time of the first block of the anchor's "
                              "2016-block difficulty period)")
    if d.qwen_anchor_height % 2016 == 0:
        if d.qwen_anchor_period_time != time_:
            raise DescriptorError("qwen_anchor_period_time: the anchor opens a difficulty period (height is a multiple "
                                  "of 2016), so it must be the anchor header's own time")
    elif d.qwen_anchor_period_time > time_ + 7200:
        raise DescriptorError("qwen_anchor_period_time: later than the anchor block itself")


def parse(text_or_obj) -> Launch:
    """Accepts exactly what ParseLaunchDescriptor accepts, and refuses what it refuses for the same
    reason in the same words: the keys are read in the node's order and the checks run in the node's
    order, so a file with several things wrong is told about the same one here and there
    (test_diff_cpp holds the two together). Takes the text of a launch file as a str, or the bytes of
    one. A dict that was already read from JSON is taken as it is (what the rules about the text
    guard against cannot be seen in it any more)."""
    if isinstance(text_or_obj, (str, bytes, bytearray)):
        o = _loads(text_or_obj)
    else:
        o = dict(text_or_obj) if isinstance(text_or_obj, dict) else None
        if o is None:
            raise DescriptorError("descriptor is not a JSON object")
    # ---- reading: one key after another, as src/kernel/launch.cpp reads them
    version = _int(o, "version", 2**32 - 1, default=VERSION)
    _check_version(version)
    name, ticker = _str(o, "name"), _str(o, "ticker")
    hrp = _str(o, "hrp", default=ticker.lower())
    pubkey_prefix = _int(o, "pubkey_prefix", 255, 40)
    script_prefix = _int(o, "script_prefix", 255, 100)
    secret_prefix = _int(o, "secret_prefix", 255, 168)
    genesis_time = _int(o, "genesis_time", 2**32 - 1, required=True)
    genesis_nonce = _int(o, "genesis_nonce", 2**32 - 1)
    pow_limit_bits = _int(o, "pow_limit_bits", 2**32 - 1, 0x1D00FFFF)
    target_spacing = _int(o, "target_spacing", 3600, 5)
    lwma_window = _int(o, "lwma_window", 1000, 90)
    ftl = _int(o, "ftl", MAX_FTL, -1)  # -1: not named; a function of the two above
    if ftl < 0:
        ftl = default_ftl(target_spacing, lwma_window)
    vw = _str(o, "virtual_work")
    virtual_work = None
    if _V0.fullmatch(vw):
        virtual_work = int(vw, 16) if vw[:2] in ("0x", "0X") else _decimal(vw)
    if virtual_work is None or virtual_work >= 2**256:  # (the node reads it into 256 bits)
        raise DescriptorError("virtual_work: expected decimal or 0x-hex integer string")
    virtual_tokens = _int(o, "virtual_tokens", MAX_MONEY)
    graduation_tokens = _int(o, "graduation_tokens", MAX_MONEY)
    tail_reward = _int(o, "tail_reward", MAX_MONEY)
    tail_halving_interval = _int(o, "tail_halving_interval", INT_MAX)
    creator_script_hex = _str(o, "creator_script", default="")
    try:
        creator_script = bytes.fromhex(creator_script_hex)
    except ValueError:
        raise DescriptorError("creator_script: invalid hex")
    creator_fee_bps = _int(o, "creator_fee_bps", 1000)
    test = _bool(o, "test")
    p2p_port, rpc_port = _int(o, "p2p_port", 65535), _int(o, "rpc_port", 65535)
    btc_anchor_height = _int(o, "btc_anchor_height", INT_MAX)
    btc_anchor_header = _hexbytes(o, "btc_anchor_header", 80, 80, bytes(80))
    btc_anchor_period_time = _int(o, "btc_anchor_period_time", 2**32 - 1)
    sats_num, sats_shift = _int(o, "sats_num", 2**62), _int(o, "sats_shift", 128)
    sats_min_payment = _int(o, "sats_min_payment", MAX_MONEY, 10_000)
    settle_deadline = _int(o, "settle_deadline", 1_000_000, 720)
    btc_confs = _int(o, "btc_confs", 100, 1)
    creator_btc_script = _hexbytes(o, "creator_btc_script", 1, 80, b"")
    btc_regtest = _bool(o, "btc_regtest")
    qwen_anchor_height = _int(o, "qwen_anchor_height", INT_MAX)
    qwen_anchor_header = _hexbytes(o, "qwen_anchor_header", 80, 80, bytes(80))
    qwen_anchor_period_time = _int(o, "qwen_anchor_period_time", 2**32 - 1)
    qwen_num, qwen_shift = _int(o, "qwen_num", 2**62), _int(o, "qwen_shift", 128)
    qwen_min_payment = _int(o, "qwen_min_payment", MAX_MONEY, 10_000)
    qwen_confs = _int(o, "qwen_confs", MAX_QWEN_CONFS, 6)
    creator_qwen_script = _hexbytes(o, "creator_qwen_script", 1, 80, b"")
    qwen_regtest = _bool(o, "qwen_regtest")
    meta = _hexbytes(o, "meta", 32, 32, bytes(32))
    metadata = o.get("metadata")  # carried, never judged here: the node ignores it too
    d = Launch(
        name=name, ticker=ticker, hrp=hrp, version=version, genesis_time=genesis_time, virtual_work=virtual_work,
        virtual_tokens=virtual_tokens, graduation_tokens=graduation_tokens, pubkey_prefix=pubkey_prefix,
        script_prefix=script_prefix, secret_prefix=secret_prefix, genesis_nonce=genesis_nonce,
        pow_limit_bits=pow_limit_bits, target_spacing=target_spacing, lwma_window=lwma_window, ftl=ftl,
        tail_reward=tail_reward, tail_halving_interval=tail_halving_interval, creator_script=creator_script,
        creator_fee_bps=creator_fee_bps, test=test, btc_anchor_height=btc_anchor_height,
        btc_anchor_header=btc_anchor_header, btc_anchor_period_time=btc_anchor_period_time, sats_num=sats_num,
        sats_shift=sats_shift, sats_min_payment=sats_min_payment, settle_deadline=settle_deadline, btc_confs=btc_confs,
        creator_btc_script=creator_btc_script, btc_regtest=btc_regtest, qwen_anchor_height=qwen_anchor_height,
        qwen_anchor_header=qwen_anchor_header, qwen_anchor_period_time=qwen_anchor_period_time, qwen_num=qwen_num,
        qwen_shift=qwen_shift, qwen_min_payment=qwen_min_payment, qwen_confs=qwen_confs,
        creator_qwen_script=creator_qwen_script, qwen_regtest=qwen_regtest, meta=meta, p2p_port=p2p_port,
        rpc_port=rpc_port, metadata=metadata if isinstance(metadata, dict) else None,
    )
    # ---- checking, in the node's order: the two legs, then the seeds, then everything else
    _validate_legs(d)
    seeds = o.get("seeds")
    if seeds is not None and (not isinstance(seeds, list) or not all(isinstance(x, str) for x in seeds)):
        raise DescriptorError("seeds: expected array of strings")
    d.seeds = list(seeds or [])
    _validate_rest(d)
    return d


def validate(d: Launch):
    """Everything the node's parser checks once a launch file is read, in its order. Raises
    DescriptorError with the node's words."""
    _validate_legs(d)
    _validate_rest(d)


def _validate_legs(d: Launch):
    has_anchor = any(d.btc_anchor_header)
    if (d.btc_anchor_height or d.btc_anchor_period_time) and not has_anchor:
        raise DescriptorError("btc_anchor_header: required with btc_anchor_height / btc_anchor_period_time")
    # Every launch has a sats leg: one kind of coin.
    if not d.sats_num:
        raise DescriptorError("sats_num: required (every launch has a sats leg)")
    if not has_anchor:
        raise DescriptorError("btc_anchor_header: required")
    if len(d.btc_anchor_header) != 80:
        raise DescriptorError("btc_anchor_header: expected 80..80 bytes of hex")
    if not 0 <= d.btc_anchor_height <= INT_MAX:
        raise DescriptorError("btc_anchor_height: out of range")
    if not 0 <= d.btc_anchor_period_time < 2**32:
        raise DescriptorError("btc_anchor_period_time: out of range")
    if not d.btc_regtest:
        _check_btc_anchor(d)
    if not d.creator_btc_script:
        raise DescriptorError("creator_btc_script: required")
    if not _earns_yield(d.creator_btc_script):
        raise DescriptorError("creator_btc_script: must be a P2PKH, P2SH or witness-program script (one a Bitcoin "
                              "node relays a payment to)")
    if d.sats_min_payment < 546:
        raise DescriptorError("sats_min_payment: at least 546")
    if d.settle_deadline < 110:
        raise DescriptorError("settle_deadline: at least 110 blocks")
    if d.btc_confs < 1:
        raise DescriptorError("btc_confs: at least 1")
    # Every launch has a QWEN leg as well: two curves, one kind of coin. The same checks, key for key.
    has_qanchor = any(d.qwen_anchor_header)
    if (d.qwen_anchor_height or d.qwen_anchor_period_time) and not has_qanchor:
        raise DescriptorError("qwen_anchor_header: required with qwen_anchor_height / qwen_anchor_period_time")
    if not d.qwen_num:
        raise DescriptorError("qwen_num: required (every launch has a QWEN leg)")
    if not has_qanchor:
        raise DescriptorError("qwen_anchor_header: required")
    if len(d.qwen_anchor_header) != 80:
        raise DescriptorError("qwen_anchor_header: expected 80..80 bytes of hex")
    if not 0 <= d.qwen_anchor_height <= INT_MAX:
        raise DescriptorError("qwen_anchor_height: out of range")
    if not 0 <= d.qwen_anchor_period_time < 2**32:
        raise DescriptorError("qwen_anchor_period_time: out of range")
    if not d.qwen_regtest:
        _check_qwen_anchor(d)
    if not d.creator_qwen_script:
        raise DescriptorError("creator_qwen_script: required")
    if not _earns_yield(d.creator_qwen_script):
        raise DescriptorError("creator_qwen_script: must be a P2PKH, P2SH or witness-program script (one a Qwencoin "
                              "node relays a payment to)")
    if d.qwen_min_payment < 546:
        raise DescriptorError("qwen_min_payment: at least 546")
    if d.qwen_confs < 1:
        raise DescriptorError("qwen_confs: at least 1")
    if d.qwen_confs > MAX_QWEN_CONFS:  # (a file is refused for this where the key is read; a launch built here, here)
        raise DescriptorError("qwen_confs: out of range")
    # A payment has to reach its confirmations before the deadline, or every block that owes one loses
    # its coins whatever its miner does. A confirmation is ten minutes on either chain and the deadline
    # is counted in this launch's own blocks, so the deadline must last, at the target spacing, at
    # least twice as long as the confirmations take. A leg on regtest is not held to it: its blocks
    # come when a test makes them.
    deadline_seconds = d.settle_deadline * d.target_spacing
    for real, key, confs in ((not d.btc_regtest, "btc_confs", d.btc_confs), (not d.qwen_regtest, "qwen_confs", d.qwen_confs)):
        if real and deadline_seconds < 1200 * confs:
            raise DescriptorError(f"settle_deadline: too short for {key}: the deadline must last at least twice as long "
                                  "as the confirmations take (ten minutes each)")


def _validate_rest(d: Launch):
    _check_version(d.version)
    try:
        name_bytes = len(d.name.encode("utf-8"))
    except UnicodeEncodeError:
        raise DescriptorError("name: invalid UTF-8")
    if not (1 <= name_bytes <= 64):  # (the node's word for what it counts: the bytes of the name in UTF-8)
        raise DescriptorError("name: 1..64 chars")
    if not re.fullmatch(r"[A-Z0-9]{2,10}", d.ticker):
        raise DescriptorError("ticker: 2..10 chars [A-Z0-9]")
    if not re.fullmatch(r"[a-z0-9]{1,20}", d.hrp) or d.hrp in RESERVED_HRPS:
        raise DescriptorError("hrp: 1..20 chars [a-z0-9], not a Bitcoin/Litecoin/Namecoin hrp")
    if d.pubkey_prefix == d.script_prefix or d.pubkey_prefix in BTC_PREFIXES or d.script_prefix in BTC_PREFIXES:
        raise DescriptorError("pubkey_prefix/script_prefix: must differ from each other and from Bitcoin's")
    if d.pow_limit_bits & 0x00800000 or bits_to_target(d.pow_limit_bits) == 0 or bits_to_target(d.pow_limit_bits) >= 2**256:
        raise DescriptorError("pow_limit_bits: invalid compact target")
    # Block times are whole seconds and LWMA counts every solvetime as at least 1 s, so with
    # T = 1 no window can ever look faster than the target and difficulty could never rise.
    if d.target_spacing < 2:
        raise DescriptorError("target_spacing: 2..3600")
    if d.lwma_window < 3:
        raise DescriptorError("lwma_window: 3..1000")
    if not 1 <= d.ftl <= MAX_FTL:
        raise DescriptorError("ftl: 1..7200")
    # See LAUNCH_MIN_FTL in src/kernel/launch.h. A test launch keeps the whole range: its tests stamp
    # blocks far from the clock on purpose.
    if not d.test and not MIN_FTL <= d.ftl < 6 * d.target_spacing:
        raise DescriptorError("ftl: at least 10 and less than 6 * target_spacing (only a test launch may be outside that)")
    if not (0 < d.virtual_work <= 2**160):
        raise DescriptorError("virtual_work: must be in (0, 2^160]")
    if not (0 < d.graduation_tokens < d.virtual_tokens):
        raise DescriptorError("need 0 < graduation_tokens < virtual_tokens")
    if d.virtual_tokens - d.graduation_tokens < d.virtual_tokens // 1000:
        raise DescriptorError("graduation_tokens may be at most 99.9% of virtual_tokens")
    if not 0 <= d.tail_halving_interval <= INT_MAX:
        raise DescriptorError("tail_halving_interval: out of range")
    if d.tail_reward > 0 and d.tail_halving_interval == 0:
        raise DescriptorError("tail_halving_interval: required when tail_reward > 0")
    if 2 * d.graduation_tokens + d.tail_reward * d.tail_halving_interval * 2 > MAX_MONEY:
        raise DescriptorError("2 * graduation_tokens + total tail emission exceeds MAX_MONEY (each of the two curves "
                              "can mint graduation_tokens)")
    if len(d.meta) != 32:
        raise DescriptorError("meta: expected 32..32 bytes of hex")
    if len(d.creator_script) > 100:
        raise DescriptorError("creator_script: at most 100 bytes")
    if d.creator_fee_bps > 0 and not d.creator_script:
        raise DescriptorError("creator_script: required when creator_fee_bps > 0")


def load(path: str) -> Launch:
    with open(path, "rb") as f:  # bytes, as the node reads it: UTF-8 whatever the locale says
        return parse(f.read())


# pump.fun's shape: 1.073B virtual tokens, 793.1M sold at graduation (73.91%),
# 30 virtual SOL -> 85 SOL raised. Here the "SOL" side is hash.
PUMP_RATIO_G = 7931
PUMP_RATIO_T = 10730


# Bitcoin regtest genesis header: the anchor of test launches.
REGTEST_GENESIS_HEADER = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f"
    "617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000")
# Bitcoin's own genesis header: the one mainnet anchor everybody can check by eye (height 0, and
# since it opens a difficulty period its period start is its own time). For tests and examples;
# a real launch anchors a few blocks below the tip (btc_anchor_from_rpc).
MAINNET_GENESIS_HEADER = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f"
    "617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c")
TEST_BTC_SCRIPT = bytes.fromhex("0014" + "c1" * 20)  # creator payout of test launches (nobody's key)


TEST_QWEN_SCRIPT = bytes.fromhex("0014" + "c2" * 20)  # the same on the QWEN leg
# What a test launch owes per hash when nothing else is said: 10,000 sats and 14,000 qwen per 2-hash
# block at the regtest floor. Different on purpose: a test that mixes the two quotes up sees it.
TEST_SATS_RATE = (5000, 0)
TEST_QWEN_RATE = (7000, 0)


def _leg_rate(d: Launch, total: int) -> tuple:
    """(num, shift) so that a whole curve owes ~total base units (the sum over its blocks of
    (work * num) >> shift, with total work W_g). The largest shift that keeps num precise."""
    wg = d.graduation_work
    for shift in range(128, -1, -1):
        num = (total << shift) // wg
        if 2**40 <= num <= 2**62 or (shift == 0 and 1 <= num <= 2**62):
            return num, shift
    raise DescriptorError("the leg's total is out of range for this curve")


def set_sats_total(d: Launch, total_sats: int):
    """Size the sats leg so the whole BTC curve owes ~total_sats of BTC."""
    try:
        d.sats_num, d.sats_shift = _leg_rate(d, total_sats)
    except DescriptorError:
        raise DescriptorError("sats total is out of range for this curve")


def set_qwen_total(d: Launch, total_qwen: int):
    """Size the QWEN leg so the whole QWEN curve owes ~total_qwen base units of QWEN (1 QWEN = 1e8)."""
    try:
        d.qwen_num, d.qwen_shift = _leg_rate(d, total_qwen)
    except DescriptorError:
        raise DescriptorError("qwen total is out of range for this curve")


def qwen_confs_needed(total_qwen: int) -> int:
    """ceil(1.25 * (total_qwen in coins) / 50): the Qwencoin confirmations at which faking a QWEN leg
    that owes total_qwen base units in all stops paying. See qwen_confs_for."""
    return -(-5 * total_qwen // (4 * QWEN_BLOCK_REWARD))


def qwen_confs_for(total_qwen: int) -> int:
    """The qwen_confs of a launch whose QWEN curve owes total_qwen base units in all, when nobody
    names one: clamp(ceil(1.25 * coins / 50), 6, 1008).

    Why. A payment on Qwencoin is proven to the launch by headers, and such a proof is only as hard
    to fake as qwen_confs Qwencoin blocks are to mine. That chain's work is small: whoever can mine a
    private fork of qwen_confs blocks can put payments into it that never happened. One such fork can
    carry the payments of every block still inside its settlement window, so in the worst case it
    fakes the whole leg. The blocks of that fork cost what mining qwen_confs real blocks costs, and
    real blocks pay 50 qwen each: so the fork must be longer than the leg is worth in block rewards,
    with a quarter on top. Then paying honestly is the cheaper way, whatever QWEN is worth.

    A total that 1008 confirmations (a week) do not cover is refused here; a launch that wants it
    anyway names its own qwen_confs."""
    need = qwen_confs_needed(total_qwen)
    if need > MAX_QWEN_CONFS:
        raise DescriptorError(
            f"qwen total: a QWEN leg of {total_qwen / COIN:,.0f} qwen would need {need} Qwencoin confirmations to be "
            f"dearer to fake than to pay, and qwen_confs goes up to {MAX_QWEN_CONFS} (covering "
            f"{MAX_QWEN_CONFS * 4 * QWEN_BLOCK_REWARD // (5 * COIN):,} qwen): make the leg smaller, or name qwen_confs yourself")
    return max(6, need)


def settle_deadline_for(d: "Launch") -> int:
    """The settlement deadline (in launch blocks) the tools give a launch when nobody names one: the
    larger of what the file has, a day of blocks when either leg follows a real chain (one block of
    that chain can take an hour and a low fee longer), and three times what a real leg's
    confirmations take at ten minutes each. The parsers refuse a deadline shorter than twice that
    (settle_deadline: too short for ...), so what comes out of here always passes; it is within the
    parsers' upper bound for every block time a launch may have."""
    need = d.settle_deadline
    if not d.btc_regtest or not d.qwen_regtest:
        need = max(need, 86400 // d.target_spacing)
    for real, confs in ((not d.btc_regtest, d.btc_confs), (not d.qwen_regtest, d.qwen_confs)):
        if real:
            need = max(need, -(-3 * confs * QWEN_BLOCK_SECONDS // d.target_spacing))
    return min(need, 1_000_000)


def btc_anchor_from_rpc(rpc, depth: int = 6):
    """(height, header hex, period start time) of the Bitcoin block `depth` below the tip."""
    height = max(0, rpc.getblockcount() - depth)
    header = rpc.getblockheader(rpc.getblockhash(height), False)
    period = rpc.getblockheader(rpc.getblockhash(height - height % 2016))["time"]
    return height, header, period


def qwen_anchor_from_rpc(rpc, depth: int = 6):
    """The same triple from a Qwencoin node (its RPC is bitcoin-cli's). Six blocks deep is an hour of
    Qwencoin: enough that the anchor stays on the chain, on a network this small."""
    return btc_anchor_from_rpc(rpc, depth)


_CHAIN_NAMES = {"btc": "Bitcoin", "qwen": "Qwencoin"}


def _check_anchor(d: Launch, rpc, quote: str) -> None:
    key, chain = quote, _CHAIN_NAMES[quote]
    height, header, period_time = d.anchor(quote)
    ours = sha256d(header)[::-1].hex()
    try:
        tip = rpc.getblockcount()
        if height > tip:
            raise DescriptorError(f"{key} anchor: the launch names {chain} block {height}, and this {chain} node is only at "
                                  f"{tip} (still syncing, or another network)")
        theirs = rpc.getblockhash(height)
        if theirs != ours:
            raise DescriptorError(f"{key} anchor: the launch's anchor header is block {ours}, but block {height} on this "
                                  f"{chain} node's chain is {theirs} (wrong height, another network, or a made-up header)")
        if bytes.fromhex(rpc.getblockheader(theirs, False)) != header:
            raise DescriptorError(f"{key} anchor: the header in the launch is not the header of {chain} block {height}")
        if not d.quote_regtest(quote):
            first = height - height % 2016
            start = rpc.getblockheader(rpc.getblockhash(first))["time"]
            if period_time != start:
                raise DescriptorError(f"{key} anchor: {key}_anchor_period_time is {period_time}, but the difficulty "
                                      f"period of block {height} starts at block {first}, whose time is {start}. With the "
                                      f"wrong start this launch would refuse real {chain} headers at the next retarget "
                                      "and nothing on it could settle after that")
    except DescriptorError:
        raise
    except Exception as e:  # RPCError, OSError, a malformed answer: the question was not answered
        raise DescriptorError(f"{key} anchor: could not ask the {chain} node: {e}")


def check_anchor(d: Launch, btc_rpc) -> None:
    """Ask a Bitcoin node whether the launch's anchor is what the launch file says it is: the header
    of the block at btc_anchor_height on the node's best chain, and (unless btc_regtest, where
    difficulty never retargets) btc_anchor_period_time the time of the first block of that block's
    2016-block difficulty period.

    The parser can only tell that the header is a Bitcoin header at all; it has no chain to look at.
    A real header at a wrong height, or a wrong period start, passes it, and such a launch refuses
    real Bitcoin headers at the first retarget after the anchor (two weeks at most): from then on no
    payment can be proven and every curve coinbase that owes sats is lost. So check before mining a
    launch, before joining one, and before taking a launch file from someone else.

    btc_rpc: a hashfun.rpc.RPC (or anything with getblockcount / getblockhash / getblockheader) for
    the Bitcoin network the launch follows. Raises DescriptorError with what is wrong."""
    _check_anchor(d, btc_rpc, "btc")


def check_qwen_anchor(d: Launch, qwen_rpc) -> None:
    """The same question about the Qwencoin anchor, put to a Qwencoin node (qwencoind's RPC is
    bitcoin-cli's). It matters more here: the parser cannot even tell that the header is a Qwencoin
    header (its work is a pass through the chain's weights, not its hash), so until a Qwencoin node or
    this launch's own node has looked, the anchor is only a claim. A wrong one leaves every QWEN-curve
    coinbase that owes qwen unspendable for good. Raises DescriptorError with what is wrong."""
    _check_anchor(d, qwen_rpc, "qwen")


def _take_anchor(anchor, regtest: bool, name: str, cli: str):
    """(height, header, period start) from what a caller gave: a height, the 80-byte header in hex, and
    the period start (which may be left out only where it is the anchor's own time, or on regtest)."""
    try:
        if not 2 <= len(anchor) <= 3:
            raise ValueError
        height, header = int(anchor[0]), bytes.fromhex(anchor[1])
        period = int(anchor[2]) if len(anchor) == 3 else None
    except (ValueError, TypeError):
        raise DescriptorError(f"{name} anchor: expected a height, the block's 80-byte header in hex, and the start time "
                              "of its difficulty period")
    if len(header) != 80:
        raise DescriptorError(f"{name} anchor: the header is 80 bytes (160 hex digits)")
    if period is None:
        if height % 2016 == 0:  # the anchor opens its difficulty period: the start is its own time
            period = struct.unpack("<I", header[68:72])[0]
        elif not regtest:
            first = height - height % 2016
            raise DescriptorError(
                f"{name} anchor: the start time of the difficulty period is missing. It may be left out only when the "
                f"height is a multiple of 2016; block {height} is inside a period, which starts at block "
                f"{first}: give that block's time ({cli} getblockheader $({cli} getblockhash {first}) shows "
                f"it), or take the whole anchor from a {_CHAIN_NAMES[name]} node (--{name}-rpc, {name}_anchor_from_rpc). "
                f"Without it the launch would stop accepting {_CHAIN_NAMES[name]} headers at the next retarget")
        else:
            period = 0
    return height, header, period


DEFAULT_SUPPLY_COINS = 12_000_000  # of each curve's virtual tokens: see make()
TEST_QWEN_CONFS = 2                # of a regtest QWEN leg: not btc_confs' 1, so a test that mixes them up sees it


def make(name: str, ticker: str, creator_script: bytes, graduation_hashes: int, *, supply_coins=DEFAULT_SUPPLY_COINS,
         creator_fee_bps=100, target_spacing=5, lwma_window=90, ftl=None, test=False, tail_years=8,
         pow_limit_bits=0x1E0FFFFF, genesis_time=None, hrp=None, btc_anchor=None, sats_total=None,
         creator_btc_script=None, btc_regtest=None, qwen_anchor=None, qwen_total=None, creator_qwen_script=None,
         qwen_regtest=None, qwen_confs=None, metadata=None, _validate=True) -> Launch:
    """Build a descriptor with pump.fun-proportioned curves and a tail that emits
    the rest of the supply over `tail_years` with 4 halvings-ish.

    supply_coins is each curve's virtual supply T0. Each of the two curves can mint G = 73.91% of it
    and the tail the other 26.09%, so at most 1.7391 * T0 coins ever exist: 12,000,000 is the largest
    round T0 that stays within 21 million.

    The two legs are given the same way: an anchor (height, 80-byte header in hex, period start time:
    what btc_anchor_from_rpc / qwen_anchor_from_rpc return), what the whole curve owes (sats_total in
    sats, qwen_total in base units of QWEN) and the creator's script on that chain. A leg on regtest
    (btc_regtest follows `test`, qwen_regtest follows btc_regtest unless said) is filled with test
    values where nothing is given. qwen_confs, when not named: qwen_confs_for(qwen_total) on a real
    Qwencoin (it refuses a total it cannot cover), 2 on regtest."""
    t0 = supply_coins * COIN
    g = t0 * PUMP_RATIO_G // PUMP_RATIO_T
    # V0 so that W_g == graduation_hashes (approximately; W_g = ceil(G*V0/(T0-G))).
    v0 = max(1, graduation_hashes * (t0 - g) // g)
    blocks_per_year = 365 * 24 * 3600 // target_spacing
    interval = max(1, blocks_per_year * tail_years // 4)
    tail = (t0 - g) // (2 * interval)
    btc_regtest = test if btc_regtest is None else btc_regtest
    d = Launch(name=name, ticker=ticker, hrp=hrp or ticker.lower(), genesis_time=genesis_time or int(time.time()),
               virtual_work=v0, virtual_tokens=t0, graduation_tokens=g, pow_limit_bits=pow_limit_bits,
               target_spacing=target_spacing, lwma_window=lwma_window,
               ftl=ftl or default_ftl(target_spacing, lwma_window), tail_reward=tail,
               tail_halving_interval=interval, creator_script=creator_script, creator_fee_bps=creator_fee_bps,
               test=test, btc_regtest=btc_regtest, qwen_regtest=btc_regtest if qwen_regtest is None else qwen_regtest)
    if metadata is not None:  # a meta.Meta: commit to it before the id is used for anything
        from .meta import attach
        attach(d, metadata)
    if btc_anchor:
        d.btc_anchor_height, d.btc_anchor_header, d.btc_anchor_period_time = \
            _take_anchor(btc_anchor, d.btc_regtest, "btc", "bitcoin-cli")
    elif d.btc_regtest:  # anchor at the regtest genesis
        d.btc_anchor_header = REGTEST_GENESIS_HEADER
    if qwen_anchor:
        d.qwen_anchor_height, d.qwen_anchor_header, d.qwen_anchor_period_time = \
            _take_anchor(qwen_anchor, d.qwen_regtest, "qwen", "qwencoin-cli")
    elif d.qwen_regtest:  # a regtest Qwencoin is an unchanged Bitcoin regtest: the same genesis
        d.qwen_anchor_header = REGTEST_GENESIS_HEADER
    d.creator_btc_script = creator_btc_script or (TEST_BTC_SCRIPT if d.btc_regtest else b"")
    d.creator_qwen_script = creator_qwen_script or (TEST_QWEN_SCRIPT if d.qwen_regtest else b"")
    if sats_total is not None:
        set_sats_total(d, sats_total)
    elif d.btc_regtest:
        d.sats_num, d.sats_shift = TEST_SATS_RATE
    if qwen_total is not None:
        set_qwen_total(d, qwen_total)
    elif d.qwen_regtest:
        d.qwen_num, d.qwen_shift = TEST_QWEN_RATE
    if qwen_confs is not None:
        d.qwen_confs = qwen_confs
    elif d.qwen_regtest:
        d.qwen_confs = TEST_QWEN_CONFS
    elif qwen_total is not None:
        d.qwen_confs = qwen_confs_for(qwen_total)
    # A payment needs confirmations on its own chain before its proof counts, and the proof has to be
    # in a launch block before the deadline: an hour of launch blocks (the parser default) is too
    # tight for a real chain.
    d.settle_deadline = settle_deadline_for(d)
    if _validate:
        validate(d)
    return d


# ---------------------------------------------------------------- reading a node's two curves
def curve_of_version(version: int) -> str:
    """The curve a block's header puts it on. (After graduation the bit is always clear, and the
    block is on neither.)"""
    return "qwen" if version & LAUNCH_VERSION_QWEN else "btc"


RECENT_BLOCKS = 100  # a curve counts as "being mined" while its last block is within this many of the tip


def quote_summary(info: dict, recent: int = RECENT_BLOCKS) -> dict:
    """The two price points of a coin from a node's `getlaunchinfo`, and what they imply for QWEN.

    {"price": {"btc": sats per coin, "qwen": qwen base units per coin},   marginal, hash not included
     "implied_qwen_sats": sats per whole QWEN (price_btc / price_qwen * 1e8), or None,
     "mined": the curves that had a block in the last `recent` blocks,
     "bound": "two-sided" | "floor" | "ceiling" | None}

    Nothing ties the curves together in consensus: whoever mints picks the cheaper one. So the implied
    price is a price only while both curves are being mined ("two-sided"). With the BTC curve alone
    being mined it is a floor (were QWEN worth less, the QWEN curve would be the cheaper way in), with
    the QWEN curve alone a ceiling, and with neither (or after graduation) it is history."""
    curves = info.get("curves") or {}
    price = {q: float((curves.get(q) or {}).get("owed_per_coin") or 0.0) for q in QUOTES}
    implied = price["btc"] / price["qwen"] * COIN if price["btc"] > 0 and price["qwen"] > 0 else None
    tip = info.get("height", 0)
    mined = [] if info.get("graduated") else [
        q for q in QUOTES if (curves.get(q) or {}).get("last_height", 0) > 0
        and tip - curves[q]["last_height"] < recent]
    bound = {("btc", "qwen"): "two-sided", ("btc",): "floor", ("qwen",): "ceiling"}.get(tuple(mined))
    return {"price": price, "implied_qwen_sats": implied, "mined": mined, "bound": bound if implied else None}
