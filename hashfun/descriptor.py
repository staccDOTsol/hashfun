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
from .ser import Tx, TxIn, TxOut, header_bytes, push, bits_to_target, work_from_bits, OP_RETURN

COIN = 100_000_000
MAX_MONEY = 21_000_000 * COIN
RESERVED_HRPS = {"bc", "tb", "bcrt", "ltc", "tltc", "rltc", "nc", "tn", "ncrt"}
BTC_PREFIXES = {0, 5, 111, 196}


class DescriptorError(ValueError):
    pass


@dataclass
class Launch:
    name: str
    ticker: str
    genesis_time: int
    virtual_work: int
    virtual_tokens: int
    graduation_tokens: int
    version: int = 1
    hrp: str = ""
    pubkey_prefix: int = 40
    script_prefix: int = 100
    secret_prefix: int = 168
    genesis_nonce: int = 0
    pow_limit_bits: int = 0x1D00FFFF
    target_spacing: int = 5
    lwma_window: int = 90
    ftl: int = 60
    tail_reward: int = 0
    tail_halving_interval: int = 0
    creator_script: bytes = b""
    creator_fee_bps: int = 0
    test: bool = False
    btc_anchor_height: int = 0
    btc_anchor_hash: str = "00" * 32  # as displayed; hashed into the id, so the chain cannot predate it
    p2p_port: int = 0
    rpc_port: int = 0
    seeds: List[str] = field(default_factory=list)

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
                bytes([1 if self.test else 0]) + u32(self.btc_anchor_height) + bytes.fromhex(self.btc_anchor_hash))

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
        h = self._derive(b"hashfun-port")
        return 20000 + ((h[0] | (h[1] << 8)) % 10000) * 2

    @property
    def rpc(self) -> int:
        return self.rpc_port or self.p2p + 1

    @property
    def datadir_name(self) -> str:
        return f"launch_{self.ticker.lower()}_{self.id_hex[:8]}"

    # ------------------------------------------------------------ genesis
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
    @property
    def graduation_work(self) -> int:
        num = self.graduation_tokens * self.virtual_work
        den = self.virtual_tokens - self.graduation_tokens
        return -(-num // den)

    @property
    def genesis_work(self) -> int:
        return work_from_bits(self.pow_limit_bits)

    def curve_supply(self, w: int) -> int:
        if w >= self.graduation_work:
            return self.graduation_tokens
        return min(self.virtual_tokens * w // (self.virtual_work + w), self.graduation_tokens)

    def tail_reward_at(self, height: int) -> int:
        if self.tail_reward <= 0 or self.tail_halving_interval <= 0:
            return 0
        h = height // self.tail_halving_interval
        return 0 if h >= 63 else self.tail_reward >> h

    def subsidy(self, w_prev: int, bits: int, height: int) -> int:
        if w_prev >= self.graduation_work:
            return self.tail_reward_at(height)
        return self.curve_supply(w_prev + work_from_bits(bits)) - self.curve_supply(w_prev)

    def creator_fee(self, subsidy: int) -> int:
        if self.creator_fee_bps <= 0 or subsidy <= 0:
            return 0
        return subsidy * self.creator_fee_bps // 10000

    def hashes_per_coin(self, w: int) -> float:
        w = min(w, self.graduation_work)
        v0 = float(self.virtual_work)
        return (v0 + w) ** 2 / (self.virtual_tokens * v0) * COIN

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
            "test": self.test, "btc_anchor_height": self.btc_anchor_height, "btc_anchor_hash": self.btc_anchor_hash,
            **({"p2p_port": self.p2p_port} if self.p2p_port else {}),
            **({"rpc_port": self.rpc_port} if self.rpc_port else {}), "seeds": self.seeds,
        }

    def dumps(self) -> str:
        return json.dumps(self.to_json(), indent=2) + "\n"


_DEC = re.compile(r"-?[0-9]+")
_HEX = re.compile(r"0x[0-9a-fA-F]+")
_V0 = re.compile(r"0[xX][0-9a-fA-F]{1,64}|[0-9]+")


def _int(o: dict, key: str, maxv: int, default: int = 0, required: bool = False) -> int:
    """launch.cpp GetUInt: a JSON integer, or a string of decimal digits (std::from_chars,
    so an optional '-' and nothing else) or lowercase-0x hex. null/missing keeps the default."""
    v = o.get(key)
    if v is None:
        if required:
            raise DescriptorError(f"{key}: required")
        return default
    if isinstance(v, str):
        if _HEX.fullmatch(v):
            v = int(v, 16)
        elif _DEC.fullmatch(v):
            v = int(v)
        else:
            raise DescriptorError(f"{key}: not an integer")
    if isinstance(v, bool) or not isinstance(v, int):
        raise DescriptorError(f"{key}: expected integer")
    if v < 0 or v > maxv:
        raise DescriptorError(f"{key}: out of range")
    return v


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


def parse(text_or_obj) -> Launch:
    """Accepts exactly what ParseLaunchDescriptor accepts (test_diff_cpp checks this)."""
    try:
        o = json.loads(text_or_obj) if isinstance(text_or_obj, str) else dict(text_or_obj)
    except ValueError as e:
        raise DescriptorError(f"descriptor is not a JSON object: {e}")
    if not isinstance(o, dict):
        raise DescriptorError("descriptor is not a JSON object")
    version = _int(o, "version", 2**32 - 1, default=1)
    if version != 1:
        raise DescriptorError("unsupported descriptor version")
    name, ticker = _str(o, "name"), _str(o, "ticker")
    hrp = _str(o, "hrp", default=ticker.lower())
    vw = _str(o, "virtual_work")
    if not _V0.fullmatch(vw):
        raise DescriptorError("virtual_work: expected decimal or 0x-hex integer string")
    try:
        creator_script = bytes.fromhex(_str(o, "creator_script", default=""))
    except ValueError:
        raise DescriptorError("creator_script: invalid hex")
    test = o.get("test")
    if test is not None and not isinstance(test, bool):
        raise DescriptorError("test: expected bool")
    anchor = o.get("btc_anchor_hash")
    if anchor is None:
        anchor = "00" * 32
    elif not isinstance(anchor, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", anchor):
        raise DescriptorError("btc_anchor_hash: expected 64 hex characters")
    seeds = o.get("seeds")
    if seeds is not None and (not isinstance(seeds, list) or not all(isinstance(x, str) for x in seeds)):
        raise DescriptorError("seeds: expected array of strings")
    d = Launch(
        name=name, ticker=ticker, hrp=hrp, version=version,
        genesis_time=_int(o, "genesis_time", 2**32 - 1, required=True),
        virtual_work=int(vw, 16) if vw[:2] in ("0x", "0X") else int(vw),
        virtual_tokens=_int(o, "virtual_tokens", MAX_MONEY),
        graduation_tokens=_int(o, "graduation_tokens", MAX_MONEY),
        pubkey_prefix=_int(o, "pubkey_prefix", 255, 40),
        script_prefix=_int(o, "script_prefix", 255, 100),
        secret_prefix=_int(o, "secret_prefix", 255, 168),
        genesis_nonce=_int(o, "genesis_nonce", 2**32 - 1),
        pow_limit_bits=_int(o, "pow_limit_bits", 2**32 - 1, 0x1D00FFFF),
        target_spacing=_int(o, "target_spacing", 3600, 60),
        lwma_window=_int(o, "lwma_window", 1000, 45),
        ftl=_int(o, "ftl", 7200, 300),
        tail_reward=_int(o, "tail_reward", MAX_MONEY),
        tail_halving_interval=_int(o, "tail_halving_interval", 2**32 - 1),
        creator_script=creator_script,
        creator_fee_bps=_int(o, "creator_fee_bps", 1000),
        test=bool(test), btc_anchor_height=_int(o, "btc_anchor_height", 2**32 - 1), btc_anchor_hash=anchor.lower(),
        p2p_port=_int(o, "p2p_port", 65535), rpc_port=_int(o, "rpc_port", 65535),
        seeds=list(seeds or []),
    )
    validate(d)
    return d


def validate(d: Launch):
    if d.btc_anchor_height and not int(d.btc_anchor_hash, 16):
        raise DescriptorError("btc_anchor_hash: required with btc_anchor_height")
    if d.version != 1:
        raise DescriptorError("unsupported descriptor version")
    try:
        name_bytes = len(d.name.encode("utf-8"))
    except UnicodeEncodeError:
        raise DescriptorError("name: invalid UTF-8")
    if not (1 <= name_bytes <= 64):
        raise DescriptorError("name: 1..64 bytes")
    if not re.fullmatch(r"[A-Z0-9]{2,10}", d.ticker):
        raise DescriptorError("ticker: 2..10 chars [A-Z0-9]")
    if not re.fullmatch(r"[a-z0-9]{1,20}", d.hrp) or d.hrp in RESERVED_HRPS:
        raise DescriptorError("hrp: 1..20 chars [a-z0-9], not a Bitcoin/Litecoin/Namecoin hrp")
    if d.pubkey_prefix == d.script_prefix or d.pubkey_prefix in BTC_PREFIXES or d.script_prefix in BTC_PREFIXES:
        raise DescriptorError("pubkey_prefix/script_prefix: must differ from each other and from Bitcoin's")
    if d.pow_limit_bits & 0x00800000 or bits_to_target(d.pow_limit_bits) == 0 or bits_to_target(d.pow_limit_bits) >= 2**256:
        raise DescriptorError("pow_limit_bits: invalid compact target")
    if d.target_spacing < 1:
        raise DescriptorError("target_spacing: 1..3600")
    if d.lwma_window < 3:
        raise DescriptorError("lwma_window: 3..1000")
    if d.ftl < 1:
        raise DescriptorError("ftl: 1..7200")
    if not (0 < d.virtual_work <= 2**160):
        raise DescriptorError("virtual_work: must be in (0, 2^160]")
    if not (0 < d.graduation_tokens < d.virtual_tokens):
        raise DescriptorError("need 0 < graduation_tokens < virtual_tokens")
    if d.virtual_tokens - d.graduation_tokens < d.virtual_tokens // 1000:
        raise DescriptorError("graduation_tokens may be at most 99.9% of virtual_tokens")
    if d.tail_reward > 0 and d.tail_halving_interval == 0:
        raise DescriptorError("tail_halving_interval: required when tail_reward > 0")
    if d.graduation_tokens + d.tail_reward * d.tail_halving_interval * 2 > MAX_MONEY:
        raise DescriptorError("graduation_tokens + total tail emission exceeds MAX_MONEY")
    if len(d.creator_script) > 100:
        raise DescriptorError("creator_script: at most 100 bytes")
    if d.creator_fee_bps > 0 and not d.creator_script:
        raise DescriptorError("creator_script: required when creator_fee_bps > 0")


def load(path: str) -> Launch:
    with open(path) as f:
        return parse(f.read())


# pump.fun's shape: 1.073B virtual tokens, 793.1M sold at graduation (73.91%),
# 30 virtual SOL -> 85 SOL raised. Here the "SOL" side is hash.
PUMP_RATIO_G = 7931
PUMP_RATIO_T = 10730


def make(name: str, ticker: str, creator_script: bytes, graduation_hashes: int, *, supply_coins=15_000_000,
         creator_fee_bps=100, target_spacing=5, lwma_window=90, ftl=None, test=False, tail_years=8,
         pow_limit_bits=0x1E0FFFFF, genesis_time=None, hrp=None, btc_anchor=None) -> Launch:
    """Build a descriptor with pump.fun-proportioned curve and a tail that emits
    the rest of the supply over `tail_years` with 4 halvings-ish."""
    t0 = supply_coins * COIN
    g = t0 * PUMP_RATIO_G // PUMP_RATIO_T
    # V0 so that W_g == graduation_hashes (approximately; W_g = ceil(G*V0/(T0-G))).
    v0 = max(1, graduation_hashes * (t0 - g) // g)
    blocks_per_year = 365 * 24 * 3600 // target_spacing
    interval = max(1, blocks_per_year * tail_years // 4)
    tail = (t0 - g) // (2 * interval)
    d = Launch(name=name, ticker=ticker, hrp=hrp or ticker.lower(), genesis_time=genesis_time or int(time.time()),
               virtual_work=v0, virtual_tokens=t0, graduation_tokens=g, pow_limit_bits=pow_limit_bits,
               target_spacing=target_spacing, lwma_window=lwma_window,
               ftl=ftl or max(15, lwma_window * target_spacing // 20), tail_reward=tail,
               tail_halving_interval=interval, creator_script=creator_script, creator_fee_bps=creator_fee_bps,
               test=test)
    if btc_anchor:
        d.btc_anchor_height, d.btc_anchor_hash = int(btc_anchor[0]), btc_anchor[1].lower()
    validate(d)
    return d
