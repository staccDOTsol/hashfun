"""Bitcoin-format serialization: varints, scripts, transactions (segwit),
BIP143 sighash, headers, merkle trees, compact targets, bech32/base58."""
import struct
from dataclasses import dataclass, field
from typing import List, Optional

from .crypto import sha256, sha256d, hash160


# ---------------------------------------------------------------- primitives
def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def varbytes(b: bytes) -> bytes:
    return varint(len(b)) + b


class Reader:
    def __init__(self, b: bytes):
        self.b, self.i = b, 0

    def read(self, n: int) -> bytes:
        if self.i + n > len(self.b):
            raise ValueError("truncated")
        r = self.b[self.i:self.i + n]
        self.i += n
        return r

    def u8(self):
        return self.read(1)[0]

    def u32(self):
        return struct.unpack("<I", self.read(4))[0]

    def i32(self):
        return struct.unpack("<i", self.read(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.read(8))[0]

    def varint(self):
        n = self.u8()
        if n == 0xFD:
            return struct.unpack("<H", self.read(2))[0]
        if n == 0xFE:
            return self.u32()
        if n == 0xFF:
            return self.u64()
        return n

    def varbytes(self):
        return self.read(self.varint())

    def done(self):
        return self.i == len(self.b)


# ---------------------------------------------------------------- script
OP_0, OP_1, OP_RETURN, OP_DUP, OP_EQUAL, OP_EQUALVERIFY = 0x00, 0x51, 0x6A, 0x76, 0x87, 0x88
OP_HASH160, OP_CHECKSIG, OP_IF, OP_ELSE, OP_ENDIF, OP_DROP = 0xA9, 0xAC, 0x63, 0x67, 0x68, 0x75
OP_SIZE, OP_SHA256, OP_CHECKLOCKTIMEVERIFY = 0x82, 0xA8, 0xB1


def push(data: bytes) -> bytes:
    n = len(data)
    if n < 0x4C:
        return bytes([n]) + data
    if n <= 0xFF:
        return b"\x4c" + bytes([n]) + data
    if n <= 0xFFFF:
        return b"\x4d" + struct.pack("<H", n) + data
    return b"\x4e" + struct.pack("<I", n) + data


def script_num(n: int) -> bytes:
    """CScriptNum encoding (minimal, sign bit)."""
    if n == 0:
        return b""
    neg, a = n < 0, abs(n)
    out = bytearray()
    while a:
        out.append(a & 0xFF)
        a >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)


def push_int(n: int) -> bytes:
    """Minimal push of a script integer (OP_0..OP_16 or data push), as CScript() << n."""
    if n == 0:
        return bytes([OP_0])
    if n == -1 or 1 <= n <= 16:
        return bytes([0x50 + n])
    return push(script_num(n))


def parse_script(script: bytes):
    """Yield (opcode, data or None)."""
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if 1 <= op < 0x4C:
            yield op, script[i:i + op]
            i += op
        elif op == 0x4C:
            n = script[i]
            yield op, script[i + 1:i + 1 + n]
            i += 1 + n
        elif op == 0x4D:
            n = struct.unpack("<H", script[i:i + 2])[0]
            yield op, script[i + 2:i + 2 + n]
            i += 2 + n
        elif op == 0x4E:
            n = struct.unpack("<I", script[i:i + 4])[0]
            yield op, script[i + 4:i + 4 + n]
            i += 4 + n
        else:
            yield op, None


def p2wpkh_script(pubkey: bytes) -> bytes:
    return b"\x00\x14" + hash160(pubkey)


def p2wsh_script(witness_script: bytes) -> bytes:
    return b"\x00\x20" + sha256(witness_script)


def p2pkh_script(pubkey: bytes) -> bytes:
    return bytes([OP_DUP, OP_HASH160, 20]) + hash160(pubkey) + bytes([OP_EQUALVERIFY, OP_CHECKSIG])


# ---------------------------------------------------------------- transactions
@dataclass
class TxIn:
    prev_txid: bytes  # internal byte order (little-endian)
    prev_vout: int
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFF
    witness: List[bytes] = field(default_factory=list)


@dataclass
class TxOut:
    value: int
    script_pubkey: bytes


@dataclass
class Tx:
    version: int = 2
    vin: List[TxIn] = field(default_factory=list)
    vout: List[TxOut] = field(default_factory=list)
    locktime: int = 0

    def has_witness(self):
        return any(i.witness for i in self.vin)

    def serialize(self, witness=True) -> bytes:
        w = witness and self.has_witness()
        out = struct.pack("<i", self.version)
        if w:
            out += b"\x00\x01"
        out += varint(len(self.vin))
        for i in self.vin:
            out += i.prev_txid + struct.pack("<I", i.prev_vout) + varbytes(i.script_sig) + struct.pack("<I", i.sequence)
        out += varint(len(self.vout))
        for o in self.vout:
            out += struct.pack("<q", o.value) + varbytes(o.script_pubkey)
        if w:
            for i in self.vin:
                out += varint(len(i.witness)) + b"".join(varbytes(x) for x in i.witness)
        return out + struct.pack("<I", self.locktime)

    def txid(self) -> bytes:
        """Internal byte order."""
        return sha256d(self.serialize(witness=False))

    def txid_hex(self) -> str:
        return self.txid()[::-1].hex()

    def wtxid(self) -> bytes:
        return sha256d(self.serialize(witness=True))

    def vsize(self) -> int:
        base = len(self.serialize(witness=False))
        total = len(self.serialize(witness=True))
        return (base * 3 + total + 3) // 4

    @classmethod
    def parse(cls, b: bytes) -> "Tx":
        r = Reader(b)
        tx = cls._parse(r)
        if not r.done():
            raise ValueError("trailing bytes")
        return tx

    @classmethod
    def _parse(cls, r: Reader) -> "Tx":
        version = r.i32()
        nin = r.varint()
        segwit = False
        if nin == 0:
            flag = r.u8()
            if flag != 1:
                raise ValueError("bad segwit flag")
            segwit = True
            nin = r.varint()
        vin = []
        for _ in range(nin):
            txid = r.read(32)
            vout = r.u32()
            ss = r.varbytes()
            seq = r.u32()
            vin.append(TxIn(txid, vout, ss, seq))
        vout = [TxOut(struct.unpack("<q", r.read(8))[0], r.varbytes()) for _ in range(r.varint())]
        if segwit:
            for i in vin:
                i.witness = [r.varbytes() for _ in range(r.varint())]
        locktime = r.u32()
        return cls(version, vin, vout, locktime)


def bip143_sighash(tx: Tx, idx: int, script_code: bytes, amount: int, hashtype: int = 1) -> bytes:
    """BIP143 segwit v0 signature hash (SIGHASH_ALL only)."""
    assert hashtype == 1
    hp = sha256d(b"".join(i.prev_txid + struct.pack("<I", i.prev_vout) for i in tx.vin))
    hs = sha256d(b"".join(struct.pack("<I", i.sequence) for i in tx.vin))
    ho = sha256d(b"".join(struct.pack("<q", o.value) + varbytes(o.script_pubkey) for o in tx.vout))
    i = tx.vin[idx]
    pre = (struct.pack("<i", tx.version) + hp + hs + i.prev_txid + struct.pack("<I", i.prev_vout) +
           varbytes(script_code) + struct.pack("<q", amount) + struct.pack("<I", i.sequence) + ho +
           struct.pack("<I", tx.locktime) + struct.pack("<I", hashtype))
    return sha256d(pre)


def p2wpkh_script_code(pubkey: bytes) -> bytes:
    return p2pkh_script(pubkey)


# ---------------------------------------------------------------- blocks
def bits_to_target(bits: int) -> int:
    exp = bits >> 24
    mant = bits & 0x7FFFFF
    if bits & 0x800000:
        raise ValueError("negative target")
    return mant >> (8 * (3 - exp)) if exp <= 3 else mant << (8 * (exp - 3))


def target_to_bits(target: int) -> int:
    """Bitcoin's arith_uint256::GetCompact."""
    size = (target.bit_length() + 7) // 8
    if size <= 3:
        compact = target << (8 * (3 - size))
    else:
        compact = target >> (8 * (size - 3))
    if compact & 0x00800000:
        compact >>= 8
        size += 1
    return compact | (size << 24)


def work_from_bits(bits: int) -> int:
    t = bits_to_target(bits)
    if t == 0:
        return 0
    return (2**256) // (t + 1)


def header_bytes(version, prev_hash_le, merkle_le, ntime, bits, nonce) -> bytes:
    return struct.pack("<i", version) + prev_hash_le + merkle_le + struct.pack("<III", ntime, bits, nonce)


def merkle_root(hashes_le: List[bytes]) -> bytes:
    if not hashes_le:
        return b"\x00" * 32
    layer = list(hashes_le)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [sha256d(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def merkle_branch_for_first(hashes_le: List[bytes]) -> List[bytes]:
    """Branch for leaf 0 (the coinbase): stratum's merkle_branch."""
    branch = []
    layer = list(hashes_le)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        branch.append(layer[1])
        layer = [sha256d(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return branch


def merkle_branch(hashes_le: List[bytes], index: int) -> List[bytes]:
    branch = []
    layer = list(hashes_le)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        branch.append(layer[index ^ 1])
        layer = [sha256d(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
        index >>= 1
    return branch


def root_from_branch(leaf: bytes, branch: List[bytes], index: int) -> bytes:
    h = leaf
    for b in branch:
        h = sha256d(b + h) if index & 1 else sha256d(h + b)
        index >>= 1
    return h


WITNESS_MAGIC = bytes.fromhex("aa21a9ed")


def witness_commitment_script(wtxids_le: List[bytes], reserved=b"\x00" * 32) -> bytes:
    """wtxids_le must start with the coinbase placeholder (32 zero bytes)."""
    root = merkle_root(wtxids_le)
    return bytes([OP_RETURN, 0x24]) + WITNESS_MAGIC + sha256d(root + reserved)


# ---------------------------------------------------------------- bech32 / base58
_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M = 0x2BC830A3


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for v in data:
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif not pad and (bits >= frombits or ((acc << (tobits - bits)) & maxv)):
        return None
    return ret


def segwit_encode(hrp: str, witver: int, prog: bytes) -> str:
    data = [witver] + _convertbits(prog, 8, 5)
    const = 1 if witver == 0 else _BECH32M
    pm = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ const
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_B32[d] for d in data + chk)


def segwit_decode(hrp: str, addr: str):
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or addr[:pos] != hrp:
        return None
    try:
        data = [_B32.index(c) for c in addr[pos + 1:]]
    except ValueError:
        return None
    if len(data) < 7:
        return None
    pm = _polymod(_hrp_expand(hrp) + data)
    witver = data[0]
    if pm != (1 if witver == 0 else _BECH32M):
        return None
    prog = _convertbits(data[1:-6], 5, 8, False)
    if prog is None or not (2 <= len(prog) <= 40):
        return None
    return witver, bytes(prog)


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check_encode(payload: bytes) -> str:
    b = payload + sha256d(payload)[:4]
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = _B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s


def b58check_decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    b = b"\0" * (len(s) - len(s.lstrip("1"))) + b
    if sha256d(b[:-4])[:4] != b[-4:]:
        raise ValueError("bad checksum")
    return b[:-4]


def address_to_script(addr: str, hrp: str, p2pkh_prefix: Optional[int] = None, p2sh_prefix: Optional[int] = None) -> bytes:
    d = segwit_decode(hrp, addr)
    if d:
        ver, prog = d
        return bytes([0 if ver == 0 else 0x50 + ver, len(prog)]) + prog
    raw = b58check_decode(addr)
    if p2pkh_prefix is not None and raw[0] == p2pkh_prefix and len(raw) == 21:
        return bytes([OP_DUP, OP_HASH160, 20]) + raw[1:] + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
    if p2sh_prefix is not None and raw[0] == p2sh_prefix and len(raw) == 21:
        return bytes([OP_HASH160, 20]) + raw[1:] + bytes([OP_EQUAL])
    raise ValueError(f"unsupported address {addr}")


def script_to_address(script: bytes, hrp: str) -> Optional[str]:
    if len(script) in (22, 34) and script[0] == 0 and script[1] == len(script) - 2:
        return segwit_encode(hrp, 0, script[2:])
    if len(script) == 34 and script[0] == 0x51 and script[1] == 32:
        return segwit_encode(hrp, 1, script[2:])
    return None
