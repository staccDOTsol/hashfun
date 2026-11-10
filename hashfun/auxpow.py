"""Merged mining (AuxPoW): aux chain merkle tree, parent coinbase commitment,
auxpow serialization for submitauxblock, and a Python port of CAuxPow::check
(src/auxpow.cpp) used by the tests and by the coordinator as a pre-submit check."""
import os
import struct
from typing import Dict, List, Tuple

from .crypto import sha256d
from .ser import Tx, varint, root_from_branch, merkle_branch, Reader, push

MM_MAGIC = bytes([0xFA, 0xBE, ord("m"), ord("m")])


def expected_index(nonce: int, chain_id: int, h: int) -> int:
    """CAuxPow::getExpectedIndex, including Namecoin's intermediate modulo."""
    mod = 1 << h
    r = nonce
    r = (r * 1103515245 + 12345) & 0xFFFFFFFFFFFFFFFF
    r %= mod
    r += chain_id
    r = (r * 1103515245 + 12345) & 0xFFFFFFFFFFFFFFFF
    r %= mod
    return r


class AuxTree:
    """Slots for a set of aux chains. leaves: chain_id -> aux block hash (internal byte order)."""

    def __init__(self, leaves: Dict[int, bytes], nonce: int = None, max_height: int = 10):
        if not leaves:
            raise ValueError("no aux chains")
        ids = list(leaves)
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate chain ids")
        for h in range(0, max_height + 1):
            if (1 << h) < len(ids):
                continue
            for n in ([nonce] if nonce is not None else range(0, 4096)):
                slots = {cid: expected_index(n, cid, h) for cid in ids}
                if len(set(slots.values())) == len(ids):
                    self.height, self.nonce, self.slots = h, n, slots
                    break
            else:
                continue
            break
        else:
            raise ValueError("could not place aux chains without slot collisions")
        size = 1 << self.height
        filler = sha256d(b"hashfun-aux-filler")
        self.layer0 = [filler] * size
        for cid, hsh in leaves.items():
            self.layer0[self.slots[cid]] = hsh
        self.leaves = dict(leaves)

    @property
    def size(self) -> int:
        return 1 << self.height

    def root(self) -> bytes:
        layer = list(self.layer0)
        while len(layer) > 1:
            layer = [sha256d(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
        return layer[0]

    def branch(self, chain_id: int) -> Tuple[List[bytes], int]:
        idx = self.slots[chain_id]
        if self.height == 0:
            return [], 0
        return merkle_branch(self.layer0, idx), idx

    def commitment(self) -> bytes:
        """Bytes to embed in the parent coinbase scriptSig."""
        return MM_MAGIC + self.root()[::-1] + struct.pack("<II", self.size, self.nonce)

    def commitment_push(self) -> bytes:
        return push(self.commitment())


def serialize_auxpow(parent_coinbase: Tx, coinbase_branch: List[bytes], chain_branch: List[bytes], chain_index: int,
                     parent_header: bytes) -> bytes:
    assert len(parent_header) == 80
    out = parent_coinbase.serialize(witness=True)
    out += b"\x00" * 32  # hashBlock (unused)
    out += varint(len(coinbase_branch)) + b"".join(coinbase_branch)
    out += struct.pack("<i", 0)  # nIndex of coinbase
    out += varint(len(chain_branch)) + b"".join(chain_branch)
    out += struct.pack("<i", chain_index)
    out += parent_header
    return out


def parse_auxpow(b: bytes):
    r = Reader(b)
    cb = Tx._parse(r)
    r.read(32)
    cbb = [r.read(32) for _ in range(r.varint())]
    r.i32()
    chb = [r.read(32) for _ in range(r.varint())]
    idx = r.i32()
    hdr = r.read(80)
    if not r.done():
        raise ValueError("trailing auxpow bytes")
    return cb, cbb, chb, idx, hdr


def check_auxpow(aux_hash: bytes, chain_id: int, auxpow: bytes, strict_chain_id=True) -> Tuple[bool, str]:
    """Port of CAuxPow::check. aux_hash in internal byte order."""
    cb, cbb, chb, idx, hdr = parse_auxpow(auxpow)
    parent_version = struct.unpack("<i", hdr[:4])[0]
    if strict_chain_id and (parent_version // (1 << 16)) == chain_id:
        return False, "Aux POW parent has our chain ID"
    if len(chb) > 30:
        return False, "Aux POW chain merkle branch too long"
    root = root_from_branch(aux_hash, chb, idx)
    vch_root = root[::-1]
    if root_from_branch(cb.txid(), cbb, 0) != hdr[36:68]:
        return False, "Aux POW merkle root incorrect"
    if not cb.vin:
        return False, "Aux POW coinbase has no inputs"
    script = cb.vin[0].script_sig
    head = script.find(MM_MAGIC)
    pc = script.find(vch_root)
    if pc < 0:
        return False, "Aux POW missing chain merkle root in parent coinbase"
    if head >= 0:
        if script.find(MM_MAGIC, head + 1) >= 0:
            return False, "Multiple merged mining headers in coinbase"
        if head + len(MM_MAGIC) != pc:
            return False, "Merged mining header is not just before chain merkle root"
    elif pc > 20:
        return False, "Aux POW chain merkle root must start in the first 20 bytes of the parent coinbase"
    pc += len(vch_root)
    if len(script) - pc < 8:
        return False, "Aux POW missing chain merkle tree size and nonce in parent coinbase"
    size, nonce = struct.unpack("<II", script[pc:pc + 8])
    if size != (1 << len(chb)):
        return False, "Aux POW merkle branch size does not match parent coinbase"
    if idx != expected_index(nonce, chain_id, len(chb)):
        return False, "Aux POW wrong index"
    return True, "ok"
