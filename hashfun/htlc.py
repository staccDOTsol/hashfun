"""P2WSH hash time-locked contracts for cross-chain atomic swaps between any two
Bitcoin-script chains (BTC, every hashfun launch).

    OP_IF
        OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY <recipient_pub>
    OP_ELSE
        <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <refund_pub>
    OP_ENDIF
    OP_CHECKSIG

The OP_SIZE check pins the secret to 32 bytes on both chains, so a secret valid
on one leg can never be rejected (or accepted at a different size) on the other.
Redeem witness: <sig> <secret> 0x01 <script>; refund witness: <sig> <> <script>
with nLockTime >= locktime and a non-final sequence.
"""
import os
from dataclasses import dataclass
from typing import Optional

from .crypto import sha256, ecdsa_sign, der_sig, pubkey_from_priv
from .ser import (Tx, TxIn, TxOut, push, push_int, parse_script, p2wsh_script, bip143_sighash, script_num,
                  OP_IF, OP_ELSE, OP_ENDIF, OP_SIZE, OP_SHA256, OP_EQUALVERIFY, OP_CHECKLOCKTIMEVERIFY, OP_DROP,
                  OP_CHECKSIG)

LOCKTIME_THRESHOLD = 500_000_000


@dataclass
class Contract:
    secret_hash: bytes
    recipient_pub: bytes
    refund_pub: bytes
    locktime: int

    def script(self) -> bytes:
        return (bytes([OP_IF, OP_SIZE]) + push_int(32) + bytes([OP_EQUALVERIFY, OP_SHA256]) + push(self.secret_hash) +
                bytes([OP_EQUALVERIFY]) + push(self.recipient_pub) + bytes([OP_ELSE]) + push_int(self.locktime) +
                bytes([OP_CHECKLOCKTIMEVERIFY, OP_DROP]) + push(self.refund_pub) + bytes([OP_ENDIF, OP_CHECKSIG]))

    def script_pubkey(self) -> bytes:
        return p2wsh_script(self.script())

    @classmethod
    def parse(cls, script: bytes) -> "Contract":
        ops = list(parse_script(script))
        try:
            shape = [o for o, _ in ops]
            if (shape[0], shape[1], shape[3], shape[4], shape[6], shape[8]) != (
                    OP_IF, OP_SIZE, OP_EQUALVERIFY, OP_SHA256, OP_EQUALVERIFY, OP_ELSE):
                raise ValueError
            if shape[2] != 0x01 or ops[2][1] != bytes([32]):
                # push_int(32) is a 1-byte push of 0x20
                raise ValueError
            h, rpub = ops[5][1], ops[7][1]
            lt_op, lt_data = ops[9]
            if lt_data is None:
                if 0x51 <= lt_op <= 0x60:
                    locktime = lt_op - 0x50
                else:
                    raise ValueError
            else:
                locktime = int.from_bytes(lt_data, "little")
            if (shape[10], shape[11], shape[13], shape[14]) != (OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_ENDIF, OP_CHECKSIG):
                raise ValueError
            fpub = ops[12][1]
            if len(h) != 32 or len(rpub) != 33 or len(fpub) != 33 or len(ops) != 15:
                raise ValueError
        except (ValueError, IndexError, TypeError):
            raise ValueError("not a hashfun HTLC script")
        c = cls(h, rpub, fpub, locktime)
        if c.script() != script:
            raise ValueError("non-canonical HTLC script")
        return c


def new_secret():
    s = os.urandom(32)
    return s, sha256(s)


def _spend(contract: Contract, prev_txid_le: bytes, vout: int, amount: int, dest_spk: bytes, fee: int,
           locktime: int, sequence: int) -> Tx:
    if amount - fee <= 0:
        raise ValueError("fee exceeds contract amount")
    return Tx(version=2, vin=[TxIn(prev_txid_le, vout, b"", sequence)], vout=[TxOut(amount - fee, dest_spk)],
              locktime=locktime)


def redeem_tx(contract: Contract, prev_txid_le: bytes, vout: int, amount: int, dest_spk: bytes, fee: int,
              recipient_priv: int, secret: bytes) -> Tx:
    if pubkey_from_priv(recipient_priv) != contract.recipient_pub:
        raise ValueError("key does not match contract recipient")
    if sha256(secret) != contract.secret_hash or len(secret) != 32:
        raise ValueError("secret does not match contract")
    tx = _spend(contract, prev_txid_le, vout, amount, dest_spk, fee, 0, 0xFFFFFFFF)
    ws = contract.script()
    sig = der_sig(*ecdsa_sign(recipient_priv, bip143_sighash(tx, 0, ws, amount))) + b"\x01"
    tx.vin[0].witness = [sig, secret, b"\x01", ws]
    return tx


def refund_tx(contract: Contract, prev_txid_le: bytes, vout: int, amount: int, dest_spk: bytes, fee: int,
              refund_priv: int) -> Tx:
    if pubkey_from_priv(refund_priv) != contract.refund_pub:
        raise ValueError("key does not match contract refund key")
    tx = _spend(contract, prev_txid_le, vout, amount, dest_spk, fee, contract.locktime, 0xFFFFFFFE)
    ws = contract.script()
    sig = der_sig(*ecdsa_sign(refund_priv, bip143_sighash(tx, 0, ws, amount))) + b"\x01"
    tx.vin[0].witness = [sig, b"", ws]
    return tx


def extract_secret(spending_tx: Tx, secret_hash: bytes) -> Optional[bytes]:
    for i in spending_tx.vin:
        w = i.witness
        if len(w) == 4 and len(w[1]) == 32 and sha256(w[1]) == secret_hash:
            return w[1]
    return None
