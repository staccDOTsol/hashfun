"""Small segwit-v0 script verifier: P2WPKH and the hashfun HTLC P2WSH script.
Used by the wallet to check a spend before broadcasting it, and by the test
simulator as its consensus check. Not a general Bitcoin script interpreter."""
from .crypto import sha256, hash160, ecdsa_verify, parse_der
from .ser import Tx, parse_script, bip143_sighash, p2pkh_script, script_num

OP = {"IF": 0x63, "ELSE": 0x67, "ENDIF": 0x68, "SIZE": 0x82, "EQUALVERIFY": 0x88, "SHA256": 0xA8,
      "CHECKLOCKTIMEVERIFY": 0xB1, "DROP": 0x75, "CHECKSIG": 0xAC}


class ScriptError(Exception):
    pass


def _num(b: bytes) -> int:
    if not b:
        return 0
    v = int.from_bytes(b, "little")
    if b[-1] & 0x80:
        return -(v & ~(0x80 << (8 * (len(b) - 1))))
    return v


def _checksig(tx, idx, sig, pub, script_code, amount):
    if not sig or sig[-1] != 1:
        return False
    try:
        r, s = parse_der(sig[:-1])
        return ecdsa_verify(pub, bip143_sighash(tx, idx, script_code, amount), r, s)
    except Exception:
        return False


def eval_witness_script(script: bytes, stack: list, tx: Tx, idx: int, amount: int):
    exec_stack = []
    for op, data in parse_script(script):
        executing = all(exec_stack)
        if op in (OP["IF"],):
            if executing:
                if not stack:
                    raise ScriptError("IF on empty stack")
                v = stack.pop()
                if v not in (b"", b"\x01"):
                    raise ScriptError("MINIMALIF")
                exec_stack.append(v == b"\x01")
            else:
                exec_stack.append(False)
            continue
        if op == OP["ELSE"]:
            exec_stack[-1] = not exec_stack[-1]
            continue
        if op == OP["ENDIF"]:
            exec_stack.pop()
            continue
        if not executing:
            continue
        if data is not None or op == 0:
            stack.append(data or b"")
        elif 0x51 <= op <= 0x60:
            stack.append(script_num(op - 0x50))
        elif op == OP["SIZE"]:
            stack.append(script_num(len(stack[-1])))
        elif op == OP["EQUALVERIFY"]:
            a, b = stack.pop(), stack.pop()
            if a != b:
                raise ScriptError("EQUALVERIFY")
        elif op == OP["SHA256"]:
            stack.append(sha256(stack.pop()))
        elif op == OP["DROP"]:
            stack.pop()
        elif op == OP["CHECKLOCKTIMEVERIFY"]:
            lt = _num(stack[-1])
            if lt < 0:
                raise ScriptError("negative locktime")
            if (lt < 500_000_000) != (tx.locktime < 500_000_000):
                raise ScriptError("locktime type mismatch")
            if lt > tx.locktime:
                raise ScriptError("locktime not reached")
            if tx.vin[idx].sequence == 0xFFFFFFFF:
                raise ScriptError("final sequence")
        elif op == OP["CHECKSIG"]:
            pub, sig = stack.pop(), stack.pop()
            stack.append(b"\x01" if _checksig(tx, idx, sig, pub, script, amount) else b"")
        else:
            raise ScriptError(f"unsupported opcode {op:#x}")
    if exec_stack:
        raise ScriptError("unbalanced IF")
    if len(stack) != 1 or stack[0] in (b"", b"\x00"):
        raise ScriptError("script evaluated false (or dirty stack)")


def verify_input(tx: Tx, idx: int, prev_spk: bytes, amount: int):
    w = list(tx.vin[idx].witness)
    if tx.vin[idx].script_sig:
        raise ScriptError("segwit input with scriptSig")
    if len(prev_spk) == 22 and prev_spk[:2] == b"\x00\x14":
        if len(w) != 2 or hash160(w[1]) != prev_spk[2:]:
            raise ScriptError("P2WPKH witness mismatch")
        if not _checksig(tx, idx, w[0], w[1], p2pkh_script(w[1]), amount):
            raise ScriptError("P2WPKH signature invalid")
        return
    if len(prev_spk) == 34 and prev_spk[:2] == b"\x00\x20":
        if not w or sha256(w[-1]) != prev_spk[2:]:
            raise ScriptError("P2WSH script hash mismatch")
        eval_witness_script(w[-1], w[:-1], tx, idx, amount)
        return
    raise ScriptError("unsupported prevout script")
