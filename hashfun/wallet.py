"""One wallet, one seed: BTC and every hashfun launch, with built-in swaps.

BIP39 mnemonic -> BIP84 (P2WPKH) per chain at m/84'/<coin_type>'/0'/{0,1}/i.
coin_type: BTC 0 (main) / 1 (test, regtest); a launch uses 0x484600 + chain_id,
so every launch gets its own account under the same seed. HTLC keys live at
m/84'/<coin_type>'/1000'/0/i. Talks to Electrum-protocol servers
(hashfun.electrum) per chain.
"""
import hashlib
import json
import os
import socket
import threading
import time
import unicodedata
from typing import Dict, List, Optional

from .crypto import XPriv, ecdsa_sign, der_sig, sha256
from .htlc import Contract, new_secret, redeem_tx, refund_tx
from .ser import (Tx, TxIn, TxOut, segwit_encode, address_to_script, p2wpkh_script, p2wpkh_script_code,
                  bip143_sighash, script_to_address, hash160)

COIN = 100_000_000
GAP = 20
LAUNCH_COIN_BASE = 0x484600
WORDS = None


def wordlist():
    global WORDS
    if WORDS is None:
        with open(os.path.join(os.path.dirname(__file__), "bip39_english.txt")) as f:
            WORDS = [w.strip() for w in f if w.strip()]
        assert len(WORDS) == 2048
    return WORDS


def new_mnemonic(strength_bits=128) -> str:
    ent = os.urandom(strength_bits // 8)
    cs = sha256(ent)[0] >> (8 - strength_bits // 32)
    bits = (int.from_bytes(ent, "big") << (strength_bits // 32)) | cs
    n = (strength_bits + strength_bits // 32) // 11
    w = wordlist()
    return " ".join(w[(bits >> (11 * (n - 1 - i))) & 0x7FF] for i in range(n))


def check_mnemonic(m: str) -> bool:
    words = m.split()
    w = wordlist()
    if len(words) not in (12, 15, 18, 21, 24) or any(x not in w for x in words):
        return False
    bits = 0
    for x in words:
        bits = (bits << 11) | w.index(x)
    total = len(words) * 11
    csl = total // 33
    ent = (bits >> csl).to_bytes((total - csl) // 8, "big")
    return (sha256(ent)[0] >> (8 - csl)) == (bits & ((1 << csl) - 1))


def mnemonic_to_seed(m: str, passphrase="") -> bytes:
    m = unicodedata.normalize("NFKD", m)
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac("sha512", m.encode(), salt.encode(), 2048)


class ElectrumClient:
    def __init__(self, hostport: str, timeout=30):
        host, port = hostport.rsplit(":", 1)
        self.sock = socket.create_connection((host, int(port)), timeout=timeout)
        self.f = self.sock.makefile("rwb")
        self._id = 0
        self._lock = threading.Lock()
        self.call("server.version", "hashfun-wallet 0.1", "1.4")

    def call(self, method, *params):
        with self._lock:  # one request in flight per connection
            self._id += 1
            rid = self._id
            self.f.write((json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": list(params)}) + "\n").encode())
            self.f.flush()
            while True:
                line = self.f.readline()
                if not line:
                    raise ConnectionError("electrum server closed the connection")
                msg = json.loads(line)
                if msg.get("id") == rid:
                    if msg.get("error"):
                        raise RuntimeError(msg["error"].get("message"))
                    return msg.get("result")

    def close(self):
        self.sock.close()


class ChainAccount:
    def __init__(self, wallet: "Wallet", name: str, cfg: dict):
        self.wallet, self.name, self.cfg = wallet, name, cfg
        self.hrp = cfg["hrp"]
        self.account = wallet.root.derive(f"m/84'/{cfg['coin_type']}'/0'")
        self.htlc_account = wallet.root.derive(f"m/84'/{cfg['coin_type']}'/1000'/0")
        self._ec = None
        self._keys = {}

    @property
    def ec(self) -> ElectrumClient:
        if self._ec is None:
            self._ec = ElectrumClient(self.cfg["electrum"])
        return self._ec

    def key(self, change: int, i: int) -> XPriv:
        k = (change, i)
        if k not in self._keys:
            self._keys[k] = self.account.ckd(change).ckd(i)
        return self._keys[k]

    def address(self, change: int, i: int) -> str:
        return segwit_encode(self.hrp, 0, hash160(self.key(change, i).pub()))

    def scan(self):
        """Returns (utxos with signing keys, next unused receive idx, next unused change idx)."""
        utxos, nxt = [], {}
        for change in (0, 1):
            i, gap = 0, 0
            last_used = -1
            while gap < GAP:
                k = self.key(change, i)
                spk = p2wpkh_script(k.pub())
                sh = sha256(spk)[::-1].hex()
                hist = self.ec.call("blockchain.scripthash.get_history", sh)
                if hist:
                    last_used, gap = i, 0
                    for u in self.ec.call("blockchain.scripthash.listunspent", sh):
                        utxos.append({**u, "key": k, "spk": spk})
                else:
                    gap += 1
                i += 1
            nxt[change] = last_used + 1
        return utxos, nxt[0], nxt[1]

    def used_keys(self) -> List[XPriv]:
        """Keys of this account that have ever received coins on its chain."""
        keys = []
        for change in (0, 1):
            i, gap = 0, 0
            while gap < GAP:
                k = self.key(change, i)
                if self.ec.call("blockchain.scripthash.get_history", sha256(p2wpkh_script(k.pub()))[::-1].hex()):
                    keys.append(k)
                    gap = 0
                else:
                    gap += 1
                i += 1
        return keys

    def receive_address(self) -> str:
        _, r, _ = self.scan()
        return self.address(0, r)

    def balance(self):
        utxos, _, _ = self.scan()
        conf = sum(u["value"] for u in utxos if u["height"] > 0)
        unconf = sum(u["value"] for u in utxos if u["height"] <= 0)
        return {"confirmed": conf, "unconfirmed": unconf}

    def feerate(self) -> int:
        r = self.ec.call("blockchain.estimatefee", 2)
        if r and r > 0:
            return max(1, int(r * COIN / 1000))
        return int(self.cfg.get("fallback_feerate", 2))

    def tip(self) -> int:
        return self.ec.call("blockchain.headers.subscribe")["height"]

    def median_time(self) -> int:
        h = self.tip()
        start = max(0, h - 10)
        raw = bytes.fromhex(self.ec.call("blockchain.block.headers", start, h - start + 1)["hex"])
        times = sorted(int.from_bytes(raw[i * 80 + 68:i * 80 + 72], "little") for i in range(len(raw) // 80))
        return times[len(times) // 2]

    def build_send(self, outputs: List[TxOut], feerate: Optional[int] = None) -> Tx:
        feerate = feerate or self.feerate()
        utxos, _, change_i = self.scan()
        utxos.sort(key=lambda u: -u["value"])
        need = sum(o.value for o in outputs)
        sel, total = [], 0
        for u in utxos:
            sel.append(u)
            total += u["value"]
            vsize = 11 + 68 * len(sel) + 31 * (len(outputs) + 1) + sum(len(o.script_pubkey) for o in outputs)
            fee = vsize * feerate
            if total >= need + fee:
                break
        else:
            raise ValueError(f"insufficient funds: have {total}, need {need} + fee")
        tx = Tx(version=2, vin=[TxIn(bytes.fromhex(u["tx_hash"])[::-1], u["tx_pos"], b"", 0xFFFFFFFD) for u in sel],
                vout=list(outputs), locktime=0)
        change = total - need - fee
        if change > 546:
            tx.vout.append(TxOut(change, p2wpkh_script(self.key(1, change_i).pub())))
        for idx, u in enumerate(sel):
            k = u["key"]
            sig = der_sig(*ecdsa_sign(k.key, bip143_sighash(tx, idx, p2wpkh_script_code(k.pub()), u["value"]))) + b"\x01"
            tx.vin[idx].witness = [sig, k.pub()]
        return tx

    def broadcast(self, tx: Tx) -> str:
        return self.ec.call("blockchain.transaction.broadcast", tx.serialize().hex())

    def send(self, address: str, amount: int, feerate=None) -> str:
        return self.broadcast(self.build_send([TxOut(amount, address_to_script(address, self.hrp))], feerate))

    # ---- swap adapter (same interface the swap engine uses) ----
    def htlc_key(self, i: int) -> XPriv:
        return self.htlc_account.ckd(i)

    def fund(self, spk: bytes, amount: int):
        tx = self.build_send([TxOut(amount, spk)])
        txid = self.broadcast(tx)
        vout = next(i for i, o in enumerate(tx.vout) if o.script_pubkey == spk)
        return txid, vout

    def output(self, txid: str, vout: int):
        tx = Tx.parse(bytes.fromhex(self.ec.call("blockchain.transaction.get", txid)))
        o = tx.vout[vout]
        sh = sha256(o.script_pubkey)[::-1].hex()
        unspent = self.ec.call("blockchain.scripthash.listunspent", sh)
        u = next((u for u in unspent if u["tx_hash"] == txid and u["tx_pos"] == vout), None)
        if u is None:
            return None
        confs = self.tip() - u["height"] + 1 if u["height"] > 0 else 0
        return o.value, o.script_pubkey, confs

    def find_spend(self, txid: str, vout: int) -> Optional[Tx]:
        tx = Tx.parse(bytes.fromhex(self.ec.call("blockchain.transaction.get", txid)))
        sh = sha256(tx.vout[vout].script_pubkey)[::-1].hex()
        prev = bytes.fromhex(txid)[::-1]
        for e in self.ec.call("blockchain.scripthash.get_history", sh):
            if e["tx_hash"] == txid:
                continue
            t = Tx.parse(bytes.fromhex(self.ec.call("blockchain.transaction.get", e["tx_hash"])))
            if any(i.prev_txid == prev and i.prev_vout == vout for i in t.vin):
                return t
        return None

    def dest_script(self) -> bytes:
        _, r, _ = self.scan()
        return p2wpkh_script(self.key(0, r).pub())


class Wallet:
    def __init__(self, path="~/.hashfun/wallet.json"):
        self.path = os.path.expanduser(path)
        with open(self.path) as f:
            self.data = json.load(f)
        self.root = XPriv.from_seed(mnemonic_to_seed(self.data["mnemonic"], self.data.get("passphrase", "")))
        self.chains: Dict[str, ChainAccount] = {n: ChainAccount(self, n, c) for n, c in self.data["chains"].items()}

    @staticmethod
    def create(path="~/.hashfun/wallet.json", mnemonic=None, passphrase=""):
        path = os.path.expanduser(path)
        if os.path.exists(path):
            raise FileExistsError(path)
        mnemonic = mnemonic or new_mnemonic()
        if not check_mnemonic(mnemonic):
            raise ValueError("invalid BIP39 mnemonic")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump({"mnemonic": mnemonic, "passphrase": passphrase, "chains": {}, "swaps": {}, "htlc_next": {}}, f, indent=1)
        os.chmod(path, 0o600)
        return Wallet(path)

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def add_chain(self, name, electrum, hrp, coin_type, kind="launch"):
        self.data["chains"][name] = {"electrum": electrum, "hrp": hrp, "coin_type": coin_type, "kind": kind}
        self.save()
        self.chains[name] = ChainAccount(self, name, self.data["chains"][name])

    # ---- BTC yield ----
    # Holding launch coins earns BTC from later buyers, paid on Bitcoin at the holder's own launch
    # script. A launch is a Bitcoin fork, so the same key spends it there.
    def yield_utxos(self, btc: str = "BTC") -> List[dict]:
        """Bitcoin UTXOs sitting at this wallet's launch keys."""
        b, out = self.chains[btc], []
        for name, c in self.chains.items():
            if c.cfg.get("kind") != "launch":
                continue
            for k in c.used_keys():
                spk = p2wpkh_script(k.pub())
                for u in b.ec.call("blockchain.scripthash.listunspent", sha256(spk)[::-1].hex()):
                    out.append({**u, "key": k, "spk": spk, "launch": name})
        return out

    def yield_balance(self, btc: str = "BTC") -> Dict[str, int]:
        by = {}
        for u in self.yield_utxos(btc):
            by[u["launch"]] = by.get(u["launch"], 0) + u["value"]
        return by

    def claim_yield(self, btc: str = "BTC", feerate: Optional[int] = None) -> Optional[str]:
        """Sweep all earned BTC into the wallet's Bitcoin account. None if there is nothing worth moving."""
        b = self.chains[btc]
        utxos = self.yield_utxos(btc)
        total = sum(u["value"] for u in utxos)
        fee = (11 + 68 * len(utxos) + 31) * (feerate or b.feerate())
        if not utxos or total - fee <= 546:
            return None
        tx = Tx(version=2, vin=[TxIn(bytes.fromhex(u["tx_hash"])[::-1], u["tx_pos"], b"", 0xFFFFFFFD) for u in utxos],
                vout=[TxOut(total - fee, b.dest_script())], locktime=0)
        for idx, u in enumerate(utxos):
            k = u["key"]
            sig = der_sig(*ecdsa_sign(k.key, bip143_sighash(tx, idx, p2wpkh_script_code(k.pub()), u["value"]))) + b"\x01"
            tx.vin[idx].witness = [sig, k.pub()]
        return b.broadcast(tx)

    def next_htlc_key(self, chain: str) -> XPriv:
        i = self.data.setdefault("htlc_next", {}).get(chain, 0)
        self.data["htlc_next"][chain] = i + 1
        self.save()
        return self.chains[chain].htlc_key(i)

    def htlc_priv(self, chain: str, pub: bytes) -> Optional[int]:
        acct = self.chains[chain]
        for i in range(self.data.get("htlc_next", {}).get(chain, 0)):
            k = acct.htlc_key(i)
            if k.pub() == pub:
                return k.key
        return None

    # ------------------------------------------------------------ taker swaps
    def swap(self, relay: str, ticker: str, side: str, amount: int, btc="BTC", wait=True, poll=2.0, log=print):
        """Taker flow against a hashfun maker relay. side="buy": pay BTC, receive TICKER."""
        import urllib.request
        from .swap import coins

        def get(path):
            with urllib.request.urlopen(relay + path, timeout=30) as r:
                return json.loads(r.read())

        def post(path, obj):
            req = urllib.request.Request(relay + path, json.dumps(obj).encode(), {"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())

        q = get(f"/quote?ticker={ticker}&side={side}&amount={coins(amount)}")
        init_chain, part_chain = (btc, ticker) if side == "buy" else (ticker, btc)
        init_amount = q["btc_amount"] if side == "buy" else amount
        if init_amount > q["max_btc"] and side == "buy":
            raise ValueError("amount exceeds maker's reorg-safe cap")
        ia, pa = self.chains[init_chain], self.chains[part_chain]
        secret, h = new_secret()
        refund_k = self.next_htlc_key(init_chain)
        recv_k = self.next_htlc_key(part_chain)
        locktime = max(q["min_init_locktime"], ia.median_time() + q["part_lock_seconds"] * 2) + 600
        c = Contract(h, bytes.fromhex(q["maker_pub"]), refund_k.pub(), locktime)
        txid, vout = ia.fund(c.script_pubkey(), init_amount)
        rec = {"ticker": ticker, "side": side, "amount": amount, "quote": q, "secret": secret.hex(),
               "init_chain": init_chain, "part_chain": part_chain, "init_contract": c.script().hex(),
               "init_txid": txid, "init_vout": vout, "state": "initiated", "created": time.time()}
        sid = h.hex()[:16]
        self.data.setdefault("swaps", {})[sid] = rec
        self.save()
        log(f"[{sid}] locked {coins(init_amount)} on {init_chain} in {txid}:{vout}")
        order = post("/orders", {"quote_id": q["quote_id"], "ticker": ticker, "side": side, "amount": coins(amount),
                                 "secret_hash": h.hex(),
                                 "taker_pub": recv_k.pub().hex(), "contract": c.script().hex(), "txid": txid, "vout": vout})
        rec["order_id"] = order["id"]
        self.save()
        log(f"[{sid}] order {order['id']} posted at {order['price']} sats/coin")
        return self.resume(relay, sid, wait=wait, poll=poll, log=log) if wait else rec

    def resume(self, relay, sid, wait=True, poll=2.0, log=print):
        import urllib.request
        rec = self.data["swaps"][sid]
        ia, pa = self.chains[rec["init_chain"]], self.chains[rec["part_chain"]]
        need_confs = rec["quote"]["fork_confs"] if rec["side"] == "buy" else rec["quote"]["btc_confs"]
        expect = rec["amount"] if rec["side"] == "buy" else rec["quote"]["btc_amount"]
        from .swap import tx_fee
        margin = int(self.data.get("redeem_margin_seconds", 600))
        init_c = Contract.parse(bytes.fromhex(rec["init_contract"]))
        secret = bytes.fromhex(rec["secret"])
        while rec["state"] not in ("done", "refunded"):
            try:
                with urllib.request.urlopen(f"{relay}/orders/{rec['order_id']}", timeout=30) as r:
                    o = json.loads(r.read())
                note = f"order {o['state']}: {o.get('note')}"
                if o["state"] == "participated":
                    pc = Contract.parse(bytes.fromhex(o["part_contract"]))
                    priv = self.htlc_priv(rec["part_chain"], pc.recipient_pub)
                    if pc.secret_hash != sha256(secret) or priv is None:
                        note = "maker contract does not pay our key with our hash; will refund at locktime"
                    else:
                        out = pa.output(o["part_txid"], o["part_vout"])
                        now = pa.median_time()
                        # Only reveal the secret while the maker cannot yet refund its leg,
                        # and while our own lock outlives the maker's.
                        safe = pc.locktime < init_c.locktime and now + margin < pc.locktime
                        if out and out[2] >= need_confs and out[0] >= expect and safe:
                            tx = redeem_tx(pc, bytes.fromhex(o["part_txid"])[::-1], o["part_vout"], out[0],
                                           pa.dest_script(), tx_fee(pa.feerate()), priv, secret)
                            rec["redeem_txid"] = pa.broadcast(tx)
                            rec["state"] = "done"
                            self.save()
                            log(f"[{sid}] redeemed {out[0]} on {rec['part_chain']} in {rec['redeem_txid']}")
                            break
                        note = f"maker locked; {out[2] if out else 0}/{need_confs} confs" + ("" if safe else " (unsafe to reveal)")
                if ia.median_time() > init_c.locktime:
                    out = ia.output(rec["init_txid"], rec["init_vout"])
                    if out:
                        priv = self.htlc_priv(rec["init_chain"], init_c.refund_pub)
                        tx = refund_tx(init_c, bytes.fromhex(rec["init_txid"])[::-1], rec["init_vout"], out[0],
                                       ia.dest_script(), tx_fee(ia.feerate(), False), priv)
                        rec["refund_txid"] = ia.broadcast(tx)
                    rec["state"] = "refunded"
                    self.save()
                    log(f"[{sid}] refunded initiator leg")
                    break
                log(f"[{sid}] {note}")
            except (RuntimeError, ConnectionError, OSError, ValueError, KeyError) as e:
                log(f"[{sid}] transient: {e}")
            if not wait:
                break
            time.sleep(poll)
        return rec


def main(argv=None):
    import argparse
    from .swap import coins, sats
    ap = argparse.ArgumentParser(description="hashfun wallet: BTC + every launch, one seed")
    ap.add_argument("--wallet", default="~/.hashfun/wallet.json")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("--mnemonic")
    p = sub.add_parser("add-chain")
    p.add_argument("name")
    p.add_argument("--electrum", required=True)
    p.add_argument("--hrp")
    p.add_argument("--coin-type", type=int)
    p.add_argument("--descriptor", help="launch descriptor; sets hrp and coin type")
    sub.add_parser("balance")
    p = sub.add_parser("receive")
    p.add_argument("chain")
    p = sub.add_parser("send")
    p.add_argument("chain")
    p.add_argument("address")
    p.add_argument("amount")
    for side in ("buy", "sell"):
        p = sub.add_parser(side)
        p.add_argument("ticker")
        p.add_argument("amount")
        p.add_argument("--relay", required=True)
    p = sub.add_parser("swaps")
    sub.add_parser("yield", help="BTC earned by holding launch coins (paid at your launch keys on Bitcoin)")
    sub.add_parser("claim-yield", help="sweep earned BTC into the wallet's Bitcoin account")
    a = ap.parse_args(argv)
    if a.cmd == "init":
        w = Wallet.create(a.wallet, a.mnemonic)
        print(json.dumps({"mnemonic": w.data["mnemonic"], "path": w.path}, indent=2))
        return
    w = Wallet(a.wallet)
    if a.cmd == "add-chain":
        if a.descriptor:
            from .descriptor import load
            d = load(a.descriptor)
            hrp, ct = d.hrp, LAUNCH_COIN_BASE + d.chain_id
        else:
            hrp, ct = a.hrp, a.coin_type
        w.add_chain(a.name, a.electrum, hrp, ct, "launch" if a.descriptor else "btc")
        print(json.dumps({"chain": a.name, "hrp": hrp, "coin_type": ct}))
    elif a.cmd == "balance":
        print(json.dumps({n: {k: coins(v) for k, v in c.balance().items()} for n, c in w.chains.items()}, indent=2))
    elif a.cmd == "receive":
        print(w.chains[a.chain].receive_address())
    elif a.cmd == "send":
        print(w.chains[a.chain].send(a.address, sats(a.amount)))
    elif a.cmd in ("buy", "sell"):
        rec = w.swap(a.relay.rstrip("/"), a.ticker, a.cmd, sats(a.amount))
        print(json.dumps({k: v for k, v in rec.items() if k != "secret"}, indent=2))
    elif a.cmd == "yield":
        print(json.dumps({k: coins(v) for k, v in w.yield_balance().items()}, indent=2))
    elif a.cmd == "claim-yield":
        print(json.dumps({"txid": w.claim_yield()}))
    elif a.cmd == "swaps":
        print(json.dumps({k: {kk: vv for kk, vv in v.items() if kk != "secret"} for k, v in w.data.get("swaps", {}).items()},
                         indent=2))


if __name__ == "__main__":
    main()
