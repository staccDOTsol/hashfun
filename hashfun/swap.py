"""Atomic swaps: CLI (decred/atomicswap-style verbs), a maker bot and an
untrusted order relay. Chain access goes through a small adapter so the same
engine runs against a node wallet (maker, CLI) or the hashfun HD wallet.

Taker buys FORK with BTC:
  1. taker initiate on BTC   (secret holder; long locktime T1)
  2. maker audit, waits N_btc confs, participate on FORK (locktime T2 << T1)
  3. taker waits N_fork confs on maker's lock, redeems FORK (reveals secret)
  4. maker extracts secret from the FORK chain, redeems BTC
Selling FORK mirrors it with the maker waiting N_fork confs first. The fork leg
is the weak leg: N_fork is sized so renting enough hash to reorg N_fork blocks
costs more than the swap is worth, and order size is capped accordingly.
"""
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, asdict
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from .crypto import random_priv, pubkey_from_priv, sha256
from .htlc import Contract, new_secret, redeem_tx, refund_tx, extract_secret
from .rpc import RPC, RPCError
from .ser import Tx, segwit_encode, address_to_script, script_to_address, work_from_bits

log = logging.getLogger("hashfun.swap")
COIN = 100_000_000


def coins(sats: int) -> str:
    return str((Decimal(sats) / COIN).quantize(Decimal("0.00000001")))


def sats(v) -> int:
    return int((Decimal(str(v)) * COIN).to_integral_value())


# ---------------------------------------------------------------- key store
class KeyStore:
    def __init__(self, path):
        self.path = os.path.expanduser(path)
        self.data = {"keys": {}, "secrets": {}}
        if os.path.exists(self.path):
            with open(self.path) as f:
                self.data = json.load(f)
        self.lock = threading.Lock()

    def save(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def new_key(self) -> bytes:
        with self.lock:
            k = random_priv()
            pub = pubkey_from_priv(k)
            self.data["keys"][pub.hex()] = f"{k:064x}"
            self.save()
            return pub

    def priv(self, pub: bytes) -> Optional[int]:
        v = self.data["keys"].get(pub.hex())
        return int(v, 16) if v else None

    def put_secret(self, secret: bytes):
        with self.lock:
            self.data["secrets"][sha256(secret).hex()] = secret.hex()
            self.save()

    def secret(self, h: bytes) -> Optional[bytes]:
        v = self.data["secrets"].get(h.hex())
        return bytes.fromhex(v) if v else None


# ---------------------------------------------------------------- chain adapter
class NodeChain:
    """Swap access to a Bitcoin Core-RPC node with a loaded wallet."""

    def __init__(self, name: str, rpc: RPC, hrp: str, conf_target=2, fallback_feerate=2):
        self.name, self.rpc, self.hrp = name, rpc, hrp
        self.conf_target, self.fallback_feerate = conf_target, fallback_feerate

    def fund(self, spk: bytes, amount: int):
        addr = script_to_address(spk, self.hrp)
        txid = self.rpc.sendtoaddress(addr, coins(amount))
        tx = Tx.parse(bytes.fromhex(self.rpc.gettransaction(txid)["hex"]))
        vout = next(i for i, o in enumerate(tx.vout) if o.script_pubkey == spk and o.value == amount)
        return txid, vout

    def output(self, txid: str, vout: int):
        """(amount, spk, confirmations) for an unspent output, else None."""
        o = self.rpc.gettxout(txid, vout, True)
        if not o:
            return None
        return sats(o["value"]), bytes.fromhex(o["scriptPubKey"]["hex"]), o["confirmations"]

    def broadcast(self, tx: Tx) -> str:
        return self.rpc.sendrawtransaction(tx.serialize().hex())

    def dest_script(self) -> bytes:
        return address_to_script(self.rpc.getnewaddress("", "bech32"), self.hrp)

    def feerate(self) -> int:
        try:
            r = self.rpc.estimatesmartfee(self.conf_target)
            if "feerate" in r:
                return max(1, int(r["feerate"] * COIN / 1000))
        except RPCError:
            pass
        return self.fallback_feerate

    def median_time(self) -> int:
        return self.rpc.getblockchaininfo()["mediantime"]

    def find_spend(self, txid: str, vout: int, lookback=500) -> Optional[Tx]:
        prev = bytes.fromhex(txid)[::-1]
        for mtxid in self.rpc.getrawmempool():
            tx = Tx.parse(bytes.fromhex(self.rpc.getrawtransaction(mtxid)))
            if any(i.prev_txid == prev and i.prev_vout == vout for i in tx.vin):
                return tx
        h = self.rpc.getblockcount()
        for height in range(h, max(-1, h - lookback), -1):
            blk = self.rpc.getblock(self.rpc.getblockhash(height), 0)
            for tx in iter_block_txs(bytes.fromhex(blk)):
                if any(i.prev_txid == prev and i.prev_vout == vout for i in tx.vin):
                    return tx
        return None


def iter_block_txs(raw: bytes):
    """Parse txs from a serialized block. Handles hashfun auxpow headers."""
    from .ser import Reader
    from .auxpow import parse_auxpow  # noqa
    r = Reader(raw)
    version = int.from_bytes(raw[:4], "little")
    r.read(80)
    if version & 0x100:  # auxpow present: coinbase tx, hashBlock, branch, idx, chain branch, idx, parent hdr
        Tx._parse(r)
        r.read(32)
        for _ in range(r.varint()):
            r.read(32)
        r.read(4)
        for _ in range(r.varint()):
            r.read(32)
        r.read(4)
        r.read(80)
    for _ in range(r.varint()):
        yield Tx._parse(r)


# ---------------------------------------------------------------- engine
def tx_fee(feerate: int, redeem=True) -> int:
    # P2WSH HTLC spend ~ 1 in / 1 out: redeem ~ 175 vB, refund ~ 165 vB
    return feerate * (180 if redeem else 170)


def initiate(chain, ks: KeyStore, counterparty_pub: bytes, amount: int, locktime: int):
    secret, h = new_secret()
    ks.put_secret(secret)
    refund_pub = ks.new_key()
    c = Contract(h, counterparty_pub, refund_pub, locktime)
    txid, vout = chain.fund(c.script_pubkey(), amount)
    return {"contract": c.script().hex(), "address": script_to_address(c.script_pubkey(), chain.hrp),
            "txid": txid, "vout": vout, "amount": amount, "secret_hash": h.hex(), "secret": secret.hex(),
            "locktime": locktime, "refund_pub": refund_pub.hex()}


def participate(chain, ks: KeyStore, counterparty_pub: bytes, amount: int, secret_hash: bytes, locktime: int):
    refund_pub = ks.new_key()
    c = Contract(secret_hash, counterparty_pub, refund_pub, locktime)
    txid, vout = chain.fund(c.script_pubkey(), amount)
    return {"contract": c.script().hex(), "address": script_to_address(c.script_pubkey(), chain.hrp),
            "txid": txid, "vout": vout, "amount": amount, "secret_hash": secret_hash.hex(), "locktime": locktime,
            "refund_pub": refund_pub.hex()}


def audit(chain, contract_hex: str, txid: str, vout: int):
    c = Contract.parse(bytes.fromhex(contract_hex))
    out = chain.output(txid, vout)
    if out is None:
        return {"ok": False, "reason": "output missing or spent"}
    amount, spk, confs = out
    if spk != c.script_pubkey():
        return {"ok": False, "reason": "output script does not commit to this contract"}
    return {"ok": True, "amount": amount, "confirmations": confs, "secret_hash": c.secret_hash.hex(),
            "recipient_pub": c.recipient_pub.hex(), "refund_pub": c.refund_pub.hex(), "locktime": c.locktime,
            "address": script_to_address(spk, chain.hrp)}


def redeem(chain, ks: KeyStore, contract_hex: str, txid: str, vout: int, secret: bytes):
    c = Contract.parse(bytes.fromhex(contract_hex))
    priv = ks.priv(c.recipient_pub)
    if priv is None:
        raise ValueError("recipient key not in keystore")
    out = chain.output(txid, vout)
    if out is None:
        raise ValueError("contract output missing or spent")
    amount = out[0]
    tx = redeem_tx(c, bytes.fromhex(txid)[::-1], vout, amount, chain.dest_script(), tx_fee(chain.feerate()), priv, secret)
    return chain.broadcast(tx)


def refund(chain, ks: KeyStore, contract_hex: str, txid: str, vout: int):
    c = Contract.parse(bytes.fromhex(contract_hex))
    priv = ks.priv(c.refund_pub)
    if priv is None:
        raise ValueError("refund key not in keystore")
    out = chain.output(txid, vout)
    if out is None:
        raise ValueError("contract output missing or spent")
    tx = refund_tx(c, bytes.fromhex(txid)[::-1], vout, out[0], chain.dest_script(), tx_fee(chain.feerate(), False), priv)
    return chain.broadcast(tx)


def find_secret(chain, contract_hex: str, txid: str, vout: int) -> Optional[bytes]:
    c = Contract.parse(bytes.fromhex(contract_hex))
    tx = chain.find_spend(txid, vout)
    return extract_secret(tx, c.secret_hash) if tx else None


# ---------------------------------------------------------------- maker
@dataclass
class Order:
    id: str
    ticker: str
    side: str  # "buy" = taker buys FORK with BTC; "sell" = taker sells FORK for BTC
    amount: int  # FORK sats
    price: int  # BTC sats per whole FORK coin
    btc_amount: int
    secret_hash: str
    taker_pub: str  # taker's recipient key on the leg the maker funds
    init_contract: str
    init_txid: str
    init_vout: int
    state: str = "new"
    part_contract: str = ""
    part_txid: str = ""
    part_vout: int = 0
    maker_txid: str = ""
    note: str = ""
    created: float = 0.0


class Maker:
    """Quotes off the consensus curve: price = hashes_per_coin x hashprice x (1 +/- spread)."""

    def __init__(self, btc: NodeChain, forks: dict, ks: KeyStore, cfg: dict, state_path: str):
        self.btc, self.forks, self.ks, self.cfg = btc, forks, ks, cfg
        self.state_path = state_path
        self.orders = {}
        if os.path.exists(state_path):
            for o in json.load(open(state_path)):
                self.orders[o["id"]] = Order(**o)
        self.maker_btc_pub = bytes.fromhex(cfg["maker_btc_pub"]) if cfg.get("maker_btc_pub") else ks.new_key()
        self.maker_fork_pub = bytes.fromhex(cfg["maker_fork_pub"]) if cfg.get("maker_fork_pub") else ks.new_key()
        self.lock = threading.RLock()
        self.quotes = {}

    def save(self):
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump([asdict(o) for o in self.orders.values()], f, indent=1)
        os.replace(tmp, self.state_path)

    def chain_cfg(self, ticker):
        return {**self.cfg.get("defaults", {}), **self.cfg.get("chains", {}).get(ticker, {})}

    def fair_price(self, ticker: str) -> float:
        """BTC sats per whole coin at the current curve price."""
        info = self.forks[ticker].rpc.getlaunchinfo()
        cc = self.chain_cfg(ticker)
        return info["hashes_per_coin"] * float(cc["hashprice_sats_per_th"]) / 1e12

    def max_order_sats(self, ticker: str) -> int:
        """Cap: cost to rent enough hash to reorg N_fork blocks at current difficulty."""
        cc = self.chain_cfg(ticker)
        info = self.forks[ticker].rpc.getlaunchinfo()
        work = int(info["next"]["work"], 16)
        return int(cc["fork_confs"] * work * float(cc["hashprice_sats_per_th"]) / 1e12 * cc.get("safety", 0.5))

    def quote(self, ticker: str, side: str, amount: int):
        cc = self.chain_cfg(ticker)
        fair = self.fair_price(ticker)
        spread = float(cc.get("spread", 0.03))
        price = int(fair * (1 + spread if side == "buy" else 1 - spread))
        btc_amount = amount * price // COIN
        now_btc = self.btc.median_time()
        now_fork = self.forks[ticker].median_time()
        q = {"ticker": ticker, "side": side, "amount": amount, "price": price, "btc_amount": btc_amount,
             "fair": fair, "maker_pub": (self.maker_btc_pub if side == "buy" else self.maker_fork_pub).hex(),
             "init_chain": "BTC" if side == "buy" else ticker,
             "min_init_locktime": (now_btc if side == "buy" else now_fork) + int(cc["init_lock_seconds"]),
             "part_lock_seconds": int(cc["part_lock_seconds"]), "btc_confs": cc["btc_confs"],
             "fork_confs": cc["fork_confs"], "max_btc": self.max_order_sats(ticker),
             "quote_id": uuid.uuid4().hex[:16], "expires": time.time() + float(cc.get("quote_ttl", 300))}
        with self.lock:
            self.quotes[q["quote_id"]] = q
            for k in [k for k, v in self.quotes.items() if v["expires"] < time.time()]:
                self.quotes.pop(k)
        return q

    def submit(self, req: dict) -> Order:
        """Orders reference a live quote, so the curve moving between quote and
        submit cannot invalidate the taker's already-funded lock."""
        q = self.quotes.get(req.get("quote_id", ""))
        if q is None or q["expires"] < time.time():
            raise ValueError("unknown or expired quote_id; request a new quote")
        if q["ticker"] != req["ticker"] or q["side"] != req["side"]:
            raise ValueError("order does not match quote")
        if q["btc_amount"] > q["max_btc"]:
            raise ValueError(f"order exceeds reorg-safe cap {q['max_btc']} sats at {q['fork_confs']} confs")
        self.quotes.pop(q["quote_id"], None)
        o = Order(id=uuid.uuid4().hex[:12], ticker=req["ticker"], side=req["side"], amount=q["amount"],
                  price=q["price"], btc_amount=q["btc_amount"], secret_hash=req["secret_hash"],
                  taker_pub=req["taker_pub"], init_contract=req["contract"], init_txid=req["txid"],
                  init_vout=int(req["vout"]), created=time.time())
        with self.lock:
            self.orders[o.id] = o
            self.save()
        return o

    def _legs(self, o: Order):
        fork = self.forks[o.ticker]
        if o.side == "buy":
            return self.btc, fork, o.btc_amount, o.amount, self.maker_btc_pub
        return fork, self.btc, o.amount, o.btc_amount, self.maker_fork_pub

    def step(self, o: Order):
        cc = self.chain_cfg(o.ticker)
        init_chain, part_chain, init_amount, part_amount, maker_pub = self._legs(o)
        init_confs = cc["btc_confs"] if o.side == "buy" else cc["fork_confs"]
        part_confs_for_taker = cc["fork_confs"] if o.side == "buy" else cc["btc_confs"]
        if o.state == "new":
            a = audit(init_chain, o.init_contract, o.init_txid, o.init_vout)
            if not a["ok"]:
                o.note = a["reason"]
                return
            c = Contract.parse(bytes.fromhex(o.init_contract))
            if (a["amount"] < init_amount or c.recipient_pub != maker_pub or a["secret_hash"] != o.secret_hash):
                o.state, o.note = "rejected", "initiator contract does not match order"
                return
            part_lt = part_chain.median_time() + int(cc["part_lock_seconds"])
            # Initiator's lock must outlive ours by a margin covering our redeem after the reveal.
            if c.locktime < part_lt + int(cc.get("lock_margin_seconds", 3600)):
                o.state, o.note = "rejected", "initiator locktime too short"
                return
            if a["confirmations"] < init_confs:
                o.note = f"waiting {a['confirmations']}/{init_confs} confs on initiator lock"
                return
            r = participate(part_chain, self.ks, bytes.fromhex(o.taker_pub), part_amount, bytes.fromhex(o.secret_hash),
                            part_lt)
            o.part_contract, o.part_txid, o.part_vout = r["contract"], r["txid"], r["vout"]
            o.state, o.note = "participated", f"taker should wait {part_confs_for_taker} confs, then redeem"
        elif o.state == "participated":
            secret = find_secret(part_chain, o.part_contract, o.part_txid, o.part_vout)
            if secret:
                o.maker_txid = redeem(init_chain, self.ks, o.init_contract, o.init_txid, o.init_vout, secret)
                o.state, o.note = "done", "redeemed initiator leg with revealed secret"
                return
            c = Contract.parse(bytes.fromhex(o.part_contract))
            if part_chain.median_time() > c.locktime and part_chain.output(o.part_txid, o.part_vout):
                o.maker_txid = refund(part_chain, self.ks, o.part_contract, o.part_txid, o.part_vout)
                o.state, o.note = "refunded", "taker never redeemed; refunded our leg"

    def tick(self):
        with self.lock:
            for o in list(self.orders.values()):
                if o.state in ("done", "refunded", "rejected"):
                    continue
                try:
                    self.step(o)
                except Exception as e:  # keep the bot alive; surface the error on the order
                    o.note = f"error: {e}"
                    log.exception("order %s", o.id)
            self.save()

    def run(self, interval=2.0):
        while True:
            self.tick()
            time.sleep(interval)


def relay_handler(maker: Maker):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            from urllib.parse import urlparse, parse_qs
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            try:
                if u.path == "/quote":
                    return self._json(200, maker.quote(q["ticker"], q.get("side", "buy"), sats(q["amount"])))
                if u.path == "/orders":
                    return self._json(200, [asdict(o) for o in maker.orders.values()])
                if u.path.startswith("/orders/"):
                    o = maker.orders.get(u.path.split("/")[2])
                    return self._json(200 if o else 404, asdict(o) if o else {"error": "not found"})
                if u.path == "/info":
                    return self._json(200, {"btc_pub": maker.maker_btc_pub.hex(), "fork_pub": maker.maker_fork_pub.hex(),
                                            "chains": list(maker.forks)})
            except Exception as e:
                return self._json(400, {"error": str(e)})
            self._json(404, {"error": "not found"})

        def do_POST(self):
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                if self.path == "/orders":
                    return self._json(200, asdict(maker.submit(body)))
            except Exception as e:
                return self._json(400, {"error": str(e)})
            self._json(404, {"error": "not found"})
    return H


# ---------------------------------------------------------------- CLI
def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="hashfun atomic swap tool (HTLC over P2WSH)")
    ap.add_argument("--rpc", required=True, help="http://user:pass@host:port of bitcoind or hashfund")
    ap.add_argument("--wallet", help="node wallet name for funding/receiving")
    ap.add_argument("--hrp", required=True, help="bech32 hrp of this chain (bcrt, bc, or the launch hrp)")
    ap.add_argument("--keystore", default="~/.hashfun/swapkeys.json")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    p = sub.add_parser("initiate")
    p.add_argument("counterparty_pub")
    p.add_argument("amount", help="coins")
    p.add_argument("--lock-seconds", type=int, default=48 * 3600)
    p = sub.add_parser("participate")
    p.add_argument("counterparty_pub")
    p.add_argument("amount")
    p.add_argument("secret_hash")
    p.add_argument("--lock-seconds", type=int, default=24 * 3600)
    for name in ("audit", "redeem", "refund", "extractsecret"):
        p = sub.add_parser(name)
        p.add_argument("contract")
        p.add_argument("txid")
        p.add_argument("--vout", type=int, default=0)
        if name == "redeem":
            p.add_argument("secret")
    p = sub.add_parser("maker", help="run maker bot + relay from a JSON config")
    p.add_argument("config")
    a = ap.parse_args(argv)
    rpc = RPC(a.rpc, wallet=a.wallet)
    chain = NodeChain("chain", rpc, a.hrp)
    ks = KeyStore(a.keystore)
    if a.cmd == "keygen":
        out = {"pubkey": ks.new_key().hex()}
    elif a.cmd == "initiate":
        out = initiate(chain, ks, bytes.fromhex(a.counterparty_pub), sats(a.amount), chain.median_time() + a.lock_seconds)
    elif a.cmd == "participate":
        out = participate(chain, ks, bytes.fromhex(a.counterparty_pub), sats(a.amount), bytes.fromhex(a.secret_hash),
                          chain.median_time() + a.lock_seconds)
    elif a.cmd == "audit":
        out = audit(chain, a.contract, a.txid, a.vout)
    elif a.cmd == "redeem":
        out = {"txid": redeem(chain, ks, a.contract, a.txid, a.vout, bytes.fromhex(a.secret))}
    elif a.cmd == "refund":
        out = {"txid": refund(chain, ks, a.contract, a.txid, a.vout)}
    elif a.cmd == "extractsecret":
        s = find_secret(chain, a.contract, a.txid, a.vout)
        out = {"secret": s.hex() if s else None}
    elif a.cmd == "maker":
        cfg = json.load(open(a.config))
        btc = NodeChain("BTC", RPC(cfg["btc"]["rpc"], wallet=cfg["btc"].get("wallet")), cfg["btc"]["hrp"])
        forks = {t: NodeChain(t, RPC(c["rpc"], wallet=c.get("wallet")), c["hrp"]) for t, c in cfg["forks"].items()}
        mk = Maker(btc, forks, ks, cfg, cfg.get("state", "maker_orders.json"))
        host, port = cfg.get("listen", "127.0.0.1:8650").rsplit(":", 1)
        srv = ThreadingHTTPServer((host, int(port)), relay_handler(mk))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        logging.basicConfig(level=logging.INFO)
        log.info("maker relay on %s:%s", host, port)
        mk.run()
        return
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
