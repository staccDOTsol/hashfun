"""hashfun web: the site (board, coin pages, launch form, swaps signed in the browser) and the
JSON API behind it. It serves every launch registered on this machine (`hashfun node add`).

  hashfun web --btc-rpc http://user:pass@127.0.0.1:8332 [--listen 127.0.0.1:8080]
              [--maker maker.json] [--allow-launch]

The server never holds user keys: the browser derives its own key from a wallet signature,
builds and signs the swap contracts and transactions itself, and uses this API only to read
chain state and to broadcast. --maker runs a swap maker in the same process (its config names
the node wallets it trades from); without it the site is read-only plus mining instructions."""
import argparse
import json
import logging
import os
import re
import threading
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional
from urllib.parse import urlparse, parse_qs

from . import descriptor as D
from . import meta as M
from . import yieldmodel as Y
from .book import Book
from .crypto import hash160
from .rpc import RPC, RPCError
from .ser import address_to_script, script_to_address

log = logging.getLogger("hashfun.web")
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "static")
COIN = D.COIN
BTC_NETS = {"main": ("bc", 0, 5), "test": ("tb", 111, 196), "testnet4": ("tb", 111, 196), "signet": ("tb", 111, 196),
            "regtest": ("bcrt", 111, 196)}


def sats(v) -> int:
    return round(float(v) * COIN)


class CoinIndex:
    """What the site shows about one launch, kept current from its node: recent blocks with what
    each owed and whom it paid, who holds the coins, the price history."""

    def __init__(self, ticker: str, rpc: RPC, d: D.Launch, btc_hrp: str, refused: Optional[str] = None):
        self.ticker, self.rpc, self.d, self.btc_hrp = ticker, rpc, d, btc_hrp
        self.lock = threading.RLock()
        # refused: why the site does not serve this launch (its Bitcoin anchor is not what the site's
        # Bitcoin node has). Nothing is read from its node then; it has no height, so it is on no
        # board and in no book, and its own page says why, like a launch that is not running.
        self.refused = refused
        self.info, self.error = None, refused or "starting"
        try:  # the picture and blurb, only if they are the ones the launch id commits to
            self.meta = M.check(d)
        except M.MetaError as e:
            log.warning("%s: %s", ticker, e)
            self.meta = None
        self.reset()

    def meta_json(self) -> dict:
        m = self.meta
        if not m:
            return {}
        return {"description": m.description, "links": {k: getattr(m, k) for k in M.LINKS if getattr(m, k)},
                "meta": self.d.meta.hex(),
                **({"image": f"/api/coin/{self.ticker}/image?m={self.d.meta.hex()[:16]}"} if m.image else {})}

    def reset(self):
        self.hashes = [self.d.genesis_hash]
        self.rows: Dict[int, dict] = {}
        self.utxo: Dict[str, tuple] = {}  # "txid:n" -> (script hex, sats, height, coinbase)
        self.bal: Dict[str, int] = {}

    def poll(self):
        if self.refused:
            return
        try:
            info = self.rpc.getlaunchinfo()
            tip = info["height"]
            with self.lock:
                top = len(self.hashes) - 1
                if top > tip or self.rpc.getblockhash(top) != self.hashes[top]:
                    self.reset()  # reorg: launch chains are small enough to simply read again
                for h in range(len(self.hashes), tip + 1):
                    self._add(h)
                for h in [h for h in sorted(self.rows)[-120:] if not self.rows[h]["final"]]:
                    self._obligation(h, tip)
                self.info, self.error = info, None
        except Exception as e:  # node restarting, etc.: keep serving the last view
            self.error = str(e)

    def _add(self, h: int):
        bh = self.rpc.getblockhash(h)
        blk = self.rpc.getblock(bh, 3)
        fees = 0
        for n, tx in enumerate(blk["tx"]):
            if n:
                fees += sats(tx.get("fee", 0))
                for vin in tx["vin"]:
                    e = self.utxo.pop(f"{vin['txid']}:{vin['vout']}", None)
                    if e:
                        self.bal[e[0]] -= e[1]
                        if self.bal[e[0]] <= 0:
                            del self.bal[e[0]]
            for o in tx["vout"]:
                v, s = sats(o["value"]), o["scriptPubKey"]["hex"]
                if v > 0 and Y.earns_yield(bytes.fromhex(s)):
                    self.utxo[f"{tx['txid']}:{o['n']}"] = (s, v, h, n == 0)
                    self.bal[s] = self.bal.get(s, 0) + v
        cb = blk["tx"][0]
        work = int(blk["chainwork"], 16) - self.d.genesis_work
        self.rows[h] = {"height": h, "hash": bh, "time": blk["time"], "ntx": len(blk["tx"]),
                        "miner": script_to_address(bytes.fromhex(cb["vout"][0]["scriptPubKey"]["hex"]), self.d.hrp),
                        "minted": sum(sats(o["value"]) for o in cb["vout"]) - fees, "auxpow": bool(blk["version"] & 0x100),
                        "hpc": self.d.hashes_per_coin(work), "work": int(blk["chainwork"], 16), "final": False}
        self.hashes.append(bh)

    def _obligation(self, h: int, tip: int):
        ob, row = self.rpc.getmintobligation(h), self.rows[h]
        row.update(owed=ob["owed"], curve=ob["curve"], settled=ob["settled"], spendable=ob["spendable"],
                   draw_known=ob["draw_known"], pay=ob.get("pay"), payee=ob.get("payee"))
        if "pay_script" in ob:
            ps = bytes.fromhex(ob["pay_script"])
            row["pay_to"] = script_to_address(ps, self.btc_hrp) or ob["pay_script"]
        row["final"] = tip - h > 60 and (ob["settled"] or not ob["curve"] or ob["owed"] == 0 or
                                         (ob["draw_known"] and ob.get("pay") == 0) or tip >= ob["deadline_height"])

    def _earns_now(self, h: int, coinbase: bool) -> bool:
        """Is an output created in block h in the holder draw? All are, except a coinbase whose block
        owes sats and has neither settled nor been told that nothing is due: it earns from then on."""
        if not coinbase:
            return True
        r = self.rows.get(h, {})
        return (not r.get("curve")) or not r.get("owed") or bool(r.get("settled")) or \
            bool(r.get("draw_known") and r.get("pay") == 0)

    def _earning_supply(self) -> int:
        """What the next holder draw is taken over: the node's own figure."""
        if self.info and "earning" in self.info:
            return self.info["earning"]
        return sum(v for (s, v, h, cb) in self.utxo.values() if self._earns_now(h, cb))

    # ---- views
    def sats_leg_per_coin(self, hpc: float) -> float:
        """BTC (sats) the miner of one whole coin owes at this point of the curve."""
        return hpc * self.d.sats_num / 2 ** self.d.sats_shift

    def summary(self) -> dict:
        d, i = self.d, self.info
        if not i:
            return {"ticker": self.ticker, "name": d.name, "id": d.id_hex, "error": self.error, **self.meta_json()}
        with self.lock:
            rows = [self.rows[h] for h in sorted(self.rows)]
            recent = rows[-30:]
            span = max(1, recent[-1]["time"] - recent[0]["time"]) if len(recent) > 1 else 0
            paid = {k: sum(r["pay"] or 0 for r in rows if r.get("settled") and r.get("payee") == k)
                    for k in ("holder", "creator", "dev")}
            return {
                "ticker": self.ticker, "name": d.name, "id": d.id_hex, "hrp": d.hrp, "height": i["height"],
                "genesis_time": d.genesis_time, "creator": script_to_address(d.creator_script, d.hrp),
                "creator_btc": script_to_address(d.creator_btc_script, self.btc_hrp) or d.creator_btc_script.hex(),
                "progress": i["progress"], "graduated": i["graduated"], "graduation_height": i["graduation_height"],
                "curve_supply": i["curve_supply"], "supply": i["supply"], "curve_tokens": d.graduation_tokens,
                "total_tokens": d.virtual_tokens, "hashes_per_coin": i["hashes_per_coin"],
                "sats_leg_per_coin": self.sats_leg_per_coin(i["hashes_per_coin"]),
                "sats_leg_at_graduation": self.sats_leg_per_coin(d.hashes_per_coin(d.graduation_work)),
                "sats_total": d.graduation_work * d.sats_num >> d.sats_shift, "paid": paid,
                "last_block_time": rows[-1]["time"] if rows else d.genesis_time,
                "hashrate": (recent[-1]["work"] - recent[0]["work"]) / span if span else 0,
                "target_spacing": d.target_spacing, "creator_fee_bps": d.creator_fee_bps, "earning_supply": self._earning_supply(),
                "holders": len(self.bal), "error": self.error, **self.meta_json(),
                "recent": [{"height": r["height"], "time": r["time"], "pay": r["pay"], "pay_to": r.get("pay_to")}
                           for r in rows if r.get("settled") and r.get("pay") and r.get("payee") == "holder"][-6:],
            }

    def detail(self) -> dict:
        s = self.summary()
        if "height" not in s:
            return s
        with self.lock:
            hs = sorted(self.rows)
            step = max(1, len(hs) // 240)
            s["blocks"] = [self.rows[h] for h in hs[-40:]][::-1]
            s["series"] = [[h, self.sats_leg_per_coin(self.rows[h]["hpc"])] for h in hs[::step]] + \
                          ([[hs[-1], self.sats_leg_per_coin(self.rows[hs[-1]]["hpc"])]] if hs else [])
            top = sorted(self.bal.items(), key=lambda kv: -kv[1])[:25]
            s["top_holders"] = [{"address": script_to_address(bytes.fromhex(k), self.d.hrp) or k, "script": k, "value": v}
                                for k, v in top]
            s["descriptor"] = self.d.to_json()
        return s

    def address(self, script_hex: str) -> dict:
        with self.lock:
            tip = len(self.hashes) - 1
            utxos = [{"txid": k.split(":")[0], "vout": int(k.split(":")[1]), "value": v, "height": h,
                      "spendable": not cb or (tip - h >= 99 and self.rows[h].get("spendable", False)),
                      "earning": self._earns_now(h, cb)}
                     for k, (s, v, h, cb) in self.utxo.items() if s == script_hex]
            return {"balance": sum(u["value"] for u in utxos), "utxos": utxos,
                    "earning": sum(u["value"] for u in utxos if u["earning"]), "earning_supply": self._earning_supply(),
                    "height": tip}

    def spendable(self, script_hex: str) -> int:
        return sum(u["value"] for u in self.address(script_hex)["utxos"] if u["spendable"])


class _Asked:
    """A Bitcoin RPC handle that remembers whether a call through it failed. descriptor.check_anchor
    reports "the anchor is wrong" and "the node did not answer" the same way, and to a site that
    keeps running only the first is a verdict."""

    def __init__(self, rpc):
        self._rpc, self.failed = rpc, False

    def __getattr__(self, name):
        fn = getattr(self._rpc, name)

        def call(*args):
            try:
                return fn(*args)
            except Exception:
                self.failed = True
                raise
        return call


class Site:
    def __init__(self, btc: RPC, registry, maker=None, allow_launch=False, launch_args=(), book_path=None,
                 book_confs=6, book_lock=14400, book_min_lock=600):
        self.btc, self.reg, self.maker, self.allow_launch = btc, registry, maker, allow_launch
        self.launch_args = list(launch_args)
        # What the page proposes for peer-to-peer swaps: confirmations to wait for on a launch
        # chain (Bitcoin: 1) and the length of the second lock. Each trader's page enforces its own.
        self.book_confs, self.book_lock = book_confs, book_lock
        chain = btc.getblockchaininfo()["chain"]
        self.btc_chain = chain
        self.btc_hrp, self.btc_p2pkh, self.btc_p2sh = BTC_NETS.get(chain, BTC_NETS["main"])
        self.coins: Dict[str, CoinIndex] = {}
        # Launches whose Bitcoin anchor this site's Bitcoin node could not be asked about yet
        # (ticker -> when it was last asked): not served until it can, asked again every anchor_retry s.
        self.anchor_asked: Dict[str, float] = {}
        self.anchor_retry = 30.0
        self.scan_lock = threading.Lock()
        self.lock = threading.RLock()
        # Sats behind bids: confirmed sats at each bidder's key, from one UTXO-set scan for all of
        # them at once (instant on regtest, about a minute on mainnet, so at most every 5 minutes there).
        self.bid_sats: Dict[str, int] = {}
        self.bid_wanted: set = set()
        self.bid_scanned, self.bid_every = 0.0, (2.0 if self.btc_chain == "regtest" else 300.0)
        self.bid_pause = 0.5 if self.btc_chain == "regtest" else 60.0  # between two scans, whoever asks
        self.book = Book(self.book_chains, self.book_backing, book_path, min_lock=book_min_lock)

    def scan_bids(self):
        """Refresh the sats behind every open bid. A key seen for the first time is scanned soon
        (its offer is not listed until then), the rest on the schedule; and there is always a pause
        between two scans, so a stream of bids from fresh keys cannot keep the node scanning."""
        now = time.time()
        with self.book.lock:
            scripts = {"0014" + hash160(bytes.fromhex(o["maker"])).hex() for o in self.book.orders.values()
                       if o["give"] == self.btc_id and self.book.open(o)}
        new = (self.bid_wanted | scripts) - set(self.bid_sats)
        if not scripts and not new:
            self.bid_sats.clear()
            return
        if now - self.bid_scanned < (self.bid_pause if new else self.bid_every):
            return
        scripts |= new
        try:
            with self.scan_lock:
                r = self.btc.scantxoutset("start", [f"raw({x})" for x in sorted(scripts)])
        finally:
            self.bid_scanned = time.time()  # the pause counts from the end of a scan, failed ones too
        found: Dict[str, int] = {x: 0 for x in scripts}
        for u in r.get("unspents", []):
            if u.get("height"):  # confirmed only, like the page's own view of its sats
                found[u["scriptPubKey"]] = found.get(u["scriptPubKey"], 0) + sats(u["amount"])
        self.bid_sats = found
        self.bid_wanted -= scripts

    def run_bids(self, interval=0.5):
        """The bid scan on its own thread: a scan of the whole UTXO set takes about a minute on
        mainnet, and the board, the indexes and the house maker must not wait for it."""
        while True:
            try:
                self.scan_bids()
            except Exception:
                log.exception("bid scan")
            time.sleep(interval)

    # ---- the peer-to-peer book: which chains it covers and what stands behind an order
    @property
    def btc_id(self) -> str:
        return "btc:" + self.btc_chain

    def book_chains(self) -> Dict[str, str]:
        return {self.btc_id: "BTC", **{c.d.id_hex: t for t, c in list(self.coins.items()) if c.info}}

    def book_backing(self, chain: str, maker: str) -> Optional[int]:
        if chain == self.btc_id:  # sats: from the background scan (scan_bids); None until it has run for this key
            script = "0014" + hash160(bytes.fromhex(maker)).hex()
            if script not in self.bid_sats:
                self.bid_wanted.add(script)
            return self.bid_sats.get(script)
        for c in list(self.coins.values()):
            if c.d.id_hex == chain:
                return c.spendable("0014" + hash160(bytes.fromhex(maker)).hex())
        return 0

    def anchor_problem(self, d: D.Launch) -> Optional[str]:
        """Is the launch's Bitcoin anchor the block at that height on this site's own Bitcoin node,
        with the right difficulty-period start (descriptor.check_anchor)? None: yes. Text: no, and
        why. LookupError: the node cannot say now (it does not answer, or has not synced that far).

        The site shows what each block owes and whom it paid on the Bitcoin its own node follows, and
        tells people how to mine. A launch anchored anywhere else (another network, a made-up header,
        a wrong period start) cannot be settled from that chain: people who mine it lose their coins."""
        asked = _Asked(self.btc)
        try:
            tip = asked.getblockcount()
        except Exception as e:  # noqa: BLE001
            raise LookupError(f"the Bitcoin node does not answer: {e}")
        if d.btc_anchor_height > tip:
            raise LookupError(f"the launch is anchored at Bitcoin block {d.btc_anchor_height} and the Bitcoin node is at "
                              f"{tip} (still syncing, or another network)")
        try:
            D.check_anchor(d, asked)
        except D.DescriptorError as e:
            if asked.failed:
                raise LookupError(str(e))
            return str(e)
        return None

    def refresh(self):
        """Pick up launches registered since the last call, then poll each one."""
        for t in sorted(self.reg.data):
            if t not in self.coins:
                if time.time() - self.anchor_asked.get(t, -1e18) < self.anchor_retry:
                    continue  # its Bitcoin anchor could not be checked a moment ago: not yet again
                rpc = self.reg.rpc(t, timeout=20)
                if rpc:
                    d = self.reg.desc(t)
                    # Once per launch, before it is served: launches the form made here pass by
                    # construction, one registered from somebody's file (`hashfun node add`) may not.
                    try:
                        refused = self.anchor_problem(d)
                    except LookupError as e:
                        if t not in self.anchor_asked:
                            log.warning("%s: not served until its Bitcoin anchor can be checked: %s", t, e)
                        self.anchor_asked[t] = time.time()
                        continue
                    self.anchor_asked.pop(t, None)
                    if refused:
                        log.warning("%s: not served: %s", t, refused)
                    with self.lock:
                        self.coins[t] = CoinIndex(t, rpc, d, self.btc_hrp, refused=refused)
        for c in list(self.coins.values()):
            c.poll()

    def run(self, interval=1.0):
        while True:
            try:
                self.refresh()
                if self.maker:
                    self.maker.tick()
                self.book.save()
            except Exception:
                log.exception("refresh")
            time.sleep(interval)

    def coin(self, ticker: str) -> CoinIndex:
        c = self.coins.get(ticker)
        if not c:
            raise KeyError(f"unknown launch {ticker}")
        return c

    def btc_script(self, addr: str) -> bytes:
        return address_to_script(addr, self.btc_hrp, self.btc_p2pkh, self.btc_p2sh)

    # ---- chain access for the browser (same shape for Bitcoin and every launch)
    def chain_rpc(self, chain: str) -> RPC:
        if chain == "btc":
            return self.btc
        c = self.coin(chain)
        if c.refused:
            raise ValueError(f"{chain} is not served here: {c.refused}")
        return c.rpc

    def txout(self, chain: str, txid: str, vout: int):
        o = self.chain_rpc(chain).gettxout(txid, vout, True)
        return None if not o else {"value": sats(o["value"]), "script": o["scriptPubKey"]["hex"],
                                   "confirmations": o["confirmations"]}

    def tx(self, chain: str, txid: str):
        t = self.chain_rpc(chain).getrawtransaction(txid, True)
        return {"txid": t["txid"], "confirmations": t.get("confirmations", 0), "hex": t["hex"],
                "vout": [{"n": o["n"], "value": sats(o["value"]), "script": o["scriptPubKey"]["hex"]} for o in t["vout"]],
                "vin": [{"txid": i.get("txid"), "vout": i.get("vout"), "witness": i.get("txinwitness", [])} for i in t["vin"]]}

    def spender(self, chain: str, txid: str, vout: int):
        """The transaction that spent an output (mempool, then recent blocks): how a swap's secret is found."""
        from .swap import NodeChain
        tx = NodeChain(chain, self.chain_rpc(chain), "").find_spend(txid, vout, lookback=300)
        return None if tx is None else {"txid": tx.txid_hex(), "witness": [[w.hex() for w in i.witness] for i in tx.vin]}

    def chain_time(self, chain: str):
        i = self.chain_rpc(chain).getblockchaininfo()
        fee = 2
        try:
            r = self.chain_rpc(chain).estimatesmartfee(2)
            fee = max(1, int(r["feerate"] * COIN / 1000)) if "feerate" in r else 2
        except RPCError:
            pass
        return {"mediantime": i["mediantime"], "height": i["blocks"], "feerate": fee}

    def btc_address(self, script_hex: str):
        """Unspent Bitcoin outputs paying a script (BTC yield lands at the holder's own script).
        Uses scantxoutset: instant on regtest, about a minute on mainnet, one scan at a time."""
        with self.scan_lock:
            r = self.btc.scantxoutset("start", [f"raw({script_hex})"])
        tip = r.get("height", 0)
        utxos = [{"txid": u["txid"], "vout": u["vout"], "value": sats(u["amount"]),
                  "confirmations": tip - u["height"] + 1 if u.get("height") else 0} for u in r.get("unspents", [])]
        return {"balance": sum(u["value"] for u in utxos), "utxos": utxos}

    # ---- maker
    def quote(self, q: dict):
        if not self.maker:
            raise ValueError("no maker is running on this site")
        side, ticker = q.get("side", "buy"), q["ticker"]
        if ticker in self.coins and self.coins[ticker].refused:
            raise ValueError(f"{ticker} is not served here: {self.coins[ticker].refused}")
        if ticker not in self.maker.forks:
            raise ValueError(f"the maker on this site does not trade ${ticker} yet")
        if "sats" in q:  # "spend this much BTC": size the order at the current price
            price = int(self.maker.fair_price(ticker) * (1 + float(self.maker.chain_cfg(ticker).get("spread", 0.03))))
            amount = int(q["sats"]) * COIN // max(1, price)
        else:
            amount = int(q["amount"])
        return self.maker.quote(ticker, side, amount)

    # ---- launching from the form
    def launch(self, body: dict) -> dict:
        if not self.allow_launch:
            raise ValueError("this site does not create launches (start it with --allow-launch)")
        name, ticker = str(body["name"]).strip(), str(body["ticker"]).strip().upper()
        if ticker in self.reg.data:
            raise ValueError(f"{ticker} already exists here")
        creator_script = bytes.fromhex(body["creator_script"])
        try:
            metadata = M.Meta.from_json(body["metadata"]) if body.get("metadata") else None
        except M.MetaError as e:
            raise ValueError(str(e))
        regtest = self.btc_chain == "regtest"
        anchor = None if regtest else D.btc_anchor_from_rpc(self.btc)
        d = D.make(name, ticker, creator_script, int(body["graduation_hashes"]),
                   creator_fee_bps=int(body.get("creator_fee_bps", 100)), btc_anchor=anchor, btc_regtest=regtest,
                   sats_total=int(body["sats_total"]), creator_btc_script=self.btc_script(body["creator_btc_address"]),
                   metadata=metadata,
                   **({"pow_limit_bits": int(body["pow_limit_bits"])} if "pow_limit_bits" in body else {}))
        d.grind_genesis()
        from .cli import home
        path = os.path.join(home(), f"{ticker}-{d.id_hex[:8]}.json")
        with open(path, "w") as f:
            f.write(d.dumps())
        try:
            self.reg.add(path)
            self.reg.up(ticker, ["-minewithoutpeers", *self.launch_args])
        except SystemExit as e:  # the CLI helpers exit on failure; a server must not
            raise ValueError(str(e))
        return {"ticker": ticker, "id": d.id_hex, "meta": d.meta.hex() if any(d.meta) else None}


def handler(site: Site):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, code, body: bytes, ctype="application/json", cache="no-store"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj).encode())

        def _static(self, name):
            path = os.path.join(STATIC, name)
            if not re.fullmatch(r"[a-z0-9.-]+", name) or not os.path.isfile(path):
                return self._json(404, {"error": "not found"})
            ctype = {"html": "text/html; charset=utf-8", "js": "text/javascript; charset=utf-8",
                     "css": "text/css; charset=utf-8", "svg": "image/svg+xml", "woff2": "font/woff2"}.get(name.rsplit(".", 1)[-1], "application/octet-stream")
            with open(path, "rb") as f:
                self._send(200, f.read(), ctype)

        def _api(self, method, parts, q, body):
            if parts == ["config"]:
                return {"btc": {"chain": site.btc_chain, "hrp": site.btc_hrp, "p2pkh": site.btc_p2pkh, "p2sh": site.btc_p2sh},
                        "maker": bool(site.maker), "allow_launch": site.allow_launch, "btc_id": site.btc_id,
                        "book": {"confs": site.book_confs, "lock": site.book_lock},
                        "launches": {t: {"hrp": c.d.hrp, "name": c.d.name, "id": c.d.id_hex, "image": c.meta_json().get("image"),
                                         "target_spacing": c.d.target_spacing}
                                     for t, c in list(site.coins.items())}}
            if parts == ["board"]:
                return [c.summary() for c in list(site.coins.values())]
            if parts == ["quote"]:
                return site.quote(q)
            if parts == ["orders"] and method == "POST":
                if not site.maker:
                    raise ValueError("no maker is running on this site")
                return asdict(site.maker.submit(body))
            if len(parts) == 2 and parts[0] == "orders":
                o = site.maker.orders.get(parts[1]) if site.maker else None
                if not o:
                    raise KeyError("order not found")
                return asdict(o)
            if parts == ["launch"] and method == "POST":
                return site.launch(body)
            if parts and parts[0] == "book":
                return site.book.api(method, parts[1:], q, body)
            if len(parts) >= 2 and parts[0] == "coin" and len(parts) == 2:
                return site.coin(parts[1]).detail()
            if len(parts) == 4 and parts[0] == "coin" and parts[2] == "address":
                c = site.coin(parts[1])
                return c.address(address_to_script(parts[3], c.d.hrp).hex())
            if len(parts) >= 3 and parts[0] == "chain":
                chain = parts[1]
                if parts[2] == "time":
                    return site.chain_time(chain)
                if parts[2] == "txout":
                    return site.txout(chain, parts[3], int(parts[4]))
                if parts[2] == "spender":
                    return site.spender(chain, parts[3], int(parts[4]))
                if parts[2] == "tx" and method == "POST":
                    return {"txid": site.chain_rpc(chain).sendrawtransaction(body["hex"])}
                if parts[2] == "tx":
                    return site.tx(chain, parts[3])
                if parts[2] == "address" and chain == "btc":
                    return site.btc_address(site.btc_script(parts[3]).hex())
            raise KeyError("no such endpoint")

        def _handle(self, method):
            u = urlparse(self.path)
            if not u.path.startswith("/api/"):
                return self._static("index.html" if u.path in ("/", "") else u.path.lstrip("/"))
            m = re.fullmatch(r"/api/coin/([A-Z0-9]{2,10})/image", u.path)
            if m and method == "GET":
                c = site.coins.get(m.group(1))
                if not c or not c.meta or not c.meta.image:
                    return self._json(404, {"error": "no picture"})
                # Content-addressed by the launch id, so it can be cached forever. The type is the
                # one the bytes themselves declare (meta.py refuses anything but four raster formats).
                return self._send(200, c.meta.image, c.meta.image_type, cache="public, max-age=31536000, immutable")
            try:
                body = None
                if method == "POST":
                    n = int(self.headers.get("Content-Length", 0))
                    if n > 400_000:
                        raise ValueError("request too large")
                    body = json.loads(self.rfile.read(n) or b"{}")
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                self._json(200, self._api(method, [p for p in u.path[5:].split("/") if p], q, body))
            except KeyError as e:
                self._json(404, {"error": str(e).strip("'\"")})
            except RPCError as e:
                self._json(400, {"error": e.message, "code": e.code})
            except (ValueError, TypeError) as e:
                self._json(400, {"error": str(e)})
            except Exception as e:  # never take the server down for one bad request
                log.exception("api")
                self._json(500, {"error": str(e)})

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")
    return H


def build_maker(cfg_path: str, reg, btc: RPC):
    """Maker from a config like `hashfun swap maker` takes; launches it does not name are served
    from the registered node's first wallet."""
    from .swap import KeyStore, Maker, NodeChain
    cfg = json.load(open(cfg_path))
    base = os.path.dirname(os.path.abspath(cfg_path))
    bw = btc.wallet(cfg["btc"]["wallet"]) if cfg.get("btc", {}).get("wallet") else btc
    forks = {}
    for t in reg.data:
        r = reg.rpc(t, timeout=20)
        if r is None:
            continue
        wallet = cfg.get("forks", {}).get(t, {}).get("wallet") or (r.listwallets() or [None])[0]
        if wallet:
            forks[t] = NodeChain(t, r.wallet(wallet), reg.desc(t).hrp)
    ks = KeyStore(os.path.join(base, cfg.get("keystore", "maker_keys.json")))
    return Maker(NodeChain("BTC", bw, cfg["btc"].get("hrp", "bc")), forks, ks, cfg, os.path.join(base, cfg.get("state", "maker_orders.json")))


def serve(site: Site, host: str, port: int) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), handler(site))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=site.run, daemon=True).start()
    threading.Thread(target=site.run_bids, daemon=True).start()
    return srv


def main(argv=None):
    from .cli import Registry
    ap = argparse.ArgumentParser(prog="hashfun web", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--btc-rpc", required=True, help="Bitcoin Core RPC URL (reads, broadcasts, header anchor for new launches; "
                                                     "a registered launch is served only if its Bitcoin anchor is on this node's chain)")
    ap.add_argument("--btc-cookie")
    ap.add_argument("--listen", default="127.0.0.1:8080")
    ap.add_argument("--maker", help="maker config JSON: run a swap maker in this process")
    ap.add_argument("--allow-launch", action="store_true", help="let the launch form create chains on this machine")
    ap.add_argument("--launch-arg", action="append", default=[], help="extra hashfund argument for chains created here")
    ap.add_argument("--book-confs", type=int, default=6,
                    help="peer-to-peer swaps: confirmations the page waits for on a launch chain (default 6; Bitcoin is 1)")
    ap.add_argument("--book-lock", type=int, default=14400,
                    help="peer-to-peer swaps: seconds the maker's lock lasts; the taker's lasts twice that (default 4 h)")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    btc = RPC(a.btc_rpc, cookie_file=a.btc_cookie)
    reg = Registry()
    maker = build_maker(a.maker, reg, btc) if a.maker else None
    from .cli import home
    site = Site(btc, reg, maker, a.allow_launch, a.launch_arg, book_path=os.path.join(home(), "book.json"),
                book_confs=a.book_confs, book_lock=a.book_lock)
    host, port = a.listen.rsplit(":", 1)
    serve(site, host, int(port))
    print(json.dumps({"site": f"http://{host}:{port}", "bitcoin": site.btc_chain, "launches": sorted(reg.data),
                      "maker": bool(maker), "allow_launch": a.allow_launch}), flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
