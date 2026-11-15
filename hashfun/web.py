"""hashfun web: the site (board, coin pages, launch form, swaps signed in the browser) and the
JSON API behind it. It serves every launch registered on this machine (`hashfun node add`).

  hashfun web --btc-rpc http://user:pass@127.0.0.1:8332 [--qwen-rpc http://user:pass@127.0.0.1:8732]
              [--listen 127.0.0.1:8080] [--base-path /fun] [--maker maker.json] [--allow-launch]

Every launch has two curves, one quoted in BTC and one in QWEN (contrib/hashfun/TWIN.md). The site
follows Bitcoin, and with --qwen-rpc Qwencoin as well: then QWEN is a chain of the book like any
other (coin/BTC, coin/QWEN and BTC/QWEN all trade), blocks can be mined on the QWEN curve from the
page, and their dues are paid on Qwencoin from the page's own key.

The server never holds user keys: the browser derives its own key from a wallet signature,
builds and signs the swap contracts and transactions itself, and uses this API only to read
chain state and to broadcast. --maker runs a swap maker in the same process (its config names
the node wallets it trades from); without it the site is read-only plus mining instructions."""
import argparse
import html
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
from urllib.request import urlopen

from . import descriptor as D
from . import meta as M
from . import yieldmodel as Y
from .book import Book
from .btclight import is_light
from .crypto import hash160
from .rpc import RPC, RPCError
from .ser import address_to_script, script_to_address

log = logging.getLogger("hashfun.web")
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "static")
COIN = D.COIN
BTC_NETS = {"main": ("bc", 0, 5), "test": ("tb", 111, 196), "testnet4": ("tb", 111, 196), "signet": ("tb", 111, 196),
            "regtest": ("bcrt", 111, 196)}
# Qwencoin kept Bitcoin's address forms on every network (its main network uses hrp "bc"): the same
# table reads its addresses. An address string therefore never says which of the two chains it is
# for: the API names the chain in the path, and the page names it wherever it shows an address.
CURVES = D.QUOTES  # ("btc", "qwen"): the two curves of a launch, named by what a block on them owes
# The pitch: one source for the words (contrib/hashfun/PITCH.md), carried here as the file the page
# itself is built with. The server says them where a script never runs: the link-preview tags.
with open(os.path.join(STATIC, "pitch.json"), encoding="utf-8") as _f:
    PITCH = json.load(_f)
JOIN = "https://huggingface.co/staccs/qwencoin"  # "Add yours": the Qwencoin project's install line


def show_price(p: float) -> str:
    """A price point as the page writes it (app.js price())."""
    if p >= 100:
        return f"{p:,.0f}"
    if p >= 1:
        return f"{p:.2f}"
    if p >= 0.01:
        return f"{p:.4f}"
    return f"{float(f'{p:.2g}'):.12f}".rstrip("0").rstrip(".") if p > 0 else "0"
OUTSIDE = {"btc": "Bitcoin", "qwen": "Qwencoin"}  # the chains of the book that are not launches


def sats(v) -> int:
    return round(float(v) * COIN)


class CoinIndex:
    """What the site shows about one launch, kept current from its node: recent blocks with what
    each owed and whom it paid, who holds the coins, and the price history of both curves."""

    def __init__(self, ticker: str, rpc: RPC, d: D.Launch, btc_hrp: str, refused: Optional[str] = None,
                 qwen_hrp: Optional[str] = None):
        self.p2p_port = None  # set by the site from its registry
        self.ticker, self.rpc, self.d, self.btc_hrp = ticker, rpc, d, btc_hrp
        # Where a payee's script is an address: on the chain of the block's quote.
        self.hrps = {"btc": btc_hrp, "qwen": qwen_hrp or btc_hrp}
        self.lock = threading.RLock()
        # refused: why the site does not serve this launch (an anchor of it is not what the site's
        # own node of that chain has). Nothing is read from its node then; it has no height, so it
        # is on no board and in no book, and its own page says why, like a launch that is not running.
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
        # A relative link: the page resolves it against wherever the site is served (--base-path).
        return {"description": m.description, "links": {k: getattr(m, k) for k in M.LINKS if getattr(m, k)},
                "meta": self.d.meta.hex(),
                **({"image": f"api/coin/{self.ticker}/image?m={self.d.meta.hex()[:16]}"} if m.image else {})}

    def reset(self):
        self.hashes = [self.d.genesis_hash]
        self.rows: Dict[int, dict] = {}
        self.utxo: Dict[str, tuple] = {}  # "txid:n" -> (script hex, sats, height, coinbase)
        self.bal: Dict[str, int] = {}
        # The two curves as the blocks read so far leave them (TWIN.md section 3): work done on each
        # and which one graduated the launch (None: neither yet).
        self.w = {x: 0 for x in CURVES}
        self.w_total = 0
        self.grad: Optional[str] = None
        self.last: Dict[str, Optional[tuple]] = {x: None for x in CURVES}  # (height, time) of the last block on it
        self.count = {x: 0 for x in CURVES}
        self.paid = {x: {"holder": 0, "creator": 0, "dev": 0} for x in CURVES}

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
        total = int(blk["chainwork"], 16) - self.d.genesis_work
        on = None
        if self.grad is None:  # before graduation every block is on one of the two curves
            on = D.curve_of_version(blk["version"])
            self.w[on] += total - self.w_total
            self.last[on] = (h, blk["time"])
            self.count[on] += 1
            if self.w[on] >= self.d.graduation_work:
                self.grad = on  # the first curve to sell out graduates the launch; both stop here
        self.w_total = total
        self.rows[h] = {"height": h, "hash": bh, "time": blk["time"], "ntx": len(blk["tx"]),
                        "miner": script_to_address(bytes.fromhex(cb["vout"][0]["scriptPubKey"]["hex"]), self.d.hrp),
                        "minted": sum(sats(o["value"]) for o in cb["vout"]) - fees, "auxpow": bool(blk["version"] & 0x100),
                        "on": on, "price": {x: self.d.price_per_coin(self.w[x], x) for x in CURVES},
                        "work": int(blk["chainwork"], 16), "final": False}
        self.hashes.append(bh)

    def _obligation(self, h: int, tip: int):
        ob, row = self.rpc.getmintobligation(h), self.rows[h]
        quote = ob.get("quote") or row["on"] or "btc"
        was = bool(row.get("settled"))
        row.update(owed=ob["owed"], curve=ob["curve"], settled=ob["settled"], spendable=ob["spendable"],
                   draw_known=ob["draw_known"], pay=ob.get("pay"), payee=ob.get("payee"), quote=quote)
        if "pay_script" in ob:
            ps = bytes.fromhex(ob["pay_script"])
            row["pay_to"] = script_to_address(ps, self.hrps[quote]) or ob["pay_script"]
        if ob["settled"] and not was and ob.get("pay") and ob.get("payee") in self.paid[quote]:
            self.paid[quote][ob["payee"]] += ob["pay"]  # counted once: a settled row is never unsettled without a reorg (reset)
        row["final"] = tip - h > 60 and (ob["settled"] or not ob["curve"] or ob["owed"] == 0 or
                                         (ob["draw_known"] and ob.get("pay") == 0) or tip >= ob["deadline_height"])

    def _earns_now(self, h: int, coinbase: bool) -> bool:
        """Is an output created in block h in the holder draw? All are, except a coinbase whose block
        owes its quote and has neither settled nor been told that nothing is due: it earns from then on."""
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

    # ---- the two curves
    def works(self) -> Dict[str, int]:
        """Work done on each curve: the node's figures when it gives them, else this index's own
        (from each block's version bit and chainwork; the two agree, and web_regtest checks it)."""
        c = (self.info or {}).get("curves") or {}
        return {x: int(c[x]["work"], 16) if x in c and "work" in c[x] else self.w[x] for x in CURVES}

    def curves(self) -> dict:
        """Per curve: its price point (base units of its quote owed per whole coin at the margin; the
        hash is not in it), how far it is mined, what it owes in all and has paid, and when it was
        last mined."""
        d, w, out = self.d, self.works(), {}
        node = (self.info or {}).get("curves") or {}
        for x in CURVES:
            c, last = node.get(x, {}), self.last[x]
            script = d.creator_quote_script(x)
            out[x] = {
                "price": d.price_per_coin(w[x], x), "price_at_start": d.price_per_coin(0, x),
                "price_at_graduation": d.price_per_coin(d.graduation_work, x),
                "progress": c.get("progress", d.curve_supply(w[x]) / d.graduation_tokens),
                "supply": c.get("supply", d.curve_supply(w[x])),
                "total": d.leg_total(x), "paid": dict(self.paid[x]),
                "min_payment": d.min_payment(x), "confs": d.confs(x),
                "creator": script_to_address(script, self.hrps[x]) or script.hex(),
                "blocks": c.get("blocks", self.count[x]), "last_height": c.get("last_height", last[0] if last else 0),
                "last_time": last[1] if last else None,
                # what the next block on this curve would mint and owe at the node's current difficulty
                **({"next": {"mint": c["next_subsidy"], "owed": c.get("next_owed", 0)}} if "next_subsidy" in c else {}),
            }
        return out

    def implied(self) -> Optional[dict]:
        """The QWEN price this coin's two price points imply, in sats per QWEN, and what kind of
        number it is (descriptor.quote_summary): a price while both curves are being mined, a floor
        while only the BTC curve is (were QWEN worth less, the QWEN curve would be the cheaper way
        in), a ceiling while only the QWEN curve is, history after graduation, and before the first
        block the ratio of the two starting prices, which is the creator's choice and nobody's trade."""
        info = self.info or {}
        if "curves" not in info:  # a node that does not report its curves: this index's own view of them
            w = self.works()
            info = {**info, "curves": {x: {"owed_per_coin": self.d.price_per_coin(w[x], x),
                                           "last_height": self.last[x][0] if self.last[x] else 0} for x in CURVES}}
        q = D.quote_summary(info)
        if q["implied_qwen_sats"] is None:
            return None
        kind = q["bound"] or ("history" if info.get("graduated") else "start")
        last = max((t[1] for t in self.last.values() if t), default=None)
        return {"sats_per_qwen": q["implied_qwen_sats"], "kind": kind, "two_sided": kind == "two-sided",
                "mined": q["mined"], "last_curve_time": last}

    # ---- views
    def summary(self) -> dict:
        d, i = self.d, self.info
        if not i:
            return {"ticker": self.ticker, "name": d.name, "id": d.id_hex, "error": self.error, **self.meta_json()}
        with self.lock:
            rows = [self.rows[h] for h in sorted(self.rows)]
            recent = rows[-30:]
            span = max(1, recent[-1]["time"] - recent[0]["time"]) if len(recent) > 1 else 0
            curves = self.curves()
            return {
                "ticker": self.ticker, "name": d.name, "id": d.id_hex, "hrp": d.hrp, "height": i["height"],
                "genesis_time": d.genesis_time, "creator": script_to_address(d.creator_script, d.hrp),
                "progress": max(c["progress"] for c in curves.values()), "graduated": i["graduated"],
                "graduated_by": i.get("graduated_by", self.grad), "graduation_height": i["graduation_height"],
                "curve_supply": i["curve_supply"], "supply": i["supply"], "curve_tokens": d.graduation_tokens,
                "total_tokens": d.virtual_tokens, "curves": curves, "implied": self.implied(),
                "last_block_time": rows[-1]["time"] if rows else d.genesis_time,
                "hashrate": (recent[-1]["work"] - recent[0]["work"]) / span if span else 0,
                "target_spacing": d.target_spacing, "creator_fee_bps": d.creator_fee_bps, "earning_supply": self._earning_supply(),
                "holders": len(self.bal), "error": self.error, **self.meta_json(),
                "recent": [{"height": r["height"], "time": r["time"], "pay": r["pay"], "pay_to": r.get("pay_to"), "quote": r["quote"]}
                           for r in rows[-600:] if r.get("settled") and r.get("pay") and r.get("payee") == "holder"][-6:],
            }

    def detail(self) -> dict:
        s = self.summary()
        if "height" not in s:
            return s
        with self.lock:
            hs = sorted(self.rows)
            step = max(1, len(hs) // 240)
            s["blocks"] = [self.rows[h] for h in hs[-40:]][::-1]
            # Each curve's price point at every sampled block. A curve's line is flat while the other is mined.
            pick = hs[::step] + ([hs[-1]] if hs and (len(hs) - 1) % step else [])
            s["series"] = {x: [[h, self.rows[h]["price"][x]] for h in pick] for x in CURVES}
            top = sorted(self.bal.items(), key=lambda kv: -kv[1])[:25]
            s["top_holders"] = [{"address": script_to_address(bytes.fromhex(k), self.d.hrp) or k, "script": k, "value": v}
                                for k, v in top]
            s["descriptor"] = self.d.to_json()
            # where this site's node of the launch listens: a miner's node must join it, or it
            # mines a chain of its own that nobody else follows
            s["p2p_port"] = self.p2p_port or self.d.p2p
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


class BtcIndex:
    """Bitcoin balances from an Electrum-protocol index (electrs, Fulcrum, ElectrumX): every
    script answered in milliseconds, many in one round trip. Without one the site scans the
    whole UTXO set per question (about a minute on mainnet, one at a time)."""

    def __init__(self, hostport: str, timeout: float = 20.0):
        host, port = hostport.rsplit(":", 1)
        self.host, self.port, self.timeout = host.strip("[]"), int(port), timeout
        self.lock = threading.Lock()
        self.sock, self.buf, self.id = None, b"", 0

    def _connect(self):
        import socket
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.buf = b""
        self._round([("server.version", ["hashfun", "1.4"])])

    def _round(self, calls):
        ids = []
        out = b""
        for method, params in calls:
            self.id += 1
            ids.append(self.id)
            out += json.dumps({"jsonrpc": "2.0", "id": self.id, "method": method, "params": params}).encode() + b"\n"
        self.sock.sendall(out)
        got = {}
        while len(got) < len(ids):
            while b"\n" not in self.buf:
                chunk = self.sock.recv(1 << 16)
                if not chunk:
                    raise ConnectionError("the Electrum index closed the connection")
                self.buf += chunk
            line, self.buf = self.buf.split(b"\n", 1)
            msg = json.loads(line)
            if msg.get("id") in ids:  # notifications (no id) are not asked for and are skipped
                got[msg["id"]] = msg
        res = []
        for i in ids:
            if got[i].get("error"):
                raise RuntimeError(f"Electrum index: {got[i]['error']}")
            res.append(got[i]["result"])
        return res

    def batch(self, calls):
        with self.lock:
            for attempt in (0, 1):  # reads only: safe to ask again once on a fresh connection
                try:
                    if self.sock is None:
                        self._connect()
                    return self._round(calls)
                except (OSError, ConnectionError, ValueError):
                    if self.sock is not None:
                        self.sock.close()
                    self.sock = None
                    if attempt:
                        raise

    def unspent(self, scripts):
        """{script hex: (tip height, [utxo...])} with confirmed and mempool outputs (height 0)."""
        from .electrum import scripthash
        scripts = list(scripts)
        res = self.batch([("blockchain.headers.subscribe", [])] +
                         [("blockchain.scripthash.listunspent", [scripthash(bytes.fromhex(s))]) for s in scripts])
        tip = res[0]["height"]
        return tip, {s: r for s, r in zip(scripts, res[1:])}


class KeyScan:
    """What stands behind bids made with an outside chain's coin (sats on Bitcoin, QWEN on
    Qwencoin): the confirmed base units at each bidder's key, from one UTXO-set scan of that chain's
    node for all of them at once (instant on regtest, about a minute on Bitcoin mainnet, so at most
    every 5 minutes there). Also answers "what does this script hold" for the page."""

    def __init__(self, rpc: RPC, chain: str, index: "BtcIndex" = None, what: str = "Bitcoin"):
        self.rpc, self.index, self.what = rpc, index, what
        self.sats: Dict[str, int] = {}
        self.wanted: set = set()
        self.scanned = 0.0
        self.every = 2.0 if chain == "regtest" else 300.0
        self.pause = 0.5 if chain == "regtest" else 60.0  # between two scans, whoever asks
        self.lock = threading.Lock()  # a node runs one scan at a time

    def get(self, script: str) -> Optional[int]:
        """Confirmed base units at a script, or None until a scan has looked at it."""
        if script not in self.sats:
            self.wanted.add(script)
        return self.sats.get(script)

    def refresh(self, scripts: set):
        """scripts: the keys with an open bid now. A key seen for the first time is scanned soon
        (its offer is not listed until then), the rest on the schedule; and there is always a pause
        between two scans, so a stream of bids from fresh keys cannot keep the node scanning."""
        now = time.time()
        new = (self.wanted | scripts) - set(self.sats)
        if not scripts and not new:
            self.sats.clear()
            return
        if self.index is not None:
            try:  # an index answers every key at once in milliseconds: no schedule, no pause
                _tip, res = self.index.unspent(sorted(scripts | new))
                self.sats = {x: sum(u["value"] for u in us if u["height"] > 0) for x, us in res.items()}
                self.wanted -= scripts | new
                self.scanned = time.time()
                return
            except Exception as e:
                log.warning("%s index not answering (%s): scanning the UTXO set instead", self.what, e)
        if now - self.scanned < (self.pause if new else self.every):
            return
        scripts = scripts | new
        try:
            with self.lock:
                r = self.rpc.scantxoutset("start", [f"raw({x})" for x in sorted(scripts)])
        finally:
            self.scanned = time.time()  # the pause counts from the end of a scan, failed ones too
        found: Dict[str, int] = {x: 0 for x in scripts}
        for u in r.get("unspents", []):
            if u.get("height"):  # confirmed only, like the page's own view of its coins
                found[u["scriptPubKey"]] = found.get(u["scriptPubKey"], 0) + sats(u["amount"])
        self.sats = found
        self.wanted -= scripts

    def address(self, script_hex: str) -> dict:
        """Unspent outputs paying a script on this chain (yield lands at the holder's own script).
        From the Electrum index when there is one (milliseconds; mempool included, as 0
        confirmations); else scantxoutset: instant on regtest and on Qwencoin, about a minute on
        Bitcoin mainnet, one at a time."""
        if self.index is not None:
            try:
                tip, res = self.index.unspent([script_hex])
                utxos = [{"txid": u["tx_hash"], "vout": u["tx_pos"], "value": u["value"],
                          "confirmations": tip - u["height"] + 1 if u["height"] > 0 else 0} for u in res[script_hex]]
                # balance: confirmed, as the scan reports it; the list also has what waits in the mempool
                return {"balance": sum(u["value"] for u in utxos if u["confirmations"] > 0), "utxos": utxos}
            except Exception as e:
                log.warning("%s index not answering (%s): scanning the UTXO set instead", self.what, e)
        with self.lock:
            r = self.rpc.scantxoutset("start", [f"raw({script_hex})"])
        tip = r.get("height", 0)
        utxos = [{"txid": u["txid"], "vout": u["vout"], "value": sats(u["amount"]),
                  "confirmations": tip - u["height"] + 1 if u.get("height") else 0} for u in r.get("unspents", [])]
        return {"balance": sum(u["value"] for u in utxos), "utxos": utxos}


class Site:
    def __init__(self, btc: RPC, registry, maker=None, allow_launch=False, launch_args=(), book_path=None,
                 book_confs=6, book_lock=14400, book_min_lock=600, btc_index: "BtcIndex" = None, qwen: RPC = None,
                 base_path: str = "", public_url: str = "", qwen_pages: str = ""):
        self.btc, self.reg, self.maker, self.allow_launch = btc, registry, maker, allow_launch
        self.btc_index = btc_index
        self.pools = None  # sitepool.SitePools when this site mines (hashfun web --pool)
        self.launch_args = list(launch_args)
        # Served under a path of somebody else's domain (--base-path /fun): "" or "/fun".
        self.base_path = "/" + base_path.strip("/") if base_path.strip("/") else ""
        # Where the world reaches the site, for the absolute addresses link previews need
        # (--public-url https://example.org/fun). Without it they are built from each request.
        self.public_url = public_url.rstrip("/")
        # The Qwencoin pages (--qwen-pages): how many machines run a node and a model right now
        # is their /graph/status.json "identities". (count, when read), or None.
        self.qwen_pages = qwen_pages.rstrip("/")
        self.pockets = None
        # What the page proposes for peer-to-peer swaps: confirmations to wait for on a launch
        # chain (Bitcoin: 1, Qwencoin: 6) and the length of the second lock. Each trader's page enforces its own.
        self.book_confs, self.book_lock = book_confs, book_lock
        chain = btc.getblockchaininfo()["chain"]
        self.btc_chain = chain
        self.btc_hrp, self.btc_p2pkh, self.btc_p2sh = BTC_NETS.get(chain, BTC_NETS["main"])
        # Qwencoin, when the site has a node of it (--qwen-rpc): a chain of the book, the chain QWEN
        # dues are paid on, and where the anchor of a new launch's QWEN leg comes from. Without one
        # the site still shows both curves of every launch (they are on the launch's own chain).
        self.qwen = qwen
        self.qwen_chain = qwen.getblockchaininfo()["chain"] if qwen is not None else None
        self.qwen_hrp, self.qwen_p2pkh, self.qwen_p2sh = BTC_NETS.get(self.qwen_chain or chain, BTC_NETS["main"])
        self.qwen_tip = None  # (height, when asked)
        self.coins: Dict[str, CoinIndex] = {}
        # Launches whose anchors this site's nodes could not be asked about yet
        # (ticker -> when it was last asked): not served until they can, asked again every anchor_retry s.
        self.anchor_asked: Dict[str, float] = {}
        self.anchor_retry = 30.0
        self.lock = threading.RLock()
        # Sats and QWEN behind bids: one scan per outside chain (KeyScan).
        self.scan: Dict[str, KeyScan] = {"btc": KeyScan(btc, chain, btc_index, "Bitcoin")}
        if qwen is not None:
            self.scan["qwen"] = KeyScan(qwen, self.qwen_chain, None, "Qwencoin")
        self.book = Book(self.book_chains, self.book_backing, book_path, min_lock=book_min_lock)

    # ---- the outside chains: Bitcoin, and Qwencoin when the site has a node of it
    @property
    def btc_id(self) -> str:
        return "btc:" + self.btc_chain

    @property
    def qwen_id(self) -> Optional[str]:
        return "qwen:" + self.qwen_chain if self.qwen is not None else None

    def outside_id(self, name: str) -> Optional[str]:
        return self.btc_id if name == "btc" else self.qwen_id

    def net(self, name: str) -> dict:
        """Address forms of an outside chain, as /api/config gives them to the page."""
        if name == "btc":
            return {"chain": self.btc_chain, "hrp": self.btc_hrp, "p2pkh": self.btc_p2pkh, "p2sh": self.btc_p2sh}
        return {"chain": self.qwen_chain, "hrp": self.qwen_hrp, "p2pkh": self.qwen_p2pkh, "p2sh": self.qwen_p2sh}

    def scan_bids(self):
        """Refresh what stands behind every open bid, on each outside chain."""
        for name, scan in self.scan.items():
            cid = self.outside_id(name)
            with self.book.lock:
                scripts = {"0014" + hash160(bytes.fromhex(o["maker"])).hex() for o in self.book.orders.values()
                           if o["give"] == cid and self.book.open(o)}
            try:
                scan.refresh(scripts)
            except Exception:
                log.exception("%s bid scan", OUTSIDE[name])

    def run_bids(self, interval=0.5):
        """The bid scans on their own thread: a scan of the whole UTXO set takes about a minute on
        Bitcoin mainnet, and the board, the indexes and the house maker must not wait for it."""
        while True:
            try:
                self.scan_bids()
            except Exception:
                log.exception("bid scan")
            time.sleep(interval)

    # ---- the peer-to-peer book: which chains it covers and what stands behind an order
    def book_chains(self) -> Dict[str, str]:
        return {self.btc_id: "BTC", **({self.qwen_id: "QWEN"} if self.qwen is not None else {}),
                **{c.d.id_hex: t for t, c in list(self.coins.items()) if c.info}}

    def book_backing(self, chain: str, maker: str) -> Optional[int]:
        script = "0014" + hash160(bytes.fromhex(maker)).hex()
        for name, scan in self.scan.items():
            if chain == self.outside_id(name):  # from the background scan; None until it has run for this key
                return scan.get(script)
        for c in list(self.coins.values()):
            if c.d.id_hex == chain:
                return c.spendable(script)
        return 0

    def _anchor(self, d: D.Launch, name: str) -> Optional[str]:
        """One anchor of a launch against this site's own node of that chain. None: it is that
        chain's block at that height, with the right difficulty-period start. Text: it is not, and
        why. LookupError: the node cannot say now (it does not answer, or has not synced that far)."""
        what, rpc = OUTSIDE[name], (self.btc if name == "btc" else self.qwen)
        height = d.btc_anchor_height if name == "btc" else d.qwen_anchor_height
        asked = _Asked(rpc)
        try:
            tip = asked.getblockcount()
        except Exception as e:  # noqa: BLE001
            raise LookupError(f"the {what} node does not answer: {e}")
        if height > tip:
            raise LookupError(f"the launch is anchored at {what} block {height} and the {what} node is at "
                              f"{tip} (still syncing, or another network)")
        try:
            (D.check_anchor if name == "btc" else D.check_qwen_anchor)(d, asked)
        except D.DescriptorError as e:
            if asked.failed:
                raise LookupError(str(e))
            return str(e)
        return None

    def anchor_problem(self, d: D.Launch) -> Optional[str]:
        """Are the launch's anchors blocks of the chains this site's own nodes follow
        (descriptor.check_anchor, check_qwen_anchor)? None: yes. Text: no, and why. LookupError: a
        node cannot say now.

        The site shows what each block owes and whom it paid on the Bitcoin and the Qwencoin its own
        nodes follow, and tells people how to mine. A launch anchored anywhere else (another
        network, a made-up header, a wrong period start) cannot be settled from that chain: people
        who mine it lose their coins. Without a Qwencoin node the site cannot ask about that
        anchor: it serves the launch and offers nothing on its QWEN curve (no mining, no dues)."""
        problem = self._anchor(d, "btc")
        if problem is None and self.qwen is not None:
            problem = self._anchor(d, "qwen")
        return problem

    def refresh(self):
        """Pick up launches registered since the last call, then poll each one."""
        for t in sorted(self.reg.data):
            if t not in self.coins:
                if time.time() - self.anchor_asked.get(t, -1e18) < self.anchor_retry:
                    continue  # an anchor of it could not be checked a moment ago: not yet again
                rpc = self.reg.rpc(t, timeout=20)
                if rpc:
                    d = self.reg.desc(t)
                    # Once per launch, before it is served: launches the form made here pass by
                    # construction, one registered from somebody's file (`hashfun node add`) may not.
                    try:
                        refused = self.anchor_problem(d)
                    except LookupError as e:
                        if t not in self.anchor_asked:
                            log.warning("%s: not served until its anchors can be checked: %s", t, e)
                        self.anchor_asked[t] = time.time()
                        continue
                    self.anchor_asked.pop(t, None)
                    if refused:
                        log.warning("%s: not served: %s", t, refused)
                    with self.lock:
                        self.coins[t] = CoinIndex(t, rpc, d, self.btc_hrp, refused=refused, qwen_hrp=self.qwen_hrp)
                        self.coins[t].p2p_port = (self.reg.data.get(t) or {}).get("p2pport")
                    if self.pools is not None and not refused:
                        try:
                            self.pools.ensure(t, rpc, d)
                        except Exception as e:
                            log.warning("%s: no pool: %s", t, e)
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

    def outside_script(self, name: str, addr: str) -> bytes:
        """The script of an address on Bitcoin or on Qwencoin. The same string is an address on
        both (TWIN.md): which chain is meant is always the caller's to say."""
        n = self.net(name)
        return address_to_script(addr, n["hrp"], n["p2pkh"], n["p2sh"])

    def btc_script(self, addr: str) -> bytes:
        return self.outside_script("btc", addr)

    # ---- chain access for the browser (same shape for Bitcoin, Qwencoin and every launch)
    def chain_rpc(self, chain: str) -> RPC:
        if chain == "btc":
            return self.btc
        if chain == "qwen":
            if self.qwen is None:
                raise ValueError("this site has no Qwencoin node")
            return self.qwen
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
        from .btclight import is_light
        from .swap import NodeChain
        rpc = self.chain_rpc(chain)
        # (Bitcoin through Electrum servers has no mempool or block to read: the output's script is asked what spent it)
        tx = rpc.find_spend(txid, vout) if is_light(rpc) else NodeChain(chain, rpc, "").find_spend(txid, vout, lookback=300)
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

    def outside_address(self, name: str, script_hex: str) -> dict:
        """Unspent outputs paying a script on Bitcoin or on Qwencoin (KeyScan.address)."""
        self.chain_rpc(name)  # refuses "qwen" on a site without a Qwencoin node
        return self.scan[name].address(script_hex)

    def btc_address(self, script_hex: str):
        return self.outside_address("btc", script_hex)

    # ---- the pitch's one live number
    def read_pockets(self):
        """One read of the Qwencoin pages' status: staked identities on the graph, each a node with
        a model. Kept with the time it was read; a failed read keeps the last good one."""
        if not re.match(r"https?://", self.qwen_pages):
            return
        with urlopen(self.qwen_pages + "/graph/status.json", timeout=10) as r:
            n = json.loads(r.read(200_000)).get("identities")
        if isinstance(n, int) and not isinstance(n, bool) and 0 <= n < 10**9:
            self.pockets = (n, time.time())

    def run_pockets(self, every=60.0):
        """Off the request path, at most once a minute."""
        while self.qwen_pages:
            try:
                self.read_pockets()
            except Exception as e:  # noqa: BLE001
                log.info("the Qwencoin pages did not answer: %s", e)
            time.sleep(every)

    def pockets_view(self) -> Optional[dict]:
        """The number, only while it is fresh (read in the last five minutes): an old count is not
        "right now"."""
        p = self.pockets
        return {"n": p[0], "add": JOIN} if p and time.time() - p[1] <= 300 else None

    # ---- QWEN, site-wide: what the launches' curves imply, and what the book says
    def qwen_view(self) -> dict:
        """The QWEN price in sats as this site sees it: the median of what the launches imply whose
        two curves are both being mined (CoinIndex.implied), and beside it the best bid and ask of
        the BTC/QWEN book. Neither is the other's input."""
        each, live = [], 0
        for t, c in sorted(self.coins.items()):
            if not c.info or c.info.get("graduated"):
                continue
            live += 1
            with c.lock:
                imp = c.implied()
            if imp:
                each.append({"ticker": t, "sats_per_qwen": imp["sats_per_qwen"], "kind": imp["kind"],
                             "last_curve_time": imp["last_curve_time"]})
        two = sorted(x["sats_per_qwen"] for x in each if x["kind"] == "two-sided")
        median = None if not two else two[len(two) // 2] if len(two) % 2 else (two[len(two) // 2 - 1] + two[len(two) // 2]) / 2
        bid = ask = None
        if self.qwen is not None:
            for o in self.book.view():
                left, left_get = o["remaining"], o["remaining_get"]
                if o["give"] == self.qwen_id and o["get"] == self.btc_id and left > 0:  # QWEN on offer for sats
                    p = o["get_amount"] / o["give_amount"] * COIN
                    if ask is None or p < ask["price"]:
                        ask = {"price": p, "qwen": left, "sats": left_get, "order": o["id"]}
                elif o["give"] == self.btc_id and o["get"] == self.qwen_id and left > 0:  # sats bid for QWEN
                    p = o["give_amount"] / o["get_amount"] * COIN
                    if bid is None or p > bid["price"]:
                        bid = {"price": p, "qwen": left_get, "sats": left, "order": o["id"]}
            now = time.time()
            if self.qwen_tip is None or now - self.qwen_tip[1] > 5:
                try:
                    self.qwen_tip = (self.qwen.getblockcount(), now)
                except Exception:  # noqa: BLE001
                    self.qwen_tip = (self.qwen_tip[0] if self.qwen_tip else None, now)
        return {"node": self.qwen is not None, "chain": self.qwen_chain, "id": self.qwen_id,
                "height": self.qwen_tip[0] if self.qwen_tip else None,
                "implied": {"sats_per_qwen": median, "launches": len(two), "of": live, "each": each},
                "book": {"bid": bid, "ask": ask}, "pockets": self.pockets_view()}

    # ---- link previews: what a crawler reads, which runs no script
    def origin(self, headers) -> str:
        """The site's public address without a trailing slash: --public-url, or the request's own
        host and scheme (as the proxy in front reports them) with the base path."""
        if self.public_url:
            return self.public_url
        proto = (headers.get("X-Forwarded-Proto") or "http").split(",")[0].strip().lower()
        host = (headers.get("X-Forwarded-Host") or headers.get("Host") or "").split(",")[0].strip()
        if proto not in ("http", "https"):
            proto = "http"
        if not re.fullmatch(r"[A-Za-z0-9.\-:\[\]]{1,255}", host):
            host = "localhost"
        return f"{proto}://{host}{self.base_path}"

    def preview(self, headers, ticker: Optional[str] = None) -> dict:
        """title, description, url, image (absolute) and the card kind for the site, or for one coin:
        its name and ticker, both price points, how far each curve is, and its own picture."""
        base = self.origin(headers)
        site = {"title": f"hashfun: {PITCH['what']}", "og_title": PITCH["what"], "description": PITCH["oneliner"],
                "url": base + "/", "image": base + "/share.png", "card": "summary_large_image", "size": (1200, 630),
                "alt": f"hashfun. {PITCH['what']} {PITCH['tagline']}"}
        c = self.coins.get(ticker) if ticker else None
        if not c or not c.info:
            return site
        with c.lock:
            cv, d = c.curves(), c.d
        point = {x: f"{show_price(cv[x]['price'])} {'QWEN sats' if x == 'qwen' else 'sats'} per coin" for x in CURVES}
        mined = {x: f"{cv[x]['progress'] * 100:.1f}%" for x in CURVES}
        first = PITCH["coin"].split(". ")[0].replace("{TICKER}", "$" + ticker) + "."
        if c.info.get("graduated"):
            state = (f"Graduated: its curves closed at {point['btc']} (BTC curve, {mined['btc']} mined) and {point['qwen']} "
                     f"(QWEN curve, {mined['qwen']} mined); merge-mined with Bitcoin now.")
        else:
            state = (f"BTC curve: {point['btc']}, {mined['btc']} mined. QWEN curve: {point['qwen']}, {mined['qwen']} mined. "
                     "Take the cheaper one.")
        m = c.meta_json()
        out = {**site, "title": f"{d.name} (${ticker}) on hashfun", "og_title": f"{d.name} (${ticker})",
               "description": f"{first} {state}", "url": f"{base}/c/{ticker}", "alt": f"{d.name} (${ticker})"}
        if m.get("image"):
            out.update(image=f"{base}/{m['image']}", card="summary", size=None)
        return out

    def page(self, headers, ticker: Optional[str] = None, depth: int = 0) -> bytes:
        """The page's HTML with the pitch's words and the preview tags in it. depth: how many
        path segments below the site's root the address is (/c/TICKER: 2), so that the page's
        relative links still resolve against the root."""
        p, e = self.preview(headers, ticker), html.escape
        tags = [f'<base href="{"../" * (depth - 1)}">' if depth > 1 else "",
                f'<meta name="description" content="{e(p["description"])}">',
                '<meta property="og:type" content="website">', '<meta property="og:site_name" content="hashfun">',
                f'<meta property="og:title" content="{e(p["og_title"])}">',
                f'<meta property="og:description" content="{e(p["description"])}">',
                f'<meta property="og:url" content="{e(p["url"])}">', f'<meta property="og:image" content="{e(p["image"])}">',
                *([f'<meta property="og:image:width" content="{p["size"][0]}">',
                   f'<meta property="og:image:height" content="{p["size"][1]}">'] if p["size"] else []),
                f'<meta property="og:image:alt" content="{e(p["alt"])}">',
                f'<meta name="twitter:card" content="{p["card"]}">', f'<meta name="twitter:title" content="{e(p["og_title"])}">',
                f'<meta name="twitter:description" content="{e(p["description"])}">',
                f'<meta name="twitter:image" content="{e(p["image"])}">', f'<link rel="canonical" href="{e(p["url"])}">']
        with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as f:
            doc = f.read()
        return doc.replace("{{title}}", e(p["title"])).replace("{{tags}}", "\n".join(t for t in tags if t)) \
            .replace("{{tagline}}", e(PITCH["tagline"])).encode()

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
    def launch_terms(self, q: dict) -> dict:
        """What the form shows before anything is created, from the same helpers that then build the
        launch (descriptor.make): the size of each curve, and for a QWEN leg of the given total the
        Qwencoin confirmations a payment proof needs (descriptor.qwen_confs_for: a proof is as hard
        to fake as that many Qwencoin blocks are to mine, so a larger leg needs more) with the
        settlement deadline that leaves room for them. Raises for a total no number of confirmations covers."""
        import types
        total, spacing = int(q.get("qwen_total", 0)), int(q.get("target_spacing", 5))
        regtest, qregtest = self.btc_chain == "regtest", self.qwen_chain in (None, "regtest") and self.btc_chain == "regtest"
        t0 = D.DEFAULT_SUPPLY_COINS * COIN
        g = t0 * D.PUMP_RATIO_G // D.PUMP_RATIO_T
        out = {"virtual_tokens": t0, "curve_tokens": g, "max_supply": t0 + g, "qwen_block_reward": D.QWEN_BLOCK_REWARD}
        if total > 0:
            confs = D.TEST_QWEN_CONFS if qregtest else D.qwen_confs_for(total)
            deadline = D.settle_deadline_for(types.SimpleNamespace(
                settle_deadline=D.Launch.settle_deadline, btc_regtest=regtest, qwen_regtest=qregtest,
                target_spacing=spacing, btc_confs=D.Launch.btc_confs, qwen_confs=confs))
            out.update(qwen_total=total, qwen_confs=confs, qwen_seconds=confs * D.QWEN_BLOCK_SECONDS,
                       settle_deadline=deadline, settle_seconds=deadline * spacing)
        return out

    def launch(self, body: dict) -> dict:
        if not self.allow_launch:
            raise ValueError("this site does not create launches (start it with --allow-launch)")
        if self.qwen is None:
            raise ValueError("this site has no Qwencoin node, and every launch is anchored on Qwencoin as well as on "
                             "Bitcoin: it cannot create launches (start it with --qwen-rpc)")
        name, ticker = str(body["name"]).strip(), str(body["ticker"]).strip().upper()
        if ticker in ("BTC", "QWEN"):
            raise ValueError(f"{ticker} names a chain here, not a coin: pick another ticker")
        if ticker in self.reg.data:
            raise ValueError(f"{ticker} already exists here")
        creator_script = bytes.fromhex(body["creator_script"])
        try:
            metadata = M.Meta.from_json(body["metadata"]) if body.get("metadata") else None
        except M.MetaError as e:
            raise ValueError(str(e))
        regtest, qregtest = self.btc_chain == "regtest", self.qwen_chain == "regtest"
        anchor = None if regtest else D.btc_anchor_from_rpc(self.btc)
        qanchor = None if qregtest else D.qwen_anchor_from_rpc(self.qwen)
        d = D.make(name, ticker, creator_script, int(body["graduation_hashes"]),
                   creator_fee_bps=int(body.get("creator_fee_bps", 100)), btc_anchor=anchor, btc_regtest=regtest,
                   sats_total=int(body["sats_total"]), creator_btc_script=self.btc_script(body["creator_btc_address"]),
                   qwen_anchor=qanchor, qwen_regtest=qregtest, qwen_total=int(body["qwen_total"]),
                   creator_qwen_script=self.outside_script("qwen", body["creator_qwen_address"]),
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
        return {"ticker": ticker, "id": d.id_hex, "meta": d.meta.hex() if any(d.meta) else None,
                "qwen_confs": d.qwen_confs, "settle_deadline": d.settle_deadline}


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
            ctype = {"html": "text/html; charset=utf-8", "js": "text/javascript; charset=utf-8", "json": "application/json",
                     "css": "text/css; charset=utf-8", "svg": "image/svg+xml", "woff2": "font/woff2",
                     "png": "image/png"}.get(name.rsplit(".", 1)[-1], "application/octet-stream")
            with open(path, "rb") as f:
                self._send(200, f.read(), ctype)

        def _page(self, ticker=None, depth=0, code=200):
            self._send(code, site.page(self.headers, ticker, depth), "text/html; charset=utf-8")

        def _api(self, method, parts, q, body):
            if parts == ["config"]:
                # qwen: the address forms of the Qwencoin this site follows, or null without a node of it.
                # They are Bitcoin's forms: one string is an address on both chains, so the page never
                # shows one without naming the chain.
                return {"btc": site.net("btc"), "qwen": site.net("qwen") if site.qwen is not None else None,
                        # btc_source: "electrum" when Bitcoin is read through Electrum servers (hashfun.btclight), not a node
                        "btc_source": "electrum" if is_light(site.btc) else "node",
                        "maker": bool(site.maker), "allow_launch": site.allow_launch and site.qwen is not None,
                        "btc_id": site.btc_id, "qwen_id": site.qwen_id, "pool": site.pools is not None,
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
            if parts == ["launch", "terms"]:
                return site.launch_terms(q)
            if parts == ["qwen"]:
                return site.qwen_view()
            if parts and parts[0] == "book":
                return site.book.api(method, parts[1:], q, body)
            if len(parts) >= 2 and parts[0] == "coin" and len(parts) == 2:
                out = site.coin(parts[1]).detail()
                if site.pools is not None:
                    out["pool"] = site.pools.info(parts[1])
                return out
            if len(parts) == 3 and parts[0] == "coin" and parts[2] == "queue" and method == "POST":
                if site.pools is None:
                    raise KeyError("this site does not mine")
                site.coin(parts[1])
                curve = str(body.get("curve", "btc"))
                if curve not in CURVES:
                    raise ValueError("curve: btc or qwen")
                if curve == "qwen" and site.qwen is None:
                    raise ValueError("this site has no Qwencoin node: it cannot see a QWEN-curve block's payment, so it "
                                     "does not mine that curve")
                return site.pools.enqueue(parts[1], str(body.get("address", "")), int(body.get("blocks", 1)), curve)
            if len(parts) == 3 and parts[0] == "coin" and parts[2] == "due":
                if site.pools is None:
                    raise KeyError("this site does not mine")
                c = site.coin(parts[1])
                script = address_to_script(q.get("address", ""), c.d.hrp).hex()
                return site.pools.due(parts[1], script)
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
                if parts[2] == "address" and chain in OUTSIDE:  # launches: /coin/T/address/A (the site's own index)
                    return site.outside_address(chain, site.outside_script(chain, parts[3]).hex())
            raise KeyError("no such endpoint")

        def _handle(self, method):
            u = urlparse(self.path)
            path = u.path
            # --base-path /fun: the site lives under a path of another server's domain. That server
            # may pass the prefix on or cut it off, so both spellings are served; the page itself
            # only ever asks for relative URLs. /fun without the slash would resolve them against /.
            base = site.base_path
            if base and path == base:
                self.send_response(301)
                self.send_header("Location", base + "/" + ("?" + u.query if u.query else ""))
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if base and path.startswith(base + "/"):
                path = path[len(base):]
            if path in ("/", "", "/index.html"):
                return self._page()
            # A coin at an address a crawler can fetch: the same page with that coin's preview tags.
            # The page itself then opens the coin (app.js: it moves to the fragment form).
            m = re.fullmatch(r"/c/([A-Za-z0-9]{2,10})(/?)", path)
            if m and method == "GET":
                t = m.group(1).upper()
                if m.group(2):  # one spelling per coin: the page's relative links count path segments
                    self.send_response(301)
                    self.send_header("Location", "../" + m.group(1))
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                known = t in site.coins and site.coins[t].info
                return self._page(t if known else None, depth=2, code=200 if known else 404)
            if not path.startswith("/api/"):
                return self._static(path.lstrip("/"))
            m = re.fullmatch(r"/api/coin/([A-Z0-9]{2,10})/image", path)
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
                self._json(200, self._api(method, [p for p in path[5:].split("/") if p], q, body))
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


class _OperatorMap(dict):
    """ticker -> the operator's address on that launch, worked out when first asked."""

    def __init__(self, addr_for_hrp, reg):
        super().__init__()
        self.addr_for_hrp, self.reg = addr_for_hrp, reg

    def get(self, ticker, default=None):
        try:
            return self.addr_for_hrp(self.reg.desc(ticker).hrp)
        except Exception:
            return default


def serve(site: Site, host: str, port: int) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), handler(site))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=site.run, daemon=True).start()
    threading.Thread(target=site.run_bids, daemon=True).start()
    if site.qwen_pages:
        threading.Thread(target=site.run_pockets, daemon=True).start()
    return srv


def main(argv=None):
    from .cli import Registry
    ap = argparse.ArgumentParser(prog="hashfun web", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--btc-rpc", required=True, help="Bitcoin Core RPC URL (reads, broadcasts, header anchor for new launches; "
                                                     "a registered launch is served only if its Bitcoin anchor is on this node's chain), "
                                                     "or electrums://HOST:PORT,HOST:PORT for Bitcoin through two Electrum servers and "
                                                     "no node here (hashfun/btclight.py)")
    ap.add_argument("--btc-cookie")
    ap.add_argument("--btc-electrum", metavar="HOST:PORT",
                    help="an Electrum-protocol index of the same Bitcoin chain (electrs, Fulcrum): Bitcoin balances "
                         "in milliseconds instead of a UTXO-set scan of about a minute each; the scan stays the fallback")
    ap.add_argument("--qwen-rpc", help="Qwencoin node RPC URL (qwencoind speaks bitcoin-cli's RPC): QWEN becomes a chain of "
                                       "the book, the QWEN curve can be mined from the page, and new launches get their "
                                       "Qwencoin anchor from it. Without it the site shows both curves and trades and "
                                       "mines only the Bitcoin side, and creates no launches")
    ap.add_argument("--qwen-cookie")
    ap.add_argument("--listen", default="127.0.0.1:8080")
    ap.add_argument("--base-path", default="", metavar="/PATH",
                    help="serve the whole site under this path as well (page, files, API), for a server that proxies "
                         "a path of its own domain here, e.g. --base-path /fun behind https://example.org/fun/")
    ap.add_argument("--public-url", default="", metavar="URL",
                    help="the address the world reaches this site at, e.g. https://example.org/fun: used for the absolute "
                         "links in link previews (default: built from each request's Host and X-Forwarded-Proto)")
    ap.add_argument("--qwen-pages", default="", metavar="URL",
                    help="the Qwencoin pages (their own site, e.g. http://127.0.0.1:8080 or https://aichat.fyi): how many "
                         "machines run a node and a model right now is read from its /graph/status.json once a minute")
    ap.add_argument("--pool", action="store_true",
                    help="mine here: a public stratum per launch (P2P port + 2), and the server's CPU mines a block "
                         "for each visitor who asks, on the curve they pick; whoever a block pays pays what it owes "
                         "(sats on Bitcoin, or QWEN on Qwencoin) from their own key")
    ap.add_argument("--pool-host", default="0.0.0.0")
    ap.add_argument("--pool-cpu", type=float, default=1.0, help="share of one core the CPU miner uses (0 = no CPU miner)")
    ap.add_argument("--operator-pubkey", help="compressed public key (hex) whose address on each launch gets --pool-cut-bps "
                                              "of the blocks the server mines for visitors")
    ap.add_argument("--pool-cut-bps", type=int, default=500)
    ap.add_argument("--maker", help="maker config JSON: run a swap maker in this process")
    ap.add_argument("--allow-launch", action="store_true", help="let the launch form create chains on this machine")
    ap.add_argument("--launch-arg", action="append", default=[], help="extra hashfund argument for chains created here")
    ap.add_argument("--book-confs", type=int, default=6,
                    help="peer-to-peer swaps: confirmations the page waits for on a launch chain (default 6; Bitcoin is 1)")
    ap.add_argument("--book-lock", type=int, default=14400,
                    help="peer-to-peer swaps: seconds the maker's lock lasts; the taker's lasts twice that (default 4 h)")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    from .btclight import connect, is_light, is_light_url
    btc = connect(a.btc_rpc) if is_light_url(a.btc_rpc) else RPC(a.btc_rpc, cookie_file=a.btc_cookie)
    qwen = RPC(a.qwen_rpc, cookie_file=a.qwen_cookie) if a.qwen_rpc else None
    reg = Registry()
    if a.maker and is_light(btc):
        raise SystemExit("--maker trades from a Bitcoin Core wallet: it needs --btc-rpc to be a Bitcoin node, not Electrum servers")
    maker = build_maker(a.maker, reg, btc) if a.maker else None
    from .cli import home
    site = Site(btc, reg, maker, a.allow_launch, a.launch_arg, book_path=os.path.join(home(), "book.json"),
                book_confs=a.book_confs, book_lock=a.book_lock,
                # (through Electrum servers the Bitcoin handle is itself the index of balances: it has unspent())
                btc_index=btc if is_light(btc) else BtcIndex(a.btc_electrum) if a.btc_electrum else None, qwen=qwen,
                base_path=a.base_path,
                public_url=a.public_url, qwen_pages=a.qwen_pages)
    if a.pool:
        from .sitepool import SitePools
        from .ser import p2wpkh_script, script_to_address
        ops = {}
        if a.operator_pubkey:
            pk = bytes.fromhex(a.operator_pubkey)
            if len(pk) != 33 or pk[0] not in (2, 3):
                raise SystemExit("--operator-pubkey must be a 33-byte compressed public key in hex")
            ops = _OperatorMap(lambda hrp: script_to_address(p2wpkh_script(pk), hrp), reg)
        site.pools = SitePools(site, operator=ops, cut_bps=a.pool_cut_bps if a.operator_pubkey else 0,
                               cpu=a.pool_cpu > 0, host=a.pool_host, duty=a.pool_cpu or 1.0)
    host, port = a.listen.rsplit(":", 1)
    serve(site, host, int(port))
    print(json.dumps({"site": f"http://{host}:{port}{site.base_path}/", "bitcoin": site.btc_chain, "qwencoin": site.qwen_chain,
                      "launches": sorted(reg.data), "maker": bool(maker),
                      "allow_launch": a.allow_launch and qwen is not None}), flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
