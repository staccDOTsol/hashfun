"""hashfun book: a peer-to-peer order book for atomic swaps between any two chains a site follows
(Bitcoin and every launch; they all run the same script engine, so one HTLC works on all of them).

The server side is a bulletin board and a mailbox, nothing more. Orders, takes and every later
message are signed by the page keys of the two traders; the swap contracts are built, checked
and funded in their browsers; no key and no coin ever comes here. What the board adds is what a
board needs: it refuses orders that are unsigned, not backed by coins, or from a maker who is not
online to honour them, and it keeps count of what is left of each order.

A swap, taker first:

  maker   posts an order     "I give 1,000 CAT, I want 50,000 sats" (any pair, either direction)
  taker   takes part of it   picks a secret, sends its hash and the timelock of its own lock
  maker   accepts            reserves that part of the order
  taker   locks              HTLC on the chain the maker wants, to the maker's key, refund at T
  maker   locks              HTLC on the chain it gives, to the taker's key, refund at T - lock
  taker   claims             reveals the secret on the maker's chain
  maker   claims             uses the revealed secret on the taker's chain

Either lock goes back to its owner after its timelock if the other side stops. The taker moves
first, so a maker is never out of pocket for an order nobody completes; a taker who locks for a
maker that then vanishes waits for the refund, which is why only live makers are listed.

Everything signed is a short text, so the browser (hashfun/web/src/book.js) and this file can
agree on it without a serializer:

  order   "hashfun-order-v1\\n" maker give give_amount get get_amount min_get expiry nonce lock confs
  take    "hashfun-take-v1\\n"  order taker get_amount secret_hash locktime ts
  note    "hashfun-fill-v1\\n"  fill kind, then key=value lines sorted by key
  alive   "hashfun-alive-v1\\n" maker ts
  cancel  "hashfun-cancel-v1\\n" order

one field per line; the signature is ECDSA (r || s, 64 bytes hex) over SHA256d of the text, by
the maker's or taker's key. Ids are the first 16 bytes of that hash. Chains are named "btc:<net>"
(btc:main, btc:regtest, ...) or by launch id, so an order cannot be replayed on another network
or against a different coin with the same ticker."""
import json
import os
import re
import secrets
import threading
import time
from typing import Callable, Dict, List, Optional

from .crypto import N, ecdsa_verify, parse_point, sha256d

MAX_AMOUNT = 21_000_000 * 100_000_000
MAX_EXPIRY = 7 * 86400
MAX_ORDERS_PER_MAKER = 50
MAX_ORDERS = 5000
LIVE_SECONDS = 20          # a maker not heard from for this long is not listed
REQUEST_SECONDS = 45       # a take the maker has not answered
SESSION_SECONDS = 600
KEEP_SECONDS = 86400       # finished fills stay readable this long

# Fill states. A take reserves part of an order from "accepted" until it ends one way or the other.
RESERVING = ("accepted", "taker_locked", "maker_locked")
FILLED = ("claimed", "done")
FINAL = ("done", "rejected", "released", "aborted", "expired", "failed")
# kind -> (who may send it, states it may be sent in, state it leads to, body keys)
NOTES = {
    "accept": ("maker", ("requested",), "accepted", ("until",)),
    "reject": ("maker", ("requested",), "rejected", ("why",)),
    "release": ("maker", ("accepted",), "released", ()),
    "fail": ("maker", ("taker_locked", "maker_locked"), "failed", ("why",)),  # would not lock, or took its lock back
    "locked": (None, None, None, ("contract", "txid", "vout")),  # both sides; see note()
    "claimed": ("taker", ("maker_locked",), "claimed", ("txid",)),
    "done": ("maker", ("maker_locked", "claimed"), "done", ()),
    "abort": ("taker", ("requested", "accepted"), "aborted", ()),
}
_HEX = re.compile(r"[0-9a-f]*")
_VALUE = re.compile(r"[0-9A-Za-z .,:_/-]{0,400}")


class BookError(ValueError):
    pass


def _hex(s, n: int, what: str) -> str:
    if not isinstance(s, str) or len(s) != 2 * n or not _HEX.fullmatch(s):
        raise BookError(f"{what}: expected {n} bytes of lowercase hex")
    return s


def _int(v, lo: int, hi: int, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise BookError(f"{what}: expected an integer in {lo}..{hi}")
    return v


def order_text(o: dict) -> str:
    return "\n".join(["hashfun-order-v1", o["maker"], o["give"], str(o["give_amount"]), o["get"], str(o["get_amount"]),
                      str(o["min_get"]), str(o["expiry"]), o["nonce"], str(o["lock"]), str(o["confs"])])


def take_text(t: dict) -> str:
    return "\n".join(["hashfun-take-v1", t["order"], t["taker"], str(t["get_amount"]), t["secret_hash"],
                      str(t["locktime"]), str(t["ts"])])


def note_text(fill: str, kind: str, body: dict) -> str:
    return "\n".join(["hashfun-fill-v1", fill, kind] + [f"{k}={body[k]}" for k in sorted(body)])


def alive_text(maker: str, ts: int) -> str:
    return f"hashfun-alive-v1\n{maker}\n{ts}"


def cancel_text(order: str) -> str:
    return f"hashfun-cancel-v1\n{order}"


def text_id(text: str) -> str:
    return sha256d(text.encode()).hex()[:32]


def verify(pub_hex: str, text: str, sig_hex) -> bool:
    try:
        _hex(sig_hex, 64, "sig")
        pub = bytes.fromhex(_hex(pub_hex, 33, "key"))
        parse_point(pub)
        r, s = int(sig_hex[:64], 16), int(sig_hex[64:], 16)
        return 0 < r < N and 0 < s < N and ecdsa_verify(pub, sha256d(text.encode()), r, s)
    except (ValueError, TypeError, AssertionError):
        return False


def give_for(o: dict, get_amount: int) -> int:
    """What a taker paying get_amount receives: pro rata, rounded down (the maker never gives
    more per unit than its order says)."""
    return o["give_amount"] * get_amount // o["get_amount"]


class Book:
    """chains(): {chain id: display ticker} of the chains this site follows.
    backing(chain id, maker pub hex): spendable balance of the maker's key on that chain, or None
    while the site does not know yet (sats on Bitcoin take a UTXO-set scan, which the site runs in
    the background: an offer waits, unlisted, until its backing has been seen)."""

    def __init__(self, chains: Callable[[], Dict[str, str]], backing: Callable[[str, str], Optional[int]],
                 path: Optional[str] = None, now: Callable[[], float] = time.time, min_lock: int = 600):
        self.chains, self.backing, self.path, self.now = chains, backing, path, now
        self.min_lock = min_lock  # shortest second lock an order may ask for (lower only on test chains)
        self.orders: Dict[str, dict] = {}
        self.fills: Dict[str, dict] = {}
        self.seen: Dict[str, float] = {}
        self.sessions: Dict[str, tuple] = {}
        self.lock = threading.RLock()
        self.dirty = False
        if path and os.path.exists(path):
            try:
                with open(path) as f:
                    saved = json.load(f)
                self.orders, self.fills = saved.get("orders", {}), saved.get("fills", {})
            except (OSError, ValueError):
                pass

    # ------------------------------------------------------------ storage
    def save(self):
        with self.lock:
            if not self.path or not self.dirty:
                return
            self.dirty = False
            data = json.dumps({"orders": self.orders, "fills": self.fills})
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            f.write(data)
        os.replace(tmp, self.path)

    # ------------------------------------------------------------ orders
    def used(self, oid: str) -> int:
        return sum(f["give_amount"] for f in self.fills.values()
                   if f["order"] == oid and f["state"] in RESERVING + FILLED)

    def remaining(self, o: dict) -> int:
        return o["give_amount"] - self.used(o["id"])

    def remaining_get(self, o: dict) -> int:
        """What is left, in the units the maker wants: the largest take that still fits."""
        left = self.remaining(o)
        return 0 if left <= 0 else left * o["get_amount"] // o["give_amount"]

    def open(self, o: dict) -> bool:
        if o.get("cancelled") or o["expiry"] <= self.now():
            return False
        left = self.remaining_get(o)
        return left >= o["min_get"] and give_for(o, left) > 0

    def live(self, maker: str) -> bool:
        return self.now() - self.seen.get(maker, 0) <= LIVE_SECONDS

    def backed(self, o: dict) -> bool:
        have = self.backing(o["give"], o["maker"])
        if have is None:
            return False  # not checked yet: nobody is shown an offer the site has not seen coins behind
        need = sum(self.remaining(x) for x in self.orders.values()
                   if x["maker"] == o["maker"] and x["give"] == o["give"] and self.open(x))
        return have >= need

    def public(self, o: dict) -> dict:
        names = self.chains()
        left = self.remaining(o)
        return {**o, "remaining": left, "remaining_get": self.remaining_get(o), "backed": self.backed(o),
                "give_ticker": names.get(o["give"], "?"), "get_ticker": names.get(o["get"], "?"),
                "open": self.open(o), "live": self.live(o["maker"])}

    def view(self, give: Optional[str] = None, get: Optional[str] = None, maker: Optional[str] = None) -> List[dict]:
        """Open orders. With maker=: all of that maker's open orders (its own page wants to see
        them whether or not it is counted as live); otherwise only what a taker can act on."""
        with self.lock:
            self.sweep()
            names = self.chains()
            out = []
            for o in self.orders.values():
                if not self.open(o) or o["give"] not in names or o["get"] not in names:
                    continue
                if maker is not None:
                    if o["maker"] != maker:
                        continue
                elif not self.live(o["maker"]) or not self.backed(o):
                    continue
                if (give and o["give"] != give) or (get and o["get"] != get):
                    continue
                out.append(self.public(o))
            return sorted(out, key=lambda o: o["get_amount"] / o["give_amount"])

    def post(self, o: dict) -> dict:
        if not isinstance(o, dict):
            raise BookError("order: expected an object")
        names = self.chains()
        clean = {
            "maker": _hex(o.get("maker"), 33, "maker"),
            "give": o.get("give"), "give_amount": _int(o.get("give_amount"), 1, MAX_AMOUNT, "give_amount"),
            "get": o.get("get"), "get_amount": _int(o.get("get_amount"), 1, MAX_AMOUNT, "get_amount"),
            "min_get": _int(o.get("min_get"), 1, MAX_AMOUNT, "min_get"),
            "expiry": _int(o.get("expiry"), 0, 2**32 - 1, "expiry"),
            "nonce": _hex(o.get("nonce"), 8, "nonce"),
            "lock": _int(o.get("lock"), self.min_lock, 86400, "lock"), "confs": _int(o.get("confs"), 0, 100, "confs"),
        }
        if clean["give"] not in names or clean["get"] not in names:
            raise BookError("this site does not follow one of those chains")
        if clean["give"] == clean["get"]:
            raise BookError("an order swaps between two different chains")
        if clean["min_get"] > clean["get_amount"]:
            raise BookError("min_get: larger than the order")
        now = self.now()
        if not now < clean["expiry"] <= now + MAX_EXPIRY:
            raise BookError("expiry: within the next 7 days")
        text = order_text(clean)
        if not verify(clean["maker"], text, o.get("sig")):
            raise BookError("order signature does not verify")
        clean["sig"], clean["id"], clean["created"] = o["sig"], text_id(text), int(now)
        with self.lock:
            if clean["id"] in self.orders:
                return self.public(self.orders[clean["id"]])
            mine = [x for x in self.orders.values() if x["maker"] == clean["maker"] and self.open(x)]
            if len(mine) >= MAX_ORDERS_PER_MAKER or len(self.orders) >= MAX_ORDERS:
                raise BookError("too many open orders")
            have = self.backing(clean["give"], clean["maker"])
            if have is not None and have < clean["give_amount"] + sum(self.remaining(x) for x in mine if x["give"] == clean["give"]):
                raise BookError(f"not enough spendable {names[clean['give']]} behind this order (and your other open orders)")
            self.orders[clean["id"]] = clean
            self.seen[clean["maker"]] = now
            self.dirty = True
            return self.public(clean)

    def cancel(self, body: dict) -> dict:
        with self.lock:
            o = self.orders.get(body.get("order"))
            if not o:
                raise KeyError("order not found")
            if not verify(o["maker"], cancel_text(o["id"]), body.get("sig")):
                raise BookError("cancel signature does not verify")
            o["cancelled"] = True
            self.dirty = True
            return self.public(o)

    # ------------------------------------------------------------ liveness
    def alive(self, body: dict) -> dict:
        """A maker's heartbeat: signed once, then a session token. Returns the fills waiting on it."""
        maker, now = _hex(body.get("maker"), 33, "maker"), self.now()
        with self.lock:
            token = body.get("session")
            sess = self.sessions.get(maker)
            if not (token and sess and secrets.compare_digest(str(token), sess[0]) and sess[1] > now):
                ts = body.get("ts")
                if isinstance(ts, bool) or not isinstance(ts, int) or abs(ts - now) > 300 or \
                        not verify(maker, alive_text(maker, ts), body.get("sig")):
                    raise BookError("sign in again")
                token = secrets.token_hex(16)
                self.sessions[maker] = (token, now + SESSION_SECONDS)
            self.seen[maker] = now
            self.sweep()
            inbox = [self.fill_view(f) for f in self.fills.values()
                     if f["maker"] == maker and f["state"] not in FINAL]
            return {"session": token, "fills": inbox, "now": int(now)}

    # ------------------------------------------------------------ fills
    def fill_view(self, f: dict) -> dict:
        return {**f, "order_data": self.orders.get(f["order"])}

    def sweep(self):
        """Time out takes nobody answered and reservations nobody used; forget old history."""
        now = self.now()
        for f in list(self.fills.values()):
            if f["state"] in FINAL:
                if now - f.get("updated", f["created"]) > KEEP_SECONDS:
                    del self.fills[f["id"]]
                    self.dirty = True
                continue
            if (f["state"] == "requested" and now - f["created"] > REQUEST_SECONDS) or \
                    (f["state"] == "accepted" and now > f.get("until", 0) + 30) or \
                    (f["state"] in RESERVING and now > f["locktime"] + KEEP_SECONDS):  # both timelocks long past
                f["state"], f["updated"], self.dirty = "expired", int(now), True
        busy = {f["order"] for f in self.fills.values()}
        for o in list(self.orders.values()):
            if o["id"] not in busy and (o.get("cancelled") or o["expiry"] + 3600 < now):
                del self.orders[o["id"]]
                self.dirty = True

    def take(self, t: dict) -> dict:
        if not isinstance(t, dict):
            raise BookError("take: expected an object")
        clean = {"order": _hex(t.get("order"), 16, "order"), "taker": _hex(t.get("taker"), 33, "taker"),
                 "get_amount": _int(t.get("get_amount"), 1, MAX_AMOUNT, "get_amount"),
                 "secret_hash": _hex(t.get("secret_hash"), 32, "secret_hash"),
                 "locktime": _int(t.get("locktime"), 500_000_000, 2**32 - 1, "locktime"),
                 "ts": _int(t.get("ts"), 0, 2**32 - 1, "ts")}
        text = take_text(clean)
        if not verify(clean["taker"], text, t.get("sig")):
            raise BookError("take signature does not verify")
        now = self.now()
        with self.lock:
            self.sweep()
            o = self.orders.get(clean["order"])
            if not o or not self.open(o):
                raise BookError("that order is gone")
            if not self.live(o["maker"]):
                raise BookError("the maker of that order is offline")
            if not self.backed(o):
                raise BookError("that order is gone: the coins behind it are not there (or not checked yet)")
            if clean["taker"] == o["maker"]:
                raise BookError("that is your own order")
            if abs(clean["ts"] - now) > 300:
                raise BookError("ts: check your clock")
            if not o["min_get"] <= clean["get_amount"] <= self.remaining_get(o):
                raise BookError(f"take between {o['min_get']} and {self.remaining_get(o)}")
            give = give_for(o, clean["get_amount"])
            if give <= 0:
                raise BookError("too small to buy anything at this price")
            if clean["locktime"] < now + 2 * o["lock"]:
                raise BookError("locktime: at least twice the order's lock from now")
            fid = text_id(text)
            if fid in self.fills:
                return self.fill_view(self.fills[fid])
            if any(f["secret_hash"] == clean["secret_hash"] for f in self.fills.values()):
                raise BookError("that secret hash was used before")
            f = {**clean, "id": fid, "sig": t["sig"], "maker": o["maker"], "give_amount": give, "state": "requested",
                 "created": int(now), "updated": int(now), "notes": []}
            self.fills[fid] = f
            self.dirty = True
            return self.fill_view(f)

    def fill(self, fid: str) -> dict:
        with self.lock:
            self.sweep()
            f = self.fills.get(fid)
            if not f:
                raise KeyError("fill not found")
            return self.fill_view(f)

    def note(self, fid: str, m: dict) -> dict:
        """Append one signed message to a fill and move its state."""
        if not isinstance(m, dict) or m.get("kind") not in NOTES:
            raise BookError("unknown message")
        kind, body = m["kind"], m.get("body") or {}
        who, states, nxt, keys = NOTES[kind]
        if not isinstance(body, dict) or sorted(body) != sorted(keys):
            raise BookError(f"{kind}: expected {', '.join(keys) or 'no fields'}")
        for k, v in body.items():
            if isinstance(v, bool) or not isinstance(v, (int, str)) or (isinstance(v, str) and not _VALUE.fullmatch(v)):
                raise BookError(f"{k}: not allowed")
        with self.lock:
            self.sweep()
            f = self.fills.get(fid)
            if not f:
                raise KeyError("fill not found")
            sender = m.get("from")
            role = "maker" if sender == f["maker"] else "taker" if sender == f["taker"] else None
            if kind == "locked" and role:
                who, states, nxt = role, (("accepted",) if role == "taker" else ("taker_locked",)), role + "_locked"
            if role is None or role != who:
                raise BookError("not yours to send")
            if not verify(sender, note_text(fid, kind, body), m.get("sig")):
                raise BookError("message signature does not verify")
            if any(n["kind"] == kind and n["from"] == sender for n in f["notes"]):
                return self.fill_view(f)  # a retry of something already recorded
            if f["state"] not in states:
                raise BookError(f"{kind}: not possible while the swap is {f['state'].replace('_', ' ')}")
            now = self.now()
            if kind == "accept":
                until = _int(body["until"], 0, 2**32 - 1, "until")
                if not now < until <= now + 900:
                    raise BookError("until: within the next 15 minutes")
                o = self.orders.get(f["order"])
                if not o or self.remaining(o) < f["give_amount"]:
                    raise BookError("the order no longer covers this take")
                f["until"] = until
            f["notes"].append({"from": sender, "kind": kind, "body": body, "sig": m["sig"], "ts": int(now)})
            f["state"], f["updated"] = nxt, int(now)
            self.seen[f["maker"]] = now if role == "maker" else self.seen.get(f["maker"], 0)
            self.dirty = True
            return self.fill_view(f)

    # ------------------------------------------------------------ http
    def api(self, method: str, parts: List[str], q: dict, body) -> object:
        if not parts and method == "GET":
            return {"orders": self.view(q.get("give"), q.get("get"), q.get("maker")), "now": int(self.now())}
        if parts == ["order"] and method == "POST":
            return self.post(body)
        if parts == ["cancel"] and method == "POST":
            return self.cancel(body)
        if parts == ["alive"] and method == "POST":
            return self.alive(body)
        if parts == ["take"] and method == "POST":
            return self.take(body)
        if len(parts) == 2 and parts[0] == "fill":
            return self.note(parts[1], body) if method == "POST" else self.fill(parts[1])
        raise KeyError("no such endpoint")
