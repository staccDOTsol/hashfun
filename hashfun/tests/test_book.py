"""Launch metadata (meta.py), the peer-to-peer order book's server side (book.py), and the site
(web.py) over stand-in nodes: its API, what it serves to link previews, and the page itself in a
real browser (PageTest, when Playwright is installed). The suites against real nodes are
web_regtest, book_regtest and sitepool_regtest."""
import struct
import unittest
import zlib

from hashfun import book as K
from hashfun import descriptor as D
from hashfun import meta as M
from hashfun.crypto import ecdsa_sign, pubkey_from_priv, sha256, sha256d


def png(w=2, h=2, rgb=b"\xff\x9a\x1f") -> bytes:
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    raw = b"".join(b"\x00" + rgb * w for _ in range(h))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + \
        chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def sign(priv: int, text: str) -> str:
    r, s = ecdsa_sign(priv, sha256d(text.encode()))
    return f"{r:064x}{s:064x}"


def pub(priv: int) -> str:
    return pubkey_from_priv(priv).hex()


class MetaTest(unittest.TestCase):
    def launch(self, **kw):
        return D.make("Rig Cat", "RIGCAT", bytes.fromhex("0014" + "11" * 20), 10**10, test=True, genesis_time=1_700_000_000, **kw)

    def test_meta_changes_the_id_and_only_when_set(self):
        plain = self.launch()
        m = M.from_image(png(), description="the rig cat", x="https://x.com/rigcat")
        with_meta = self.launch(metadata=m)
        self.assertNotEqual(plain.id, with_meta.id)
        self.assertEqual(with_meta.meta, m.hash())
        self.assertEqual(with_meta.canonical_bytes(), plain.canonical_bytes() + m.hash())
        self.assertEqual(self.launch(metadata=M.Meta()).id, plain.id)  # nothing to commit to
        # another picture, another launch id (so another genesis block and another chain)
        self.assertNotEqual(self.launch(metadata=M.from_image(png(rgb=b"\xc7\xf2\x3e"), description="the rig cat")).id, with_meta.id)
        self.assertNotEqual(with_meta.genesis_coinbase().txid(), plain.genesis_coinbase().txid())

    def test_round_trip_and_check(self):
        m = M.from_image(png(), description="line one\nline two", website="https://rigcat.example/a?b=1", telegram="https://t.me/rigcat")
        d = D.parse(self.launch(metadata=m).dumps())
        got = M.check(d)
        self.assertEqual((got.description, got.image, got.image_type, got.website, got.telegram, got.x),
                         (m.description, m.image, "image/png", m.website, m.telegram, ""))
        self.assertIsNone(M.check(self.launch()))
        d.metadata = None  # the launch commits to a picture this file does not carry: nothing to show
        self.assertIsNone(M.check(d))

    def test_swapped_bytes_are_refused(self):
        d = D.parse(self.launch(metadata=M.from_image(png(), description="real")).dumps())
        for k, v in (("description", "fake"), ("image", M.Meta(image=png(rgb=b"\0\0\0")).to_json()["image"]), ("x", "https://x.com/evil")):
            bad = D.parse(d.dumps())
            bad.metadata[k] = v
            with self.assertRaises(M.MetaError, msg=k):
                M.check(bad)
        stray = self.launch()
        stray.metadata = {"description": "not committed"}
        with self.assertRaises(M.MetaError):
            M.check(stray)

    def test_validation(self):
        ok = dict(description="x")
        for bad in (dict(image=b"<svg xmlns='http://www.w3.org/2000/svg'/>", image_type="image/svg+xml"),
                    dict(image=png(), image_type="image/jpeg"), dict(image=b"", image_type="image/png"),
                    dict(image=png() + bytes(M.MAX_IMAGE), image_type="image/png"), dict(description="x" * 501),
                    dict(description="a\x00b"), dict(website="http://plain.example"), dict(x="javascript:alert(1)"),
                    dict(telegram="https://t.me/a b"), dict(website="https://" + "a" * 200), dict(x='https://x.com/"><script>')):
            with self.assertRaises(M.MetaError, msg=str(bad)[:60]):
                M.Meta(**{**ok, **bad}).validate()
        for kind, head in (("image/jpeg", b"\xff\xd8\xff\xe0" + bytes(20)), ("image/gif", b"GIF89a" + bytes(20)),
                           ("image/webp", b"RIFF\x10\0\0\0WEBPVP8 " + bytes(8)), ("image/png", png())):
            self.assertEqual(M.image_type_of(head), kind)
            M.from_image(head).validate()
        for o in ({"image": "@@@"}, {"image": 5}, {"description": 1}, [], "x"):
            with self.assertRaises(M.MetaError, msg=str(o)):
                M.Meta.from_json(o)

    def test_canonical_bytes(self):
        m = M.Meta(description="hi", image_type="image/png", image=b"\x89PNG\r\n\x1a\n", website="https://a.b", x="", telegram="")
        want = b"hashfun-meta\x01" + b"\x02hi" + b"\x09image/png" + b"\x08\x89PNG\r\n\x1a\n" + b"\x0bhttps://a.b" + b"\x00" + b"\x00"
        self.assertEqual(m.canonical(), want)
        self.assertEqual(m.hash(), sha256(want))


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


class BookTest(unittest.TestCase):
    A, B, BTC = "aa" * 32, "bb" * 32, "btc:regtest"
    MAKER, TAKER, OTHER = 0x1111, 0x2222, 0x3333

    def setUp(self):
        self.clock = Clock()
        self.balances = {(self.A, pub(self.MAKER)): 1000 * D.COIN, (self.B, pub(self.TAKER)): 500 * D.COIN}
        # sats behind a key are known only once the site has scanned for them: None until then
        self.sats = {}
        self.book = K.Book(lambda: {self.BTC: "BTC", self.A: "CAT", self.B: "DOG"},
                           lambda chain, maker: self.sats.get(maker) if chain == self.BTC else self.balances.get((chain, maker), 0),
                           now=self.clock)

    def order(self, priv=None, **kw):
        priv = priv or self.MAKER
        o = {"maker": pub(priv), "give": self.A, "give_amount": 100 * D.COIN, "get": self.BTC, "get_amount": 50_000,
             "min_get": 5_000, "expiry": int(self.clock.t) + 3600, "nonce": "0102030405060708", "lock": 3600, "confs": 1}
        o.update(kw)
        o["sig"] = sign(priv, K.order_text(o))
        return o

    def take(self, o, amount, priv=None, **kw):
        priv = priv or self.TAKER
        t = {"order": o["id"], "taker": pub(priv), "get_amount": amount, "secret_hash": sha256(bytes([len(self.book.fills)]) * 4).hex(),
             "locktime": int(self.clock.t) + 2 * o["lock"] + 600, "ts": int(self.clock.t)}
        t.update(kw)
        t["sig"] = sign(priv, K.take_text(t))
        return t

    def note(self, fid, priv, kind, **body):
        return self.book.note(fid, {"from": pub(priv), "kind": kind, "body": body, "sig": sign(priv, K.note_text(fid, kind, body))})

    def alive(self, priv=None):
        priv = priv or self.MAKER
        ts = int(self.clock.t)
        return self.book.alive({"maker": pub(priv), "ts": ts, "sig": sign(priv, K.alive_text(pub(priv), ts))})

    def test_order_must_be_signed_backed_and_sane(self):
        o = self.book.post(self.order())
        self.assertEqual((o["remaining"], o["remaining_get"], o["give_ticker"], o["get_ticker"]), (100 * D.COIN, 50_000, "CAT", "BTC"))
        self.assertEqual(self.book.post(self.order())["id"], o["id"])  # the same order again is the same order
        bad = self.order(nonce="0000000000000001")
        bad["give_amount"] += 1  # changed after signing
        with self.assertRaisesRegex(K.BookError, "signature"):
            self.book.post(bad)
        forged = self.order(nonce="0000000000000002")
        forged["sig"] = sign(self.OTHER, K.order_text(forged))
        with self.assertRaisesRegex(K.BookError, "signature"):
            self.book.post(forged)
        with self.assertRaisesRegex(K.BookError, "not enough spendable CAT"):
            self.book.post(self.order(nonce="0000000000000003", give_amount=950 * D.COIN))  # 100 already offered
        with self.assertRaisesRegex(K.BookError, "not enough spendable CAT"):
            self.book.post(self.order(priv=self.OTHER))  # holds none
        for kw, msg in ((dict(get=self.A), "two different chains"), (dict(give="cc" * 32), "does not follow"),
                        (dict(expiry=int(self.clock.t) - 1), "expiry"), (dict(expiry=int(self.clock.t) + 8 * 86400), "expiry"),
                        (dict(min_get=50_001), "min_get"), (dict(lock=599), "lock"), (dict(give_amount=0), "give_amount"),
                        (dict(give_amount=True), "give_amount"), (dict(nonce="xyz"), "nonce"), (dict(confs=101), "confs")):
            with self.assertRaisesRegex(K.BookError, msg, msg=str(kw)):
                self.book.post(self.order(**kw))
        # sats behind a bid take a scan: the bid is accepted, and listed only once the sats have been seen
        bid = self.book.post(self.order(priv=self.OTHER, give=self.BTC, get=self.A, give_amount=50_000, get_amount=100 * D.COIN,
                                        min_get=D.COIN))
        listed = lambda: [x["id"] for x in self.book.view(give=self.BTC)]  # noqa: E731
        self.assertEqual((bid["backed"], listed()), (False, []))
        self.assertEqual([x["id"] for x in self.book.view(maker=pub(self.OTHER))], [bid["id"]])  # its maker sees it waiting
        with self.assertRaisesRegex(K.BookError, "offline|gone"):
            self.book.take(self.take(bid, D.COIN))  # and nobody can take what is not listed
        self.sats[pub(self.OTHER)] = 49_999
        self.assertEqual(listed(), [])
        self.sats[pub(self.OTHER)] = 50_000
        self.assertEqual(listed(), [bid["id"]])
        with self.assertRaisesRegex(K.BookError, "not enough spendable BTC"):   # the same sats twice
            self.book.post(self.order(priv=self.OTHER, give=self.BTC, get=self.A, give_amount=1, get_amount=D.COIN,
                                      min_get=D.COIN, nonce="00000000000000cc"))

    def test_only_live_backed_open_orders_are_listed(self):
        o = self.book.post(self.order())
        self.assertEqual([x["id"] for x in self.book.view()], [o["id"]])
        self.clock.t += K.LIVE_SECONDS + 1
        self.assertEqual(self.book.view(), [])                                   # the maker's page went quiet
        self.assertEqual([x["id"] for x in self.book.view(maker=pub(self.MAKER))], [o["id"]])  # its own page still sees it
        self.alive()
        self.assertEqual(len(self.book.view()), 1)
        self.balances[(self.A, pub(self.MAKER))] = 99 * D.COIN                   # the coins behind it moved away
        self.assertEqual(self.book.view(), [])
        self.balances[(self.A, pub(self.MAKER))] = 1000 * D.COIN
        self.assertEqual(len(self.book.view(give=self.A, get=self.BTC)), 1)
        self.assertEqual(self.book.view(give=self.BTC), [])
        with self.assertRaisesRegex(K.BookError, "signature"):
            self.book.cancel({"order": o["id"], "sig": sign(self.OTHER, K.cancel_text(o["id"]))})
        self.book.cancel({"order": o["id"], "sig": sign(self.MAKER, K.cancel_text(o["id"]))})
        self.assertEqual(self.book.view(maker=pub(self.MAKER)), [])
        cheap = self.book.post(self.order(nonce="00000000000000aa", get_amount=40_000))
        dear = self.book.post(self.order(nonce="00000000000000bb", get_amount=60_000))
        self.assertEqual([x["id"] for x in self.book.view()], [cheap["id"], dear["id"]])   # best price first
        self.clock.t += 3601
        self.alive()
        self.assertEqual(self.book.view(), [])                                   # expired

    def test_heartbeat_needs_the_key_then_a_session(self):
        self.book.post(self.order())
        with self.assertRaisesRegex(K.BookError, "sign in"):
            self.book.alive({"maker": pub(self.MAKER), "ts": int(self.clock.t), "sig": sign(self.OTHER, K.alive_text(pub(self.MAKER), int(self.clock.t)))})
        with self.assertRaisesRegex(K.BookError, "sign in"):
            self.book.alive({"maker": pub(self.MAKER), "session": "guess"})
        s = self.alive()["session"]
        self.clock.t += 5
        self.assertEqual(self.book.alive({"maker": pub(self.MAKER), "session": s})["session"], s)
        self.clock.t += K.SESSION_SECONDS + 1
        with self.assertRaisesRegex(K.BookError, "sign in"):
            self.book.alive({"maker": pub(self.MAKER), "session": s})
        old = int(self.clock.t) - 301
        with self.assertRaisesRegex(K.BookError, "sign in"):  # a replayed old heartbeat
            self.book.alive({"maker": pub(self.MAKER), "ts": old, "sig": sign(self.MAKER, K.alive_text(pub(self.MAKER), old))})

    def test_a_swap_from_take_to_done(self):
        o = self.book.post(self.order())
        f = self.book.take(self.take(o, 20_000))
        self.assertEqual((f["state"], f["give_amount"], f["maker"]), ("requested", 40 * D.COIN, pub(self.MAKER)))
        self.assertEqual(self.book.view()[0]["remaining"], 100 * D.COIN)          # a request reserves nothing yet
        self.assertEqual([x["id"] for x in self.alive()["fills"]], [f["id"]])       # the maker's page hears of it
        with self.assertRaisesRegex(K.BookError, "not yours"):
            self.note(f["id"], self.TAKER, "accept", until=int(self.clock.t) + 60)
        with self.assertRaisesRegex(K.BookError, "not yours"):
            self.note(f["id"], self.OTHER, "abort")
        with self.assertRaisesRegex(K.BookError, "not possible"):
            self.note(f["id"], self.TAKER, "locked", contract="6382", txid="11" * 32, vout=0)
        self.note(f["id"], self.MAKER, "accept", until=int(self.clock.t) + 120)
        v = self.book.view()[0]
        self.assertEqual((v["remaining"], v["remaining_get"]), (60 * D.COIN, 30_000))
        self.assertEqual(self.note(f["id"], self.TAKER, "locked", contract="6382", txid="11" * 32, vout=1)["state"], "taker_locked")
        self.assertEqual(self.note(f["id"], self.TAKER, "locked", contract="6382", txid="11" * 32, vout=1)["state"], "taker_locked")  # a retry
        with self.assertRaisesRegex(K.BookError, "not possible"):
            self.note(f["id"], self.MAKER, "done")
        self.assertEqual(self.note(f["id"], self.MAKER, "locked", contract="6382", txid="22" * 32, vout=0)["state"], "maker_locked")
        self.assertEqual(self.note(f["id"], self.TAKER, "claimed", txid="33" * 32)["state"], "claimed")
        got = self.note(f["id"], self.MAKER, "done")
        self.assertEqual(got["state"], "done")
        self.assertEqual([n["kind"] for n in got["notes"]], ["accept", "locked", "locked", "claimed", "done"])
        self.assertTrue(all(K.verify(n["from"], K.note_text(f["id"], n["kind"], n["body"]), n["sig"]) for n in got["notes"]))
        self.assertEqual(got["order_data"]["id"], o["id"])
        self.assertEqual(self.book.view()[0]["remaining"], 60 * D.COIN)           # filled for good
        self.assertEqual(self.alive()["fills"], [])
        # the rest in two more takes; the order closes when what is left is below its minimum
        f2 = self.book.take(self.take(o, 26_000))
        self.note(f2["id"], self.MAKER, "accept", until=int(self.clock.t) + 120)
        self.assertEqual(self.book.view(), [])                                   # 4,000 left < min 5,000
        with self.assertRaisesRegex(K.BookError, "gone"):
            self.book.take(self.take(o, 4_000))

    def test_takes_are_checked(self):
        o = self.book.post(self.order())
        for kw, msg in ((dict(get_amount=4_999), "take between"), (dict(get_amount=50_001), "take between"),
                        (dict(locktime=int(self.clock.t) + 7199), "locktime"), (dict(ts=int(self.clock.t) - 400), "clock"),
                        (dict(secret_hash="zz"), "secret_hash"), (dict(order="00" * 16), "gone")):
            t = self.take(o, kw.pop("get_amount", 10_000), **kw)
            with self.assertRaisesRegex(K.BookError, msg, msg=msg):
                self.book.take(t)
        with self.assertRaisesRegex(K.BookError, "own order"):
            self.book.take(self.take(o, 10_000, priv=self.MAKER))
        t = self.take(o, 10_000)
        t["get_amount"] = 20_000  # changed after signing
        with self.assertRaisesRegex(K.BookError, "signature"):
            self.book.take(t)
        first = self.book.take(self.take(o, 10_000))
        with self.assertRaisesRegex(K.BookError, "used before"):
            self.book.take(self.take(o, 10_000, priv=self.OTHER, secret_hash=first["secret_hash"]))
        self.clock.t += K.LIVE_SECONDS + 1
        with self.assertRaisesRegex(K.BookError, "offline"):
            self.book.take(self.take(o, 10_000, priv=self.OTHER))

    def test_reservations_end(self):
        o = self.book.post(self.order())
        left = lambda: self.book.public(self.book.orders[o["id"]])["remaining"]
        a = self.book.take(self.take(o, 20_000))
        self.clock.t += K.REQUEST_SECONDS + 1                                    # the maker never answered
        self.alive()
        self.assertEqual(self.book.fill(a["id"])["state"], "expired")
        b = self.book.take(self.take(o, 20_000))
        self.note(b["id"], self.MAKER, "accept", until=int(self.clock.t) + 60)
        self.assertEqual(left(), 60 * D.COIN)
        self.clock.t += 91                                                       # the taker never locked
        self.alive()
        self.assertEqual((self.book.fill(b["id"])["state"], left()), ("expired", 100 * D.COIN))
        with self.assertRaisesRegex(K.BookError, "not possible"):
            self.note(b["id"], self.TAKER, "locked", contract="6382", txid="11" * 32, vout=0)
        for end, who in (("reject", self.MAKER), ("abort", self.TAKER)):
            c = self.book.take(self.take(o, 20_000))
            self.note(c["id"], who, end, **({"why": "no"} if end == "reject" else {}))
            self.assertEqual(left(), 100 * D.COIN)
        d = self.book.take(self.take(o, 20_000))
        self.note(d["id"], self.MAKER, "accept", until=int(self.clock.t) + 60)
        self.note(d["id"], self.MAKER, "release")
        self.assertEqual(left(), 100 * D.COIN)
        e = self.book.take(self.take(o, 20_000))
        self.note(e["id"], self.MAKER, "accept", until=int(self.clock.t) + 60)
        self.note(e["id"], self.TAKER, "locked", contract="6382", txid="11" * 32, vout=0)
        self.assertEqual(self.note(e["id"], self.MAKER, "fail", why="too late")["state"], "failed")
        self.assertEqual(left(), 100 * D.COIN)
        # the maker locked, the taker never claimed, the maker took its lock back
        g = self.book.take(self.take(o, 20_000))
        self.note(g["id"], self.MAKER, "accept", until=int(self.clock.t) + 60)
        self.note(g["id"], self.TAKER, "locked", contract="6382", txid="11" * 32, vout=0)
        self.note(g["id"], self.MAKER, "locked", contract="6382", txid="22" * 32, vout=0)
        self.assertEqual(left(), 60 * D.COIN)
        self.assertEqual(self.note(g["id"], self.MAKER, "fail", why="refunded")["state"], "failed")
        self.assertEqual(left(), 100 * D.COIN)
        # a maker whose browser died mid-swap does not hold part of its offer forever
        h = self.book.take(self.take(o, 20_000))
        self.note(h["id"], self.MAKER, "accept", until=int(self.clock.t) + 60)
        self.note(h["id"], self.TAKER, "locked", contract="6382", txid="33" * 32, vout=0)
        expiry = self.book.orders[o["id"]]["expiry"]
        self.book.orders[o["id"]]["expiry"] = int(self.clock.t) + 10 * 86400  # keep the order itself alive for this check
        self.clock.t = h["locktime"] + K.KEEP_SECONDS + 1
        self.alive()
        self.assertEqual((self.book.fill(h["id"])["state"], left()), ("expired", 100 * D.COIN))
        self.clock.t = h["created"]
        self.book.orders[o["id"]]["expiry"] = expiry
        self.alive()
        # two takers cannot both be promised the same coins
        x = self.book.take(self.take(o, 30_000))
        y = self.book.take(self.take(o, 30_000, priv=self.OTHER))
        self.note(x["id"], self.MAKER, "accept", until=int(self.clock.t) + 60)
        with self.assertRaisesRegex(K.BookError, "no longer covers"):
            self.note(y["id"], self.MAKER, "accept", until=int(self.clock.t) + 60)

    def test_messages_are_checked(self):
        o = self.book.post(self.order())
        f = self.book.take(self.take(o, 20_000))
        for m, msg in (({"from": pub(self.MAKER), "kind": "steal", "body": {}}, "unknown"),
                       ({"from": pub(self.MAKER), "kind": "accept", "body": {}}, "expected until"),
                       ({"from": pub(self.MAKER), "kind": "accept", "body": {"until": 1, "x": 2}}, "expected until"),
                       ({"from": pub(self.MAKER), "kind": "reject", "body": {"why": "line\nbreak"}}, "not allowed"),
                       ({"from": pub(self.MAKER), "kind": "reject", "body": {"why": ["a"]}}, "not allowed")):
            with self.assertRaisesRegex(K.BookError, msg, msg=msg):
                self.book.note(f["id"], {**m, "sig": "00" * 64})
        with self.assertRaisesRegex(K.BookError, "signature"):
            self.book.note(f["id"], {"from": pub(self.MAKER), "kind": "accept", "body": {"until": int(self.clock.t) + 60},
                                     "sig": sign(self.OTHER, K.note_text(f["id"], "accept", {"until": int(self.clock.t) + 60}))})
        with self.assertRaisesRegex(K.BookError, "until"):
            self.note(f["id"], self.MAKER, "accept", until=int(self.clock.t) + 901)
        with self.assertRaises(KeyError):
            self.book.fill("00" * 16)

    def test_rounding_never_gives_more_than_the_order(self):
        o = self.book.post(self.order(give_amount=3 * D.COIN + 1, get_amount=70_001, min_get=5_000))
        total = 0
        for i, amount in enumerate((33_333, 20_001, 9_999)):
            f = self.book.take(self.take(o, amount))
            self.note(f["id"], self.MAKER, "accept", until=int(self.clock.t) + 60)
            self.assertEqual(f["give_amount"], (3 * D.COIN + 1) * amount // 70_001)
            total += f["give_amount"]
            v = self.book.public(self.book.orders[o["id"]])
            self.assertEqual(v["remaining"], 3 * D.COIN + 1 - total)
            self.assertLessEqual(K.give_for(o, v["remaining_get"]), v["remaining"])

    def test_saved_and_restored(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "book.json")
            b1 = K.Book(self.book.chains, self.book.backing, path, now=self.clock)
            o = b1.post(self.order())
            b1.save()
            b2 = K.Book(self.book.chains, self.book.backing, path, now=self.clock)
            self.assertEqual(list(b2.orders), [o["id"]])
            self.assertEqual(b2.view(), [])  # restored, but its maker has to show up again before it is listed


# ---------------------------------------------------------------- the site without nodes
# Stand-ins shaped like the RPCs the site reads (web.py): an outside chain (Bitcoin, or Qwencoin,
# whose RPC is the same), a launch node whose chain the test builds block by block on either curve,
# the registry and the site's pool. They hold no consensus logic of their own: what a block mints
# and owes comes from the descriptor's helpers, which test_diff_cpp holds to the node.
class FakeChain:
    def __init__(self, chain="regtest", height=120, now=1_800_000_000):
        self.chain, self.height, self.now = chain, height, now
        self.utxos = {}      # (txid, vout) -> (script hex, value, height; 0 = unconfirmed)
        self.sent = []
        self.scans = 0

    def fund(self, script_hex: str, value: int, confirmed=True) -> tuple:
        op = (sha256(bytes([len(self.utxos)]) + bytes.fromhex(script_hex)).hex(), len(self.utxos) % 3)
        self.utxos[op] = (script_hex, value, self.height if confirmed else 0)
        return op

    def getblockchaininfo(self):
        return {"chain": self.chain, "blocks": self.height, "mediantime": self.now - 3000}

    def getblockcount(self):
        return self.height

    def getblockhash(self, h):
        if h != 0:
            raise K.BookError("the stand-in only has the regtest genesis")
        return sha256d(D.REGTEST_GENESIS_HEADER)[::-1].hex()

    def getblockheader(self, h, verbose=True):
        return {"time": 1296688602} if verbose else D.REGTEST_GENESIS_HEADER.hex()

    def scantxoutset(self, action, descs):
        self.scans += 1
        want = {x[4:-1] for x in descs}
        return {"height": self.height, "unspents": [
            {"txid": t, "vout": n, "scriptPubKey": s, "amount": v / D.COIN, "height": h}
            for (t, n), (s, v, h) in self.utxos.items() if s in want]}

    def gettxout(self, txid, vout, mempool=True):
        u = self.utxos.get((txid, vout))
        return None if not u else {"value": u[1] / D.COIN, "scriptPubKey": {"hex": u[0]},
                                   "confirmations": self.height - u[2] + 1 if u[2] else 0}

    def estimatesmartfee(self, n):
        return {"errors": ["no estimate"]}

    def sendrawtransaction(self, hexstr):
        self.sent.append(hexstr)
        return sha256d(bytes.fromhex(hexstr))[::-1].hex()


class FakeLaunch:
    """A launch node as the site reads it. mine(curve) adds a block on that curve."""

    def __init__(self, d: D.Launch, t0=1_800_000_000, node_curves=True):
        self.d, self.t0, self.node_curves = d, t0, node_curves
        self.blocks = [{"hash": d.genesis_hash, "version": 1, "work": 0, "time": d.genesis_time, "tx": [], "ob": None}]
        self.w = {"btc": 0, "qwen": 0}
        self.count = {"btc": 0, "qwen": 0}
        self.last = {"btc": 0, "qwen": 0}
        self.grad_h, self.grad_by = 0, None
        self.tail = 0

    @property
    def height(self):
        return len(self.blocks) - 1

    def mine(self, curve="btc", work=2, miner="0014" + "aa" * 20, payee="holder", pay=None, pay_script=None, settled=False,
             draw_known=True, dt=5):
        h, d = len(self.blocks), self.d
        on = None if self.grad_by else curve
        if on:
            minted = d.curve_supply(self.w[on] + work) - d.curve_supply(self.w[on])
            owed = d.owed(work, on)
            self.w[on] += work
            self.count[on] += 1
            self.last[on] = h
            if self.w[on] >= d.graduation_work:
                self.grad_by, self.grad_h = on, h
        else:
            minted, owed = d.tail_reward_at(h), 0
            self.tail += work
        pay = owed if pay is None else pay
        ob = {"owed": owed, "curve": bool(on), "settled": settled, "spendable": settled or not owed, "draw_known": draw_known,
              "deadline_height": h + d.settle_deadline, "tag": sha256(bytes([h % 256]) * 3)[:20].hex(), "quote": on or "btc"}
        if owed and draw_known:
            ob.update(pay=pay, payee=payee, pay_script=pay_script or ("0014" + "bb" * 20))
        hsh = sha256d(bytes.fromhex(self.blocks[-1]["hash"]) + bytes([h % 256, len(curve)])).hex()
        self.blocks.append({"hash": hsh, "version": 0x20000000 | (0x200 if on == "qwen" else 0), "work": work,
                            "time": self.blocks[-1]["time"] + dt if h > 1 else self.t0, "ob": ob, "tx": [{
                                "txid": sha256(hsh.encode()).hex(), "vin": [{"coinbase": "00"}],
                                "vout": [{"n": 0, "value": minted / D.COIN, "scriptPubKey": {"hex": miner}}]}]})
        return h

    def settle(self, h):
        self.blocks[h]["ob"].update(settled=True, spendable=True)

    # ---- the RPCs
    def getlaunchinfo(self):
        d, total = self.d, sum(b["work"] for b in self.blocks)
        out = {"height": self.height, "graduated": bool(self.grad_by), "graduation_height": self.grad_h or -1,
               "curve_supply": d.curve_minted(self.w["btc"], self.w["qwen"]), "progress": max(
                   d.curve_supply(self.w[x]) / d.graduation_tokens for x in self.w),
               "supply": d.curve_minted(self.w["btc"], self.w["qwen"]), "hashes_per_coin": d.hashes_per_coin(self.w["btc"]),
               "earning": sum(round(b["tx"][0]["vout"][0]["value"] * D.COIN) for b in self.blocks[1:]), "work": total}
        if self.node_curves:
            out["graduated_by"] = self.grad_by
            out["curves"] = {x: {"work": f"{self.w[x]:064x}", "supply": d.curve_supply(self.w[x]),
                                 "progress": d.curve_supply(self.w[x]) / d.graduation_tokens,
                                 "hashes_per_coin": d.hashes_per_coin(self.w[x]), "owed_per_coin": d.price_per_coin(self.w[x], x),
                                 "blocks": self.count[x], "last_height": self.last[x]} for x in self.w}
        return out

    def getblockhash(self, h):
        return self.blocks[h]["hash"]

    def getblock(self, hsh, verbosity=3):
        h = next(i for i, b in enumerate(self.blocks) if b["hash"] == hsh)
        b = self.blocks[h]
        work = self.d.genesis_work + sum(x["work"] for x in self.blocks[:h + 1])
        return {"tx": b["tx"], "chainwork": f"{work:064x}", "version": b["version"], "time": b["time"]}

    def getmintobligation(self, h):
        return dict(self.blocks[h]["ob"])


class FakeRegistry:
    def __init__(self, launches):
        self.launches = launches  # ticker -> FakeLaunch
        self.data = {t: {} for t in launches}

    def rpc(self, t, timeout=60):
        return self.launches[t]

    def desc(self, t):
        return self.launches[t].d


class FakePools:
    def __init__(self, curves=("btc", "qwen")):
        self.curves, self.asked, self.dues = list(curves), [], {}

    def ensure(self, t, rpc, d):
        pass

    def info(self, t):
        q = {x: sum(1 for a in self.asked if a[0] == t and a[3] == x) for x in ("btc", "qwen")}
        return {"stratum_port": 20004, "queue": sum(q.values()), "queues": q, "curves": self.curves, "mining": False,
                "cut_bps": 500, "settler": {}}

    def enqueue(self, t, address, blocks=1, curve="btc"):
        if curve not in self.curves:
            raise ValueError(f"the {curve} curve is not mined here")
        self.asked.append((t, address, blocks, curve))
        return {"position": len(self.asked) - 1, "queue": len(self.asked), "at": 0, "curve": curve}

    def due(self, t, script_hex):
        return self.dues.get((t, script_hex), [])


def twin(name="Twin Cat", ticker="TWN", grad=10**6, **kw) -> D.Launch:
    d = D.make(name, ticker, bytes.fromhex("0014" + "11" * 20), grad, test=True, pow_limit_bits=0x207FFFFF,
               genesis_time=1_799_990_000, **kw)
    d.grind_genesis()
    return d


def get(port, path, base="", headers=None):
    import json
    import urllib.request
    req = urllib.request.Request(f"http://127.0.0.1:{port}{base}{path}", headers=headers or {})
    with urllib.request.urlopen(req, timeout=20) as r:
        body = r.read()
        return json.loads(body) if r.headers["Content-Type"].startswith("application/json") else body.decode()


class SiteTest(unittest.TestCase):
    """web.py over the stand-ins: the two curves of a coin as the site reports them, what they
    imply for QWEN, the Qwencoin chain in the API and the book, and the base path."""

    def site(self, launches, qwen=True, **kw):
        from hashfun import web
        self.btc, self.qwen = FakeChain(), FakeChain(height=77) if qwen else None
        s = web.Site(self.btc, FakeRegistry(launches), qwen=self.qwen, **kw)
        s.refresh()
        return s

    def serve(self, s):
        import threading
        from http.server import ThreadingHTTPServer
        from hashfun import web
        srv = ThreadingHTTPServer(("127.0.0.1", 0), web.handler(s))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def test_two_curves_each_with_its_own_price(self):
        d = twin()
        n = FakeLaunch(d)
        for _ in range(30):
            n.mine("btc", work=4000)
        for _ in range(10):
            n.mine("qwen", work=4000)
        s = self.site({"TWN": n})
        c = s.coins["TWN"].summary()
        b, q = c["curves"]["btc"], c["curves"]["qwen"]
        self.assertEqual((b["blocks"], q["blocks"], b["last_height"], q["last_height"]), (30, 10, 30, 40))
        # each curve's price point is its own work at its own rate, in its own quote
        self.assertAlmostEqual(b["price"], d.price_per_coin(120_000, "btc"))
        self.assertAlmostEqual(q["price"], d.price_per_coin(40_000, "qwen"))
        self.assertGreater(b["price"] / b["price_at_start"], q["price"] / q["price_at_start"])  # the BTC curve is further along
        self.assertAlmostEqual(b["price_at_graduation"] / b["price_at_start"], q["price_at_graduation"] / q["price_at_start"])
        self.assertEqual((b["total"], q["total"]), (d.leg_total("btc"), d.leg_total("qwen")))
        self.assertEqual(c["progress"], max(b["progress"], q["progress"]))
        self.assertEqual(c["curve_supply"], d.curve_supply(120_000) + d.curve_supply(40_000))
        # the history: one point per curve per block; a curve's line is flat while the other is mined
        ser = s.coins["TWN"].detail()["series"]
        self.assertEqual(len(ser["btc"]), len(ser["qwen"]))
        self.assertEqual(ser["qwen"][0][1], ser["qwen"][29][1])
        self.assertEqual(ser["btc"][30][1], ser["btc"][-1][1])
        self.assertLess(ser["btc"][0][1], ser["btc"][29][1])
        self.assertLess(ser["qwen"][29][1], ser["qwen"][-1][1])
        rows = {r["height"]: r for r in s.coins["TWN"].detail()["blocks"]}
        self.assertEqual((rows[40]["on"], rows[40]["quote"], rows[30]["on"]), ("qwen", "qwen", "btc"))

    def test_the_index_agrees_with_a_node_that_reports_its_curves_and_works_without(self):
        d = twin()
        a, b = FakeLaunch(d), FakeLaunch(d, node_curves=False)
        for n in (a, b):
            for i in range(25):
                n.mine("qwen" if i % 3 == 0 else "btc", work=1000 + 37 * i)
        s = self.site({"TWN": a})
        s2 = self.site({"TWN": b})
        x, y = s.coins["TWN"].summary(), s2.coins["TWN"].summary()
        self.assertEqual(s.coins["TWN"].w, {q: int(a.getlaunchinfo()["curves"][q]["work"], 16) for q in ("btc", "qwen")})
        for q in ("btc", "qwen"):
            for k in ("price", "progress", "supply", "blocks", "last_height"):
                self.assertAlmostEqual(x["curves"][q][k], y["curves"][q][k], msg=(q, k))
        self.assertEqual(x["implied"], y["implied"])

    def test_what_the_two_prices_imply_for_qwen_and_what_kind_of_number_it_is(self):
        d = twin()
        cases = {}
        for name, plan in {"start": [], "floor": ["btc"] * 5, "ceiling": ["qwen"] * 5, "two-sided": ["btc", "qwen"] * 3,
                           "floor again": ["qwen"] * 2 + ["btc"] * 100}.items():
            n = FakeLaunch(d)
            for cv in plan:
                n.mine(cv, work=500)
            cases[name] = self.site({"TWN": n}).coins["TWN"].summary()["implied"]
        self.assertEqual([cases[k]["kind"] for k in cases], ["start", "floor", "ceiling", "two-sided", "floor"])
        self.assertEqual([cases[k]["two_sided"] for k in cases], [False, False, False, True, False])
        # price_btc / price_qwen * 1e8: at the start, the ratio of the two rates
        self.assertAlmostEqual(cases["start"]["sats_per_qwen"], d.price_per_coin(0, "btc") / d.price_per_coin(0, "qwen") * D.COIN)
        self.assertGreater(cases["floor"]["sats_per_qwen"], cases["start"]["sats_per_qwen"])   # only the BTC price rose
        self.assertLess(cases["ceiling"]["sats_per_qwen"], cases["start"]["sats_per_qwen"])
        # graduation closes both curves: what they imply is history, and the other curve stays where it was
        n = FakeLaunch(twin(grad=20_000))
        for cv in ["qwen", "btc"] * 3:
            n.mine(cv, work=1500)
        while not n.grad_by:
            n.mine("btc", work=4000)
        for _ in range(5):
            n.mine("btc", work=4000)   # tail blocks: on neither curve
        c = self.site({"TWN": n}).coins["TWN"]
        sm = c.summary()
        self.assertEqual((sm["graduated"], sm["graduated_by"], sm["implied"]["kind"]), (True, "btc", "history"))
        self.assertEqual(sm["curves"]["qwen"]["blocks"], 3)
        self.assertEqual(sm["curves"]["btc"]["progress"], 1.0)
        self.assertLess(sm["curves"]["qwen"]["progress"], 1.0)
        self.assertEqual([r["on"] for r in c.detail()["blocks"][:5]], [None] * 5)
        self.assertEqual(c.detail()["series"]["btc"][-1][1], c.detail()["series"]["btc"][-6][1])  # frozen at graduation

    def test_payouts_are_counted_in_the_quote_of_the_block_and_shown_on_its_chain(self):
        n = FakeLaunch(twin())
        key = "0014" + "cd" * 20
        h1 = n.mine("btc", work=4000, pay=11_000, pay_script=key, settled=True)
        h2 = n.mine("qwen", work=4000, pay=15_000, pay_script=key, settled=True)
        n.mine("qwen", work=4000, pay=9_000, payee="creator", settled=True)
        n.mine("btc", work=4000, pay=7_000, pay_script=key)   # drawn, not paid yet
        s = self.site({"TWN": n})
        c = s.coins["TWN"].summary()
        self.assertEqual(c["curves"]["btc"]["paid"], {"holder": 11_000, "creator": 0, "dev": 0})
        self.assertEqual(c["curves"]["qwen"]["paid"], {"holder": 15_000, "creator": 9_000, "dev": 0})
        s.refresh()
        s.refresh()   # counted once, however often the index polls
        self.assertEqual(s.coins["TWN"].summary()["curves"]["qwen"]["paid"]["holder"], 15_000)
        self.assertEqual([(r["height"], r["quote"], r["pay"]) for r in c["recent"]], [(h1, "btc", 11_000), (h2, "qwen", 15_000)])
        n.settle(4)
        s.refresh()
        self.assertEqual(s.coins["TWN"].summary()["curves"]["btc"]["paid"]["holder"], 18_000)

    def test_qwencoin_is_a_chain_of_the_site_only_with_a_node_of_it(self):
        n = FakeLaunch(twin())
        s = self.site({"TWN": n})
        port = self.serve(s)
        cfg = get(port, "/api/config")
        self.assertEqual((cfg["btc_id"], cfg["qwen_id"], cfg["qwen"]["hrp"], cfg["qwen"]["chain"]), ("btc:regtest", "qwen:regtest", "bcrt", "regtest"))
        self.assertEqual(s.book_chains(), {"btc:regtest": "BTC", "qwen:regtest": "QWEN", s.coins["TWN"].d.id_hex: "TWN"})
        key = "0014" + "ee" * 20
        from hashfun.ser import script_to_address
        addr = script_to_address(bytes.fromhex(key), "bcrt")
        # the same key and the same address string on both chains; each balance is its own chain's
        self.btc.fund(key, 70_000)
        self.qwen.fund(key, 3 * D.COIN)
        self.qwen.fund(key, D.COIN, confirmed=False)
        self.assertEqual(get(port, f"/api/chain/btc/address/{addr}")["balance"], 70_000)
        q = get(port, f"/api/chain/qwen/address/{addr}")
        self.assertEqual((q["balance"], sorted(u["confirmations"] for u in q["utxos"])), (4 * D.COIN, [0, 1]))
        self.assertEqual(get(port, "/api/chain/qwen/time")["height"], 77)
        # no Qwencoin node: no QWEN chain in the config or the book, and the path says so
        s2 = self.site({"TWN": n}, qwen=False)
        port2 = self.serve(s2)
        cfg = get(port2, "/api/config")
        self.assertEqual((cfg["qwen"], cfg["qwen_id"], cfg["allow_launch"]), (None, None, False))
        self.assertNotIn("QWEN", s2.book_chains().values())
        import urllib.error
        with self.assertRaises(urllib.error.HTTPError) as e:
            get(port2, f"/api/chain/qwen/address/{addr}")
        self.assertEqual(e.exception.code, 400)
        self.assertIn("no Qwencoin node", e.exception.read().decode())
        self.assertEqual(len(s2.coins["TWN"].summary()["curves"]), 2)   # both curves are still shown: they are on the launch's own chain

    def test_the_config_says_where_bitcoin_is_read_from(self):
        from unittest import mock
        from hashfun import web
        s = self.site({"TWN": FakeLaunch(twin())})
        port = self.serve(s)
        self.assertEqual(get(port, "/api/config")["btc_source"], "node")
        with mock.patch.object(web, "is_light", lambda rpc: rpc is s.btc):   # as if --btc-rpc were electrums://...
            self.assertEqual(get(port, "/api/config")["btc_source"], "electrum")

    def test_bids_in_qwen_are_backed_by_a_scan_of_the_qwencoin_node(self):
        n = FakeLaunch(twin())
        s = self.site({"TWN": n})
        s.book.now = lambda: 1_800_000_000.0
        maker = 0x4444
        from hashfun.crypto import hash160
        key = "0014" + hash160(pubkey_from_priv(maker)).hex()
        o = {"maker": pub(maker), "give": "qwen:regtest", "give_amount": 2 * D.COIN, "get": "btc:regtest", "get_amount": 500_000,
             "min_get": 5_000, "expiry": 1_800_003_600, "nonce": "0102030405060708", "lock": 3600, "confs": 1}
        o["sig"] = sign(maker, K.order_text(o))
        posted = s.book.post(o)
        self.assertEqual((posted["give_ticker"], posted["get_ticker"], posted["backed"]), ("QWEN", "BTC", False))   # not seen yet
        self.assertEqual(s.book.view(), [])
        self.qwen.fund(key, 2 * D.COIN)
        s.scan_bids()
        self.assertEqual((self.qwen.scans, self.btc.scans), (1, 0))   # the QWEN behind it is looked for on Qwencoin, not on Bitcoin
        s.book.seen[pub(maker)] = 1_800_000_000.0
        self.assertEqual([x["id"] for x in s.book.view()], [posted["id"]])
        # and sats behind a bid on Bitcoin, as before: the same key, the other chain, its own scan
        o2 = dict(o, give="btc:regtest", give_amount=300_000, get="qwen:regtest", get_amount=D.COIN, nonce="0102030405060709")
        o2["sig"] = sign(maker, K.order_text(o2))
        s.book.post(o2)
        s.scan["btc"].scanned = s.scan["qwen"].scanned = 0
        s.scan_bids()
        self.assertEqual(self.btc.scans, 1)
        self.assertEqual(len(s.book.view()), 1)   # QWEN at that key does not back a bid in sats
        self.btc.fund(key, 300_000)
        s.scan["btc"].scanned = 0
        s.scan_bids()
        self.assertEqual(len(s.book.view()), 2)
        v = s.qwen_view()
        self.assertEqual((round(v["book"]["ask"]["price"]), round(v["book"]["bid"]["price"])), (250_000, 300_000))
        self.assertEqual((v["book"]["ask"]["qwen"], v["book"]["bid"]["sats"]), (2 * D.COIN, 300_000))

    def test_the_site_wide_qwen_price_is_the_median_of_the_two_sided_launches(self):
        launches = {}
        for i, (t, plan) in enumerate({"AAA": ["btc", "qwen"] * 4, "BBB": ["btc"] * 6 + ["qwen"], "CCC": ["qwen", "btc"] * 2,
                                       "DDD": ["btc"] * 9, "EEE": []}.items()):
            n = FakeLaunch(twin(name=t, ticker=t, qwen_total=(i + 1) * 40 * D.COIN, sats_total=D.COIN // 10))
            for cv in plan:
                n.mine(cv, work=30_000)
            launches[t] = n
        s = self.site(launches)
        v = s.qwen_view()
        two = sorted(x["sats_per_qwen"] for x in v["implied"]["each"] if x["kind"] == "two-sided")
        self.assertEqual((v["implied"]["launches"], v["implied"]["of"], len(two)), (3, 5, 3))
        self.assertEqual(v["implied"]["sats_per_qwen"], two[1])
        self.assertEqual({x["ticker"]: x["kind"] for x in v["implied"]["each"]},
                         {"AAA": "two-sided", "BBB": "two-sided", "CCC": "two-sided", "DDD": "floor", "EEE": "start"})
        self.assertEqual((v["node"], v["chain"], v["height"]), (True, "regtest", 77))
        # nothing two-sided: no price, said as such
        s = self.site({"DDD": launches["DDD"], "EEE": launches["EEE"]})
        self.assertEqual(s.qwen_view()["implied"]["sats_per_qwen"], None)

    def test_mining_from_the_page_names_its_curve(self):
        n = FakeLaunch(twin())
        s = self.site({"TWN": n})
        s.pools = FakePools()
        port = self.serve(s)
        import json
        import urllib.error
        import urllib.request

        def post(path, body):
            req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", json.dumps(body).encode(), {"Content-Type": "application/json"})
            return json.load(urllib.request.urlopen(req, timeout=20))
        self.assertEqual(post("/api/coin/TWN/queue", {"address": "twn1qxyz", "blocks": 1, "curve": "qwen"})["curve"], "qwen")
        self.assertEqual(post("/api/coin/TWN/queue", {"address": "twn1qxyz"})["curve"], "btc")   # the BTC curve when nothing is said
        self.assertEqual([a[3] for a in s.pools.asked], ["qwen", "btc"])
        with self.assertRaises(urllib.error.HTTPError) as e:
            post("/api/coin/TWN/queue", {"address": "twn1qxyz", "curve": "sol"})
        self.assertEqual(e.exception.code, 400)
        self.assertEqual(get(port, "/api/coin/TWN")["pool"]["queues"], {"btc": 1, "qwen": 1})
        # a site without a Qwencoin node cannot see a QWEN payment: it does not mine that curve
        s2 = self.site({"TWN": n}, qwen=False)
        s2.pools = FakePools()
        port2 = self.serve(s2)
        with self.assertRaises(urllib.error.HTTPError) as e:
            req = urllib.request.Request(f"http://127.0.0.1:{port2}/api/coin/TWN/queue", json.dumps({"address": "a", "curve": "qwen"}).encode(),
                                         {"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=20)
        self.assertIn("no Qwencoin node", e.exception.read().decode())
        self.assertEqual(s2.pools.asked, [])

    def test_the_whole_site_under_a_base_path(self):
        n = FakeLaunch(twin(metadata=M.from_image(png(), description="two curves")))
        n.mine("btc")
        s = self.site({"TWN": n}, base_path="/fun/")
        self.assertEqual(s.base_path, "/fun")
        port = self.serve(s)
        for base in ("/fun", ""):   # the server in front may pass the prefix on or cut it off
            self.assertEqual(get(port, "/api/board", base)[0]["ticker"], "TWN")
            page = get(port, "/", base)
            self.assertIn('src="app.js"', page)
            self.assertIn('href="style.css"', page)
            self.assertNotIn('"/app.js"', page)
            self.assertIn("font-face", get(port, "/style.css", base))
        css = get(port, "/style.css", "/fun")
        self.assertNotIn("url(/", css)   # fonts, like everything the page asks for, relative to where it is served
        img = get(port, "/api/board", "/fun")[0]["image"]
        self.assertFalse(img.startswith("/"))
        import urllib.request
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/fun/{img}", timeout=20) as r:
            self.assertEqual(r.read(), png())

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        import urllib.error
        with self.assertRaises(urllib.error.HTTPError) as e:   # /fun alone would resolve the page's links against /
            urllib.request.build_opener(NoRedirect).open(f"http://127.0.0.1:{port}/fun?x=1", timeout=20)
        self.assertEqual((e.exception.code, e.exception.headers["Location"]), (301, "/fun/?x=1"))


    def test_link_previews_are_in_the_html_a_crawler_gets(self):
        """A crawler runs no script: the title, the description and the Open Graph and Twitter tags
        are in the page as served. The site says the pitch; a coin says its name, both price
        points and how far each curve is, with its own picture. Addresses in them are absolute."""
        import re
        import urllib.error
        import urllib.request
        from hashfun import web
        n = FakeLaunch(twin(name="Rig Cat", ticker="RIG", metadata=M.from_image(png(), description="two curves")))
        for cv in ["btc"] * 6 + ["qwen"] * 2:
            n.mine(cv, work=30_000)
        plain = FakeLaunch(twin(name="No Picture", ticker="NOP"))
        s = self.site({"RIG": n, "NOP": plain}, base_path="/fun")
        port = self.serve(s)
        tag = lambda page, key: re.search(r'<meta (?:name|property)="%s" content="([^"]*)">' % re.escape(key), page).group(1)  # noqa: E731
        # the site, as a proxy in front of it passes the request on
        page = get(port, "/", "/fun", {"Host": "example.org", "X-Forwarded-Proto": "https"})
        self.assertIn(f"<title>hashfun: {web.PITCH['what']}</title>", page)
        self.assertEqual(tag(page, "description"), web.PITCH["oneliner"])
        self.assertEqual((tag(page, "og:title"), tag(page, "og:description")), (web.PITCH["what"], web.PITCH["oneliner"]))
        self.assertEqual((tag(page, "og:url"), tag(page, "og:image")), ("https://example.org/fun/", "https://example.org/fun/share.png"))
        self.assertEqual((tag(page, "og:image:width"), tag(page, "og:image:height")), ("1200", "630"))
        self.assertEqual((tag(page, "twitter:card"), tag(page, "twitter:title"), tag(page, "twitter:image")),
                         ("summary_large_image", web.PITCH["what"], "https://example.org/fun/share.png"))
        self.assertIn(f'<span class="m tagline">{web.PITCH["tagline"]}</span>', page)   # the tagline beside the name, in the HTML itself
        self.assertNotIn("{{", page)
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/fun/share.png", timeout=20) as r:   # the picture those tags name
            pic = r.read()
            self.assertEqual((r.headers["Content-Type"], pic[:8], struct.unpack(">II", pic[16:24])), ("image/png", b"\x89PNG\r\n\x1a\n", (1200, 630)))
        # a coin, at an address a crawler can fetch
        cv = s.coins["RIG"].summary()["curves"]
        for path in ("/c/RIG", "/c/rig"):
            page = get(port, path, "/fun", {"Host": "example.org", "X-Forwarded-Proto": "https"})
            self.assertIn("<title>Rig Cat ($RIG) on hashfun</title>", page)
            self.assertIn('<base href="../">', page)   # the page's relative links still resolve against the site's root
            desc = tag(page, "og:description")
            self.assertEqual(tag(page, "description"), desc)
            for x, unit in (("btc", "sats per coin"), ("qwen", "QWEN sats per coin")):
                self.assertIn(f"{web.show_price(cv[x]['price'])} {unit}, {cv[x]['progress'] * 100:.1f}% mined", desc)
            self.assertTrue(desc.startswith("$RIG is its own chain with two curves."))
            self.assertEqual((tag(page, "og:title"), tag(page, "og:url"), tag(page, "twitter:card")), ("Rig Cat ($RIG)", "https://example.org/fun/c/RIG", "summary"))
            img = tag(page, "og:image")
            self.assertTrue(img.startswith("https://example.org/fun/api/coin/RIG/image?m="))
            self.assertEqual(tag(page, "twitter:image"), img)
        with urllib.request.urlopen(img.replace("https://example.org", f"http://127.0.0.1:{port}"), timeout=20) as r:
            self.assertEqual(r.read(), png())   # the coin's own picture
        page = get(port, "/c/NOP", "/fun", {"Host": "example.org"})   # no picture of its own: the site's
        self.assertEqual((tag(page, "og:image"), tag(page, "twitter:card"), tag(page, "og:url")),
                         ("http://example.org/fun/share.png", "summary_large_image", "http://example.org/fun/c/NOP"))
        # --public-url says where the world reaches the site, whatever the request claims
        s.public_url = "https://aichat.fyi/fun"
        page = get(port, "/c/RIG", "", {"Host": "evil.example"})
        self.assertEqual(tag(page, "og:url"), "https://aichat.fyi/fun/c/RIG")
        s.public_url = ""
        page = get(port, "/", "", {"Host": 'x"><script>alert(1)</script>', "X-Forwarded-Proto": "javascript"})
        self.assertEqual(tag(page, "og:url"), "http://localhost/fun/")   # a host that is not a host is not echoed
        # a coin's name is its creator's text: it is escaped wherever it is written
        n.d.name = 'Cat "><img src=x onerror=alert(1)> & co'
        page = get(port, "/c/RIG", "/fun")
        self.assertNotIn("<img src=x", page)
        self.assertIn("Cat &quot;&gt;&lt;img src=x onerror=alert(1)&gt; &amp; co ($RIG)", page)
        # one spelling per coin, and an unknown one is not found (with the site's own tags)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        with self.assertRaises(urllib.error.HTTPError) as e:
            urllib.request.build_opener(NoRedirect).open(f"http://127.0.0.1:{port}/fun/c/RIG/", timeout=20)
        self.assertEqual((e.exception.code, e.exception.headers["Location"]), (301, "../RIG"))
        with self.assertRaises(urllib.error.HTTPError) as e:
            get(port, "/c/NOPE", "/fun")
        self.assertEqual(e.exception.code, 404)
        self.assertIn(f"<title>hashfun: {web.PITCH['what']}</title>", e.exception.read().decode())

    def test_pockets_is_a_fresh_count_from_the_qwencoin_pages_or_nothing(self):
        import json
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from hashfun import web
        answer = {"body": json.dumps({"name": "aichat.fyi", "identities": 5, "height": 6126}).encode(), "asked": 0}

        class Pages(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                answer["asked"] += 1
                ok = self.path == "/graph/status.json"
                self.send_response(200 if ok else 404)
                self.send_header("Content-Length", str(len(answer["body"]) if ok else 0))
                self.end_headers()
                self.wfile.write(answer["body"] if ok else b"")
        pages = ThreadingHTTPServer(("127.0.0.1", 0), Pages)
        threading.Thread(target=pages.serve_forever, daemon=True).start()
        self.addCleanup(pages.server_close)
        self.addCleanup(pages.shutdown)
        s = self.site({}, qwen_pages=f"http://127.0.0.1:{pages.server_address[1]}/")
        self.assertIsNone(s.qwen_view()["pockets"])   # not read yet: nothing is said
        s.read_pockets()
        self.assertEqual(s.qwen_view()["pockets"], {"n": 5, "add": web.JOIN})   # a small number, as it is
        self.assertEqual(web.JOIN, "https://huggingface.co/staccs/qwencoin")
        for body in (b"not json", json.dumps({"identities": -1}).encode(), json.dumps({"identities": True}).encode(),
                     json.dumps({"identities": "5"}).encode(), json.dumps({"height": 1}).encode()):
            answer["body"] = body
            try:
                s.read_pockets()
            except Exception:  # noqa: BLE001  (the reader thread logs it and asks again a minute later)
                pass
            self.assertEqual(s.pockets[0], 5)   # a bad read keeps the last good one
        s.pockets = (5, s.pockets[1] - 299)
        self.assertEqual(s.qwen_view()["pockets"]["n"], 5)
        s.pockets = (5, s.pockets[1] - 2)   # read more than five minutes ago: not "right now" any more
        self.assertIsNone(s.qwen_view()["pockets"])
        self.assertIsNone(self.site({}).qwen_view()["pockets"])   # no --qwen-pages: no line
        asked = answer["asked"]
        self.site({}, qwen_pages="file:///etc/hostname").read_pockets()   # only http(s) is ever fetched
        self.assertEqual(answer["asked"], asked)

    def test_the_launch_form_s_qwen_terms_come_from_the_descriptor_s_helpers(self):
        from hashfun import web
        s = web.Site(FakeChain("main"), FakeRegistry({}), qwen=FakeChain("main"))
        for coins_, confs in ((50, 6), (500, 13), (5000, 125), (25_000, 625), (40_320, 1008)):
            t = s.launch_terms({"qwen_total": str(coins_ * D.COIN)})
            self.assertEqual((t["qwen_confs"], t["qwen_seconds"]), (confs, confs * 600), coins_)
            self.assertEqual(t["qwen_confs"], D.qwen_confs_for(coins_ * D.COIN))
            self.assertGreaterEqual(t["settle_seconds"], 3 * t["qwen_seconds"])   # room to pay, confirm and prove
        with self.assertRaises(ValueError) as e:   # a leg no number of confirmations covers is refused, with the reason
            s.launch_terms({"qwen_total": str(50_000 * D.COIN)})
        self.assertIn("make the leg smaller", str(e.exception))
        t = s.launch_terms({})
        self.assertEqual((t["curve_tokens"], t["max_supply"]), (twin().graduation_tokens, twin().virtual_tokens + twin().graduation_tokens))
        r = self.site({}).launch_terms({"qwen_total": str(D.COIN)})   # a regtest Qwencoin: the test leg's confirmations
        self.assertEqual(r["qwen_confs"], D.TEST_QWEN_CONFS)


# ---------------------------------------------------------------- the page, in a browser
WALLET = 0x7777   # the stand-in wallet's key: its P2WPKH is the "UniSat address" of the browser tests
SIG = "HhashfunPageTestWalletSignatureAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
MOCK_WALLET = """(() => { window.unisat = {
  requestAccounts: async () => ['%(addr)s'], getAccounts: async () => ['%(addr)s'], getNetwork: async () => 'regtest',
  signMessage: async (m) => window.__hf_sign(m), sendBitcoin: async (to, sats) => window.__hf_send(to, sats),
  getPublicKey: async () => '%(pub)s', signPsbt: async (hex, opts) => window.__hf_psbt(hex) }; })();"""
BLOCKED_STORAGE = """for (const n of ['localStorage', 'sessionStorage'])
  Object.defineProperty(window, n, { get() { throw new DOMException('The operation is insecure.', 'SecurityError'); } });"""


def page_key(sig: str = SIG) -> int:
    """The key the page derives from the wallet's signature (btc.js keyFromSignature)."""
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    k = sha256(b"hashfun-key-v1" + sig.encode())
    while not 1 <= int.from_bytes(k, "big") < n:
        k = sha256(k)
    return int.from_bytes(k, "big")


def demo(now: int, qwen=True, empty=False, **kw):
    """A site over stand-in nodes with coins in every state the page has to show: both curves being
    mined, one only, none yet, graduated; dues on both chains for the page's key; offers in all
    three pairs. Returns (site, btc, qwen, launches)."""
    from hashfun import web
    from hashfun.crypto import hash160
    launches = {}

    def make(name, t, plan, grad=4 * 10**6, work=40_000, **mk):
        n = FakeLaunch(twin(name=name, ticker=t, grad=grad, **mk), t0=now - 5 * len(plan) - 20)
        for i, cv in enumerate(plan):
            n.mine(cv, work=work, pay=12_000 + 137 * i if i % 3 else 0, pay_script="0014" + ("%02x" % (i % 7 + 1)) * 20,
                   payee=["holder", "holder", "creator", "holder", "dev"][i % 5], settled=i < len(plan) - 8, draw_known=i < len(plan) - 6)
        return n
    if not empty:
        launches["RIGCAT"] = make("Rig Cat", "RIGCAT", (["btc"] * 3 + ["qwen"]) * 14, sats_total=D.COIN // 2, qwen_total=40 * D.COIN,
                                  metadata=M.from_image(png(64, 64), description="The cat that mines.\nTwo curves, one cat.", x="https://x.com/rigcat"))
        launches["MOON"] = make("Moon Dog", "MOON", ["btc"] * 30, sats_total=D.COIN // 10, qwen_total=500 * D.COIN)
        launches["QWAK"] = make("Qwak", "QWAK", ["qwen"] * 22, sats_total=D.COIN, qwen_total=50 * D.COIN)
        launches["FRESH"] = make("Fresh Mint", "FRESH", [])
        launches["DONE"] = make("Done Deal", "DONE", ["qwen", "btc"] * 6 + ["qwen"] * 40, grad=600_000, work=30_000)
    btc, qw = FakeChain(now=now), FakeChain(height=6126, now=now)
    site = web.Site(btc, FakeRegistry(launches), qwen=qw if qwen else None, allow_launch=True, **kw)
    site.pools = FakePools(["btc", "qwen"] if qwen else ["btc"])
    site.refresh()
    key = "0014" + hash160(pubkey_from_priv(page_key())).hex()
    btc.fund(key, 61_234)
    qw.fund(key, int(2.5 * D.COIN))
    qw.fund("0014" + hash160(pubkey_from_priv(WALLET)).hex(), int(0.75 * D.COIN))
    if launches:
        site.pools.dues[("RIGCAT", key)] = [
            {"height": 50, "key": "50", "quote": "btc", "pay": 12_400, "pay_script": "0014" + "01" * 20, "tag": "ab" * 20, "paid": False, "deadline_height": 770},
            {"height": 52, "key": "52", "quote": "qwen", "pay": 15_000, "pay_script": "0014" + "02" * 20, "tag": "cd" * 20, "paid": False, "deadline_height": 772},
            {"height": 53, "key": "53", "quote": "qwen", "pay": 21_000, "pay_script": "0014" + "03" * 20, "tag": "ef" * 20, "paid": False, "deadline_height": 773}]
        cid, makers = launches["RIGCAT"].d.id_hex, [0x5551, 0x5552, 0x5553]

        def order(priv, give, ga, get_, gt, nonce):
            o = {"maker": pub(priv), "give": give, "give_amount": ga, "get": get_, "get_amount": gt, "min_get": 2000,
                 "expiry": now + 3600, "nonce": nonce, "lock": 14400, "confs": 1}
            o["sig"] = sign(priv, K.order_text(o))
            return o
        for m in makers:   # what stands behind their offers, on each chain
            ks = "0014" + hash160(pubkey_from_priv(m)).hex()
            btc.fund(ks, 5_000_000)
            qw.fund(ks, 20 * D.COIN)
            site.coins["RIGCAT"].utxo["%064x:0" % m] = (ks, 500 * D.COIN, 1, False)
            site.coins["RIGCAT"].bal[ks] = 500 * D.COIN
        posts = [order(makers[0], cid, 100 * D.COIN, "btc:regtest", 60_000, "00000000000000a1"),
                 order(makers[1], "btc:regtest", 40_000, cid, 80 * D.COIN, "00000000000000a2")]
        if qwen:
            posts += [order(makers[0], cid, 50 * D.COIN, "qwen:regtest", int(0.02 * D.COIN), "00000000000000a3"),
                      order(makers[2], "qwen:regtest", int(0.015 * D.COIN), cid, 40 * D.COIN, "00000000000000a4"),
                      order(makers[1], "qwen:regtest", 2 * D.COIN, "btc:regtest", 520_000, "00000000000000a5"),
                      order(makers[2], "btc:regtest", 480_000, "qwen:regtest", 2 * D.COIN, "00000000000000a6")]
        for o in posts:
            site.book.post(o)
        site.scan_bids()
        site.demo_makers = makers
    return site, btc, qw, launches


def keep_live(site):
    """The stand-in makers stay online and their backing stays seen, as real ones' pages would do."""
    import threading
    import time

    def loop():
        while True:
            for m in getattr(site, "demo_makers", []):
                site.book.seen[pub(m)] = time.time()
            for sc in site.scan.values():
                sc.scanned = 0
            try:
                site.scan_bids()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(1)
    threading.Thread(target=loop, daemon=True).start()


try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


@unittest.skipUnless(sync_playwright, "Playwright is not installed")
class PageTest(unittest.TestCase):
    """The page in Chromium over the stand-in nodes: what a visitor sees and what the page sends
    when they act. The wallet is a stand-in too (the UniSat extension cannot run here): it signs
    with a key the test holds, so every transaction the page builds or accepts is checked."""

    @classmethod
    def setUpClass(cls):
        import json
        import threading
        import time
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from hashfun import web

        class Pages(BaseHTTPRequestHandler):   # the Qwencoin pages' status, for the pitch's one live number
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = json.dumps({"identities": 5}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        cls.pages = ThreadingHTTPServer(("127.0.0.1", 0), Pages)
        threading.Thread(target=cls.pages.serve_forever, daemon=True).start()
        cls.now = int(time.time())
        cls.site, cls.btc, cls.qwen, cls.launches = demo(cls.now, base_path="/fun", qwen_pages=f"http://127.0.0.1:{cls.pages.server_address[1]}")
        cls.site.read_pockets()
        keep_live(cls.site)
        cls.bare, _, _, _ = demo(cls.now, empty=True)
        cls.servers = [web.serve(cls.site, "127.0.0.1", 0), web.serve(cls.bare, "127.0.0.1", 0)]
        cls.url = f"http://127.0.0.1:{cls.servers[0].server_address[1]}"
        cls.bare_url = f"http://127.0.0.1:{cls.servers[1].server_address[1]}"
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch()
        cls.wallet_pub = pubkey_from_priv(WALLET)
        from hashfun.crypto import hash160
        from hashfun.ser import segwit_encode
        cls.wallet_addr = segwit_encode("bcrt", 0, hash160(cls.wallet_pub))
        cls.key_addr = segwit_encode("bcrt", 0, hash160(pubkey_from_priv(page_key())))
        cls.key_script = "0014" + hash160(pubkey_from_priv(page_key())).hex()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        for s in cls.servers + [cls.pages]:
            s.shutdown()
            s.server_close()

    def open(self, path="/", wallet=True, blocked=False, url=None, width=1440, height=1000, psbt=None, answers=()):
        ctx = self.browser.new_context(viewport={"width": width, "height": height})
        self.addCleanup(ctx.close)
        page = ctx.new_page()
        page.errors, page.sent, said = [], [], list(answers)
        page.on("pageerror", lambda e: page.errors.append(f"pageerror: {e}"))
        page.on("console", lambda m: page.errors.append(f"console: {m.text}") if m.type == "error" and "Failed to load resource" not in m.text else None)
        page.dialogs = []

        def dialog(d):
            page.dialogs.append(d.message)
            d.accept(said.pop(0)) if d.type == "prompt" and said else d.accept()
        page.on("dialog", dialog)
        if wallet:
            page.expose_function("__hf_sign", lambda m: SIG)
            page.expose_function("__hf_send", lambda to, sats: page.sent.append((to, int(sats))) or "ab" * 32)
            page.expose_function("__hf_psbt", psbt or self.sign_psbt)
            page.add_init_script(MOCK_WALLET % {"addr": self.wallet_addr, "pub": self.wallet_pub.hex()})
        if blocked:
            page.add_init_script(BLOCKED_STORAGE)
        page.goto((url or self.url + "/fun") + path, wait_until="domcontentloaded")
        return page

    def connect(self, page):
        page.click("#wallet")
        page.wait_for_function("document.getElementById('wallet').textContent.startsWith('bcrt1q')")

    def sign_psbt(self, psbt_hex: str, pay_to=None) -> str:
        """The stand-in wallet: signs every input of the request with its key (P2WPKH) and returns it
        finalized, as wallets do. pay_to: a dishonest one that pays somebody else."""
        from hashfun.crypto import der_sig
        from hashfun.ser import Reader, Tx, bip143_sighash, p2wpkh_script_code, varint
        r = Reader(bytes.fromhex(psbt_hex))
        assert r.read(5) == b"psbt\xff"

        def kmap():
            out = {}
            while True:
                klen = r.varint()
                if klen == 0:
                    return out
                k = r.read(klen)
                out[k] = r.varbytes()
        tx = Tx.parse(kmap()[b"\x00"])
        utxos = [kmap()[b"\x01"] for _ in tx.vin]
        if pay_to:
            tx.vout[0].script_pubkey = pay_to
        kv = lambda t, v: varint(1) + bytes([t]) + varint(len(v)) + v  # noqa: E731
        out = b"psbt\xff" + kv(0, tx.serialize(witness=False)) + b"\x00"
        for n, u in enumerate(utxos):
            value = int.from_bytes(u[:8], "little")
            sig = der_sig(*ecdsa_sign(WALLET, bip143_sighash(tx, n, p2wpkh_script_code(self.wallet_pub), value))) + b"\x01"
            wit = b"\x02" + varint(len(sig)) + sig + varint(len(self.wallet_pub)) + self.wallet_pub
            out += kv(1, u) + kv(8, wit) + b"\x00"
        return (out + b"\x00" * len(tx.vout)).hex()

    def words(self):
        from hashfun import web
        return web.PITCH

    # ---- the pitch
    def test_board_opens_with_the_pitch_whole_at_first_then_one_line_never_gone(self):
        w = self.words()
        page = self.open(wallet=False)
        page.wait_for_selector("#pitch[data-open='1'] #pitch-pockets")
        self.assertEqual(page.inner_text("header .tagline"), w["tagline"])
        block = page.inner_text("#pitch")
        self.assertEqual(page.inner_text("#pitch-what").replace("\n", " ").upper(), w["what"].upper())
        for k in ("fact_chain", "fact_prices", "fact_holders", "why"):
            self.assertIn(w[k], block, k)
        self.assertEqual([page.inner_text(f"#pitch-facts [data-fact='{k}'] p") for k in ("fact_chain", "fact_prices", "fact_holders")],
                         [w["fact_chain"], w["fact_prices"], w["fact_holders"]])
        self.assertEqual(page.inner_text("#pitch-pockets"), w["pockets"].replace("{n}", "5"))
        self.assertEqual(page.get_attribute("#pitch-pockets a", "href"), "https://huggingface.co/staccs/qwencoin")
        self.assertEqual((page.inner_text("#way-mine").upper(), page.inner_text("#way-make").upper()), ("MINE A COIN", "MAKE A COIN"))
        self.assertTrue(page.get_attribute("#way-mine", "href").endswith("/mine"))
        self.assertEqual(page.get_attribute("#way-make", "href"), "#/launch")
        # above the coins: the block comes before the first card
        self.assertTrue(page.evaluate("document.getElementById('pitch').compareDocumentPosition(document.querySelector('a.card[href^=\"#/c/\"]')) & 4"))
        # afterwards: one line, with a way to open it again
        page.reload(wait_until="domcontentloaded")
        page.wait_for_selector("#pitch[data-open='0'] #pitch-open")
        line = page.inner_text("#pitch")
        self.assertIn(w["what"].upper(), line.replace("\n", " ").upper())
        self.assertIn(w["tagline"], line)
        self.assertEqual(page.locator("#pitch-facts").count(), 0)
        page.click("#pitch-open")
        page.wait_for_selector("#pitch[data-open='1'] #pitch-why")
        self.assertIn(w["why"], page.inner_text("#pitch"))
        page.click("#pitch-hide")
        page.wait_for_selector("#pitch[data-open='0']")
        self.assertEqual(page.errors, [])

    def test_the_block_shows_with_storage_blocked_and_the_page_still_works(self):
        w = self.words()
        page = self.open(blocked=True)
        page.wait_for_selector("#pitch[data-open='1'] #pitch-facts")
        self.assertIn(w["why"], page.inner_text("#pitch"))
        self.assertTrue(page.evaluate("(() => { try { window.localStorage; return false; } catch (e) { return true; } })()"))
        page.wait_for_selector("a.card[href='#/c/RIGCAT']")   # the board itself is there too
        page.reload(wait_until="domcontentloaded")
        page.wait_for_selector("#pitch[data-open='1'] #pitch-facts")   # nothing was remembered: whole again, never an error
        self.connect(page)   # the key lives as long as the page does
        page.goto(self.url + "/fun/#/c/RIGCAT/mine")
        page.wait_for_selector("#mineme")
        self.assertEqual(page.errors, [])

    def test_an_empty_board_is_the_pitch_and_the_way_to_make_the_first_coin(self):
        w = self.words()
        page = self.open(url=self.bare_url, wallet=False)
        page.wait_for_selector("#pitch[data-open='1'] #way-make")
        page.reload(wait_until="domcontentloaded")   # seen before, and still whole: there is nothing else to show
        page.wait_for_function("document.querySelector('#pitch[data-open=\"1\"]') && document.querySelector('#pitch').innerText.includes('No coin here yet')")
        self.assertIn(w["fact_chain"], page.inner_text("#pitch"))
        self.assertEqual((page.locator("#way-mine").count(), page.get_attribute("#way-make", "href")), (0, "#/launch"))
        self.assertEqual(page.locator("#pitch-pockets").count(), 0)   # this site was not told where the Qwencoin pages are
        self.assertEqual(page.errors, [])

    def test_a_coin_page_the_mine_panel_and_the_launch_form_say_their_words(self):
        w = self.words()
        page = self.open("/#/c/RIGCAT/mine")
        page.wait_for_selector("#coin-pitch")
        self.assertEqual(page.inner_text("#coin-pitch"), w["coin"].replace("{TICKER}", "$RIGCAT"))
        # under the name, and the two price points right after it
        order = page.evaluate("""() => { const all = [...document.querySelectorAll('h1, #coin-pitch, #price, #price-qwen, #blurb, svg')];
            return all.map((e) => e.id || e.tagName.toLowerCase()); }""")
        self.assertEqual(order[:4], ["h1", "coin-pitch", "price", "price-qwen"])
        page.wait_for_selector("#mine-pitch")
        self.assertEqual(page.inner_text("#mine-pitch"), w["mine"])
        page.goto(self.url + "/fun/#/launch")
        page.wait_for_selector("#launch-pitch")
        self.assertEqual((page.inner_text("#launch-pitch"), page.inner_text("#launch-honest")), (w["launch"], w["honest"]))
        self.assertEqual(page.inner_text("header .tagline"), w["tagline"])
        self.assertEqual(page.errors, [])

    # ---- two curves
    def test_the_board_and_a_coin_show_two_price_points_and_what_they_imply(self):
        from hashfun import web
        page = self.open(wallet=False)
        page.wait_for_selector("a.card[href='#/c/RIGCAT'] [data-point='qwen']")
        cv = self.site.coins["RIGCAT"].summary()["curves"]
        card = page.locator("a.card[href='#/c/RIGCAT']")
        self.assertEqual(card.locator("[data-point='btc']").inner_text(), f"{web.show_price(cv['btc']['price'])} sats per coin")
        self.assertEqual(card.locator("[data-point='qwen']").inner_text(), f"{web.show_price(cv['qwen']['price'])} QWEN sats per coin")
        kinds = {t: page.locator(f"a.card[href='#/c/{t}'] [data-implied]").get_attribute("data-implied") for t in self.launches}
        self.assertEqual(kinds, {"RIGCAT": "two-sided", "MOON": "floor", "QWAK": "ceiling", "FRESH": "start", "DONE": "history"})
        # QWEN site-wide: the median of the two-sided coins (here: one), and the book beside it
        v = self.site.qwen_view()
        page.wait_for_selector("#qwen-implied")
        self.assertEqual(page.inner_text("#qwen-implied").upper(), f"1 QWEN = {round(v['implied']['sats_per_qwen']):,}")
        self.assertEqual((page.inner_text("#qwen-bid"), page.inner_text("#qwen-ask")), ("240,000 sats", "260,000 sats"))
        self.assertIn("1 of 4 coins", page.inner_text("#qwen-strip"))
        page.goto(self.url + "/fun/#/c/RIGCAT")
        page.wait_for_selector("#implied-kind")
        self.assertEqual((page.inner_text("#price"), page.inner_text("#price-qwen")), (web.show_price(cv["btc"]["price"]), web.show_price(cv["qwen"]["price"])))
        self.assertEqual(page.inner_text("#implied-kind").lower(), "two-sided")
        self.assertEqual(page.inner_text("#implied-price").upper(), f"1 QWEN = {round(v['implied']['sats_per_qwen']):,}")
        self.assertEqual(page.locator("svg polyline[data-line]").count(), 2)
        self.assertEqual(sorted(page.locator("[data-progress]").evaluate_all("els => els.map((e) => e.dataset.progress)")), ["btc", "qwen"])
        sides = page.locator(".tr[data-on]").evaluate_all("els => els.map((e) => e.dataset.on)")
        self.assertTrue({"btc", "qwen"} <= set(sides))
        rows = page.locator(".tr[data-on='qwen']").all_inner_texts()
        self.assertTrue(any("QWEN ·" in r for r in rows) and not any(" sats ·" in r for r in rows))   # a QWEN-curve block pays QWEN
        page.goto(self.url + "/fun/#/c/MOON")
        page.wait_for_function("document.getElementById('implied-kind') && document.getElementById('implied-kind').innerText.toLowerCase() === 'floor'")
        self.assertIn("at least", page.inner_text("#implied"))
        page.goto(self.url + "/fun/#/c/DONE")
        page.wait_for_function("document.querySelector('[data-progress=\"btc\"]') && document.querySelector('[data-progress=\"btc\"]').innerText.includes('never minted')")
        self.assertIn("graduated the coin", page.inner_text("[data-progress='qwen']"))
        self.assertEqual(page.errors, [])

    def test_mining_from_the_page_on_the_curve_picked_and_paying_each_due_on_its_own_chain(self):
        from hashfun.ser import Tx
        page = self.open("/#/c/RIGCAT/mine")
        page.wait_for_selector("#curve-qwen")
        self.connect(page)
        before = len(self.site.pools.asked)
        page.click("#curve-qwen")
        page.wait_for_selector("#curve-qwen[aria-pressed='true']")
        self.assertIn("/qwen", page.inner_text("pre.code"))   # the stratum line follows the pick
        page.click("#mineme")
        page.wait_for_function("document.getElementById('toast').textContent.includes('QWEN curve')")
        page.click("#curve-btc")
        page.wait_for_selector("#curve-btc[aria-pressed='true']")
        page.click("#mineme")
        page.wait_for_function("document.getElementById('toast').textContent.includes('BTC curve')")
        self.assertEqual([a[3] for a in self.site.pools.asked[before:]], ["qwen", "btc"])
        # what the page's blocks owe, each on its own chain
        page.wait_for_selector("[data-dues='qwen'] #paydue-qwen")
        self.assertIn("0.00036 QWEN, on Qwencoin", page.inner_text("[data-dues='qwen']"))
        self.assertIn("12,400 sats, on Bitcoin", page.inner_text("[data-dues='btc']"))
        self.assertEqual(page.inner_text("#paydue").upper(), "PAY 12,400 SATS ON BITCOIN")
        self.assertEqual(page.inner_text("#paydue-qwen").upper(), "PAY 0.00036 QWEN ON QWENCOIN")
        self.assertIn(f"{self.key_addr}. Send QWEN there on Qwencoin first", page.inner_text("[data-dues='qwen']"))
        nb, nq = len(self.btc.sent), len(self.qwen.sent)
        page.click("#paydue-qwen")
        page.wait_for_function("document.getElementById('toast').textContent.includes('on Qwencoin')")
        self.assertEqual((len(self.btc.sent), len(self.qwen.sent)), (nb, nq + 1))   # paid on Qwencoin, and only there
        tx = Tx.parse(bytes.fromhex(self.qwen.sent[-1]))
        self.assertEqual([(o.value, o.script_pubkey.hex()) for o in tx.vout[:2]], [(15_000, "0014" + "02" * 20), (21_000, "0014" + "03" * 20)])
        self.assertEqual(tx.vout[2].script_pubkey.hex(), "6a2a" + b"HF".hex() + "cd" * 20 + "ef" * 20)   # output i is bound to block i
        self.assertEqual((tx.vout[2].value, tx.vout[3].script_pubkey.hex()), (0, self.key_script))   # change stays at the key, on Qwencoin
        spent = [(i.prev_txid[::-1].hex(), i.prev_vout) for i in tx.vin]
        self.assertTrue(all(self.qwen.utxos[op][0] == self.key_script for op in spent))
        page.click("#paydue")
        page.wait_for_function("document.getElementById('toast').textContent.includes('on Bitcoin')")
        self.assertEqual((len(self.btc.sent), len(self.qwen.sent)), (nb + 1, nq + 1))
        tx = Tx.parse(bytes.fromhex(self.btc.sent[-1]))
        self.assertEqual((tx.vout[0].value, tx.vout[0].script_pubkey.hex(), tx.vout[1].script_pubkey.hex()), (12_400, "0014" + "01" * 20, "6a16" + b"HF".hex() + "ab" * 20))
        self.assertTrue(all(self.btc.utxos[(i.prev_txid[::-1].hex(), i.prev_vout)][0] == self.key_script for i in tx.vin))
        self.assertEqual(page.sent, [])   # the wallet was not asked for anything
        self.assertEqual(page.errors, [])

    def test_the_book_trades_all_three_pairs_and_names_the_chain_of_every_address(self):
        page = self.open("/#/swap/btc/qwen")
        self.connect(page)
        page.wait_for_selector("button.offer")
        self.assertEqual(page.locator("#sw-pay option").all_inner_texts()[:2], ["Bitcoin (sats)", "Qwencoin (QWEN)"])
        self.assertIn("260,000 SATS PER QWEN", page.inner_text("button.offer").upper())
        self.assertIn("then 6 on Qwencoin", page.inner_text(".trade"))
        self.assertIn(f"arrives at your hashfun key on Qwencoin: {self.key_addr}", page.inner_text(".trade"))
        page.wait_for_function("document.getElementById('sw-bal').textContent.includes('on Qwencoin')")
        self.assertEqual(page.inner_text("#sw-bal"), "At your hashfun key: 61,234 sats on Bitcoin · 2.50 QWEN on Qwencoin")
        page.goto(self.url + "/fun/#/swap/qwen/RIGCAT")
        page.wait_for_selector("#qwen-deposit")
        self.assertIn("QWEN PER COIN", page.inner_text("button.offer").upper())   # the label is set in capitals
        self.assertIn(f"send QWEN on Qwencoin to {self.key_addr}", page.inner_text("#qwen-deposit"))
        page.wait_for_function("document.getElementById('sw-bal').textContent.includes('on Bitcoin')")
        self.assertEqual(page.inner_text("#sw-bal"), "At your hashfun key: 2.50 QWEN on Qwencoin · 61,234 sats on Bitcoin")
        page.goto(self.url + "/fun/#/c/RIGCAT")
        page.wait_for_selector("#tab-book")
        page.click("#tab-book")
        page.wait_for_selector("#book [data-book='qwen'] a[data-order]")
        self.assertEqual(page.locator("#book [data-book='btc'] a[data-order]").count(), 2)
        self.assertEqual(page.locator("#book [data-book='qwen'] a[data-order]").count(), 2)
        self.assertEqual(page.errors, [])

    def test_bags_show_the_key_on_both_chains_and_move_qwen_from_the_key_and_from_the_wallet(self):
        from hashfun.crypto import ecdsa_verify, hash160, parse_der
        from hashfun.ser import Tx, bip143_sighash, p2wpkh_script_code, segwit_encode
        there = "0014" + "9a" * 20
        to = segwit_encode("bcrt", 0, bytes.fromhex("9a" * 20))
        page = self.open("/#/bags", answers=[to, self.key_addr, to])
        self.connect(page)
        page.goto(self.url + "/fun/#/bags")
        page.wait_for_function("document.querySelector('[data-held=\"wallet-qwen\"]') && document.getElementById('yield').textContent !== '…'")
        self.assertEqual((page.inner_text("#yield"), page.inner_text("#yield-qwen")), ("61,234", "2.50"))
        self.assertIn(f"61,234 sats on Bitcoin", page.inner_text("[data-held='btc']"))
        self.assertIn(f"{self.key_addr} on Bitcoin", page.inner_text("[data-held='btc']"))
        self.assertIn("2.50 QWEN on Qwencoin", page.inner_text("[data-held='qwen']"))
        self.assertIn(f"{self.key_addr} on Qwencoin", page.inner_text("[data-held='qwen']"))   # the same string, each time with its chain
        self.assertIn("0.75 QWEN on Qwencoin", page.inner_text("[data-held='wallet-qwen']"))
        self.assertIn(f"{self.wallet_addr} on Qwencoin", page.inner_text("[data-held='wallet-qwen']"))
        # QWEN at the hashfun key: the page signs
        n = len(self.qwen.sent)
        page.click("#send-qwen")
        page.wait_for_function("document.getElementById('toast').textContent.includes('on Qwencoin')")
        tx = Tx.parse(bytes.fromhex(self.qwen.sent[-1]))
        self.assertEqual((len(self.qwen.sent), len(tx.vout), tx.vout[0].script_pubkey.hex()), (n + 1, 1, there))
        self.assertTrue(0 < int(2.5 * D.COIN) - tx.vout[0].value < 2000)
        # QWEN at the wallet's own address: the wallet signs a PSBT, the site's Qwencoin node gets the result
        page.click("#move-qwen")
        page.wait_for_function("document.getElementById('toast').textContent.includes('Sent 0.7')")
        tx = Tx.parse(bytes.fromhex(self.qwen.sent[-1]))
        self.assertEqual((len(self.qwen.sent), tx.vout[0].script_pubkey.hex()), (n + 2, self.key_script))   # to the hashfun key, the default
        wallet_script = "0014" + hash160(self.wallet_pub).hex()
        op = (tx.vin[0].prev_txid[::-1].hex(), tx.vin[0].prev_vout)
        self.assertEqual(self.qwen.utxos[op][0], wallet_script)
        r, s_ = parse_der(tx.vin[0].witness[0][:-1])
        self.assertTrue(ecdsa_verify(self.wallet_pub, bip143_sighash(tx, 0, p2wpkh_script_code(self.wallet_pub), self.qwen.utxos[op][1]), r, s_))
        self.assertTrue(any("UniSat will show it as a Bitcoin transaction" in d and "on Qwencoin" in d for d in page.dialogs))
        self.assertEqual(len(self.btc.sent), 0 if not self.btc.sent else len(self.btc.sent))
        self.assertEqual(page.errors, [])
        # a wallet that signs something else than it was asked: nothing is broadcast
        bad = self.open("/#/bags", answers=[to], psbt=lambda h: self.sign_psbt(h, pay_to=bytes.fromhex("0014" + "66" * 20)))
        self.connect(bad)
        bad.goto(self.url + "/fun/#/bags")
        bad.wait_for_selector("#move-qwen")
        n = len(self.qwen.sent)
        bad.click("#move-qwen")
        bad.wait_for_function("document.getElementById('toast').textContent.includes('different transaction')")
        self.assertEqual(len(self.qwen.sent), n)

    def test_a_site_reading_bitcoin_through_electrum_servers_says_so_once(self):
        page = self.open(wallet=False)
        page.wait_for_selector("#pitch")
        self.assertEqual(page.locator("#btc-source").count(), 0)   # a site with its own node says nothing

        def electrum(route):
            r = route.fetch()
            route.fulfill(response=r, json={**r.json(), "btc_source": "electrum"})
        page.route("**/api/config", electrum)
        page.reload(wait_until="domcontentloaded")
        page.wait_for_selector("#btc-source")
        self.assertEqual(page.inner_text("#btc-source"), "This site reads Bitcoin through Electrum servers, not a node of its own.")
        self.assertEqual(page.errors, [])

    def test_a_coin_s_preview_address_opens_the_coin_under_the_base_path(self):
        page = self.open("/c/RIGCAT", wallet=False)
        page.wait_for_selector("#coin-pitch")
        self.assertEqual(page.evaluate("location.pathname + location.hash"), "/fun/#/c/RIGCAT")
        self.assertIn("RIG CAT", page.inner_text("h1").upper())
        calls = []
        page.on("request", lambda r: calls.append(r.url))
        page.wait_for_timeout(1500)
        self.assertTrue(calls and all("/fun/api/" in u for u in calls if "/api/" in u))   # everything it asks for is under the prefix
        page.goto(self.url + "/fun/#/launch")
        page.wait_for_function("document.getElementById('qterms') && document.getElementById('qterms').textContent.includes('Qwencoin confirmations')")
        self.assertIn(f"{D.TEST_QWEN_CONFS} Qwencoin confirmations", page.inner_text("#qterms"))
        self.assertIn("as hard to fake as that many Qwencoin blocks are to mine", page.inner_text("#qterms"))
        self.assertEqual(page.errors, [])


if __name__ == "__main__":
    unittest.main()
