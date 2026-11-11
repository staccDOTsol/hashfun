"""Launch metadata (meta.py) and the peer-to-peer order book's server side (book.py)."""
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


if __name__ == "__main__":
    unittest.main()
