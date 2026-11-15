"""The browser's Bitcoin code (hashfun/web/src/btc.js) against the Python it mirrors: addresses,
HTLC scripts, signed redeem / refund / P2WPKH transactions, byte for byte. Needs node and the
web dependencies (cd hashfun/web && npm install); skipped otherwise."""
import hashlib
import json
import os
import random
import shutil
import subprocess
import unittest

from hashfun.crypto import ecdsa_sign, der_sig, pubkey_from_priv, sha256, sha256d, hash160
from hashfun.htlc import Contract, redeem_tx, refund_tx
from hashfun.ser import (Tx, TxIn, TxOut, segwit_encode, address_to_script, bip143_sighash, p2wpkh_script,
                         p2wpkh_script_code, b58check_encode)

WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def run_js(cases):
    p = subprocess.run(["node", os.path.join(WEB, "src", "vectors.mjs")], input=json.dumps(cases).encode(),
                       capture_output=True, timeout=120)
    if p.returncode:
        raise RuntimeError(p.stderr.decode()[-2000:])
    return json.loads(p.stdout)


@unittest.skipUnless(shutil.which("node") and os.path.isdir(os.path.join(WEB, "node_modules")),
                     "node or hashfun/web/node_modules missing")
class WebJsTest(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(int(os.environ.get("HFDIFF_SEED", "7")))

    def rb(self, n):
        return bytes(self.rng.getrandbits(8) for _ in range(n))

    def priv(self):
        return self.rng.randrange(1, N)

    def test_addresses(self):
        cases, want = [], []
        for _ in range(60):
            hrp = self.rng.choice(["bc", "bcrt", "tb", "flt", "rigcat", "a1"])
            ver = self.rng.choice([0, 0, 1, 1, 2, 16])
            prog = self.rb(self.rng.choice([20, 32]) if ver == 0 else 32 if ver == 1 else self.rng.randint(2, 40))
            addr = segwit_encode(hrp, ver, prog)
            cases.append({"op": "addr", "hrp": hrp, "ver": ver, "prog": prog.hex()})
            want.append({"addr": addr, "script": address_to_script(addr, hrp).hex(), "back": addr})
        for _ in range(10):
            ver = self.rng.choice([0, 5])
            addr = b58check_encode(bytes([ver]) + self.rb(20))
            cases.append({"op": "legacy", "addr": addr, "p2pkh": 0, "p2sh": 5})
            want.append({"script": address_to_script(addr, "bc", 0, 5).hex()})
        self.assertEqual(run_js(cases), want)

    def test_bad_addresses_rejected(self):
        good = segwit_encode("bc", 0, self.rb(20))
        bad = [good[:-1] + ("q" if good[-1] != "q" else "p"), good.replace("bc1", "tb1"), good[:10] + "B" + good[11:],
               segwit_encode("bc", 1, self.rb(32))[:-6] + good[-6:]]
        out = run_js([{"op": "legacy", "addr": a, "p2pkh": 0, "p2sh": 5} for a in bad])
        self.assertTrue(all("error" in o for o in out), out)

    def contract(self):
        secret = self.rb(32)
        rk, fk = self.priv(), self.priv()
        lt = self.rng.choice([self.rng.randint(1_600_000_000, 2_100_000_000), self.rng.randint(2**31, 2**32 - 1),
                              self.rng.randint(17, 500_000), 0x7FFFFFFF, 0x80, 0x7F, 0x8000, 0xFFFF])
        return Contract(sha256(secret), pubkey_from_priv(rk), pubkey_from_priv(fk), lt), secret, rk, fk

    @staticmethod
    def cj(c):
        return {"h": c.secret_hash.hex(), "rpub": c.recipient_pub.hex(), "fpub": c.refund_pub.hex(), "locktime": c.locktime}

    def test_contract_scripts(self):
        cases, want = [], []
        for _ in range(60):
            c, _, _, _ = self.contract()
            cases.append({"op": "contract", "contract": self.cj(c)})
            want.append({"script": c.script().hex(), "spk": c.script_pubkey().hex(), "locktime": c.locktime,
                         "rpub": c.recipient_pub.hex(), "fpub": c.refund_pub.hex(), "h": c.secret_hash.hex()})
        self.assertEqual(run_js(cases), want)

    def test_parse_rejects_what_python_rejects(self):
        c, _, _, _ = self.contract()
        s = c.script()
        muts = [s[:-1], s + b"\x00", bytes([s[0] ^ 1]) + s[1:], s[:74] + b"\x68" + s[75:], s[:2] + b"\x01\x21" + s[4:],
                s[:40] + b"\x20" + s[41:], b"", s[:60]]
        for i in range(40):
            j = self.rng.randrange(len(s))
            muts.append(s[:j] + bytes([s[j] ^ (1 << self.rng.randrange(8))]) + s[j + 1:])
        py = []
        for m in muts:
            try:
                Contract.parse(m)
                py.append(True)
            except ValueError:
                py.append(False)
        js = ["error" not in o for o in run_js([{"op": "parse", "script": m.hex()} for m in muts])]
        self.assertEqual(js, py)

    def test_htlc_spends(self):
        cases, want = [], []
        for _ in range(40):
            c, secret, rk, fk = self.contract()
            txid, vout = self.rb(32), self.rng.randrange(4)
            amount, fee = self.rng.randint(20_000, 10**12), self.rng.randint(200, 5000)
            dest = p2wpkh_script(pubkey_from_priv(self.priv()))
            base = {"contract": self.cj(c), "txid": txid[::-1].hex(), "vout": vout, "amount": amount, "dest": dest.hex(), "fee": fee}
            r = redeem_tx(c, txid, vout, amount, dest, fee, rk, secret)
            cases.append({**base, "op": "redeem", "priv": f"{rk:064x}", "secret": secret.hex()})
            want.append({"hex": r.serialize().hex(), "txid": r.txid_hex()})
            f = refund_tx(c, txid, vout, amount, dest, fee, fk)
            cases.append({**base, "op": "refund", "priv": f"{fk:064x}"})
            want.append({"hex": f.serialize().hex(), "txid": f.txid_hex()})
        self.assertEqual(run_js(cases), want)

    def test_wrong_key_or_secret_refused(self):
        c, secret, rk, fk = self.contract()
        base = {"contract": self.cj(c), "txid": "11" * 32, "vout": 0, "amount": 100_000, "dest": "0014" + "22" * 20, "fee": 500}
        out = run_js([{**base, "op": "redeem", "priv": f"{fk:064x}", "secret": secret.hex()},
                      {**base, "op": "redeem", "priv": f"{rk:064x}", "secret": (bytes(32)).hex()},
                      {**base, "op": "refund", "priv": f"{rk:064x}"},
                      {**base, "op": "redeem", "priv": f"{rk:064x}", "secret": secret.hex(), "fee": 100_000}])
        self.assertTrue(all("error" in o for o in out), out)

    def test_p2wpkh_spends(self):
        cases, want = [], []
        for _ in range(30):
            k = self.priv()
            pub = pubkey_from_priv(k)
            utxos = [{"txid": self.rb(32).hex(), "vout": self.rng.randrange(5), "value": self.rng.randint(1000, 10**11)}
                     for _ in range(self.rng.randint(1, 4))]
            outs = [TxOut(self.rng.randint(546, 10**10), self.rng.choice([p2wpkh_script(pubkey_from_priv(self.priv())),
                                                                         b"\x51\x20" + self.rb(32), b"\x00\x20" + self.rb(32)]))
                    for _ in range(self.rng.randint(1, 3))]
            tx = Tx(version=2, vin=[TxIn(bytes.fromhex(u["txid"])[::-1], u["vout"], b"", 0xFFFFFFFD) for u in utxos], vout=outs)
            for i, u in enumerate(utxos):
                sig = der_sig(*ecdsa_sign(k, bip143_sighash(tx, i, p2wpkh_script_code(pub), u["value"]))) + b"\x01"
                tx.vin[i].witness = [sig, pub]
            cases.append({"op": "p2wpkh", "priv": f"{k:064x}", "utxos": utxos,
                          "outputs": [{"value": o.value, "script": o.script_pubkey.hex()} for o in outs]})
            want.append({"hex": tx.serialize().hex(), "txid": tx.txid_hex(), "pub": pub.hex()})
        self.assertEqual(run_js(cases), want)

    def test_key_from_signature(self):
        sigs = ["H" + hashlib.sha256(bytes([i])).hexdigest() + "=" for i in range(8)]
        want = []
        for s in sigs:
            k = sha256(b"hashfun-key-v1" + s.encode())
            while not 1 <= int.from_bytes(k, "big") < N:
                k = sha256(k)
            want.append({"key": k.hex()})
        self.assertEqual(run_js([{"op": "key", "sig": s} for s in sigs]), want)
        self.assertEqual(len({w["key"] for w in want}), len(sigs))
        self.assertTrue(sha256d(b"") and hash160(b""))

    def test_committed_bundle_is_built_from_these_sources(self):
        """static/app.js is what the site serves and what ships in the npm package: it must be the
        build of src/ as it stands (a stale bundle once hid a fix from the browser test)."""
        import tempfile
        esbuild = os.path.join(WEB, "node_modules", ".bin", "esbuild")
        if not os.path.exists(esbuild):
            self.skipTest("esbuild not installed")
        builds = (("static/app.js", ["src/app.js", "--bundle", "--minify", "--format=iife", "--target=es2020"]),
                  ("maker.cjs", ["src/maker.mjs", "--bundle", "--platform=node", "--format=cjs", "--target=node18"]))
        with tempfile.TemporaryDirectory() as tmp:
            for committed, args in builds:
                out = os.path.join(tmp, os.path.basename(committed))
                subprocess.run([esbuild, *args, "--outfile=" + out, "--log-level=error"], cwd=WEB, check=True, timeout=120)
                with open(out, "rb") as a, open(os.path.join(WEB, committed), "rb") as b:
                    self.assertEqual(hashlib.sha256(a.read()).hexdigest(), hashlib.sha256(b.read()).hexdigest(),
                                     f"{committed} is stale: cd hashfun/web && npm run build")

    def test_sources_lint_clean(self):
        """A name used before its declaration in the same scope throws only when that line runs
        (it once sat in the offer form, where no unit test reaches). The linter sees it statically."""
        eslint = os.path.join(WEB, "node_modules", ".bin", "eslint")
        if not os.path.exists(eslint):
            self.skipTest("eslint not installed")
        p = subprocess.run(["npm", "run", "--silent", "lint"], cwd=WEB, capture_output=True, timeout=180)
        self.assertEqual(p.returncode, 0, (p.stdout + p.stderr).decode()[-2000:])

    def test_metadata_hash(self):
        from hashfun import meta as M
        cases, want = [], []
        for i in range(24):
            head = self.rng.choice([b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff\xe0", b"GIF89a", b"RIFF\x00\x00\x00\x00WEBP", b""])
            image = head + self.rb(self.rng.choice([0, 20, 300, 70000 - len(head)]) if head else 0)
            m = M.Meta(description=self.rng.choice(["", "rig cat", "λ ✓ two\nlines", "x" * 500]), image=image,
                       image_type=M.image_type_of(image) or "", website=self.rng.choice(["", "https://a.example/b?c=d"]),
                       x=self.rng.choice(["", "https://x.com/rigcat"]), telegram=self.rng.choice(["", "https://t.me/rigcat"]))
            cases.append({"op": "meta", "meta": {"description": m.description, "image_type": m.image_type, "image": image.hex(),
                                                 "website": m.website, "x": m.x, "telegram": m.telegram}})
            want.append({"hash": m.hash().hex(), "type": M.image_type_of(image), "b64": m.to_json().get("image", "")})
        self.assertEqual(run_js(cases), want)

    def test_signed_text_both_ways(self):
        from hashfun import book as K
        texts = ["hashfun-alive-v1\n02ab\n1800000000", "x", "λ\nline two", "a" * 400]
        keys = [self.priv() for _ in texts]
        out = run_js([{"op": "sign", "priv": f"{k:064x}", "text": t} for k, t in zip(keys, texts)])
        for k, t, o in zip(keys, texts, out):   # the page signs, the board verifies
            self.assertTrue(o["ok"])
            self.assertTrue(K.verify(pubkey_from_priv(k).hex(), t, o["sig"]), t)
            self.assertFalse(K.verify(pubkey_from_priv(k).hex(), t + "!", o["sig"]))
            self.assertFalse(K.verify(pubkey_from_priv(keys[0] + 1).hex(), t, o["sig"]))
        cases, want = [], []
        for k, t in zip(keys, texts):           # the other side signs (here: Python), the page verifies
            r, s_ = ecdsa_sign(k, sha256d(t.encode()))
            sig, pub = f"{r:064x}{s_:064x}", pubkey_from_priv(k).hex()
            cases += [{"op": "verify", "pub": pub, "text": t, "sig": sig}, {"op": "verify", "pub": pub, "text": t + " ", "sig": sig},
                      {"op": "verify", "pub": pub, "text": t, "sig": sig[:-2] + ("00" if sig[-2:] != "00" else "01")},
                      {"op": "verify", "pub": pub, "text": t, "sig": "zz"}]
            want += [{"ok": True}, {"ok": False}, {"ok": False}, {"ok": False}]
        self.assertEqual(run_js(cases), want)

    def test_book_texts_and_ids(self):
        from hashfun import book as K
        cases, want = [], []
        for _ in range(20):
            o = {"maker": pubkey_from_priv(self.priv()).hex(), "give": self.rb(32).hex(), "give_amount": self.rng.randint(1, 21 * 10**14),
                 "get": self.rng.choice(["btc:main", "btc:regtest", self.rb(32).hex()]), "get_amount": self.rng.randint(1, 21 * 10**14),
                 "min_get": self.rng.randint(1, 10**9), "expiry": self.rng.randint(1, 2**32 - 1), "nonce": self.rb(8).hex(),
                 "lock": self.rng.randint(600, 86400), "confs": self.rng.randint(0, 100)}
            t = {"order": K.text_id(K.order_text(o)), "taker": pubkey_from_priv(self.priv()).hex(),
                 "get_amount": self.rng.randint(1, o["get_amount"]), "secret_hash": self.rb(32).hex(),
                 "locktime": self.rng.randint(500_000_000, 2**32 - 1), "ts": self.rng.randint(0, 2**32 - 1)}
            body = self.rng.choice([{}, {"until": 1800000000}, {"why": "too late"}, {"vout": 1, "txid": "ab" * 32, "contract": "6382"}])
            fill, kind, ts = K.text_id(K.take_text(t)), self.rng.choice(["accept", "locked", "fail"]), self.rng.randint(0, 2**32 - 1)
            cases.append({"op": "book", "order": o, "take": t, "fill": fill, "kind": kind, "body": body, "maker": o["maker"], "ts": ts,
                          "order_id": t["order"]})
            want.append({"order": K.order_text(o), "take": K.take_text(t), "note": K.note_text(fill, kind, body),
                         "alive": K.alive_text(o["maker"], ts), "cancel": K.cancel_text(t["order"]), "id": t["order"],
                         "give": K.give_for(o, t["get_amount"])})
        self.assertEqual(run_js(cases), want)

    # ---------------------------------------------------------------- Qwencoin in the page
    def test_engine_names_three_kinds_of_chain(self):
        """Bitcoin, Qwencoin and the launches, as the swap engine names them: in the API, in what it
        signs, and as addresses. A key has one address string on Bitcoin and on Qwencoin."""
        priv = self.priv()
        cat = {"id": "ab" * 32, "hrp": "cat", "target_spacing": 5}
        cfg = {"btc_id": "btc:main", "qwen_id": "qwen:main", "btc": {"chain": "main", "hrp": "bc"}, "qwen": {"chain": "main", "hrp": "bc"},
               "launches": {"CAT": cat}, "book": {"confs": 6, "lock": 14400}}
        key = hash160(pubkey_from_priv(priv))
        both, only_btc = run_js([{"op": "engine", "priv": f"{priv:064x}", "cfg": c, "names": ["btc", "qwen", "CAT"]}
                                 for c in (cfg, {**cfg, "qwen": None, "qwen_id": None})])
        self.assertEqual(both["btc"], {"id": "btc:main", "back": "btc", "addr": segwit_encode("bc", 0, key), "confs": 1, "label": "sats", "outside": True})
        self.assertEqual(both["qwen"], {"id": "qwen:main", "back": "qwen", "addr": segwit_encode("bc", 0, key), "confs": 6, "label": "QWEN", "outside": True})
        self.assertEqual(both["CAT"], {"id": "ab" * 32, "back": "CAT", "addr": segwit_encode("cat", 0, key), "confs": 6, "label": "$CAT", "outside": False})
        self.assertEqual(both["btc"]["addr"], both["qwen"]["addr"])   # which is why the chain is named beside every address
        self.assertEqual((only_btc["qwen"]["id"], only_btc["qwen"]["addr"]), (None, "error: this site has no Qwencoin node"))
        self.assertEqual(only_btc["btc"], both["btc"])

    @staticmethod
    def _kv(type_: int, value: bytes, keydata: bytes = b"") -> bytes:
        from hashfun.ser import varint
        return varint(1 + len(keydata)) + bytes([type_]) + keydata + varint(len(value)) + value

    def test_psbt_request_is_bip174(self):
        """What the page hands a wallet to sign (QWEN at the wallet's own address): the unsigned
        transaction and, per input, the output it spends, plus what each address kind needs."""
        from hashfun.ser import varint
        pub = pubkey_from_priv(self.priv())
        dest = p2wpkh_script(pubkey_from_priv(self.priv()))
        scripts = {"p2wpkh": p2wpkh_script(pub), "p2sh": b"\xa9\x14" + hash160(p2wpkh_script(pub)) + b"\x87", "p2tr": b"\x51\x20" + self.rb(32)}
        cases, want = [], []
        for kind, script in scripts.items():
            ins = [{"txid": self.rb(32).hex(), "vout": self.rng.randint(0, 5), "value": self.rng.randint(10_000, 10**9)} for _ in range(self.rng.randint(1, 4))]
            outs = [{"value": sum(i["value"] for i in ins) - 500, "script": dest.hex()}]
            tx = Tx(version=2, vin=[TxIn(bytes.fromhex(i["txid"])[::-1], i["vout"], b"", 0xfffffffd) for i in ins],
                    vout=[TxOut(o["value"], bytes.fromhex(o["script"])) for o in outs])
            extra = {"p2wpkh": b"", "p2sh": self._kv(4, p2wpkh_script(pub)), "p2tr": self._kv(0x17, pub[1:])}[kind]
            utxo = lambda i: i["value"].to_bytes(8, "little") + varint(len(script)) + script  # noqa: E731
            psbt = b"psbt\xff" + self._kv(0, tx.serialize(witness=False)) + b"\x00" + \
                b"".join(self._kv(1, utxo(i)) + extra + b"\x00" for i in ins) + b"\x00" * len(outs)
            cases.append({"op": "psbt", "inputs": ins, "script": script.hex(), "outputs": outs, "pub": pub.hex()})
            want.append({"psbt": psbt.hex(), "kind": kind})
        self.assertEqual(run_js(cases), want)
        legacy = b"\x76\xa9\x14" + self.rb(20) + b"\x88\xac"
        other = b"\xa9\x14" + self.rb(20) + b"\x87"   # a script hash that is not this key's wrapped segwit
        bad = run_js([{"op": "psbt", "inputs": [{"txid": "00" * 32, "vout": 0, "value": 9000}], "script": x.hex(),
                       "outputs": [{"value": 8000, "script": dest.hex()}], "pub": pub.hex()} for x in (legacy, other)])
        self.assertIn("legacy", bad[0]["error"])
        self.assertIn("not a wrapped segwit address", bad[1]["error"])

    def test_psbt_answer_is_read_back_and_checked(self):
        """What comes back from the wallet: finalized (as wallets return it), or a bare signature.
        The page broadcasts only a transaction that spends and pays exactly what it asked for."""
        from hashfun.ser import varint
        priv = self.priv()
        pub = pubkey_from_priv(priv)
        script, dest = p2wpkh_script(pub), p2wpkh_script(pubkey_from_priv(self.priv()))
        ins = [{"txid": self.rb(32).hex(), "vout": 1, "value": 70_000}, {"txid": self.rb(32).hex(), "vout": 0, "value": 30_000}]
        outs = [{"value": 99_000, "script": dest.hex()}]
        tx = Tx(version=2, vin=[TxIn(bytes.fromhex(i["txid"])[::-1], i["vout"], b"", 0xfffffffd) for i in ins],
                vout=[TxOut(99_000, dest)])
        sigs = []
        for n, i in enumerate(ins):
            r, s_ = ecdsa_sign(priv, bip143_sighash(tx, n, p2wpkh_script_code(pub), i["value"]))
            sigs.append(der_sig(r, s_) + b"\x01")
        head = b"psbt\xff" + self._kv(0, tx.serialize(witness=False)) + b"\x00"
        utxo = lambda i: self._kv(1, i["value"].to_bytes(8, "little") + varint(len(script)) + script)  # noqa: E731
        wit = lambda sig: b"\x02" + varint(len(sig)) + sig + varint(len(pub)) + pub  # noqa: E731
        final = head + b"".join(utxo(i) + self._kv(8, wit(s_)) + b"\x00" for i, s_ in zip(ins, sigs)) + b"\x00"
        partial = head + b"".join(utxo(i) + self._kv(2, s_, pub) + b"\x00" for i, s_ in zip(ins, sigs)) + b"\x00"
        signed = Tx(version=2, vin=[TxIn(bytes.fromhex(i["txid"])[::-1], i["vout"], b"", 0xfffffffd, [s_, pub]) for i, s_ in zip(ins, sigs)],
                    vout=[TxOut(99_000, dest)])
        want = {"hex": signed.serialize().hex(), "txid": signed.txid_hex(), "same": True}
        wrapped = b"\x16" + p2wpkh_script(pub)   # a wrapped-segwit input also has a scriptSig: the push of its redeem script
        nested = head + b"".join(utxo(i) + self._kv(7, wrapped) + self._kv(8, wit(s_)) + b"\x00" for i, s_ in zip(ins, sigs)) + b"\x00"
        nested_tx = Tx(version=2, vin=[TxIn(bytes.fromhex(i["txid"])[::-1], i["vout"], wrapped, 0xfffffffd, [s_, pub]) for i, s_ in zip(ins, sigs)],
                       vout=[TxOut(99_000, dest)])
        unsigned = head + b"".join(utxo(i) + b"\x00" for i in ins) + b"\x00"
        elsewhere = [{"value": 99_000, "script": p2wpkh_script(pubkey_from_priv(self.priv())).hex()}]
        got = run_js([{"op": "unpsbt", "psbt": final.hex(), "inputs": ins, "outputs": outs},
                      {"op": "unpsbt", "psbt": partial.hex(), "inputs": ins, "outputs": outs},
                      {"op": "unpsbt", "psbt": nested.hex(), "inputs": ins, "outputs": outs},
                      {"op": "unpsbt", "psbt": final.hex(), "inputs": ins, "outputs": elsewhere},        # pays somebody else
                      {"op": "unpsbt", "psbt": final.hex(), "inputs": ins[::-1], "outputs": outs},       # spends something else
                      {"op": "unpsbt", "psbt": final.hex(), "inputs": ins, "outputs": [{"value": 98_000, "script": dest.hex()}]},
                      {"op": "unpsbt", "psbt": unsigned.hex(), "inputs": ins, "outputs": outs},
                      {"op": "unpsbt", "psbt": "00" * 40, "inputs": ins, "outputs": outs}])
        self.assertEqual(got[0], want)
        self.assertEqual(got[1], want)
        self.assertEqual(got[2], {"hex": nested_tx.serialize().hex(), "txid": nested_tx.txid_hex(), "same": True})
        self.assertEqual([g.get("same") for g in got[3:6]], [False, False, False])
        self.assertEqual([g.get("error") for g in got[6:]], ["the wallet did not return a signed transaction"] * 2)

    # ---------------------------------------------------------------- the pitch
    def test_the_pitch_is_said_in_the_source_s_words(self):
        """contrib/hashfun/PITCH.md is the one source. The page is built with static/pitch.json,
        which must be that table word for word; the page takes each place's text from it; and the
        built page carries the words (a bundle that lost them would say nothing to anyone)."""
        import re
        root = os.path.dirname(os.path.dirname(WEB))
        with open(os.path.join(root, "contrib", "hashfun", "PITCH.md"), encoding="utf-8") as f:
            table = dict(re.findall(r"^\| `(\w+)` \| (.+?) \|$", f.read(), re.M))
        with open(os.path.join(WEB, "static", "pitch.json"), encoding="utf-8") as f:
            words = json.load(f)
        self.assertEqual(words, table)
        self.assertEqual(sorted(words), sorted(["tagline", "what", "oneliner", "fact_chain", "fact_prices", "fact_holders", "why",
                                                "pockets", "coin", "mine", "launch", "honest"]))
        with open(os.path.join(WEB, "src", "app.js"), encoding="utf-8") as f:
            src = f.read()
        for place, uses in {"the board's block": ["PITCH.what", "'fact_chain'", "'fact_prices'", "'fact_holders'", "PITCH.why", "PITCH.pockets",
                                                    "PITCH.tagline", "id: 'way-mine'", "id: 'way-make'"],
                            "a coin's page": ["PITCH.coin"], "the mine panel": ["PITCH.mine"],
                            "the launch form": ["PITCH.launch", "PITCH.honest"]}.items():
            for u in uses:
                self.assertIn(u, src, f"{place}: {u}")
        with open(os.path.join(WEB, "static", "app.js"), encoding="utf-8") as f:
            bundle = f.read()
        for k, text in words.items():
            if k == "oneliner":   # said by the server, in the link-preview tags
                continue
            for piece in re.split(r"\{\w+\}", text):
                self.assertIn(json.dumps(piece, ensure_ascii=False)[1:-1], bundle, k)
        with open(os.path.join(WEB, "static", "index.html"), encoding="utf-8") as f:
            page = f.read()
        self.assertIn('<span class="m tagline">{{tagline}}</span>', page)   # beside the name, on every page; web.py fills it in
        self.assertIn("<title>{{title}}</title>", page)
        self.assertIn("{{tags}}", page)

    def test_nothing_the_site_says_has_an_em_dash(self):
        root = os.path.dirname(WEB)
        files = [os.path.join(WEB, "src", n) for n in ("app.js", "book.js", "btc.js", "maker.mjs", "share.html", "share.py")] + \
            [os.path.join(WEB, "static", n) for n in ("index.html", "style.css", "pitch.json", "app.js")] + \
            [os.path.join(WEB, "maker.cjs"), os.path.join(root, "web.py"), os.path.join(root, "book.py")]
        for path in files:
            with open(path, encoding="utf-8") as f:
                self.assertNotIn("—", f.read(), path)


if __name__ == "__main__":
    unittest.main()
