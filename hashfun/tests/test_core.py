"""Unit tests: crypto/serialization vectors, the consensus model (curve, graduation,
tail, LWMA), descriptor identity + genesis, HTLC scripts, AuxPoW construction.
Run: python -m unittest discover -s hashfun/tests -v"""
import random
import unittest

from hashfun import descriptor as D
from hashfun.auxpow import AuxTree, serialize_auxpow, check_auxpow, expected_index
from hashfun.crypto import (XPriv, ecdsa_sign, ecdsa_verify, der_sig, parse_der, pubkey_from_priv, sha256, sha256d,
                            _ripemd160_py, ripemd160)
from hashfun.htlc import Contract, new_secret, redeem_tx, refund_tx, extract_secret
from hashfun.interp import verify_input, ScriptError
from hashfun.ser import (Tx, TxIn, TxOut, bip143_sighash, segwit_encode, segwit_decode, b58check_encode,
                         bits_to_target, target_to_bits, work_from_bits, p2wpkh_script, merkle_root,
                         merkle_branch_for_first, header_bytes, push, push_int)
from hashfun.wallet import mnemonic_to_seed, new_mnemonic, check_mnemonic

COIN = 100_000_000


def test_launch(**kw):
    base = dict(name="Test Launch", ticker="TST", genesis_time=1_800_000_000, virtual_work=71,
                virtual_tokens=15_000_000 * COIN, graduation_tokens=11_086_000 * COIN, pow_limit_bits=0x207FFFFF,
                target_spacing=60, lwma_window=10, ftl=60, tail_reward=10 * COIN, tail_halving_interval=1000,
                creator_script=bytes.fromhex("0014" + "11" * 20), creator_fee_bps=100, test=True, hrp="tst",
                btc_anchor_header=D.REGTEST_GENESIS_HEADER, sats_num=5000, creator_btc_script=D.TEST_BTC_SCRIPT)
    base.update(kw)
    d = D.Launch(**base)
    D.validate(d)
    return d


class Vectors(unittest.TestCase):
    def test_bip32_tv1(self):
        m = XPriv.from_seed(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
        self.assertEqual(b58check_encode(m.serialize()),
                         "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        self.assertEqual(b58check_encode(m.derive("m/0'/1/2'/2/1000000000").serialize()),
                         "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")

    def test_bip39_trezor_vector(self):
        m = "abandon " * 11 + "about"
        self.assertTrue(check_mnemonic(m))
        self.assertEqual(mnemonic_to_seed(m, "TREZOR").hex(),
                         "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")
        for _ in range(5):
            self.assertTrue(check_mnemonic(new_mnemonic()))
        self.assertFalse(check_mnemonic("abandon " * 12))

    def test_bech32(self):
        a = segwit_encode("bc", 0, bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6"))
        self.assertEqual(a, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        self.assertEqual(segwit_decode("bc", a)[1].hex(), "751e76e8199196d454941c45d1b3a323f1433bd6")
        self.assertIsNone(segwit_decode("tb", a))

    def test_ripemd_fallback(self):
        for m in (b"", b"abc", bytes(range(256)) * 3):
            self.assertEqual(_ripemd160_py(m), ripemd160(m))

    def test_ecdsa(self):
        for k in (1, 2, 12345, 2**200 + 7):
            h = sha256(k.to_bytes(32, "big"))
            r, s = ecdsa_sign(k, h)
            self.assertLessEqual(s, D.MAX_MONEY * 0 + (2**256 - 1))
            self.assertTrue(ecdsa_verify(pubkey_from_priv(k), h, r, s))
            self.assertEqual(parse_der(der_sig(r, s)), (r, s))
            self.assertFalse(ecdsa_verify(pubkey_from_priv(k + 1), h, r, s))

    def test_bip143_native_p2wpkh(self):
        tx = Tx.parse(bytes.fromhex(
            "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"))
        code = bytes.fromhex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac")
        self.assertEqual(bip143_sighash(tx, 1, code, 600000000).hex(),
                         "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")

    def test_compact(self):
        for bits in (0x1D00FFFF, 0x207FFFFF, 0x1B0404CB, 0x170331DB):
            self.assertEqual(target_to_bits(bits_to_target(bits)), bits)
        self.assertEqual(work_from_bits(0x1D00FFFF), 0x100010001)


class Curve(unittest.TestCase):
    def test_graduation_threshold_exact(self):
        for _ in range(200):
            v0 = random.randint(1, 2**80)
            t0 = random.randint(10**6, 21 * 10**14)
            g = random.randint(1, t0 - max(1, t0 // 1000))
            d = test_launch(virtual_work=v0, virtual_tokens=t0, graduation_tokens=g)
            wg = d.graduation_work
            self.assertGreaterEqual(t0 * wg // (v0 + wg), g)
            self.assertLess(t0 * (wg - 1) // (v0 + wg - 1), g)

    def test_path_independent_issuance(self):
        d = test_launch()
        for _ in range(20):
            w, minted = 0, 0
            bits_choices = [0x207FFFFF, 0x2007FFFF, 0x1F7FFFFF, 0x1F0FFFFF]
            while w < d.graduation_work * 1.2:
                b = random.choice(bits_choices)
                minted += d.subsidy(w, b, 5)
                w += work_from_bits(b)
                if w >= d.graduation_work:
                    break
            self.assertEqual(minted, d.curve_supply(w))
            if w >= d.graduation_work:
                self.assertEqual(minted, d.graduation_tokens)

    def test_reward_proportional_to_work_and_price_rises(self):
        d = test_launch()
        w = 0
        last_ppw = None
        while w < d.graduation_work // 2:
            s = d.subsidy(w, 0x207FFFFF, 5)
            ppw = work_from_bits(0x207FFFFF) / max(s, 1)
            if last_ppw is not None:
                self.assertGreaterEqual(ppw, last_ppw * 0.999)
            last_ppw = ppw
            w += work_from_bits(0x207FFFFF)
        self.assertLess(d.hashes_per_coin(0), d.hashes_per_coin(d.graduation_work))

    def test_tail_after_graduation(self):
        d = test_launch()
        wg = d.graduation_work
        self.assertEqual(d.subsidy(wg, 0x207FFFFF, 999), 10 * COIN)
        self.assertEqual(d.subsidy(wg, 0x207FFFFF, 1000), 5 * COIN)
        self.assertEqual(d.subsidy(wg + 10**30, 0x1D00FFFF, 1), 10 * COIN)

    def test_no_overflow_bounds(self):
        # worst case allowed by validation: V0 = 2^160, G = 99.9% of T0, T0 = MAX_MONEY
        t0 = D.MAX_MONEY
        g = t0 - t0 // 1000
        d = test_launch(virtual_work=2**160, virtual_tokens=t0, graduation_tokens=g, tail_reward=0,
                        tail_halving_interval=0)
        self.assertLess(t0 * d.graduation_work, 2**256)
        self.assertLess(g * d.virtual_work, 2**256)

    def test_creator_fee(self):
        d = test_launch()
        self.assertEqual(d.creator_fee(10_000), 100)
        self.assertEqual(d.creator_fee(0), 0)


class Lwma(unittest.TestCase):
    def chain(self, d, n, spacing_fn, start_bits=None):
        ts, bits = [d.genesis_time], [d.pow_limit_bits]
        for i in range(1, n):
            b = d.lwma_next_bits(ts, bits)
            bits.append(b)
            ts.append(ts[-1] + spacing_fn(i, b))
        return ts, bits

    def test_capped_at_pow_limit_and_overflow_guard(self):
        d = test_launch(pow_limit_bits=0x207FFFFF, lwma_window=10)
        ts, bits = self.chain(d, 40, lambda i, b: 6000)
        self.assertTrue(all(bits_to_target(b) <= bits_to_target(0x207FFFFF) for b in bits))
        self.assertEqual(bits[-1], 0x207FFFFF)

    def test_fast_blocks_raise_difficulty_slow_lower(self):
        d = test_launch(pow_limit_bits=0x1F00FFFF, lwma_window=10, target_spacing=60)
        ts, bits = self.chain(d, 30, lambda i, b: 6)
        self.assertGreater(work_from_bits(bits[-1]), 5 * work_from_bits(bits[1]))
        hard = bits[-1]
        ts2, bits2 = list(ts), list(bits)
        for _ in range(30):
            b = d.lwma_next_bits(ts2, bits2)
            bits2.append(b)
            ts2.append(ts2[-1] + 600)
        self.assertLess(work_from_bits(bits2[-1]), work_from_bits(hard))

    def test_converges_to_hashrate(self):
        # Deterministic hashrate model: solvetime = work / H. LWMA should settle
        # where expected work per block = H * T, i.e. blocks every T seconds.
        d = test_launch(pow_limit_bits=0x1F00FFFF, lwma_window=10, target_spacing=60)
        for H in (2e6, 5e7):
            ts, bits = self.chain(d, 200, lambda i, b: max(1, round(work_from_bits(b) / H)))
            self.assertAlmostEqual(work_from_bits(bits[-1]) / (H * 60), 1.0, delta=0.06)
            spacing = (ts[-1] - ts[-51]) / 50
            self.assertAlmostEqual(spacing / 60, 1.0, delta=0.06)

    def test_constant_spacing_is_a_fixed_point(self):
        d = test_launch(pow_limit_bits=0x1F00FFFF, lwma_window=10, target_spacing=60)
        ts, bits = self.chain(d, 25, lambda i, b: 6)
        for _ in range(60):
            bits.append(d.lwma_next_bits(ts, bits))
            ts.append(ts[-1] + 60)
        tail = [work_from_bits(b) for b in bits[-10:]]
        self.assertLess(max(tail) / min(tail), 1.01)

    def test_out_of_order_timestamps_never_negative(self):
        d = test_launch(pow_limit_bits=0x1F00FFFF, lwma_window=10)
        ts = [d.genesis_time + i * 60 for i in range(12)]
        ts[6] = ts[2]  # out of order
        bits = [0x1F00FFFF] * 12
        b = d.lwma_next_bits(ts, bits)
        self.assertLessEqual(bits_to_target(b), bits_to_target(0x1F00FFFF))
        self.assertGreater(bits_to_target(b), 0)


    def test_stall_relief_revives_abandoned_chain(self):
        # A sniper mines 60 one-second blocks (difficulty ratchets ~1.4x per block), then all
        # hash leaves. LWMA alone would leave the chain stuck at that difficulty forever.
        d = test_launch(pow_limit_bits=0x1F00FFFF, lwma_window=10, target_spacing=5)
        T, limit = d.target_spacing, bits_to_target(d.pow_limit_bits)
        ts, bits = [1_700_000_000], [d.pow_limit_bits]
        for _ in range(60):
            ts.append(ts[-1] + 1)
            bits.append(d.next_bits(ts[:-1], bits, ts[-1]))
        stuck = bits_to_target(d.lwma_next_bits(ts, bits))
        self.assertLess(stuck, limit >> 20)
        # Inside the first 6T nothing changes; after that the target doubles every 6T up to the limit.
        self.assertEqual(d.next_bits(ts, bits, ts[-1] + 6 * T - 1), d.lwma_next_bits(ts, bits))
        self.assertEqual(d.next_bits(ts, bits, ts[-1] - 100), d.lwma_next_bits(ts, bits))
        for n in (1, 2, 7):
            got = bits_to_target(d.next_bits(ts, bits, ts[-1] + 6 * T * n))
            self.assertAlmostEqual(got / (stuck << n), 1, places=4)
        waited = next(n for n in range(1, 400) if bits_to_target(d.next_bits(ts, bits, ts[-1] + 6 * T * n)) == limit)
        self.assertLess(waited * 6 * T, 20 * 60, "an abandoned chain is back at the pow limit within 20 minutes")
        # The relieved block feeds LWMA, so the chain stays easy instead of snapping back.
        hard = bits[-1]
        ts.append(ts[-1] + 6 * T * waited)
        bits.append(d.next_bits(ts[:-1], bits, ts[-1]))
        self.assertGreater(bits_to_target(d.lwma_next_bits(ts, bits)), stuck << 5)
        # Work-priced issuance: the relieved block mints by its (tiny) work, so waiting is no discount.
        big = test_launch(pow_limit_bits=0x1F00FFFF, lwma_window=10, target_spacing=5, virtual_work=1 << 60)
        easy_sub, hard_sub = big.subsidy(0, bits[-1], 61), big.subsidy(0, hard, 61)
        self.assertLess(easy_sub, hard_sub)
        self.assertLessEqual(easy_sub / work_from_bits(bits[-1]), hard_sub / work_from_bits(hard) * 1.01)


class Descriptor(unittest.TestCase):
    def test_roundtrip_identity_and_genesis(self):
        d = test_launch()
        d.grind_genesis()
        self.assertTrue(d.genesis_valid())
        d2 = D.parse(d.dumps())
        self.assertEqual(d2.id, d.id)
        self.assertEqual(d2.genesis_hash, d.genesis_hash)
        self.assertTrue(1 <= d.chain_id <= 0x1FFF and d.chain_id not in (1, 98, 4096))
        self.assertTrue(all(b & 0x80 for b in d.magic))
        self.assertTrue(20000 <= d.p2p < 40000)

    def test_nonce_ports_seeds_not_in_id(self):
        d = test_launch()
        i0 = d.id
        d.genesis_nonce, d.p2p_port, d.seeds = 7, 12345, ["seed.example"]
        self.assertEqual(d.id, i0)
        d.creator_fee_bps = 101
        self.assertNotEqual(d.id, i0)

    def test_validation(self):
        with self.assertRaises(D.DescriptorError):
            test_launch(hrp="bc")
        with self.assertRaises(D.DescriptorError):
            test_launch(graduation_tokens=15_000_000 * COIN)
        with self.assertRaises(D.DescriptorError):
            test_launch(creator_fee_bps=100, creator_script=b"")
        with self.assertRaises(D.DescriptorError):
            test_launch(tail_reward=21_000_000 * COIN, tail_halving_interval=10)

    def test_make_pump_shape(self):
        d = D.make("Pumpish", "PMP", bytes.fromhex("0014" + "22" * 20), 10**22,
                   btc_anchor=(0, D.REGTEST_GENESIS_HEADER.hex()), sats_total=70_000_000,
                   creator_btc_script=D.TEST_BTC_SCRIPT)
        self.assertAlmostEqual(d.graduation_tokens / d.virtual_tokens, 0.7391, places=3)
        self.assertAlmostEqual(d.graduation_work / 10**22, 1.0, places=3)
        # pump.fun: price at graduation / price at start = (T0/(T0-G))^2 ~ 14.7
        self.assertAlmostEqual(d.hashes_per_coin(d.graduation_work) / d.hashes_per_coin(0), 14.7, delta=0.1)


class Htlc(unittest.TestCase):
    def setUp(self):
        self.rk, self.fk = 0xA11CE, 0xB0B
        self.secret, self.h = new_secret()
        self.c = Contract(self.h, pubkey_from_priv(self.rk), pubkey_from_priv(self.fk), 1_900_000_000)
        self.prev = sha256d(b"funding")

    def test_parse_roundtrip(self):
        self.assertEqual(Contract.parse(self.c.script()), self.c)
        small = Contract(self.h, pubkey_from_priv(self.rk), pubkey_from_priv(self.fk), 10)
        self.assertEqual(Contract.parse(small.script()).locktime, 10)
        with self.assertRaises(ValueError):
            Contract.parse(self.c.script()[:-1])

    def test_redeem_path(self):
        tx = redeem_tx(self.c, self.prev, 0, 100_000, p2wpkh_script(pubkey_from_priv(5)), 1000, self.rk, self.secret)
        verify_input(tx, 0, self.c.script_pubkey(), 100_000)
        self.assertEqual(extract_secret(tx, self.h), self.secret)
        bad = redeem_tx(self.c, self.prev, 0, 100_000, p2wpkh_script(pubkey_from_priv(5)), 1000, self.rk, self.secret)
        bad.vin[0].witness[1] = b"\x00" * 32
        with self.assertRaises(ScriptError):
            verify_input(bad, 0, self.c.script_pubkey(), 100_000)
        with self.assertRaises(ScriptError):  # signature commits to amount
            verify_input(tx, 0, self.c.script_pubkey(), 100_001)

    def test_refund_path(self):
        tx = refund_tx(self.c, self.prev, 0, 100_000, p2wpkh_script(pubkey_from_priv(5)), 1000, self.fk)
        self.assertEqual(tx.locktime, self.c.locktime)
        verify_input(tx, 0, self.c.script_pubkey(), 100_000)
        tx.locktime -= 1
        with self.assertRaises(ScriptError):
            verify_input(tx, 0, self.c.script_pubkey(), 100_000)
        with self.assertRaises(ValueError):
            refund_tx(self.c, self.prev, 0, 100_000, b"\x00\x14" + b"\0" * 20, 1000, self.rk)


class AuxPow(unittest.TestCase):
    def build_parent(self, tree, extra_txs=3, parent_version=0x20000000):
        script = push_int(800_000) + tree.commitment_push() + push(b"\x01" * 8)
        cb = Tx(version=1, vin=[TxIn(b"\0" * 32, 0xFFFFFFFF, script, 0xFFFFFFFF)],
                vout=[TxOut(50 * COIN, p2wpkh_script(pubkey_from_priv(9)))])
        txids = [cb.txid()] + [sha256d(bytes([i])) for i in range(extra_txs)]
        root = merkle_root(txids)
        hdr = header_bytes(parent_version, sha256d(b"prev"), root, 1_800_000_000, 0x207FFFFF, 0)
        return cb, merkle_branch_for_first(txids), hdr

    def test_single_and_multi_chain(self):
        for n in (1, 2, 5):
            leaves = {cid: sha256d(bytes([cid & 0xFF, cid >> 8])) for cid in random.sample(range(2, 0x1FFE), n)}
            tree = AuxTree(leaves)
            cb, br, hdr = self.build_parent(tree)
            for cid, h in leaves.items():
                cbr, idx = tree.branch(cid)
                ap = serialize_auxpow(cb, br, cbr, idx, hdr)
                ok, why = check_auxpow(h, cid, ap)
                self.assertTrue(ok, why)
                self.assertEqual(idx, expected_index(tree.nonce, cid, tree.height))

    def test_slots_separate_congruent_chain_ids(self):
        # Slots collide iff ids are congruent mod 2^h, independent of the nonce; ids 5 and
        # 5+1024 need h=11 (the old nonce search stopped at h=10 and raised).
        for n in (0, 1, 0xDEADBEEF):
            for a, b in ((5, 5 + 1024), (3, 3 + 4096), (1, 0x1FFF)):
                self.assertEqual(expected_index(n, a, 10) == expected_index(n, b, 10), (a - b) % 1024 == 0)
        tree = AuxTree({5: sha256d(b"x"), 5 + 1024: sha256d(b"y"), 77: sha256d(b"z")})
        self.assertEqual(tree.height, 11)
        cb, br, hdr = self.build_parent(tree)
        for cid, h in tree.leaves.items():
            cbr, idx = tree.branch(cid)
            self.assertTrue(check_auxpow(h, cid, serialize_auxpow(cb, br, cbr, idx, hdr))[0])
        everyone = AuxTree({cid: sha256d(cid.to_bytes(2, "little")) for cid in range(1, 0x2000)})
        self.assertEqual(everyone.height, 13)

    def test_rejections(self):
        leaves = {700: sha256d(b"a"), 900: sha256d(b"b")}
        tree = AuxTree(leaves)
        cb, br, hdr = self.build_parent(tree)
        cbr, idx = tree.branch(700)
        ap = serialize_auxpow(cb, br, cbr, idx, hdr)
        self.assertFalse(check_auxpow(sha256d(b"other"), 700, ap)[0])
        self.assertFalse(check_auxpow(leaves[700], 900, ap)[0])
        cb2, br2, hdr2 = self.build_parent(tree, parent_version=(700 << 16) | 4)
        self.assertEqual(check_auxpow(leaves[700], 700, serialize_auxpow(cb2, br2, cbr, idx, hdr2))[1],
                         "Aux POW parent has our chain ID")


if __name__ == "__main__":
    unittest.main()
