"""Unit tests: crypto/serialization vectors, the consensus model (curve, graduation,
tail, LWMA), descriptor identity + genesis, HTLC scripts, AuxPoW construction.
Run: python -m unittest discover -s hashfun/tests -v"""
import random
import os
import struct
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
    # Each of the two curves can mint graduation_tokens, so 2 * G + the tail has to stay within 21M.
    base = dict(name="Test Launch", ticker="TST", genesis_time=1_800_000_000, virtual_work=71,
                virtual_tokens=12_000_000 * COIN, graduation_tokens=8_869_000 * COIN, pow_limit_bits=0x207FFFFF,
                target_spacing=60, lwma_window=10, ftl=60, tail_reward=10 * COIN, tail_halving_interval=1000,
                creator_script=bytes.fromhex("0014" + "11" * 20), creator_fee_bps=100, test=True, hrp="tst",
                btc_anchor_header=D.REGTEST_GENESIS_HEADER, sats_num=5000, creator_btc_script=D.TEST_BTC_SCRIPT,
                btc_regtest=True, qwen_anchor_header=D.REGTEST_GENESIS_HEADER, qwen_num=7000,
                creator_qwen_script=D.TEST_QWEN_SCRIPT, qwen_regtest=True)
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
    """Each of a launch's two curves is this curve, on its own work: a block mints from the curve its
    header puts it on, and the first curve to sell out graduates the launch."""

    def test_graduation_threshold_exact(self):
        for _ in range(200):
            v0 = random.randint(1, 2**80)
            t0 = random.randint(10**6, 105 * 10**13)  # 2 * G has to stay within 21M
            g = random.randint(1, t0 - max(1, t0 // 1000))
            d = test_launch(virtual_work=v0, virtual_tokens=t0, graduation_tokens=g, tail_reward=0, tail_halving_interval=0)
            wg = d.graduation_work
            self.assertGreaterEqual(t0 * wg // (v0 + wg), g)
            self.assertLess(t0 * (wg - 1) // (v0 + wg - 1), g)

    def test_path_independent_issuance_on_each_curve(self):
        d = test_launch()
        for _ in range(20):
            w, minted = {"btc": 0, "qwen": 0}, {"btc": 0, "qwen": 0}
            bits_choices = [0x207FFFFF, 0x2007FFFF, 0x1F7FFFFF, 0x1F0FFFFF]
            share = random.choice([0.1, 0.5, 0.9])  # of the blocks that go to the QWEN curve
            while not d.graduated(w["btc"], w["qwen"]):
                b, quote = random.choice(bits_choices), "qwen" if random.random() < share else "btc"
                minted[quote] += d.subsidy(w["btc"], w["qwen"], quote, b, 5)
                w[quote] += work_from_bits(b)
                for q in D.QUOTES:  # each curve has minted what its own work stands for, whatever the other did
                    self.assertEqual(minted[q], d.curve_supply(w[q]))
            first = "btc" if w["btc"] >= d.graduation_work else "qwen"
            other = "qwen" if first == "btc" else "btc"
            self.assertEqual(minted[first], d.graduation_tokens)            # the crossing block minted only up to G
            self.assertLess(minted[other], d.graduation_tokens)             # the other curve's rest is never minted
            self.assertEqual(d.curve_minted(w["btc"], w["qwen"]), minted["btc"] + minted["qwen"])
            for quote in D.QUOTES:                                          # from here on: the tail, on either side
                self.assertEqual(d.subsidy(w["btc"], w["qwen"], quote, 0x207FFFFF, 5), 10 * COIN)

    def test_the_curves_do_not_move_each_other(self):
        d = test_launch()
        one = work_from_bits(0x207FFFFF)
        first = d.subsidy(0, 0, "btc", 0x207FFFFF, 1)
        self.assertEqual(first, d.subsidy(0, 0, "qwen", 0x207FFFFF, 1))    # the same shape, the same first block
        for sold in (one, 50 * one, d.graduation_work - 1):
            self.assertEqual(d.subsidy(0, sold, "btc", 0x207FFFFF, 9), first)   # work on the QWEN curve leaves the BTC curve
            self.assertEqual(d.subsidy(sold, 0, "qwen", 0x207FFFFF, 9), first)  # at its start, and the other way round
            self.assertLess(d.subsidy(sold, 0, "btc", 0x207FFFFF, 9), first)
        self.assertFalse(d.graduated(d.graduation_work - 1, d.graduation_work - 1))  # together twice the work, and not graduated
        self.assertTrue(d.graduated(d.graduation_work, 0) and d.graduated(0, d.graduation_work))

    def test_reward_proportional_to_work_and_price_rises(self):
        d = test_launch()
        w = 0
        last_ppw = None
        while w < d.graduation_work // 2:
            s = d.subsidy(w, 0, "btc", 0x207FFFFF, 5)
            ppw = work_from_bits(0x207FFFFF) / max(s, 1)
            if last_ppw is not None:
                self.assertGreaterEqual(ppw, last_ppw * 0.999)
            last_ppw = ppw
            w += work_from_bits(0x207FFFFF)
        self.assertLess(d.hashes_per_coin(0), d.hashes_per_coin(d.graduation_work))

    def test_tail_after_graduation(self):
        d = test_launch()
        wg = d.graduation_work
        for wb, wq in ((wg, 0), (0, wg), (wg, wg - 1)):                     # graduated by either curve
            for quote in D.QUOTES:
                self.assertEqual(d.subsidy(wb, wq, quote, 0x207FFFFF, 999), 10 * COIN)
                self.assertEqual(d.subsidy(wb, wq, quote, 0x207FFFFF, 1000), 5 * COIN)
        self.assertEqual(d.subsidy(wg + 10**30, 0, "btc", 0x1D00FFFF, 1), 10 * COIN)

    def test_no_overflow_bounds(self):
        # the worst cases validation allows: V0 = 2^160 with T0 = MAX_MONEY (then G is at most half of it,
        # both curves can mint G), and with G = 99.9% of T0 (then T0 is at most MAX_MONEY / 1.998)
        for t0, g in ((D.MAX_MONEY, D.MAX_MONEY // 2), (D.MAX_MONEY * 1000 // 1998, None)):
            g = t0 - t0 // 1000 if g is None else g
            d = test_launch(virtual_work=2**160, virtual_tokens=t0, graduation_tokens=g, tail_reward=0,
                            tail_halving_interval=0)
            self.assertLessEqual(2 * g, D.MAX_MONEY)
            self.assertLess(t0 * d.graduation_work, 2**256)
            self.assertLess(g * d.virtual_work, 2**256)

    def test_both_curves_count_against_the_supply(self):
        why = r"2 \* graduation_tokens \+ total tail emission exceeds MAX_MONEY \(each of the two curves can mint graduation_tokens\)"
        half = D.MAX_MONEY // 2
        test_launch(virtual_tokens=D.MAX_MONEY, graduation_tokens=half, tail_reward=0, tail_halving_interval=0)
        with self.assertRaisesRegex(D.DescriptorError, why):
            test_launch(virtual_tokens=D.MAX_MONEY, graduation_tokens=half + 1, tail_reward=0, tail_halving_interval=0)
        with self.assertRaisesRegex(D.DescriptorError, why):   # what one curve alone was allowed before
            test_launch(virtual_tokens=15_000_000 * COIN, graduation_tokens=11_086_000 * COIN)
        test_launch(virtual_tokens=D.MAX_MONEY, graduation_tokens=half - 1000, tail_reward=1, tail_halving_interval=1000)
        with self.assertRaisesRegex(D.DescriptorError, why):
            test_launch(virtual_tokens=D.MAX_MONEY, graduation_tokens=half - 999, tail_reward=1, tail_halving_interval=1000)
        # make()'s default supply is the largest round one that fits with pump.fun's proportions
        d = D.make("Fits", "FIT", b"", 10**9, creator_fee_bps=0, test=True)
        self.assertEqual(d.virtual_tokens, 12_000_000 * COIN)
        self.assertLessEqual(2 * d.graduation_tokens + 2 * d.tail_reward * d.tail_halving_interval, D.MAX_MONEY)
        with self.assertRaisesRegex(D.DescriptorError, why):
            D.make("Too many", "MANY", b"", 10**9, creator_fee_bps=0, test=True, supply_coins=13_000_000)

    def test_creator_fee(self):
        d = test_launch()
        self.assertEqual(d.creator_fee(10_000), 100)
        self.assertEqual(d.creator_fee(0), 0)

    def test_what_a_block_owes_and_the_two_price_points(self):
        d = test_launch(sats_num=5000, sats_shift=0, qwen_num=7000, qwen_shift=0)
        work = work_from_bits(0x207FFFFF)
        self.assertEqual((d.owed(work, "btc"), d.owed(work, "qwen"), d.owed(work)), (10_000, 14_000, 10_000))
        self.assertEqual((d.owed_rate("btc"), d.owed_rate("qwen")), ((5000, 0), (7000, 0)))
        self.assertEqual((d.leg_total("btc"), d.leg_total("qwen")), (d.graduation_work * 5000, d.graduation_work * 7000))
        # a curve's price point: base units of its quote owed per whole coin, at the margin
        for w in (0, d.graduation_work // 3, d.graduation_work):
            self.assertAlmostEqual(d.price_per_coin(w, "btc"), d.hashes_per_coin(w) * 5000)
            self.assertAlmostEqual(d.price_per_coin(w, "qwen"), d.hashes_per_coin(w) * 7000)
        # what they imply for QWEN, in sats per QWEN: with both curves equally sold, the ratio of the rates
        self.assertAlmostEqual(d.implied_qwen_sats(0, 0), 5000 / 7000 * COIN)
        self.assertAlmostEqual(d.implied_qwen_sats(77, 77), 5000 / 7000 * COIN)
        # the more the BTC curve is sold beyond the QWEN curve, the more sats a coin costs there: QWEN is implied dearer
        self.assertGreater(d.implied_qwen_sats(d.graduation_work // 2, 0), d.implied_qwen_sats(0, 0))
        self.assertLess(d.implied_qwen_sats(0, d.graduation_work // 2), d.implied_qwen_sats(0, 0))
        shifted = test_launch(sats_num=5, sats_shift=3, qwen_num=3, qwen_shift=1)
        self.assertEqual((shifted.owed(1000, "btc"), shifted.owed(1000, "qwen")), (625, 1500))
        self.assertEqual([D.curve_of_version(v) for v in (0x20000000, 0x20000200, 0x200, 0x100, 0x20010300)],
                         ["btc", "qwen", "qwen", "btc", "qwen"])

    def test_quote_summary_says_what_the_implied_price_is(self):
        def info(height, btc_last, qwen_last, graduated=False, pb=2000.0, pq=4_000_000.0):
            return {"height": height, "graduated": graduated,
                    "curves": {"btc": {"owed_per_coin": pb, "last_height": btc_last},
                               "qwen": {"owed_per_coin": pq, "last_height": qwen_last}}}
        q = D.quote_summary(info(500, 500, 499))
        self.assertEqual((q["price"], q["implied_qwen_sats"], q["mined"], q["bound"]),
                         ({"btc": 2000.0, "qwen": 4_000_000.0}, 50_000.0, ["btc", "qwen"], "two-sided"))
        self.assertEqual(D.quote_summary(info(500, 500, 0))["bound"], "floor")         # only the BTC curve is being mined
        self.assertEqual(D.quote_summary(info(500, 500, 400))["bound"], "floor")       # the QWEN curve's last block is old
        self.assertEqual(D.quote_summary(info(500, 401, 500))["bound"], "two-sided")   # within the last hundred
        self.assertEqual(D.quote_summary(info(500, 100, 500))["bound"], "ceiling")
        self.assertEqual(D.quote_summary(info(500, 0, 0))["bound"], None)              # nothing mined yet
        self.assertEqual(D.quote_summary(info(500, 500, 500, graduated=True))["mined"], [])
        self.assertEqual(D.quote_summary(info(500, 500, 500, pq=0.0))["implied_qwen_sats"], None)
        self.assertEqual(D.quote_summary({"height": 3})["implied_qwen_sats"], None)    # a node that reports no curves


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
        easy_sub, hard_sub = big.subsidy(0, 0, "btc", bits[-1], 61), big.subsidy(0, 0, "btc", hard, 61)
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
        self.assertTrue(20002 <= d.p2p <= 31998 and d.p2p % 4 == 2 and d.rpc == d.p2p - 1)  # and p2p + 1 is the node's Tor listener

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
            test_launch(graduation_tokens=12_000_000 * COIN)
        with self.assertRaises(D.DescriptorError):
            test_launch(creator_fee_bps=100, creator_script=b"")
        with self.assertRaises(D.DescriptorError):
            test_launch(tail_reward=21_000_000 * COIN, tail_halving_interval=10)

    def test_make_pump_shape(self):
        qh, qstarts = qwen_headers()
        d = D.make("Pumpish", "PMP", bytes.fromhex("0014" + "22" * 20), 10**22,
                   btc_anchor=(0, D.MAINNET_GENESIS_HEADER.hex()), sats_total=70_000_000,
                   creator_btc_script=D.TEST_BTC_SCRIPT, qwen_anchor=(0, qh[0].hex()), qwen_total=1000 * COIN,
                   creator_qwen_script=D.TEST_QWEN_SCRIPT)
        self.assertAlmostEqual(d.graduation_tokens / d.virtual_tokens, 0.7391, places=3)
        self.assertAlmostEqual(d.graduation_work / 10**22, 1.0, places=3)
        # pump.fun: price at graduation / price at start = (T0/(T0-G))^2 ~ 14.7
        self.assertAlmostEqual(d.hashes_per_coin(d.graduation_work) / d.hashes_per_coin(0), 14.7, delta=0.1)
        # a production launch: 5 s blocks, a 90-block window, and the ftl that follows from the two
        self.assertEqual((d.version, d.target_spacing, d.lwma_window, d.ftl, d.test, d.btc_regtest, d.qwen_regtest),
                         (3, 5, 90, 22, False, False, False))
        self.assertEqual(d.btc_anchor_period_time, 1231006505)  # the anchor opens its period: Bitcoin's first block time
        self.assertEqual((d.qwen_anchor_height, d.qwen_anchor_header, d.qwen_anchor_period_time), (0, qh[0], qstarts[0]))
        # each leg owes its total over a whole curve, in its own coin, to within the rate's rounding
        self.assertAlmostEqual(d.leg_total("btc") / 70_000_000, 1.0, places=6)
        self.assertAlmostEqual(d.leg_total("qwen") / (1000 * COIN), 1.0, places=6)
        # two starting price points, and the QWEN price they stand for: 0.7 BTC against 1000 QWEN is 70,000 sats a QWEN
        self.assertAlmostEqual(d.implied_qwen_sats(0, 0) / 70_000, 1.0, places=6)
        self.assertAlmostEqual(d.price_per_coin(0, "btc") / d.price_per_coin(0, "qwen"), 0.0007, places=9)
        # 1000 QWEN owed: 25 Qwencoin confirmations (see qwen_confs_for), and a day to pay and prove
        self.assertEqual((d.qwen_confs, d.btc_confs, d.settle_deadline), (25, 1, 86400 // 5))

    # ---- the rules that came with descriptor versions 2 and 3. test_diff_cpp runs the same cases, and
    # many more, against the node's own parser; these run everywhere, with no node built.
    def test_version_3_and_what_becomes_of_1_and_2(self):
        import json
        d = test_launch()
        self.assertEqual((d.version, D.VERSION), (3, 3))
        self.assertEqual(d.canonical_bytes()[:18], b"hashfun-launch\x03\x00\x00\x00")
        j = d.to_json()
        self.assertEqual(j["version"], 3)
        self.assertEqual(D.parse(json.dumps({k: v for k, v in j.items() if k != "version"})).id, d.id)
        for v, why in ((1, "version: 1 is the earlier, pre-release rule set. This launch file must be created again"),
                       (2, "version: 2 is the earlier rule set with one curve, quoted in BTC only. This launch file must be "
                           "created again"),
                       (0, "unsupported descriptor version"), (4, "unsupported descriptor version")):
            with self.assertRaisesRegex(D.DescriptorError, why):
                D.parse(json.dumps(dict(j, version=v)))
            with self.assertRaisesRegex(D.DescriptorError, why):
                test_launch(version=v)
        old = test_launch()
        old.version = 2  # the version is hashed into the id: the same launch under the old rules was another chain
        self.assertNotEqual(old.id, d.id)

    def test_the_qwen_leg_is_part_of_the_launch_id(self):
        """Every QWEN field is hashed into the id, after btc_regtest and before the metadata hash."""
        d = test_launch()
        canon = d.canonical_bytes()
        tail = (struct.pack("<I", 0) + D.REGTEST_GENESIS_HEADER + struct.pack("<I", 0) + struct.pack("<q", 7000) +
                struct.pack("<I", 0) + struct.pack("<q", 10_000) + struct.pack("<I", 6) + b"\x16" + D.TEST_QWEN_SCRIPT + b"\x01")
        self.assertTrue(canon.endswith(b"\x16" + D.TEST_BTC_SCRIPT + b"\x01" + tail))
        with_meta = test_launch(meta=b"\x07" * 32)
        self.assertEqual(with_meta.canonical_bytes(), canon + b"\x07" * 32)
        ids = {d.id}
        for change in (dict(qwen_anchor_height=5), dict(qwen_anchor_header=D.REGTEST_GENESIS_HEADER[:79] + b"\x01"),
                       dict(qwen_anchor_period_time=9), dict(qwen_num=7001), dict(qwen_shift=1), dict(qwen_min_payment=546),
                       dict(qwen_confs=7), dict(creator_qwen_script=D.TEST_BTC_SCRIPT), dict(sats_num=7000, qwen_num=5000)):
            ids.add(test_launch(**change).id)
        self.assertEqual(len(ids), 10)
        j = d.to_json()
        self.assertEqual([k for k in j if k.startswith(("qwen_", "creator_qwen"))],
                         ["qwen_anchor_height", "qwen_anchor_header", "qwen_anchor_period_time", "qwen_num", "qwen_shift",
                          "qwen_min_payment", "qwen_confs", "creator_qwen_script", "qwen_regtest"])
        self.assertEqual(list(j).index("qwen_anchor_height"), list(j).index("btc_regtest") + 1)
        self.assertEqual(D.parse(d.dumps()), d)

    def test_fields_left_out_take_their_defaults(self):
        import json
        genesis = D.MAINNET_GENESIS_HEADER
        qgenesis = qwen_headers()[0][0]
        minimal = {"name": "Minimal", "ticker": "MIN", "genesis_time": 1_700_000_000, "virtual_work": "1000000",
                   "virtual_tokens": 1000 * COIN, "graduation_tokens": 500 * COIN, "sats_num": 1,
                   "btc_anchor_header": genesis.hex(), "btc_anchor_period_time": header_time(genesis),
                   "creator_btc_script": "0014" + "22" * 20, "qwen_num": 1,
                   "qwen_anchor_header": qgenesis.hex(), "qwen_anchor_period_time": header_time(qgenesis),
                   "creator_qwen_script": "0014" + "33" * 20, "settle_deadline": 1440}
        d = D.parse(json.dumps(minimal))
        self.assertEqual((d.version, d.hrp, d.target_spacing, d.lwma_window, d.ftl, d.pow_limit_bits, d.test, d.btc_regtest,
                          d.btc_anchor_height, d.sats_min_payment, d.btc_confs),
                         (3, "min", 5, 90, 22, 0x1D00FFFF, False, False, 0, 10_000, 1))
        # The deadline is one of the few on a real chain: its own default, 720 blocks, is an hour at the
        # default block time, and the six Qwencoin confirmations asked for by default take an hour themselves.
        hour = {k: v for k, v in minimal.items() if k != "settle_deadline"}
        with self.assertRaisesRegex(D.DescriptorError, "settle_deadline: too short for qwen_confs"):
            D.parse(json.dumps(hour))
        self.assertEqual(D.parse(json.dumps(dict(hour, qwen_confs=3))).settle_deadline, 720)
        self.assertEqual(D.parse(json.dumps(dict(hour, qwen_regtest=True, btc_regtest=True))).settle_deadline, 720)
        self.assertEqual((d.qwen_regtest, d.qwen_anchor_height, d.qwen_shift, d.qwen_min_payment, d.qwen_confs),
                         (False, 0, 0, 10_000, 6))
        for same in (dict(minimal, target_spacing=5, lwma_window=90, ftl=22), dict(minimal, ftl=None),
                     dict(minimal, target_spacing=None, lwma_window=None, version=3),
                     dict(minimal, qwen_confs=6, qwen_min_payment=10_000, qwen_shift=0, qwen_anchor_height=0, qwen_regtest=False),
                     dict(minimal, qwen_confs=None, qwen_regtest=None)):
            self.assertEqual(D.parse(json.dumps(same)).id, d.id)
        for k in minimal:  # and none of those few can go
            with self.assertRaises(D.DescriptorError):
                D.parse(json.dumps({x: v for x, v in minimal.items() if x != k}))
        # The ftl of a launch that names none follows its block time and its window, and always passes
        # the rule a launch has to pass.
        self.assertEqual([D.default_ftl(T, N) for T, N in ((5, 90), (2, 15), (10, 10), (60, 45), (3600, 1000), (2, 1000))],
                         [22, 10, 10, 135, 7200, 11])
        for T in range(2, 3601):
            for N in (3, 4, 19, 20, 21, 45, 90, 144, 999, 1000):
                f = D.default_ftl(T, N)
                self.assertTrue(D.MIN_FTL <= f < 6 * T and f <= D.MAX_FTL, (T, N, f))
        for T, N in ((2, 3), (2, 15), (5, 90), (10, 10), (60, 45), (600, 144), (3600, 1000)):
            # (3600 blocks: two hours also at a block time of two seconds, as the six confirmations need)
            self.assertEqual(D.parse(json.dumps(dict(minimal, target_spacing=T, lwma_window=N, settle_deadline=3600))).ftl,
                             D.default_ftl(T, N))
            qwen = dict(qwen_anchor=(0, qgenesis.hex()), qwen_total=10**9, creator_qwen_script=D.TEST_QWEN_SCRIPT)
            made = D.make("Defaults", "DFT", b"", 10**12, creator_fee_bps=0, target_spacing=T, lwma_window=N,
                          btc_anchor=(0, genesis.hex()), sats_total=10**6, creator_btc_script=D.TEST_BTC_SCRIPT, **qwen)
            self.assertEqual((made.ftl, made.test, made.btc_regtest), (D.default_ftl(T, N), False, False))
            self.assertEqual(D.make("Named", "NMD", b"", 10**12, creator_fee_bps=0, target_spacing=T, lwma_window=N, ftl=10,
                                    btc_anchor=(0, genesis.hex()), sats_total=10**6, creator_btc_script=D.TEST_BTC_SCRIPT,
                                    **qwen).ftl, 10)

    def test_ftl_stays_below_a_stall_relief_step(self):
        rule = r"ftl: at least 10 and less than 6 \* target_spacing"
        for T, ftl, ok in ((10, 9, False), (10, 10, True), (10, 59, True), (10, 60, False), (2, 9, False), (2, 10, True),
                           (2, 11, True), (2, 12, False), (60, 359, True), (60, 360, False), (1200, 7199, True),
                           (1200, 7200, False), (1201, 7200, True), (3600, 7200, True)):
            if ok:
                self.assertEqual(production_launch(target_spacing=T, ftl=ftl).ftl, ftl)
            else:
                with self.assertRaisesRegex(D.DescriptorError, rule, msg=(T, ftl)):
                    production_launch(target_spacing=T, ftl=ftl)
        # A test launch stamps blocks far from the clock on purpose: it keeps the whole range.
        for ftl in (1, 9, 60, 360, 7200):
            test_launch(ftl=ftl)
            production_launch(test=True, ftl=ftl)
        for ftl in (0, 7201):
            for make in (test_launch, production_launch):
                with self.assertRaisesRegex(D.DescriptorError, r"ftl: 1\.\.7200"):
                    make(ftl=ftl)

    def test_fields_the_node_holds_as_an_int(self):
        import json
        top, j = 2**31 - 1, production_launch().to_json()
        production_launch(tail_halving_interval=top)
        production_launch(tail_reward=1, tail_halving_interval=top)
        production_launch(btc_anchor_height=top)
        for field in ("tail_halving_interval", "btc_anchor_height"):
            self.assertEqual(getattr(D.parse(json.dumps(dict(j, **{field: top}))), field), top)
            for v in (2**31, 2**32 - 1, 2**32, -1):
                with self.assertRaisesRegex(D.DescriptorError, field + ": out of range", msg=v):
                    production_launch(**{field: v})
                with self.assertRaisesRegex(D.DescriptorError, field + ": out of range", msg=v):
                    D.parse(json.dumps(dict(j, **{field: v})))

    def test_anchor_has_to_be_a_bitcoin_header(self):
        hdrs = mainnet_headers()
        t0, own, own2016 = header_time(hdrs[0]), header_time(hdrs[1500]), header_time(hdrs[2016])
        self.assertEqual(sha256d(hdrs[0]), sha256d(D.MAINNET_GENESIS_HEADER))

        def with_bits(bits):
            return hdrs[1500][:72] + struct.pack("<I", bits) + hdrs[1500][76:]

        # the stored header with another nonce: difficulty 1 on its face, and a hash nowhere near
        missed = next(h for h in (hdrs[1500][:76] + struct.pack("<I", n) for n in range(1, 50))
                      if int.from_bytes(sha256d(h), "little") > bits_to_target(0x1D00FFFF))
        good = [(1500, hdrs[1500], t0), (1500, hdrs[1500], own), (1500, hdrs[1500], own + 7200), (1500, hdrs[1500], 1),
                (0, hdrs[0], t0), (4032, hdrs[0], t0), (2016, hdrs[2016], own2016),
                (2017, hdrs[2016], t0)]  # a wrong height that no parser can see: check_anchor asks a Bitcoin node
        bad = [((1500, hdrs[1500], 0), "btc_anchor_period_time: required"),
               ((1500, hdrs[1500], own + 7201), "btc_anchor_period_time: later than the anchor block itself"),
               ((1500, missed, t0), "its hash does not meet its own difficulty"),
               ((0, missed, header_time(missed)), "its hash does not meet its own difficulty"),
               ((2016, hdrs[2016], t0), "the anchor opens a difficulty period"),
               ((2016, hdrs[2016], own2016 + 1), "the anchor opens a difficulty period"),
               ((0, hdrs[0], t0 - 1), "the anchor opens a difficulty period"),
               ((0, D.REGTEST_GENESIS_HEADER, header_time(D.REGTEST_GENESIS_HEADER)), "easier than Bitcoin's minimum difficulty"),
               ((1500, with_bits(0x1D010000), t0), "easier than Bitcoin's minimum difficulty"),
               ((1500, with_bits(0x2100FFFF), t0), "easier than Bitcoin's minimum difficulty"),
               ((1500, with_bits(0x1B0404CB), t0), "its hash does not meet its own difficulty")]
        bad += [((1500, with_bits(bits), t0), "its difficulty bits are not a valid target")
                for bits in (0, 0x1D80FFFF, 0x1D000000, 0x01003456, 0x2200FFFF, 0xFF000001, 0x04800001)]
        for height, header, period in good:
            production_launch(btc_anchor_height=height, btc_anchor_header=header, btc_anchor_period_time=period)
        for (height, header, period), why in bad:
            with self.assertRaisesRegex(D.DescriptorError, why, msg=(height, header.hex(), period)):
                production_launch(btc_anchor_height=height, btc_anchor_header=header, btc_anchor_period_time=period)
            # with btc_regtest none of it is asked: regtest has no difficulty to speak of
            production_launch(btc_anchor_height=height, btc_anchor_header=header, btc_anchor_period_time=period, btc_regtest=True)
        for regtest in (False, True):
            with self.assertRaisesRegex(D.DescriptorError, "btc_anchor_header: required"):
                production_launch(btc_anchor_header=bytes(80), btc_regtest=regtest)

    def test_creator_btc_script_has_to_earn(self):
        from hashfun import yieldmodel as Y
        rng = random.Random(5)
        earning = [b"\x76\xa9\x14" + rng.randbytes(20) + b"\x88\xac", b"\xa9\x14" + rng.randbytes(20) + b"\x87",
                   b"\x00\x14" + rng.randbytes(20), b"\x00\x20" + rng.randbytes(32), b"\x51\x20" + rng.randbytes(32),
                   b"\x51\x02" + rng.randbytes(2), b"\x60\x28" + rng.randbytes(40)]
        others = [b"\x51", b"\x51\x01\xaa", b"\x00\x00", b"\x51\x29" + rng.randbytes(41), b"\x6a\x14" + rng.randbytes(20),
                  b"\x61\x02\xaa\xbb", b"\x50\x02\xaa\xbb", b"\x00\x13" + rng.randbytes(20), b"\x00\x15" + rng.randbytes(20),
                  b"\x76\xa9\x14" + rng.randbytes(20) + b"\x88\xad", b"\xa9\x14" + rng.randbytes(20) + b"\x88",
                  b"\x21" + rng.randbytes(33) + b"\xac", b"\x51" * 80]
        for s in earning:
            self.assertEqual(production_launch(creator_btc_script=s).creator_btc_script, s)
            test_launch(creator_btc_script=s)
        for s in others:
            for make in (production_launch, test_launch):  # a test launch is not let off: its miners are paid in BTC too
                with self.assertRaisesRegex(D.DescriptorError, "creator_btc_script: must be a P2PKH, P2SH or witness-program"):
                    make(creator_btc_script=s)
        with self.assertRaisesRegex(D.DescriptorError, "creator_btc_script: required"):
            production_launch(creator_btc_script=b"")
        # One rule, written down where a launch file is read and where the sats leg is run.
        scripts = set(earning + others)
        for s in earning:
            scripts.update(s[:i] + bytes([b]) + s[i + 1:] for i in (0, 1, 2, len(s) - 2, len(s) - 1)
                           for b in (0, 0x14, 0x20, 0x4f, 0x50, 0x51, 0x60, 0x61, 0x87, 0x88, 0xac, len(s) - 2, len(s) - 1))
            scripts.update([s + b"\x00", s[:-1], s[1:], b"\x00" + s])
        scripts.update(rng.randbytes(rng.randrange(1, 60)) for _ in range(500))
        self.assertGreater(len(scripts), 800)
        self.assertEqual([s for s in sorted(scripts) if D._earns_yield(s)], [s for s in sorted(scripts) if Y.earns_yield(s)])
        self.assertGreater(sum(map(D._earns_yield, scripts)), 20)

    def test_the_text_of_a_launch_file(self):
        """Where JSON readers disagree, a launch file is refused (so is it by the node): no file is one
        launch to one reader and another launch, or none, to the next."""
        import json
        import tempfile
        base = production_launch().to_json()
        text = json.dumps(base)
        d = D.parse(text)

        def more(extra):
            return text[:-1] + "," + extra + "}"

        self.assertEqual(D.parse(text.encode()).id, d.id)
        refused = [
            (more('"ticker":"RULE"'), "ticker: the key appears twice"), (more('"ticker":"ZZZ"'), "ticker: the key appears twice"),
            ('{"ticker":"ZZZ",' + text[1:], "ticker: the key appears twice"), (more('"foo":1,"foo":2'), "foo: the key appears twice"),
            (more('"metadata":{"a":1,"a":2}'), "a: the key appears twice"), (more('"x":[{"a":1,"a":1}]'), "a: the key appears twice"),
            (more('"tick\\u0065r":"ZZZ"'), "ticker: the key appears twice"),
            (more('"x":NaN'), "NaN is not a JSON value"), (more('"x":Infinity'), "Infinity is not a JSON value"),
            (more('"x":-Infinity'), "-Infinity is not a JSON value"), (text.replace('"sats_shift": 3', '"sats_shift": NaN'), "NaN"),
            (more('"x":' + "[" * 64 + "]" * 64), "nested more than 64 levels"),
            (more('"x":' + "[" * 511 + "]" * 511), "nested more than 64 levels"),
            # (past 512 levels the node's reader does not read the text at all)
            (more('"x":' + "[" * 512 + "]" * 512), "descriptor is not a JSON object"),
            (more('"x":' + "[" * 100_000 + "]" * 100_000), "descriptor is not a JSON object"),
            (more('"x":' + "1" * 41), "a number of more than 40 characters"), (more('"x":1.' + "1" * 39), "more than 40 characters"),
            (more('"x":"\\ud800"'), "not valid UTF-8"), (more('"\\udc00":1'), "not valid UTF-8"),
            (text.replace('"name": "', '"name": "\\ud83d', 1), "not valid UTF-8"),
            (text.encode().replace(b"Rules", b"R\xe9gles"), "descriptor is not valid UTF-8"),
            (text.encode().replace(b"Rules", b"\xc1\x81"), "descriptor is not valid UTF-8"),
            (text.encode().replace(b"Rules", b"\xed\xa0\x80"), "descriptor is not valid UTF-8"),
            (text.encode("utf-16"), "descriptor is not valid UTF-8"), (b"\xef\xbb\xbf" + text.encode(), "not a JSON object"),
            (text + text, "not a JSON object"), ("[" + text + "]", "not a JSON object"), ("", "not a JSON object"),
            (json.dumps(dict(base, genesis_time="9" * 5000)), "genesis_time: not an integer"),
            (json.dumps(dict(base, virtual_work="9" * 5000)), "virtual_work: expected decimal or 0x-hex integer string"),
        ]
        for bad, why in refused:
            with self.assertRaisesRegex(D.DescriptorError, why, msg=bad[:80]):
                D.parse(bad)
        same = [more('"x":' + "[" * 63 + "]" * 63), more('"x":' + "1" * 40), more('"x":{"a":1},"y":{"a":1}'),
                more('"x":"\\ud83d\\ude00"'), " \r\n" + text + "\n", text.encode().replace(b", ", b",\r\n"),
                json.dumps(dict(base, btc_anchor_height="0" * 5000 + "1500")),
                json.dumps(dict(base, virtual_work="0" * 5000 + str(10**12)))]
        for good in same:
            self.assertEqual(D.parse(good).id, d.id, good[:80])
        self.assertEqual(D.parse(text.encode().replace(b"Rules", "Règles".encode())).name, "Règles")
        # A dict that was already read (a web form, a test) is taken as it is.
        self.assertEqual(D.parse(base).id, d.id)
        # A file is read as bytes: UTF-8, whatever the locale would make of it.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "launch.json")
            with open(path, "wb") as f:
                f.write(text.encode().replace(b"Rules", "Règles".encode()))
            self.assertEqual(D.load(path).name, "Règles")
            with open(path, "wb") as f:
                f.write(text.encode().replace(b"Rules", b"R\xe8gles"))  # Latin-1
            with self.assertRaisesRegex(D.DescriptorError, "descriptor is not valid UTF-8"):
                D.load(path)

    def test_make_takes_a_boundary_anchors_own_time(self):
        hdrs = mainnet_headers()
        t0 = header_time(hdrs[0])

        qh, qstarts = qwen_headers()

        def make(anchor, **kw):
            qwen = {} if kw.get("test") else dict(qwen_anchor=(0, qh[0].hex()), qwen_total=10**9,
                                                  creator_qwen_script=D.TEST_QWEN_SCRIPT)
            return D.make("Anchored", "ANC", b"", 10**12, creator_fee_bps=0, btc_anchor=anchor, sats_total=10**6,
                          creator_btc_script=D.TEST_BTC_SCRIPT, **qwen, **kw)

        for height, header in ((0, hdrs[0]), (2016, hdrs[2016]), (4032, hdrs[0])):  # the period starts with the anchor
            d = make((height, header.hex()))
            self.assertEqual((d.btc_anchor_height, d.btc_anchor_header, d.btc_anchor_period_time),
                             (height, header, header_time(header)))
            as_text = make([str(height), header.hex(), str(header_time(header))])  # strings, as a command line has them
            self.assertEqual((as_text.btc_anchor_height, as_text.btc_anchor_period_time), (height, header_time(header)))
        d = make((1500, hdrs[1500].hex(), t0))
        self.assertEqual(d.btc_anchor_period_time, t0)
        with self.assertRaisesRegex(D.DescriptorError, "left out only when the height is a multiple of 2016; block 1500 is inside "
                                                       "a period, which starts at block 0"):
            make((1500, hdrs[1500].hex()))
        with self.assertRaisesRegex(D.DescriptorError, "block 4031 is inside a period, which starts at block 2016"):
            make((4031, hdrs[1500].hex()))
        with self.assertRaisesRegex(D.DescriptorError, "the anchor opens a difficulty period"):
            make((2016, hdrs[2016].hex(), t0))  # given, and wrong
        # Regtest Bitcoin never retargets: no period start to ask for.
        d = make((1500, D.REGTEST_GENESIS_HEADER.hex()), test=True)
        self.assertEqual((d.btc_anchor_height, d.btc_anchor_period_time, d.btc_regtest), (1500, 0, True))
        self.assertEqual(make(None, test=True).btc_anchor_header, D.REGTEST_GENESIS_HEADER)
        for anchor, why in (((1500, "zz" * 80, t0), "btc anchor: expected a height"), (("x", hdrs[0].hex()), "btc anchor: expected"),
                            ((0, hdrs[0].hex(), "soon"), "btc anchor: expected"), ((0,), "btc anchor: expected"),
                            ((0, hdrs[0].hex(), t0, 1), "btc anchor: expected"), ((0, hdrs[0].hex()[:-2]), "the header is 80 bytes"),
                            ((0, hdrs[0]), "btc anchor: expected"), ((2**31, hdrs[1500].hex(), t0), "btc_anchor_height: out of range"),
                            ((1500, hdrs[1500].hex(), 2**32), "btc_anchor_period_time: out of range"),
                            ((1500, hdrs[1500].hex(), -1), "btc_anchor_period_time: out of range")):
            with self.assertRaisesRegex(D.DescriptorError, why, msg=str(anchor)[:60]):
                make(anchor)

        # The Qwencoin anchor is given the same way, and read by the same rules.
        def qmake(anchor, **kw):
            return D.make("Anchored", "ANC", b"", 10**12, creator_fee_bps=0, btc_anchor=(0, hdrs[0].hex()), sats_total=10**6,
                          creator_btc_script=D.TEST_BTC_SCRIPT, qwen_anchor=anchor, qwen_total=10**9,
                          creator_qwen_script=D.TEST_QWEN_SCRIPT, **kw)
        for height in (0, 2016, 4032, 6048):  # each opens a period of the real chain: the start is its own time
            d = qmake((height, qh[height].hex()))
            self.assertEqual((d.qwen_anchor_height, d.qwen_anchor_header, d.qwen_anchor_period_time, d.qwen_regtest),
                             (height, qh[height], qstarts[height], False))
        self.assertEqual(qmake((2000, qh[2000].hex(), qstarts[0])).qwen_anchor_period_time, qstarts[0])
        with self.assertRaisesRegex(D.DescriptorError, "qwen anchor: the start time of the difficulty period is missing.*block 2000 "
                                                       "is inside a period, which starts at block 0.*qwencoin-cli getblockheader.*"
                                                       "--qwen-rpc, qwen_anchor_from_rpc.*stop accepting Qwencoin headers"):
            qmake((2000, qh[2000].hex()))
        with self.assertRaisesRegex(D.DescriptorError, "qwen_anchor_period_time: the anchor opens a difficulty period"):
            qmake((2016, qh[2016].hex(), qstarts[0]))
        for anchor, why in (((2000, "zz" * 80, 5), "qwen anchor: expected a height"), ((0,), "qwen anchor: expected"),
                            ((0, qh[0].hex()[:-2]), "qwen anchor: the header is 80 bytes"),
                            ((2**31, qh[2000].hex(), qstarts[0]), "qwen_anchor_height: out of range")):
            with self.assertRaisesRegex(D.DescriptorError, why):
                qmake(anchor)
        # a leg on regtest: the regtest genesis when nothing is given, no period start to ask for
        d = make(None, test=True)
        self.assertEqual((d.qwen_anchor_header, d.qwen_regtest, d.qwen_num, d.qwen_shift, d.qwen_confs, d.creator_qwen_script),
                         (D.REGTEST_GENESIS_HEADER, True, 7000, 0, 2, D.TEST_QWEN_SCRIPT))
        d = D.make("Mixed", "MIX", b"", 10**12, creator_fee_bps=0, btc_anchor=(0, hdrs[0].hex()), sats_total=10**6,
                   creator_btc_script=D.TEST_BTC_SCRIPT, qwen_regtest=True, qwen_anchor=(77, D.REGTEST_GENESIS_HEADER.hex()))
        self.assertEqual((d.btc_regtest, d.qwen_regtest, d.qwen_anchor_height, d.qwen_anchor_period_time), (False, True, 77, 0))

    def test_qwen_anchor_has_to_look_like_a_qwencoin_header(self):
        """What a parser can say about a Qwencoin anchor: its bits and its period start. Not its work:
        that is a pass through the chain's weights, which the node does at its start."""
        qh, qstarts = qwen_headers()
        own = header_time(qh[2000])

        def with_bits(bits):
            return qh[2000][:72] + struct.pack("<I", bits) + qh[2000][76:]

        other_nonce = qh[2000][:76] + struct.pack("<I", 0xFFFFFFFF)  # no work behind it: a parser cannot see that
        good = [(2000, qh[2000], qstarts[0]), (2000, qh[2000], own), (2000, qh[2000], own + 7200), (2000, qh[2000], 1),
                (0, qh[0], qstarts[0]), (2016, qh[2016], qstarts[2016]), (6048, qh[6048], qstarts[6048]),
                (2000, other_nonce, qstarts[0]), (2000, with_bits(0x2000FFFF), qstarts[0]), (2000, with_bits(0x1B0404CB), qstarts[0]),
                (2000, D.MAINNET_GENESIS_HEADER, 1),           # a Bitcoin header: harder than Qwencoin's limit, so it passes here
                (2001, qh[2000], qstarts[0])]                  # a wrong height: check_qwen_anchor asks a Qwencoin node
        bad = [((2000, qh[2000], 0), "qwen_anchor_period_time: required"),
               ((2000, qh[2000], own + 7201), "qwen_anchor_period_time: later than the anchor block itself"),
               ((2016, qh[2016], qstarts[0]), "qwen_anchor_period_time: the anchor opens a difficulty period"),
               ((0, qh[0], qstarts[0] - 1), "qwen_anchor_period_time: the anchor opens a difficulty period"),
               ((0, D.REGTEST_GENESIS_HEADER, header_time(D.REGTEST_GENESIS_HEADER)),
                r"qwen_anchor_header: easier than Qwencoin's minimum difficulty \(not a Qwencoin mainnet header; a regtest "
                "anchor needs qwen_regtest"),
               ((2000, with_bits(0x20010000), qstarts[0]), "easier than Qwencoin's minimum difficulty"),
               ((2000, with_bits(0x2100FFFF), qstarts[0]), "easier than Qwencoin's minimum difficulty")]
        bad += [((2000, with_bits(bits), qstarts[0]), "qwen_anchor_header: its difficulty bits are not a valid target")
                for bits in (0, 0x1D80FFFF, 0x1D000000, 0x01003456, 0x2200FFFF, 0xFF000001, 0x04800001)]
        for height, header, period in good:
            production_launch(qwen_anchor_height=height, qwen_anchor_header=header, qwen_anchor_period_time=period)
        for (height, header, period), why in bad:
            with self.assertRaisesRegex(D.DescriptorError, why, msg=(height, header.hex(), period)):
                production_launch(qwen_anchor_height=height, qwen_anchor_header=header, qwen_anchor_period_time=period)
            # with qwen_regtest none of it is asked
            production_launch(qwen_anchor_height=height, qwen_anchor_header=header, qwen_anchor_period_time=period, qwen_regtest=True)
        for regtest in (False, True):
            with self.assertRaisesRegex(D.DescriptorError, "qwen_anchor_header: required"):
                production_launch(qwen_anchor_header=bytes(80), qwen_anchor_height=0, qwen_anchor_period_time=0,
                                  qwen_regtest=regtest)
            with self.assertRaisesRegex(D.DescriptorError, "qwen_anchor_header: required with qwen_anchor_height"):
                production_launch(qwen_anchor_header=bytes(80), qwen_regtest=regtest)

    def test_the_deadline_has_to_cover_the_confirmations(self):
        """A payment has to reach its confirmations before the deadline, or every block that owes one
        loses its coins whatever its miner does: settle_deadline blocks of target_spacing seconds must
        last twice as long as the confirmations of a leg on a real chain take, at ten minutes each."""
        short = "settle_deadline: too short for {}: the deadline must last at least twice as long as the confirmations " \
                r"take \(ten minutes each\)"
        production_launch(settle_deadline=720, qwen_confs=36, btc_confs=36)     # 720 minutes: 36 confirmations, twice
        for change, key in ((dict(qwen_confs=37), "qwen_confs"), (dict(btc_confs=37), "btc_confs"),
                            (dict(btc_confs=37, qwen_confs=37), "btc_confs")):  # Bitcoin's is looked at first
            with self.assertRaisesRegex(D.DescriptorError, short.format(key)):
                production_launch(settle_deadline=720, **change)
        production_launch(settle_deadline=20160, qwen_confs=1008)
        with self.assertRaisesRegex(D.DescriptorError, short.format("qwen_confs")):
            production_launch(settle_deadline=20159, qwen_confs=1008)
        # the block time counts, a leg on regtest does not
        production_launch(target_spacing=600, settle_deadline=110, qwen_confs=55)
        with self.assertRaisesRegex(D.DescriptorError, short.format("qwen_confs")):
            production_launch(target_spacing=600, settle_deadline=110, qwen_confs=56)
        production_launch(settle_deadline=720, qwen_regtest=True, qwen_confs=1008)
        production_launch(settle_deadline=720, btc_regtest=True, btc_confs=100)
        with self.assertRaisesRegex(D.DescriptorError, short.format("btc_confs")):
            production_launch(settle_deadline=720, qwen_regtest=True, btc_confs=37)
        test_launch(settle_deadline=110, btc_confs=100, qwen_confs=1008)        # both legs on regtest
        # it is the last thing asked of the legs, and comes before everything about the chain itself
        with self.assertRaisesRegex(D.DescriptorError, "qwen_min_payment: at least 546"):
            production_launch(settle_deadline=720, qwen_confs=37, qwen_min_payment=1)
        with self.assertRaisesRegex(D.DescriptorError, short.format("qwen_confs")):
            production_launch(settle_deadline=720, qwen_confs=37, ticker="ab")
        # What the tools make never fails it: settle_deadline_for gives every real leg three times its
        # confirmations (and a day at least), whatever the block time and whoever set the confirmations.
        for spacing in (2, 3, 5, 60, 600, 3600):
            for btc_confs, qwen_confs in ((1, 1), (1, 6), (100, 6), (6, 1008), (100, 1008)):
                for regtest, qregtest in ((False, False), (True, False), (False, True)):
                    d = production_launch(target_spacing=spacing, ftl=D.default_ftl(spacing, 45), btc_confs=btc_confs,
                                          qwen_confs=qwen_confs, btc_regtest=regtest, qwen_regtest=qregtest,
                                          settle_deadline=10**6)
                    d.settle_deadline = 720
                    d.settle_deadline = D.settle_deadline_for(d)
                    D.validate(d)
                    real = [c for c, r in ((btc_confs, regtest), (qwen_confs, qregtest)) if not r]
                    self.assertGreaterEqual(d.settle_deadline * spacing, 1800 * max(real), (spacing, btc_confs, qwen_confs))
                    self.assertGreaterEqual(d.settle_deadline, 86400 // spacing)
                    self.assertLessEqual(d.settle_deadline, 1_000_000)
        qh, qstarts = qwen_headers()
        for total in (1, 240, 241, 40_320):  # make(): what `launch new` and the site's form call
            d = D.make("Cover", "CVR", bytes.fromhex("0014" + "11" * 20), 10**9, btc_anchor=(2016, mainnet_headers()[2016].hex()),
                       sats_total=COIN, creator_btc_script=bytes.fromhex("0014" + "22" * 20), target_spacing=2,
                       qwen_anchor=(2000, qh[2000].hex(), qstarts[0]), qwen_total=total * COIN,
                       creator_qwen_script=bytes.fromhex("0014" + "33" * 20))
            self.assertEqual(d.qwen_confs, max(6, -(-5 * total // 200)))
            self.assertGreaterEqual(d.settle_deadline * 2, 1800 * d.qwen_confs)

    def test_a_refusal_is_in_the_nodes_words_and_the_first_one_the_node_would_give(self):
        """What the node says of a launch file is what this says (test_diff_cpp holds the two together
        on thousands of files; these are the ones a reader may want to see): the words of each kind of
        fault, and of two faults the one whose key the node reads first."""
        import json
        base = production_launch().to_json()

        def why(**change):
            with self.assertRaises(D.DescriptorError) as e:
                D.parse(json.dumps({k: v for k, v in dict(base, **change).items() if v is not None}))
            return str(e.exception)

        for change, words in (
                (dict(genesis_time=2**63), "genesis_time: expected integer"),      # past 64 bits: not an integer to the node
                (dict(genesis_time=2**63 - 1), "genesis_time: out of range"),
                (dict(genesis_time=1.5), "genesis_time: expected integer"), (dict(genesis_time=True), "genesis_time: expected integer"),
                (dict(genesis_time="0x"), "genesis_time: invalid hex"), (dict(genesis_time="0xzz"), "genesis_time: invalid hex"),
                (dict(genesis_time="0x1" + "0" * 16), "genesis_time: invalid hex"),  # more than 64 bits of hex
                (dict(genesis_time="0x" + "f" * 16), "genesis_time: out of range"),
                (dict(genesis_time="9" * 30), "genesis_time: not an integer"), (dict(genesis_time="x"), "genesis_time: not an integer"),
                (dict(genesis_time="0X10"), "genesis_time: not an integer"), (dict(genesis_time="-5"), "genesis_time: out of range"),
                (dict(creator_script=5), "creator_script: expected string"), (dict(creator_script="zz"), "creator_script: invalid hex"),
                (dict(name=""), "name: 1..64 chars"), (dict(name="\u03bb" * 33), "name: 1..64 chars"),  # 66 bytes of UTF-8
                (dict(virtual_work=str(2**256)), "virtual_work: expected decimal or 0x-hex integer string"),
                (dict(virtual_work=str(2**256 - 1)), "virtual_work: must be in (0, 2^160]"),
                (dict(qwen_regtest=1), "qwen_regtest: expected bool"), (dict(btc_regtest="true"), "btc_regtest: expected bool"),
                # two faults: the key read first
                (dict(genesis_time="x", qwen_regtest=1), "genesis_time: not an integer"),
                (dict(btc_regtest=1, qwen_anchor_height=-1), "btc_regtest: expected bool"),
                (dict(qwen_anchor_header="zz", sats_num="x"), "sats_num: not an integer"),
                (dict(meta="zz", qwen_confs=2000), "qwen_confs: out of range"),
                (dict(creator_script=5, creator_fee_bps="x"), "creator_script: expected string"),
                # what is read comes before what is checked; the legs before the seeds, the seeds before the rest
                (dict(sats_num=0, meta="zz"), "meta: expected 32..32 bytes of hex"),
                (dict(sats_num=0, qwen_num=0, seeds="x", name=""), "sats_num: required (every launch has a sats leg)"),
                (dict(qwen_num=0, seeds="x", name=""), "qwen_num: required (every launch has a QWEN leg)"),
                (dict(seeds="x", name=""), "seeds: expected array of strings"), (dict(name="", ticker="ab"), "name: 1..64 chars")):
            self.assertEqual(why(**change), words, change)
        text = json.dumps(base)
        for extra, words in (('"x":[' + "1" * 41 + '],"ticker":"ZZZ"', "ticker: the key appears twice in one object"),
                             ('"y":' + "1" * 41 + ',"x":{"a":1,"a":2}', "descriptor: a number of more than 40 characters"),
                             ('"x":' + "[" * 64 + "]" * 64 + ',"y":{"a":1,"a":2}', "descriptor: nested more than 64 levels"),
                             ('"foo":1,"bar":2,"bar":3,"foo":4', "bar: the key appears twice in one object")):
            with self.assertRaises(D.DescriptorError) as e:
                D.parse(text[:-1] + "," + extra + "}")
            self.assertEqual(str(e.exception), words)
        for extra in ('"ticker":"Z","x":NaN', '"x":1,"x":"\\ud800"', '"ticker":"Z","x":' + "[" * 512 + "]" * 512):
            with self.assertRaisesRegex(D.DescriptorError, "^descriptor is not a JSON object"):  # before anything else in it
                D.parse(text[:-1] + "," + extra + "}")

    def test_the_qwen_leg_is_as_mandatory_as_the_sats_leg(self):
        import json
        for change, why in ((dict(qwen_num=0), r"qwen_num: required \(every launch has a QWEN leg\)"),
                            (dict(creator_qwen_script=b""), "creator_qwen_script: required"),
                            (dict(creator_qwen_script=b"\x51"), "creator_qwen_script: must be a P2PKH, P2SH or witness-program "
                                                                 r"script \(one a Qwencoin node relays a payment to\)"),
                            (dict(creator_qwen_script=b"\x6a\x14" + bytes(20)), "creator_qwen_script: must be"),
                            (dict(qwen_min_payment=545), "qwen_min_payment: at least 546"),
                            (dict(qwen_confs=0), "qwen_confs: at least 1")):
            with self.assertRaisesRegex(D.DescriptorError, why):
                production_launch(**change)
            with self.assertRaisesRegex(D.DescriptorError, why):  # a test launch is not let off either
                test_launch(**change)
        for change in (dict(qwen_min_payment=546), dict(qwen_confs=1), dict(qwen_confs=1008, settle_deadline=20160),
                       dict(qwen_num=2**62), dict(qwen_shift=128), dict(creator_qwen_script=b"\x51\x20" + bytes(32))):
            production_launch(**change)
        j = production_launch(settle_deadline=20160).to_json()  # two weeks of blocks: long enough for a week of confirmations
        # the file's own limits: qwen_confs goes to 1008 where btc_confs stops at 100
        for key, value, ok in (("qwen_confs", 1008, True), ("qwen_confs", 1009, False), ("btc_confs", 100, True),
                               ("btc_confs", 101, False), ("qwen_num", 2**62, True), ("qwen_num", 2**62 + 1, False),
                               ("qwen_shift", 128, True), ("qwen_shift", 129, False), ("qwen_anchor_height", 2**31, False),
                               ("qwen_anchor_period_time", 2**32, False), ("qwen_min_payment", D.MAX_MONEY + 1, False)):
            if ok:
                self.assertEqual(getattr(D.parse(json.dumps(dict(j, **{key: value}))), key), value)
            else:
                with self.assertRaisesRegex(D.DescriptorError, key + ": out of range"):
                    D.parse(json.dumps(dict(j, **{key: value})))
        for key, value, why in (("qwen_regtest", 1, "qwen_regtest: expected bool"), ("qwen_regtest", "true", "qwen_regtest: expected bool"),
                                ("qwen_anchor_header", "ab" * 79, "qwen_anchor_header: expected 80..80 bytes of hex"),
                                ("creator_qwen_script", "51" * 81, "creator_qwen_script: expected 1..80 bytes of hex"),
                                ("creator_qwen_script", "", "creator_qwen_script: expected 1..80 bytes of hex"),
                                ("qwen_num", "x", "qwen_num: not an integer"), ("qwen_confs", 1.5, "qwen_confs: expected integer")):
            with self.assertRaisesRegex(D.DescriptorError, why):
                D.parse(json.dumps(dict(j, **{key: value})))

    def test_qwen_confs_and_the_deadline_follow_the_size_of_the_leg(self):
        """A proof of a payment on Qwencoin is as hard to fake as qwen_confs Qwencoin blocks are to mine,
        and a block pays 50 qwen: the leg must be dearer to fake than to pay."""
        for coins, need in ((1, 1), (40, 1), (41, 2), (240, 6), (241, 7), (1000, 25), (4000, 100), (40_320, 1008)):
            self.assertEqual(D.qwen_confs_needed(coins * COIN), need, coins)
            self.assertEqual(D.qwen_confs_for(coins * COIN), max(6, need), coins)
        self.assertEqual(D.qwen_confs_needed(40 * COIN + 1), 2)
        with self.assertRaisesRegex(D.DescriptorError, "a QWEN leg of 40,321 qwen would need 1009 Qwencoin confirmations.*"
                                                       "goes up to 1008 .covering 40,320 qwen.: make the leg smaller, or name "
                                                       "qwen_confs yourself"):
            D.qwen_confs_for(40_321 * COIN)
        qh, qstarts = qwen_headers()
        hdrs = mainnet_headers()

        def make(total, **kw):
            return D.make("Sized", "SIZE", b"", 10**12, creator_fee_bps=0, btc_anchor=(0, hdrs[0].hex()), sats_total=10**6,
                          creator_btc_script=D.TEST_BTC_SCRIPT, qwen_anchor=(0, qh[0].hex()), qwen_total=total * COIN,
                          creator_qwen_script=D.TEST_QWEN_SCRIPT, **kw)
        day = 86400 // 5
        # (qwen owed, qwen_confs, settle_deadline in 5 s blocks): a day, or three times the confirmations' ten minutes each
        for total, confs, deadline in ((100, 6, day), (1000, 25, day), (2000, 50, 3 * 50 * 600 // 5), (40_320, 1008, 362_880)):
            d = make(total)
            self.assertEqual((d.qwen_confs, d.settle_deadline), (confs, deadline), total)
        with self.assertRaisesRegex(D.DescriptorError, "would need 1250 Qwencoin confirmations"):
            make(50_000)
        d = make(50_000, qwen_confs=300)                                    # named: taken as it is
        self.assertEqual((d.qwen_confs, d.settle_deadline), (300, 3 * 300 * 600 // 5))
        self.assertEqual(make(100, target_spacing=600, lwma_window=10).settle_deadline, 720)   # a day is 144 blocks: the file's own default is more
        self.assertEqual(make(40_320, target_spacing=2, lwma_window=15).settle_deadline, 907_200)
        slow = make(40_320, qwen_confs=1008, target_spacing=2, lwma_window=15)
        slow.qwen_confs, slow.settle_deadline = 1008, 110
        self.assertEqual(D.settle_deadline_for(slow), 907_200)
        slow.target_spacing = 2
        self.assertLessEqual(D.settle_deadline_for(slow), 1_000_000)        # never past what a launch file may say
        # a regtest leg: no ten-minute blocks to wait for
        t = D.make("Test", "TEST", b"", 10**9, creator_fee_bps=0, test=True)
        self.assertEqual((t.qwen_confs, t.btc_confs, t.settle_deadline), (2, 1, 720))

    def test_check_qwen_anchor_asks_a_qwencoin_node(self):
        qh, qstarts = qwen_headers()
        node = FakeBitcoin([qh[h] for h in range(15)])                      # a Qwencoin node at height 14

        def anchored(height, header, period, **kw):
            return production_launch(qwen_anchor_height=height, qwen_anchor_header=header, qwen_anchor_period_time=period, **kw)

        for d in (anchored(8, qh[8], qstarts[0]), anchored(0, qh[0], qstarts[0])):
            self.assertIsNone(D.check_qwen_anchor(d, node))
        for d, why in ((anchored(7, qh[8], qstarts[0]), "block 7 on this Qwencoin node's chain is " + node.hash(7)),
                       (anchored(2000, qh[2000], qstarts[0]), "this Qwencoin node is only at 14"),
                       (anchored(8, qh[8], qstarts[0] + 1), f"qwen_anchor_period_time is {qstarts[0] + 1}, but the difficulty period "
                                                            f"of block 8 starts at block 0, whose time is {qstarts[0]}"),
                       (anchored(8, qh[8][:76] + bytes(4), qstarts[0]), "the launch's anchor header is block ")):
            with self.assertRaisesRegex(D.DescriptorError, "qwen anchor: .*" + why):
                D.check_qwen_anchor(d, node)
        # the Bitcoin question is put to the Bitcoin node and the Qwencoin question to the Qwencoin node
        btc = FakeBitcoin(mainnet_headers())
        self.assertIsNone(D.check_anchor(production_launch(), btc))
        with self.assertRaisesRegex(D.DescriptorError, "btc anchor: the launch names Bitcoin block 1500, and this Bitcoin node is only at 14"):
            D.check_anchor(production_launch(), node)
        with self.assertRaisesRegex(D.DescriptorError, "qwen anchor: .*block 2000 on this Qwencoin node's chain is"):
            D.check_qwen_anchor(production_launch(), btc)
        for failure in (OSError("connection refused"), KeyError("time")):
            with self.assertRaisesRegex(D.DescriptorError, "qwen anchor: could not ask the Qwencoin node"):
                D.check_qwen_anchor(anchored(8, qh[8], qstarts[0]), FakeBitcoin([qh[h] for h in range(15)], fail=failure))
        on_regtest = anchored(8, qh[8], 0, qwen_regtest=True)               # no period start to check, the block itself it has
        self.assertIsNone(D.check_qwen_anchor(on_regtest, node))
        height, header, period = D.qwen_anchor_from_rpc(node)
        self.assertEqual((height, header, period), (8, qh[8].hex(), qstarts[0]))
        self.assertIsNone(D.check_qwen_anchor(anchored(height, bytes.fromhex(header), period), node))

    def test_check_anchor_asks_a_bitcoin_node(self):
        hdrs = mainnet_headers()
        t0, node = header_time(hdrs[0]), FakeBitcoin(mainnet_headers())

        def anchored(height, header, period, **kw):
            return production_launch(btc_anchor_height=height, btc_anchor_header=header, btc_anchor_period_time=period, **kw)

        for d in (anchored(1500, hdrs[1500], t0), anchored(0, hdrs[0], t0), anchored(2015, hdrs[2015], t0),
                  anchored(2016, hdrs[2016], header_time(hdrs[2016])), production_launch()):
            self.assertIsNone(D.check_anchor(d, node))
        self.assertEqual(node.asked[:4], [("getblockcount",), ("getblockhash", 1500), ("getblockheader", node.hash(1500), False),
                                          ("getblockhash", 0)])
        # Each of these is a launch file both parsers accept. Only a Bitcoin node can tell.
        for d, why in ((anchored(1499, hdrs[1500], t0), "block 1499 on this Bitcoin node's chain is " + node.hash(1499)),
                       (anchored(2017, hdrs[2016], t0), "this Bitcoin node is only at 2016"),
                       (anchored(1500, hdrs[1500], t0 + 1), f"btc_anchor_period_time is {t0 + 1}, but the difficulty period of "
                                                            f"block 1500 starts at block 0, whose time is {t0}"),
                       (anchored(1500, hdrs[1500], 1), "btc_anchor_period_time is 1, but"),
                       (anchored(4032, hdrs[0], t0), "this Bitcoin node is only at 2016")):
            with self.assertRaisesRegex(D.DescriptorError, "btc anchor: .*" + why):
                D.check_anchor(d, node)
        with self.assertRaisesRegex(D.DescriptorError, "the launch's anchor header is block " + node.hash(1500) + ", but block 1500"):
            D.check_anchor(anchored(1500, hdrs[1500], t0), FakeBitcoin(hdrs[:1500] + [hdrs[1499]] + hdrs[1501:]))
        # A launch on regtest Bitcoin has no period start to check, the block itself it has.
        on_regtest = anchored(1500, hdrs[1500], 0, btc_regtest=True)
        self.assertIsNone(D.check_anchor(on_regtest, node))
        with self.assertRaisesRegex(D.DescriptorError, "btc anchor: .*block 1500 on this Bitcoin node's chain is"):
            D.check_anchor(anchored(1500, hdrs[1499], 0, btc_regtest=True), node)
        # A node that does not answer has not said yes.
        for failure in (OSError("connection refused"), KeyError("time"), ValueError("not JSON")):
            with self.assertRaisesRegex(D.DescriptorError, "btc anchor: could not ask the Bitcoin node"):
                D.check_anchor(production_launch(), FakeBitcoin(hdrs, fail=failure))
        with self.assertRaisesRegex(D.DescriptorError, "the header in the launch is not the header of Bitcoin block 1500"):
            D.check_anchor(production_launch(), FakeBitcoin(hdrs, lie=hdrs[1499]))
        # What btc_anchor_from_rpc takes from a node is an anchor that passes.
        height, header, period = D.btc_anchor_from_rpc(node)
        self.assertEqual((height, header, period), (2010, hdrs[2010].hex(), t0))
        self.assertIsNone(D.check_anchor(anchored(height, bytes.fromhex(header), period), node))


def production_launch(**kw):
    """A launch on production rules (not a test launch, Bitcoin's mainnet rules), anchored in the middle
    of the stored difficulty period. Its deadline, 3600 blocks, covers its confirmations at any block
    time a launch may have, so a test may change the block time alone."""
    hdrs = mainnet_headers()
    qh, qstarts = qwen_headers()
    fields = dict(name="Rules", ticker="RULE", hrp="rule", genesis_time=1_700_000_000, virtual_work=10**12,
                  virtual_tokens=12_000_000 * COIN, graduation_tokens=8_869_000 * COIN, pow_limit_bits=0x207FFFFF,
                  target_spacing=60, lwma_window=45, ftl=135, btc_anchor_height=1500, btc_anchor_header=hdrs[1500],
                  btc_anchor_period_time=header_time(hdrs[0]), sats_num=5, sats_shift=3,
                  creator_btc_script=bytes.fromhex("0014" + "22" * 20),
                  # the QWEN leg on the real Qwencoin: anchored in the middle of that chain's first period
                  qwen_anchor_height=2000, qwen_anchor_header=qh[2000], qwen_anchor_period_time=qstarts[0],
                  qwen_num=7, qwen_shift=2, creator_qwen_script=bytes.fromhex("0014" + "33" * 20), settle_deadline=3600)
    fields.update(kw)
    d = D.Launch(**fields)
    D.validate(d)
    return d


_QWEN_HEADERS = []


def qwen_headers():
    """Headers of the real Qwencoin chain (data/qwen_headers.json): ({height: header}, {period's first
    height: its time}). Heights 0..14 and the blocks around the chain's first three retargets."""
    if not _QWEN_HEADERS:
        import json
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "qwen_headers.json")) as f:
            data = json.load(f)
        _QWEN_HEADERS.extend([{x["height"]: bytes.fromhex(x["header"]) for x in data["headers"]},
                              {int(k): v for k, v in data["period_starts"].items()}])
    return _QWEN_HEADERS


_MAINNET_HEADERS = []


def mainnet_headers():
    """Bitcoin's genesis block and 2,016 blocks Bitcoin Core mined on it under mainnet rules: one whole
    difficulty period and the first block of the next (data/mainnet_alt_headers.hex)."""
    if not _MAINNET_HEADERS:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "mainnet_alt_headers.hex")) as f:
            _MAINNET_HEADERS.extend(bytes.fromhex(x) for x in f.read().split())
    return _MAINNET_HEADERS


def header_time(header: bytes) -> int:
    return struct.unpack("<I", header[68:72])[0]


class FakeBitcoin:
    """The three calls check_anchor makes, answered from a list of headers (height = position)."""

    def __init__(self, headers, fail=None, lie=None):
        self.headers, self.fail, self.lie, self.asked = list(headers), fail, lie, []
        self.by_hash = {sha256d(h)[::-1].hex(): h for h in self.headers}

    def hash(self, height):
        return sha256d(self.headers[height])[::-1].hex()

    def getblockcount(self):
        self.asked.append(("getblockcount",))
        if self.fail:
            raise self.fail
        return len(self.headers) - 1

    def getblockhash(self, height):
        self.asked.append(("getblockhash", height))
        return self.hash(height)

    def getblockheader(self, block_hash, verbose=True):
        self.asked.append(("getblockheader", block_hash, verbose))
        header = self.lie or self.by_hash[block_hash]
        return {"hash": block_hash, "time": header_time(header)} if verbose else header.hex()


class LaunchTool(unittest.TestCase):
    """hashfun launch new / info (hashfun/launch.py): the Bitcoin anchor a launch is given."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp(prefix="hashfun-launch-test-")
        self.addCleanup(__import__("shutil").rmtree, self.tmp, ignore_errors=True)
        self.out = os.path.join(self.tmp, "launch.json")
        self.hdrs = mainnet_headers()
        self.t0 = header_time(self.hdrs[0])

    BTC_URL, QWEN_URL = "http://127.0.0.1:1", "http://127.0.0.1:2"

    def run_tool(self, *argv, node=None, qnode=None):
        """(exit code, stdout, stderr) of the launch tool; `node` stands in for the Bitcoin node of
        --btc-rpc (asked at BTC_URL) and `qnode` for the Qwencoin node of --qwen-rpc (at QWEN_URL)."""
        import contextlib
        import io
        from unittest import mock
        from hashfun import launch
        out, err, code = io.StringIO(), io.StringIO(), 0
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch("hashfun.rpc.RPC", lambda url, cookie_file=None: qnode if url == self.QWEN_URL else node):
            try:
                launch.main(list(argv))
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    QWEN_LEG = ("--qwen-total", "100", "--creator-qwen-address", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")

    def btc_leg(self):
        """A Bitcoin anchor that needs nothing else said (it opens its difficulty period)."""
        return ("--btc-anchor", f"2016:{self.hdrs[2016].hex()}")

    def new(self, *more, node=None, qnode=None, qwen=None):
        """`launch new` with a sats leg and (unless qwen=() says otherwise) a QWEN leg anchored at
        Qwencoin's own first block."""
        if qwen is None:
            qwen = (*self.QWEN_LEG, "--qwen-anchor", f"0:{qwen_headers()[0][0].hex()}")
        return self.run_tool("new", "--name", "Tool", "--ticker", "TOOL", "--creator-address", segwit_encode("tool", 0, bytes(20)),
                             "--graduation-hashes", "1e6", "--pow-limit", "207fffff", "--sats-total", "0.01",
                             "--creator-btc-address", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "-o", self.out, *qwen, *more,
                             node=node, qnode=qnode)

    def test_anchor_without_its_period_start(self):
        # in the middle of a difficulty period the start time has to be given: the tool says so and writes nothing
        code, _, err = self.new("--btc-anchor", f"1500:{self.hdrs[1500].hex()}")
        self.assertEqual(code, 2)
        self.assertIn("--btc-anchor HEIGHT:HEADERHEX[:PERIODTIME]", err)
        self.assertIn("may be left out only when the height is a multiple of 2016", err)
        self.assertIn("block 1500 is inside a period, which starts at block 0", err)
        self.assertFalse(os.path.exists(self.out))
        # at a retarget boundary it is the header's own time
        code, out, err = self.new("--btc-anchor", f"2016:{self.hdrs[2016].hex()}")
        self.assertEqual(code, 0, err)
        d = D.load(self.out)
        self.assertEqual((d.btc_anchor_height, d.btc_anchor_header, d.btc_anchor_period_time, d.btc_regtest, d.test),
                         (2016, self.hdrs[2016], header_time(self.hdrs[2016]), False, False))
        self.assertEqual((d.version, d.ftl), (3, D.default_ftl(5, 90)))
        self.assertTrue(d.genesis_valid())
        self.assertIn("Add --btc-rpc URL to check it against a Bitcoin node", err)  # taken as given, and said so
        self.assertIn("Add --qwen-rpc URL to check it against a Qwencoin node", err)
        import json
        self.assertEqual(json.loads(out)["btc_anchor"], {"height": 2016, "block": sha256d(self.hdrs[2016])[::-1].hex(),
                                                         "period_time": header_time(self.hdrs[2016]), "regtest": False})

    def test_anchor_with_its_period_start(self):
        code, _, err = self.new("--btc-anchor", f"1500:{self.hdrs[1500].hex()}:{self.t0}")
        self.assertEqual(code, 0, err)
        d = D.load(self.out)
        self.assertEqual((d.btc_anchor_height, d.btc_anchor_period_time), (1500, self.t0))
        for anchor, why in ((f"1500:{self.hdrs[1500].hex()}:0", "btc_anchor_period_time: required"),
                            (f"2016:{self.hdrs[2016].hex()}:{self.t0}", "the anchor opens a difficulty period"),
                            (f"1500:{self.hdrs[1500].hex()[:-8]}00000001:{self.t0}", "does not meet its own difficulty"),
                            (f"0:{D.REGTEST_GENESIS_HEADER.hex()}", "easier than Bitcoin's minimum difficulty"),
                            ("1500", "btc anchor: expected a height"), (f"x:{self.hdrs[0].hex()}", "btc anchor: expected a height"),
                            (f"0:{self.hdrs[0].hex()[:-2]}", "the header is 80 bytes")):
            code, _, err = self.new("--btc-anchor", anchor)
            self.assertEqual(code, 2, anchor[:20])
            self.assertIn(why, err)
            self.assertNotIn("Traceback", err)
        # --help says which is which
        code, out, _ = self.run_tool("new", "--help")
        self.assertEqual(code, 0)
        self.assertIn("PERIODTIME may be left out only when HEIGHT is a multiple of 2016", " ".join(out.split()))

    def test_test_launches_need_no_period_start(self):
        code, _, err = self.new("--test", "--btc-anchor", f"1500:{D.REGTEST_GENESIS_HEADER.hex()}")
        self.assertEqual(code, 0, err)
        d = D.load(self.out)
        self.assertEqual((d.btc_anchor_height, d.btc_anchor_period_time, d.btc_regtest, d.test), (1500, 0, True, True))
        code, _, err = self.new("--test")
        self.assertEqual(code, 0, err)
        self.assertEqual(D.load(self.out).btc_anchor_header, D.REGTEST_GENESIS_HEADER)
        # --test fills both legs: nothing about Qwencoin has to be said
        code, _, err = self.new("--test", qwen=())
        self.assertEqual(code, 0, err)
        d = D.load(self.out)
        self.assertEqual((d.qwen_regtest, d.qwen_anchor_header, d.qwen_num, d.qwen_confs, d.creator_qwen_script),
                         (True, D.REGTEST_GENESIS_HEADER, 7000, 2, D.TEST_QWEN_SCRIPT))
        code, _, err = self.new("--test", "--qwen-regtest", "--qwen-anchor", f"9:{D.REGTEST_GENESIS_HEADER.hex()}", qwen=())
        self.assertEqual((code, D.load(self.out).qwen_anchor_height, D.load(self.out).qwen_regtest), (0, 9, True), err)

    def test_a_test_launch_may_have_a_real_qwen_leg(self):
        """--test makes the QWEN leg a regtest one only when no Qwencoin is named. With a Qwencoin node or
        a Qwencoin anchor the leg follows the real chain (how a test launch is run against a real
        Qwencoin), and --qwen-regtest says otherwise."""
        qh, qstarts = qwen_headers()
        qnode = FakeBitcoin([qh[h] for h in range(15)])  # --qwen-rpc alone anchors six below its tip: block 8
        real = (*self.QWEN_LEG, "--qwen-anchor", f"8:{qh[8].hex()}:{qstarts[0]}")
        for label, args, qn, want in (
                ("nothing named", ("--test",), None, True),
                ("--qwen-regtest", ("--qwen-regtest", *self.btc_leg(), "--creator-qwen-address", "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                                    "--qwen-hrp", "bcrt"), None, True),
                ("--test and an anchor", ("--test", *real), None, False),
                ("--test and a node", ("--test", *self.QWEN_LEG, "--qwen-rpc", self.QWEN_URL), qnode, False),
                ("--test, an anchor and a node", ("--test", *real, "--qwen-rpc", self.QWEN_URL), qnode, False),
                ("an anchor, no --test", (*self.btc_leg(), *real), None, False)):
            code, _, err = self.new(*args, qnode=qn, qwen=())
            self.assertEqual(code, 0, (label, err))
            d = D.load(self.out)
            self.assertEqual(d.qwen_regtest, want, label)
            self.assertEqual(d.test, "--test" in args, label)
            if not want:  # the real chain's rules: its own confirmations, a deadline that covers them, a real anchor
                self.assertEqual((d.qwen_confs, d.qwen_anchor_height, d.qwen_anchor_header), (6, 8, qh[8]), label)
                self.assertGreaterEqual(d.settle_deadline * d.target_spacing, 3 * d.qwen_confs * 600, label)
            else:
                self.assertEqual(d.qwen_confs, D.TEST_QWEN_CONFS, label)
        # a test launch on a regtest Qwencoin node says so: without --qwen-regtest its anchor is held to the
        # real chain's rules, and a regtest header is far too easy to be one
        regtest_node = FakeBitcoin([D.REGTEST_GENESIS_HEADER])
        code, _, err = self.new("--test", *self.QWEN_LEG, "--qwen-rpc", self.QWEN_URL, qnode=regtest_node, qwen=())
        self.assertEqual(code, 2)
        self.assertIn("easier than Qwencoin's minimum difficulty (not a Qwencoin mainnet header; a regtest anchor needs "
                      "qwen_regtest)", err)
        code, _, err = self.new("--test", "--qwen-regtest", *self.QWEN_LEG, "--qwen-rpc", self.QWEN_URL, qnode=regtest_node, qwen=())
        self.assertEqual((code, D.load(self.out).qwen_regtest), (0, True), err)

    def test_the_qwen_leg_is_asked_for_like_the_sats_leg(self):
        import json
        qh, qstarts = qwen_headers()
        qnode = FakeBitcoin([qh[h] for h in range(15)])
        # nothing said about Qwencoin: no launch, and the message says what is missing
        code, _, err = self.new(*self.btc_leg(), qwen=())
        self.assertEqual(code, 2)
        self.assertIn("qwen_num: required (every launch has a QWEN leg)", err)
        self.assertIn("--qwen-total, --creator-qwen-address and a Qwencoin anchor (--qwen-rpc or --qwen-anchor)", err)
        self.assertFalse(os.path.exists(self.out))
        for missing, why in ((("--qwen-total", "100", "--qwen-anchor", f"0:{qh[0].hex()}"), "creator_qwen_script: required"),
                             (self.QWEN_LEG, "qwen_anchor_header: required")):
            code, _, err = self.new(*self.btc_leg(), qwen=missing)
            self.assertEqual(code, 2)
            self.assertIn(why, err)
        # --qwen-rpc alone: the anchor six blocks below the Qwencoin node's tip
        code, out, err = self.new(*self.btc_leg(), "--qwen-rpc", self.QWEN_URL, qwen=self.QWEN_LEG, qnode=qnode)
        self.assertEqual(code, 0, err)
        d = D.load(self.out)
        self.assertEqual((d.qwen_anchor_height, d.qwen_anchor_header, d.qwen_anchor_period_time, d.qwen_regtest),
                         (8, qh[8], qstarts[0], False))
        self.assertNotIn("the Qwencoin anchor was taken as given", err)
        self.assertEqual(d.creator_qwen_script, bytes.fromhex("0014751e76e8199196d454941c45d1b3a323f1433bd6"))
        self.assertAlmostEqual(d.leg_total("qwen") / (100 * COIN), 1.0, places=5)
        self.assertAlmostEqual(d.leg_total("btc") / 1_000_000, 1.0, places=5)
        info = json.loads(out)
        self.assertEqual(info["qwen_anchor"], {"height": 8, "block": sha256d(qh[8])[::-1].hex(), "period_time": qstarts[0],
                                               "regtest": False})
        self.assertEqual((info["legs"]["qwen"]["total"], info["legs"]["qwen"]["confs"], info["legs"]["btc"]["confs"]),
                         (d.leg_total("qwen"), 6, 1))
        self.assertAlmostEqual(info["legs"]["implied_qwen_sats_at_start"], 10_000, delta=0.1)  # 0.01 BTC against 100 QWEN
        # the confirmations a QWEN payment needs, and what that means in hours, are said
        self.assertIn("qwen_confs 6: a payment on Qwencoin counts once it is 6 blocks deep, about 1.0 hours", err)
        os.remove(self.out)
        # an anchor given by hand is checked against the Qwencoin node
        code, _, err = self.new(*self.btc_leg(), "--qwen-anchor", f"8:{qh[8].hex()}:{qstarts[0]}", "--qwen-rpc", self.QWEN_URL, qwen=self.QWEN_LEG,
                                qnode=qnode)
        self.assertEqual((code, D.load(self.out).qwen_anchor_height), (0, 8), err)
        os.remove(self.out)
        for anchor, why in ((f"8:{qh[8].hex()}:{qstarts[0] + 60}", f"qwen_anchor_period_time is {qstarts[0] + 60}, but"),
                            (f"7:{qh[8].hex()}:{qstarts[0]}", "block 7 on this Qwencoin node's chain is"),
                            (f"2000:{qh[2000].hex()}:{qstarts[0]}", "this Qwencoin node is only at 14")):
            code, _, err = self.new(*self.btc_leg(), "--qwen-anchor", anchor, "--qwen-rpc", self.QWEN_URL, qwen=self.QWEN_LEG, qnode=qnode)
            self.assertEqual(code, 2)
            self.assertIn(why, err)
            self.assertFalse(os.path.exists(self.out))
        code, _, err = self.new(*self.btc_leg(), "--qwen-anchor", f"2000:{qh[2000].hex()}", qwen=self.QWEN_LEG)
        self.assertEqual(code, 2)
        self.assertIn("--qwen-anchor HEIGHT:HEADERHEX[:PERIODTIME]", err)
        self.assertIn("block 2000 is inside a period, which starts at block 0", err)
        code, _, err = self.new(*self.btc_leg(), "--qwen-rpc", self.QWEN_URL, qwen=self.QWEN_LEG,
                                qnode=FakeBitcoin([qh[0]], fail=OSError("connection refused")))
        self.assertEqual(code, 2)
        self.assertIn("could not read the anchor from the Qwencoin node: connection refused", err)

    def test_a_qwen_leg_too_large_for_its_confirmations_is_refused(self):
        qh = qwen_headers()[0]
        anchor = ("--qwen-anchor", f"0:{qh[0].hex()}", "--creator-qwen-address", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        code, _, err = self.new(*self.btc_leg(), qwen=("--qwen-total", "2000", *anchor))
        self.assertEqual(code, 0, err)
        d = D.load(self.out)
        self.assertEqual((d.qwen_confs, d.settle_deadline), (50, 18_000))    # 50 confirmations: 8.3 hours; three times that to settle
        self.assertIn("qwen_confs 50: a payment on Qwencoin counts once it is 50 blocks deep, about 8.3 hours; settle_deadline "
                      "18000 launch blocks, about 25.0 hours", err)
        os.remove(self.out)
        code, _, err = self.new(*self.btc_leg(), qwen=("--qwen-total", "50000", *anchor))
        self.assertEqual(code, 2)
        self.assertIn("a QWEN leg of 50,000 qwen would need 1250 Qwencoin confirmations", err)
        self.assertEqual(len(err.strip().splitlines()[-1].split("error: ")[1].splitlines()), 1)  # in one line
        self.assertFalse(os.path.exists(self.out))
        code, _, err = self.new(*self.btc_leg(), "--qwen-confs", "1008", qwen=("--qwen-total", "50000", *anchor))
        self.assertEqual((code, D.load(self.out).qwen_confs), (0, 1008), err)
        code, _, err = self.new(*self.btc_leg(), "--qwen-confs", "1009", qwen=("--qwen-total", "100", *anchor))
        self.assertEqual(code, 2)
        self.assertIn("qwen_confs", err)

    def test_btc_rpc_gives_the_anchor_or_checks_the_one_given(self):
        node = FakeBitcoin(self.hdrs)
        code, _, err = self.new("--btc-rpc", "http://127.0.0.1:1", node=node)  # six blocks below the node's tip
        self.assertNotIn("the Bitcoin anchor was taken as given", err)
        self.assertEqual(code, 0, err)
        d = D.load(self.out)
        self.assertEqual((d.btc_anchor_height, d.btc_anchor_header, d.btc_anchor_period_time), (2010, self.hdrs[2010], self.t0))
        os.remove(self.out)
        # an anchor given by hand is checked against the node, not replaced by the node's
        code, _, err = self.new("--btc-anchor", f"1500:{self.hdrs[1500].hex()}:{self.t0}", "--btc-rpc", "http://127.0.0.1:1", node=node)
        self.assertEqual(code, 0, err)
        self.assertEqual(D.load(self.out).btc_anchor_height, 1500)
        os.remove(self.out)
        for anchor, why in ((f"1500:{self.hdrs[1500].hex()}:{self.t0 + 60}", f"btc_anchor_period_time is {self.t0 + 60}, but"),
                            (f"1499:{self.hdrs[1500].hex()}:{self.t0}", "block 1499 on this Bitcoin node's chain is")):
            code, _, err = self.new("--btc-anchor", anchor, "--btc-rpc", "http://127.0.0.1:1", node=node)
            self.assertEqual(code, 2)
            self.assertIn(why, err)
            self.assertFalse(os.path.exists(self.out))
        code, _, err = self.new("--btc-rpc", "http://127.0.0.1:1", node=FakeBitcoin(self.hdrs, fail=OSError("connection refused")))
        self.assertEqual(code, 2)
        self.assertIn("could not read the anchor from the Bitcoin node: connection refused", err)

    def test_info_reads_and_checks_a_launch_file(self):
        import json
        node = FakeBitcoin(self.hdrs)
        d = production_launch()
        with open(self.out, "w") as f:
            f.write(d.dumps())
        code, out, err = self.run_tool("info", self.out)
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["btc_anchor"], {"height": 1500, "block": node.hash(1500), "period_time": self.t0,
                                                         "regtest": False})
        code, out, err = self.run_tool("info", self.out, "--btc-rpc", "http://127.0.0.1:1", node=node)
        self.assertEqual(code, 0, err)
        self.assertTrue(json.loads(out)["btc_anchor"]["checked"])
        self.assertNotIn("checked", json.loads(out)["qwen_anchor"])           # nobody asked a Qwencoin node
        qh, qstarts = qwen_headers()
        self.assertEqual(json.loads(out)["qwen_anchor"], {"height": 2000, "block": sha256d(qh[2000])[::-1].hex(),
                                                          "period_time": qstarts[0], "regtest": False})
        qnode = FakeBitcoin([qh[h] for h in range(15)])
        code, out, err = self.run_tool("info", self.out, "--qwen-rpc", self.QWEN_URL, qnode=qnode)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("qwen anchor: the launch names Qwencoin block 2000, and this Qwencoin node is only at 14", err)
        with open(self.out, "w") as f:
            f.write(production_launch(qwen_anchor_height=8, qwen_anchor_header=qh[8]).dumps())
        code, out, err = self.run_tool("info", self.out, "--qwen-rpc", self.QWEN_URL, "--btc-rpc", self.BTC_URL, node=node, qnode=qnode)
        self.assertEqual(code, 0, err)
        self.assertTrue(json.loads(out)["qwen_anchor"]["checked"] and json.loads(out)["btc_anchor"]["checked"])
        with open(self.out, "w") as f:
            f.write(d.dumps())
        wrong = production_launch(btc_anchor_period_time=self.t0 + 1)  # a file both parsers accept
        with open(self.out, "w") as f:
            f.write(wrong.dumps())
        self.assertEqual(self.run_tool("info", self.out)[0], 0)
        code, out, err = self.run_tool("info", self.out, "--btc-rpc", "http://127.0.0.1:1", node=node)
        self.assertEqual((code, out), (2, ""))
        self.assertIn(f"btc_anchor_period_time is {self.t0 + 1}, but the difficulty period of block 1500 starts at block 0", err)
        # a file made for the rules before these, and one that is no launch file at all
        for version, why in ((1, "version: 1 is the earlier, pre-release rule set. This launch file must be created again"),
                             (2, "version: 2 is the earlier rule set with one curve, quoted in BTC only. This launch file must be "
                                 "created again")):
            with open(self.out, "w") as f:
                f.write(json.dumps(dict(d.to_json(), version=version)))
            for cmd in ("info", "conf"):
                code, out, err = self.run_tool(cmd, self.out)
                self.assertEqual((code, out), (2, ""))
                self.assertIn(why, err)
                self.assertNotIn("Traceback", err)
        code, _, err = self.run_tool("info", os.path.join(self.tmp, "none.json"))
        self.assertEqual(code, 2)
        self.assertIn("No such file", err)


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


class WalletVaultTest(unittest.TestCase):
    def test_chacha20_poly1305_rfc8439(self):
        from hashfun.crypto import aead_encrypt, aead_decrypt
        key, nonce = bytes(range(0x80, 0xA0)), bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
              b"sunscreen would be it.")
        sealed = aead_encrypt(key, nonce, pt, aad)
        self.assertEqual(sealed[:16].hex(), "d31a8d34648e60db7b86afbc53ef7ec2")
        self.assertEqual(sealed[-16:].hex(), "1ae10b594f09e26a7e902ecbd0600691")
        self.assertEqual(aead_decrypt(key, nonce, sealed, aad), pt)
        for bad in (sealed[:-1] + bytes([sealed[-1] ^ 1]), bytes([sealed[0] ^ 1]) + sealed[1:]):
            with self.assertRaises(ValueError):
                aead_decrypt(key, nonce, bad, aad)
        with self.assertRaises(ValueError):
            aead_decrypt(key, nonce, sealed, b"other")

    def test_wallet_file_holds_no_secrets_once_encrypted(self):
        import tempfile
        from hashfun.wallet import Wallet, WalletLocked
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "w.json")
            w = Wallet.create(path, password="correct horse battery")
            words = w.data["mnemonic"]
            w.data["swaps"]["x"] = {"secret": "aa" * 32}
            w.add_chain("BTC", "127.0.0.1:1", "bcrt", 1, "btc")
            raw = open(path).read()
            self.assertNotIn(words.split()[0] + " " + words.split()[1], raw)
            self.assertNotIn("aa" * 32, raw)
            self.assertIn('"chains"', raw)
            with self.assertRaises(WalletLocked):
                Wallet(path)
            with self.assertRaises(WalletLocked):
                Wallet(path, "wrong password")
            again = Wallet(path, "correct horse battery")
            self.assertEqual(again.data["mnemonic"], words)
            self.assertEqual(again.data["swaps"]["x"]["secret"], "aa" * 32)
            self.assertEqual(again.root.key, w.root.key)
            again.set_password("another one, longer")
            self.assertEqual(Wallet(path, "another one, longer").data["mnemonic"], words)
            with self.assertRaises(WalletLocked):
                Wallet(path, "correct horse battery")




class RpcConnections(unittest.TestCase):
    """The RPC client keeps one connection per thread for calls that only read, and never sends
    anything else twice. A new connection per call ran a Mac out of ports in the first CI run."""

    def setUp(self):
        import http.server
        import json
        import threading
        seen = self.seen = {"conns": set(), "calls": [], "drop_after": None, "served": 0}

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen["conns"].add(self.client_address)
                seen["calls"].append(req["method"])
                seen["served"] += 1
                if req["method"] == "getnothing":  # close without a word, as a node that died would
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
                body = json.dumps({"result": req["method"], "error": None, "id": req["id"]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                if seen["drop_after"] is not None and seen["served"] >= seen["drop_after"]:
                    seen["drop_after"] = None
                    self.close_connection = True  # an idle connection the node gave up on: closed, and nobody told the client

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        from hashfun.rpc import RPC
        self.rpc = RPC(f"http://u:p@127.0.0.1:{self.srv.server_address[1]}", timeout=5)

    def tearDown(self):
        self.rpc.close()
        self.srv.shutdown()
        self.srv.server_close()

    def test_reads_share_one_connection(self):
        for _ in range(50):
            self.assertEqual(self.rpc.getblockcount(), "getblockcount")
        self.assertEqual(self.rpc.wallet("w").listunspent(), "listunspent")
        self.assertEqual(len(self.seen["conns"]), 1, "50 reads and a wallet view's read: one connection")

    def test_anything_else_gets_its_own_connection(self):
        self.rpc.getblockcount()
        self.rpc.sendtoaddress("a", 1)
        self.rpc.submitblock("00")
        self.rpc.getblockcount()
        self.assertEqual(len(self.seen["conns"]), 3, "the kept one, and one for each call that changes something")

    def test_a_read_is_sent_again_when_the_kept_connection_went_stale(self):
        self.seen["drop_after"] = 1
        self.rpc.getblockcount()            # served, then the server closes the connection behind it
        self.assertEqual(self.rpc.getbestblockhash(), "getbestblockhash")  # stale: sent again on a new one
        self.assertEqual(len(self.seen["conns"]), 2)
        self.assertEqual(self.seen["calls"].count("getbestblockhash"), 1, "the first attempt never reached the server")

    def test_nothing_that_changes_things_is_ever_sent_twice(self):
        import http.client
        self.seen["drop_after"] = 1
        self.rpc.getblockcount()
        self.rpc.sendtoaddress("a", 1)      # its own connection: the stale kept one is not in its way
        self.assertEqual(self.seen["calls"].count("sendtoaddress"), 1)
        with self.assertRaises((http.client.HTTPException, OSError)):
            self.rpc.wallet("w").getnothing()   # a new connection, and the server hangs up: no second try
        self.assertEqual(self.seen["calls"].count("getnothing"), 1)

    def test_each_thread_has_its_own(self):
        import threading
        self.rpc.getblockcount()
        t = threading.Thread(target=self.rpc.getblockcount)
        t.start()
        t.join()
        self.assertEqual(len(self.seen["conns"]), 2)

    def test_after_an_error_the_next_call_starts_clean(self):
        import http.client
        with self.assertRaises((http.client.HTTPException, OSError)):
            self.rpc.getnothing()
        self.assertEqual(self.rpc.getblockcount(), "getblockcount")

if __name__ == "__main__":
    unittest.main()
