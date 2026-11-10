"""Differential test: the node's consensus C++ (kernel/launch.cpp, kernel/chainparams.cpp,
launchcurve.cpp, pow.cpp) against the independent Python model, value by value.

The C++ side is contrib/hashfun/difftest (build.sh compiles just those files plus their
leaf dependencies, no node, no build system). Point HFDIFF at the binary:

  bash contrib/hashfun/difftest/build.sh /tmp/hfdiff
  HFDIFF=/tmp/hfdiff python -m unittest hashfun.tests.test_diff_cpp -v

Skipped when HFDIFF is unset. HFDIFF_SEED / HFDIFF_N tune the random cases.
"""
import json
import os
import random
import subprocess
import unittest

from hashfun import descriptor as D
from hashfun.ser import bits_to_target, target_to_bits, work_from_bits

COIN = 100_000_000
SEED = int(os.environ.get("HFDIFF_SEED", "1"))
N = int(os.environ.get("HFDIFF_N", "40"))
DELETE = object()


class Driver:
    def __init__(self, path):
        self.p = subprocess.Popen([path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def __call__(self, **req):
        self.p.stdin.write(json.dumps(req) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError("driver exited")
        return json.loads(line)

    def close(self):
        self.p.stdin.close()
        self.p.wait(10)


def launch(rng, easy=True, **kw):
    """A random but valid descriptor; easy=True keeps genesis grinding cheap."""
    t0 = rng.choice([1000, 21_000, 15_000_000, 21_000_000, 20_999_999]) * COIN
    g = rng.randint(1, t0 - t0 // 1000) if rng.random() < 0.5 else t0 * D.PUMP_RATIO_G // D.PUMP_RATIO_T
    ihl = rng.choice([0, 1, 1000, 210_000, 2**31])
    tail = 0 if ihl == 0 else rng.randint(0, (D.MAX_MONEY - g) // (2 * ihl))
    script = bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 22, 34, 100])))
    base = dict(
        name=rng.choice(["Test Launch", "x", "λ launch ✓", "a" * 64]),
        ticker=rng.choice(["TST", "AB", "ABCDEFGHIJ", "Z9"]),
        hrp=rng.choice(["tst", "z", "abcdefghij0123456789"]),
        genesis_time=rng.choice([0, 1, 1_700_000_000, 2**32 - 1]),
        virtual_work=rng.choice([1, 2, rng.randrange(1, 2**64), rng.randrange(1, 2**160), 2**160]),
        virtual_tokens=t0, graduation_tokens=g,
        pubkey_prefix=rng.choice([40, 1, 255]), script_prefix=rng.choice([100, 2, 254]),
        secret_prefix=rng.randrange(256),
        pow_limit_bits=rng.choice([0x207FFFFF, 0x2000FFFF, 0x1F00FFFF, 0x1F7FFFFF] if easy else [0x1D00FFFF]),
        target_spacing=rng.choice([1, 10, 60, 600, 3600]), lwma_window=rng.choice([3, 10, 45, 144, 1000]),
        ftl=rng.choice([1, 300, 7200]), tail_reward=tail, tail_halving_interval=ihl if tail else rng.choice([0, ihl]),
        creator_script=script, creator_fee_bps=rng.choice([0, 1, 100, 1000]) if script else 0,
        test=rng.random() < 0.5,
        p2p_port=rng.choice([0, 0, 18444]), rpc_port=rng.choice([0, 0, 18445]),
    )
    base.update(kw)
    d = D.Launch(**base)
    D.validate(d)
    if easy:
        d.grind_genesis()
    return d


def first_graduation(works, wg):
    acc = 0
    for h, w in enumerate(works, 1):
        acc += w
        if acc >= wg:
            return h
    return -1


def tail_minted_py(d, lo, hi):
    """Independent of LaunchTailMinted's segment loop: per-height sum where cheap,
    closed form per halving otherwise."""
    if lo > hi:
        return 0
    if hi - lo <= 20_000:
        return sum(d.tail_reward_at(h) for h in range(lo, hi + 1))
    total, H = 0, d.tail_halving_interval
    for k in range(64):
        a, b = max(lo, k * H), min(hi, (k + 1) * H - 1)
        if a <= b:
            total += (b - a + 1) * d.tail_reward_at(a)
    return total


@unittest.skipUnless(os.environ.get("HFDIFF"), "HFDIFF not set (build contrib/hashfun/difftest)")
class DiffCpp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.drv = Driver(os.environ["HFDIFF"])

    @classmethod
    def tearDownClass(cls):
        cls.drv.close()

    def desc(self, d):
        r = self.drv(op="desc", json=d.dumps())
        self.assertTrue(r["ok"], r)
        return r

    def assert_identity(self, d):
        r = self.desc(d)
        self.assertEqual(r["canon"], d.canonical_bytes().hex())
        self.assertEqual(r["id"], d.id_hex)
        self.assertEqual(r["magic"], d.magic.hex())
        self.assertEqual(r["chain_id"], d.chain_id)
        self.assertEqual((r["p2p"], r["rpc"]), (d.p2p, d.rpc))
        self.assertEqual(r["datadir"], d.datadir_name)
        return r

    def test_identity_and_params(self):
        rng = random.Random(SEED)
        for i in range(N):
            d = launch(rng)
            with self.subTest(i=i, ticker=d.ticker):
                r = self.assert_identity(d)
                self.assertNotIn("params_error", r)
                self.assertEqual(r["genesis"], d.genesis_hash)
                self.assertEqual(int(r["graduation_work"], 16), d.graduation_work)
                self.assertEqual(int(r["genesis_work"], 16), d.genesis_work)
                self.assertEqual(int(r["pow_limit_bits"], 16), target_to_bits(bits_to_target(d.pow_limit_bits)))
                self.assertEqual((r["params_chain_id"], r["params_magic"], r["params_port"], r["hrp"]),
                                 (d.chain_id, d.magic.hex(), d.p2p, d.hrp))

    def test_unground_genesis_refused(self):
        rng = random.Random(SEED + 1)
        d = launch(rng, easy=False)
        r = self.assert_identity(d)  # identity does not depend on the nonce
        if int(d.genesis_hash, 16) > bits_to_target(d.pow_limit_bits):
            self.assertIn("genesis_nonce", r.get("params_error", ""))

    def test_parser_agrees_on_accept_reject(self):
        rng = random.Random(SEED + 2)
        base = launch(rng, creator_script=bytes.fromhex("0014" + "11" * 20), creator_fee_bps=100,
                      tail_reward=COIN, tail_halving_interval=1000).to_json()
        t0 = base["virtual_tokens"]
        mutations = [
            {"ticker": "ab"}, {"ticker": "A"}, {"ticker": "ABCDEFGHIJK"}, {"ticker": "AB-C"}, {"ticker": ""},
            {"hrp": "bc"}, {"hrp": "tb"}, {"hrp": "bcrt"}, {"hrp": "ncrt"}, {"hrp": ""}, {"hrp": "Upper"},
            {"hrp": "a" * 21}, {"hrp": "a" * 20}, {"name": ""}, {"name": "x" * 65}, {"name": "x" * 64},
            {"name": "\u03bb" * 40}, {"name": "\u03bb" * 32}, {"ticker": "\u00c5B"},
            {"pubkey_prefix": 0}, {"script_prefix": 5}, {"pubkey_prefix": 111}, {"script_prefix": 196},
            {"pubkey_prefix": 100, "script_prefix": 100}, {"pubkey_prefix": 256},
            {"pow_limit_bits": "0x20800000"}, {"pow_limit_bits": "0x00000000"}, {"pow_limit_bits": "0x03000000"},
            {"pow_limit_bits": "0x22000001"}, {"pow_limit_bits": "0x2100ffff"}, {"pow_limit_bits": 545259519},
            {"target_spacing": 0}, {"target_spacing": 3600}, {"target_spacing": 3601},
            {"lwma_window": 2}, {"lwma_window": 3}, {"lwma_window": 1000}, {"lwma_window": 1001},
            {"ftl": 0}, {"ftl": 7200}, {"ftl": 7201},
            {"virtual_work": "0"}, {"virtual_work": str(2**160)}, {"virtual_work": str(2**160 + 1)},
            {"virtual_work": "0x" + "f" * 40}, {"virtual_work": "0x" + "1" + "0" * 40}, {"virtual_work": "-5"},
            {"virtual_work": "abc"}, {"virtual_work": 123}, {"virtual_work": "0X10"}, {"virtual_work": " 5"},
            {"graduation_tokens": 0}, {"graduation_tokens": t0}, {"graduation_tokens": t0 + 1},
            {"graduation_tokens": t0 - t0 // 1000}, {"graduation_tokens": t0 - t0 // 1000 + 1},
            {"virtual_tokens": D.MAX_MONEY + 1}, {"virtual_tokens": -1},
            {"tail_reward": COIN, "tail_halving_interval": 0},
            {"tail_reward": (D.MAX_MONEY - base["graduation_tokens"]) // 2000, "tail_halving_interval": 1000},
            {"tail_reward": (D.MAX_MONEY - base["graduation_tokens"]) // 2000 + 1, "tail_halving_interval": 1000},
            {"creator_script": "00" * 101}, {"creator_script": "00" * 100}, {"creator_script": ""},
            {"creator_script": "abc"}, {"creator_script": "zz"}, {"creator_fee_bps": 1000},
            {"creator_fee_bps": 1001}, {"version": 2}, {"version": 0},
            {"genesis_time": -1}, {"genesis_time": 2**32}, {"genesis_time": 2**32 - 1}, {"genesis_nonce": 2**32},
            {"genesis_time": "1700000000"}, {"genesis_time": 1.5}, {"genesis_time": True},
            {"test": "yes"}, {"test": 1}, {"test": False},
            {"p2p_port": 65536}, {"p2p_port": -1}, {"p2p_port": 1}, {"seeds": "x"}, {"seeds": ["a:1", "b"]},
            {"foo": 1}, {"secret_prefix": 300}, {"name": 5}, {"hrp": 5}, {"creator_script": 0},
            {"virtual_work": "0x"}, {"virtual_work": "0x" + "0" * 64}, {"virtual_work": "0x" + "0" * 63 + "5"},
            {"virtual_work": "0x" + "0" * 65}, {"virtual_work": ""}, {"virtual_work": "+5"}, {"virtual_work": "5.0"},
            {"genesis_time": "0x"}, {"genesis_time": "0x10"}, {"genesis_time": "0X10"}, {"genesis_time": "+5"},
            {"genesis_time": " 5"}, {"genesis_time": "1_0"}, {"genesis_time": "05"}, {"genesis_time": "-0"},
            {"genesis_time": ""}, {"genesis_time": 1e3}, {"genesis_time": 10**30}, {"genesis_time": "-"},
            {"pow_limit_bits": "0x" + "0" * 20 + "207fffff"}, {"pow_limit_bits": "0x1" + "0" * 16},
            {"creator_script": " 00 11\t"}, {"creator_script": "0 011"}, {"creator_script": "\u00a00011"},
            {"test": None}, {"seeds": None}, {"hrp": None}, {"seeds": [1]}, {"version": "1"}, {"version": None},
        ] + [{k: DELETE} for k in ("name", "ticker", "genesis_time", "virtual_work", "virtual_tokens",
                                    "graduation_tokens", "hrp", "pow_limit_bits")] + \
            [{k: None} for k in ("name", "ticker", "genesis_time", "virtual_work", "virtual_tokens", "graduation_tokens")]
        disagreements = []
        for m in mutations:
            o = dict(base)
            for k, v in m.items():
                if v is DELETE:
                    o.pop(k, None)
                else:
                    o[k] = v
            text = json.dumps(o)
            try:
                py = D.parse(text)
            except D.DescriptorError as e:
                py, py_err = None, str(e)
            r = self.drv(op="desc", json=text)
            if bool(r["ok"]) != (py is not None):
                disagreements.append((m, "c++ " + ("accepts" if r["ok"] else f"rejects: {r.get('error')}"),
                                      "py " + ("accepts" if py else f"rejects: {py_err}")))
            elif py is not None:
                self.assertEqual(r["id"], py.id_hex, m)
        self.assertEqual(disagreements, [], "\n".join(map(str, disagreements)))

    def test_curve_lwma_subsidy_graduation(self):
        rng = random.Random(SEED + 3)
        for i in range(max(4, N // 4)):
            T = rng.choice([1, 10, 60])
            window = rng.choice([3, 10, 45])
            t0 = 15_000_000 * COIN
            d = launch(rng, pow_limit_bits=rng.choice([0x207FFFFF, 0x1F00FFFF]), target_spacing=T, lwma_window=window,
                       virtual_work=rng.choice([1, 50, 10_000]), creator_script=b"\x51", creator_fee_bps=100,
                       virtual_tokens=t0, graduation_tokens=rng.choice([rng.randint(1, t0 - t0 // 1000),
                                                                       t0 * D.PUMP_RATIO_G // D.PUMP_RATIO_T]),
                       tail_reward=COIN, tail_halving_interval=rng.choice([7, 100]), genesis_time=1_700_000_000)
            pow_limit = bits_to_target(d.pow_limit_bits)
            times, bits = [d.genesis_time], [d.pow_limit_bits]
            # Mostly honest (bits = model's next), with jitter: zero/negative/huge solvetimes and off-model bits.
            for _ in range(rng.choice([60, 150, 300])):
                st = rng.choice([T, T, T // 2 or 1, 0, -T, 7 * T, 1, 3 * T])
                times.append(max(0, times[-1] + st))
                b = d.lwma_next_bits(times[:-1], bits)
                if rng.random() < 0.15:
                    b = target_to_bits(rng.randrange(1, pow_limit + 1))
                bits.append(b)
            r = self.drv(op="chain", json=d.dumps(), headers=[[t, b] for t, b in zip(times[1:], bits[1:])])
            self.assertTrue(r["ok"], r)
            works = [work_from_bits(b) for b in bits[1:]]
            gh = first_graduation(works, d.graduation_work)
            acc, mism = 0, []
            for h in range(len(times)):
                if h:
                    sub = d.subsidy(acc, bits[h], h)
                    if r["subsidy"][h - 1] != sub or r["creator_fee"][h - 1] != d.creator_fee(sub):
                        mism.append(("subsidy", h, r["subsidy"][h - 1], sub))
                    acc += works[h - 1]
                nb = d.lwma_next_bits(times[:h + 1], bits[:h + 1])
                if int(r["next_bits"][h], 16) != nb:
                    mism.append(("next_bits", h, r["next_bits"][h], f"{nb:08x}"))
                if int(r["rel_work"][h], 16) != acc:
                    mism.append(("rel_work", h, r["rel_work"][h], hex(acc)))
                if r["curve_supply"][h] != d.curve_supply(acc):
                    mism.append(("curve_supply", h, r["curve_supply"][h], d.curve_supply(acc)))
                grad = acc >= d.graduation_work
                if r["graduated"][h] != grad or r["graduation_height"][h] != (gh if grad else -1):
                    mism.append(("graduation", h, r["graduated"][h], r["graduation_height"][h], gh))
            self.assertTrue(all(r["permitted"]))
            self.assertEqual(mism[:5], [], f"case {i}: T={T} N={window} V0={d.virtual_work}")
            with self.subTest(i=i):
                # Graduated chains must have minted exactly G on the curve, then tail.
                if gh > 0:
                    self.assertEqual(sum(r["subsidy"][:gh]), d.graduation_tokens)

    def test_tail_minted(self):
        rng = random.Random(SEED + 4)
        for ihl in (1, 7, 1000, 210_000, 2**31 - 1):
            d = launch(rng, tail_reward=rng.randint(1, D.MAX_MONEY // (4 * ihl)), tail_halving_interval=ihl,
                       graduation_tokens=COIN)
            ranges = [[0, 0], [5, 4], [0, 100], [ihl - 1, ihl + 1], [ihl, 3 * ihl], [0, 64 * ihl if ihl < 2**24 else 2**31 - 1],
                      [2**31 - 2, 2**31 - 1]] + [sorted([rng.randrange(2**31), rng.randrange(2**31)]) for _ in range(5)]
            ranges = [[max(0, min(a, 2**31 - 1)), max(0, min(b, 2**31 - 1))] for a, b in ranges]
            r = self.drv(op="tail", json=d.dumps(), ranges=ranges)
            for (a, b), got, rew in zip(ranges, r["tail_minted"], r["tail_reward"]):
                self.assertEqual(got, tail_minted_py(d, a, b), (ihl, a, b))
                self.assertEqual(rew, d.tail_reward_at(b), (ihl, b))


if __name__ == "__main__":
    unittest.main()
