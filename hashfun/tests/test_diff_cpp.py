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
import struct
import subprocess
import unittest

from hashfun import descriptor as D
from hashfun.ser import bits_to_target, target_to_bits, work_from_bits

COIN = 100_000_000
SEED = int(os.environ.get("HFDIFF_SEED", "1"))
N = int(os.environ.get("HFDIFF_N", "40"))
DELETE = object()
SATS = {"sats_num": 5, "sats_shift": 3, "btc_anchor_header": "ab" * 80, "creator_btc_script": "0014" + "22" * 20}


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


_HDRS = []


def mainnet_headers():
    """2,017 headers under Bitcoin's mainnet rules with real proof of work: Bitcoin's genesis block and
    2,016 blocks Bitcoin Core mined on top of it (one whole difficulty period and the first block of
    the next). The only cheap source of anchors a parser on mainnet rules accepts."""
    if not _HDRS:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "mainnet_alt_headers.hex")
        with open(path) as f:
            _HDRS.extend(bytes.fromhex(x) for x in f.read().split())
    return _HDRS


def header_time(header):
    return struct.unpack("<I", header[68:72])[0]


def earning_script(rng):
    """A script form that earns (launchyield::EarnsYield): what creator_btc_script has to be."""
    return rng.choice([
        b"\x76\xa9\x14" + rng.randbytes(20) + b"\x88\xac",                # P2PKH
        b"\xa9\x14" + rng.randbytes(20) + b"\x87",                         # P2SH
        b"\x00\x14" + rng.randbytes(20), b"\x00\x20" + rng.randbytes(32),   # P2WPKH, P2WSH
        b"\x51\x20" + rng.randbytes(32),                                   # P2TR
        b"\x60\x02" + rng.randbytes(2), b"\x52\x28" + rng.randbytes(40),    # the shortest and the longest witness program
    ])


def btc_anchor(rng, regtest):
    """(height, header, period start) of an anchor the parsers accept. On regtest anything nonzero
    goes; on mainnet rules it has to be a real header with a period start that can be true."""
    if regtest:
        return rng.choice([0, rng.randrange(1, 2**31)]), rng.randbytes(79) + b"\x01", rng.choice([0, rng.randrange(2**32)])
    hdrs = mainnet_headers()
    i = rng.choice([0, 1, 1500, 2015, 2016])
    height = i + 2016 * rng.choice([0, 1, 400, (2**31 - 1 - i) // 2016])
    own = header_time(hdrs[i])
    period = own if height % 2016 == 0 else rng.choice([header_time(hdrs[0]), own + 7200, 1])
    return height, hdrs[i], period


def launch(rng, easy=True, **kw):
    """A random but valid descriptor; easy=True keeps genesis grinding cheap."""
    t0 = rng.choice([1000, 21_000, 15_000_000, 21_000_000, 20_999_999]) * COIN
    g = rng.randint(1, t0 - t0 // 1000) if rng.random() < 0.5 else t0 * D.PUMP_RATIO_G // D.PUMP_RATIO_T
    ihl = rng.choice([0, 1, 1000, 210_000, 2**31 - 1])
    tail = 0 if ihl == 0 else rng.randint(0, (D.MAX_MONEY - g) // (2 * ihl))
    script = bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 22, 34, 100])))
    # Fields that depend on each other are drawn for the values the caller fixed, if any.
    spacing = kw.get("target_spacing", rng.choice([2, 10, 60, 600, 3600]))
    window = kw.get("lwma_window", rng.choice([3, 10, 45, 144, 1000]))
    test = kw.get("test", rng.random() < 0.5)
    regtest = kw.get("btc_regtest", rng.random() < 0.5)
    # a test launch may stamp blocks anywhere; any other needs 10 <= ftl < 6 * target_spacing
    ftl = rng.choice([1, 300, 7200]) if test else rng.choice([10, min(7200, 6 * spacing - 1), D.default_ftl(spacing, window)])
    anchor_height, anchor_header, anchor_period = btc_anchor(rng, regtest)
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
        target_spacing=spacing, lwma_window=window,
        ftl=ftl, tail_reward=tail, tail_halving_interval=ihl if tail else rng.choice([0, ihl]),
        creator_script=script, creator_fee_bps=rng.choice([0, 1, 100, 1000]) if script else 0,
        test=test,
        btc_anchor_height=anchor_height, btc_anchor_period_time=anchor_period,
        btc_anchor_header=anchor_header, sats_num=rng.randrange(1, 2**62), sats_shift=rng.randrange(129),
        sats_min_payment=rng.choice([546, 10_000, 10**8]), settle_deadline=rng.choice([110, 720, 10**6]),
        btc_confs=rng.choice([1, 6, 100]), creator_btc_script=earning_script(rng),
        btc_regtest=regtest,
        meta=rng.choice([bytes(32), rng.randbytes(32), bytes(31) + b"\x01"]),
    )
    base.update(kw)
    d = D.Launch(**base)
    D.validate(d)
    if easy:
        d.grind_genesis()
    return d


def production_launch(**kw):
    """One fixed launch on production rules (not a test launch, Bitcoin's mainnet rules), anchored in the
    middle of the stored difficulty period: what the rule tests change one field at a time."""
    hdrs = mainnet_headers()
    fields = dict(name="Rules", ticker="RULE", hrp="rule", genesis_time=1_700_000_000, virtual_work=10**12,
                  virtual_tokens=15_000_000 * COIN, graduation_tokens=15_000_000 * COIN * D.PUMP_RATIO_G // D.PUMP_RATIO_T,
                  pow_limit_bits=0x207FFFFF, target_spacing=60, lwma_window=45, ftl=135,
                  btc_anchor_height=1500, btc_anchor_header=hdrs[1500], btc_anchor_period_time=header_time(hdrs[0]),
                  sats_num=5, sats_shift=3, creator_btc_script=bytes.fromhex("0014" + "22" * 20))
    fields.update(kw)
    d = D.Launch(**fields)
    D.validate(d)
    return d


def with_changes(base, m):
    """The launch file `base` (a to_json() dict) as text, with the fields of m set, or left out where m
    says DELETE."""
    o = dict(base)
    for k, v in m.items():
        if v is DELETE:
            o.pop(k, None)
        else:
            o[k] = v
    return json.dumps(o)


def describe(m):
    """A change to a launch file, for a failure message."""
    def show(v):
        text = "(left out)" if v is DELETE else json.dumps(v)
        return text if len(text) <= 48 else text[:45] + "..."
    return ", ".join(f"{k}={show(v)}" for k, v in m.items()) or "(unchanged)"


# creator_btc_script: forms that earn (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, the shortest and the longest
# witness program) and things that only look like them.
H20, H32 = "22" * 20, "33" * 32
EARNING = ("76a914" + H20 + "88ac", "a914" + H20 + "87", "0014" + H20, "0020" + H32, "5120" + H32, "5102aabb",
           "6028" + "44" * 40)
NOT_EARNING = ("51", "5101aa", "0000", "5129" + "44" * 41, "6a14" + H20, "6102aabb", "5002aabb", "4f02aabb",
               "0013" + H20, "0015" + H20, "76a914" + H20 + "88ad", "76a915" + H20 + "88ac", "a914" + H20 + "88",
               "a914" + H20 + "8700", "21" + "02" * 33 + "ac", "51" * 80, "0014" + H20 + "00")


def field_mutations(base, sats):
    """Changes to the launch file `base`, one or a few fields at a time: values at and past every limit,
    values of the wrong kind, fields left out. `sats` is a sats leg that is valid for this launch."""
    t0 = base["virtual_tokens"]
    hdrs = mainnet_headers()
    start = header_time(hdrs[0])
    keys = sorted(set(base) | {"meta", "metadata", "p2p_port", "rpc_port", "creator_btc_script", "seeds"})

    def anchor(height, header, period):
        return {"btc_anchor_height": height, "btc_anchor_header": header.hex(), "btc_anchor_period_time": period}

    anchors = [anchor(height, header, period) for height, header, periods in (
        (0, hdrs[0], (start, start - 1, 0)), (4032, hdrs[0], (start, 1)),
        (1, hdrs[1], (start, 0, header_time(hdrs[1]) + 7200, header_time(hdrs[1]) + 7201)),
        (1500, hdrs[1500], (start, 1, 0, 2**32 - 1)), (2015, hdrs[2015], (start,)),
        (2016, hdrs[2016], (start, header_time(hdrs[2016]), 0)), (2017, hdrs[2016], (start,)),
        (2**31 - 128, hdrs[0], (start,)), (2**31 - 1, hdrs[1500], (start,)),
        (0, D.REGTEST_GENESIS_HEADER, (0, header_time(D.REGTEST_GENESIS_HEADER))),
        (1500, hdrs[1500][:76] + b"\x00\x00\x00\x01", (start,)), (7, bytes(79) + b"\x01", (0, 5))) for period in periods]
    anchors += [{**a, "btc_regtest": regtest} for a in anchors for regtest in (True, False)]
    anchors += [anchor(1500, hdrs[1500][:72] + struct.pack("<I", bits) + hdrs[1500][76:], start)
                for bits in (0, 0x1D80FFFF, 0x1D000000, 0x01003456, 0x2100FFFF, 0x2200FFFF, 0xFF000001, 0x04800001,
                             0x1D010000, 0x1E00FFFF, 0x207FFFFF, 0x1B0404CB, 0x03000001)]
    return [
        {"ticker": "ab"}, {"ticker": "A"}, {"ticker": "ABCDEFGHIJK"}, {"ticker": "AB-C"}, {"ticker": ""},
        {"hrp": "bc"}, {"hrp": "tb"}, {"hrp": "bcrt"}, {"hrp": "ncrt"}, {"hrp": ""}, {"hrp": "Upper"},
        {"hrp": "a" * 21}, {"hrp": "a" * 20}, {"name": ""}, {"name": "x" * 65}, {"name": "x" * 64},
        {"name": "\u03bb" * 40}, {"name": "\u03bb" * 32}, {"ticker": "\u00c5B"},
        {"pubkey_prefix": 0}, {"script_prefix": 5}, {"pubkey_prefix": 111}, {"script_prefix": 196},
        {"pubkey_prefix": 100, "script_prefix": 100}, {"pubkey_prefix": 256},
        {"pow_limit_bits": "0x20800000"}, {"pow_limit_bits": "0x00000000"}, {"pow_limit_bits": "0x03000000"},
        {"pow_limit_bits": "0x22000001"}, {"pow_limit_bits": "0x2100ffff"}, {"pow_limit_bits": 545259519},
        {"target_spacing": 0}, {"target_spacing": 1}, {"target_spacing": 2}, {"target_spacing": 3600}, {"target_spacing": 3601},
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
        {"foo": 1}, {"secret_prefix": 300},
        {"btc_anchor_height": 5}, {"btc_anchor_period_time": 5}, {"btc_anchor_height": 5, "btc_anchor_header": "00" * 80},
        {"btc_anchor_height": 5, "btc_anchor_header": "ab" * 80}, {"btc_anchor_header": "AB" * 80},
        {"btc_anchor_header": "ab" * 79}, {"btc_anchor_header": "ab" * 81}, {"btc_anchor_header": "zz" * 80},
        {"btc_anchor_header": " " + "ab" * 79 + "a"}, {"btc_anchor_header": 5}, {"btc_anchor_header": None},
        {"btc_anchor_header": ""}, {"sats_num": 0}, {"sats_num": DELETE}, {"creator_btc_script": DELETE},
        {"btc_anchor_header": DELETE}, {"btc_anchor_header": "00" * 80},
        {"btc_regtest": True}, {"btc_regtest": False}, {"btc_regtest": 1}, {"btc_regtest": "true"}, {"btc_regtest": None},
        {"meta": "ab" * 32}, {"meta": "00" * 32}, {"meta": "AB" * 32}, {"meta": "ab" * 31}, {"meta": "ab" * 33},
        {"meta": "zz" * 32}, {"meta": ""}, {"meta": 5}, {"meta": None}, {"meta": DELETE}, {"meta": " " + "ab" * 31 + "a"},
        {"metadata": {"description": "x"}}, {"metadata": "junk"}, {"metadata": None},
        {"meta": "ab" * 32, "metadata": {"image": "!!"}},
        {**sats}, {**sats, "sats_num": 2**62}, {**sats, "sats_num": 2**62 + 1}, {**sats, "sats_shift": 128},
        {**sats, "sats_shift": 129}, {**sats, "sats_min_payment": 545}, {**sats, "sats_min_payment": 546},
        {**sats, "settle_deadline": 109}, {**sats, "settle_deadline": 110}, {**sats, "settle_deadline": 10**6 + 1},
        {**sats, "btc_confs": 0}, {**sats, "btc_confs": 100}, {**sats, "btc_confs": 101},
        {**sats, "creator_btc_script": ""}, {**sats, "creator_btc_script": "5"}, {**sats, "creator_btc_script": "51" * 81},
        {**sats, "creator_btc_script": "51" * 80}, {**sats, "creator_btc_script": "5 1"}, {**sats, "creator_btc_script": None},
        {"sats_min_payment": 1}, {"btc_confs": 0}, {"creator_btc_script": "51"},
        {"btc_anchor_height": 2**32}, {"btc_anchor_height": "7"}, {"name": 5}, {"hrp": 5}, {"creator_script": 0},
        {"virtual_work": "0x"}, {"virtual_work": "0x" + "0" * 64}, {"virtual_work": "0x" + "0" * 63 + "5"},
        {"virtual_work": "0x" + "0" * 65}, {"virtual_work": ""}, {"virtual_work": "+5"}, {"virtual_work": "5.0"},
        {"genesis_time": "0x"}, {"genesis_time": "0x10"}, {"genesis_time": "0X10"}, {"genesis_time": "+5"},
        {"genesis_time": " 5"}, {"genesis_time": "1_0"}, {"genesis_time": "05"}, {"genesis_time": "-0"},
        {"genesis_time": ""}, {"genesis_time": 1e3}, {"genesis_time": 10**30}, {"genesis_time": "-"},
        {"pow_limit_bits": "0x" + "0" * 20 + "207fffff"}, {"pow_limit_bits": "0x1" + "0" * 16},
        {"creator_script": " 00 11\t"}, {"creator_script": "0 011"}, {"creator_script": "\u00a00011"},
        {"test": None}, {"seeds": None}, {"hrp": None}, {"seeds": [1]}, {"version": "1"}, {"version": None},
        # ---- descriptor version 2: ftl against the block time
        *[{"target_spacing": t, "ftl": f} for t, fs in ((2, (9, 10, 11, 12)), (10, (9, 10, 59, 60)), (1200, (7199, 7200)),
                                                        (1201, (7200, 7201)), (3600, (7200,))) for f in fs],
        *[{"target_spacing": t, "lwma_window": n, "ftl": DELETE} for t in (2, 3, 5, 10, 60, 1200, 3600) for n in (3, 15, 90, 1000)],
        {"target_spacing": DELETE, "lwma_window": DELETE, "ftl": DELETE}, {"target_spacing": DELETE, "ftl": DELETE},
        {"lwma_window": DELETE, "ftl": DELETE}, {"ftl": "22"}, {"ftl": 10.0}, {"ftl": 9}, {"ftl": 10}, {"ftl": 11}, {"ftl": 12},
        *[{"test": t, "ftl": f} for t in (True, False) for f in (1, 9, 10, 300, 7200)],
        # ---- fields the node holds as an int
        *[{"tail_reward": r, "tail_halving_interval": v} for r in (0, 1) for v in (2**31 - 1, 2**31, 2**32 - 1, 2**32)],
        *[{"btc_anchor_height": v} for v in (2015, 2016, 2**31 - 128, 2**31 - 1, 2**31, 2**32 - 1)],
        # ---- the version
        {"version": 1}, {"version": 3}, {"version": 2**32 - 1}, {"version": 2**32}, {"version": "2"}, {"version": "0x2"},
        {"version": -2}, {"version": 2.0}, {"version": True}, {"version": [2]},
        # ---- the Bitcoin anchor, creator_btc_script
        *anchors, *[{"creator_btc_script": x} for x in EARNING + NOT_EARNING],
        # ---- space inside creator_script's hex, which both parsers read past in the same places
        {"creator_script": "00\n11"}, {"creator_script": "00\u000b11"}, {"creator_script": "00\u000c11"},
        {"creator_script": "00\r11"}, {"creator_script": "0\n011"}, {"creator_script": "00\u001c11"},
        {"creator_script": "00\u008511"}, {"creator_script": "00\u202811"}, {"creator_script": "00 11 "},
        # ---- every field left out, null (the same thing to both parsers), and of every wrong kind
        *[{k: DELETE} for k in keys], *[{k: None} for k in keys],
        *[{k: v} for k in keys for v in ([], {}, [1], {"a": 1}, "x", "", "0", "00", 1.5, True, False, -1, 0, 1, 2**64)],
    ]


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

    # ------------------------------------------------------------ the two parsers on one launch file
    def both(self, text, label=""):
        """One launch file, as text or as the bytes of a file, through both parsers: (the node accepts,
        the node's error, Python accepts, Python's error, the launch id when both accept). Two parsers
        that both accept must have read the same launch, byte for byte."""
        try:
            py, py_err = D.parse(text), ""
        except D.DescriptorError as e:
            py, py_err = None, str(e)
        r = self.drv(op="desc", json_hex=text.hex()) if isinstance(text, bytes) else self.drv(op="desc", json=text)
        self.assertNotIn("exception", r, label)
        if r["ok"] and py is not None:
            self.assertEqual(r["canon"], py.canonical_bytes().hex(), label)
            self.assertEqual(r["id"], py.id_hex, label)
        return bool(r["ok"]), r.get("error", ""), py is not None, py_err, r.get("id")

    def check_cases(self, cases):
        """cases: (label, text or bytes, expected). expected: None (the parsers only have to agree with
        each other), True (both accept), or a string (both refuse, and both say so in these words; ""
        for any words)."""
        problems = []
        for label, text, expected in cases:
            c_ok, c_err, p_ok, p_err, _ = self.both(text, label)
            if c_ok != p_ok:
                problems.append(f"{label}: the node {'accepts' if c_ok else 'refuses (' + c_err + ')'}, "
                                f"python {'accepts' if p_ok else 'refuses (' + p_err + ')'}")
            elif expected is True and not c_ok:
                problems.append(f"{label}: expected a valid launch. node: {c_err} / python: {p_err}")
            elif isinstance(expected, str) and (c_ok or expected not in c_err or expected not in p_err):
                problems.append(f"{label}: expected both to refuse with '{expected}'. node: {c_err or 'accepts'} / "
                                f"python: {p_err or 'accepts'}")
        self.assertEqual(problems, [], "\n" + "\n".join(problems))
        return len(cases)

    def launch_id(self, base, changes):
        """The id both parsers give the file `base` with `changes`; the file has to be a valid launch."""
        c_ok, c_err, p_ok, p_err, lid = self.both(with_changes(base, changes), describe(changes))
        self.assertTrue(c_ok and p_ok, (describe(changes), c_err, p_err))
        return lid

    def test_parser_agrees_on_accept_reject(self):
        """Every way of getting a field wrong that we could think of, against three launches: a test launch
        on regtest Bitcoin, a production launch on mainnet rules, and a production launch on regtest
        Bitcoin (the fleet tests). Whatever one parser makes of a file, the other makes the same."""
        rng = random.Random(SEED + 2)
        total = 0
        for test, regtest in ((True, True), (False, False), (False, True)):
            base = launch(rng, creator_script=bytes.fromhex("0014" + "11" * 20), creator_fee_bps=100,
                          tail_reward=COIN, tail_halving_interval=1000, test=test, btc_regtest=regtest).to_json()
            # a made-up anchor header is only a valid anchor on regtest: elsewhere the launch keeps its real one
            sats = SATS if regtest else {k: v for k, v in SATS.items() if k != "btc_anchor_header"}
            self.assertEqual(self.both(json.dumps(base))[:4], (True, "", True, ""), "the launch the changes are made to")
            cases = [(f"test={test} btc_regtest={regtest}: {describe(m)}", with_changes(base, m), None)
                     for m in field_mutations(base, sats)]
            total += self.check_cases(cases)
        self.assertGreater(total, 2000)

    def test_new_rules_accept_and_reject(self):
        """The rules that came with descriptor version 2, each at its boundary, on one fixed production
        launch with one thing changed at a time: both parsers accept, or both refuse and say why in the
        same words."""
        from hashfun.crypto import sha256d
        hdrs = mainnet_headers()
        t0, own, h2016 = header_time(hdrs[0]), header_time(hdrs[1500]), hdrs[2016]
        base = production_launch().to_json()
        self.assertEqual((base["target_spacing"], base["lwma_window"], base["ftl"], base["test"], base["btc_regtest"]),
                         (60, 45, 135, False, False))
        FTL = "ftl: at least 10 and less than 6 * target_spacing"
        FORM = "creator_btc_script: must be a P2PKH, P2SH or witness-program script"
        BITS = "btc_anchor_header: its difficulty bits are not a valid target"
        EASY = "btc_anchor_header: easier than Bitcoin's minimum difficulty"
        MISS = "btc_anchor_header: its hash does not meet its own difficulty"
        OPENS = "btc_anchor_period_time: the anchor opens a difficulty period"

        def anchor(height, header, period, **more):
            return {"btc_anchor_height": height, "btc_anchor_header": header.hex(), "btc_anchor_period_time": period, **more}

        def with_bits(header, bits):
            return header[:72] + struct.pack("<I", bits) + header[76:]

        # the stored header with another nonce: still difficulty 1 on its face, and its hash is nowhere near
        missed = next(h for h in (hdrs[1500][:76] + struct.pack("<I", n) for n in range(1, 50))
                      if int.from_bytes(sha256d(h), "little") > bits_to_target(0x1D00FFFF))
        rules = [
            # ---- ftl: a launch that is not a test needs 10 <= ftl < 6 * target_spacing
            ({}, True), ({"ftl": 9}, FTL), ({"ftl": 10}, True), ({"ftl": 359}, True), ({"ftl": 360}, FTL),
            ({"ftl": 7200}, FTL), ({"ftl": 7201}, "ftl: out of range"), ({"ftl": 0}, "ftl: 1..7200"),
            ({"target_spacing": 2, "ftl": 9}, FTL), ({"target_spacing": 2, "ftl": 10}, True),
            ({"target_spacing": 2, "ftl": 11}, True), ({"target_spacing": 2, "ftl": 12}, FTL),
            ({"target_spacing": 10, "ftl": 59}, True), ({"target_spacing": 10, "ftl": 60}, FTL),
            ({"target_spacing": 1200, "ftl": 7199}, True), ({"target_spacing": 1200, "ftl": 7200}, FTL),
            ({"target_spacing": 1201, "ftl": 7200}, True), ({"target_spacing": 3600, "ftl": 7200}, True),
            ({"test": True, "ftl": 1}, True), ({"test": True, "ftl": 360}, True), ({"test": True, "ftl": 7200}, True),
            ({"test": True, "ftl": 0}, "ftl: 1..7200"), ({"test": True, "ftl": 7201}, "ftl: out of range"),
            ({"ftl": DELETE}, True), ({"ftl": None}, True), ({"target_spacing": 2, "lwma_window": 3, "ftl": DELETE}, True),
            ({"target_spacing": 3600, "lwma_window": 1000, "ftl": DELETE}, True),
            # ---- fields the node holds as an int: below 2^31
            ({"tail_halving_interval": 2**31 - 1}, True), ({"tail_reward": 1, "tail_halving_interval": 2**31 - 1}, True),
            ({"tail_halving_interval": 2**31}, "tail_halving_interval: out of range"),
            ({"tail_halving_interval": 2**32 - 1}, "tail_halving_interval: out of range"),
            ({"tail_halving_interval": 2**32}, "tail_halving_interval: out of range"),
            ({"tail_halving_interval": str(2**31 - 1)}, True),
            ({"tail_halving_interval": "0x80000000"}, "tail_halving_interval: out of range"),
            ({"btc_anchor_height": 2**31 - 1}, True), ({"btc_anchor_height": 2**31}, "btc_anchor_height: out of range"),
            ({"btc_anchor_height": 2**32 - 1}, "btc_anchor_height: out of range"),
            ({"btc_anchor_height": 2**32}, "btc_anchor_height: out of range"),
            ({"btc_regtest": True, "btc_anchor_height": 2**31 - 1}, True),
            ({"btc_regtest": True, "btc_anchor_height": 2**31}, "btc_anchor_height: out of range"),
            # ---- version: 2, and 1 is told what happened to it
            ({"version": 2}, True), ({"version": "2"}, True), ({"version": DELETE}, True), ({"version": None}, True),
            ({"version": 1}, "pre-release rule set. This launch file must be created again"),
            ({"version": "1"}, "pre-release rule set. This launch file must be created again"),
            ({"version": "0x1"}, "pre-release rule set"), ({"version": 0}, "unsupported descriptor version"),
            ({"version": 3}, "unsupported descriptor version"), ({"version": 2**32 - 1}, "unsupported descriptor version"),
            ({"version": 2**32}, "version: out of range"), ({"version": -1}, "version: out of range"),
            ({"version": 2.0}, "version: expected integer"), ({"version": True}, "version: expected integer"),
            ({"version": "two"}, "version: not an integer"),
            # ---- the Bitcoin anchor, on mainnet rules: a real header, and a period start that can be true
            (anchor(1500, hdrs[1500], t0), True), (anchor(1500, hdrs[1500], own), True), (anchor(1500, hdrs[1500], 1), True),
            (anchor(1500, hdrs[1500], own + 7200), True),
            (anchor(1500, hdrs[1500], own + 7201), "btc_anchor_period_time: later than the anchor block itself"),
            (anchor(1500, hdrs[1500], 2**32 - 1), "btc_anchor_period_time: later than the anchor block itself"),
            (anchor(1500, hdrs[1500], 0), "btc_anchor_period_time: required"),
            ({"btc_anchor_period_time": DELETE}, "btc_anchor_period_time: required"),
            ({"btc_anchor_period_time": None}, "btc_anchor_period_time: required"),
            (anchor(1500, missed, t0), MISS), (anchor(0, missed, header_time(missed)), MISS),
            # at a retarget boundary the period starts with the anchor itself
            (anchor(2016, h2016, header_time(h2016)), True), (anchor(2016, h2016, t0), OPENS),
            (anchor(2016, h2016, header_time(h2016) + 1), OPENS), (anchor(2016, h2016, 0), "btc_anchor_period_time: required"),
            (anchor(0, hdrs[0], t0), True), (anchor(4032, hdrs[0], t0), True), (anchor(0, hdrs[0], t0 - 1), OPENS),
            (anchor(2**31 - 128, hdrs[0], t0), True), (anchor(2**31 - 128, hdrs[1500], t0), OPENS),
            ({"btc_anchor_height": DELETE, "btc_anchor_header": hdrs[0].hex(), "btc_anchor_period_time": t0}, True),
            (anchor(2017, h2016, t0), True),  # a parser cannot know the height is wrong: check_anchor() asks a Bitcoin node
            # the difficulty bits: a valid compact target, no easier than Bitcoin ever was
            (anchor(1500, with_bits(hdrs[1500], 0x1D80FFFF), t0), BITS), (anchor(1500, with_bits(hdrs[1500], 0), t0), BITS),
            (anchor(1500, with_bits(hdrs[1500], 0x1D000000), t0), BITS), (anchor(1500, with_bits(hdrs[1500], 0x01003456), t0), BITS),
            (anchor(1500, with_bits(hdrs[1500], 0x2100FFFF), t0), EASY), (anchor(1500, with_bits(hdrs[1500], 0xFF000001), t0), BITS),
            (anchor(1500, with_bits(hdrs[1500], 0x2200FFFF), t0), BITS), (anchor(1500, with_bits(hdrs[1500], 0x04800001), t0), BITS),
            (anchor(1500, with_bits(hdrs[1500], 0x1D010000), t0), EASY), (anchor(1500, with_bits(hdrs[1500], 0x1E00FFFF), t0), EASY),
            (anchor(1500, with_bits(hdrs[1500], 0x207FFFFF), t0), EASY), (anchor(1500, with_bits(hdrs[1500], 0x2000FFFF), t0), EASY),
            (anchor(1500, with_bits(hdrs[1500], 0x1B0404CB), t0), MISS), (anchor(1500, with_bits(hdrs[1500], 0x03000001), t0), MISS),
            (anchor(0, D.REGTEST_GENESIS_HEADER, header_time(D.REGTEST_GENESIS_HEADER)), EASY),
            (anchor(1500, bytes(79) + b"\x01", t0), BITS), (anchor(1500, bytes(80), t0), "btc_anchor_header: required"),
            # with btc_regtest none of that is asked: regtest has no difficulty to speak of
            (anchor(0, D.REGTEST_GENESIS_HEADER, 0, btc_regtest=True), True),
            (anchor(2016, missed, 7, btc_regtest=True), True), (anchor(1500, bytes(79) + b"\x01", 0, btc_regtest=True), True),
            (anchor(1500, bytes(80), 0, btc_regtest=True), "btc_anchor_header: required"),
            # ---- creator_btc_script: a script form that earns, which is one a Bitcoin node relays a payment to
            *[({"creator_btc_script": x}, True) for x in EARNING], *[({"creator_btc_script": x}, FORM) for x in NOT_EARNING],
            ({"creator_btc_script": DELETE}, "creator_btc_script: required"),
            ({"creator_btc_script": None}, "creator_btc_script: required"),
            ({"creator_btc_script": ""}, "creator_btc_script: expected 1..80 bytes of hex"),
            ({"creator_btc_script": "51" * 81}, "creator_btc_script: expected 1..80 bytes of hex"),
            ({"btc_regtest": True, "creator_btc_script": "51"}, FORM), ({"test": True, "creator_btc_script": "51"}, FORM),
        ]
        self.check_cases([(describe(m), with_changes(base, m), expected) for m, expected in rules])
        accepted = sum(1 for _, expected in rules if expected is True)
        self.assertGreater(accepted, 40)
        self.assertGreater(len(rules) - accepted, 80)
        # A field left out is the field at its default: the same launch, the same id, in both parsers.
        same = self.launch_id(base, {})
        self.assertEqual(same, production_launch().id_hex)
        for m in ({"ftl": DELETE}, {"ftl": None}, {"version": DELETE}, {"version": None}, {"version": "2"},
                  {"btc_anchor_period_time": str(t0)}, {"btc_anchor_height": "0x5dc"}):
            self.assertEqual(self.launch_id(base, m), same, describe(m))
        for left_out, written in (
                ({"target_spacing": DELETE, "lwma_window": DELETE, "ftl": DELETE}, {"target_spacing": 5, "lwma_window": 90, "ftl": 22}),
                ({"target_spacing": DELETE, "ftl": DELETE}, {"target_spacing": 5, "ftl": 11}),
                ({"lwma_window": DELETE, "ftl": DELETE}, {"lwma_window": 90, "ftl": 270}),
                ({"target_spacing": 2, "lwma_window": 3, "ftl": DELETE}, {"target_spacing": 2, "lwma_window": 3, "ftl": 10}),
                ({"target_spacing": 2, "lwma_window": 1000, "ftl": DELETE}, {"target_spacing": 2, "lwma_window": 1000, "ftl": 11}),
                ({"target_spacing": 3600, "lwma_window": 1000, "ftl": DELETE},
                 {"target_spacing": 3600, "lwma_window": 1000, "ftl": 7200}),
                ({"btc_anchor_height": DELETE, "btc_anchor_header": hdrs[0].hex(), "btc_anchor_period_time": t0},
                 anchor(0, hdrs[0], t0))):
            self.assertEqual(self.launch_id(base, left_out), self.launch_id(base, written), describe(left_out))
        # ... and one with another version, or another ftl, is another launch
        self.assertNotEqual(self.launch_id(base, {"ftl": 136}), same)

    def test_defaults_alike(self):
        """A launch file may leave out everything that has a default. Both parsers fill in the same values:
        for the ftl, a function of the block time and the LWMA window that always passes the ftl rule."""
        base = production_launch().to_json()
        cases, grid = [], [(T, N) for T in (2, 3, 4, 5, 9, 10, 60, 600, 1199, 1200, 1201, 3600)
                           for N in (3, 4, 15, 19, 20, 21, 45, 90, 144, 999, 1000)]
        for T, N in grid:
            for test in (False, True):
                m = {"target_spacing": T, "lwma_window": N, "test": test, "ftl": DELETE}
                d = D.parse(with_changes(base, m))  # the default passes the rule of a launch that is not a test
                self.assertEqual(d.ftl, D.default_ftl(T, N), (T, N))
                self.assertTrue(D.MIN_FTL <= d.ftl < 6 * T and d.ftl <= D.MAX_FTL, (T, N, d.ftl))
                cases.append((describe(m), with_changes(base, m), True))  # the node reads the same ftl: both() compares the bytes
        self.check_cases(cases)
        self.assertEqual([D.default_ftl(T, N) for T, N in ((5, 90), (2, 15), (10, 10), (60, 45), (3600, 1000), (2, 1000))],
                         [22, 10, 10, 135, 7200, 11])
        # The least a launch file can say.
        genesis = D.MAINNET_GENESIS_HEADER
        minimal = {"name": "Minimal", "ticker": "MIN", "genesis_time": 1_700_000_000, "virtual_work": "1000000",
                   "virtual_tokens": 1000 * COIN, "graduation_tokens": 500 * COIN, "sats_num": 1,
                   "btc_anchor_header": genesis.hex(), "btc_anchor_period_time": header_time(genesis),
                   "creator_btc_script": "0014" + "22" * 20}
        self.assertEqual(self.both(json.dumps(minimal))[:4], (True, "", True, ""))
        d = D.parse(json.dumps(minimal))
        self.assertEqual(
            (d.version, d.hrp, d.pubkey_prefix, d.script_prefix, d.secret_prefix, d.genesis_nonce, d.pow_limit_bits,
             d.target_spacing, d.lwma_window, d.ftl, d.tail_reward, d.tail_halving_interval, d.creator_script,
             d.creator_fee_bps, d.test, d.btc_anchor_height, d.sats_shift, d.sats_min_payment, d.settle_deadline,
             d.btc_confs, d.btc_regtest, d.meta, d.p2p_port, d.rpc_port, d.seeds),
            (2, "min", 40, 100, 168, 0, 0x1D00FFFF, 5, 90, 22, 0, 0, b"", 0, False, 0, 0, 10_000, 720, 1, False,
             bytes(32), 0, 0, []))
        written = dict(minimal, version=2, hrp="min", pubkey_prefix=40, script_prefix=100, secret_prefix=168, genesis_nonce=0,
                       pow_limit_bits="0x1d00ffff", target_spacing=5, lwma_window=90, ftl=22, tail_reward=0,
                       tail_halving_interval=0, creator_script="", creator_fee_bps=0, test=False, btc_anchor_height=0,
                       sats_shift=0, sats_min_payment=10_000, settle_deadline=720, btc_confs=1, btc_regtest=False,
                       meta="00" * 32, p2p_port=0, rpc_port=0, seeds=[])
        self.assertEqual(self.launch_id(minimal, {}), self.launch_id(written, {}))
        # every one of those few is needed
        self.check_cases([(f"minimal without {k}", with_changes(minimal, {k: DELETE}), "") for k in minimal])
        # on regtest Bitcoin the period start is not: regtest never retargets
        regtest = dict(minimal, btc_regtest=True, btc_anchor_header=D.REGTEST_GENESIS_HEADER.hex())
        del regtest["btc_anchor_period_time"]
        self.assertEqual(self.both(json.dumps(regtest))[:4], (True, "", True, ""))

    def test_raw_text_agrees(self):
        """The file itself, before any field is looked at. JSON readers differ at the edges (Python keeps
        the last of two equal keys and the node's reader the first, Python reads NaN, any nesting, half
        surrogate pairs; the node's reader takes bytes that are not UTF-8): a file at one of those edges is
        refused by both parsers, so that no file can be one launch here and another, or none, there."""
        base = production_launch().to_json()
        text = json.dumps(base)
        raw = text.encode()

        def more(extra):  # further members, as written, at the end of the launch's object
            return text[:-1] + "," + extra + "}"

        def name(b):  # the launch's name as these bytes
            return json.dumps(dict(base, name="@@")).encode().replace(b"@@", b)

        other = "ZZZ" if base["ticker"] != "ZZZ" else "YYY"
        JSON, TWICE, UTF8 = "descriptor is not a JSON object", "the key appears twice in one object", "descriptor is not valid UTF-8"
        DEEP, LONG = "descriptor: nested more than 64 levels", "descriptor: a number of more than 40 characters"
        cases = [
            ("as written", text, True), ("as bytes", raw, True),
            # ---- a key twice: refused wherever it is and whatever the two values are
            ("ticker again, the same", more('"ticker":' + json.dumps(base["ticker"])), "ticker: " + TWICE),
            ("ticker again, another (last differs)", more(f'"ticker":"{other}"'), "ticker: " + TWICE),
            ("ticker first another, then the real one", '{"ticker":"%s",' % other + text[1:], "ticker: " + TWICE),
            ("a key the parsers do not know, twice", more('"foo":1,"foo":2'), "foo: " + TWICE),
            ("twice by way of an escape", more('"tick\\u0065r":"%s"' % other), "ticker: " + TWICE),
            ("twice inside metadata", more('"metadata":{"a":1,"a":2}'), "a: " + TWICE),
            ("twice inside an array element", more('"x":[{"a":1,"a":1}]'), "a: " + TWICE),
            ("twice, three levels down", more('"x":{"y":{"z":1,"z":1}}'), "z: " + TWICE),
            ("the empty key twice", more('"":1,"":2'), ": " + TWICE),
            ("the same key in two objects", more('"x":{"a":1},"y":{"a":1}'), True),
            ("keys that differ in case", more('"Ticker":"%s"' % other), True),
            # ---- values JSON does not have
            ("NaN", more('"x":NaN'), JSON), ("Infinity", more('"x":Infinity'), JSON), ("-Infinity", more('"x":-Infinity'), JSON),
            ("NaN as a field", text.replace('"sats_shift": 3', '"sats_shift": NaN'), JSON),
            ("nan", more('"x":nan'), JSON), ("True", more('"x":True'), JSON), ("None", more('"x":None'), JSON),
            ("a number that does not fit a float", more('"x":1e400'), True), ("minus zero", more('"x":-0'), True),
            ("an integer written as 1.0", text.replace('"sats_shift": 3', '"sats_shift": 3.0'), "sats_shift: expected integer"),
            ("an integer written as 3e0", text.replace('"sats_shift": 3', '"sats_shift": 3e0'), "sats_shift: expected integer"),
            ("an integer written as -0", text.replace('"genesis_nonce": 0', '"genesis_nonce": -0'), True),
            ("a leading zero", more('"x":01'), JSON), ("a plus sign", more('"x":+1'), JSON), ("hex", more('"x":0x10'), JSON),
            ("no digit before the point", more('"x":.5'), JSON), ("no digit after the point", more('"x":5.'), JSON),
            # ---- numbers of any length
            ("a number of 40 characters", more('"x":' + "1" * 40), True), ("of 41", more('"x":' + "1" * 41), LONG),
            ("a fraction of 40 characters", more('"x":1.' + "1" * 38), True), ("a fraction of 41", more('"x":1.' + "1" * 39), LONG),
            ("a number of 5000 digits", more('"x":' + "1" * 5000), LONG), ("deep inside", more('"x":[[{"y":' + "7" * 41 + "}]]"), LONG),
            ("digits in a string are a string", more('"x":"' + "1" * 5000 + '"'), True),
            # ---- nesting
            ("64 levels of arrays", more('"x":' + "[" * 63 + "]" * 63), True), ("65", more('"x":' + "[" * 64 + "]" * 64), DEEP),
            ("64 levels of objects", more('"x":' + '{"a":' * 63 + "1" + "}" * 63), True),
            ("65", more('"x":' + '{"a":' * 64 + "1" + "}" * 64), DEEP),
            ("numbers at level 65", more('"x":' + "[" * 63 + "1,2" + "]" * 63), True),
            ("513 levels", more('"x":' + "[" * 512 + "]" * 512), ""),
            ("100,000 levels", more('"x":' + "[" * 100_000 + "]" * 100_000), ""),
            # ---- strings: escapes
            ("half a surrogate pair", more('"x":"\\ud800"'), JSON), ("the other half", more('"x":"\\udc00"'), JSON),
            ("the halves the wrong way round", more('"x":"\\ude00\\ud83d"'), JSON),
            ("a half, then a letter", more('"x":"\\ud800a"'), JSON),
            ("half a pair in a key", more('"\\ud800":1'), JSON), ("a whole pair", more('"x":"\\ud83d\\ude00"'), True),
            ("half a pair in the name", text.replace('"name": "', '"name": "\\ud83d', 1), JSON),
            ("an escaped NUL", more('"x":"\\u0000"'), True), ("an unknown escape", more('"x":"\\q"'), JSON),
            ("a tab as written", more('"x":"a\tb"'), JSON), ("0x1f as written", more('"x":"a\x1fb"'), JSON),
            ("0x7f as written", more('"x":"a\x7fb"'), True), ("an escaped slash", more('"x":"\\/"'), True),
            # ---- around the object
            ("space before and after", " \t\r\n" + text + "\n \n", True), ("CR LF line ends", raw.replace(b", ", b",\r\n"), True),
            ("a byte order mark", b"\xef\xbb\xbf" + raw, JSON), ("something after", text + "x", JSON),
            ("two objects", text + text, JSON),
            ("a comma before the brace", text[:-1] + ",}", JSON), ("a comment", text[:-1] + "/* c */}", JSON),
            ("single quotes", more("'x':1"), JSON), ("a form feed as space", text[:-1] + "\f}", JSON),
            ("a no-break space as space", text[:-1] + " }", JSON), ("an array", "[" + text + "]", JSON),
            ("null", "null", JSON), ("a string", '"x"', JSON), ("a number", "5", JSON), ("nothing", "", JSON), ("spaces", "  ", JSON),
            ("a NUL after", raw + b"\x00", JSON), ("a NUL before", b"\x00" + raw, JSON),
            # ---- bytes that are not UTF-8, which only a file can hold
            ("e acute", name("é".encode()), True), ("euro sign", name("€".encode()), True),
            ("a face", name("\U0001f600".encode()), True), ("U+0080", name(b"\xc2\x80"), True), ("U+07FF", name(b"\xdf\xbf"), True),
            ("U+0800", name(b"\xe0\xa0\x80"), True), ("U+D7FF", name(b"\xed\x9f\xbf"), True), ("U+E000", name(b"\xee\x80\x80"), True),
            ("U+FFFF", name(b"\xef\xbf\xbf"), True), ("U+10000", name(b"\xf0\x90\x80\x80"), True),
            ("U+10FFFF", name(b"\xf4\x8f\xbf\xbf"), True),
            ("A in two bytes", name(b"\xc1\x81"), UTF8), ("NUL in two bytes", name(b"\xc0\x80"), UTF8),
            ("U+07FF in three bytes", name(b"\xe0\x9f\xbf"), UTF8), ("U+FFFF in four bytes", name(b"\xf0\x8f\xbf\xbf"), UTF8),
            ("a surrogate as bytes", name(b"\xed\xa0\x80"), UTF8), ("the last surrogate as bytes", name(b"\xed\xbf\xbf"), UTF8),
            ("a surrogate pair as bytes", name(b"\xed\xa0\xbd\xed\xb8\x80"), UTF8), ("U+110000", name(b"\xf4\x90\x80\x80"), UTF8),
            ("a byte f5", name(b"\xf5\x80\x80\x80"), UTF8), ("five bytes", name(b"\xf8\x88\x80\x80\x80"), UTF8),
            ("a byte ff", name(b"\xff"), UTF8), ("Latin-1 e acute", name(b"\xe9"), UTF8),
            ("a continuation byte alone", name(b"\x80"), UTF8),
            ("two bytes cut short", name(b"\xc3"), UTF8), ("three cut short", name(b"\xe2\x82"), UTF8),
            ("four cut short", name(b"\xf0\x9f\x98"), UTF8), ("a wrong continuation", name(b"\xc3\x28"), UTF8),
            ("A in two bytes, in the ticker", json.dumps(dict(base, ticker="@@")).encode().replace(b"@@", b"\xc1\x81B"), UTF8),
            ("in a value nobody reads", raw[:-1] + b',"x":"\xc1\x81"}', UTF8),
            ("in metadata", raw[:-1] + b',"metadata":{"d":"\xed\xa0\x80"}}', UTF8), ("after the object", raw + b"\xff", UTF8),
            ("UTF-16", text.encode("utf-16"), UTF8), ("UTF-16 without the mark", text.encode("utf-16-le"), JSON),
            # ---- digits in a string, which is how a launch file may write any integer
            ("5000 zeros before a 5", with_changes(base, {"genesis_time": "0" * 5000 + "5"}), True),
            ("5000 nines", with_changes(base, {"genesis_time": "9" * 5000}), "genesis_time: "),
            ("minus 5000 zeros", with_changes(base, {"genesis_time": "-" + "0" * 5000}), True),
            ("minus 5000 zeros and a 5", with_changes(base, {"genesis_time": "-" + "0" * 5000 + "5"}), "genesis_time: out of range"),
            ("virtual_work with 5000 zeros in front", with_changes(base, {"virtual_work": "0" * 5000 + "7"}), True),
            ("virtual_work of 5000 nines", with_changes(base, {"virtual_work": "9" * 5000}), "virtual_work: "),
            ("virtual_work 2^256 - 1", with_changes(base, {"virtual_work": str(2**256 - 1)}), "virtual_work: must be in (0, 2^160]"),
            ("virtual_work 2^256", with_changes(base, {"virtual_work": str(2**256)}), "virtual_work: "),
            ("sats_num 2^63 - 1", with_changes(base, {"sats_num": str(2**63 - 1)}), "sats_num: out of range"),
            ("sats_num 2^63", with_changes(base, {"sats_num": str(2**63)}), "sats_num: "),
            ("hex with 5000 zeros in front", with_changes(base, {"genesis_time": "0x" + "0" * 5000 + "7"}), True),
            ("hex of 17 digits", with_changes(base, {"genesis_time": "0x1" + "0" * 16}), "genesis_time: "),
        ]
        self.check_cases(cases)
        # The two that differ only in zeros are the launch they spell.
        self.assertEqual(self.launch_id(base, {"genesis_time": "0" * 5000 + "5"}), self.launch_id(base, {"genesis_time": 5}))
        self.assertEqual(self.launch_id(base, {"virtual_work": "0" * 5000 + "7"}), self.launch_id(base, {"virtual_work": "7"}))
        # A file is read as its bytes (D.load), whatever the locale would make of them.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            for label, data, good in (("ok", name("é".encode()), True), ("latin1", name(b"\xe9"), False)):
                path = os.path.join(tmp, label + ".json")
                with open(path, "wb") as f:
                    f.write(data)
                if good:
                    self.assertEqual(D.load(path).id_hex, self.both(data)[4])
                else:
                    with self.assertRaisesRegex(D.DescriptorError, "not valid UTF-8"):
                        D.load(path)

    def test_earning_script_rule_alike(self):
        """creator_btc_script has to be a script that earns. That rule is written down four times
        (launchyield::EarnsYield, EarningScript in kernel/launch.cpp, descriptor._earns_yield,
        yieldmodel.earns_yield): all four draw the same line, on the forms and on everything one byte
        away from them."""
        from hashfun.ser import Tx, TxIn, TxOut
        rng = random.Random(SEED + 11)
        base = production_launch().to_json()
        forms = [b"\x76\xa9\x14" + rng.randbytes(20) + b"\x88\xac", b"\xa9\x14" + rng.randbytes(20) + b"\x87",
                 b"\x00\x14" + rng.randbytes(20), b"\x00\x20" + rng.randbytes(32), b"\x51\x20" + rng.randbytes(32),
                 b"\x51\x02" + rng.randbytes(2), b"\x60\x28" + rng.randbytes(40), b"\x00\x02" + rng.randbytes(2)]
        scripts = set(forms)
        for f in forms:
            scripts.update([f + b"\x00", f[:-1], f[1:], b"\x00" + f, f[:1] + f])
            for i in range(min(len(f), 4)):  # the bytes that make the form, each to every value that could matter
                scripts.update(f[:i] + bytes([b]) + f[i + 1:] for b in (0, 1, 0x13, 0x14, 0x15, 0x4f, 0x50, 0x51, 0x60, 0x61,
                                                                         0x6a, 0x76, 0xa9, len(f) - 3, len(f) - 2, len(f) - 1, 0xff))
            for i in (len(f) - 2, len(f) - 1):
                scripts.update(f[:i] + bytes([b]) + f[i + 1:] for b in (0, 0x87, 0x88, 0xac, 0xad, 0xff))
        for n in (1, 2, 3, 4, 5, 22, 23, 25, 34, 41, 42, 43, 80):
            for first in (0x00, 0x01, 0x4f, 0x50, 0x51, 0x52, 0x60, 0x61, 0x6a, 0x76, 0xa9):
                body = rng.randbytes(n - 1)
                scripts.add(bytes([first]) + body)
                if n >= 2:
                    scripts.update(bytes([first, k]) + body[1:] for k in (n - 3, n - 2, n - 1) if 0 <= k < 256)
        scripts = sorted(s for s in scripts if 1 <= len(s) <= 80)
        earning = [s for s in scripts if D._earns_yield(s)]
        self.assertGreater(len(earning), 40)
        self.assertGreater(len(scripts) - len(earning), 400)
        for f in forms:
            self.assertIn(f, earning)
        self.check_cases([(f"creator_btc_script {s.hex()}", with_changes(base, {"creator_btc_script": s.hex()}),
                           True if D._earns_yield(s) else "creator_btc_script: must be a P2PKH, P2SH or witness-program script")
                          for s in scripts])
        with self.subTest("yieldmodel.earns_yield"):
            from hashfun import yieldmodel as Y
            self.assertEqual([s.hex() for s in scripts if Y.earns_yield(s)], [s.hex() for s in earning])
        with self.subTest("launchyield::EarnsYield"):  # an output of a plain transaction is a coin iff its script earns
            got = []
            for s in scripts:
                tx = Tx(vin=[TxIn(rng.randbytes(32), 0)], vout=[TxOut(1, s)])
                if self.drv(op="regouts", tx=tx.serialize().hex())["outs"]:
                    got.append(s.hex())
            self.assertEqual(got, [s.hex() for s in earning])

    def test_int_max_reaches_chain_params(self):
        """The fields the node's chain parameters hold as an int, at the largest value a launch file may
        give them: the node builds its parameters from such a file and the tail runs on that interval."""
        d = production_launch(tail_reward=1, tail_halving_interval=2**31 - 1, btc_anchor_height=2**31 - 1,
                              lwma_window=1000, settle_deadline=10**6, btc_confs=100)
        d.grind_genesis()
        r = self.assert_identity(d)
        self.assertNotIn("params_error", r)
        self.assertEqual(r["genesis"], d.genesis_hash)
        ranges = [[1, 10], [2**31 - 3, 2**31 - 2], [2**31 - 2, 2**31 - 1]]
        t = self.drv(op="tail", json=d.dumps(), ranges=ranges)
        self.assertEqual(t["tail_reward"], [1, 1, 0])
        self.assertEqual(t["tail_minted"], [tail_minted_py(d, a, b) for a, b in ranges])
        for m in ({"tail_halving_interval": 2**31}, {"btc_anchor_height": 2**31}):
            node_ok, _, python_ok, _, _ = self.both(with_changes(d.to_json(), m))
            self.assertEqual((node_ok, python_ok), (False, False), describe(m))

    def test_curve_lwma_subsidy_graduation(self):
        rng = random.Random(SEED + 3)
        for i in range(max(4, N // 4)):
            T = rng.choice([2, 10, 60])
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
                st = rng.choice([T, T, T // 2 or 1, 0, -T, 6 * T - 1, 6 * T, 7 * T, 1, 3 * T, 40 * T, 2000 * T])
                times.append(max(0, times[-1] + st))
                b = d.next_bits(times[:-1], bits, times[-1])
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
                    want = d.next_bits(times[:h], bits[:h], times[h])
                    if int(r["bits_for_time"][h - 1], 16) != want:
                        mism.append(("bits_for_time", h, r["bits_for_time"][h - 1], f"{want:08x}"))
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

    def test_auxpow_against_node_validator(self):
        """The pool's real AuxPoW builder (AuxTree, serialize_auxpow) and its pre-submit check
        (check_auxpow) against the node's deserializer, CAuxPow::check and parent PoW check,
        on honest and malformed merge-mined headers."""
        from hashfun.auxpow import AuxTree, MM_MAGIC, check_auxpow, serialize_auxpow
        from hashfun.crypto import sha256d
        from hashfun.ser import Tx, TxIn, TxOut, header_bytes, merkle_branch_for_first, merkle_root, push, push_int
        import struct

        rng = random.Random(SEED + 5)
        d = launch(rng, pow_limit_bits=0x207FFFFF)
        cid, pow_limit = d.chain_id, bits_to_target(0x207FFFFF)

        def solve(hdr80, target):
            for n in range(1 << 32):
                h = hdr80[:76] + struct.pack("<I", n)
                if int.from_bytes(sha256d(h), "little") <= target:
                    return h

        mutations = [None] * 8 + ["parent_chain_id", "header_chain_id", "nonce", "size", "late_root", "two_headers",
                                  "gap", "truncate", "cb_branch", "chain_branch", "parent_pow", "long_branch",
                                  "no_flag", "early_root_no_magic"]
        seen, disagreements = {}, []
        for i in range(max(len(mutations) * 3, N)):
            m = mutations[i % len(mutations)]
            aux_bits = 0x1F00FFFF if m == "parent_pow" else rng.choice([0x207FFFFF, 0x2000FFFF])
            hdr_cid = cid + 1 if m == "header_chain_id" else cid
            aux_version = 4 | (hdr_cid << 16) | (0 if m == "no_flag" else 0x100)
            aux_hdr = header_bytes(aux_version, os.urandom(32), os.urandom(32), 1_700_000_000 + i, aux_bits, 0)
            aux_hash = sha256d(aux_hdr)
            pool = [x for x in range(1, 0x2000) if x != cid]
            tree = AuxTree({cid: aux_hash, **{c: os.urandom(32) for c in rng.sample(pool, rng.choice([0, 1, 4, 20]))}})
            branch, idx = tree.branch(cid)
            root_le = tree.root()[::-1]
            size, nonce = tree.size, tree.nonce
            if m == "nonce":
                nonce ^= 0x5A5A
            if m == "size":
                size *= 2
            commit = MM_MAGIC + root_le + struct.pack("<II", size, nonce)
            if m == "late_root":
                script = push_int(100 + i) + push(b"\xEE" * 24) + push(root_le + struct.pack("<II", size, nonce))
            elif m == "early_root_no_magic":
                script = push(root_le + struct.pack("<II", size, nonce)) + push(os.urandom(8))
            elif m == "two_headers":
                script = push_int(100 + i) + push(commit) + push(MM_MAGIC + os.urandom(4))
            elif m == "gap":
                script = push_int(100 + i) + push(MM_MAGIC + b"\x00" + root_le + struct.pack("<II", size, nonce))
            elif m == "truncate":
                script = push_int(100 + i) + push(MM_MAGIC + root_le + struct.pack("<I", size)[:3])
            else:
                script = push_int(100 + i) + push(commit) + push(os.urandom(8))
            cb = Tx(version=1, vin=[TxIn(b"\0" * 32, 0xFFFFFFFF, script, 0xFFFFFFFF,
                                         [b"\0" * 32] if rng.random() < 0.5 else [])],
                    vout=[TxOut(50 * COIN, b"\x51"), TxOut(0, b"\x6a\x24\xaa\x21\xa9\xed" + os.urandom(32))])
            others = [Tx(vin=[TxIn(os.urandom(32), 0)], vout=[TxOut(1000, b"\x51")])
                      for _ in range(rng.choice([1, 3, 7]) if m == "cb_branch" else rng.choice([0, 1, 3, 7]))]
            txids = [cb.txid()] + [t.txid() for t in others]
            cb_branch = merkle_branch_for_first(txids)
            if m == "cb_branch":
                cb_branch[rng.randrange(len(cb_branch))] = os.urandom(32)
            if m == "chain_branch":
                branch = (branch or []) + [os.urandom(32)] if not branch else \
                    [os.urandom(32) if j == 0 else b for j, b in enumerate(branch)]
            if m == "long_branch":
                branch = [os.urandom(32) for _ in range(31)]
            parent_version = (4 | (cid << 16)) if m == "parent_chain_id" else 0x20000000
            parent = header_bytes(parent_version, os.urandom(32), merkle_root(txids), 1_700_000_000, 0x207FFFFF, 0)
            target = bits_to_target(aux_bits)
            if m != "parent_pow":
                parent = solve(parent, target)
            apow = serialize_auxpow(cb, cb_branch, branch, idx, parent)

            # Python verdict, in the node's order: header chain id, auxpow flag, parent PoW, CAuxPow::check.
            version = struct.unpack("<i", aux_hdr[:4])[0]
            py_ok = (version // 65536 == cid and version & 0x100 and 0 < target <= pow_limit
                     and int.from_bytes(sha256d(parent), "little") <= target
                     and check_auxpow(aux_hash, cid, apow)[0])
            r = self.drv(op="auxpow", json=d.dumps(), header=(aux_hdr + apow).hex())
            self.assertTrue(r["ok"], r)
            seen.setdefault(m, set()).add(r["stage"])
            if bool(py_ok) != r["valid"]:
                disagreements.append((m, r["stage"], check_auxpow(aux_hash, cid, apow)[1]))
        self.assertEqual(disagreements, [])
        # Honest headers validate, including the legacy layout (root in the first 20 bytes, no magic).
        self.assertEqual(seen[None] | seen["early_root_no_magic"], {"ok"})
        for m, stages in seen.items():
            if m in (None, "early_root_no_magic", "nonce"):
                continue  # "nonce": a wrong nonce lands on the right slot whenever the tree has one leaf
            self.assertNotIn("ok", stages, m)

    # ------------------------------------------------------------ sats leg (launchyield.cpp)
    def test_yield_draw(self):
        from hashfun import yieldmodel as Y
        rng = random.Random(SEED + 6)
        for i in range(max(200, N * 5)):
            work = rng.choice([0, 1, 2, rng.randrange(2**40), rng.randrange(2**80), rng.randrange(2**200), 2**256 - 1])
            num = rng.choice([0, 1, rng.randrange(1, 2**62), 2**62])
            shift = rng.choice([0, 1, 20, 64, 80, 128])
            mn = rng.choice([546, 10_000, 10**8])
            lid, sb, mb = rng.randbytes(32), rng.randbytes(32), rng.randbytes(32)
            total = rng.choice([0, 1, 7, rng.randrange(1, 2**64), rng.randrange(1, 2**100)])
            r = self.drv(op="yield", work="%064x" % work, num=num, shift=shift, min=mn, id=lid.hex(), seed_block=sb.hex(),
                         mint_block=mb.hex(), total="%064x" % total)
            ow = Y.owed(work, num, shift)
            seed = Y.draw_seed(lid, sb)
            pay, payee = Y.compute_draw(ow, mn, seed)
            self.assertEqual((r["owed"], r["seed"], r["pay"], r["payee"], r["tag"]),
                             (ow, seed.hex(), pay, payee, Y.pay_tag(lid, mb).hex()), i)
            points = [int(x, 16) for x in r["points"]]
            self.assertEqual(points, [Y.candidate_point(seed, k, total) for k in range(len(points))], i)
            self.assertEqual(bool(points), total != 0)  # the holder draw is point 0 over the live value: it has to be there
        # The draw is fair: 80/10/10 by class, and small debts pay their expectation.
        n, cls, paid = 40_000, [0, 0, 0], 0
        for k in range(n):
            pay, payee = Y.compute_draw(1234, 10_000, Y.draw_seed(b"\x07" * 32, k.to_bytes(32, "little")))
            cls[payee] += 1
            paid += pay
        self.assertAlmostEqual(cls[0] / n, 0.8, delta=0.01)
        self.assertAlmostEqual(cls[1] / n, 0.1, delta=0.01)
        self.assertAlmostEqual(paid / n / 1234, 1.0, delta=0.05)

    def test_registered_outputs(self):
        """The coins of a transaction and where their yield is paid. Every output with value and an
        earning script is a coin, paid at its own script. One exception: a coinbase may redirect its
        output 0 with its FIRST OP_RETURN "HFY1"<payload> output, and only if the payload is itself
        an earning script. HFY1 anywhere else (another transaction, a second output) does nothing."""
        from hashfun import yieldmodel as Y
        from hashfun.ser import Tx, TxIn, TxOut
        rng = random.Random(SEED + 7)

        def any_script():
            return rng.choice([
                b"\x51", b"\x00\x14" + rng.randbytes(20), b"\x6a\x01\x01", b"", b"\x00\x20" + rng.randbytes(32),
                b"\x51\x20" + rng.randbytes(32), b"\x76\xa9\x14" + rng.randbytes(20) + b"\x88\xac",
                b"\xa9\x14" + rng.randbytes(20) + b"\x87", b"\x76\xa9\x14" + rng.randbytes(20) + b"\x88\xad",
                b"\x60\x28" + rng.randbytes(40), b"\x60\x29" + rng.randbytes(41), b"\x00\x02\x01\x02",
                b"\x00\x01\x01", b"\x4f\x02\x01\x02", b"\x00\x15" + rng.randbytes(20),
                b"\x21" + rng.randbytes(33) + b"\xac", b"\x52\x02\xab\xcd"])

        def hfy1(payload):
            """OP_RETURN "HFY1"<payload>, in any of the push encodings a script may use."""
            data = b"HFY1" + payload
            return rng.choice([Y.yield_tag_script(payload)] * 3 + [
                b"\x6a\x4c" + bytes([len(data)]) + data, b"\x6a\x4d" + struct.pack("<H", len(data)) + data,
                b"\x6a\x4e" + struct.pack("<I", len(data)) + data])

        def tag_output(kind):
            """(script, the payload it redirects to or None, is it an HFY1 output at all)."""
            earning = earning_script(rng)
            if kind == "earning":
                return hfy1(earning), earning, True
            if kind == "other":  # an HFY1 output whose payload is not a script that earns: it redirects nothing
                payload = rng.choice([b"", b"\x51", b"\x99", b"\x61" + rng.randbytes(21), b"\x00\x14" + rng.randbytes(19),
                                      b"\x00\x14" + rng.randbytes(21), earning + b"\x00", earning[:-1], bytes(81),
                                      b"\x6a\x01\x01", b"\x21" + rng.randbytes(33) + b"\xac"])
                return hfy1(payload), None, True
            # not an HFY1 output: another tag, two pushes, a push that runs short, no push
            return rng.choice([Y.op_return(b"HFY2" + earning), b"\x6a" + Y.push_data(b"HFY1" + earning) + b"\x51",
                               b"\x6a" + Y.push_data(b"HFY1") + Y.push_data(earning), b"\x6a\x05HFY", b"\x6a",
                               b"\x6a\x4c\x30HFY1" + earning[:10], Y.op_return(b"HFY" + earning), Y.op_return(b"hfy1" + earning),
                               b"\x6b" + Y.push_data(b"HFY1" + earning)]), None, False

        seen = set()
        for i in range(max(600, N * 15)):
            coinbase = rng.random() < 0.6
            outs = [TxOut(rng.choice([0, 1, 546, 10**8]), any_script()) for _ in range(rng.randrange(0, 5))]
            kinds = [rng.choice(["earning", "earning", "other", "other", "nothing"]) for _ in range(rng.choice([0, 1, 1, 2, 2, 3]))]
            tags = [tag_output(k) for k in kinds]
            where = sorted(rng.randrange(len(outs) + 1) for _ in tags)  # the tags keep their order among the outputs
            for n, (pos, (script, _payload, _is)) in enumerate(zip(where, tags)):
                outs.insert(pos + n, TxOut(rng.choice([0, 0, 0, 546]), script))
            vin = [TxIn(b"\0" * 32, 0xFFFFFFFF, b"\x01\x01", 0xFFFFFFFF)] if coinbase else [TxIn(rng.randbytes(32), rng.choice([0, 0xFFFFFFFF]))]
            tx = Tx(vin=vin, vout=outs or [TxOut(1, b"\x51")])
            self.assertEqual(Y.is_coinbase(tx), coinbase)
            got = Y.registered_outputs(tx, coinbase)
            r = self.drv(op="regouts", tx=tx.serialize().hex())
            self.assertEqual([tuple(x) for x in r["outs"]], [(v, a, b.hex()) for v, a, b in got], (i, coinbase, kinds))
            # The rule once more, from what the generator knows it built.
            own = [(n, o.value, o.script_pubkey) for n, o in enumerate(tx.vout) if o.value > 0 and Y.earns_yield(o.script_pubkey)]
            first = next(((kind, payload) for kind, (_s, payload, is_tag) in zip(kinds, tags) if is_tag), None)
            target = first[1] if coinbase and first else None
            self.assertEqual(got, [(n, v, target if (target and n == 0) else sc) for n, v, sc in own], (i, coinbase, kinds))
            valid_later = first is not None and any(pl for (_s, pl, t) in tags[[t for (_s, _p, t) in tags].index(True) + 1:])
            zero_is_coin = bool(own) and own[0][0] == 0
            if not coinbase and first and first[1] and zero_is_coin:
                seen.add("an HFY1 output outside a coinbase is ignored")
            if coinbase and first and first[0] == "other" and valid_later and zero_is_coin:
                seen.add("a first HFY1 that redirects nothing is not replaced by a later valid one")
            if coinbase and target and valid_later and zero_is_coin:
                seen.add("of two valid HFY1 outputs the first counts")
            if coinbase and target and zero_is_coin and len(own) > 1:
                seen.add("only output 0 is redirected")
            if coinbase and target and not zero_is_coin and own:
                seen.add("a redirect with no coin at output 0 changes nothing")
            if coinbase and target and kinds[0] == "nothing" and zero_is_coin:
                seen.add("an output that is not an HFY1 output does not use up the redirect")
        self.assertEqual(len(seen), 6, seen)

    def test_btc_payment_proofs(self):
        from hashfun import yieldmodel as Y
        from hashfun.crypto import sha256d
        from hashfun.ser import Tx, TxIn, TxOut, merkle_root
        rng = random.Random(SEED + 8)
        mutations = [None] * 6 + ["recipient", "underpay", "tag_pos", "no_tag", "root", "index", "branch", "witness",
                                  "size64", "truncated", "vout", "tag_other_block", "big_index",
                                  # Only the FIRST tag list of the transaction counts (if every list counted, one
                                  # paying output could carry a tag per list and settle a mint block per list):
                                  "second_list",     # the right tag, at the right position, but in a second list
                                  "bad_first_list",  # a first list that is no list (wrong length, or empty), then a good one
                                  "extra_list",      # still valid: a good first list, then anything
                                  "list_first"]      # still valid: the list before the outputs it binds
        still_valid = {None, "extra_list", "list_first"}
        seen = {}
        for i in range(max(len(mutations) * 4, N)):
            m = mutations[i % len(mutations)]
            lid, mint = rng.randbytes(32), rng.randbytes(32)
            tag = Y.pay_tag(lid, mint)
            n_pay = rng.randrange(1, 4)
            k = rng.randrange(n_pay)
            recips = [rng.choice([b"\x00\x14" + rng.randbytes(20), b"\x51\x20" + rng.randbytes(32)]) for _ in range(n_pay)]
            pays = [rng.randrange(546, 10**7) for _ in range(n_pay)]
            tags = [Y.pay_tag(lid, rng.randbytes(32)) for _ in range(n_pay)]
            tags[k] = tag
            if m == "tag_pos" and n_pay == 1:
                tags = [rng.randbytes(20), tag]
            elif m == "tag_pos":
                j = (k + 1) % n_pay
                tags[k], tags[j] = tags[j], tags[k]
            if m == "tag_other_block":
                tags[k] = Y.pay_tag(lid, rng.randbytes(32))
            vout = [TxOut(a, s_) for a, s_ in zip(pays, recips)]
            pay_vout, joined = k, b"".join(tags)
            lists = [] if m == "no_tag" else [Y.payment_outputs_tag(tags)]
            if m == "second_list":
                lists.insert(0, Y.payment_outputs_tag([Y.pay_tag(lid, rng.randbytes(32)) for _ in tags]))
            elif m == "bad_first_list":
                lists.insert(0, Y.op_return(b"HF" + rng.choice([joined + rng.randbytes(1), joined[:-1], joined + rng.randbytes(19), b""])))
            elif m == "extra_list":
                lists.append(rng.choice([Y.payment_outputs_tag([rng.randbytes(20) for _ in tags]), Y.op_return(b"HF" + rng.randbytes(7)),
                                         Y.op_return(b"HF"), Y.payment_outputs_tag(tags[::-1])]))
            if m == "list_first":  # every output moves up one, and so does its tag
                vout, pay_vout = [TxOut(0, Y.payment_outputs_tag([rng.randbytes(20)] + tags))] + vout, k + 1
            else:
                vout += [TxOut(0, script) for script in lists]
            vout.append(TxOut(rng.randrange(10**6), b"\x00\x14" + rng.randbytes(20)))  # change
            tx = Tx(version=2, vin=[TxIn(rng.randbytes(32), rng.randrange(4), b"", 0xFFFFFFFD, [rng.randbytes(72), rng.randbytes(33)])],
                    vout=vout)
            raw = tx.serialize(witness=(m == "witness"))
            txid = sha256d(tx.serialize(witness=False))
            others = [rng.randbytes(32) for _ in range(rng.choice([0, 1, 2, 5, 12]))]
            pos = rng.randrange(len(others) + 1)
            txids = others[:pos] + [txid] + others[pos:]
            # merkle branch for position pos
            branch, level, idx = [], txids[:], pos
            while len(level) > 1:
                if len(level) % 2:
                    level.append(level[-1])
                branch.append(level[idx ^ 1])
                level = [sha256d(level[j] + level[j + 1]) for j in range(0, len(level), 2)]
                idx >>= 1
            root = merkle_root(txids)
            self.assertEqual(level[0], root)
            recipient, pay = recips[k], pays[k]
            if m == "recipient":
                recipient = b"\x00\x14" + rng.randbytes(20)
            if m == "underpay":
                pay += 1
            if m == "root":
                root = rng.randbytes(32)
            if m == "branch" and branch:
                branch[rng.randrange(len(branch))] = rng.randbytes(32)
            elif m == "branch":
                branch = [rng.randbytes(32)]
            proof = Y.PaymentProof(rng.randrange(2**32), rng.randbytes(32), pos, branch, pay_vout, rng.randrange(256), raw)
            if m == "index":
                proof.tx_index = pos ^ 1 if len(txids) > 1 else 1
            if m == "big_index":
                proof.tx_index = pos + (1 << len(branch))
            if m == "vout":
                proof.pay_vout = len(vout) + 3
            if m == "size64":
                proof.raw_tx = rng.randbytes(64)
            payload = proof.payload()
            if m == "truncated":
                payload = payload[:rng.choice([3, 44, 45, 45 + 32 * len(branch) + 4])]
            r = self.drv(op="proof", payload=payload.hex(), root=root.hex(), tag=tag.hex(), recipient=recipient.hex(), pay=pay)
            parsed = Y.PaymentProof.parse(payload)
            self.assertEqual(r["parsed"], parsed is not None, m)
            if parsed is None:
                seen.setdefault(m, set()).add(False)
                continue
            ok, why = Y.verify_btc_payment(parsed, root, tag, recipient, pay)
            self.assertEqual((r["valid"], r["error"]), (ok, why), m)
            self.assertEqual((r["mint_height"], r["btc_block"], r["candidate"]),
                             (parsed.mint_height, parsed.btc_block.hex(), parsed.candidate))
            seen.setdefault(m, set()).add(ok)
        for m, v in seen.items():
            if m in still_valid:
                self.assertEqual(v, {True}, m)
            elif not (m == "index" and True in v):
                self.assertEqual(v, {False}, m)
        self.assertEqual(set(seen), set(mutations))
        # The review's case by name: ONE paying output and two tag lists, each naming another mint
        # block. The payment settles the block the first list names and no other.
        lid, recipient = rng.randbytes(32), b"\x00\x14" + rng.randbytes(20)
        tag_a, tag_b = Y.pay_tag(lid, rng.randbytes(32)), Y.pay_tag(lid, rng.randbytes(32))
        raw = Tx(version=2, vin=[TxIn(rng.randbytes(32), 0)],
                 vout=[TxOut(50_000, recipient), TxOut(0, Y.payment_outputs_tag([tag_a])),
                       TxOut(0, Y.payment_outputs_tag([tag_b]))]).serialize(witness=False)
        payload = Y.PaymentProof(7, rng.randbytes(32), 0, [], 0, 0, raw).payload()
        for tag, want in ((tag_a, True), (tag_b, False)):
            r = self.drv(op="proof", payload=payload.hex(), root=sha256d(raw).hex(), tag=tag.hex(), recipient=recipient.hex(), pay=50_000)
            ok, why = Y.verify_btc_payment(Y.PaymentProof.parse(payload), sha256d(raw), tag, recipient, 50_000)
            self.assertEqual((r["valid"], r["error"], ok), (want, why, want))

    def test_btc_header_chain(self):
        from hashfun import yieldmodel as Y
        from hashfun.crypto import sha256d
        from hashfun.ser import header_bytes
        import struct
        rng = random.Random(SEED + 9)

        def mine(prev, time_, bits=0x207FFFFF, valid=True):
            for n in range(1 << 20):
                h = header_bytes(0x20000000, prev, rng.randbytes(32), time_, bits, n)
                if (int.from_bytes(sha256d(h), "little") <= bits_to_target(bits)) == valid:
                    return h

        for case in range(max(6, N // 10)):
            anchor = mine(rng.randbytes(32), 1_700_000_000)
            height = rng.randrange(0, 10**6)
            model = Y.BtcChain(anchor, height, 0, True)
            ops, expect, tips = [], [], [sha256d(anchor)]
            times = {sha256d(anchor): 1_700_000_000}
            for _ in range(rng.randrange(20, 60)):
                kind = rng.choice(["add"] * 8 + ["bad_bits", "bad_pow", "bad_time", "orphan", "dup", "del", "conf", "conf"])
                parent = rng.choice(tips[-4:])
                if kind == "add":
                    h = mine(parent, times[parent] + rng.randrange(1, 900))
                elif kind == "bad_bits":
                    h = mine(parent, times[parent] + 600, bits=0x207FFFFE)
                elif kind == "bad_pow":
                    h = mine(parent, times[parent] + 600, valid=False)
                elif kind == "bad_time":
                    h = mine(parent, times[parent] - rng.randrange(0, 5000))
                elif kind == "orphan":
                    h = mine(rng.randbytes(32), 1_800_000_000)
                elif kind == "dup":
                    h = None
                if kind in ("del", "conf"):
                    target = rng.choice(tips)
                    ops.append([kind, target.hex()])
                    if kind == "del":
                        model.remove(target)
                        expect.append("")
                        if target not in model.nodes:
                            tips.remove(target)
                    else:
                        expect.append(model.confirmations(target))
                    continue
                if kind == "dup":
                    known = [k for k in tips if k != model.anchor]
                    if not known:
                        continue
                    hh = rng.choice(known)
                    ops.append(["add", self._hdr_cache[hh].hex()])
                    expect.append(model.accept(self._hdr_cache[hh])[1])
                    continue
                ok, why = model.accept(h)
                ops.append(["add", h.hex()])
                expect.append(why)
                if ok:
                    tips.append(sha256d(h))
                    times[sha256d(h)] = struct.unpack("<I", h[68:72])[0]
                    self._hdr_cache[sha256d(h)] = h
            r = self.drv(op="btc", anchor=anchor.hex(), height=height, period_time=0, regtest=True, ops=ops)
            self.assertEqual(r["results"], expect, case)
            self.assertEqual((r["best"], r["best_height"], r["size"]),
                             (model.best.hex(), model.nodes[model.best].height, len(model.nodes)))
            self.assertGreater(len(model.nodes), 5)
        # Regression: Bitcoin timestamps are not monotonic. Right after the anchor the median of
        # 11 cannot be known, so a header no later than the anchor must still connect; once 11
        # ancestors exist the rule applies.
        anchor = mine(rng.randbytes(32), 1_700_000_000)
        model, ops, prev = Y.BtcChain(anchor, 5, 0, True), [], sha256d(anchor)
        for i in range(14):
            h = mine(prev, 1_700_000_000 - (i % 3))
            ops.append(["add", h.hex()])
            ok, why = model.accept(h)
            self.assertEqual(ok, i < 10, (i, why))
            if not ok:
                break
            prev = sha256d(h)
        r = self.drv(op="btc", anchor=anchor.hex(), height=5, period_time=0, regtest=True, ops=ops)
        self.assertEqual(r["results"], [""] * 10 + ["btc header time is not past the median"])
        self.assertEqual(r["best_height"], 15)

    _hdr_cache = {}

    def test_btc_retarget(self):
        from hashfun import yieldmodel as Y
        from hashfun.ser import header_bytes
        from hashfun.crypto import sha256d
        rng = random.Random(SEED + 10)

        def expected(prev_bits, prev_time, period_time, anchor_height):
            anchor = header_bytes(1, bytes(32), bytes(32), prev_time, prev_bits, 0)
            return anchor, Y.BtcChain(anchor, anchor_height, period_time, False)

        # Bitcoin's first retarget (block 32256): 0x1d00ffff -> 0x1d00d86a.
        anchor, chain = expected(0x1D00FFFF, 1262152739, 1261130161, 32255)
        self.assertEqual(chain.expected_bits(chain.nodes[chain.anchor]), 0x1D00D86A)
        for i in range(max(100, N * 2)):
            bits = rng.choice([0x1D00FFFF, 0x1B0404CB, 0x170331DB, 0x1702C4E4, 0x1C0FFFFF])
            t1 = rng.randrange(1_300_000_000, 1_900_000_000)
            t0 = t1 - rng.choice([1, 1209600, 302400, 302399, 4838400, 4838401, rng.randrange(1, 6_000_000), -500])
            boundary = rng.random() < 0.7
            height = 2016 * rng.randrange(1, 500) - (1 if boundary else rng.randrange(2, 2016))
            anchor, chain = expected(bits, t1, t0, height)
            want = chain.expected_bits(chain.nodes[chain.anchor])
            if not boundary:
                self.assertEqual(want, bits)
            ops = []
            for cand in (want, want ^ 1, bits):
                ops.append(["add", header_bytes(1, sha256d(anchor), rng.randbytes(32), t1 + 600, cand, rng.randrange(2**32)).hex()])
            r = self.drv(op="btc", anchor=anchor.hex(), height=height, period_time=t0 & 0xFFFFFFFF, regtest=False, ops=ops)
            # Difficulty is checked before proof of work, so an unmined header reveals the expected bits.
            py = [Y.BtcChain(anchor, height, t0 & 0xFFFFFFFF, False).accept(bytes.fromhex(o[1]))[1] for o in ops]
            self.assertEqual(r["results"], py, (i, hex(bits), t1 - t0, height))
            self.assertIn(r["results"][0], ("btc header lacks proof of work", ""))
            self.assertEqual(r["results"][1], "btc header has wrong difficulty")

    def test_btc_mainnet_rules_against_core(self):
        """2,017 headers of an alternate mainnet chain produced and validated by stock Bitcoin Core
        32.1 (its own test/functional/mining_mainnet.py): difficulty 1 for one period, then the
        retarget at height 2016 to 0x1c3fffc0. Both implementations must follow it, from the genesis
        anchor and from an anchor in the middle of the period, and reject any other difficulty."""
        from hashfun import yieldmodel as Y
        from hashfun.crypto import sha256d
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "mainnet_alt_headers.hex")
        with open(path) as f:
            hdrs = [bytes.fromhex(x) for x in f.read().split()]
        self.assertEqual(len(hdrs), 2017)
        self.assertEqual(sha256d(hdrs[0])[::-1].hex(), "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
        t0 = struct.unpack("<I", hdrs[0][68:72])[0]
        self.assertEqual([struct.unpack("<I", hdrs[i][72:76])[0] for i in (2015, 2016)], [0x1D00FFFF, 0x1C3FFFC0])
        for anchor_at, period_time in ((0, t0), (1500, t0), (2015, t0)):
            model = Y.BtcChain(hdrs[anchor_at], anchor_at, period_time, False)
            ops = []
            for hdr in hdrs[anchor_at + 1:]:
                self.assertEqual(model.accept(hdr), (True, ""))
                ops.append(["add", hdr.hex()])
            self.assertEqual(model.best, sha256d(hdrs[-1]))
            r = self.drv(op="btc", anchor=hdrs[anchor_at].hex(), height=anchor_at, period_time=period_time, regtest=False, ops=ops)
            self.assertEqual(r["results"], [""] * len(ops))
            self.assertEqual((r["best"], r["best_height"]), (sha256d(hdrs[-1]).hex(), 2016))
        # A wrong period start (anchor mid-period) or any other nBits at the boundary is refused.
        bad = bytearray(hdrs[2016])
        bad[72:76] = struct.pack("<I", 0x1D00FFFF)
        # (This chain's period ran in under 3.5 days, so its span is clamped; a period start ten days
        # earlier gives an unclamped, different target.)
        for anchor_at, period_time, last, why in ((1500, t0 - 86400 * 10, hdrs[2016], "btc header has wrong difficulty"),
                                                 (0, t0, bytes(bad), "btc header has wrong difficulty")):
            model = Y.BtcChain(hdrs[anchor_at], anchor_at, period_time, False)
            ops = [["add", x.hex()] for x in hdrs[anchor_at + 1:2016]] + [["add", last.hex()]]
            for x in hdrs[anchor_at + 1:2016]:
                model.accept(x)
            self.assertEqual(model.accept(last)[1], why)
            r = self.drv(op="btc", anchor=hdrs[anchor_at].hex(), height=anchor_at, period_time=period_time, regtest=False, ops=ops)
            self.assertEqual(r["results"][-1], why)
            self.assertEqual(r["best_height"], 2015)

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
