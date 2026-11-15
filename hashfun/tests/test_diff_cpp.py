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
from hashfun.tests.test_core import qwen_headers

COIN = 100_000_000
SEED = int(os.environ.get("HFDIFF_SEED", "1"))
N = int(os.environ.get("HFDIFF_N", "40"))
DELETE = object()
SATS = {"sats_num": 5, "sats_shift": 3, "btc_anchor_header": "ab" * 80, "creator_btc_script": "0014" + "22" * 20}
QWEN = {"qwen_num": 7, "qwen_shift": 2, "qwen_anchor_header": "cd" * 80, "creator_qwen_script": "0014" + "33" * 20}
NOT_JSON = "descriptor is not a JSON object"
# Qwencoin's work table (528 MB), for the checks that run the real pass: QWORK_TABLE, or where the tools keep it.
TABLE = os.environ.get("QWORK_TABLE") or os.path.join(os.path.expanduser(os.environ.get("HASHFUN_HOME", "~/.hashfun")), "qwork.bin")
VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "qwen_headers.json")


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
        self.p.stdout.close()


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


def qwen_anchor(rng, regtest):
    """(height, header, period start) of a Qwencoin anchor the parsers accept. On regtest anything
    nonzero goes; otherwise a header of the real chain (its bits within Qwencoin's limit) with a
    period start that can be true. No parser looks at its work."""
    if regtest:
        return rng.choice([0, rng.randrange(1, 2**31)]), rng.randbytes(79) + b"\x01", rng.choice([0, rng.randrange(2**32)])
    qh, starts = qwen_headers()
    i = rng.choice([0, 8, 2000, 2016, 4032, 6048, 6100])
    height = i + 2016 * rng.choice([0, 1, 400, (2**31 - 1 - i) // 2016])
    own = header_time(qh[i])
    period = own if height % 2016 == 0 else rng.choice([starts[i - i % 2016], own + 7200, 1])
    return height, qh[i], period


def launch(rng, easy=True, **kw):
    """A random but valid descriptor; easy=True keeps genesis grinding cheap."""
    t0 = rng.choice([1000, 21_000, 12_000_000, 15_000_000, 21_000_000, 20_999_999]) * COIN
    # each of the two curves can mint G: 2 * G and the tail together stay within MAX_MONEY
    top = min(t0 - t0 // 1000, D.MAX_MONEY // 2)
    g = rng.randint(1, top) if rng.random() < 0.5 else min(t0 * D.PUMP_RATIO_G // D.PUMP_RATIO_T, top)
    ihl = rng.choice([0, 1, 1000, 210_000, 2**31 - 1])
    tail = 0 if ihl == 0 else rng.randint(0, (D.MAX_MONEY - 2 * g) // (2 * ihl))
    script = bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 22, 34, 100])))
    # Fields that depend on each other are drawn for the values the caller fixed, if any.
    spacing = kw.get("target_spacing", rng.choice([2, 10, 60, 600, 3600]))
    window = kw.get("lwma_window", rng.choice([3, 10, 45, 144, 1000]))
    test = kw.get("test", rng.random() < 0.5)
    regtest = kw.get("btc_regtest", rng.random() < 0.5)
    qregtest = kw.get("qwen_regtest", rng.random() < 0.5)
    # a test launch may stamp blocks anywhere; any other needs 10 <= ftl < 6 * target_spacing
    ftl = rng.choice([1, 300, 7200]) if test else rng.choice([10, min(7200, 6 * spacing - 1), D.default_ftl(spacing, window)])
    anchor_height, anchor_header, anchor_period = btc_anchor(rng, regtest)
    qanchor_height, qanchor_header, qanchor_period = qwen_anchor(rng, qregtest)
    # the deadline has to last twice as long as the confirmations of a leg on a real chain take
    btc_confs, qwen_confs = kw.get("btc_confs", rng.choice([1, 6, 100])), kw.get("qwen_confs", rng.choice([1, 6, 100, 101, 1008]))
    least = max([110] + [-(-1200 * confs // spacing) for real, confs in ((not regtest, btc_confs), (not qregtest, qwen_confs)) if real])
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
        sats_min_payment=rng.choice([546, 10_000, 10**8]), settle_deadline=rng.choice([least, max(least, 720), 10**6]),
        btc_confs=btc_confs, creator_btc_script=earning_script(rng),
        btc_regtest=regtest,
        qwen_anchor_height=qanchor_height, qwen_anchor_period_time=qanchor_period, qwen_anchor_header=qanchor_header,
        qwen_num=rng.randrange(1, 2**62), qwen_shift=rng.randrange(129), qwen_min_payment=rng.choice([546, 10_000, 10**8]),
        qwen_confs=qwen_confs, creator_qwen_script=earning_script(rng), qwen_regtest=qregtest,
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
    middle of the stored difficulty period: what the rule tests change one field at a time. Its
    deadline, 3600 blocks, is long enough for its confirmations at any block time a launch may have
    (two hours at two seconds), so a test may change the block time alone."""
    hdrs = mainnet_headers()
    qh, qstarts = qwen_headers()
    fields = dict(name="Rules", ticker="RULE", hrp="rule", genesis_time=1_700_000_000, virtual_work=10**12,
                  virtual_tokens=12_000_000 * COIN, graduation_tokens=12_000_000 * COIN * D.PUMP_RATIO_G // D.PUMP_RATIO_T,
                  pow_limit_bits=0x207FFFFF, target_spacing=60, lwma_window=45, ftl=135,
                  btc_anchor_height=1500, btc_anchor_header=hdrs[1500], btc_anchor_period_time=header_time(hdrs[0]),
                  sats_num=5, sats_shift=3, creator_btc_script=bytes.fromhex("0014" + "22" * 20),
                  # the QWEN leg on the real Qwencoin, anchored in the middle of that chain's first period
                  qwen_anchor_height=2000, qwen_anchor_header=qh[2000], qwen_anchor_period_time=qstarts[0],
                  qwen_num=7, qwen_shift=2, creator_qwen_script=bytes.fromhex("0014" + "33" * 20), settle_deadline=3600)
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


def field_mutations(base, sats, qwen):
    """Changes to the launch file `base`, one or a few fields at a time: values at and past every limit,
    values of the wrong kind, fields left out. `sats` and `qwen` are a sats leg and a QWEN leg that are
    valid for this launch."""
    t0 = base["virtual_tokens"]
    hdrs = mainnet_headers()
    start = header_time(hdrs[0])
    qh, qstarts = qwen_headers()
    keys = sorted(set(base) | {"meta", "metadata", "p2p_port", "rpc_port", "creator_btc_script", "creator_qwen_script", "seeds"})

    def qanchor(height, header, period):
        return {"qwen_anchor_height": height, "qwen_anchor_header": header.hex(), "qwen_anchor_period_time": period}

    q2000, qt = qh[2000], header_time(qh[2000])
    qanchors = [qanchor(height, header, period) for height, header, periods in (
        (0, qh[0], (qstarts[0], qstarts[0] - 1, 0)), (4032, qh[0], (qstarts[0], 1)),
        (8, qh[8], (qstarts[0], 0, header_time(qh[8]) + 7200, header_time(qh[8]) + 7201)),
        (2000, q2000, (qstarts[0], 1, 0, 2**32 - 1, qt + 7200, qt + 7201)), (2015, qh[2015], (qstarts[0],)),
        (2016, qh[2016], (qstarts[0], qstarts[2016], 0)), (2017, qh[2016], (qstarts[2016],)),
        (6048, qh[6048], (qstarts[6048], qstarts[4032])), (2**31 - 128, qh[0], (qstarts[0],)), (2**31 - 1, q2000, (qstarts[0],)),
        (0, D.REGTEST_GENESIS_HEADER, (0, header_time(D.REGTEST_GENESIS_HEADER))),
        (2000, q2000[:76] + b"\x00\x00\x00\x01", (qstarts[0],)),            # another nonce: no parser sees its work
        (1500, hdrs[1500], (start, 1)),                                        # a Bitcoin header: within Qwencoin's limit
        (7, bytes(79) + b"\x01", (0, 5))) for period in periods]
    qanchors += [{**a, "qwen_regtest": regtest} for a in qanchors for regtest in (True, False)]
    qanchors += [qanchor(2000, q2000[:72] + struct.pack("<I", bits) + q2000[76:], qstarts[0])
                 for bits in (0, 0x1D80FFFF, 0x1D000000, 0x01003456, 0x2100FFFF, 0x2200FFFF, 0xFF000001, 0x04800001,
                              0x2000FFFF, 0x20010000, 0x2000FFFE, 0x207FFFFF, 0x1F3FFFC0, 0x1D00FFFF, 0x03000001)]
    half = D.MAX_MONEY // 2  # of the supply: what one curve may mint at most

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
        # ---- both curves count against the supply: 2 * G + the tail within MAX_MONEY
        {"tail_reward": (D.MAX_MONEY - 2 * base["graduation_tokens"]) // 2000, "tail_halving_interval": 1000},
        {"tail_reward": (D.MAX_MONEY - 2 * base["graduation_tokens"]) // 2000 + 1, "tail_halving_interval": 1000},
        {"tail_reward": (D.MAX_MONEY - base["graduation_tokens"]) // 2000, "tail_halving_interval": 1000},
        *[{"virtual_tokens": D.MAX_MONEY, "graduation_tokens": g, "tail_reward": r, "tail_halving_interval": 1000 if r else 0}
          for g, r in ((half, 0), (half + 1, 0), (half - 1000, 1), (half - 999, 1), (half - 1, 0), (D.MAX_MONEY - 21000 * COIN, 0))],
        {"virtual_tokens": 15_000_000 * COIN, "graduation_tokens": 11_086_000 * COIN, "tail_reward": 0, "tail_halving_interval": 0},
        {"creator_script": "00" * 101}, {"creator_script": "00" * 100}, {"creator_script": ""},
        {"creator_script": "abc"}, {"creator_script": "zz"}, {"creator_fee_bps": 1000},
        {"creator_fee_bps": 1001}, {"version": 2}, {"version": 3}, {"version": 0},
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
        {"version": 1}, {"version": 3}, {"version": 4}, {"version": 2**32 - 1}, {"version": 2**32}, {"version": "2"},
        {"version": "3"}, {"version": "0x2"}, {"version": "0x3"}, {"version": -2}, {"version": -3}, {"version": 2.0},
        {"version": 3.0}, {"version": True}, {"version": [2]}, {"version": [3]},
        # ---- the QWEN leg, key for key what the sats leg has
        {"qwen_anchor_height": 5}, {"qwen_anchor_period_time": 5}, {"qwen_anchor_height": 5, "qwen_anchor_header": "00" * 80},
        {"qwen_anchor_height": 5, "qwen_anchor_header": "cd" * 80}, {"qwen_anchor_header": "CD" * 80},
        {"qwen_anchor_header": "cd" * 79}, {"qwen_anchor_header": "cd" * 81}, {"qwen_anchor_header": "zz" * 80},
        {"qwen_anchor_header": " " + "cd" * 79 + "c"}, {"qwen_anchor_header": 5}, {"qwen_anchor_header": None},
        {"qwen_anchor_header": ""}, {"qwen_num": 0}, {"qwen_num": DELETE}, {"creator_qwen_script": DELETE},
        {"qwen_anchor_header": DELETE}, {"qwen_anchor_header": "00" * 80},
        {"qwen_regtest": True}, {"qwen_regtest": False}, {"qwen_regtest": 1}, {"qwen_regtest": "true"}, {"qwen_regtest": None},
        {**qwen}, {**qwen, "qwen_num": 2**62}, {**qwen, "qwen_num": 2**62 + 1}, {**qwen, "qwen_num": 2**63},
        {**qwen, "qwen_shift": 128}, {**qwen, "qwen_shift": 129}, {**qwen, "qwen_min_payment": 545},
        {**qwen, "qwen_min_payment": 546}, {**qwen, "qwen_min_payment": D.MAX_MONEY}, {**qwen, "qwen_min_payment": D.MAX_MONEY + 1},
        {**qwen, "qwen_confs": 0}, {**qwen, "qwen_confs": 1}, {**qwen, "qwen_confs": 100}, {**qwen, "qwen_confs": 101},
        {**qwen, "qwen_confs": 1008}, {**qwen, "qwen_confs": 1009}, {**qwen, "qwen_confs": 2**32},
        {**qwen, "btc_confs": 101}, {**qwen, "btc_confs": 1008},         # the Bitcoin leg's limit did not move
        {**qwen, "creator_qwen_script": ""}, {**qwen, "creator_qwen_script": "5"}, {**qwen, "creator_qwen_script": "51" * 81},
        {**qwen, "creator_qwen_script": "51" * 80}, {**qwen, "creator_qwen_script": "5 1"}, {**qwen, "creator_qwen_script": None},
        {"qwen_min_payment": 1}, {"qwen_confs": 0}, {"creator_qwen_script": "51"},
        {"qwen_anchor_height": 2**32}, {"qwen_anchor_height": "7"}, {"qwen_num": "7"}, {"qwen_num": "0x7"}, {"qwen_num": -1},
        *[{"qwen_anchor_height": v} for v in (2015, 2016, 2**31 - 128, 2**31 - 1, 2**31, 2**32 - 1)],
        *qanchors, *[{"creator_qwen_script": x} for x in EARNING + NOT_EARNING],
        # the two legs do not stand in for each other
        {"sats_num": 0, **qwen}, {"qwen_num": 0, **sats}, {"creator_btc_script": DELETE, **qwen},
        # ---- the deadline against the confirmations of a leg on a real chain (1200 seconds for each)
        *[{"target_spacing": t, "ftl": 10, "settle_deadline": n + k, "btc_confs": b, "qwen_confs": q}
          for t, b, q in ((2, 1, 1), (2, 100, 1), (2, 1, 1008), (10, 6, 6), (60, 100, 101), (600, 1, 1008), (3600, 100, 1008))
          for n in {max(110, -(-1200 * b // t)), max(110, -(-1200 * q // t))} for k in (-1, 0, 1)],
        *[{"settle_deadline": n, "btc_regtest": r, "qwen_regtest": qr} for n in (110, 720, 10**6)
          for r in (True, False) for qr in (True, False)],
        {"settle_deadline": 10**6}, {"settle_deadline": 10**6, "btc_confs": 100, "qwen_confs": 1008},
        {"btc_regtest": True, "qwen_regtest": False}, {"btc_regtest": False, "qwen_regtest": True},
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


class QwenMainSim:
    """A made-up Qwencoin under its main-network rules, for the driver's "work":"hash" (for the length
    of one request the node takes a Qwencoin header's own SHA256d hash as its work value, as the model
    does with work_value=sha256d_work: no table). Headers here are mined that way, with the bits
    Qwencoin's rules ask for: the limit 0x2000ffff until the chain's first retarget. The same
    interface as test_yieldstate.BtcSim."""

    def __init__(self, name: str, height: int, period_seconds: int = 100):
        from hashfun import yieldmodel as Y
        from hashfun.ser import header_bytes
        from hashfun.tests.test_yieldstate import H
        self.name, self.anchor_height, self.time = name, height, 1_800_000_000
        self.anchor = header_bytes(0x20000000, H(name, "below"), H(name, "anchor"), self.time, 0x2000FFFF, 0)
        # the time of the first block of the anchor's period: so little before the anchor that the
        # retarget at the end of the period is a full step (a quarter of the target)
        self.period_time = self.time - period_seconds
        self.tree = Y.QwenChain(self.anchor, height, self.period_time, False, Y.sha256d_work)
        self.chain, self.roots = [self.anchor], {}

    def mine(self, txids):
        """A block holding these transactions (after a made-up coinbase). Returns its hash."""
        import itertools
        from hashfun.crypto import sha256d
        from hashfun.ser import header_bytes, merkle_root
        from hashfun.tests.test_yieldstate import H
        self.time += 600
        txids = [H(self.name, "coinbase", len(self.chain), self.time)] + list(txids)
        prev = sha256d(self.chain[-1])
        bits = self.tree.expected_bits(self.tree.nodes[prev])
        target, root = bits_to_target(bits), merkle_root(txids)
        for nonce in itertools.count():
            header = header_bytes(0x20000000, prev, root, self.time, bits, nonce)
            if int.from_bytes(sha256d(header), "little") <= target:
                break
        ok, why = self.tree.accept(header)
        assert ok, why
        self.chain.append(header)
        self.roots[sha256d(header)] = txids
        return sha256d(header)


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

    @staticmethod
    def node_words(python_error):
        """What the node says where Python says this. The same words, except that where the text is not
        JSON at all Python adds what its own reader made of it."""
        return NOT_JSON if python_error.startswith(NOT_JSON) else python_error

    def check_cases(self, cases):
        """cases: (label, text or bytes, expected). expected: None (the parsers have to agree with each
        other), True (both accept), or a string (both refuse, and these words are in what they say; ""
        for any words). Agreeing means more than both refusing: a refused file is refused by both for
        the same reason in the same words, also when several things are wrong with it (the keys are
        read and the checks made in one order)."""
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
            elif not c_ok and c_err != self.node_words(p_err):
                problems.append(f"{label}: refused by both, for another reason. node: {c_err} / python: {p_err}")
        self.assertEqual(problems[:40], [], "\n" + "\n".join(problems[:40]) + f"\n({len(problems)} in all)")
        return len(cases)

    def launch_id(self, base, changes):
        """The id both parsers give the file `base` with `changes`; the file has to be a valid launch."""
        c_ok, c_err, p_ok, p_err, lid = self.both(with_changes(base, changes), describe(changes))
        self.assertTrue(c_ok and p_ok, (describe(changes), c_err, p_err))
        return lid

    def test_parser_agrees_on_accept_reject(self):
        """Every way of getting a field wrong that we could think of, against five launches: a test launch
        on a regtest Bitcoin and a regtest Qwencoin, a production launch on the two real chains, a
        production launch on two regtest chains (the fleet tests), and the two with one leg on each kind.
        Whatever one parser makes of a file, the other makes the same."""
        rng = random.Random(SEED + 2)
        total = 0
        for test, regtest, qregtest in ((True, True, True), (False, False, False), (False, True, True),
                                        (False, False, True), (False, True, False)):
            # T0 12M at pump proportions leaves the tail 3.26M coins under the two-curve bound: 1000 a halving fits
            t0 = 12_000_000 * COIN
            base = launch(rng, creator_script=bytes.fromhex("0014" + "11" * 20), creator_fee_bps=100,
                          virtual_tokens=t0, graduation_tokens=t0 * D.PUMP_RATIO_G // D.PUMP_RATIO_T,
                          tail_reward=COIN, tail_halving_interval=1000, test=test, btc_regtest=regtest,
                          qwen_regtest=qregtest).to_json()
            # a made-up anchor header is only a valid anchor on regtest: elsewhere the launch keeps its real one
            sats = SATS if regtest else {k: v for k, v in SATS.items() if k != "btc_anchor_header"}
            qwen = QWEN if qregtest else {k: v for k, v in QWEN.items() if k != "qwen_anchor_header"}
            self.assertEqual(self.both(json.dumps(base))[:4], (True, "", True, ""), "the launch the changes are made to")
            cases = [(f"test={test} btc_regtest={regtest} qwen_regtest={qregtest}: {describe(m)}", with_changes(base, m), None)
                     for m in field_mutations(base, sats, qwen)]
            total += self.check_cases(cases)
        self.assertGreater(total, 5000)

    def test_a_file_with_several_things_wrong_is_told_about_the_same_one(self):
        """Two parsers that both refuse a file may still name different faults in it, if they read its
        keys or make their checks in another order: then a tool says one thing is wrong with a launch
        file and the node another. Files with two to four faults at once, drawn from every single fault
        the suite knows, and documents with several faults in their text: the node and Python name the
        same one, in the same words."""
        rng = random.Random(SEED + 14)
        named = {}
        cases = []
        for test, regtest, qregtest in ((True, True, True), (False, False, False), (False, True, False)):
            t0 = 12_000_000 * COIN
            base = launch(rng, creator_script=bytes.fromhex("0014" + "11" * 20), creator_fee_bps=100,
                          virtual_tokens=t0, graduation_tokens=t0 * D.PUMP_RATIO_G // D.PUMP_RATIO_T,
                          tail_reward=COIN, tail_halving_interval=1000, test=test, btc_regtest=regtest,
                          qwen_regtest=qregtest).to_json()
            sats = SATS if regtest else {k: v for k, v in SATS.items() if k != "btc_anchor_header"}
            qwen = QWEN if qregtest else {k: v for k, v in QWEN.items() if k != "qwen_anchor_header"}
            faults = []  # every change that by itself makes the file one both refuse, with what the node says of it
            for m in field_mutations(base, sats, qwen):
                c_ok, c_err, p_ok, _p_err, _ = self.both(with_changes(base, m))
                if not c_ok and not p_ok:
                    faults.append((m, c_err))
            self.assertGreater(len(faults), 400)
            for _ in range(max(1500, N * 40)):
                picks = rng.sample(faults, rng.choice([2, 2, 3, 4]))
                if len({k for m, _ in picks for k in m}) < sum(len(m) for m, _ in picks):
                    continue  # two of them change the same key: one would undo the other
                m = {}
                for change, _ in picks:
                    m.update(change)
                text = with_changes(base, m)
                cases.append((f"test={test} btc_regtest={regtest} qwen_regtest={qregtest}: {describe(m)}", text, ""))
                key = self.drv(op="desc", json=text).get("error", "").split(":")[0]  # the key the node names first
                named[key] = named.get(key, 0) + 1
        self.assertGreater(len(cases), 3000)
        self.check_cases(cases)
        # the faults named are not all one key: the order was put to the test from many sides
        self.assertGreater(len(named), 30, named)
        # The reviewer's example, and its kind: a fault in a key that is read early and one in a key read late.
        base = production_launch().to_json()
        pairs = [
            ({"genesis_time": "x", "qwen_regtest": 1}, "genesis_time: not an integer"),
            ({"qwen_regtest": 1, "meta": "zz"}, "qwen_regtest: expected bool"),
            ({"btc_regtest": 1, "genesis_time": "x"}, "genesis_time: not an integer"),
            ({"btc_regtest": 1, "qwen_anchor_height": -1}, "btc_regtest: expected bool"),
            ({"qwen_anchor_header": "zz", "sats_num": "x"}, "sats_num: not an integer"),
            ({"creator_qwen_script": "zz", "qwen_num": "x"}, "qwen_num: not an integer"),
            ({"creator_qwen_script": "zz", "qwen_regtest": 1}, "creator_qwen_script: expected 1..80 bytes of hex"),
            ({"meta": "zz", "qwen_confs": 2000}, "qwen_confs: out of range"),
            ({"meta": "zz", "seeds": "x"}, "meta: expected 32..32 bytes of hex"),
            ({"version": 2, "name": 5}, "version: 2 is the earlier rule set"), ({"version": "x", "name": 5}, "version: not an integer"),
            ({"name": 5, "ticker": 5}, "name: expected string"), ({"ticker": 5, "hrp": 5}, "ticker: expected string"),
            ({"hrp": 5, "pubkey_prefix": 300}, "hrp: expected string"),
            ({"test": 1, "creator_fee_bps": 2000}, "creator_fee_bps: out of range"), ({"test": 1, "p2p_port": 70000}, "test: expected bool"),
            ({"creator_script": 5, "tail_halving_interval": -1}, "tail_halving_interval: out of range"),
            ({"creator_script": "zz", "creator_fee_bps": "x"}, "creator_script: invalid hex"),
            ({"creator_script": 5, "creator_fee_bps": "x"}, "creator_script: expected string"),
            ({"virtual_work": "x", "virtual_tokens": -1}, "virtual_work: expected decimal or 0x-hex integer string"),
            ({"virtual_work": str(2**256), "ftl": "x"}, "ftl: not an integer"),
            ({"virtual_work": str(2**256), "virtual_tokens": "x"}, "virtual_work: expected decimal or 0x-hex integer string"),
            ({"virtual_work": 5, "lwma_window": 5000}, "lwma_window: out of range"),
            # what is read comes before what is checked, and the checks have their order too
            ({"sats_num": 0, "meta": "zz"}, "meta: expected 32..32 bytes of hex"),
            ({"sats_num": 0, "qwen_num": 0, "seeds": "x", "name": ""}, "sats_num: required"),
            ({"qwen_num": 0, "seeds": "x", "name": ""}, "qwen_num: required"),
            ({"seeds": "x", "name": ""}, "seeds: expected array of strings"), ({"seeds": [1], "ticker": "ab"}, "seeds: expected"),
            ({"name": "", "ticker": "ab"}, "name: 1..64 chars"), ({"ticker": "ab", "hrp": "bc"}, "ticker: 2..10 chars"),
            ({"hrp": "bc", "pubkey_prefix": 0}, "hrp: 1..20 chars"), ({"pubkey_prefix": 0, "pow_limit_bits": 0}, "pubkey_prefix/script_prefix"),
            ({"pow_limit_bits": 0, "target_spacing": 1, "settle_deadline": 10**6}, "pow_limit_bits: invalid compact target"),
            ({"target_spacing": 1, "settle_deadline": 10**6, "lwma_window": 2}, "target_spacing: 2..3600"),
            # (a block time of one second makes this launch's deadline an hour: that is said first)
            ({"target_spacing": 1, "lwma_window": 2}, "settle_deadline: too short for qwen_confs"),
            ({"lwma_window": 2, "ftl": 0}, "lwma_window: 3..1000"),
            ({"ftl": 0, "virtual_work": "0"}, "ftl: 1..7200"), ({"ftl": 9, "virtual_work": "0"}, "ftl: at least 10"),
            ({"virtual_work": "0", "graduation_tokens": 0}, "virtual_work: must be in (0, 2^160]"),
            ({"graduation_tokens": 0, "tail_reward": 1, "tail_halving_interval": 0}, "need 0 < graduation_tokens < virtual_tokens"),
            ({"graduation_tokens": base["virtual_tokens"] - 1, "creator_script": "00" * 101}, "graduation_tokens may be at most 99.9%"),
            ({"tail_reward": 1, "tail_halving_interval": 0, "creator_script": "00" * 101}, "tail_halving_interval: required when tail_reward > 0"),
            ({"tail_reward": D.MAX_MONEY, "tail_halving_interval": 5, "creator_script": "00" * 101}, "2 * graduation_tokens + total tail emission"),
            ({"creator_script": "00" * 101, "creator_fee_bps": 5}, "creator_script: at most 100 bytes"),
            ({"creator_script": "", "creator_fee_bps": 5}, "creator_script: required when creator_fee_bps > 0"),
            # the sats leg before the QWEN leg, each in its own order, the deadline last
            ({"creator_btc_script": "51", "qwen_num": 0}, "creator_btc_script: must be"),
            ({"btc_confs": 0, "qwen_anchor_header": "00" * 80}, "btc_confs: at least 1"),
            ({"sats_min_payment": 1, "settle_deadline": 1, "btc_confs": 0}, "sats_min_payment: at least 546"),
            ({"settle_deadline": 1, "btc_confs": 0}, "settle_deadline: at least 110 blocks"),
            ({"qwen_min_payment": 1, "qwen_confs": 0}, "qwen_min_payment: at least 546"),
            ({"qwen_confs": 0, "btc_confs": 100}, "qwen_confs: at least 1"),
            ({"settle_deadline": 720, "btc_confs": 100, "qwen_confs": 1008}, "settle_deadline: too short for btc_confs"),
            ({"qwen_confs": 1008, "seeds": "x"}, "settle_deadline: too short for qwen_confs"),
        ]
        self.check_cases([(describe(m), with_changes(base, m), expected) for m, expected in pairs])
        # The text itself: what is not JSON to the node's reader comes first wherever it stands, then what
        # the node looks for in the document, a value before what is inside it and members in the order written.
        text = json.dumps(base)

        def more(extra):
            return text[:-1] + "," + extra + "}"

        TWICE, LONG, DEEP = "the key appears twice in one object", "descriptor: a number of more than 40 characters", \
            "descriptor: nested more than 64 levels"
        long_number, deep = "1" * 41, "[" * 64 + "]" * 64
        documents = [
            ("a key twice, then a long number inside", more('"x":[' + long_number + '],"ticker":"ZZZ"'), "ticker: " + TWICE),
            ("a long number inside, then the key twice", '{"ticker":"ZZZ",' + text[1:-1] + ',"x":[' + long_number + "]}", "ticker: " + TWICE),
            ("twice in a member, then a long number", more('"x":{"a":1,"a":2},"y":' + long_number), "a: " + TWICE),
            ("a long number, then twice in a later member", more('"y":' + long_number + ',"x":{"a":1,"a":2}'), LONG),
            ("too deep, then twice in a later member", more('"x":' + deep + ',"y":{"a":1,"a":2}'), DEEP),
            ("twice in a member, then too deep", more('"y":{"a":1,"a":2},"x":' + deep), "a: " + TWICE),
            ("a long number below the depth limit's reach", more('"x":' + "[" * 65 + long_number + "]" * 65), DEEP),
            ("a long number as the value of a key that is there twice", more('"x":{"a":' + long_number + ',"a":2}'), "a: " + TWICE),
            ("three keys twice: the first to come again is named", more('"foo":1,"bar":2,"bar":3,"foo":4'), "bar: " + TWICE),
            ("an early key again at the end", more('"zz":1,"name":"again"'), "name: " + TWICE),
            ("a key twice, then text that is not JSON", more('"ticker":"Z"') + "x", NOT_JSON),
            ("a key twice and NaN", more('"ticker":"Z","x":NaN'), NOT_JSON),
            ("half a surrogate pair and a key twice", more('"x":"\\ud800","ticker":"Z"'), NOT_JSON),
            ("half a surrogate pair in the value of a key that is there twice", more('"x":1,"x":"\\ud800"'), NOT_JSON),
            ("half a surrogate pair in a key that is there twice", more('"\\ud800":1,"\\ud800":2'), NOT_JSON),
            ("a key twice in an array and not an object", "[" + more('"ticker":"Z"') + "]", NOT_JSON),
            ("bytes that are not UTF-8 after a key twice", more('"ticker":"Z"').encode() + b"\xff", "descriptor is not valid UTF-8"),
            ("bytes that are not UTF-8 in text that is not JSON", b"\xff" + text.encode() + b"x", "descriptor is not valid UTF-8"),
            ("a key twice and a field of the wrong kind", more('"foo":1,"foo":2').replace('"sats_shift": 3', '"sats_shift": "x"'), "foo: " + TWICE),
            ("a long number and a field of the wrong kind", more('"x":' + long_number).replace('"sats_shift": 3', '"sats_shift": "x"'), LONG),
            ("version 2 and a key twice", more('"foo":1,"foo":2').replace('"version": 3', '"version": 2'), "foo: " + TWICE),
            # how deep the node's reader reads at all: 512 levels, the outer object counted
            ("511 arrays inside the object", more('"x":' + "[" * 511 + "]" * 511), DEEP),
            ("512 arrays inside the object", more('"x":' + "[" * 512 + "]" * 512), NOT_JSON),
            ("511 objects inside the object", more('"x":' + '{"a":' * 511 + "1" + "}" * 511), DEEP),
            ("512 objects inside the object", more('"x":' + '{"a":' * 512 + "1" + "}" * 512), NOT_JSON),
            ("512 arrays, after a key twice", more('"ticker":"Z","x":' + "[" * 512 + "]" * 512), NOT_JSON),
            ("600 arrays and a long number", more('"y":' + long_number + ',"x":' + "[" * 600 + "]" * 600), NOT_JSON),
            ("100,000 arrays", more('"x":' + "[" * 100_000 + "]" * 100_000), NOT_JSON),
        ]
        self.check_cases(documents)

    def test_new_rules_accept_and_reject(self):
        """The rules that came with descriptor versions 2 and 3, each at its boundary, on one fixed
        production launch with one thing changed at a time: both parsers accept, or both refuse and say
        why in the same words."""
        from hashfun.crypto import sha256d
        hdrs = mainnet_headers()
        t0, own, h2016 = header_time(hdrs[0]), header_time(hdrs[1500]), hdrs[2016]
        qh, qstarts = qwen_headers()
        q0, q2000, q2016, qs0 = qh[0], qh[2000], qh[2016], qstarts[0]
        qown = header_time(q2000)
        self.assertEqual((header_time(q0), header_time(q2016)), (qs0, qstarts[2016]))
        base = production_launch().to_json()
        self.assertEqual((base["target_spacing"], base["lwma_window"], base["ftl"], base["test"], base["btc_regtest"],
                          base["qwen_regtest"], base["version"]), (60, 45, 135, False, False, False, 3))
        G = base["graduation_tokens"]
        SUPPLY = ("2 * graduation_tokens + total tail emission exceeds MAX_MONEY (each of the two curves can mint "
                  "graduation_tokens)")
        V1 = "version: 1 is the earlier, pre-release rule set. This launch file must be created again (hashfun launch new)"
        V2 = ("version: 2 is the earlier rule set with one curve, quoted in BTC only. This launch file must be created "
              "again (hashfun launch new)")
        QFORM = ("creator_qwen_script: must be a P2PKH, P2SH or witness-program script (one a Qwencoin node relays a "
                 "payment to)")
        QBITS = "qwen_anchor_header: its difficulty bits are not a valid target"
        QEASY = ("qwen_anchor_header: easier than Qwencoin's minimum difficulty (not a Qwencoin mainnet header; a regtest "
                 "anchor needs qwen_regtest)")
        QOPENS = ("qwen_anchor_period_time: the anchor opens a difficulty period (height is a multiple of 2016), so it must "
                  "be the anchor header's own time")
        QLATE = "qwen_anchor_period_time: later than the anchor block itself"
        QNEED = "qwen_anchor_period_time: required (the time of the first block of the anchor's 2016-block difficulty period)"
        QWITH = "qwen_anchor_header: required with qwen_anchor_height / qwen_anchor_period_time"
        QNUM = "qwen_num: required (every launch has a QWEN leg)"
        NO_QANCHOR = {"qwen_anchor_header": DELETE, "qwen_anchor_height": DELETE, "qwen_anchor_period_time": DELETE}
        SHORT_B = ("settle_deadline: too short for btc_confs: the deadline must last at least twice as long as the "
                   "confirmations take (ten minutes each)")
        SHORT_Q = ("settle_deadline: too short for qwen_confs: the deadline must last at least twice as long as the "
                   "confirmations take (ten minutes each)")
        WEEK = {"settle_deadline": 20160}  # blocks of this launch (a minute each): two weeks, twice a week of confirmations
        HALF_DAY = {"settle_deadline": 720}  # twelve hours: twice what 36 confirmations take

        def qanchor(height, header, period, **more):
            return {"qwen_anchor_height": height, "qwen_anchor_header": header.hex(), "qwen_anchor_period_time": period, **more}
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
            # ---- version: 3, and 1 and 2 are each told what happened to them
            ({"version": 3}, True), ({"version": "3"}, True), ({"version": "0x3"}, True), ({"version": DELETE}, True),
            ({"version": None}, True),
            ({"version": 1}, V1), ({"version": "1"}, V1), ({"version": "0x1"}, V1),
            ({"version": 2}, V2), ({"version": "2"}, V2), ({"version": "0x2"}, V2),
            # (a rule set 2 file as it was written: no QWEN leg. What it is told is its version, not what it lacks)
            ({"version": 2, "qwen_num": DELETE, "creator_qwen_script": DELETE, **NO_QANCHOR}, V2),
            ({"version": 0}, "unsupported descriptor version"), ({"version": 4}, "unsupported descriptor version"),
            ({"version": 2**32 - 1}, "unsupported descriptor version"),
            ({"version": 2**32}, "version: out of range"), ({"version": -1}, "version: out of range"),
            ({"version": 3.0}, "version: expected integer"), ({"version": True}, "version: expected integer"),
            ({"version": "three"}, "version: not an integer"),
            # ---- the supply: each of the two curves can mint graduation_tokens, and the tail comes on top
            ({"tail_reward": (D.MAX_MONEY - 2 * G) // 2000, "tail_halving_interval": 1000}, True),
            ({"tail_reward": (D.MAX_MONEY - 2 * G) // 2000 + 1, "tail_halving_interval": 1000}, SUPPLY),
            ({"tail_reward": (D.MAX_MONEY - G) // 2000, "tail_halving_interval": 1000}, SUPPLY),  # the bound of one curve
            ({"virtual_tokens": 15_000_000 * COIN, "graduation_tokens": 15_000_000 * COIN * D.PUMP_RATIO_G // D.PUMP_RATIO_T},
             SUPPLY),
            ({"virtual_tokens": 12_075_000 * COIN, "graduation_tokens": 12_075_000 * COIN * D.PUMP_RATIO_G // D.PUMP_RATIO_T},
             True),
            ({"virtual_tokens": D.MAX_MONEY, "graduation_tokens": D.MAX_MONEY // 2}, True),
            ({"virtual_tokens": D.MAX_MONEY, "graduation_tokens": D.MAX_MONEY // 2 + 1}, SUPPLY),
            ({"virtual_tokens": D.MAX_MONEY, "graduation_tokens": D.MAX_MONEY // 2, "tail_reward": 1, "tail_halving_interval": 1},
             SUPPLY),
            # ---- the QWEN leg: every launch has one
            ({"qwen_num": 0}, QNUM), ({"qwen_num": DELETE}, QNUM), ({"qwen_num": None}, QNUM), ({"qwen_num": 1}, True),
            ({"qwen_num": 2**62}, True), ({"qwen_num": 2**62 + 1}, "qwen_num: out of range"), ({"qwen_num": "0x7"}, True),
            ({"qwen_num": -1}, "qwen_num: out of range"), ({"qwen_num": 7.0}, "qwen_num: expected integer"),
            ({"qwen_shift": 128}, True), ({"qwen_shift": 129}, "qwen_shift: out of range"), ({"qwen_shift": DELETE}, True),
            ({"qwen_min_payment": 545}, "qwen_min_payment: at least 546"), ({"qwen_min_payment": 546}, True),
            ({"qwen_min_payment": 0}, "qwen_min_payment: at least 546"), ({"qwen_min_payment": D.MAX_MONEY}, True),
            ({"qwen_min_payment": D.MAX_MONEY + 1}, "qwen_min_payment: out of range"),
            # qwen_confs: up to a week of Qwencoin blocks; Bitcoin's stay at a hundred. (A week of confirmations
            # needs a deadline of two: 20160 of this launch's blocks, a minute each. See below.)
            ({"qwen_confs": 0}, "qwen_confs: at least 1"), ({"qwen_confs": 1}, True), ({**WEEK, "qwen_confs": 100}, True),
            ({**WEEK, "qwen_confs": 101}, True), ({**WEEK, "qwen_confs": 1008}, True),
            ({**WEEK, "qwen_confs": 1009}, "qwen_confs: out of range"),
            ({"qwen_confs": 2**32}, "qwen_confs: out of range"), ({**WEEK, "btc_confs": 100}, True),
            ({**WEEK, "btc_confs": 101}, "btc_confs: out of range"),
            # ---- the deadline against the confirmations: settle_deadline blocks of target_spacing seconds must
            # last twice as long as the confirmations of a leg on a real chain take, at ten minutes each
            ({**HALF_DAY, "qwen_confs": 36}, True), ({**HALF_DAY, "qwen_confs": 37}, SHORT_Q),
            ({**HALF_DAY, "btc_confs": 36}, True), ({**HALF_DAY, "btc_confs": 37}, SHORT_B),
            ({**HALF_DAY, "btc_confs": 37, "qwen_confs": 37}, SHORT_B),          # Bitcoin's is looked at first
            ({"qwen_confs": 180}, True), ({"qwen_confs": 181}, SHORT_Q),          # this launch's own 3600 blocks
            ({"settle_deadline": 120}, True), ({"settle_deadline": 119}, SHORT_Q),   # qwen_confs 6: two hours
            ({"settle_deadline": 119, "qwen_confs": 5}, True), ({"settle_deadline": 110, "qwen_confs": 6}, SHORT_Q),
            ({"settle_deadline": 110, "qwen_confs": 5, "btc_confs": 6}, SHORT_B),
            ({"settle_deadline": 20160, "qwen_confs": 1008}, True), ({"settle_deadline": 20159, "qwen_confs": 1008}, SHORT_Q),
            ({"settle_deadline": 2000, "btc_confs": 100}, True), ({"settle_deadline": 1999, "btc_confs": 100}, SHORT_B),
            # the block time counts: the same deadline in blocks is ten times as long at ten times the spacing
            ({"target_spacing": 600, "ftl": 135, "settle_deadline": 110, "qwen_confs": 55}, True),
            ({"target_spacing": 600, "ftl": 135, "settle_deadline": 110, "qwen_confs": 56}, SHORT_Q),
            ({"target_spacing": 2, "ftl": 10, "settle_deadline": 3600}, True),
            ({"target_spacing": 2, "ftl": 10, "settle_deadline": 3599}, SHORT_Q),
            ({"target_spacing": 2, "ftl": 10, "settle_deadline": 10**6, "qwen_confs": 1008, "btc_confs": 100}, True),
            ({"target_spacing": 2, "ftl": 10, "settle_deadline": 604_799, "qwen_confs": 1008}, SHORT_Q),
            ({"target_spacing": 2, "ftl": 10, "settle_deadline": 604_800, "qwen_confs": 1008}, True),
            # a leg on regtest is not held to it (its blocks come when a test makes them), the other one still is
            ({"qwen_regtest": True, "qwen_confs": 1008}, True), ({"btc_regtest": True, "btc_confs": 100}, True),
            ({**HALF_DAY, "qwen_regtest": True, "btc_confs": 37}, SHORT_B),
            ({**HALF_DAY, "btc_regtest": True, "qwen_confs": 37}, SHORT_Q),
            ({"btc_regtest": True, "qwen_regtest": True, "settle_deadline": 110, "btc_confs": 100, "qwen_confs": 1008}, True),
            # it is the last thing asked of the two legs: whatever else is wrong with them is said first
            ({"qwen_confs": 37, "qwen_min_payment": 1}, "qwen_min_payment: at least 546"),
            ({"btc_confs": 37, "creator_qwen_script": "51"}, QFORM), ({"qwen_confs": 37, "sats_min_payment": 1}, "sats_min_payment: at least 546"),
            ({"settle_deadline": 109, "qwen_confs": 1008}, "settle_deadline: at least 110 blocks"),
            # ... and it comes before the seeds and everything about the chain itself
            ({**HALF_DAY, "qwen_confs": 37, "seeds": "x"}, SHORT_Q), ({**HALF_DAY, "qwen_confs": 37, "ticker": "ab"}, SHORT_Q),
            ({"qwen_confs": 37, "target_spacing": 1}, SHORT_Q),
            ({"qwen_regtest": "true"}, "qwen_regtest: expected bool"), ({"qwen_regtest": 1}, "qwen_regtest: expected bool"),
            # the sats leg is looked at first, then the QWEN leg in its own order
            ({"sats_num": 0, "qwen_num": 0}, "sats_num: required (every launch has a sats leg)"),
            ({"qwen_num": 0, "qwen_anchor_header": DELETE}, QWITH), ({"qwen_num": 0, **NO_QANCHOR}, QNUM),
            ({"qwen_num": 0, "creator_qwen_script": DELETE}, QNUM),
            ({"creator_qwen_script": DELETE, "qwen_min_payment": 1}, "creator_qwen_script: required"),
            ({"qwen_min_payment": 1, "qwen_confs": 0}, "qwen_min_payment: at least 546"),
            (qanchor(2000, q2000, 0, creator_qwen_script="51"), QNEED),   # the anchor before the script
            # ---- the Qwencoin anchor: a header within Qwencoin's limit, and a period start that can be true
            (qanchor(2000, q2000, qs0), True), (qanchor(2000, q2000, qown), True), (qanchor(2000, q2000, 1), True),
            (qanchor(2000, q2000, qown + 7200), True), (qanchor(2000, q2000, qown + 7201), QLATE),
            (qanchor(2000, q2000, 2**32 - 1), QLATE), (qanchor(2000, q2000, 0), QNEED),
            ({"qwen_anchor_period_time": DELETE}, QNEED), ({"qwen_anchor_period_time": None}, QNEED),
            ({"qwen_anchor_header": DELETE}, QWITH), ({"qwen_anchor_header": None}, QWITH), (NO_QANCHOR, "qwen_anchor_header: required"),
            ({"qwen_anchor_header": "cd" * 79}, "qwen_anchor_header: expected 80..80 bytes of hex"),
            (qanchor(2000, bytes(80), qs0), QWITH), (qanchor(0, bytes(80), 0), "qwen_anchor_header: required"),
            # no parser can see a Qwencoin header's work (it takes the chain's table): another nonce is the same to
            # both, and so is a Bitcoin header. The node checks the anchor's work when it starts.
            (qanchor(2000, q2000[:76] + b"\x01\x00\x00\x00", qs0), True), (qanchor(1500, hdrs[1500], t0), True),
            # at a retarget boundary the period starts with the anchor itself
            (qanchor(2016, q2016, header_time(q2016)), True), (qanchor(2016, q2016, qs0), QOPENS),
            (qanchor(2016, q2016, header_time(q2016) + 1), QOPENS), (qanchor(2016, q2016, 0), QNEED),
            (qanchor(0, q0, qs0), True), (qanchor(4032, q0, qs0), True), (qanchor(0, q0, qs0 - 1), QOPENS),
            (qanchor(6048, qh[6048], qstarts[6048]), True), (qanchor(6048, qh[6048], qstarts[4032]), QOPENS),
            (qanchor(2**31 - 128, q0, qs0), True), (qanchor(2**31 - 128, q2000, qs0), QOPENS),
            (qanchor(2**31 - 1, q2000, qs0), True), (qanchor(2**31, q2000, qs0), "qwen_anchor_height: out of range"),
            ({"qwen_anchor_height": DELETE, "qwen_anchor_header": q0.hex(), "qwen_anchor_period_time": qs0}, True),
            (qanchor(2017, q2016, qs0), True),  # a parser cannot know the height is wrong: check_qwen_anchor() asks a node
            # the difficulty bits: a valid compact target, no easier than Qwencoin's limit 0x2000ffff
            (qanchor(2000, with_bits(q2000, 0x1D80FFFF), qs0), QBITS), (qanchor(2000, with_bits(q2000, 0), qs0), QBITS),
            (qanchor(2000, with_bits(q2000, 0x1D000000), qs0), QBITS), (qanchor(2000, with_bits(q2000, 0x01003456), qs0), QBITS),
            (qanchor(2000, with_bits(q2000, 0xFF000001), qs0), QBITS), (qanchor(2000, with_bits(q2000, 0x2200FFFF), qs0), QBITS),
            (qanchor(2000, with_bits(q2000, 0x04800001), qs0), QBITS),
            (qanchor(2000, with_bits(q2000, 0x2100FFFF), qs0), QEASY), (qanchor(2000, with_bits(q2000, 0x20010000), qs0), QEASY),
            (qanchor(2000, with_bits(q2000, 0x207FFFFF), qs0), QEASY),
            (qanchor(2000, with_bits(q2000, 0x2000FFFF), qs0), True), (qanchor(2000, with_bits(q2000, 0x2000FFFE), qs0), True),
            (qanchor(2000, with_bits(q2000, 0x1F3FFFC0), qs0), True), (qanchor(2000, with_bits(q2000, 0x1D00FFFF), qs0), True),
            (qanchor(2000, with_bits(q2000, 0x03000001), qs0), True),
            (qanchor(0, D.REGTEST_GENESIS_HEADER, header_time(D.REGTEST_GENESIS_HEADER)), QEASY),
            (qanchor(2000, bytes(79) + b"\x01", qs0), QBITS),
            # with qwen_regtest none of that is asked
            (qanchor(0, D.REGTEST_GENESIS_HEADER, 0, qwen_regtest=True), True),
            (qanchor(2016, q2000, 7, qwen_regtest=True), True), (qanchor(2000, bytes(79) + b"\x01", 0, qwen_regtest=True), True),
            (qanchor(2000, bytes(80), 0, qwen_regtest=True), QWITH), (qanchor(0, bytes(80), 0, qwen_regtest=True),
                                                                      "qwen_anchor_header: required"),
            # one leg on a regtest chain says nothing about the other
            ({"btc_regtest": True}, True), ({"qwen_regtest": True}, True),
            (qanchor(0, D.REGTEST_GENESIS_HEADER, 0, btc_regtest=True), QEASY),
            (anchor(0, D.REGTEST_GENESIS_HEADER, 0, qwen_regtest=True), EASY),
            # ---- creator_qwen_script: the same forms, for the same reason
            *[({"creator_qwen_script": x}, True) for x in EARNING], *[({"creator_qwen_script": x}, QFORM) for x in NOT_EARNING],
            ({"creator_qwen_script": DELETE}, "creator_qwen_script: required"),
            ({"creator_qwen_script": None}, "creator_qwen_script: required"),
            ({"creator_qwen_script": ""}, "creator_qwen_script: expected 1..80 bytes of hex"),
            ({"creator_qwen_script": "51" * 81}, "creator_qwen_script: expected 1..80 bytes of hex"),
            ({"qwen_regtest": True, "creator_qwen_script": "51"}, QFORM), ({"test": True, "creator_qwen_script": "51"}, QFORM),
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
        self.assertGreater(accepted, 90)
        self.assertGreater(len(rules) - accepted, 160)
        # A field left out is the field at its default: the same launch, the same id, in both parsers.
        same = self.launch_id(base, {})
        self.assertEqual(same, production_launch().id_hex)
        for m in ({"ftl": DELETE}, {"ftl": None}, {"version": DELETE}, {"version": None}, {"version": "3"},
                  {"btc_anchor_period_time": str(t0)}, {"btc_anchor_height": "0x5dc"}, {"qwen_anchor_height": "0x7d0"},
                  {"qwen_anchor_period_time": str(qs0)}, {"qwen_shift": "2"}, {"qwen_min_payment": DELETE},
                  {"qwen_min_payment": 10_000}, {"qwen_confs": DELETE}, {"qwen_confs": 6}, {"qwen_regtest": DELETE},
                  {"qwen_regtest": None}):
            self.assertEqual(self.launch_id(base, m), same, describe(m))
        # Every field of the QWEN leg is part of what the launch is: change one and it is another launch.
        others = [self.launch_id(base, m) for m in (
            {"qwen_anchor_height": 2001}, {"qwen_anchor_header": qh[2001].hex()}, {"qwen_anchor_period_time": 1},
            {"qwen_num": 8}, {"qwen_shift": 3}, {"qwen_min_payment": 546}, {"qwen_confs": 7},
            {"creator_qwen_script": "0014" + "34" * 20}, {"qwen_regtest": True})]
        self.assertEqual(len(set(others + [same])), 10)
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
        qgenesis = qwen_headers()[0][0]
        # (The deadline is among them: the default one, 720 blocks, is an hour at the default block time
        # of five seconds, and the six Qwencoin confirmations a launch asks for by default take an hour
        # themselves. A launch on the real Qwencoin has to say how long it gives a payment.)
        minimal = {"name": "Minimal", "ticker": "MIN", "genesis_time": 1_700_000_000, "virtual_work": "1000000",
                   "virtual_tokens": 1000 * COIN, "graduation_tokens": 500 * COIN, "sats_num": 1,
                   "btc_anchor_header": genesis.hex(), "btc_anchor_period_time": header_time(genesis),
                   "creator_btc_script": "0014" + "22" * 20, "qwen_num": 1,
                   "qwen_anchor_header": qgenesis.hex(), "qwen_anchor_period_time": header_time(qgenesis),
                   "creator_qwen_script": "0014" + "33" * 20, "settle_deadline": 1440}
        self.assertEqual(self.both(json.dumps(minimal))[:4], (True, "", True, ""))
        d = D.parse(json.dumps(minimal))
        self.assertEqual(
            (d.version, d.hrp, d.pubkey_prefix, d.script_prefix, d.secret_prefix, d.genesis_nonce, d.pow_limit_bits,
             d.target_spacing, d.lwma_window, d.ftl, d.tail_reward, d.tail_halving_interval, d.creator_script,
             d.creator_fee_bps, d.test, d.btc_anchor_height, d.sats_shift, d.sats_min_payment,
             d.btc_confs, d.btc_regtest, d.qwen_anchor_height, d.qwen_shift, d.qwen_min_payment, d.qwen_confs,
             d.qwen_regtest, d.meta, d.p2p_port, d.rpc_port, d.seeds),
            (3, "min", 40, 100, 168, 0, 0x1D00FFFF, 5, 90, 22, 0, 0, b"", 0, False, 0, 0, 10_000, 1, False,
             0, 0, 10_000, 6, False, bytes(32), 0, 0, []))
        written = dict(minimal, version=3, hrp="min", pubkey_prefix=40, script_prefix=100, secret_prefix=168, genesis_nonce=0,
                       pow_limit_bits="0x1d00ffff", target_spacing=5, lwma_window=90, ftl=22, tail_reward=0,
                       tail_halving_interval=0, creator_script="", creator_fee_bps=0, test=False, btc_anchor_height=0,
                       sats_shift=0, sats_min_payment=10_000, btc_confs=1, btc_regtest=False,
                       qwen_anchor_height=0, qwen_shift=0, qwen_min_payment=10_000, qwen_confs=6, qwen_regtest=False,
                       meta="00" * 32, p2p_port=0, rpc_port=0, seeds=[])
        self.assertEqual(self.launch_id(minimal, {}), self.launch_id(written, {}))
        # every one of those few is needed
        self.check_cases([(f"minimal without {k}", with_changes(minimal, {k: DELETE}), "") for k in minimal])
        # the deadline's own default is 720 blocks: enough where the confirmations are fewer
        hour = dict(minimal, qwen_confs=3)
        del hour["settle_deadline"]
        self.assertEqual(D.parse(json.dumps(hour)).settle_deadline, 720)
        self.assertEqual(self.launch_id(hour, {}), self.launch_id(hour, {"settle_deadline": 720}))
        # on a regtest chain the period start is not: regtest never retargets
        regtest = dict(minimal, btc_regtest=True, btc_anchor_header=D.REGTEST_GENESIS_HEADER.hex(),
                       qwen_regtest=True, qwen_anchor_header=D.REGTEST_GENESIS_HEADER.hex())
        del regtest["btc_anchor_period_time"], regtest["qwen_anchor_period_time"], regtest["settle_deadline"]
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
        # the creator's script on Qwencoin is held to the same line (a Qwencoin node relays what a Bitcoin node does)
        self.check_cases([(f"creator_qwen_script {s.hex()}", with_changes(base, {"creator_qwen_script": s.hex()}),
                           True if D._earns_yield(s) else "creator_qwen_script: must be a P2PKH, P2SH or witness-program script")
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
                              lwma_window=1000, settle_deadline=10**6, btc_confs=100, qwen_anchor_height=2**31 - 1,
                              qwen_confs=1008, qwen_shift=128, qwen_num=2**62)
        d.grind_genesis()
        r = self.assert_identity(d)
        self.assertNotIn("params_error", r)
        self.assertEqual(r["genesis"], d.genesis_hash)
        ranges = [[1, 10], [2**31 - 3, 2**31 - 2], [2**31 - 2, 2**31 - 1]]
        t = self.drv(op="tail", json=d.dumps(), ranges=ranges)
        self.assertEqual(t["tail_reward"], [1, 1, 0])
        self.assertEqual(t["tail_minted"], [tail_minted_py(d, a, b) for a, b in ranges])
        for m in ({"tail_halving_interval": 2**31}, {"btc_anchor_height": 2**31}, {"qwen_anchor_height": 2**31},
                  {"qwen_confs": 1009}):
            node_ok, _, python_ok, _, _ = self.both(with_changes(d.to_json(), m))
            self.assertEqual((node_ok, python_ok), (False, False), describe(m))

    def test_curve_lwma_subsidy_graduation(self):
        """Random header chains on the two curves: every block says by bit 9 of its version which curve
        it is on. Per block: difficulty (LWMA, stall relief), the work of each curve, what each curve has
        minted, the subsidy on the block's own curve, graduation by whichever curve sells out first, and
        the rule that the bit may not be set on a graduated parent. The chains break that rule on
        purpose: what the node counts then is defined too (TWIN.md section 3)."""
        from hashfun import yieldstate as S
        rng = random.Random(SEED + 3)
        seen = {"btc": 0, "qwen": 0, "": 0, "bit after graduation": 0, "both curves mined": 0}
        t0 = 12_000_000 * COIN
        pump, top = t0 * D.PUMP_RATIO_G // D.PUMP_RATIO_T, min(t0 - t0 // 1000, D.MAX_MONEY // 2 - 1000 * COIN)
        # (share of the blocks that set the QWEN bit, V0, blocks): the first cases are chosen so that every
        # way a launch can go is in the run whatever the seed: sold out by the BTC curve alone, by the QWEN
        # curve alone, by one of two curves both being mined, and not sold out. The rest are drawn.
        fixed = [(0.0, 20, 150), (1.0, 20, 150), (0.5, 20, 300), (0.15, 10_000, 150), (0.85, 20, 300)]
        for i in range(max(10, N // 4)):
            T = rng.choice([2, 10, 60])
            window = rng.choice([3, 10, 45])
            if i < len(fixed):
                (share, v0, length), limit, g = fixed[i], 0x207FFFFF, pump
            else:
                limit = rng.choice([0x207FFFFF, 0x1F00FFFF])
                # a block at the harder limit is 65537 hashes: the curve is that much longer there
                share, v0 = rng.choice([0.0, 0.15, 0.5, 0.85, 1.0]), rng.choice([1, 50, 10_000]) * (1 if limit == 0x207FFFFF else 30_000)
                length, g = rng.choice([60, 150, 300]), rng.choice([rng.randint(1, top), pump])  # 2 * G and this tail fit MAX_MONEY
            d = launch(rng, pow_limit_bits=limit, target_spacing=T, lwma_window=window,
                       virtual_work=v0, creator_script=b"\x51", creator_fee_bps=100,
                       virtual_tokens=t0, graduation_tokens=g,
                       tail_reward=COIN, tail_halving_interval=rng.choice([7, 100]), genesis_time=1_700_000_000)
            pow_limit = bits_to_target(d.pow_limit_bits)
            times, bits, versions = [d.genesis_time], [d.pow_limit_bits], [1]
            # Mostly honest (bits = model's next), with jitter: zero/negative/huge solvetimes and off-model bits.
            for _ in range(length):
                st = rng.choice([T, T, T // 2 or 1, 0, -T, 6 * T - 1, 6 * T, 7 * T, 1, 3 * T, 40 * T, 2000 * T])
                times.append(max(0, times[-1] + st))
                b = d.next_bits(times[:-1], bits, times[-1])
                if rng.random() < 0.15:
                    b = target_to_bits(rng.randrange(1, pow_limit + 1))
                bits.append(b)
                # any version: only bit 9 says anything about the curve (the others are the base version,
                # the auxpow flag, the chain id; a negative one has every high bit set)
                v = rng.choice([0, 4, 0x100, 0x20000000, 4 | d.chain_id << 16, rng.getrandbits(31), -1, -2**31]) & ~0x200
                versions.append(v | 0x200 if rng.random() < share else v)
            r = self.drv(op="chain", json=d.dumps(), headers=[[t, b, v] for t, b, v in zip(times[1:], bits[1:], versions[1:])])
            self.assertTrue(r["ok"], r)
            works = [work_from_bits(b) for b in bits[1:]]
            wg = d.graduation_work
            wb = wq = 0
            first = None    # the first graduated block: (height, the curve that sold out, what each curve had minted)
            mism, minted_on = [], {"btc": 0, "qwen": 0}
            for h in range(len(times)):
                if h:
                    on_qwen, parent_graduated = bool(versions[h] & 0x200), wb >= wg or wq >= wg
                    quote = "qwen" if on_qwen else "btc"
                    sub = d.subsidy(wb, wq, quote, bits[h], h)
                    if r["subsidy"][h - 1] != sub or r["creator_fee"][h - 1] != d.creator_fee(sub):
                        mism.append(("subsidy", h, r["subsidy"][h - 1], sub))
                    if r["version_ok"][h - 1] != (not (on_qwen and parent_graduated)):
                        mism.append(("version_ok", h, r["version_ok"][h - 1]))
                    seen["bit after graduation"] += on_qwen and parent_graduated
                    after = S.works_after(d, (wb, wq), bits[h], versions[h], h)
                    if not parent_graduated:
                        minted_on[quote] += sub
                    if on_qwen and not parent_graduated:
                        wq += works[h - 1]
                    else:  # the BTC curve, and everything after graduation whatever its bit says
                        wb += works[h - 1]
                    if after != (wb, wq):
                        mism.append(("yieldstate.works_after", h, after, (wb, wq)))
                    if first is None and (wb >= wg or wq >= wg):
                        first = (h, "btc" if wb >= wg else "qwen", (d.curve_supply(wb), d.curve_supply(wq)))
                    want = d.next_bits(times[:h], bits[:h], times[h])
                    if int(r["bits_for_time"][h - 1], 16) != want:
                        mism.append(("bits_for_time", h, r["bits_for_time"][h - 1], f"{want:08x}"))
                nb = d.lwma_next_bits(times[:h + 1], bits[:h + 1])
                if int(r["next_bits"][h], 16) != nb:
                    mism.append(("next_bits", h, r["next_bits"][h], f"{nb:08x}"))
                got = (int(r["rel_work"][h], 16), int(r["work_btc"][h], 16), int(r["work_qwen"][h], 16))
                if got != (wb + wq, wb, wq):
                    mism.append(("work", h, got, (wb + wq, wb, wq)))
                # what a curve has minted stands still from the graduation block on
                minted = first[2] if first else (d.curve_supply(wb), d.curve_supply(wq))
                got = (r["minted_btc"][h], r["minted_qwen"][h], r["curve_supply"][h])
                if got != (minted[0], minted[1], sum(minted)):
                    mism.append(("minted", h, got, minted))
                if not first and d.curve_minted(wb, wq) != sum(minted):
                    mism.append(("Launch.curve_minted", h, d.curve_minted(wb, wq), sum(minted)))
                got = (r["graduated"][h], r["graduation_height"][h], r["graduated_by"][h])
                if got != ((True, first[0], first[1]) if first else (False, -1, "")):
                    mism.append(("graduation", h, got, first))
            self.assertTrue(all(r["permitted"]))
            self.assertEqual(mism[:5], [], f"case {i}: T={T} N={window} V0={d.virtual_work} share={share}")
            seen[first[1] if first else ""] += 1
            seen["both curves mined"] += wq > 0 and any(not v & 0x200 for v in versions[1:(first[0] if first else len(versions))])
            with self.subTest(i=i):
                if first:
                    gh, by, minted = first
                    # The curve that sold out minted exactly G, the other what its own work bought and no
                    # more, and the subsidies up to the graduation block are those two sums, curve by curve.
                    self.assertEqual(minted[0 if by == "btc" else 1], d.graduation_tokens)
                    self.assertLess(minted[1 if by == "btc" else 0], d.graduation_tokens)
                    self.assertEqual((minted_on["btc"], minted_on["qwen"]), minted)
                    self.assertEqual(sum(r["subsidy"][:gh]), sum(minted))
                    self.assertTrue(d.graduation_tokens <= sum(minted) < 2 * d.graduation_tokens)
                    # after it, the tail: whatever a block's bit says
                    self.assertEqual(r["subsidy"][gh:], [d.tail_reward_at(h) for h in range(gh + 1, len(times))])
                    self.assertEqual(int(r["work_qwen"][-1], 16), int(r["work_qwen"][gh], 16))
                else:
                    self.assertEqual((minted_on["btc"], minted_on["qwen"]), (r["minted_btc"][-1], r["minted_qwen"][-1]))
        # the cases have to have reached every way a launch can end
        if os.environ.get("HFDIFF_VERBOSE"):
            print("\nchains:", seen)
        for k in seen:
            self.assertGreater(seen[k], 0, seen)

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

    def header_tree(self, rules, seed):
        """Random header trees under one chain's regtest rules (Bitcoin's, or Qwencoin's: the same tree,
        the same messages under the chain's own name): forks, removals, confirmations, every refusal, and
        the limit on work checks a launch block has (which the node applies to the Qwencoin relay)."""
        from hashfun import yieldmodel as Y
        from hashfun.crypto import sha256d
        from hashfun.ser import header_bytes
        rng = random.Random(seed)
        make = Y.QwenChain if rules == "qwen" else Y.BtcChain
        cache, said, grown = {}, set(), 0

        def mine(prev, time_, bits=0x207FFFFF, valid=True):
            for n in range(1 << 20):
                h = header_bytes(0x20000000, prev, rng.randbytes(32), time_, bits, n)
                if (int.from_bytes(sha256d(h), "little") <= bits_to_target(bits)) == valid:
                    return h

        for case in range(max(6, N // 10)):
            anchor = mine(rng.randbytes(32), 1_700_000_000)
            height = rng.randrange(0, 10**6)
            model = make(anchor, height, 0, True)
            budget = None  # [work checks left], or None: no limit
            ops, expect, tips = [], [], [sha256d(anchor)]
            times = {sha256d(anchor): 1_700_000_000}
            for _ in range(rng.randrange(20, 60)):
                kind = rng.choice(["add"] * 8 + ["bad_bits", "bad_pow", "bad_time", "orphan", "dup", "del", "conf", "conf",
                                                 "budget", "budget"])
                parent = rng.choice(tips[-4:])
                if kind == "budget":
                    n = rng.choice([0, 1, 2, 3, 8, -1, -1, -1, -1])
                    budget = None if n < 0 else [n]
                    ops.append(["budget", n])
                    expect.append("")
                    continue
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
                    h = cache[rng.choice(known)]
                left = None if budget is None else budget[0]
                ok, why = model.accept(h, budget)
                # a work check is spent exactly by a header that got as far as its work
                spent = why in ("", f"{rules} header lacks proof of work", f"{rules} header time is not past the median")
                self.assertEqual(None if budget is None else left - budget[0], None if budget is None else int(spent), why)
                said.add(why)
                ops.append(["add", h.hex()])
                expect.append(why)
                if ok:
                    tips.append(sha256d(h))
                    times[sha256d(h)] = struct.unpack("<I", h[68:72])[0]
                    cache[sha256d(h)] = h
            r = self.drv(op="btc", anchor=anchor.hex(), height=height, period_time=0, regtest=True, rules=rules, ops=ops)
            self.assertEqual(r["results"], expect, case)
            self.assertEqual((r["best"], r["best_height"], r["size"]),
                             (model.best.hex(), model.nodes[model.best].height, len(model.nodes)))
            self.assertEqual(r["budget"], -1 if budget is None else budget[0])
            grown += len(model.nodes) > 5
        self.assertGreater(grown, 2)
        # (the median rule needs eleven ancestors: the chain just below gets there on purpose)
        self.assertEqual(said - {f"{rules} header time is not past the median"}, {"", *(f"{rules} header {x}" for x in (
            "already known", "does not connect", "has wrong difficulty", "lacks proof of work",
            "not looked at: this block has had its share of work checks"))})
        # Regression: Bitcoin timestamps are not monotonic. Right after the anchor the median of
        # 11 cannot be known, so a header no later than the anchor must still connect; once 11
        # ancestors exist the rule applies.
        anchor = mine(rng.randbytes(32), 1_700_000_000)
        model, ops, prev = make(anchor, 5, 0, True), [], sha256d(anchor)
        for i in range(14):
            h = mine(prev, 1_700_000_000 - (i % 3))
            ops.append(["add", h.hex()])
            ok, why = model.accept(h)
            self.assertEqual(ok, i < 10, (i, why))
            if not ok:
                break
            prev = sha256d(h)
        r = self.drv(op="btc", anchor=anchor.hex(), height=5, period_time=0, regtest=True, rules=rules, ops=ops)
        self.assertEqual(r["results"], [""] * 10 + [f"{rules} header time is not past the median"])
        self.assertEqual(r["best_height"], 15)
        # The limit as a launch block meets it: eight headers have their work checked, the ninth and
        # everything after it are not looked at, and a header refused before its work costs nothing.
        anchor = mine(rng.randbytes(32), 1_700_000_000)
        model, chain, prev = make(anchor, 0, 0, True), [], sha256d(anchor)
        for i in range(12):
            chain.append(mine(prev, 1_700_000_600 + 600 * i))
            prev = sha256d(chain[-1])
        budget = [8]
        order = [chain[1], mine(sha256d(anchor), 1_700_000_600, bits=0x207FFFFE)] + chain[:9] + [chain[0]] + chain[9:]
        expect = [model.accept(h, budget)[1] for h in order]
        self.assertEqual(expect, [f"{rules} header does not connect", f"{rules} header has wrong difficulty"] + [""] * 8
                         + [f"{rules} header not looked at: this block has had its share of work checks",
                            f"{rules} header already known"]
                         + [f"{rules} header does not connect"] * 3)
        r = self.drv(op="btc", anchor=anchor.hex(), height=0, period_time=0, regtest=True, rules=rules,
                     ops=[["budget", 8]] + [["add", h.hex()] for h in order])
        self.assertEqual((r["results"][1:], r["budget"], r["best_height"]), (expect, 0, 8))
        # Difficulty bits that are no target (negative, overflowing, zero) are refused before any work
        # is looked at: such a header costs nothing either. (Only an anchor no parser accepts gets a tree
        # there; the two implementations agree all the same.)
        for bits in (0x1D80FFFF, 0x2200FFFF, 0x1D000000, 0):
            anchor = header_bytes(1, bytes(32), bytes(32), 1_700_000_000, bits, 0)
            child = header_bytes(1, sha256d(anchor), bytes(32), 1_700_000_600, bits, 7)
            budget = [3]
            why = make(anchor, 5, 1_699_990_000, False).accept(child, budget)[1]
            self.assertEqual((why, budget), (f"{rules} header lacks proof of work", [3]), hex(bits))
            r = self.drv(op="btc", anchor=anchor.hex(), height=5, period_time=1_699_990_000, regtest=False, rules=rules,
                         ops=[["budget", 3], ["add", child.hex()]])
            self.assertEqual((r["results"], r["budget"]), (["", why], 3), hex(bits))

    def test_btc_header_chain(self):
        self.header_tree("btc", SEED + 9)

    def test_qwen_regtest_header_chain(self):
        self.header_tree("qwen", SEED + 12)

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

    def test_qwen_retarget(self):
        """Qwencoin's retarget: Bitcoin's schedule and clamp, its own limit (0x2000ffff, where target *
        timespan no longer fits 256 bits, so the quotient is taken without forming the product) and the
        cap at that limit. Difficulty is checked before work, so a header nobody mined shows which
        bits each side expects."""
        from hashfun import yieldmodel as Y
        from hashfun.ser import header_bytes
        from hashfun.crypto import sha256d
        rng = random.Random(SEED + 13)
        T, LIMIT = 1209600, bits_to_target(0x2000FFFF)
        # the chain's own three retargets, each a full step down
        qh, qstarts = qwen_headers()
        for boundary, start in ((2016, qstarts[0]), (4032, qstarts[2016]), (6048, qstarts[4032])):
            chain = Y.QwenChain(qh[boundary - 1], boundary - 1, start, False)
            self.assertEqual(chain.expected_bits(chain.nodes[chain.anchor]), struct.unpack("<I", qh[boundary][72:76])[0])
        seen = {"capped": 0, "product does not fit": 0, "boundary": 0, "inside": 0}
        for i in range(max(150, N * 3)):
            bits = rng.choice([0x2000FFFF, 0x2000FFFF, 0x1F3FFFC0, 0x1F0FFFF0, 0x1F03FFFC, 0x1E7FFFFF, 0x1D00FFFF, 0x2000ABCD])
            t1 = rng.randrange(1_750_000_000, 1_900_000_000)
            span = rng.choice([1, T, T // 4, T // 4 - 1, 4 * T, 4 * T + 1, rng.randrange(1, 6_000_000), -500, T + 1, 2 * T])
            t0 = t1 - span
            boundary = rng.random() < 0.7
            height = 2016 * rng.randrange(1, 500) - (1 if boundary else rng.randrange(2, 2016))
            anchor = header_bytes(1, bytes(32), bytes(32), t1, bits, 0)
            chain = Y.QwenChain(anchor, height, t0 & 0xFFFFFFFF, False)
            want = chain.expected_bits(chain.nodes[chain.anchor])
            target, clamped = bits_to_target(bits), min(max(span, T // 4), 4 * T)
            if boundary:
                self.assertEqual(want, target_to_bits(min(target * clamped // T, LIMIT)), (hex(bits), span))
                seen["capped"] += target * clamped // T > LIMIT
                seen["product does not fit"] += target * clamped >= 2**256
            else:
                self.assertEqual(want, bits)
            seen["boundary" if boundary else "inside"] += 1
            ops = [["add", header_bytes(1, sha256d(anchor), rng.randbytes(32), t1 + 600, cand, rng.randrange(2**32)).hex()]
                   for cand in (want, want ^ 1, bits)]
            r = self.drv(op="btc", anchor=anchor.hex(), height=height, period_time=t0 & 0xFFFFFFFF, regtest=False,
                         rules="qwen", ops=ops)
            py = [Y.QwenChain(anchor, height, t0 & 0xFFFFFFFF, False).accept(bytes.fromhex(o[1]))[1] for o in ops]
            # past the difficulty check a header's work is a pass through the table: this model has none, and
            # whether the driver has depends on what ran before, so "got as far as its work" is all that is compared
            at_work = {"qwen header cannot be checked: Qwencoin's work table is not loaded": "at its work",
                       "qwen header lacks proof of work": "at its work", "": "at its work"}
            self.assertEqual([at_work.get(x, x) for x in r["results"]], [at_work.get(x, x) for x in py], (i, hex(bits), span, height))
            self.assertEqual(at_work.get(r["results"][0]), "at its work")
            self.assertEqual(r["results"][1], "qwen header has wrong difficulty")
        for k, v in seen.items():
            self.assertGreater(v, 5, seen)

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

    # ------------------------------------------------------------ Qwencoin's own rules, on its real chain
    def qwen_vectors(self):
        """({height: header}, {header: work value}, {period's first height: its time}) of the real chain."""
        with open(VECTORS) as f:
            data = json.load(f)
        return ({x["height"]: bytes.fromhex(x["header"]) for x in data["headers"]},
                {bytes.fromhex(x["header"]): int(x["work"], 16) for x in data["headers"]},
                {int(k): v for k, v in data["period_starts"].items()}, {x["height"]: x["hash"] for x in data["headers"]})

    def need_table(self):
        if not os.path.exists(TABLE):
            self.skipTest(f"Qwencoin's work table is not at {TABLE} (hashfun qwork fetch, or set QWORK_TABLE)")
        try:  # the Python pass through the table (hashfun.qwork.Table) is the one place numpy is used
            import numpy  # noqa: F401
        except ImportError:
            self.skipTest("the Python pass through Qwencoin's work table needs numpy (pip install numpy)")

    def test_qwork_values(self):
        """A Qwencoin header's proof of work is a pass through the chain's table, not its hash. Three
        implementations of that pass on real headers: the node's (src/crypto/qwork.cpp, Qwencoin's own
        file), the values the Qwencoin project's reference gave (the vectors), and hashfun/qwork.py."""
        self.need_table()
        from hashfun import qwork
        h, work, _starts, hashes = self.qwen_vectors()
        heights = [0, 1, 2, 5, 14, 2015, 2016, 2017, 4031, 4032, 6047, 6048, 6115]
        r = self.drv(op="qwork", table=TABLE, headers=[h[x].hex() for x in heights])
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["hashes"], [hashes[x] for x in heights])
        self.assertEqual([int(v, 16) for v in r["values"]], [work[h[x]] for x in heights])
        self.assertEqual(r["meets"], [True] * len(heights))
        for x, value in zip(heights, r["values"]):  # each meets its own bits, and not by its hash
            target = bits_to_target(struct.unpack("<I", h[x][72:76])[0])
            self.assertLessEqual(int(value, 16), target)
        # another nonce is another pass: the node's value and the Python pass agree on headers nobody mined
        table = qwork.Table(TABLE)
        forged = [h[x][:76] + struct.pack("<I", n) for x, n in ((1, 0), (2016, 0xFFFFFFFF), (6115, 12345))]
        r = self.drv(op="qwork", table=TABLE, headers=[x.hex() for x in forged] + [h[5].hex()])
        self.assertEqual([int(v, 16) for v in r["values"]], [table.work_value(x) for x in forged] + [work[h[5]]])
        self.assertEqual(table.work_value(h[5]), work[h[5]])
        self.assertEqual(r["meets"][:3], [int(v, 16) <= bits_to_target(struct.unpack("<I", x[72:76])[0])
                                          for v, x in zip(r["values"], forged)])
        self.assertIn(False, r["meets"][:3])
        # what is not the chain's table is not used
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            wrong = os.path.join(tmp, "qwork.bin")
            with open(wrong, "wb") as f:
                f.write(b"QWRK1\0\0\0" + bytes(1000))
            other = Driver(os.environ["HFDIFF"])
            try:
                for path in (wrong, os.path.join(tmp, "nothing-here.bin")):
                    r = other(op="qwork", table=path, headers=[h[1].hex()])
                    self.assertFalse(r["ok"], r)
                    self.assertTrue(r["error"], r)
                    self.assertIsNotNone(qwork.quick_problem(path))
            finally:
                other.close()

    def test_qwen_mainnet_rules_against_the_real_chain(self):
        """Headers of the live Qwencoin chain around its genesis and its first three retargets, through
        the node's Qwencoin tree with the real table and through the model with the reference values:
        both follow the chain across every retarget from anchors before, at and after a boundary, both
        refuse any other difficulty, and a header with another nonce has no work."""
        self.need_table()
        from hashfun import qwork, yieldmodel as Y
        from hashfun.crypto import sha256d
        h, work, starts, _hashes = self.qwen_vectors()
        table = qwork.Table(TABLE)

        def value(header):  # the reference's value where there is one, the Python pass otherwise
            return work[header] if header in work else table.work_value(header)

        def run(anchor, ops, period=None, budget=None, drv=None, with_table=True):
            start = starts[anchor - anchor % 2016] if period is None else period
            model, left, expect = Y.QwenChain(h[anchor], anchor, start, False, value), None, []
            for op in ops:
                if op[0] == "budget":
                    left = None if op[1] < 0 else [op[1]]
                    expect.append("")
                else:
                    expect.append(model.accept(bytes.fromhex(op[1]), left)[1])
            r = (drv or self.drv)(op="btc", anchor=h[anchor].hex(), height=anchor, period_time=start, regtest=False,
                                  rules="qwen", ops=ops, **({"table": TABLE} if with_table else {}))
            self.assertEqual((r["best"], r["best_height"], r["size"], r["budget"]),
                             (model.best.hex(), model.nodes[model.best].height, len(model.nodes), -1 if left is None else left[0]))
            return r["results"], expect, model

        for anchor, last in ((0, 14), (2010, 2030), (2016, 2024), (4025, 4040), (6040, 6056)):
            got, expect, model = run(anchor, [["add", h[x].hex()] for x in range(anchor + 1, last + 1)])
            self.assertEqual((got, expect), ([""] * (last - anchor),) * 2, anchor)
            self.assertEqual((model.best, model.confirmations(sha256d(h[anchor + 1]))), (sha256d(h[last]), last - anchor))
        # at a retarget: the previous period's bits, and any other but the right ones, are refused; then the
        # real header is taken, once
        for boundary in (2016, 4032, 6048):
            real = h[boundary]
            ops = [["add", h[x].hex()] for x in range(boundary - 3, boundary)]
            for bits in (h[boundary - 1][72:76], struct.pack("<I", struct.unpack("<I", real[72:76])[0] + 1), b"\xff\xff\x00\x20"):
                ops.append(["add", (real[:72] + bits + real[76:]).hex()])
            ops += [["add", real.hex()], ["add", real.hex()]]
            got, expect, _ = run(boundary - 4, ops)
            self.assertEqual(got, expect)
            self.assertEqual(got, [""] * 3 + ["qwen header has wrong difficulty"] * 3 + ["", "qwen header already known"])
        # a wrong period start in the launch is found out at the retarget, by both
        got, expect, _ = run(4025, [["add", h[x].hex()] for x in range(4026, 4033)], period=starts[2016] - 2_000_000)
        self.assertEqual((got, expect), ([""] * 6 + ["qwen header has wrong difficulty"],) * 2)
        # work is the pass: the same header with another nonce has none (and costs its check all the same);
        # a launch block gets eight checks
        nobody = h[3][:76] + b"\xff\xff\xff\xff"
        ops = [["budget", 8], ["add", h[2].hex()], ["add", h[1].hex()], ["add", h[2].hex()], ["add", nobody.hex()],
               *[["add", h[x].hex()] for x in range(3, 12)]]
        got, expect, _ = run(0, ops)
        self.assertEqual(got, expect)
        self.assertEqual(got, ["", "qwen header does not connect", "", "", "qwen header lacks proof of work"] + [""] * 5
                         + ["qwen header not looked at: this block has had its share of work checks"]
                         + ["qwen header does not connect"] * 3)
        # without the table no header of the real chain can be checked: a node that has none says so
        # (hashfund does not start in that state; the model's default work function is that state)
        bare = Driver(os.environ["HFDIFF"])
        try:
            r = bare(op="btc", anchor=h[0].hex(), height=0, period_time=starts[0], regtest=False, rules="qwen",
                     ops=[["budget", 2], ["add", h[1].hex()], ["add", h[2].hex()]])
        finally:
            bare.close()
        model, left = Y.QwenChain(h[0], 0, starts[0], False), [2]
        expect = [model.accept(h[1], left)[1], model.accept(h[2], left)[1]]
        self.assertEqual(r["results"][1:], expect)
        self.assertEqual(expect, ["qwen header cannot be checked: Qwencoin's work table is not loaded", "qwen header does not connect"])
        self.assertEqual((r["budget"], left), (1, [1]))

    def test_qwen_main_rules_on_made_up_chains(self):
        """Qwencoin's main-network rules where its real chain has not been yet, with no table: for one
        request the node takes a header's own hash as its work value ("work":"hash"), as the model does
        with work_value=sha256d_work, and the headers here are mined that way. Retargets in every
        direction, the two timestamp rules at the edges of a difficulty period at their boundary and one
        second past it, and the limit on work checks."""
        from hashfun import yieldmodel as Y
        from hashfun.crypto import sha256d
        from hashfun.ser import header_bytes
        rng = random.Random(SEED + 15)
        T, LIMIT = 1209600, 0x2000FFFF
        opens = "qwen header opens a difficulty period too long before its parent's time"
        closes = "qwen header closes a difficulty period before the time the period opened"

        def mine(prev, time_, bits):
            target, root = bits_to_target(bits), rng.randbytes(32)
            for n in range(1 << 32):
                h = header_bytes(0x20000000, sha256d(prev), root, time_, bits, n)
                if int.from_bytes(sha256d(h), "little") <= target:
                    return h

        def both(anchor, height, period, headers, budget=None):
            """The same headers, in order, to the model and to the node: what each says of each one."""
            model, left = Y.QwenChain(anchor, height, period, False, Y.sha256d_work), None if budget is None else [budget]
            expect = [model.accept(h, left)[1] for h in headers]
            r = self.drv(op="btc", anchor=anchor.hex(), height=height, period_time=period, regtest=False, rules="qwen",
                         work="hash", ops=([["budget", budget]] if budget is not None else []) + [["add", h.hex()] for h in headers])
            got = r["results"][1:] if budget is not None else r["results"]
            self.assertEqual(got, expect)
            self.assertEqual((r["best"], r["best_height"], r["size"], r["budget"]),
                             (model.best.hex(), model.nodes[model.best].height, len(model.nodes), -1 if left is None else left[0]))
            return expect, model

        t0 = 1_800_000_000
        # ---- retargets: a quarter, the same, three times, and four times capped at the limit
        for bits, span, want in ((LIMIT, T // 4, 0x1F3FFFC0), (LIMIT, 1, 0x1F3FFFC0), (LIMIT, T, LIMIT), (LIMIT, 9 * T, LIMIT),
                                 (0x1F3FFFC0, 3 * T, None), (0x1F3FFFC0, 4 * T, LIMIT), (0x1F3FFFC0, T + 1, None)):
            anchor = header_bytes(0x20000000, rng.randbytes(32), rng.randbytes(32), t0, bits, 0)   # block 2014 of its period
            period = t0 + 600 - span                                                             # so that block 2015 closes it after `span`
            last = mine(anchor, t0 + 600, bits)
            model = Y.QwenChain(anchor, 2014, period, False, Y.sha256d_work)
            self.assertTrue(model.accept(last)[0])
            expected = model.expected_bits(model.nodes[sha256d(last)])
            if want is not None:
                self.assertEqual(expected, want, (hex(bits), span))
            self.assertEqual(expected, target_to_bits(min(bits_to_target(bits) * min(max(span, T // 4), 4 * T) // T, bits_to_target(LIMIT))))
            first = mine(last, t0 + 1200, expected)
            wrong = header_bytes(0x20000000, sha256d(last), rng.randbytes(32), t0 + 1200, expected ^ 1, 0)
            expect, _ = both(anchor, 2014, period, [last, wrong, first, mine(first, t0 + 1800, expected)])
            self.assertEqual(expect, ["", "qwen header has wrong difficulty", "", ""], (hex(bits), span))
        # ---- the first block of a period: ten minutes before its parent, and not a second more
        anchor = header_bytes(0x20000000, rng.randbytes(32), rng.randbytes(32), t0, LIMIT, 0)   # block 2015: it closes its period
        period = t0 - 5 * T                                                                  # a slow period: the limit stays
        for back, want in ((601, opens), (600, ""), (0, ""), (-600, "")):
            expect, _ = both(anchor, 2015, period, [mine(anchor, t0 - back, LIMIT)])
            self.assertEqual(expect, [want], back)
        # ---- the last block of a period: the time of the period's first block, and not a second earlier.
        # Above an anchor inside the period that time is the launch file's qwen_anchor_period_time.
        anchor = header_bytes(0x20000000, rng.randbytes(32), rng.randbytes(32), t0, LIMIT, 0)   # block 2014
        for stamp, want in ((t0 + 4999, closes), (t0 + 5000, ""), (t0 + 5001, "")):
            expect, _ = both(anchor, 2014, t0 + 5000, [mine(anchor, stamp, LIMIT)])
            self.assertEqual(expect, [want], stamp - t0)
        # neither rule is asked on the block next to the edge
        expect, _ = both(anchor, 2013, t0 + 5000, [mine(anchor, t0 - 9000, LIMIT)])
        self.assertEqual(expect, [""])
        # ---- ... and once the tree holds the period's first block it is that block's own time: a first
        # block stamped far ahead, a period that goes on from the old times (the median of eleven does not
        # move for one block), and a last block that has to reach the first one's time all the same.
        anchor = header_bytes(0x20000000, rng.randbytes(32), rng.randbytes(32), t0, LIMIT, 0)   # block 2015
        ahead = t0 + 3_000_000
        chain = [mine(anchor, ahead, LIMIT)]                                                    # 2016
        for k in range(1, 2015):                                                                # 2017 .. 4030
            chain.append(mine(chain[-1], t0 + 600 * k, LIMIT))
        on_schedule, a_second_short, in_time = (mine(chain[-1], stamp, LIMIT) for stamp in (t0 + 600 * 2015, ahead - 1, ahead))
        expect, model = both(anchor, 2015, period, chain + [on_schedule, a_second_short, in_time])
        self.assertEqual(expect, [""] * 2015 + [closes, closes, ""])
        self.assertEqual((model.nodes[model.best].height, model.nodes[model.best].period_time), (4031, ahead))
        # the period it closed lasted no time at all by its own stamps: the next one is four times as hard
        nxt = model.expected_bits(model.nodes[model.best])
        self.assertEqual(nxt, 0x1F3FFFC0)
        expect, _ = both(anchor, 2015, period, chain + [in_time, mine(in_time, ahead - 600, nxt), mine(in_time, ahead - 601, nxt)])
        self.assertEqual(expect[-2:], ["", opens])
        # ---- eight work checks to a launch block, under these rules too; a header refused for its time
        # has had its work looked at and costs one
        anchor = header_bytes(0x20000000, rng.randbytes(32), rng.randbytes(32), t0, LIMIT, 0)   # block 2010
        chain = [mine(anchor, t0 + 600, LIMIT)]
        for k in range(2, 5):
            chain.append(mine(chain[-1], t0 + 600 * k, LIMIT))                                  # 2011 .. 2014
        early = mine(chain[-1], t0 - 1, LIMIT)                                                  # 2015, before the period opened
        rest = [mine(chain[-1], t0 + 3000, LIMIT)]                                              # 2015
        for k in range(6, 12):                                                                  # 2016 ..: the next period,
            rest.append(mine(rest[-1], t0 + 600 * k, 0x1F3FFFC0))                               # four times as hard
        expect, _ = both(anchor, 2010, t0, chain + [early] + rest, budget=8)
        self.assertEqual(expect, [""] * 4 + [closes] + [""] * 3
                         + ["qwen header not looked at: this block has had its share of work checks"]
                         + ["qwen header does not connect"] * 3)
        # without the stand-in (and without the table) the node can check none of them, and says so
        bare = Driver(os.environ["HFDIFF"])
        try:
            r = bare(op="btc", anchor=anchor.hex(), height=2010, period_time=t0, regtest=False, rules="qwen",
                     ops=[["add", chain[0].hex()]])
            self.assertEqual(r["results"], ["qwen header cannot be checked: Qwencoin's work table is not loaded"])
            r = bare(op="btc", anchor=anchor.hex(), height=2010, period_time=t0, regtest=False, rules="qwen", work="hash",
                     ops=[["add", chain[0].hex()]])
            self.assertEqual(r["results"], [""])
            r = bare(op="btc", anchor=anchor.hex(), height=2010, period_time=t0, regtest=False, rules="qwen",
                     ops=[["add", chain[0].hex()]])                    # the stand-in ended with its request
            self.assertEqual(r["results"], ["qwen header cannot be checked: Qwencoin's work table is not loaded"])
        finally:
            bare.close()

    def test_node_self_test(self):
        """The node's own checks of rule set 3 (contrib/hashfun/difftest/selftest.cpp: curves, relays,
        state, the table, the real headers), run from here so that one command shows both. Without the
        table its table checks are skipped, and said to be."""
        have = os.path.exists(TABLE)
        r = self.drv(op="selftest", vectors=VECTORS, **({"table": TABLE} if have else {}))
        failed = [(c["name"], c["detail"]) for c in r["checks"] if not c["ok"]]
        self.assertEqual(failed, [])
        self.assertTrue(r["ok"], r)
        self.assertGreaterEqual(len(r["checks"]), 20)
        skipped = [c["name"] for c in r["checks"] if c["skipped"]]
        if have:
            self.assertEqual(skipped, [])
        else:
            self.assertTrue(all("table" in name or "vectors" in name or "real" in name for name in skipped), skipped)
        if os.environ.get("HFDIFF_VERBOSE"):
            print("\nself test:", len(r["checks"]), "checks,", len(skipped), "skipped")

    # ------------------------------------------------------------ the two legs' state, block by block
    def state_run(self, seed, steps, main_qwen=False):
        """One random launch chain through the node's state (src/launchyieldstate.cpp) and through the
        model (hashfun/yieldstate.py), from the same bytes: whole serialized blocks on both curves, with
        coins made, spent and redirected, headers of a regtest Bitcoin and a regtest Qwencoin relayed
        (more than a block may take, out of order, in the coinbase and where they do not count, after
        reorganizations of those chains), payments on both chains proven right and wrong, merge-mined
        blocks, reorganizations of the launch chain, the launch selling out, the legs ending, and a walk
        back from past the end. After every step the node says everything it knows (every obligation
        with its draw, both relays, the counts) and it has to be what the model says.

        main_qwen: the QWEN leg follows a made-up Qwencoin under its main-network rules instead (anchored
        late in a difficulty period, so the relay crosses the period's edge and a retarget), with a
        header's own hash for its work value on both sides (the driver's "work":"hash")."""
        from hashfun import yieldmodel as Y, yieldstate as S
        from hashfun.auxpow import AuxTree, serialize_auxpow
        from hashfun.crypto import sha256d
        from hashfun.ser import Tx, TxIn, TxOut, header_bytes, merkle_branch, merkle_root, push, push_int, varint
        from hashfun.tests.test_yieldstate import BtcSim, H, person
        rng = random.Random(seed)
        if main_qwen:
            sims = (BtcSim(f"btc {seed}"), QwenMainSim(f"qwen {seed}", 2016 * rng.randrange(1, 50) + rng.randrange(1850, 1950)))
            # a minute a block: the 110 blocks of the deadline are long enough for the leg's confirmations
            qleg = dict(qwen_regtest=False, qwen_anchor_header=sims[1].anchor, qwen_anchor_height=sims[1].anchor_height,
                        qwen_anchor_period_time=sims[1].period_time, target_spacing=60)
        else:
            sims = (BtcSim(f"btc {seed}"), BtcSim(f"qwen {seed}"))
            qleg = dict(qwen_regtest=True, qwen_anchor_header=sims[1].anchor, qwen_anchor_height=rng.choice([0, 6000]),
                        qwen_anchor_period_time=0)
        t0 = 12_000_000 * COIN
        # A block's work is what its bits say and nothing is validated, so the blocks here pick their own:
        # 2, 256, 65537 or 2^24 hashes. At 1/16 sat and 3/32 qwen-sat a hash that is a block that owes
        # nothing, one far below the minimum payment, one near it and one far above it. V0 is so large
        # that only the block made to sell a curve out (2^48 hashes) does.
        d = launch(rng, test=True, btc_regtest=True, pow_limit_bits=0x207FFFFF, virtual_work=2**36,
                   virtual_tokens=t0, graduation_tokens=t0 * D.PUMP_RATIO_G // D.PUMP_RATIO_T, tail_reward=COIN,
                   tail_halving_interval=1000, btc_anchor_header=sims[0].anchor, btc_anchor_height=rng.choice([0, 800_000]),
                   btc_anchor_period_time=0, sats_num=1, sats_shift=4, sats_min_payment=10_000, qwen_num=3, qwen_shift=5,
                   qwen_min_payment=rng.choice([6_000, 10_000]), settle_deadline=110, btc_confs=rng.choice([1, 2]),
                   qwen_confs=rng.choice([1, 2, 3]), **qleg)
        bits_of = [0x207FFFFF, 0x2000FFFF, 0x1F00FFFF, 0x1F00FFFF, 0x1E00FFFF, 0x1E00FFFF]
        self.assertEqual([work_from_bits(b) for b in (0x207FFFFF, 0x2000FFFF, 0x1F00FFFF, 0x1E00FFFF)], [2, 256, 65537, 2**24 + 256])
        self.assertGreater(work_from_bits(0x1B00FFFF), d.graduation_work)
        self.assertGreater(d.graduation_work, 2**24 * 2 * steps)
        params = S.Params.from_launch(d)
        state = S.State(params, S.HeaderRelay.from_launch(d),
                        S.HeaderRelay.qwen_from_launch(d, Y.sha256d_work if main_qwen else Y.no_qwork))
        genesis, w0 = S.block_from_raw(d, d.genesis_header() + varint(1) + d.genesis_coinbase().serialize(), 0, (0, 0))
        state.connect(genesis)
        blocks, works = [genesis], [w0]
        people = [person(40 + k) for k in range(5)]
        proofs = []  # every proof output ever made, also the wrong ones: they ride again after a reorg
        out_steps, views = [], []
        stats = {"settled_btc": 0, "settled_qwen": 0, "wrong": 0, "wrong_chain": 0, "reorgs": 0, "relay_reorgs": 0, "kills": 0,
                 "holder_draws": 0, "past_the_end": 0, "reopened": 0, "pass_limit": 0, "merge_mined_seeds": 0, "curve_btc": 0,
                 "curve_qwen": 0, "released_at_draw": 0, "in_another_tx": 0, "qwen_headers_outside_the_coinbase": 0,
                 "qwen_headers": 0}
        curve_until, walked_back = steps // 5, False  # the legs end at curve_until + 110, inside the run

        def relay_view(relay):
            c = relay.chain
            return {"best": c.best[::-1].hex(), "height": c.nodes[c.best].height, "headers": len(c.nodes)}

        def view():
            count = {}
            for q, name in ((S.BTC, "btc"), (S.QWEN, "qwen")):
                on = [h for h, i in enumerate(state.info) if i.curve and i.quote == q]
                count[name] = [len(on), on[-1] if on else 0]
            obligations = []
            for h in range(1, state.height() + 1):
                o = state.obligation(h)
                if o["draw_known"]:
                    o["seed"] = state.info[h].seed.hex()
                obligations.append(o)
            return {"height": state.height(), "closed": state.closed(), "earning": state.earning(), "coins": len(state.coins),
                    "btc": relay_view(state.relay), "qwen": relay_view(state.qrelay), "count": count,
                    "graduated": d.graduated(*works[-1]), "obligations": obligations}

        def dump():
            out_steps.append(["dump"])
            views.append(view())

        def make_block():
            h = len(blocks)
            graduated = d.graduated(*works[-1])
            on_qwen = not graduated and rng.random() < 0.5   # after graduation the bit is clear, as the rules have it
            if h == curve_until:
                bits = 0x1B00FFFF                              # the block that sells its curve out
            elif h <= 8:
                bits = rng.choice(bits_of[2:])                 # the first blocks all owe: the first draws find nobody holding
            else:
                bits = rng.choice(bits_of)
            merge_mined = rng.random() < (0.3 if graduated else 0.1)
            version = 4 | d.chain_id << 16 | (0x200 if on_qwen else 0) | (0x100 if merge_mined else 0)
            outs = [TxOut(rng.choice([0, 1, 50, 500, 12_345_678]), rng.choice(people)), TxOut(rng.choice([0, 3]), people[0])]
            if rng.random() < 0.15:  # a redirect of the coinbase's first coin, or a broken one
                outs.append(TxOut(0, Y.yield_tag_script(rng.choice([person(77), b"\x51", b""]))))
            special = []
            # relay: the Bitcoin headers the launch has not seen, sometimes
            known = set(state.relay.chain.nodes)
            missing = [x for x in sims[0].chain[1:] if sha256d(x) not in known]
            if missing and rng.random() < 0.8:
                special.append(TxOut(0, Y.op_return(b"HFH1" + b"".join(missing[:rng.randrange(1, 6)]))))
            # ... and the Qwencoin headers, in one or two outputs, now and then more than a block may take,
            # some of them known already, some not connecting yet
            qknown = set(state.qrelay.chain.nodes)
            qmissing = [x for x in sims[1].chain[1:] if sha256d(x) not in qknown]
            offered = 0
            if qmissing and rng.random() < 0.8:
                lead = [x for x in sims[1].chain[1:] if sha256d(x) in qknown][-rng.randrange(0, 3) or len(sims[1].chain):]
                batch = lead + qmissing[:rng.randrange(1, 14)]
                offered = len(batch) - len(lead)
                if rng.random() < 0.2 and len(batch) > 2:
                    batch = batch[1:] + batch[:1]  # the first header last: the ones after it may not connect before it
                cut = rng.randrange(0, len(batch) + 1) if rng.random() < 0.4 else len(batch)
                for part in (batch[:cut], batch[cut:]):
                    if part:
                        special.append(TxOut(0, Y.op_return(b"HFH2" + b"".join(part))))
            special += [TxOut(0, script) for script in rng.sample(proofs, min(len(proofs), rng.randrange(0, 4)))]
            # A Bitcoin relay or a proof counts in any transaction of the block, in block order. Qwencoin
            # headers count in the coinbase only: put elsewhere they are not looked at, and cost nothing.
            elsewhere = [o for o in special if rng.random() < 0.3]
            outs += [o for o in special if all(o is not e for e in elsewhere)]
            stats["qwen_headers_outside_the_coinbase"] += any(Y.tagged_return(o.script_pubkey, b"HFH2") is not None for o in elsewhere)
            txs = [Tx(version=2, vin=[TxIn(bytes(32), 0xFFFFFFFF, push_int(h) + push(rng.randbytes(4)))], vout=outs)]
            live = [(c.txid, c.vout) for c in state.coins if c.live]
            for _ in range(rng.randrange(0, 4) if h > 8 else 0):  # (the transactions here make coins from nothing)
                spends = rng.sample(live, min(len(live), rng.randrange(0, 3)))
                live = [x for x in live if x not in spends]
                if rng.random() < 0.1 or not spends:
                    spends.append((rng.randbytes(32), 0))  # an outpoint that is no coin: kills nothing
                vin = [TxIn(txid, n, b"", 0xFFFFFFFD, [rng.randbytes(72), rng.randbytes(33)] if rng.random() < 0.5 else [])
                       for txid, n in spends]
                vout = [TxOut(rng.choice([0, 1, 10, 100, 1000, 10**9]), rng.choice(people + [b"\x51", b"\x6a\x01\x00"]))
                        for _ in range(rng.randrange(1, 4))]
                txs.append(Tx(version=2, vin=vin, vout=vout))
            if elsewhere:
                txs.insert(rng.randrange(1, len(txs) + 1), Tx(version=2, vin=[TxIn(rng.randbytes(32), 1)], vout=elsewhere))
                stats["in_another_tx"] += 1
            header = header_bytes(version, blocks[-1].hash, merkle_root([t.txid() for t in txs]),
                                  1_700_000_000 + 60 * h + rng.randrange(60), bits, rng.getrandbits(32))
            aux = b""
            if merge_mined:
                tree = AuxTree({d.chain_id: sha256d(header)})
                pcb = Tx(version=1, vin=[TxIn(bytes(32), 0xFFFFFFFF, push_int(h) + tree.commitment_push())], vout=[TxOut(0, b"\x6a")])
                aux = serialize_auxpow(pcb, [], [], 0, header_bytes(1, rng.randbytes(32), pcb.txid(), 1_700_000_000, 0x207FFFFF,
                                                                   rng.getrandbits(32)))
            return header + aux + varint(len(txs)) + b"".join(t.serialize() for t in txs), offered

        def pay_someone():
            quote = rng.choice([S.BTC, S.QWEN])
            due = [h for h, i in enumerate(state.info) if i.draw_known and i.pay > 0 and not i.settled and i.quote == quote]
            if not due:
                return
            pick = rng.sample(due, min(len(due), rng.randrange(1, 4)))
            wrong = rng.choice([None, None, None, None, None, "script", "short", "tag", "candidate", "two lists", "chain", "proof tag"])
            pays = [(state.info[h].pay_script, state.info[h].pay, Y.pay_tag(d.id, state.info[h].hash)) for h in pick]
            lists, candidate = None, 0
            if wrong == "script":
                pays[0] = (person(99), pays[0][1], pays[0][2])
            elif wrong == "short":
                pays[0] = (pays[0][0], pays[0][1] - 1, pays[0][2])
            elif wrong == "tag":
                pays[0] = (pays[0][0], pays[0][1], H("other")[:20])
            elif wrong == "candidate":
                candidate = 1
            elif wrong == "two lists":  # the real tags only in a second list
                lists = [[H("decoy", k)[:20] for k in range(len(pays))], [t for _, _, t in pays]]
            outs = [TxOut(amount, script) for script, amount, _ in pays]
            for tags in ([[t for _, _, t in pays]] if lists is None else lists):
                outs.append(TxOut(0, Y.payment_outputs_tag(tags)))
            raw = Tx(version=2, vin=[TxIn(rng.randbytes(32), 0)], vout=outs).serialize(witness=False)
            # "chain": everything right, paid on the other chain (and proven as a payment there).
            # "proof tag": paid on the right chain, proven with the other chain's tag.
            paid_on = 1 - quote if wrong == "chain" else quote
            said = 1 - paid_on if wrong == "proof tag" else paid_on
            block = sims[paid_on].mine([sha256d(raw)])
            txids = sims[paid_on].roots[block]
            for vout, h in enumerate(pick):
                proof = Y.PaymentProof(h, block, 1, merkle_branch(txids, 1), vout, candidate, raw)
                proofs.append(Y.op_return(proof.payload(S.QUOTE_NAMES[said])))
            stats["wrong"] += wrong is not None
            stats["wrong_chain"] += wrong in ("chain", "proof tag")

        for step in range(steps):
            depth = rng.randrange(1, 5) if len(blocks) > 1 and rng.random() < 0.12 else 0
            if len(state.above) >= 2 and not walked_back:  # once per run: from past the end back to before it
                depth, walked_back = len(state.above) + rng.randrange(1, 4), True
            if depth:
                was_closed = state.closed()
                for _ in range(min(len(blocks) - 1, depth)):
                    state.disconnect()
                    blocks.pop()
                    works.pop()
                    out_steps.append(["disconnect"])
                stats["reorgs"] += 1
                stats["reopened"] += was_closed and not state.closed()
                dump()
            if rng.random() < 0.6:
                pay_someone()
            if rng.random() < 0.3:
                sims[0].mine([])
            if rng.random() < 0.5:
                for _ in range(rng.choice([1, 1, 2, 12])):
                    sims[1].mine([])
            if rng.random() < 0.06:  # one of the two chains reorganizes: its last blocks are replaced by a longer branch
                sim = rng.choice(sims)
                back = min(len(sim.chain) - 1, rng.randrange(1, 4))
                if back:
                    del sim.chain[-back:]
                    for _ in range(back + 1):
                        sim.mine([])
                    stats["relay_reorgs"] += 1
            raw, offered = make_block()
            b, w = S.block_from_raw(d, raw, len(blocks), works[-1])
            tracked = state.connect(b)
            blocks.append(b)
            works.append(w)
            out_steps.append(["connect", raw.hex()])
            dump()
            if not tracked:
                stats["past_the_end"] += 1
                continue
            i = state.info[-1]
            stats["curve_qwen" if b.quote == S.QWEN else "curve_btc"] += b.curve
            stats["kills"] += len(i.killed)
            stats["qwen_headers"] += len(i.qrelayed)
            stats["pass_limit"] += offered > Y.MAX_QWEN_PASSES and len(i.qrelayed) == Y.MAX_QWEN_PASSES
            for m in i.settled_here:
                stats["settled_qwen" if state.info[m].quote == S.QWEN else "settled_btc"] += 1
            if i.drew >= 0:
                stats["holder_draws"] += state.info[i.drew].coin is not None
                stats["released_at_draw"] += i.drew in i.released_here
                stats["merge_mined_seeds"] += b.work_hash != b.hash
        r = self.drv(op="state", json=d.dumps(), steps=out_steps, **({"work": "hash"} if main_qwen else {}))
        self.assertTrue(r["ok"], r)
        self.assertEqual(len(r["dumps"]), len(views))
        for k, (got, want) in enumerate(zip(r["dumps"], views)):
            if got != want:
                top = {key: (got.get(key), want[key]) for key in want if key != "obligations" and got.get(key) != want[key]}
                per = [(o["height"], S.differences(g, o)) for g, o in zip(got["obligations"], want["obligations"]) if g != o][:3]
                self.fail(f"seed {seed}: what the node says after step {k} (height {want['height']}) is not what the model "
                          f"says. node / model: {top}; obligations: {per}; "
                          f"{len(got['obligations'])} / {len(want['obligations'])} obligations")
        self.assertTrue(views[-1]["closed"] and views[-1]["graduated"])
        if main_qwen:  # the relay went over the edge of a difficulty period, and the retarget there
            best = state.qrelay.chain.nodes[state.qrelay.chain.best]
            self.assertGreater(best.height // 2016, sims[1].anchor_height // 2016)
            self.assertEqual(best.bits, 0x1F3FFFC0)
            stats["qwen_retargets"] = 1
        return stats

    def test_state_machine_alike(self):
        total = {}
        for k in range(int(os.environ.get("HFDIFF_STATE_SEEDS", "3"))):
            for name, v in self.state_run(SEED * 1000 + k, 330).items():
                total[name] = total.get(name, 0) + v
        if os.environ.get("HFDIFF_VERBOSE"):
            print("\nstate:", total)
        for name, v in total.items():  # the runs have to have reached every path they are there for
            self.assertGreater(v, 2, (name, total))

    def test_state_machine_alike_on_qwencoins_main_rules(self):
        """The same, with the QWEN leg on a made-up Qwencoin under its main-network rules: the launch's
        Qwencoin relay follows that chain over the edge of a difficulty period and a retarget, and
        payments are proven against blocks on both sides of it."""
        total = {}
        for k in range(int(os.environ.get("HFDIFF_STATE_SEEDS", "3")) - 1 or 1):
            for name, v in self.state_run(SEED * 1000 + 500 + k, 330, main_qwen=True).items():
                total[name] = total.get(name, 0) + v
        if os.environ.get("HFDIFF_VERBOSE"):
            print("\nstate, Qwencoin's main rules:", total)
        for name, v in total.items():
            self.assertGreater(v, 0 if name == "qwen_retargets" else 2, (name, total))

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
