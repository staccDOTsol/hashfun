"""Which node binary the CLI runs on which machine, and where the tools ask a Bitcoin node about a
launch's Bitcoin anchor before they act on the launch.

The npm package lays itself out as <package>/py/hashfun/*.py beside <package>/prebuilt/<target>/hashfund;
the first tests build that layout in a temporary directory with a stand-in binary and ask the CLI what it
would run. The anchor tests run the real command paths against a stand-in Bitcoin node (a list of
headers) and stand-in launch nodes."""
import contextlib
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from hashfun import cli, web
from hashfun import descriptor as D
from hashfun.tests.test_core import FakeBitcoin, header_time, mainnet_headers, production_launch, qwen_headers

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the hashfun package directory
FAKE = "#!/bin/sh\necho \"stand-in hashfund for $(basename \"$(dirname \"$0\")\")\"\n"


class TargetTest(unittest.TestCase):
    def target(self, system, machine, translated=""):
        done = subprocess.CompletedProcess([], 0, stdout=translated, stderr="")
        with mock.patch.object(sys, "platform", system), mock.patch("platform.machine", return_value=machine), \
                mock.patch("subprocess.run", return_value=done):
            return cli.platform_target()

    def test_the_four_targets(self):
        self.assertEqual(self.target("linux", "x86_64"), "linux-x64")
        self.assertEqual(self.target("linux", "aarch64"), "linux-arm64")
        self.assertEqual(self.target("darwin", "arm64"), "darwin-arm64")
        self.assertEqual(self.target("darwin", "x86_64", "0\n"), "darwin-x64")
        self.assertEqual(self.target("linux", "AMD64"), "linux-x64")

    def test_an_intel_python_on_an_arm_mac_gets_the_arm_node(self):
        self.assertEqual(self.target("darwin", "x86_64", "1\n"), "darwin-arm64")

    def test_anything_else_has_no_target(self):
        for system, machine in (("win32", "AMD64"), ("linux", "riscv64"), ("freebsd14", "amd64"), ("linux", "armv7l")):
            self.assertIsNone(self.target(system, machine), f"{system} {machine}")


class ChoiceTest(unittest.TestCase):
    """The real CLI, run from a copy laid out like the npm package."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hashfun-cli-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        pkg = os.path.join(self.tmp, "py", "hashfun")
        os.makedirs(pkg)
        for n in os.listdir(HERE):
            if n.endswith(".py") or n == "bip39_english.txt":
                shutil.copy(os.path.join(HERE, n), pkg)
        self.target = cli.platform_target()
        self.assertIsNotNone(self.target, "these tests run on a platform hashfun ships for")
        self.bins = {}
        for t in ("linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64"):
            d = os.path.join(self.tmp, "prebuilt", t)
            os.makedirs(d)
            self.bins[t] = os.path.join(d, "hashfund")
            with open(self.bins[t], "w") as f:
                f.write(FAKE)
            os.chmod(self.bins[t], 0o755)

    def doctor(self, **env):
        e = {k: v for k, v in os.environ.items() if k not in ("HASHFUND", "PYTHONPATH")}
        e.update(PYTHONPATH=os.path.join(self.tmp, "py"), PATH="/usr/bin:/bin", **env)
        p = subprocess.run([sys.executable, "-m", "hashfun.cli", "doctor", "--quick"], capture_output=True, text=True, env=e,
                           cwd=self.tmp)
        return p.returncode, p.stdout + p.stderr

    def test_the_package_runs_the_binary_shipped_for_this_machine(self):
        rc, out = self.doctor()
        self.assertEqual(rc, 0, out)
        self.assertIn(self.bins[self.target], out)
        self.assertIn(f"shipped with the package for {self.target}", out)
        self.assertIn(f"stand-in hashfund for {self.target}", out)

    def test_HASHFUND_is_an_order_not_a_hint(self):
        other = os.path.join(self.tmp, "mine")
        with open(other, "w") as f:
            f.write("#!/bin/sh\necho my own build\n")
        os.chmod(other, 0o755)
        rc, out = self.doctor(HASHFUND=other)
        self.assertEqual(rc, 0, out)
        self.assertIn("my own build", out)
        self.assertIn("$HASHFUND", out)
        rc, out = self.doctor(HASHFUND=os.path.join(self.tmp, "nothing-here"))
        self.assertEqual(rc, 1, out)
        self.assertIn("no such file", out)
        self.assertNotIn("stand-in", out)  # the packaged one is not quietly used instead

    def test_a_binary_that_lost_its_executable_bit_is_repaired(self):
        os.chmod(self.bins[self.target], 0o644)
        rc, out = self.doctor()
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.stat(self.bins[self.target]).st_mode & stat.S_IXUSR)

    def test_a_package_without_this_machines_binary_says_so(self):
        os.remove(self.bins[self.target])
        rc, out = self.doctor()
        self.assertEqual(rc, 1, out)
        self.assertIn(f"no hashfund for {self.target}", out)
        self.assertNotIn("stand-in", out)  # never another platform's binary


@unittest.skipUnless(os.environ.get("HASHFUND") and os.path.isfile(os.environ.get("HASHFUND", "")), "HASHFUND is not set")
class SelfTest(unittest.TestCase):
    """The real binary: doctor's self-test, and a chain written by one node and judged by another."""

    def test_doctor_self_test_on_the_real_binary(self):
        line = cli.self_test(os.environ["HASHFUND"])
        self.assertIn("every mint equal", line)

    def test_a_mined_chain_replays_to_the_same_conclusions_and_a_changed_one_does_not(self):
        import json
        binary, tmp = os.environ["HASHFUND"], tempfile.mkdtemp(prefix="hashfun-chain-test-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        path = os.path.join(tmp, "chain.json")
        said = cli.mine_chain(binary, path, blocks=110)
        self.assertRegex(said, r"on the BTC curve, \d+ on the QWEN curve, graduated by the BTC curve at \d+")
        with open(path) as f:
            good = json.load(f)
        self.assertEqual((len(good["blocks"]), good["hashfun_chain"]), (110, 2))
        state = good["state"]
        self.assertTrue(state["graduated"] and state["graduated_by"] == "btc")
        self.assertTrue(state["curves"]["btc"]["blocks"] > state["curves"]["qwen"]["blocks"] > 20)  # both curves were mined
        self.assertEqual({o["quote"] for o in good["owed"] if o["curve"]}, {"btc", "qwen"})
        self.assertIn("same tip, same UTXO set", cli.replay_chain(binary, path))

        def changed(edit):
            data = json.loads(json.dumps(good))
            edit(data)
            other = os.path.join(tmp, "changed.json")
            with open(other, "w") as f:
                json.dump(data, f)
            with self.assertRaises(RuntimeError) as e:
                cli.replay_chain(binary, other)
            return str(e.exception)

        def flip(data):  # one hex digit inside block 40's coinbase
            b = data["blocks"][39]
            data["blocks"][39] = b[:200] + ("0" if b[200] != "0" else "1") + b[201:]
        self.assertIn("rejects block 40", changed(flip))
        self.assertIn("different utxo", changed(lambda d: d["utxo"].update(hash_serialized_3="00" * 32)))
        self.assertIn("different state", changed(lambda d: d["state"].update(curve_supply=d["state"]["curve_supply"] + 1)))
        self.assertIn("different state", changed(lambda d: d["state"]["curves"]["qwen"].update(blocks=0)))
        self.assertIn("different debt for block 7", changed(lambda d: d["owed"][6].update(owed=d["owed"][6]["owed"] + 1)))
        self.assertIn("different debt for block 3", changed(lambda d: d["owed"][2].update(quote="btc")))  # block 3 is on the QWEN curve
        self.assertIn("different tip", changed(lambda d: d["blocks"].pop()))
        self.assertIn("written under the earlier rules", changed(lambda d: d.update(hashfun_chain=1)))


class Bitcoin(FakeBitcoin):
    """The stand-in Bitcoin node of test_core, as the tools hold it: possibly through a wallet, and
    (the site) asked once which network it is on. drop: a call it fails to answer, while it is set."""

    drop = None

    def getblockhash(self, height):
        if self.drop == "getblockhash":
            raise OSError("timed out")
        return super().getblockhash(height)

    def getblockheader(self, block_hash, verbose=True):
        if self.drop == "getblockheader":
            raise OSError("timed out")
        return super().getblockheader(block_hash, verbose)

    def wallet(self, name):
        self.asked.append(("wallet", name))
        return self

    loaded = None  # the wallets the node has loaded (None: it does not say)

    def listwallets(self):
        if self.loaded is None:
            raise OSError("timed out")
        return list(self.loaded)

    def getblockchaininfo(self):
        return {"chain": "main"}

    def anchor_questions(self):
        return [q for q in self.asked if q[0] in ("getblockcount", "getblockhash", "getblockheader")]


def qwencoin(**kw):
    """The stand-in Qwencoin node: the first fifteen blocks of the real chain."""
    qh = qwen_headers()[0]
    return Bitcoin([qh[h] for h in range(15)], **kw)


def anchored(ticker="RULE", **kw):
    """A production launch (test_core.production_launch: Bitcoin mainnet rules, anchored at block 1500 of
    the stored headers; the real Qwencoin, anchored at its block 8) with a mined genesis, so that its
    file loads."""
    qh, qstarts = qwen_headers()
    kw = {"qwen_anchor_height": 8, "qwen_anchor_header": qh[8], "qwen_anchor_period_time": qstarts[0], **kw}
    d = production_launch(ticker=ticker, hrp=ticker.lower(), **kw)
    d.grind_genesis()
    return d


def wrong_period(ticker="RULE"):
    """A launch file both parsers accept and only a Bitcoin node can fault: the right header at the
    right height, the start of its difficulty period one second off."""
    return anchored(ticker, btc_anchor_period_time=header_time(mainnet_headers()[0]) + 1)


class StubRegistry:
    """What the mining path and the site read from the registry: one launch, whose node is a mock."""

    def __init__(self, d, tmp):
        self.d, self.node, self.ups = d, mock.MagicMock(name="launch node"), 0
        self.node.getlaunchinfo.side_effect = OSError("a stand-in node")
        self.data = {d.ticker: {"id": d.id_hex, "descriptor": os.path.join(tmp, "descriptor.json")}}

    def desc(self, ticker):
        return self.d

    def rpc(self, ticker, timeout=60):
        return self.node

    def get(self, ticker):
        return self.data[ticker]

    def up(self, ticker, extra=(), fetch_table=False):
        self.ups += 1
        return False


BTC_URL, QWEN_URL = "http://u:p@127.0.0.1:1", "http://u:p@127.0.0.1:2"


def nodes(btc=None, qwen=None):
    """What the tools get when they open an RPC: the Bitcoin stand-in at BTC_URL, the Qwencoin one at QWEN_URL."""
    return lambda url, cookie_file=None: qwen if url == QWEN_URL else btc


class AnchorOnRegister(unittest.TestCase):
    """hashfun node add --btc-rpc / --qwen-rpc: a launch file from somebody else is registered only if
    the user's own Bitcoin and Qwencoin nodes say its anchors are true."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hashfun-anchor-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        env = mock.patch.dict(os.environ, {"HASHFUN_HOME": os.path.join(self.tmp, "home")})
        env.start()
        self.addCleanup(env.stop)

    def file(self, d):
        path = os.path.join(self.tmp, d.ticker.lower() + ".json")
        with open(path, "w") as f:
            f.write(d.dumps())
        return path

    def add(self, d, btc=None, qwen=None):
        """Run `hashfun node add FILE [--btc-rpc URL] [--qwen-rpc URL]`. (what it exited with or None, its stderr)"""
        argv = (["node", "add", self.file(d)] + (["--btc-rpc", BTC_URL] if btc else []) + (["--qwen-rpc", QWEN_URL] if qwen else []))
        err, code = io.StringIO(), None
        with mock.patch.object(cli, "RPC", side_effect=nodes(btc, qwen)), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(err):
            try:
                cli.main(argv)
            except SystemExit as e:
                code = e.code
        return code, err.getvalue()

    def registered(self):
        return sorted(cli.Registry().data)

    def test_true_anchors_are_registered(self):
        btc, qwen = Bitcoin(mainnet_headers()), qwencoin()
        self.assertEqual(self.add(anchored(), btc, qwen), (None, ""))
        self.assertEqual(self.registered(), ["RULE"])
        self.assertTrue(btc.anchor_questions(), "the Bitcoin node was asked")
        self.assertEqual(qwen.anchor_questions()[:3], [("getblockcount",), ("getblockhash", 8), ("getblockheader", qwen.hash(8), False)])

    def test_ports_something_else_listens_on_are_not_given_to_the_node(self):
        """A launch's ports come from its id. Where one of them is taken on this machine (another program, or
        this launch's node in another folder), the node gets another: it would not start on a taken port."""
        import socket
        d = anchored("PORT")
        self.assertIsNone(self.add(anchored("FREE"))[0])
        e = cli.Registry().data["FREE"]
        self.assertEqual((e["rpcport"], e["p2pport"]), (anchored("FREE").rpc, None))        # nothing in the way: the launch's own
        held = []
        try:
            for port in (d.rpc, d.p2p):
                s = socket.socket()
                s.bind(("127.0.0.1", port))
                s.listen(1)
                held.append(s)
            self.assertIsNone(self.add(d)[0])
            e = cli.Registry().data["PORT"]
            self.assertNotIn(e["rpcport"], (d.rpc, d.p2p))
            self.assertNotIn(e["p2pport"], (None, d.p2p, d.rpc, e["rpcport"]))
            for port in (e["rpcport"], e["p2pport"]):
                self.assertFalse(cli.port_in_use(port))
            self.assertTrue(cli.port_in_use(d.rpc) and cli.port_in_use(d.p2p))
            first = dict(e)
            self.assertIsNone(self.add(d)[0])                                           # registered again: it keeps what it has
            self.assertEqual({k: cli.Registry().data["PORT"][k] for k in ("rpcport", "p2pport")},
                             {k: first[k] for k in ("rpcport", "p2pport")})
        finally:
            for s in held:
                s.close()

    def test_a_launch_the_bitcoin_node_denies_is_not_registered(self):
        hdrs = mainnet_headers()
        t0 = header_time(hdrs[0])
        cases = (
            (wrong_period("PERI"), Bitcoin(hdrs), "btc_anchor_period_time is"),
            # the right block of another chain: the node has a different block at that height
            (anchored("FORK"), Bitcoin(hdrs[:1500] + [hdrs[1499]] + hdrs[1501:]), "but block 1500 on this Bitcoin node's chain is"),
            (anchored("HIGH", btc_anchor_height=4032, btc_anchor_header=hdrs[0], btc_anchor_period_time=t0), Bitcoin(hdrs),
             "this Bitcoin node is only at 2016"),
            (anchored("DOWN"), Bitcoin(hdrs, fail=OSError("connection refused")), "could not ask the Bitcoin node"),
        )
        for d, btc, why in cases:
            code, _ = self.add(d, btc, qwencoin())
            self.assertIsInstance(code, str, d.ticker)  # sys.exit(text): the text on stderr, status 1, no traceback
            self.assertTrue(code.startswith(self.file(d) + ": btc anchor: "), code)
            self.assertIn(why, code)
        self.assertEqual(self.registered(), [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "home", "launches")), "nothing of a refused launch is kept")

    def test_a_launch_the_qwencoin_node_denies_is_not_registered(self):
        """No parser can tell that a launch's Qwencoin anchor is a Qwencoin block at all: here is where
        somebody else's file is found out."""
        qh, qstarts = qwen_headers()
        made_up = qh[8][:76] + bytes(4)                                     # a header nobody mined: both parsers take it
        cases = (
            (anchored("QPER", qwen_anchor_period_time=qstarts[0] + 1), qwencoin(), "qwen_anchor_period_time is"),
            (anchored("QFAK", qwen_anchor_header=made_up), qwencoin(), "but block 8 on this Qwencoin node's chain is"),
            (anchored("QHIG", qwen_anchor_height=2000, qwen_anchor_header=qh[2000]), qwencoin(), "this Qwencoin node is only at 14"),
            (anchored("QDWN"), qwencoin(fail=OSError("connection refused")), "could not ask the Qwencoin node"),
            # a Bitcoin node given as the Qwencoin node: another chain altogether
            (anchored("QBTC"), Bitcoin(mainnet_headers()), "but block 8 on this Qwencoin node's chain is"),
        )
        for d, qwen, why in cases:
            code, _ = self.add(d, Bitcoin(mainnet_headers()), qwen)
            self.assertIsInstance(code, str, d.ticker)
            self.assertTrue(code.startswith(self.file(d) + ": qwen anchor: "), code)
            self.assertIn(why, code)
            code, _ = self.add(d, None, qwen)                               # the Qwencoin node alone is enough to refuse it
            self.assertIn(": qwen anchor: ", code)
        self.assertEqual(self.registered(), [])

    def test_a_node_that_was_not_given_is_not_asked_and_one_line_each_says_so(self):
        code, err = self.add(wrong_period("PERI"))
        self.assertIsNone(code)
        self.assertEqual(self.registered(), ["PERI"])
        self.assertEqual(len(err.splitlines()), 2, err)
        self.assertIn("Bitcoin anchor was not checked", err.splitlines()[0])
        self.assertIn("Qwencoin anchor was not checked (no --qwen-rpc URL of a Qwencoin node)", err.splitlines()[1])
        code, err = self.add(anchored("ONLY"), Bitcoin(mainnet_headers()))
        self.assertEqual((code, len(err.splitlines())), (None, 1), err)
        self.assertIn("Qwencoin anchor was not checked", err)
        code, err = self.add(anchored("QNLY"), None, qwencoin())
        self.assertEqual((code, len(err.splitlines())), (None, 1), err)
        self.assertIn("Bitcoin anchor was not checked", err)

    def test_a_launch_on_regtest_chains_is_asked_about_its_blocks_only(self):
        regtest = dict(btc_regtest=True, btc_anchor_height=0, btc_anchor_header=D.REGTEST_GENESIS_HEADER, btc_anchor_period_time=0,
                       qwen_regtest=True, qwen_anchor_height=0, qwen_anchor_header=D.REGTEST_GENESIS_HEADER,
                       qwen_anchor_period_time=0)
        btc, qwen = Bitcoin([D.REGTEST_GENESIS_HEADER]), Bitcoin([D.REGTEST_GENESIS_HEADER])
        self.assertEqual(self.add(anchored("REGT", **regtest), btc, qwen), (None, ""))
        for node in (btc, qwen):
            self.assertEqual(node.anchor_questions(), [("getblockcount",), ("getblockhash", 0), ("getblockheader", node.hash(0), False)])
        code, _ = self.add(anchored("MAIN", **regtest), Bitcoin(mainnet_headers()), qwen)  # a mainnet node: another network
        self.assertIn("but block 0 on this Bitcoin node's chain is", code)
        code, _ = self.add(anchored("QMAI", **regtest), btc, qwencoin())
        self.assertIn("but block 0 on this Qwencoin node's chain is", code)
        self.assertEqual(self.registered(), ["REGT"])


class AnchorBeforeMining(unittest.TestCase):
    """hashfun mine: the node of each chain a block's debt will be paid through is asked before
    anything is built, and a no stops the command before a block can be mined."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hashfun-anchor-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.settler = mock.patch("hashfun.settler.Settler").start()
        self.source = mock.patch("hashfun.stratum.LaunchSource").start()
        self.server = mock.patch("hashfun.stratum.StratumServer").start()
        self.addCleanup(mock.patch.stopall)

    def build(self, d, btc, qwen=None, **kw):
        reg = StubRegistry(d, self.tmp)
        with mock.patch.object(cli, "RPC", side_effect=nodes(btc, qwen)):
            try:
                return reg, cli.build_source(reg, d.ticker, "payout", BTC_URL if btc else None, "bc",
                                             qwen_rpc=QWEN_URL if qwen else None, **kw), None
            except SystemExit as e:
                return reg, None, e.code

    def test_a_true_anchor_builds_the_pool_and_its_settler(self):
        btc = Bitcoin(mainnet_headers())
        reg, built, code = self.build(anchored(), btc, btc_wallet="hot")
        self.assertIsNone(code)
        self.assertEqual(btc.asked[0], ("wallet", "hot"))  # the handle that is asked is the one that will pay
        self.assertTrue(btc.anchor_questions())
        self.settler.assert_called_once()
        self.assertIs(self.settler.call_args.args[1], btc)
        self.assertIsNone(self.settler.call_args.kwargs["qwen_wallet"])
        self.source.assert_called_once()
        self.assertEqual(self.source.call_args.kwargs["curve"], "btc")      # the curve its one wallet can pay
        self.assertIs(built[0], self.source.return_value)

    def test_a_qwencoin_wallet_alone_mines_the_qwen_curve(self):
        """What a Qwencoin machine has: qwen it mined, and no Bitcoin node."""
        qwen = qwencoin()
        reg, built, code = self.build(anchored(), None, qwen, qwen_wallet="mined")
        self.assertIsNone(code)
        self.assertEqual(qwen.asked[0], ("wallet", "mined"))
        self.assertTrue(qwen.anchor_questions())
        self.assertIsNone(self.settler.call_args.args[1])                   # no Bitcoin wallet: nothing is ever paid there
        self.assertIs(self.settler.call_args.kwargs["qwen_wallet"], qwen)
        self.assertEqual(self.source.call_args.kwargs["curve"], "qwen")

    def test_with_both_wallets_the_curve_has_to_be_said(self):
        btc, qwen = Bitcoin(mainnet_headers()), qwencoin()
        reg, built, code = self.build(anchored(), btc, qwen)
        self.assertRegex(code, "^--curve btc|qwen: a Bitcoin and a Qwencoin wallet were both given")
        self.source.assert_not_called()
        for curve in ("btc", "qwen"):
            self.source.reset_mock()
            self.settler.reset_mock()
            reg, built, code = self.build(anchored(), btc, qwen, curve=curve)
            self.assertIsNone(code)
            self.assertEqual(self.source.call_args.kwargs["curve"], curve)
            self.assertEqual((self.settler.call_args.args[1], self.settler.call_args.kwargs["qwen_wallet"]), (btc, qwen))
        # a curve named without the wallet that pays it, and no wallet at all
        self.source.reset_mock()
        for kw, have, why in ((dict(curve="qwen"), (btc, None), "--curve qwen: a block on the QWEN curve owes qwen, so mining it needs "
                                                               "a funded Qwencoin wallet: --qwen-rpc URL"),
                              (dict(curve="btc"), (None, qwen), "--curve btc: a block on the BTC curve owes sats, so mining it needs a "
                                                                "funded Bitcoin wallet: --btc-rpc URL"),
                              ({}, (None, None), "pass --btc-rpc URL of a funded Bitcoin Core wallet")):
            reg, built, code = self.build(anchored(), *have, **kw)
            self.assertIn(why, code)
        self.source.assert_not_called()

    def test_a_node_with_no_wallet_gives_its_headers_and_pays_nothing(self):
        """--btc-rpc / --qwen-rpc without a wallet name: the node's own wallet when it has exactly one
        loaded. A node with none is still worth having (the launch needs that chain's headers for
        everybody's proofs): its headers are relayed and nothing is paid there. With several loaded,
        which one pays has to be said."""
        btc, qwen = Bitcoin(mainnet_headers()), qwencoin()
        btc.loaded, qwen.loaded = ["savings"], []
        with contextlib.redirect_stderr(io.StringIO()) as err:
            reg, built, code = self.build(anchored(), btc, qwen)
        self.assertIsNone(code)
        self.assertIn("the Qwencoin node has no wallet loaded: its headers are relayed to RULE", err.getvalue())
        self.assertIn(("wallet", "savings"), btc.asked)                       # the one wallet it has
        self.assertTrue(btc.anchor_questions() and qwen.anchor_questions())   # both anchors were still checked
        kw = self.settler.call_args.kwargs
        self.assertEqual((self.settler.call_args.args[1], kw["qwen_wallet"], kw["btc_node"], kw["qwen_node"]),
                         (btc, None, None, qwen))
        self.assertEqual(self.source.call_args.kwargs["curve"], "btc")        # the curve there is a wallet for
        self.source.reset_mock()
        with contextlib.redirect_stderr(io.StringIO()):
            reg, built, code = self.build(anchored(), btc, qwen, curve="qwen")
        self.assertIn("--curve qwen: a block on the QWEN curve owes qwen, so mining it needs a funded Qwencoin wallet", code)
        btc.loaded = []
        with contextlib.redirect_stderr(io.StringIO()):
            reg, built, code = self.build(anchored(), btc, qwen)
        self.assertIn("neither node has a wallet loaded", code)
        btc.loaded, qwen.loaded = ["a", "b"], ["only"]
        reg, built, code = self.build(anchored(), btc, qwen, curve="qwen")
        self.assertIn("--btc-wallet NAME: the Bitcoin node has 2 wallets loaded (a, b): say which one pays", code)
        self.source.assert_not_called()
        # a wallet that is named is taken at its word, whatever the node has loaded
        reg, built, code = self.build(anchored(), btc, qwen, curve="qwen", btc_wallet="b")
        self.assertIsNone(code)
        self.assertEqual((self.settler.call_args.args[1], self.settler.call_args.kwargs["qwen_wallet"]), (btc, qwen))

    def test_an_anchor_a_node_denies_builds_nothing(self):
        hdrs = mainnet_headers()
        qh, qstarts = qwen_headers()
        for d, btc, qwen, why in (
                (wrong_period(), Bitcoin(hdrs), None, "RULE: btc anchor: btc_anchor_period_time is"),
                (anchored(), Bitcoin(hdrs[:1400]), None, "RULE: btc anchor: .*this Bitcoin node is only at 1399"),
                (anchored(), Bitcoin(hdrs, fail=OSError("connection refused")), None, "RULE: btc anchor: could not ask the Bitcoin node"),
                (anchored(qwen_anchor_period_time=qstarts[0] + 1), None, qwencoin(), "RULE: qwen anchor: qwen_anchor_period_time is"),
                (anchored(qwen_anchor_header=qh[8][:76] + bytes(4)), Bitcoin(hdrs), qwencoin(), "RULE: qwen anchor: .*block 8 on this "
                                                                                                "Qwencoin node's chain is"),
                (anchored(), Bitcoin(hdrs), qwencoin(fail=OSError("connection refused")), "RULE: qwen anchor: could not ask the Qwencoin node")):
            reg, built, code = self.build(d, btc, qwen, curve="btc" if btc else "qwen")
            self.assertIsNone(built)
            self.assertIsInstance(code, str)
            self.assertRegex(code, why)
            self.settler.assert_not_called()
            self.source.assert_not_called()
            self.assertEqual(reg.node.method_calls, [], "the launch's node was not touched either")

    def test_the_mine_command_stops_before_it_serves_work(self):
        reg = StubRegistry(wrong_period(), self.tmp)
        argv = ["mine", "RULE", "--payout", "rule1qexample", "--btc-rpc", BTC_URL, "--no-cpu", "--duration", "0.01"]
        with mock.patch.object(cli, "Registry", return_value=reg), mock.patch.object(cli, "RPC", side_effect=nodes(Bitcoin(mainnet_headers()))), \
                contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit) as e:
            cli.main(argv)
        self.assertRegex(str(e.exception.code), "^RULE: btc anchor: btc_anchor_period_time is")
        self.assertEqual(out.getvalue(), "")  # not even the line that announces the stratum address
        self.server.assert_not_called()
        self.settler.assert_not_called()

    def test_the_mine_command_serves_work_on_a_true_anchor(self):
        async def serve():
            return None
        self.server.return_value.serve.side_effect = serve
        self.settler.return_value.status.return_value = {"wallets": ["qwen"]}
        self.source.return_value.curve = "qwen"
        for extra, btc, qwen, curve in ((["--btc-rpc", BTC_URL], Bitcoin(mainnet_headers()), None, "btc"),
                                        (["--qwen-rpc", QWEN_URL, "--qwen-wallet", "mined"], None, qwencoin(), "qwen"),
                                        (["--btc-rpc", BTC_URL, "--qwen-rpc", QWEN_URL, "--curve", "qwen"], Bitcoin(mainnet_headers()),
                                         qwencoin(), "qwen")):
            reg = StubRegistry(anchored(), self.tmp)
            self.server.reset_mock()
            self.source.reset_mock()
            argv = ["mine", "RULE", "--payout", "rule1qexample", "--no-cpu", "--duration", "0.01", *extra]
            with mock.patch.object(cli, "Registry", return_value=reg), mock.patch.object(cli, "RPC", side_effect=nodes(btc, qwen)), \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                cli.main(argv)
            self.assertIn('"launch": "RULE"', out.getvalue())
            self.assertEqual(self.source.call_args.kwargs["curve"], curve)
            self.server.assert_called_once()
            self.assertIs(self.server.call_args.args[0], self.source.return_value)
        # neither wallet: the command says what mining needs, and serves nothing
        self.server.reset_mock()
        with mock.patch.object(cli, "Registry", return_value=StubRegistry(anchored(), self.tmp)), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as e:
            cli.main(["mine", "RULE", "--payout", "rule1qexample", "--no-cpu"])
        self.assertIn("or --qwen-rpc URL of a funded Qwencoin wallet", str(e.exception.code))
        self.server.assert_not_called()


class WorkTable(unittest.TestCase):
    """What a node of a launch on the real Qwencoin is started with: that chain's work table."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hashfun-qwork-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        env = mock.patch.dict(os.environ, {"HASHFUN_HOME": self.tmp, "HASHFUN_QWORK": ""})
        env.start()
        self.addCleanup(env.stop)

    def test_a_regtest_qwen_leg_needs_no_table(self):
        self.assertEqual(cli.qwork_args(anchored(qwen_regtest=True), "RULE"), [])

    def test_the_real_qwencoin_needs_it_and_the_tools_say_how_to_get_it(self):
        from hashfun import qwork
        path = os.path.join(self.tmp, "qwork.bin")
        self.assertEqual(qwork.default_path(), path)
        with self.assertRaises(SystemExit) as e:
            cli.qwork_args(anchored(), "RULE")
        self.assertRegex(str(e.exception.code), "^RULE: its QWEN leg follows the real Qwencoin.*is not there.*hashfun qwork fetch")
        with open(path, "wb") as f:                                        # a download that stopped
            f.write(b"QWRK1\0\0\0" + bytes(100))
        with self.assertRaises(SystemExit) as e:
            cli.qwork_args(anchored(), "RULE")
        self.assertIn("is 108 bytes, the table is 528,482,328 (an interrupted download?)", str(e.exception.code))
        with mock.patch.object(qwork, "quick_problem", return_value=None):  # the table in place
            self.assertEqual(cli.qwork_args(anchored(), "RULE"), [f"-qwork={path}"])
        # with fetch=True a missing table is downloaded first; a download that fails stops the command
        with mock.patch.object(qwork, "fetch", side_effect=RuntimeError("could not fetch it")) as fetch, \
                self.assertRaises(SystemExit) as e:
            cli.qwork_args(anchored(), "RULE", fetch=True)
        fetch.assert_called_once()
        self.assertEqual(str(e.exception.code), "RULE: could not fetch it")

    def test_the_table_file_is_judged_by_size_shape_and_hash(self):
        from hashfun import qwork
        path = os.path.join(self.tmp, "t.bin")
        self.assertIn("is not there", qwork.problem(path))
        with mock.patch.object(qwork, "TABLE_BYTES", 24 + 16), mock.patch.object(qwork, "TABLE_SHA256", "00" * 32):
            import struct
            with open(path, "wb") as f:
                f.write(b"NOTQWRK1" + struct.pack("<IIII", 24, 1024, 3584, 0) + bytes(16))
            self.assertIn("is not a Qwencoin work table", qwork.problem(path))
            with open(path, "wb") as f:
                f.write(b"QWRK1\0\0\0" + struct.pack("<IIII", 24, 1024, 3584, 0) + bytes(16))
            self.assertIsNone(qwork.quick_problem(path))
            self.assertRegex(qwork.problem(path), "has SHA-256 [0-9a-f]{64}, the chain's table has 0000")
            with mock.patch.object(qwork, "TABLE_SHA256", qwork.sha256_of(path)):
                self.assertIsNone(qwork.problem(path))
                self.assertEqual(qwork.fetch(path, url="http://127.0.0.1:1/never-asked"), path)  # already there: no download
        self.assertEqual((qwork.TABLE_BYTES, qwork.TABLE_SHA256), (528_482_328, "8f53884f7727e80b86f3ddf288d3c3f0f998f1c63b8cd4f0bdad182ddd3f2c03"))

    def test_a_download_is_resumed_and_put_in_place_only_when_whole_and_right(self):
        """Against a local server that sends the file in two parts (the first connection breaks off)."""
        import hashlib
        import struct
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from hashfun import qwork
        body = b"QWRK1\0\0\0" + struct.pack("<IIII", 24, 1024, 3584, 0) + os.urandom(5000)
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                rng = self.headers.get("Range")
                seen.append(rng)
                start = int(rng.split("=")[1].rstrip("-")) if rng else 0
                part = body[start:start + 3000] if not rng else body[start:]   # the first answer stops early
                self.send_response(206 if rng else 200)
                self.send_header("Content-Length", str(len(body) - start))     # ... having promised all of it
                self.end_headers()
                self.wfile.write(part)

            def log_message(self, *a):
                pass
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        url, path, said = f"http://127.0.0.1:{srv.server_address[1]}/qwork.bin", os.path.join(self.tmp, "dl", "qwork.bin"), []
        with mock.patch.object(qwork, "TABLE_BYTES", len(body)), mock.patch.object(qwork, "TABLE_SHA256", hashlib.sha256(body).hexdigest()), \
                mock.patch.object(qwork.time, "sleep"):
            self.assertEqual(qwork.fetch(path, url, say=said.append), path)
            with open(path, "rb") as f:
                self.assertEqual(f.read(), body)
            self.assertEqual(seen, [None, "bytes=3000-"])
            self.assertFalse(os.path.exists(path + ".part"))
            self.assertTrue(any("resuming" in line for line in said))
            # a server that serves something else: nothing is put in place
            os.remove(path)
        with mock.patch.object(qwork, "TABLE_BYTES", len(body)), mock.patch.object(qwork, "TABLE_SHA256", "11" * 32), \
                mock.patch.object(qwork.time, "sleep"), self.assertRaisesRegex(RuntimeError, "nothing was put in place"):
            qwork.fetch(path, url)
        self.assertFalse(os.path.exists(path) or os.path.exists(path + ".part"))


class AnchorOnTheSite(unittest.TestCase):
    """hashfun web: a registered launch is served only once the site's own Bitcoin node has said its
    anchor is true; a launch it denies is shown as refused, with the reason, and nothing is read from it."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hashfun-anchor-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def site(self, d, btc, qwen=None):
        reg = StubRegistry(d, self.tmp)
        return web.Site(btc, reg, qwen=qwen), reg

    def test_a_true_anchor_is_served(self):
        btc = Bitcoin(mainnet_headers())
        site, reg = self.site(anchored(), btc)
        site.refresh()
        self.assertIsNone(site.coins["RULE"].refused)
        reg.node.getlaunchinfo.assert_called()  # it is being read
        asked = len(btc.anchor_questions())
        site.refresh()
        self.assertEqual(len(btc.anchor_questions()), asked, "asked once, not on every round")

    def test_a_denied_anchor_is_refused_with_the_reason(self):
        btc = Bitcoin(mainnet_headers())
        site, reg = self.site(wrong_period(), btc)
        with self.assertLogs("hashfun.web", "WARNING") as logs:
            site.refresh()
        self.assertEqual(len(logs.output), 1)
        self.assertIn("RULE: not served: btc anchor: btc_anchor_period_time is", logs.output[0])
        coin = site.coins["RULE"]
        self.assertIn("btc anchor: btc_anchor_period_time is", coin.refused)
        for view in (coin.summary(), coin.detail()):  # what the board and the coin page are given
            self.assertEqual(view["error"], coin.refused)
            self.assertNotIn("height", view)  # no height: on no board, and its page shows the error
        self.assertEqual(site.book_chains(), {"btc:main": "BTC"})  # not in the peer-to-peer book
        with self.assertRaisesRegex(ValueError, "RULE is not served here: btc anchor"):
            site.chain_rpc("RULE")  # nor behind the page's chain reads and broadcasts
        site.maker = mock.Mock(forks={"RULE": object()})
        with self.assertRaisesRegex(ValueError, "RULE is not served here: btc anchor"):
            site.quote({"ticker": "RULE", "amount": 1})  # nor quoted by a maker that runs with the site
        site.maker.quote.assert_not_called()
        site.maker = None
        asked = len(btc.anchor_questions())
        site.refresh()
        site.refresh()
        self.assertEqual(len(btc.anchor_questions()), asked, "asked once")
        self.assertEqual(reg.node.method_calls, [], "nothing is read from a refused launch's node")

    def test_a_bitcoin_node_that_cannot_say_yet_is_asked_again(self):
        hdrs = mainnet_headers()
        halfway, later = Bitcoin(hdrs), Bitcoin(hdrs)  # they answer the first question and then go quiet
        halfway.drop, later.drop = "getblockhash", "getblockheader"
        for btc, heal, why in (
                (Bitcoin(hdrs, fail=OSError("connection refused")), lambda b: setattr(b, "fail", None), "does not answer"),
                (halfway, lambda b: setattr(b, "drop", None), "could not ask the Bitcoin node: timed out"),
                (later, lambda b: setattr(b, "drop", None), "could not ask the Bitcoin node: timed out"),
                (Bitcoin(hdrs[:1400]), lambda b: (b.headers.extend(hdrs[1400:]), b.by_hash.update(Bitcoin(hdrs).by_hash)),
                 "the Bitcoin node is at 1399")):
            site, reg = self.site(anchored(), btc)
            with self.assertLogs("hashfun.web", "WARNING") as logs:
                site.refresh()
            self.assertEqual(len(logs.output), 1)
            self.assertIn("RULE: not served until its anchors can be checked", logs.output[0])
            self.assertIn(why, logs.output[0])
            self.assertEqual(site.coins, {})  # neither served nor refused: no verdict yet
            asked = len(btc.asked)
            with self.assertNoLogs("hashfun.web", "WARNING"):
                site.refresh()  # inside the retry window: the Bitcoin node is left alone, and the log too
            self.assertEqual(len(btc.asked), asked)
            site.anchor_retry = 0
            with self.assertNoLogs("hashfun.web", "WARNING"):
                site.refresh()  # still cannot say: asked again, said once
            self.assertEqual(site.coins, {})
            heal(btc)
            site.refresh()
            self.assertIsNone(site.coins["RULE"].refused)
            reg.node.getlaunchinfo.assert_called()

    def test_a_site_with_a_qwencoin_node_asks_it_about_the_qwencoin_anchor(self):
        qh, qstarts = qwen_headers()
        btc, qwen = Bitcoin(mainnet_headers()), qwencoin()
        site, reg = self.site(anchored(), btc, qwen)
        site.refresh()
        self.assertIsNone(site.coins["RULE"].refused)
        self.assertTrue(qwen.anchor_questions(), "the Qwencoin node was asked")
        # a launch whose Qwencoin anchor the node denies is refused like one whose Bitcoin anchor is
        site, reg = self.site(anchored(qwen_anchor_header=qh[8][:76] + bytes(4)), Bitcoin(mainnet_headers()), qwencoin())
        with self.assertLogs("hashfun.web", "WARNING") as logs:
            site.refresh()
        self.assertIn("RULE: not served: qwen anchor: ", logs.output[0])
        self.assertIn("qwen anchor: ", site.coins["RULE"].refused)
        self.assertEqual(reg.node.method_calls, [], "nothing is read from a refused launch's node")
        # without a Qwencoin node the site cannot ask: the launch is served (and its QWEN curve is not mined here)
        site, reg = self.site(anchored(qwen_anchor_header=qh[8][:76] + bytes(4)), Bitcoin(mainnet_headers()))
        site.refresh()
        self.assertIsNone(site.coins["RULE"].refused)

    def test_a_header_the_node_reports_differently_is_a_verdict_not_an_outage(self):
        hdrs = mainnet_headers()
        site, _ = self.site(anchored(), Bitcoin(hdrs, lie=hdrs[1499]))
        with self.assertLogs("hashfun.web", "WARNING"):
            site.refresh()
        self.assertIn("the header in the launch is not the header of Bitcoin block 1500", site.coins["RULE"].refused)


if __name__ == "__main__":
    unittest.main()
