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
from hashfun.tests.test_core import FakeBitcoin, header_time, mainnet_headers, production_launch

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
        self.assertIn("graduated at", cli.mine_chain(binary, path, blocks=90))
        with open(path) as f:
            good = json.load(f)
        self.assertEqual(len(good["blocks"]), 90)
        self.assertTrue(good["state"]["graduated"])
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
        self.assertIn("different sats owed for block 7", changed(lambda d: d["owed"][6].update(owed=d["owed"][6]["owed"] + 1)))
        self.assertIn("different tip", changed(lambda d: d["blocks"].pop()))


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

    def getblockchaininfo(self):
        return {"chain": "main"}

    def anchor_questions(self):
        return [q for q in self.asked if q[0] in ("getblockcount", "getblockhash", "getblockheader")]


def anchored(ticker="RULE", **kw):
    """A production launch (test_core.production_launch: Bitcoin mainnet rules, anchored at block 1500 of
    the stored headers) with a mined genesis, so that its file loads."""
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

    def up(self, ticker, extra=()):
        self.ups += 1
        return False


class AnchorOnRegister(unittest.TestCase):
    """hashfun node add --btc-rpc: a launch file from somebody else is registered only if the user's own
    Bitcoin node says its anchor is true."""

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

    def add(self, d, btc=None):
        """Run `hashfun node add FILE [--btc-rpc URL]`. (what it exited with or None, its stderr)"""
        argv = ["node", "add", self.file(d)] + (["--btc-rpc", "http://u:p@127.0.0.1:1"] if btc else [])
        err, code = io.StringIO(), None
        with mock.patch.object(cli, "RPC", return_value=btc), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(err):
            try:
                cli.main(argv)
            except SystemExit as e:
                code = e.code
        return code, err.getvalue()

    def registered(self):
        return sorted(cli.Registry().data)

    def test_a_true_anchor_is_registered(self):
        btc = Bitcoin(mainnet_headers())
        self.assertEqual(self.add(anchored(), btc), (None, ""))
        self.assertEqual(self.registered(), ["RULE"])
        self.assertTrue(btc.anchor_questions(), "the Bitcoin node was asked")

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
            code, _ = self.add(d, btc)
            self.assertIsInstance(code, str, d.ticker)  # sys.exit(text): the text on stderr, status 1, no traceback
            self.assertTrue(code.startswith(self.file(d) + ": btc anchor: "), code)
            self.assertIn(why, code)
        self.assertEqual(self.registered(), [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "home", "launches")), "nothing of a refused launch is kept")

    def test_without_a_bitcoin_node_nobody_is_asked_and_one_line_says_so(self):
        code, err = self.add(wrong_period("PERI"))
        self.assertIsNone(code)
        self.assertEqual(self.registered(), ["PERI"])
        self.assertEqual(len(err.splitlines()), 1, err)
        self.assertIn("Bitcoin anchor was not checked", err)

    def test_a_launch_on_regtest_bitcoin_is_asked_about_its_block_only(self):
        d = anchored("REGT", btc_regtest=True, btc_anchor_height=0, btc_anchor_header=D.REGTEST_GENESIS_HEADER,
                     btc_anchor_period_time=0)
        btc = Bitcoin([D.REGTEST_GENESIS_HEADER])
        self.assertEqual(self.add(d, btc), (None, ""))
        self.assertEqual(btc.anchor_questions(), [("getblockcount",), ("getblockhash", 0), ("getblockheader", btc.hash(0), False)])
        code, _ = self.add(anchored("MAIN", btc_regtest=True, btc_anchor_height=0, btc_anchor_header=D.REGTEST_GENESIS_HEADER,
                                    btc_anchor_period_time=0), Bitcoin(mainnet_headers()))  # a mainnet node: another network
        self.assertIn("but block 0 on this Bitcoin node's chain is", code)
        self.assertEqual(self.registered(), ["REGT"])


class AnchorBeforeMining(unittest.TestCase):
    """hashfun mine: the Bitcoin node the sats will be paid through is asked before anything is built,
    and a no stops the command before a block can be mined."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hashfun-anchor-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.settler = mock.patch("hashfun.settler.Settler").start()
        self.source = mock.patch("hashfun.stratum.LaunchSource").start()
        self.server = mock.patch("hashfun.stratum.StratumServer").start()
        self.addCleanup(mock.patch.stopall)

    def build(self, d, btc, **kw):
        reg = StubRegistry(d, self.tmp)
        with mock.patch.object(cli, "RPC", return_value=btc):
            try:
                return reg, cli.build_source(reg, d.ticker, "payout", "http://u:p@127.0.0.1:1", "bc", **kw), None
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
        self.source.assert_called_once()
        self.assertIs(built[0], self.source.return_value)

    def test_an_anchor_the_bitcoin_node_denies_builds_nothing(self):
        hdrs = mainnet_headers()
        for d, btc, why in ((wrong_period(), Bitcoin(hdrs), "RULE: btc anchor: btc_anchor_period_time is"),
                            (anchored(), Bitcoin(hdrs[:1400]), "RULE: btc anchor: .*this Bitcoin node is only at 1399"),
                            (anchored(), Bitcoin(hdrs, fail=OSError("connection refused")),
                             "RULE: btc anchor: could not ask the Bitcoin node")):
            reg, built, code = self.build(d, btc)
            self.assertIsNone(built)
            self.assertIsInstance(code, str)
            self.assertRegex(code, why)
            self.settler.assert_not_called()
            self.source.assert_not_called()
            self.assertEqual(reg.node.method_calls, [], "the launch's node was not touched either")

    def test_the_mine_command_stops_before_it_serves_work(self):
        reg = StubRegistry(wrong_period(), self.tmp)
        argv = ["mine", "RULE", "--payout", "rule1qexample", "--btc-rpc", "http://u:p@127.0.0.1:1", "--no-cpu", "--duration", "0.01"]
        with mock.patch.object(cli, "Registry", return_value=reg), mock.patch.object(cli, "RPC", return_value=Bitcoin(mainnet_headers())), \
                contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit) as e:
            cli.main(argv)
        self.assertRegex(str(e.exception.code), "^RULE: btc anchor: btc_anchor_period_time is")
        self.assertEqual(out.getvalue(), "")  # not even the line that announces the stratum address
        self.server.assert_not_called()
        self.settler.assert_not_called()

    def test_the_mine_command_serves_work_on_a_true_anchor(self):
        reg = StubRegistry(anchored(), self.tmp)

        async def serve():
            return None
        self.server.return_value.serve.side_effect = serve
        argv = ["mine", "RULE", "--payout", "rule1qexample", "--btc-rpc", "http://u:p@127.0.0.1:1", "--no-cpu", "--duration", "0.01"]
        with mock.patch.object(cli, "Registry", return_value=reg), mock.patch.object(cli, "RPC", return_value=Bitcoin(mainnet_headers())), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            cli.main(argv)
        self.assertIn('"launch": "RULE"', out.getvalue())
        self.server.assert_called_once()
        self.assertIs(self.server.call_args.args[0], self.source.return_value)


class AnchorOnTheSite(unittest.TestCase):
    """hashfun web: a registered launch is served only once the site's own Bitcoin node has said its
    anchor is true; a launch it denies is shown as refused, with the reason, and nothing is read from it."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hashfun-anchor-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def site(self, d, btc):
        reg = StubRegistry(d, self.tmp)
        return web.Site(btc, reg), reg

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
            self.assertIn("RULE: not served until its Bitcoin anchor can be checked", logs.output[0])
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

    def test_a_header_the_node_reports_differently_is_a_verdict_not_an_outage(self):
        hdrs = mainnet_headers()
        site, _ = self.site(anchored(), Bitcoin(hdrs, lie=hdrs[1499]))
        with self.assertLogs("hashfun.web", "WARNING"):
            site.refresh()
        self.assertIn("the header in the launch is not the header of Bitcoin block 1500", site.coins["RULE"].refused)


if __name__ == "__main__":
    unittest.main()
