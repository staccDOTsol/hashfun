"""Which node binary the CLI runs on which machine.

The npm package lays itself out as <package>/py/hashfun/*.py beside <package>/prebuilt/<target>/hashfund;
these tests build that layout in a temporary directory with a stand-in binary and ask the CLI what it
would run."""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from hashfun import cli

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


if __name__ == "__main__":
    unittest.main()
