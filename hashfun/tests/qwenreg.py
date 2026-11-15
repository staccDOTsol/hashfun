"""A regtest Qwencoin for the tests: a second stock bitcoind on regtest.

Qwencoin is a Bitcoin fork whose regtest is Bitcoin's regtest, unchanged: SHA256d work at the
regtest limit, `bcrt` addresses, the same genesis block, bitcoin-cli's RPC (what Qwencoin changes,
the work function bound to a language model's weights, is its main network's). So for everything a
launch does with a regtest Qwencoin (`qwen_regtest`: header relay, payments, proofs, swaps), any
Bitcoin Core regtest node plays the part. The tests run two of them side by side: one is Bitcoin,
the other is Qwencoin. They share a genesis block and nothing else: neither has a peer, each mines
its own blocks, so a header, a transaction or a proof of one is unknown to the other.

    from hashfun.tests.qwenreg import QwenNode
    q = QwenNode(bitcoind_binary, os.path.join(workdir, "qwencoin"))
    wallet = q.funded_wallet()          # a wallet RPC holding spendable regtest QWEN
    q.mine(2)                           # blocks, when a payment needs confirmations
    Settler(launch_rpc, btc_wallet, state_path, pay_depth=0, qwen_wallet=wallet)
    ...
    q.stop()

A launch made with `descriptor.make(..., test=True)` follows this node as it is: its Qwencoin
anchor is the regtest genesis block, its QWEN leg owes 7000 qwen-sats per hash (the sats leg 5000)
and a payment needs 2 confirmations here (1 on Bitcoin).
"""
import glob
import os
import subprocess
import time
from typing import List, Optional

from hashfun.cli import free_port
from hashfun.rpc import RPC, RPCError

HRP = "bcrt"  # of a regtest Qwencoin's addresses (Qwencoin uses Bitcoin's prefixes on every network)


class QwenNode:
    """A bitcoind on regtest playing the regtest Qwencoin: its own data directory, its own RPC port,
    no peers."""

    def __init__(self, bitcoind: str, datadir: str, rpcport: Optional[int] = None, args: List[str] = ()):
        self.binary, self.datadir = bitcoind, datadir
        self.rpcport = rpcport or free_port()
        os.makedirs(datadir, exist_ok=True)
        self.errlog = os.path.join(datadir, "stderr.log")
        with open(self.errlog, "ab") as err:
            self.proc = subprocess.Popen([bitcoind, "-regtest", f"-datadir={datadir}", "-server=1", "-listen=0", "-connect=0",
                                          "-txindex=1", "-fallbackfee=0.0001", f"-rpcport={self.rpcport}",
                                          "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-printtoconsole=0", *args],
                                         stdout=subprocess.DEVNULL, stderr=err)
        self.url = f"http://127.0.0.1:{self.rpcport}"
        self.cookie = os.path.join(datadir, "regtest", ".cookie")
        deadline = time.time() + 120
        while time.time() < deadline:
            if self.proc.poll() is not None:
                with open(self.errlog, "rb") as f:
                    raise RuntimeError(f"the Qwencoin stand-in exited {self.proc.returncode}: "
                                       f"{f.read()[-1500:].decode(errors='replace')}")
            # a stale cookie from a killed run fails until the node rewrites it: keep trying
            for cookie in glob.glob(os.path.join(datadir, "*", ".cookie")):
                try:
                    rpc = RPC(self.url, cookie_file=cookie)
                    rpc.getblockcount()
                    self.rpc, self.cookie = rpc, cookie
                    return
                except Exception:  # noqa: BLE001  (still starting)
                    pass
            time.sleep(0.2)
        self.proc.kill()
        raise RuntimeError("the Qwencoin stand-in did not start")

    def wallet(self, name: str = "qwen") -> RPC:
        """The node's wallet of that name (made if it is not there, loaded if it is not loaded)."""
        try:
            self.rpc.loadwallet(name)
        except RPCError as e:
            if e.code == -18:  # not found
                self.rpc.createwallet(name)
            elif e.code != -35:  # already loaded
                raise
        return self.rpc.wallet(name)

    def mine(self, n: int = 1, address: Optional[str] = None) -> List[str]:
        """n blocks (to an address of the default wallet unless one is given). Returns their hashes."""
        return self.rpc.generatetoaddress(n, address or self.wallet().getnewaddress("", "bech32"))

    def funded_wallet(self, name: str = "qwen", blocks: int = 110) -> RPC:
        """A wallet with spendable coins: `blocks` blocks mined to it (100 to mature the first)."""
        w = self.wallet(name)
        if w.getbalances()["mine"]["trusted"] < 1:
            self.rpc.generatetoaddress(blocks, w.getnewaddress("", "bech32"))
        return w

    def header(self, height: int) -> bytes:
        return bytes.fromhex(self.rpc.getblockheader(self.rpc.getblockhash(height), False))

    def stop(self):
        try:
            self.rpc.stop()
            self.proc.wait(60)
        except Exception:  # noqa: BLE001
            self.proc.kill()

    def __enter__(self) -> "QwenNode":
        return self

    def __exit__(self, *_):
        self.stop()
