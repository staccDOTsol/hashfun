"""hashfun: one command for the whole stack.

  hashfun launch new ...            create a coin (descriptor + genesis); `launch info` to inspect
  hashfun node add <descriptor>     register a launch on this machine
  hashfun node up [TICKER ...]      start a hashfund node per launch (all registered if none named)
  hashfun node ls                   height, curve progress, graduation, peers
  hashfun node rpc TICKER METHOD [ARGS ...]
  hashfun node down [TICKER ...]
  hashfun mine TICKER --payout ADDR start a pool for the launch and (optionally) a CPU miner on it;
                                    merge-mines every other registered launch that has graduated and,
                                    for launches with a sats leg, pays and proves the Bitcoin owed
  hashfun wallet ... | swap ... | pool ... | proxy ... | electrum ... | board ... | miner ...
                                    the individual tools (same arguments as hashfun-<tool>)

State lives in $HASHFUN_HOME (default ~/.hashfun): launches.json, one datadir per launch.
The node binary is $HASHFUND, else `hashfund` on PATH.
"""
import argparse
import asyncio
import glob
import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from typing import Dict, List, Optional

from . import descriptor as D
from .rpc import RPC, RPCError

TOOLS = {"launch": "launch", "wallet": "wallet", "swap": "swap", "pool": "pool_cli", "proxy": "proxy",
         "electrum": "electrum", "board": "board", "miner": "miner"}


def home() -> str:
    h = os.path.expanduser(os.environ.get("HASHFUN_HOME", "~/.hashfun"))
    os.makedirs(h, exist_ok=True)
    return h


def hashfund_binary() -> str:
    b = os.environ.get("HASHFUND") or shutil.which("hashfund")
    if not b or not os.path.exists(b):
        sys.exit("hashfund binary not found: set HASHFUND=/path/to/hashfund or put it on PATH")
    return b


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Registry:
    """launches.json: ticker -> {descriptor, datadir, rpcport}."""

    def __init__(self):
        self.path = os.path.join(home(), "launches.json")
        self.data: Dict[str, dict] = {}
        if os.path.exists(self.path):
            with open(self.path) as f:
                self.data = json.load(f)

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=1)
        os.replace(tmp, self.path)

    def add(self, descriptor_path: str) -> str:
        d = D.load(descriptor_path)
        base = os.path.join(home(), "launches", f"{d.ticker}-{d.id_hex[:8]}")
        os.makedirs(base, exist_ok=True)
        dst = os.path.join(base, "descriptor.json")
        shutil.copyfile(descriptor_path, dst)
        old = self.data.get(d.ticker)
        if old and old["id"] != d.id_hex:
            sys.exit(f"{d.ticker} is already registered with a different launch id ({old['id'][:16]}...)")
        self.data[d.ticker] = {"id": d.id_hex, "descriptor": dst, "datadir": os.path.join(base, "node"),
                               "rpcport": (old or {}).get("rpcport") or free_port()}
        self.save()
        return d.ticker

    def get(self, ticker: str) -> dict:
        if ticker not in self.data:
            sys.exit(f"unknown launch {ticker}: register it with `hashfun node add <descriptor.json>`")
        return self.data[ticker]

    def pick(self, tickers: List[str]) -> List[str]:
        return tickers or sorted(self.data)

    def desc(self, ticker: str) -> D.Launch:
        return D.load(self.get(ticker)["descriptor"])

    # ---- node control ----
    def rpc(self, ticker: str, timeout: float = 60) -> Optional[RPC]:
        e = self.get(ticker)
        for cookie in glob.glob(os.path.join(e["datadir"], "*", ".cookie")):
            try:
                r = RPC(f"http://127.0.0.1:{e['rpcport']}", cookie_file=cookie, timeout=timeout)
                r.getblockcount()
                return r
            except RPCError:
                return r  # reachable, still warming up
            except Exception:
                pass
        return None

    def up(self, ticker: str, extra: List[str] = ()) -> bool:
        """Start the node if it is not running. True if it was started now."""
        if self.rpc(ticker, timeout=3):
            return False
        e = self.get(ticker)
        os.makedirs(e["datadir"], exist_ok=True)
        args = [hashfund_binary(), f"-datadir={e['datadir']}", f"-launch={e['descriptor']}", "-server=1",
                f"-rpcport={e['rpcport']}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-txindex=1",
                "-printtoconsole=0", *extra]
        with open(os.path.join(e["datadir"], "stderr.log"), "ab") as err:
            p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err, start_new_session=True)
        deadline = time.time() + 120
        while time.time() < deadline:
            if p.poll() is not None:
                with open(os.path.join(e["datadir"], "stderr.log"), "rb") as f:
                    sys.exit(f"hashfund for {ticker} exited: {f.read()[-1500:].decode(errors='replace')}")
            r = self.rpc(ticker, timeout=3)
            if r:
                try:
                    r.getblockcount()
                    return True
                except Exception:
                    pass
            time.sleep(0.3)
        sys.exit(f"hashfund for {ticker} did not come up within 120 s")

    def down(self, ticker: str) -> bool:
        r = self.rpc(ticker, timeout=5)
        if not r:
            return False
        try:
            r.stop()
        except Exception:
            pass
        for _ in range(200):
            if not self.rpc(ticker, timeout=2):
                return True
            time.sleep(0.2)
        return True

    def status(self, ticker: str) -> dict:
        d = self.desc(ticker)
        row = {"ticker": ticker, "id": d.id_hex[:16], "running": False, "rpcport": self.get(ticker)["rpcport"],
               "sats_leg": bool(d.sats_num)}
        r = self.rpc(ticker, timeout=5)
        if not r:
            return row
        try:
            i = r.getlaunchinfo()
            row.update(running=True, height=i["height"], graduated=i["graduated"],
                       curve_pct=round(100 * i["curve_supply"] / d.graduation_tokens, 4),
                       hashes_per_coin=i["hashes_per_coin"], peers=r.getconnectioncount())
        except Exception as e:
            row.update(running=True, error=str(e))
        return row


def cmd_node(a, reg: Registry):
    if a.node_cmd == "add":
        t = reg.add(a.descriptor)
        print(json.dumps({"registered": t, **{k: v for k, v in reg.get(t).items()}}, indent=2))
    elif a.node_cmd == "up":
        print(json.dumps({t: "started" if reg.up(t, a.arg) else "already running" for t in reg.pick(a.tickers)}, indent=2))
    elif a.node_cmd == "down":
        print(json.dumps({t: "stopped" if reg.down(t) else "not running" for t in reg.pick(a.tickers)}, indent=2))
    elif a.node_cmd == "ls":
        print(json.dumps([reg.status(t) for t in reg.pick(a.tickers)], indent=2))
    elif a.node_cmd == "rpc":
        r = reg.rpc(a.ticker)
        if not r:
            sys.exit(f"{a.ticker} is not running: hashfun node up {a.ticker}")

        def conv(x):
            try:
                return json.loads(x)
            except ValueError:
                return x
        try:
            out = r.call(a.method, *[conv(x) for x in a.params])
        except RPCError as e:
            sys.exit(str(e))
        print(out if isinstance(out, str) else json.dumps(out, indent=2))


def build_source(reg: Registry, ticker: str, payout: Optional[str], btc_rpc: Optional[str], btc_hrp: str,
                 max_pay_sats: Optional[int] = None, btc_cookie: Optional[str] = None, btc_wallet: Optional[str] = None):
    """LaunchSource for `ticker`, carrying every other registered, running launch as an aux chain
    (only graduated ones are merge-mined; the pool re-checks each round) and a Settler if the
    launch has a sats leg."""
    from .settler import Settler
    from .stratum import LaunchSource
    d = reg.desc(ticker)
    rpc = reg.rpc(ticker)
    if not rpc:
        sys.exit(f"{ticker} is not running: hashfun node up {ticker}")
    children = {}
    for other in sorted(reg.data):
        if other == ticker:
            continue
        orpc = reg.rpc(other, timeout=5)
        if not orpc:
            continue
        od = reg.desc(other)
        try:
            wallets = orpc.listwallets()
            w = orpc.wallet(wallets[0]) if wallets else None
            addr = w.getnewaddress("", "bech32") if w else None
        except Exception:
            addr = None
        if addr:  # merge-mined rewards need somewhere to go on that chain
            children[other] = {"rpc": orpc, "hrp": od.hrp, "payout": addr}
    settler = None
    if d.sats_num:
        if not btc_rpc:
            sys.exit(f"{ticker} has a sats leg: pass --btc-rpc URL of a funded Bitcoin Core wallet "
                     "(http://user:pass@host:port/wallet/<name>) to pay and prove the Bitcoin owed per block")
        btc = RPC(btc_rpc, cookie_file=btc_cookie)
        if btc_wallet:
            btc = btc.wallet(btc_wallet)
        settler = Settler(rpc, btc, os.path.join(os.path.dirname(reg.get(ticker)["descriptor"]), "settler.json"),
                          max_pay_sats=max_pay_sats)
    return LaunchSource(rpc, d.hrp, d.ticker, default_payout=payout, children=children, settler=settler,
                        yield_hrp=btc_hrp), children, settler


def cmd_mine(a, reg: Registry):
    from .miner import StratumMiner
    from .stratum import StratumServer
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(asctime)s %(name)s %(message)s")
    reg.up(a.ticker)
    src, children, settler = build_source(reg, a.ticker, a.payout, a.btc_rpc, a.btc_hrp,
                                          int(a.max_pay_btc * D.COIN) if a.max_pay_btc else None,
                                          a.btc_cookie, a.btc_wallet)
    host, port = a.listen.rsplit(":", 1)
    user = a.payout + (f",{a.btc_address}" if a.btc_address else "")
    print(json.dumps({"stratum": f"stratum+tcp://{host}:{port}", "user": user, "launch": a.ticker,
                      "merge_mining_candidates": sorted(children), "sats_leg": bool(settler),
                      "cpu_miner": not a.no_cpu}), flush=True)

    async def run():
        srv = StratumServer(src, host, int(port), difficulty=a.difficulty, stats_path=a.stats)
        task = asyncio.ensure_future(srv.serve())
        await asyncio.sleep(0.5)
        try:
            if a.no_cpu:
                await (asyncio.wait_for(task, a.duration) if a.duration else task)
            else:
                res = await StratumMiner("127.0.0.1" if host in ("0.0.0.0", "") else host, int(port), user).run(a.duration)
                print(json.dumps({"miner": res, "blocks": [e for e in src.blocks_found][-20:],
                                  "settler": settler.status() if settler else None}), flush=True)
        except asyncio.TimeoutError:
            pass
        finally:
            task.cancel()
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in TOOLS:
        import importlib
        return importlib.import_module(f"hashfun.{TOOLS[argv[0]]}").main(argv[1:])
    ap = argparse.ArgumentParser(prog="hashfun", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("node", help="run hashfund nodes for registered launches").add_subparsers(dest="node_cmd", required=True)
    p = n.add_parser("add")
    p.add_argument("descriptor")
    for name in ("up", "down", "ls"):
        p = n.add_parser(name)
        p.add_argument("tickers", nargs="*")
        if name == "up":
            p.add_argument("--arg", action="append", default=[], help="extra hashfund argument, e.g. --arg=-addnode=host:port")
    p = n.add_parser("rpc")
    p.add_argument("ticker")
    p.add_argument("method")
    p.add_argument("params", nargs="*")
    p = sub.add_parser("mine", help="pool + optional CPU miner for one launch")
    p.add_argument("ticker")
    p.add_argument("--payout", required=True, help="launch address that receives the coinbase")
    p.add_argument("--btc-address", help="send this miner's BTC yield here instead of to its launch key")
    p.add_argument("--btc-rpc", help="Bitcoin Core wallet RPC URL; required for launches with a sats leg")
    p.add_argument("--btc-cookie", help="Bitcoin Core .cookie file, if the URL has no user:pass")
    p.add_argument("--btc-wallet", help="Bitcoin Core wallet name")
    p.add_argument("--btc-hrp", default="bc")
    p.add_argument("--max-pay-btc", type=float, help="never pay more than this for one block's sats")
    p.add_argument("--listen", default="127.0.0.1:3333")
    p.add_argument("--difficulty", type=float, default=1.0, help="share difficulty")
    p.add_argument("--no-cpu", action="store_true", help="only serve stratum (point ASICs or rented hash at it)")
    p.add_argument("--duration", type=float, help="stop after this many seconds")
    p.add_argument("--stats")
    p.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    reg = Registry()
    if a.cmd == "node":
        cmd_node(a, reg)
    elif a.cmd == "mine":
        cmd_mine(a, reg)


def _sigterm(*_):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _sigterm)
    main()
