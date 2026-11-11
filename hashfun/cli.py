"""hashfun: one command for the whole stack.

  hashfun launch new ...            create a coin (descriptor + genesis); `launch info` to inspect
  hashfun node add <descriptor>     register a launch on this machine (--peer host:port of a node to join)
  hashfun node up [TICKER ...]      start a hashfund node per launch (all registered if none named);
                                    --first for the first node of a new launch (it has no peers yet)
  hashfun node ls                   height, curve progress, graduation, peers
  hashfun node rpc TICKER METHOD [ARGS ...]
  hashfun node down [TICKER ...]
  hashfun mine TICKER --payout ADDR start a pool for the launch and (optionally) a CPU miner on it;
                                    merge-mines every other registered launch that has graduated and
                                    pays and proves the Bitcoin each block owes (needs --btc-rpc)
  hashfun web --btc-rpc URL         the site: board, coin pages, launch form, swaps signed in the browser
  hashfun wallet ... | swap ... | pool ... | proxy ... | electrum ... | board ... | miner ...
                                    the individual tools (same arguments as hashfun-<tool>)

  hashfun doctor                    which node binary this machine gets, and a self-test of it (seconds)

State lives in $HASHFUN_HOME (default ~/.hashfun): launches.json, one datadir per launch.
The node binary (hashfund) is picked for this machine's system and processor from the ones the
package ships: macOS or Linux, Intel/AMD or ARM. $HASHFUND overrides the choice.
"""
import argparse
import asyncio
import glob
import json
import logging
import os
import platform
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
         "electrum": "electrum", "board": "board", "miner": "miner", "web": "web"}


def home() -> str:
    h = os.path.expanduser(os.environ.get("HASHFUN_HOME", "~/.hashfun"))
    os.makedirs(h, exist_ok=True)
    return h


def platform_target() -> Optional[str]:
    """This machine, named as the package names its node binaries: linux-x64, linux-arm64,
    darwin-x64, darwin-arm64. None for anything else."""
    system = {"linux": "linux", "darwin": "darwin"}.get(sys.platform)
    cpu = {"x86_64": "x64", "amd64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine().lower())
    if system == "darwin" and cpu == "x64":
        # An Intel build of Python on an Apple silicon Mac runs translated and reports x86_64: the
        # machine itself is ARM and gets the ARM node.
        try:
            if subprocess.run(["sysctl", "-n", "sysctl.proc_translated"], capture_output=True, text=True, timeout=5).stdout.strip() == "1":
                cpu = "arm64"
        except (OSError, subprocess.SubprocessError):
            pass
    return f"{system}-{cpu}" if system and cpu else None


def hashfund_candidates() -> List[tuple]:
    """Where this machine's hashfund may be, best first: (what it is, path)."""
    here = os.path.dirname(os.path.abspath(__file__))
    t, out = platform_target(), []
    if t:
        # installed from npm: <package>/py/hashfun/cli.py beside <package>/prebuilt/<target>/hashfund
        out.append((f"shipped with the package for {t}", os.path.join(here, "..", "..", "prebuilt", t, "hashfund")))
        # a source checkout: hashfun/cli.py, with the package's binaries and a developer's own build
        out.append((f"built in this checkout for {t}", os.path.join(here, "..", "contrib", "hashfun", "npm", "prebuilt", t, "hashfund")))
    out.append(("this checkout's own build", os.path.join(here, "..", "build", "bin", "hashfund")))
    on_path = shutil.which("hashfund")
    if on_path:
        out.append(("on PATH", on_path))
    return [(why, os.path.normpath(p)) for why, p in out]


def hashfund_choice() -> tuple:
    """(path, why) of the node binary to run. $HASHFUND is an order, not a hint: when it is set
    nothing else is tried."""
    forced = os.environ.get("HASHFUND")
    if forced:
        if not os.path.isfile(forced):
            sys.exit(f"HASHFUND={forced}: no such file")
        return forced, "$HASHFUND"
    for why, p in hashfund_candidates():
        if os.path.isfile(p) and not os.access(p, os.X_OK):
            try:
                os.chmod(p, 0o755)  # some unpackers drop the executable bit
            except OSError:
                sys.exit(f"{p} ({why}) is not executable: chmod +x it")
        if os.path.isfile(p):
            return p, why
    t = platform_target()
    if not t:
        sys.exit(f"hashfun has no node binary for this machine ({sys.platform} {platform.machine()}): it ships for macOS and "
                 "Linux on Intel/AMD and ARM processors. On Windows, run it inside WSL. Or build hashfund yourself and "
                 "set HASHFUND=/path/to/hashfund")
    sys.exit(f"no hashfund for {t} here: this copy of hashfun came without its node binaries. Install the npm package "
             "(npm i -g hashfun), or build one (bash contrib/hashfun/dist/build.sh in the source tree), or set "
             "HASHFUND=/path/to/hashfund")


def hashfund_binary() -> str:
    return hashfund_choice()[0]


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

    def add(self, descriptor_path: str, peers=(), p2p_port: Optional[int] = None) -> str:
        d = D.load(descriptor_path)
        try:
            from .meta import MetaError, check
            check(d)  # a picture that is not the one the launch id commits to: refuse the file
        except MetaError as e:
            sys.exit(f"{descriptor_path}: {e}")
        base = os.path.join(home(), "launches", f"{d.ticker}-{d.id_hex[:8]}")
        os.makedirs(base, exist_ok=True)
        dst = os.path.join(base, "descriptor.json")
        shutil.copyfile(descriptor_path, dst)
        old = self.data.get(d.ticker)
        if old and old["id"] != d.id_hex:
            sys.exit(f"{d.ticker} is already registered with a different launch id ({old['id'][:16]}...)")
        self.data[d.ticker] = {"id": d.id_hex, "descriptor": dst, "datadir": os.path.join(base, "node"),
                               "rpcport": (old or {}).get("rpcport") or free_port(),
                               "peers": sorted(set((old or {}).get("peers", [])) | set(peers)),
                               "p2pport": p2p_port or (old or {}).get("p2pport")}
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
                "-printtoconsole=0", *[f"-addnode={x}" for x in e.get("peers", [])],
                *([f"-port={e['p2pport']}"] if e.get("p2pport") else []), *extra]
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
               }
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
        t = reg.add(a.descriptor, a.peer, a.p2p_port)
        print(json.dumps({"registered": t, **{k: v for k, v in reg.get(t).items()}}, indent=2))
    elif a.node_cmd == "up":
        extra = list(a.arg) + (["-minewithoutpeers"] if a.first else [])
        print(json.dumps({t: "started" if reg.up(t, extra) else "already running" for t in reg.pick(a.tickers)}, indent=2))
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


class _TestNode:
    """A hashfund on a launch file, in a temporary directory, for the length of a `with`."""

    def __init__(self, binary: str, launch_text: str):
        import tempfile
        self.binary, self.text, self.tmp, self.p = binary, launch_text, tempfile.mkdtemp(prefix="hashfun-doctor-"), None

    def __enter__(self) -> RPC:
        desc, datadir, port = os.path.join(self.tmp, "launch.json"), os.path.join(self.tmp, "node"), free_port()
        with open(desc, "w") as f:
            f.write(self.text)
        os.makedirs(datadir)
        with open(os.path.join(self.tmp, "stderr.log"), "wb") as err:
            self.p = subprocess.Popen([self.binary, f"-datadir={datadir}", f"-launch={desc}", "-server=1", f"-rpcport={port}",
                                       "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-listen=0", "-printtoconsole=0"],
                                      stdout=subprocess.DEVNULL, stderr=err)
        deadline = time.time() + 60
        while True:
            if self.p.poll() is not None:
                with open(os.path.join(self.tmp, "stderr.log"), "rb") as f:
                    raise RuntimeError(f"the node exited ({self.p.returncode}): "
                                       f"{f.read()[-800:].decode(errors='replace').strip() or 'no message'}")
            if time.time() > deadline:
                raise RuntimeError("the node did not answer within 60 s")
            for cookie in glob.glob(os.path.join(datadir, "*", ".cookie")):
                try:
                    r = RPC(f"http://127.0.0.1:{port}", cookie_file=cookie, timeout=30)
                    r.getblockcount()
                    return r
                except Exception:  # noqa: BLE001  (still starting)
                    pass
            time.sleep(0.2)

    def __exit__(self, kind, *_):
        try:
            if self.p is not None and self.p.poll() is None:
                if kind is None:
                    self.p.terminate()  # SIGTERM is a clean shutdown for the node
                    try:
                        if self.p.wait(60) != 0:
                            raise RuntimeError(f"the node did not stop cleanly (exit {self.p.returncode})")
                    except subprocess.TimeoutExpired:
                        self.p.kill()
                        raise RuntimeError("the node did not stop within 60 s") from None
                else:
                    self.p.kill()
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)


def _test_launch(name: str, graduation_hashes: int):
    """A launch only a test would make: the easiest proof of work there is. (descriptor, payout script)."""
    from .crypto import hash160, pubkey_from_priv, random_priv
    spk = b"\x00\x14" + hash160(pubkey_from_priv(random_priv()))
    d = D.make(name, "DOC", spk, graduation_hashes, test=True, pow_limit_bits=0x207FFFFF, target_spacing=10,
               lwma_window=10, genesis_time=int(time.time()) - 7200)
    d.grind_genesis()
    return d, spk


def _check_mints(rpc: RPC, d, upto: int):
    """The node's arithmetic against this CLI's own copy of the consensus rules, block by block."""
    work = 0  # the curve counts work above the genesis block
    for h in range(1, upto + 1):
        blk = rpc.getblock(rpc.getblockhash(h), 2)
        bits = int(blk["bits"], 16)
        minted = sum(round(v["value"] * D.COIN) for v in blk["tx"][0]["vout"])
        if minted != d.subsidy(work, bits, h):
            raise RuntimeError(f"block {h} minted {minted} units; the rules say {d.subsidy(work, bits, h)}")
        if not blk["tx"][0]["vin"][0]["coinbase"].startswith(d.coinbase_prefix(h).hex()):
            raise RuntimeError(f"block {h}: its coinbase does not start with the height and this launch's id")
        work += D.work_from_bits(bits)


def self_test(binary: str) -> str:
    """Start the node on a throwaway test launch, mine on its curve, read what a block owes, stop.
    Returns one line on success; raises RuntimeError with what went wrong."""
    from .ser import script_to_address
    t0 = time.time()
    d, spk = _test_launch("doctor self-test", 2 * 10**6)
    with _TestNode(binary, d.dumps()) as rpc:
        if rpc.getblockhash(0) != d.genesis_hash:
            raise RuntimeError("the node's genesis block is not the one the launch file commits to")
        addr, mined = script_to_address(spk, d.hrp), 0
        for _ in range(200):
            mined += len(rpc.generatetoaddress(1, addr, 1_000_000))
            if mined >= 5:
                break
        info, owed = rpc.getlaunchinfo(), rpc.getmintobligation(1)
        if mined < 5 or info["height"] != mined:
            raise RuntimeError(f"mined {mined} blocks but the node is at height {info['height']}")
        _check_mints(rpc, d, mined)
        if owed.get("curve") is not True or not owed.get("owed", 0) > 0:
            raise RuntimeError(f"block 1 should owe sats on the curve: {owed}")
    return (f"node up on a test launch, {mined} blocks mined and every mint equal to the rules' own arithmetic, "
            f"sats owed per block readable, clean stop ({time.time() - t0:.1f} s)")


# ---- one machine's chain, checked by another machine's node --------------------------------------
# The node ships built by different compilers for different processors. They must agree on every
# rule or the network splits. `doctor --mine FILE` mines a short chain (up the curve, through
# graduation, into the tail) and writes it down with what this node concluded from it;
# `doctor --replay FILE` feeds those blocks to this machine's node and requires the same conclusions.
_UTXO_KEYS = ("height", "bestblock", "txouts", "total_amount", "hash_serialized_3")
_INFO_KEYS = ("launch_id", "height", "work", "curve_supply", "tail_minted", "supply", "graduated", "graduation_height")


def _conclusions(rpc: RPC, height: int) -> dict:
    utxo, info = rpc.gettxoutsetinfo(), rpc.getlaunchinfo()
    return {"tip": rpc.getbestblockhash(), "utxo": {k: utxo.get(k) for k in _UTXO_KEYS},
            "state": {k: info.get(k) for k in _INFO_KEYS},
            "owed": [rpc.getmintobligation(h) for h in range(1, height + 1)]}


def mine_chain(binary: str, path: str, blocks: int = 120) -> str:
    from .ser import script_to_address
    d, spk = _test_launch("doctor chain", 120)  # graduates after about 60 blocks at 2 hashes a block
    with _TestNode(binary, d.dumps()) as rpc:
        addr, t = script_to_address(spk, d.hrp), d.genesis_time
        for _ in range(blocks):
            t += d.target_spacing
            rpc.setmocktime(t)
            while not rpc.generatetoaddress(1, addr, 1_000_000):
                pass
        _check_mints(rpc, d, blocks)
        out = {"hashfun_chain": 1, "by": {"target": platform_target(), "hashfund": _version_line(binary)},
               "launch": json.loads(d.dumps()), "blocks": [rpc.getblock(rpc.getblockhash(h), 0) for h in range(1, blocks + 1)],
               **_conclusions(rpc, blocks)}
    if not out["state"]["graduated"] or not 0 < out["state"]["graduation_height"] < blocks:
        raise RuntimeError(f"the test chain was meant to graduate on the way: {out['state']}")
    with open(path, "w") as f:
        json.dump(out, f)
    return (f"{blocks} blocks mined on a test launch (graduated at {out['state']['graduation_height']}), every mint equal to "
            f"the rules' own arithmetic; written with this node's conclusions to {path}")


def replay_chain(binary: str, path: str) -> str:
    with open(path) as f:
        data = json.load(f)
    if data.get("hashfun_chain") != 1:
        raise RuntimeError(f"{path} is not a chain written by `hashfun doctor --mine`")
    with _TestNode(binary, json.dumps(data["launch"])) as rpc:
        for h, raw in enumerate(data["blocks"], 1):
            r = rpc.submitblock(raw)
            if r is not None:
                raise RuntimeError(f"this node rejects block {h} of that chain: {r}")
        mine = _conclusions(rpc, len(data["blocks"]))
    for part in ("tip", "utxo", "state"):
        if mine[part] != data[part]:
            raise RuntimeError(f"same blocks, different {part}: here {json.dumps(mine[part])}, there {json.dumps(data[part])}")
    for h, (a, b) in enumerate(zip(mine["owed"], data["owed"]), 1):
        if a != b:
            raise RuntimeError(f"same blocks, different sats owed for block {h}: here {json.dumps(a)}, there {json.dumps(b)}")
    by = data.get("by", {})
    return (f"{len(data['blocks'])} blocks mined by {by.get('target')} ({by.get('hashfund')}) accepted here; same tip, same UTXO set, "
            f"same curve state (graduated at {mine['state'].get('graduation_height')}), same sats owed for every block")


def _version_line(binary: str) -> str:
    r = subprocess.run([binary, "-version"], capture_output=True, text=True, timeout=60)
    text = (r.stdout or r.stderr).strip()
    return text.splitlines()[0] if text else f"exit {r.returncode}, no output"


def cmd_doctor(a) -> int:
    """What this machine will run, checked by running it."""
    import hashlib
    rows, bad = [], False

    def row(name, value, ok=True):
        nonlocal bad
        bad = bad or not ok
        rows.append((name, value if ok else "FAILED: " + value))
    t = platform_target()
    row("machine", f"{t} ({platform.system()} {platform.release()}, {platform.machine()})" if t
        else f"{sys.platform} {platform.machine()}: not a platform hashfun ships a node for", bool(t))
    row("python", f"{platform.python_version()} at {sys.executable}" + ("" if hasattr(hashlib, "scrypt") else ": built without scrypt"),
        sys.version_info >= (3, 10) and hasattr(hashlib, "scrypt"))
    node = shutil.which("node")
    if node:
        v = subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip()
        ok = v.lstrip("v").split(".")[0].isdigit() and int(v.lstrip("v").split(".")[0]) >= 18
        row("node (for hashfun book)", f"{v} at {node}" + ("" if ok else ": 18 or newer is needed"), ok)
    else:
        rows.append(("node (for hashfun book)", "not installed: only `hashfun book` needs it"))
    binary = None
    try:
        binary, why = hashfund_choice()
        row("hashfund", f"{binary} ({why})")
    except SystemExit as e:
        row("hashfund", str(e), False)
    if binary:
        try:
            r = subprocess.run([binary, "-version"], capture_output=True, text=True, timeout=60)
            first = (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr).strip() else f"exit {r.returncode}, no output"
            row("it runs", first, r.returncode == 0)
        except (OSError, subprocess.SubprocessError) as e:
            row("it runs", f"{e}" + (": this file is for another kind of machine" if getattr(e, "errno", 0) == 8 else ""), False)
        if not bad and not a.quick:
            try:
                row("self-test", self_test(binary))
            except Exception as e:  # noqa: BLE001
                row("self-test", str(e), False)
        for name, fn, path in (("chain mined", mine_chain, a.mine), ("chain replayed", replay_chain, a.replay)):
            if not bad and path:
                try:
                    row(name, fn(binary, path))
                except Exception as e:  # noqa: BLE001
                    row(name, str(e), False)
    width = max(len(n) for n, _ in rows)
    for n, v in rows:
        print(f"{n.ljust(width)}  {v}")
    print("\nall good" if not bad else "\nnot ready: see FAILED above", file=sys.stdout if not bad else sys.stderr)
    return 1 if bad else 0


def build_source(reg: Registry, ticker: str, payout: Optional[str], btc_rpc: Optional[str], btc_hrp: str,
                 max_pay_sats: Optional[int] = None, btc_cookie: Optional[str] = None, btc_wallet: Optional[str] = None,
                 pay_depth: int = 12):
    """LaunchSource for `ticker`, carrying every other registered, running launch as an aux chain
    (only graduated ones are merge-mined; the pool re-checks each round) and the Settler that pays
    and proves the Bitcoin each curve block owes."""
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
    # Every curve block owes Bitcoin, so mining always needs a funded Bitcoin wallet.
    if not btc_rpc:
        sys.exit("pass --btc-rpc URL of a funded Bitcoin Core wallet (http://user:pass@host:port, plus "
                 "--btc-wallet NAME): each block mined on the curve owes sats, paid and proven automatically")
    btc = RPC(btc_rpc, cookie_file=btc_cookie)
    if btc_wallet:
        btc = btc.wallet(btc_wallet)
    settler = Settler(rpc, btc, os.path.join(os.path.dirname(reg.get(ticker)["descriptor"]), "settler.json"),
                      max_pay_sats=max_pay_sats, pay_depth=pay_depth)
    return LaunchSource(rpc, d.hrp, d.ticker, default_payout=payout, children=children, settler=settler,
                        yield_hrp=btc_hrp), children, settler


def cmd_mine(a, reg: Registry):
    from .miner import StratumMiner
    from .stratum import StratumServer
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(asctime)s %(name)s %(message)s")
    reg.up(a.ticker)
    src, children, settler = build_source(reg, a.ticker, a.payout, a.btc_rpc, a.btc_hrp,
                                          int(a.max_pay_btc * D.COIN) if a.max_pay_btc else None,
                                          a.btc_cookie, a.btc_wallet, a.pay_depth)
    host, port = a.listen.rsplit(":", 1)
    user = a.payout + (f",{a.btc_address}" if a.btc_address else "")
    print(json.dumps({"stratum": f"stratum+tcp://{host}:{port}", "user": user, "launch": a.ticker,
                      "merge_mining_candidates": sorted(children),
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
    if argv and argv[0] == "book":  # the page's peer-to-peer engine, hosted by node (hashfun/web/src/maker.mjs)
        node = shutil.which("node")
        if not node:
            sys.exit("hashfun book runs under node (18 or newer): install it, or use the npm package")
        os.execv(node, [node, os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "maker.cjs"), *argv[1:]])
    if argv and argv[0] in TOOLS:
        import importlib
        return importlib.import_module(f"hashfun.{TOOLS[argv[0]]}").main(argv[1:])
    ap = argparse.ArgumentParser(prog="hashfun", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("node", help="run hashfund nodes for registered launches").add_subparsers(dest="node_cmd", required=True)
    p = n.add_parser("add")
    p.add_argument("descriptor")
    p.add_argument("--peer", action="append", default=[], help="host:port of a node of this launch to connect to")
    p.add_argument("--p2p-port", type=int, help="listen here instead of the launch's own port")
    for name in ("up", "down", "ls"):
        p = n.add_parser(name)
        p.add_argument("tickers", nargs="*")
        if name == "up":
            p.add_argument("--arg", action="append", default=[], help="extra hashfund argument, e.g. --arg=-addnode=host:port")
            p.add_argument("--first", action="store_true",
                           help="first node of a new launch: serve mining work with no peers connected")
    p = n.add_parser("rpc")
    p.add_argument("ticker")
    p.add_argument("method")
    p.add_argument("params", nargs="*")
    p = sub.add_parser("mine", help="pool + optional CPU miner for one launch")
    p.add_argument("ticker")
    p.add_argument("--payout", required=True, help="launch address that receives the coinbase")
    p.add_argument("--btc-address", help="send this miner's BTC yield here instead of to its launch key")
    p.add_argument("--btc-rpc", required=True, help="Bitcoin Core RPC URL of a funded wallet (pays the sats each block owes)")
    p.add_argument("--btc-cookie", help="Bitcoin Core .cookie file, if the URL has no user:pass")
    p.add_argument("--btc-wallet", help="Bitcoin Core wallet name")
    p.add_argument("--btc-hrp", default="bc")
    p.add_argument("--max-pay-btc", type=float, help="never pay more than this for one block's sats")
    p.add_argument("--pay-depth", type=int, default=12,
                   help="pay a block's sats once it is this many blocks deep (reorgs deeper than depth-6 can cost a payment)")
    p.add_argument("--listen", default="127.0.0.1:3333")
    p.add_argument("--difficulty", type=float, default=1.0, help="share difficulty")
    p.add_argument("--no-cpu", action="store_true", help="only serve stratum (point ASICs or rented hash at it)")
    p.add_argument("--duration", type=float, help="stop after this many seconds")
    p.add_argument("--stats")
    p.add_argument("-v", "--verbose", action="store_true")
    p = sub.add_parser("doctor", help="which hashfund this machine gets, and a self-test of it")
    p.add_argument("--quick", action="store_true", help="skip the self-test (no node is started)")
    p.add_argument("--mine", metavar="FILE", help="also mine a short test chain and write it, with this node's conclusions, to FILE")
    p.add_argument("--replay", metavar="FILE", help="also replay a chain another machine wrote with --mine: this node must "
                                                    "accept every block and reach the same conclusions")
    a = ap.parse_args(argv)
    if a.cmd == "doctor":
        return cmd_doctor(a)
    reg = Registry()
    if a.cmd == "node":
        cmd_node(a, reg)
    elif a.cmd == "mine":
        cmd_mine(a, reg)


def _sigterm(*_):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _sigterm)
    sys.exit(main())
