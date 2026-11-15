"""hashfun: one command for the whole stack.

  hashfun launch new ...            create a coin (descriptor + genesis); `launch info` to inspect
  hashfun node add <descriptor>     register a launch on this machine (--peer host:port of a node to join;
                                    --btc-rpc URL / --qwen-rpc URL first ask your Bitcoin / Qwencoin node
                                    whether the launch's anchor on that chain is true, as `hashfun mine`
                                    does before its first block)
  hashfun node up [TICKER ...]      start a hashfund node per launch (all registered if none named);
                                    --first for the first node of a new launch (it has no peers yet)
  hashfun node ls                   height, both curves' progress, graduation, peers
  hashfun node rpc TICKER METHOD [ARGS ...]
  hashfun node down [TICKER ...]
  hashfun mine TICKER --payout ADDR start a pool for the launch and (optionally) a CPU miner on it;
                                    merge-mines every other registered launch that has graduated and
                                    pays and proves what each block owes: sats on Bitcoin for the BTC
                                    curve (--btc-rpc), qwen on Qwencoin for the QWEN curve (--qwen-rpc).
                                    --curve btc|qwen says which one to mine
  hashfun qwork fetch|check|path    Qwencoin's work table (528 MB, once per machine): a node of a launch
                                    needs it to check the Qwencoin headers relayed into the launch
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
import random
import shutil
import signal
import socket
import subprocess
import sys
import time
from typing import Dict, List, Optional

from . import descriptor as D
from .btclight import connect as btc_light, is_light_url
from .rpc import RPC, RPCError

TOOLS = {"launch": "launch", "wallet": "wallet", "swap": "swap", "pool": "pool_cli", "proxy": "proxy",
         "electrum": "electrum", "board": "board", "miner": "miner", "web": "web", "qwork": "qwork"}


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


_HANDED_OUT = set()


def free_port() -> int:
    """A port to listen on later: free now, and under the range systems hand out to outgoing
    connections (Linux from 32768, macOS from 49152). A port the system picks itself (bind to 0)
    comes from that range, and can be taken as some connection's source port before the node that
    was promised it gets to listen."""
    for _ in range(400):
        p = random.randrange(20000, 32768)
        if p in _HANDED_OUT:
            continue
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
        except OSError:
            continue
        finally:
            s.close()
        _HANDED_OUT.add(p)
        return p
    raise RuntimeError("no free port between 20000 and 32767")


def port_in_use(port: int) -> bool:
    """Is something on this machine listening on that port now? Another program, or a node of the
    same launch started from another folder: a launch's ports come from its id, so they are the
    same numbers on every machine."""
    for host in ("127.0.0.1", "0.0.0.0"):
        s = socket.socket()
        try:
            # (reuse: a port whose last listener has just gone is free; one that is listened on is not)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
        except OSError:
            return True
        finally:
            s.close()
    return False


def check_btc_anchor(d: D.Launch, btc, what: str):
    """Stop (exit, with the reason) unless the Bitcoin node `btc` says the launch's Bitcoin anchor is
    true: the header of the block at that height on its chain, with the right difficulty-period start.

    The launch's whole view of Bitcoin grows from that anchor. On a wrong one, payments made on the
    real chain can never be proven on the launch, and every curve coinbase that owes sats is lost; a
    wrong period start works for up to two weeks and then fails the same way. So the tools ask before
    they register a launch from a file (given a Bitcoin node) and before they mine one, and they
    treat a Bitcoin node that does not answer as not having said yes. Once per launch per run."""
    try:
        D.check_anchor(d, btc)
    except D.DescriptorError as e:
        sys.exit(f"{what}: {e}")


def check_qwen_anchor(d: D.Launch, qwen, what: str):
    """The same for the launch's Qwencoin anchor and a Qwencoin node. Here the node's word is all
    there is: a launch file cannot show that its Qwencoin anchor is a Qwencoin block at all (that
    takes the chain's weights), so a file from someone else is a claim until a Qwencoin node, or the
    launch's own hashfund at its start, has looked."""
    try:
        D.check_qwen_anchor(d, qwen)
    except D.DescriptorError as e:
        sys.exit(f"{what}: {e}")


def qwork_args(d: D.Launch, what: str, fetch: bool = False) -> List[str]:
    """What a hashfund of this launch needs on its command line for the Qwencoin relay: nothing on a
    regtest Qwencoin, -qwork=<the table> on the real one. fetch: download the table (528 MB, once per
    machine) if it is not there; otherwise stop and say how to get it."""
    if d.qwen_regtest:
        return []
    from . import qwork
    path = qwork.default_path()
    why = qwork.quick_problem(path)
    if why and fetch:
        try:
            qwork.fetch(path, say=lambda t: print(t, file=sys.stderr, flush=True))
        except RuntimeError as e:
            sys.exit(f"{what}: {e}")
    elif why:
        sys.exit(f"{what}: its QWEN leg follows the real Qwencoin, and a node needs that chain's work table to check the "
                 f"Qwencoin headers relayed into the launch: {why}. Get it once with `hashfun qwork fetch` (528 MB), or copy "
                 "qwork.bin from a Qwencoin node's folder there")
    return [f"-qwork={path}"]


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

    def add(self, descriptor_path: str, peers=(), p2p_port: Optional[int] = None, btc=None, qwen=None) -> str:
        """Register a launch file. btc / qwen: an RPC of the Bitcoin / the Qwencoin network the launch
        follows; with it the launch's anchor on that chain is checked against that node first (see
        check_btc_anchor, check_qwen_anchor), and a launch that fails is not registered."""
        d = D.load(descriptor_path)
        try:
            from .meta import MetaError, check
            check(d)  # a picture that is not the one the launch id commits to: refuse the file
        except MetaError as e:
            sys.exit(f"{descriptor_path}: {e}")
        if btc is not None:
            check_btc_anchor(d, btc, descriptor_path)
        if qwen is not None:
            check_qwen_anchor(d, qwen, descriptor_path)
        base = os.path.join(home(), "launches", f"{d.ticker}-{d.id_hex[:8]}")
        os.makedirs(base, exist_ok=True)
        dst = os.path.join(base, "descriptor.json")
        shutil.copyfile(descriptor_path, dst)
        old = self.data.get(d.ticker)
        if old and old["id"] != d.id_hex:
            sys.exit(f"{d.ticker} is already registered with a different launch id ({old['id'][:16]}...)")
        # The RPC port: the one already registered; else the launch's own (one under its P2P port),
        # unless another registered launch has it or something on this machine listens there; else
        # any free one that is not this launch's P2P port. The P2P port: the one asked for; else the
        # one already registered; else the launch's own (not written down), unless something on this
        # machine listens there, and then a free one. A node whose port is taken does not start, and
        # nothing about a launch depends on which port its node has here.
        p2pport = p2p_port or (old or {}).get("p2pport")
        if not old and not p2pport and port_in_use(d.p2p):
            p2pport = free_port()
        rpcport = (old or {}).get("rpcport")
        taken = {e.get("rpcport") for t, e in self.data.items() if t != d.ticker} | {p2pport or d.p2p}
        if not rpcport:
            rpcport = d.rpc
            while rpcport in taken or port_in_use(rpcport):
                rpcport = free_port()
        self.data[d.ticker] = {"id": d.id_hex, "descriptor": dst, "datadir": os.path.join(base, "node"),
                               "rpcport": rpcport,
                               "peers": sorted(set((old or {}).get("peers", [])) | set(peers)),
                               "p2pport": p2pport}
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

    def up(self, ticker: str, extra: List[str] = (), fetch_table: bool = False) -> bool:
        """Start the node if it is not running. True if it was started now. A launch that follows the
        real Qwencoin is started with that chain's work table (qwork_args); fetch_table: download it
        if this machine does not have it yet."""
        if self.rpc(ticker, timeout=3):
            return False
        e = self.get(ticker)
        os.makedirs(e["datadir"], exist_ok=True)
        table = [] if any(str(x).startswith("-qwork=") for x in extra) else qwork_args(self.desc(ticker), ticker, fetch_table)
        args = [hashfund_binary(), f"-datadir={e['datadir']}", f"-launch={e['descriptor']}", "-server=1",
                f"-rpcport={e['rpcport']}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-txindex=1",
                "-printtoconsole=0", *table, *[f"-addnode={x}" for x in e.get("peers", [])],
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
            curves = i.get("curves") or {}
            q = D.quote_summary(i)
            row.update(running=True, height=i["height"], graduated=i["graduated"], graduated_by=i.get("graduated_by"),
                       # each curve on its own: how much of it is sold, and its price point (base units of
                       # its quote per coin: sats on the BTC curve, qwen-sats on the QWEN curve)
                       curves={c: {"pct": round(100 * curves[c]["supply"] / d.graduation_tokens, 4),
                                   "price_per_coin": curves[c]["owed_per_coin"], "blocks": curves[c]["blocks"]}
                               for c in D.QUOTES if c in curves},
                       implied_qwen_sats=q["implied_qwen_sats"], implied_is=q["bound"], peers=r.getconnectioncount())
        except Exception as e:
            row.update(running=True, error=str(e))
        return row


def cmd_node(a, reg: Registry):
    if a.node_cmd == "add":
        nodes = {}
        for quote, chain in (("btc", "Bitcoin"), ("qwen", "Qwencoin")):
            url = getattr(a, f"{quote}_rpc")
            if url:
                try:
                    # (Bitcoin may be electrums://HOST:PORT,HOST:PORT: Electrum servers, no node; hashfun.btclight)
                    nodes[quote] = (btc_light(url) if quote == "btc" and is_light_url(url) else
                                    RPC(url, cookie_file=getattr(a, f"{quote}_cookie")))
                except Exception as e:  # noqa: BLE001  (a URL that is not one, a cookie file that is not there)
                    sys.exit(f"--{quote}-rpc: {e}")
            else:
                print(f"note: the launch's {chain} anchor was not checked (no --{quote}-rpc URL of a {chain} node). "
                      "`hashfun mine` checks it before it mines with a wallet of that chain.", file=sys.stderr)
        t = reg.add(a.descriptor, a.peer, a.p2p_port, btc=nodes.get("btc"), qwen=nodes.get("qwen"))
        print(json.dumps({"registered": t, **{k: v for k, v in reg.get(t).items()}}, indent=2))
    elif a.node_cmd == "up":
        extra = list(a.arg) + (["-minewithoutpeers"] if a.first else [])
        print(json.dumps({t: "started" if reg.up(t, extra, fetch_table=True) else "already running"
                          for t in reg.pick(a.tickers)}, indent=2))
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


def _check_mints(rpc: RPC, d, upto: int) -> dict:
    """The node's arithmetic against this CLI's own copy of the consensus rules, block by block: what
    each block mints on the curve its header puts it on, and what it owes in that curve's quote.
    Returns how many blocks were on each curve."""
    from .yieldstate import works_after
    works, on = (0, 0), {"btc": 0, "qwen": 0}  # (Wb, Wq): each curve counts its own work, above the genesis block
    for h in range(1, upto + 1):
        blk = rpc.getblock(rpc.getblockhash(h), 2)
        bits, quote = int(blk["bits"], 16), D.curve_of_version(blk["version"])
        curve = not d.graduated(*works)
        minted = sum(round(v["value"] * D.COIN) for v in blk["tx"][0]["vout"])
        want = d.subsidy(*works, quote, bits, h)
        if minted != want:
            raise RuntimeError(f"block {h} minted {minted} units; the rules say {want}")
        if not blk["tx"][0]["vin"][0]["coinbase"].startswith(d.coinbase_prefix(h).hex()):
            raise RuntimeError(f"block {h}: its coinbase does not start with the height and this launch's id")
        ob = rpc.getmintobligation(h)
        owes = d.owed(D.work_from_bits(bits), quote) if curve else 0
        if (ob.get("curve"), ob.get("quote"), ob.get("owed")) != (curve, quote if curve else "btc", owes):
            raise RuntimeError(f"block {h}: the node says curve={ob.get('curve')} quote={ob.get('quote')} owed={ob.get('owed')}; "
                               f"the rules say curve={curve} quote={quote if curve else 'btc'} owed={owes}")
        if curve:
            on[quote] += 1
        works = works_after(d, works, bits, blk["version"], h)
    return on


def self_test(binary: str) -> str:
    """Start the node on a throwaway test launch, mine on both of its curves, read what each block
    owes, stop. Returns one line on success; raises RuntimeError with what went wrong."""
    from .ser import script_to_address
    t0 = time.time()
    d, spk = _test_launch("doctor self-test", 2 * 10**6)
    with _TestNode(binary, d.dumps()) as rpc:
        if rpc.getblockhash(0) != d.genesis_hash:
            raise RuntimeError("the node's genesis block is not the one the launch file commits to")
        addr, mined = script_to_address(spk, d.hrp), 0
        for _ in range(200):
            rpc.setminecurve("qwen" if mined % 2 else "btc")  # blocks 1, 3, 5 on the BTC curve, 2 and 4 on the QWEN curve
            mined += len(rpc.generatetoaddress(1, addr, 1_000_000))
            if mined >= 5:
                break
        info = rpc.getlaunchinfo()
        if mined < 5 or info["height"] != mined:
            raise RuntimeError(f"mined {mined} blocks but the node is at height {info['height']}")
        on = _check_mints(rpc, d, mined)
        if on != {"btc": 3, "qwen": 2}:
            raise RuntimeError(f"3 blocks were mined on the BTC curve and 2 on the QWEN curve; the chain has {on}")
        got = {c: (info["curves"][c]["blocks"], info["curves"][c]["supply"]) for c in D.QUOTES}
        want = {"btc": (3, d.curve_supply(3 * 2)), "qwen": (2, d.curve_supply(2 * 2))}  # 2 hashes a block at this limit
        if got != want:
            raise RuntimeError(f"the node's two curves stand at {got}; the rules say {want}")
    return (f"node up on a test launch, {mined} blocks mined on its two curves and every mint equal to the rules' own "
            f"arithmetic, what each block owes (sats or qwen) readable, clean stop ({time.time() - t0:.1f} s)")


# ---- one machine's chain, checked by another machine's node --------------------------------------
# The node ships built by different compilers for different processors. They must agree on every
# rule or the network splits. `doctor --mine FILE` mines a short chain (up the curve, through
# graduation, into the tail) and writes it down with what this node concluded from it;
# `doctor --replay FILE` feeds those blocks to this machine's node and requires the same conclusions.
_UTXO_KEYS = ("height", "bestblock", "txouts", "total_amount", "hash_serialized_3")
_INFO_KEYS = ("launch_id", "height", "work", "curve_supply", "tail_minted", "supply", "graduated", "graduation_height",
              "graduated_by")
_CURVE_KEYS = ("work", "supply", "blocks", "last_height")  # of each curve: the whole numbers (no doubles: they may round apart)
CHAIN_FORMAT = 2  # of the file `doctor --mine` writes: 2 = chains under rule set 3 (two curves)


def _conclusions(rpc: RPC, height: int) -> dict:
    utxo, info = rpc.gettxoutsetinfo(), rpc.getlaunchinfo()
    state = {k: info.get(k) for k in _INFO_KEYS}
    state["curves"] = {c: {k: (info.get("curves") or {}).get(c, {}).get(k) for k in _CURVE_KEYS} for c in D.QUOTES}
    return {"tip": rpc.getbestblockhash(), "utxo": {k: utxo.get(k) for k in _UTXO_KEYS}, "state": state,
            "owed": [rpc.getmintobligation(h) for h in range(1, height + 1)]}


def mine_chain(binary: str, path: str, blocks: int = 120) -> str:
    from .ser import script_to_address
    # 2 hashes a block. Two blocks in three go to the BTC curve, which sells out after about 60 of its
    # own: the launch graduates around block 90 with the QWEN curve a little over half sold, and the
    # rest is tail. The miner keeps being told to change curve after that too: there is none left.
    d, spk = _test_launch("doctor chain", 120)
    with _TestNode(binary, d.dumps()) as rpc:
        addr, t = script_to_address(spk, d.hrp), d.genesis_time
        for n in range(1, blocks + 1):
            t += d.target_spacing
            rpc.setmocktime(t)
            rpc.setminecurve("qwen" if n % 3 == 0 else "btc")
            while not rpc.generatetoaddress(1, addr, 1_000_000):
                pass
        on = _check_mints(rpc, d, blocks)
        out = {"hashfun_chain": CHAIN_FORMAT, "by": {"target": platform_target(), "hashfund": _version_line(binary)},
               "launch": json.loads(d.dumps()), "blocks": [rpc.getblock(rpc.getblockhash(h), 0) for h in range(1, blocks + 1)],
               **_conclusions(rpc, blocks)}
    state = out["state"]
    if not state["graduated"] or not 0 < state["graduation_height"] < blocks or state["graduated_by"] != "btc":
        raise RuntimeError(f"the test chain was meant to graduate by its BTC curve on the way: {state}")
    if not on["qwen"] or not 0 < state["curves"]["qwen"]["supply"] < d.graduation_tokens:
        raise RuntimeError(f"the test chain was meant to leave its QWEN curve part sold: {state}")
    with open(path, "w") as f:
        json.dump(out, f)
    return (f"{blocks} blocks mined on a test launch ({on['btc']} on the BTC curve, {on['qwen']} on the QWEN curve, graduated "
            f"by the BTC curve at {state['graduation_height']}), every mint and every debt equal to the rules' own "
            f"arithmetic; written with this node's conclusions to {path}")


def replay_chain(binary: str, path: str) -> str:
    with open(path) as f:
        data = json.load(f)
    if data.get("hashfun_chain") == 1:
        raise RuntimeError(f"{path} was written under the earlier rules (one curve): mine it again with this version's "
                           "`hashfun doctor --mine`")
    if data.get("hashfun_chain") != CHAIN_FORMAT:
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
            raise RuntimeError(f"same blocks, different debt for block {h}: here {json.dumps(a)}, there {json.dumps(b)}")
    by = data.get("by", {})
    return (f"{len(data['blocks'])} blocks mined by {by.get('target')} ({by.get('hashfund')}) accepted here; same tip, same UTXO set, "
            f"same state of both curves (graduated at {mine['state'].get('graduation_height')}), the same owed for every block")


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


def loaded_wallets(node) -> Optional[List[str]]:
    """The wallets a Bitcoin Core or Qwencoin node has loaded; [] for a node with none (or built
    without a wallet); None when it could not be asked (then the node's URL is used as the wallet it
    was given as, and a payment says what is wrong if there is none)."""
    try:
        names = node.listwallets()
    except RPCError as e:
        return [] if e.code == -32601 else None  # method not found: no wallet in this build
    except Exception:  # noqa: BLE001  (not answering right now)
        return None
    return list(names) if isinstance(names, list) else None


def build_source(reg: Registry, ticker: str, payout: Optional[str], btc_rpc: Optional[str], btc_hrp: str,
                 max_pay_sats: Optional[int] = None, btc_cookie: Optional[str] = None, btc_wallet: Optional[str] = None,
                 pay_depth: int = 12, curve: Optional[str] = None, qwen_rpc: Optional[str] = None,
                 qwen_cookie: Optional[str] = None, qwen_wallet: Optional[str] = None, max_pay_qwen: Optional[int] = None):
    """LaunchSource for `ticker`, carrying every other registered, running launch as an aux chain
    (only graduated ones are merge-mined; the pool re-checks each round) and the Settler that pays
    and proves what each curve block owes, on Bitcoin and on Qwencoin.

    curve: the curve to mine ("btc" / "qwen"). Left out, it is the one a wallet was given for; with
    both wallets it has to be said."""
    from .settler import Settler
    from .stratum import LaunchSource
    d = reg.desc(ticker)
    rpc = reg.rpc(ticker)
    if not rpc:
        sys.exit(f"{ticker} is not running: hashfun node up {ticker}")
    # Every curve block owes its curve's coin, so mining always needs a funded wallet of that chain.
    if not btc_rpc and not qwen_rpc:
        sys.exit("pass --btc-rpc URL of a funded Bitcoin Core wallet (http://user:pass@host:port, plus --btc-wallet NAME) "
                 "to mine the BTC curve, or --qwen-rpc URL of a funded Qwencoin wallet (plus --qwen-wallet NAME) to mine the "
                 "QWEN curve: each block mined on a curve owes that curve's coin, paid and proven automatically")
    wallets, relay_only = {}, {}
    for quote, chain, url, cookie, name, check in (("btc", "Bitcoin", btc_rpc, btc_cookie, btc_wallet, check_btc_anchor),
                                                   ("qwen", "Qwencoin", qwen_rpc, qwen_cookie, qwen_wallet, check_qwen_anchor)):
        if not url:
            continue
        # Bitcoin through Electrum servers (electrums://...): the wallet is a file with one private key
        # (--btc-wallet FILE), and the header chain is fetched down to the launch's anchor at the start.
        light = quote == "btc" and is_light_url(url)
        node = btc_light(url, anchor=d.btc_anchor_height) if light else RPC(url, cookie_file=cookie)
        w = node.wallet(name) if name else node
        # Before the first block, and before anything else is touched: this is the node what blocks
        # owe will be paid through, so its chain must be the one the launch is anchored in.
        check(d, w, ticker)
        if light and not name:
            relay_only[quote] = node
            print(f"no key file for Bitcoin (--btc-wallet FILE): its headers are relayed to {ticker} through the Electrum "
                  "servers, and nothing is paid on Bitcoin from here", file=sys.stderr)
            continue
        if not name:
            # No wallet named: the node's own, if it has exactly one loaded. A node with none still
            # gives the launch its chain's headers (everybody's proofs on that chain need them), and
            # pays nothing; with several, which one pays has to be said.
            loaded = loaded_wallets(node)
            if loaded is not None and len(loaded) > 1:
                sys.exit(f"--{quote}-wallet NAME: the {chain} node has {len(loaded)} wallets loaded ({', '.join(loaded)}): "
                         "say which one pays")
            if loaded == []:
                relay_only[quote] = node
                print(f"the {chain} node has no wallet loaded: its headers are relayed to {ticker}, and nothing is paid on "
                      f"{chain} from here (name one with --{quote}-wallet NAME to mine the {quote.upper()} curve)", file=sys.stderr)
                continue
            if loaded:  # exactly one: ask for it by name, so that a second one loaded later changes nothing
                w = node.wallet(loaded[0])
        wallets[quote] = w
    if not wallets:
        sys.exit("neither node has a wallet loaded, and each block mined on a curve owes that curve's coin: pass "
                 "--btc-wallet NAME (with --btc-rpc) to mine the BTC curve, or --qwen-wallet NAME (with --qwen-rpc) to mine "
                 "the QWEN curve")
    if curve is None:
        if len(wallets) == 2:
            sys.exit("--curve btc|qwen: a Bitcoin and a Qwencoin wallet were both given, so say which curve to mine. (Both "
                     "chains' headers are relayed either way, and a block of yours on the other curve is paid from its wallet.)")
        curve = next(iter(wallets))
    elif curve not in D.QUOTES:
        sys.exit(f"--curve {curve}: btc or qwen")
    elif curve not in wallets:
        chain = "Bitcoin" if curve == "btc" else "Qwencoin"
        sys.exit(f"--curve {curve}: a block on the {curve.upper()} curve owes {'sats' if curve == 'btc' else 'qwen'}, so mining "
                 f"it needs a funded {chain} wallet: --{curve}-rpc URL [--{curve}-wallet NAME]")
    children = {}
    for other in sorted(reg.data):
        if other == ticker:
            continue
        orpc = reg.rpc(other, timeout=5)
        if not orpc:
            continue
        od = reg.desc(other)
        try:
            names = orpc.listwallets()
            w = orpc.wallet(names[0]) if names else None
            addr = w.getnewaddress("", "bech32") if w else None
        except Exception:
            addr = None
        if addr:  # merge-mined rewards need somewhere to go on that chain
            children[other] = {"rpc": orpc, "hrp": od.hrp, "payout": addr}
    settler = Settler(rpc, wallets.get("btc"), os.path.join(os.path.dirname(reg.get(ticker)["descriptor"]), "settler.json"),
                      max_pay_sats=max_pay_sats, pay_depth=pay_depth, qwen_wallet=wallets.get("qwen"),
                      max_pay_qwen=max_pay_qwen, btc_node=relay_only.get("btc"), qwen_node=relay_only.get("qwen"))
    return LaunchSource(rpc, d.hrp, d.ticker, default_payout=payout, children=children, settler=settler,
                        yield_hrp=btc_hrp, curve=curve), children, settler


def cmd_mine(a, reg: Registry):
    from .miner import StratumMiner
    from .stratum import StratumServer
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(asctime)s %(name)s %(message)s")
    reg.up(a.ticker, fetch_table=True)
    src, children, settler = build_source(reg, a.ticker, a.payout, a.btc_rpc, a.btc_hrp,
                                          int(a.max_pay_btc * D.COIN) if a.max_pay_btc else None,
                                          a.btc_cookie, a.btc_wallet, a.pay_depth, curve=a.curve, qwen_rpc=a.qwen_rpc,
                                          qwen_cookie=a.qwen_cookie, qwen_wallet=a.qwen_wallet,
                                          max_pay_qwen=int(a.max_pay_qwen * D.COIN) if a.max_pay_qwen else None)
    host, port = a.listen.rsplit(":", 1)
    user = a.payout + (f",{a.btc_address}" if a.btc_address else "")
    print(json.dumps({"stratum": f"stratum+tcp://{host}:{port}", "user": user, "launch": a.ticker, "curve": src.curve,
                      "pays_from": settler.status()["wallets"], "merge_mining_candidates": sorted(children),
                      "cpu_miner": not a.no_cpu}), flush=True)

    async def run():
        srv = StratumServer(src, host, int(port), difficulty=a.difficulty, stats_path=a.stats)
        task = asyncio.ensure_future(srv.serve())
        # the pool opens its port once the node has given it a first template: at once on most machines, not on all
        while not srv.listening and not task.done():
            await asyncio.sleep(0.05)
        if task.done():
            task.result()  # the pool could not start (its port is taken, say): that error, not a miner's
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
    p.add_argument("--btc-rpc", help="Bitcoin Core RPC URL: before registering, check that the launch's Bitcoin anchor is "
                                     "the block at that height on this node's chain (do this for a launch file you were given)")
    p.add_argument("--btc-cookie", help="Bitcoin Core .cookie file, if the URL has no user:pass")
    p.add_argument("--qwen-rpc", help="Qwencoin node RPC URL: before registering, check that the launch's Qwencoin anchor is "
                                      "the block at that height on this node's chain (nothing but a Qwencoin node, or the "
                                      "launch's own node at its start, can tell that it is a Qwencoin block at all)")
    p.add_argument("--qwen-cookie", help="the Qwencoin node's .cookie file, if the URL has no user:pass")
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
    p.add_argument("--btc-address", help="send this miner's yield (BTC and QWEN) here instead of to its launch key")
    p.add_argument("--curve", choices=("btc", "qwen"),
                   help="the curve to mine: blocks on the BTC curve owe sats, blocks on the QWEN curve owe qwen. Default: "
                        "the one a wallet was given for (with both wallets, it has to be said)")
    p.add_argument("--btc-rpc", help="Bitcoin Core RPC URL of a funded wallet (pays the sats each block on the BTC curve owes), "
                                     "or electrums://HOST:PORT,HOST:PORT with --btc-wallet KEYFILE (no node here); mining does "
                                     "not start unless the launch's Bitcoin anchor is on its chain")
    p.add_argument("--btc-cookie", help="Bitcoin Core .cookie file, if the URL has no user:pass")
    p.add_argument("--btc-wallet", help="Bitcoin Core wallet name (with --btc-rpc electrums://...: a file holding the paying "
                                        "key, 64 hex digits or WIF). Left out: the node's own wallet if it has exactly one "
                                        "loaded; with none loaded the node only gives the launch Bitcoin's headers")
    p.add_argument("--btc-hrp", default="bc")
    p.add_argument("--max-pay-btc", type=float, help="never pay more than this for one block's sats")
    p.add_argument("--qwen-rpc", help="Qwencoin node RPC URL of a funded wallet (pays the qwen each block on the QWEN curve "
                                      "owes; qwencoind speaks bitcoin-cli's RPC); mining does not start unless the launch's "
                                      "Qwencoin anchor is on its chain")
    p.add_argument("--qwen-cookie", help="the Qwencoin node's .cookie file, if the URL has no user:pass")
    p.add_argument("--qwen-wallet", help="Qwencoin wallet name")
    p.add_argument("--max-pay-qwen", type=float, help="never pay more than this (in QWEN) for one block's qwen")
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
