"""Fleet test: several hashfund nodes per launch talking P2P on localhost, a stock bitcoind
(regtest) as Bitcoin, real time. The launches are production-mode (test=false: no mock clock,
mining RPCs gated on peers); only the Bitcoin their sats leg follows is regtest.

  python -m hashfun.tests.fleet_regtest --hashfund build/bin/hashfund --bitcoind /path/to/bitcoind

  F1  production gating: an old tip is not "initial block download", no peers means no
      templates unless -minewithoutpeers, the clock cannot be mocked, pruning is refused
  F2  nodes connect; a node cut off from its peers stops serving templates
  F3  a pool (stratum + settler, as `hashfun mine` runs it) mines on node A while Bitcoin makes
      a block every 2 s; three nodes agree on tip, UTXO set, Bitcoin relay and every obligation
  F4  a late joiner syncs from genesis and arrives at the same sats-leg state
  F5  a node restarted mid-run catches up; a node restarted with no new blocks rebuilds the
      same state from disk
  F6  a matured but unsettled coinbase is rejected by every mempool; a settled one, broadcast
      on a node that mined nothing, relays, is mined and confirms everywhere
  F7  partitions: an isolated node with its own branch (carrying a forged Bitcoin branch)
      reorgs back and forgets it; the pool's own node loses a race to a second pool and its
      settler pays nothing for the orphaned blocks
  F8  a second launch graduates and is merge-mined by the first launch's pool; AuxPoW blocks
      propagate and a late joiner syncs the mixed chain
  F9  verifychain; two pools with two Bitcoin wallets settle everything they mined
  F10 stall relief in real time: a cached template is rebuilt when the clock enters the next
      relief step (getblocktemplate and createauxblock), nBits equals the model, peers accept
"""
import argparse
import asyncio
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback

from hashfun import descriptor as D
from hashfun import yieldmodel as Y
from hashfun.crypto import sha256d, hash160, pubkey_from_priv, random_priv
from hashfun.miner import StratumMiner
from hashfun.rpc import RPC, RPCError
from hashfun.ser import TxOut, address_to_script, bits_to_target, header_bytes
from hashfun.settler import Settler
from hashfun.stratum import LaunchSource, StratumServer
from hashfun.tests.e2e_regtest import RESULTS, check, free_port, open_wallet, block_from_gbt, ser_block, COIN, DAY

GBT = {"rules": ["segwit"]}


def rpc_err(fn):
    """(code, message) of the RPC error fn raises, or None if it succeeds."""
    try:
        fn()
    except RPCError as e:
        return e.code, e.message
    return None


def wait(cond, timeout, what):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if cond():
                return True
        except (RPCError, OSError, KeyError):
            pass
        time.sleep(0.25)
    print(f"   timed out after {timeout}s waiting for: {what}", flush=True)
    return False


class FNode:
    def __init__(self, binary, datadir, args, rpcport, name=""):
        self.binary, self.datadir, self.args, self.rpcport, self.name = binary, datadir, list(args), rpcport, name
        self.url = f"http://127.0.0.1:{rpcport}"
        self.proc = self.rpc = None
        self.p2p = None
        self.start()

    def start(self):
        os.makedirs(self.datadir, exist_ok=True)
        self.errlog = os.path.join(self.datadir, "stderr.log")
        with open(self.errlog, "ab") as err:
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.datadir}", "-server=1", "-txindex=1",
                                          "-fallbackfee=0.0001", f"-rpcport={self.rpcport}", "-printtoconsole=0"]
                                         + self.args, stdout=subprocess.DEVNULL, stderr=err)
        deadline = time.time() + 120
        while time.time() < deadline:
            if self.proc.poll() is not None:
                with open(self.errlog, "rb") as f:
                    tail = f.read()[-2000:].decode(errors="replace")
                raise RuntimeError(f"{os.path.basename(self.binary)} {self.name} exited {self.proc.returncode}: {tail}")
            for cookie in glob.glob(os.path.join(self.datadir, "*", ".cookie")):
                try:
                    rpc = RPC(self.url, cookie_file=cookie)
                    rpc.getblockcount()
                    self.rpc = rpc
                    return
                except Exception:
                    pass
            time.sleep(0.2)
        self.proc.kill()
        raise RuntimeError(f"{self.binary} {self.name} did not start")

    def stop(self):
        if self.proc is None or self.proc.poll() is not None:
            return
        try:
            self.rpc.stop()
            self.proc.wait(60)
        except Exception:
            self.proc.kill()
            self.proc.wait(10)


class BtcTicker(threading.Thread):
    """Bitcoin, compressed: a regtest block every `interval` seconds."""

    def __init__(self, wallet: RPC, addr: str, interval: float):
        super().__init__(daemon=True)
        self.wallet, self.addr, self.interval = wallet, addr, interval
        self.halt = threading.Event()

    def run(self):
        while not self.halt.wait(self.interval):
            try:
                self.wallet.generatetoaddress(1, self.addr)
            except Exception:
                pass


class Rig:
    """What `hashfun mine` runs: a pool on one node (templates, settler, merge-mined children)
    and a CPU miner pointed at it."""

    def __init__(self, loop, node, d, payout, btc_payout, settler, children=None):
        self.loop, self.node, self.settler = loop, node, settler
        self.src = LaunchSource(node.rpc, d.hrp, d.ticker, settler=settler, yield_hrp="bcrt", children=children)
        self.port = free_port()
        self.server = StratumServer(self.src, "127.0.0.1", self.port, difficulty=2e-6, poll_interval=0.2)
        asyncio.run_coroutine_threadsafe(self.server.serve(), loop)
        self.miner = StratumMiner("127.0.0.1", self.port, f"{payout},{btc_payout}", batch=4096)
        self.fut = None
        time.sleep(0.6)

    def start(self):
        if self.fut is None or self.fut.done():
            self.fut = asyncio.run_coroutine_threadsafe(self.miner.run(None), self.loop)

    def stop(self):
        if self.fut is not None:
            self.fut.cancel()
            try:
                self.fut.result(15)
            except BaseException:
                pass
            self.fut = None


class paused:
    """Stop the given rigs for the duration of a with-block, then restart the ones that ran."""

    def __init__(self, *rigs):
        self.rigs = [r for r in rigs if r is not None]

    def __enter__(self):
        self.running = [r for r in self.rigs if r.fut is not None and not r.fut.done()]
        for r in self.running:
            r.stop()
        time.sleep(0.5)

    def __exit__(self, *exc):
        for r in self.running:
            r.start()


FLOOR_BITS = 0x1F01FFFF  # ~32,768 hashes per block at the floor
FLOOR_WORK = 32768


def mk_launch(ticker, creator_spk, creator_btc_spk, graduation_hashes):
    """Production-mode launch on a regtest Bitcoin: 2 s blocks, a floor a CPU miner clears in a
    fraction of a second, and 1/4 sat per hash, so blocks owe real sats from the start (a
    floor block's 8,192 sats are a lottery for the 10,000 minimum; heavier blocks pay in full).
    LWMA raises difficulty about 8% per block at best with this window, so a CPU pool reaches
    its 2 s equilibrium within a few dozen blocks."""
    d = D.make(f"{ticker} fleet", ticker, creator_spk, graduation_hashes, test=False, btc_regtest=True,
               pow_limit_bits=FLOOR_BITS, target_spacing=2, lwma_window=15, genesis_time=int(time.time()) - 2 * DAY,
               creator_btc_script=creator_btc_spk, _validate=False)
    d.sats_num, d.sats_shift = 1, 2
    D.validate(d)
    d.grind_genesis()
    return d


def mine_gbt(node, payout_spk, extra_outs=()):
    """One block by hand from getblocktemplate (plain PoW solved in Python). No settler knows it."""
    for _ in range(200):
        try:
            t = node.rpc.getblocktemplate(GBT)
            break
        except RPCError as e:
            # A burst outruns the clock: block times must pass the median of the last 11, so they
            # creep ahead until the next one would be past the future limit. Wait for real time.
            if "time-too-new" not in e.message:
                raise
            time.sleep(0.25)
    else:
        raise RuntimeError("template stayed time-too-new")
    hdr, txs = block_from_gbt(t, payout_spk, extra_outs=extra_outs)
    r = node.rpc.submitblock(ser_block(hdr, txs))
    if r is not None:
        raise RuntimeError(f"hand-built block rejected: {r}")
    return t["height"], sha256d(hdr)[::-1].hex()


def fake_btc_headers(prev_hex: str, first_time: int, n: int):
    """n regtest-valid Bitcoin headers on top of prev: a branch that exists nowhere else."""
    out, prev, target = [], bytes.fromhex(prev_hex)[::-1], bits_to_target(0x207FFFFF)
    for i in range(n):
        root, nonce = os.urandom(32), 0
        while True:
            h = header_bytes(0x20000000, prev, root, first_time + i, 0x207FFFFF, nonce)
            if int.from_bytes(sha256d(h), "little") <= target:
                break
            nonce += 1
        out.append(h)
        prev = sha256d(h)
    return out


def chainwork(node) -> int:
    return int(node.rpc.getblockheader(node.rpc.getbestblockhash())["chainwork"], 16)


def snapshot(node) -> dict:
    r = node.rpc
    best = r.getbestblockhash()
    tip = r.getblockheader(best)
    info = r.getlaunchinfo()
    return {"tip": best, "height": tip["height"], "chainwork": tip["chainwork"],
            "launch": {k: info.get(k) for k in ("graduated", "graduation_height", "curve_supply")},
            "relay": r.getbtcrelay(), "utxo": r.gettxoutsetinfo("muhash")["muhash"],
            "obligations": [r.getmintobligation(h) for h in range(1, tip["height"] + 1)],
            "still": r.getbestblockhash() == best}


def first_diff(a, b, path=""):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if a.get(k) != b.get(k):
                return first_diff(a.get(k), b.get(k), f"{path}.{k}")
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                return first_diff(x, y, f"{path}[{i}]")
    return f"{path}: {json.dumps(a)[:160]} != {json.dumps(b)[:160]}"


def agree(nodes, timeout=60):
    """All nodes on the same tip with identical consensus-derived state. Mining must be paused.
    Returns (ok, detail, snapshot)."""
    if not wait(lambda: len({n.rpc.getbestblockhash() for n in nodes}) == 1, timeout, "nodes on one tip"):
        return False, "tips differ: " + json.dumps({n.name: n.rpc.getblockcount() for n in nodes}), None
    for _ in range(5):
        snaps = [snapshot(n) for n in nodes]
        if all(s.pop("still") for s in snaps) and len({s["tip"] for s in snaps}) == 1:
            for n, s in zip(nodes[1:], snaps[1:]):
                if s != snaps[0]:
                    return False, f"{nodes[0].name} vs {n.name}: {first_diff(snaps[0], s)}", snaps[0]
            return True, "", snaps[0]
        time.sleep(1)
    return False, "tip kept moving", None


class Fleet:
    def __init__(self, a):
        self.a = a
        self.dir = os.path.abspath(a.workdir) if a.workdir else tempfile.mkdtemp(prefix="hashfun-fleet-")
        os.makedirs(self.dir, exist_ok=True)
        self.nodes, self.rigs, self.ticker = [], [], None
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()

    def launch_node(self, name, desc_path, peers=(), extra=()):
        p2p = free_port()
        n = FNode(self.a.hashfund, os.path.join(self.dir, name),
                  [f"-launch={desc_path}", "-listen=1", f"-port={p2p}", f"-bind=127.0.0.1:{p2p}", "-listenonion=0",
                   "-discover=0", "-dnsseed=0", "-fixedseeds=0"] + [f"-addnode=127.0.0.1:{q.p2p}" for q in peers]
                  + list(extra), free_port(), name)
        n.p2p = p2p
        self.nodes.append(n)
        return n

    @staticmethod
    def connect(a, b):
        try:
            a.rpc.addnode(f"127.0.0.1:{b.p2p}", "onetry")
        except RPCError:
            pass

    def stop(self):
        for r in self.rigs:
            r.stop()
        if self.ticker:
            self.ticker.halt.set()
        for n in self.nodes:
            n.stop()

    # ------------------------------------------------------------------ the run
    def run(self):
        a, t_start = self.a, time.time()
        lap = [time.time()]

        def phase(name):
            print(f"-- {name}  (+{time.time() - lap[0]:.0f}s, total {time.time() - t_start:.0f}s)", flush=True)
            lap[0] = time.time()

        # ---- Bitcoin: one stock regtest node, two wallets (one per pool)
        btc = FNode(a.bitcoind, os.path.join(self.dir, "btc"), ["-regtest", "-listen=0"], free_port(), "btc")
        self.nodes.append(btc)
        wb = open_wallet(btc.rpc)
        w2 = open_wallet(btc.rpc, "w2")
        btc_addr = wb.getnewaddress("", "bech32")
        wb.generatetoaddress(110, btc_addr)
        wb.sendtoaddress(w2.getnewaddress("", "bech32"), 50)
        wb.generatetoaddress(1, btc_addr)

        def bspk(addr):
            return bytes.fromhex(wb.getaddressinfo(addr)["scriptPubKey"])
        creator_btc, miner_btc, miner2_btc = (wb.getnewaddress("", "bech32") for _ in range(3))

        # ---- two launches: FLT stays on its curve, GRD graduates within seconds
        creator_spk = b"\x00\x14" + hash160(pubkey_from_priv(random_priv()))
        dF = mk_launch("FLT", creator_spk, bspk(creator_btc), 10**12)
        dG = mk_launch("GRD", creator_spk, bspk(creator_btc), 20 * FLOOR_WORK)
        pF, pG = os.path.join(self.dir, "FLT.json"), os.path.join(self.dir, "GRD.json")
        for p, d in ((pF, dF), (pG, dG)):
            with open(p, "w") as f:
                f.write(d.dumps())

        # ================================================================= F1
        phase("F1 production gating")
        A = self.launch_node("A", pF)
        check("F1 a two-day-old tip is not treated as initial block download",
              A.rpc.getblockchaininfo()["initialblockdownload"] is False)
        e = rpc_err(lambda: A.rpc.getblocktemplate(GBT))
        check("F1 a node with no peers refuses getblocktemplate", e is not None and e[0] == -9, str(e))
        check("F1 a production launch cannot mock its clock", rpc_err(lambda: A.rpc.setmocktime(1)) is not None)
        A.stop()
        pr = subprocess.run([a.hashfund, f"-datadir={os.path.join(self.dir, 'A')}", f"-launch={pF}", "-prune=550",
                             "-printtoconsole=0", "-listen=0"], capture_output=True, timeout=120)
        check("F1 pruning is refused on a launch chain",
              pr.returncode != 0 and b"Pruning is not supported" in pr.stderr, pr.stderr[-300:].decode(errors="replace"))
        A.args.append("-minewithoutpeers")
        A.start()
        check("F1 -minewithoutpeers lets the first node of a launch mine alone",
              rpc_err(lambda: A.rpc.getblocktemplate(GBT)) is None)

        # ================================================================= F2
        phase("F2 peers")
        B = self.launch_node("B", pF, peers=[A])
        C = self.launch_node("C", pF, peers=[A, B], extra=["-minewithoutpeers"])
        ok = wait(lambda: A.rpc.getconnectioncount() >= 2 and B.rpc.getconnectioncount() >= 2
                  and C.rpc.getconnectioncount() >= 2, 40, "three nodes connected")
        check("F2 nodes connect over P2P", ok)
        check("F2 a connected node serves templates without the flag", rpc_err(lambda: B.rpc.getblocktemplate(GBT)) is None)
        B.rpc.setnetworkactive(False)
        wait(lambda: B.rpc.getconnectioncount() == 0, 20, "B offline")
        e = rpc_err(lambda: B.rpc.getblocktemplate(GBT))
        check("F2 a node cut off from its peers stops serving templates", e is not None and e[0] == -9, str(e))
        B.rpc.setnetworkactive(True)
        self.connect(B, A)
        self.connect(C, B)
        wait(lambda: B.rpc.getconnectioncount() >= 2, 30, "B back")

        wA, wB, wC = open_wallet(A.rpc), open_wallet(B.rpc), open_wallet(C.rpc)
        addrA, rogue_addr = wA.getnewaddress("", "bech32"), wA.getnewaddress("", "bech32")
        addrB, addrC = wB.getnewaddress("", "bech32"), wC.getnewaddress("", "bech32")
        spkA, rogue_spk = address_to_script(addrA, dF.hrp), address_to_script(rogue_addr, dF.hrp)

        # GRD: two nodes now; the pool on A carries it as an aux chain once it has graduated.
        G1 = self.launch_node("G1", pG, extra=["-minewithoutpeers"])
        G2 = self.launch_node("G2", pG, peers=[G1])
        wG = open_wallet(G1.rpc)
        addrG = wG.getnewaddress("", "bech32")
        spkG = address_to_script(addrG, dG.hrp)

        # ================================================================= F3
        phase("F3 pool + settler on A, three nodes follow")
        self.ticker = BtcTicker(wb, btc_addr, 2.0)
        self.ticker.start()
        # Default pay_depth (12): a block is paid once its draw block is 6 deep.
        setA = Settler(A.rpc, wb, os.path.join(self.dir, "settler-A.json"), max_pay_sats=COIN)
        rigA = Rig(self.loop, A, dF, addrA, miner_btc, setA,
                   children={"GRD": {"rpc": G1.rpc, "hrp": dG.hrp, "payout": addrG}})
        self.rigs.append(rigA)
        rigA.start()

        for _ in range(400):  # GRD's whole curve, by hand
            if G1.rpc.getlaunchinfo()["graduated"]:
                break
            mine_gbt(G1, spkG)
        grad_h = G1.rpc.getlaunchinfo()["graduation_height"]
        print(f"   GRD graduated at block {grad_h}", flush=True)

        wait(lambda: A.rpc.getblockcount() >= 30, 180, "FLT at 30 blocks")
        # Three blocks nobody will settle, owing real sats: for the spend-lock check in F6.
        rogue = []
        with paused(rigA):
            for _ in range(10):
                h, bh = mine_gbt(A, rogue_spk)
                if A.rpc.getmintobligation(h)["owed"] >= dF.sats_min_payment:
                    rogue.append((h, bh))
                if len(rogue) >= 3:
                    break
        print(f"   rogue (unsettled) blocks at {[h for h, _ in rogue]}, "
              f"work/block now {int(A.rpc.getlaunchinfo()['next']['work'], 16)}", flush=True)

        def settled_by_payment():
            return [h for h in range(1, A.rpc.getblockcount() + 1) if A.rpc.getmintobligation(h)["settled"]]
        wait(lambda: A.rpc.getblockcount() >= 50 and len(settled_by_payment()) >= 3, 240, "50 blocks, 3 settlements")
        with paused(rigA):
            ok, why, snap = agree([A, B, C])
            check("F3 three nodes agree on tip, UTXO set, Bitcoin relay and every obligation", ok, why)
            paid = settled_by_payment()
            check("F3 the pool settled obligations with Bitcoin payments, automatically", len(paid) >= 3, f"{len(paid)}")
            relay, btc_tip = A.rpc.getbtcrelay(), btc.rpc.getblockcount()
            check("F3 the header relay tracks Bitcoin", relay["height"] >= btc_tip - 6, f"{relay['height']}/{btc_tip}")
            print(f"   FLT {A.rpc.getblockcount()} blocks, {len(paid)} settled by payment, relay {relay['height']}/{btc_tip}, "
                  f"settler {setA.status()}", flush=True)

        # ================================================================= F4
        phase("F4 late joiner")
        Dn = self.launch_node("D", pF, peers=[A])
        wait(lambda: Dn.rpc.getblockcount() >= A.rpc.getblockcount() - 3, 90, "D synced")
        with paused(rigA):
            ok, why, _ = agree([A, Dn])
            check("F4 a late joiner syncs from genesis to the same sats-leg state", ok, why)

        # ================================================================= F5
        phase("F5 restarts")
        C.stop()
        h0 = A.rpc.getblockcount()
        wait(lambda: A.rpc.getblockcount() >= h0 + 6, 120, "6 blocks while C is down")
        C.start()
        self.connect(C, A)
        wait(lambda: C.rpc.getblockcount() >= A.rpc.getblockcount() - 2, 60, "C caught up")
        with paused(rigA):
            ok, why, _ = agree([A, B, C, Dn])
            check("F5 a node restarted mid-run catches up and agrees", ok, why)
            B.stop()
            B.start()
            wB = open_wallet(B.rpc)  # RPC handles die with the old cookie
            ok, why, _ = agree([A, B])
            check("F5 a restart with no new blocks rebuilds the same state from disk", ok, why)
            self.connect(B, A)
            self.connect(B, C)

        # ================================================================= F7a
        phase("F7 partition: an isolated node loses")
        base = A.rpc.getblockcount()
        C.rpc.setnetworkactive(False)
        wait(lambda: C.rpc.getconnectioncount() == 0, 20, "C isolated")
        rel = C.rpc.getbtcrelay()
        fork_at = btc.rpc.getblockhash(rel["height"] - 2)
        fake = fake_btc_headers(fork_at, int(time.time()) + 1, 5)
        fake_tip = sha256d(fake[-1])[::-1].hex()
        spkC = address_to_script(addrC, dF.hrp)
        mine_gbt(C, spkC, extra_outs=[TxOut(0, Y.op_return(b"HFH1" + b"".join(fake)))])
        for _ in range(2):
            mine_gbt(C, spkC)
        c_tip, c_rel = C.rpc.getbestblockhash(), C.rpc.getbtcrelay()
        check("F7 (setup) the isolated node followed a forged Bitcoin branch on its own blocks",
              c_rel["best"] == fake_tip and c_rel["height"] == rel["height"] + 3, json.dumps(c_rel))
        wait(lambda: A.rpc.getblockcount() >= base + 5 and chainwork(A) > chainwork(C), 180, "A's branch heavier")
        C.rpc.setnetworkactive(True)
        self.connect(C, A)
        self.connect(C, B)
        wait(lambda: C.rpc.getblockhash(base + 1) == A.rpc.getblockhash(base + 1), 60, "C reorged")
        with paused(rigA):
            ok, why, _ = agree([A, B, C, Dn])
            check("F7 the isolated node reorgs onto the heavier branch and its state matches again", ok, why)
            check("F7 its own branch is gone from the active chain", C.rpc.getbestblockhash() != c_tip
                  and C.rpc.getblockheader(c_tip)["confirmations"] < 0)
            check("F7 the forged Bitcoin headers left with the orphaned blocks",
                  C.rpc.getbtcrelay() == A.rpc.getbtcrelay() and C.rpc.getbtcrelay()["best"] != fake_tip,
                  json.dumps(C.rpc.getbtcrelay()))

        # ================================================================= F7b
        phase("F7 partition: the pool's own node loses to a second pool")
        setB = Settler(B.rpc, w2, os.path.join(self.dir, "settler-B.json"), max_pay_sats=COIN)
        rigB = Rig(self.loop, B, dF, addrB, miner2_btc, setB)
        self.rigs.append(rigB)
        rigA.stop()
        time.sleep(1)
        wait(lambda: len({n.rpc.getbestblockhash() for n in (A, B, C, Dn)}) == 1, 30, "one tip before the split")
        fork_h = A.rpc.getblockcount()
        A.rpc.setnetworkactive(False)
        wait(lambda: A.rpc.getconnectioncount() == 0, 20, "A isolated")
        rigA.start()
        wait(lambda: A.rpc.getblockcount() >= fork_h + 2, 120, "A mines 2 blocks alone")
        rigA.stop()
        orphans = {A.rpc.getblockhash(h) for h in range(fork_h + 1, A.rpc.getblockcount() + 1)}
        rigB.start()
        wait(lambda: B.rpc.getblockcount() >= A.rpc.getblockcount() + 2 and chainwork(B) > chainwork(A), 240,
             "B's branch heavier")
        A.rpc.setnetworkactive(True)
        self.connect(B, A)
        self.connect(C, A)
        self.connect(Dn, A)
        ok = wait(lambda: A.rpc.getblockhash(fork_h + 1) == B.rpc.getblockhash(fork_h + 1), 90, "A reorged")
        check("F7 the pool's own node reorgs onto the other pool's heavier branch",
              ok and A.rpc.getblockhash(fork_h + 1) not in orphans)
        rigB.stop()
        ok, why, _ = agree([A, B, C, Dn])
        check("F7 all four nodes agree after the reorg", ok, why)
        time.sleep(1.5)  # a few settler cycles on the new chain (A's pool keeps polling)
        with setA.lock:
            paid_for_orphans = [k for k in setA.st["paid"] if k.split(":")[1] in orphans]
            check("F7 the settler paid nothing for its orphaned blocks", not paid_for_orphans and not setA.st["lost"],
                  json.dumps([paid_for_orphans, setA.st["lost"]]))
        print(f"   {len(orphans)} blocks of pool A orphaned at {fork_h + 1}..; settler A {setA.status()}", flush=True)
        rigA.start()
        rigB.start()  # two pools race from here on

        # ================================================================= F8
        phase("F8 graduated launch merge-mined by the presale pool")
        wait(lambda: G1.rpc.getblockcount() >= grad_h + 8, 120, "GRD aux blocks")
        with paused(rigA, rigB):
            tipG = G1.rpc.getblockcount()
            aux = [h for h in range(grad_h + 1, tipG + 1)
                   if G1.rpc.getblockheader(G1.rpc.getblockhash(h))["version"] & 0x100]
            check("F8 the presale pool merge-mined the graduated launch", len(aux) >= 5, f"{len(aux)} of {tipG - grad_h}")
            parent = (G1.rpc.getblock(G1.rpc.getblockhash(aux[-1]), 1).get("auxpow") or {}).get("parentblock") if aux else None
            pver = (parent["version"] if isinstance(parent, dict) else
                    int.from_bytes(bytes.fromhex(parent)[:4], "little", signed=True)) if parent else 0
            check("F8 the AuxPoW parent is a block header of the presale launch", pver >> 16 == dF.chain_id, f"{pver:#x}")
            ok = wait(lambda: G2.rpc.getbestblockhash() == G1.rpc.getbestblockhash(), 60, "G2 follows")
            check("F8 AuxPoW blocks propagate over P2P", ok)
            G3 = self.launch_node("G3", pG, peers=[G2])
            ok, why, _ = agree([G1, G2, G3], timeout=90)
            check("F8 a late joiner syncs the chain of plain-PoW and AuxPoW blocks", ok, why)
            print(f"   GRD at {tipG}: {len(aux)} merge-mined blocks after graduation at {grad_h}", flush=True)

        # ================================================================= F6
        phase("F6 mempool: the settlement lock and transaction relay")
        need = max([h for h, _ in rogue] + [0]) + 102
        wait(lambda: A.rpc.getblockcount() >= need, 900, f"FLT at {need} (coinbase maturity)")

        def spend(wallet, txid, value, to):
            raw = A.rpc.createrawtransaction([{"txid": txid, "vout": 0}], [{to: f"{value - 0.0001:.8f}"}])
            s = wallet.signrawtransactionwithwallet(raw)
            if not s.get("complete"):
                raise RuntimeError(f"could not sign: {s}")
            return s["hex"]

        def coinbase(h):
            blk = A.rpc.getblock(A.rpc.getblockhash(h), 2)
            return blk["tx"][0]["txid"], blk["tx"][0]["vout"][0]

        locked = [h for h, bh in rogue if A.rpc.getblockhash(h) == bh and A.rpc.getmintobligation(h).get("pay", 0) > 0
                  and not A.rpc.getmintobligation(h)["settled"]]
        if check("F6 (setup) an unsettled block that owes sats is in the chain", bool(locked), json.dumps(rogue)):
            txid, out = coinbase(locked[0])
            hexa = spend(wA, txid, out["value"], addrB)
            ea, ec = rpc_err(lambda: A.rpc.sendrawtransaction(hexa)), rpc_err(lambda: C.rpc.sendrawtransaction(hexa))
            check("F6 a matured but unsettled coinbase is rejected by every mempool",
                  ea is not None and ec is not None and "unsettled-coinbase" in ea[1] and "unsettled-coinbase" in ec[1],
                  f"{ea} {ec}")
        tip = A.rpc.getblockcount()
        good = [h for h in range(1, tip - 100) if coinbase(h)[1]["scriptPubKey"]["hex"] == spkA.hex()
                and A.rpc.getmintobligation(h)["settled"]]
        offered = {u["txid"] for u in wA.listunspent(1)}
        check("F6 the node wallet offers settled coinbases and keeps unsettled ones out of coin selection",
              bool(locked) and not offered & {coinbase(h)[0] for h in locked}
              and bool(offered & {coinbase(h)[0] for h in good}), f"{len(offered)} offered")
        check("F6 so a plain wallet send works next to unsettled coinbases",
              rpc_err(lambda: wA.sendtoaddress(addrC, "0.01")) is None)
        if check("F6 (setup) a matured coinbase settled by a Bitcoin payment exists", bool(good), f"tip {tip}"):
            txid, out = coinbase(good[0])
            sent = C.rpc.sendrawtransaction(spend(wA, txid, out["value"], addrB))
            ok = wait(lambda: all(sent in n.rpc.getrawmempool() or n.rpc.getrawtransaction(sent, True).get("confirmations", 0) > 0
                                  for n in (A, B, Dn)), 30, "tx in every mempool")
            check("F6 a settled coinbase spend broadcast on a non-mining node reaches every node", ok)
            ok = wait(lambda: all(n.rpc.getrawtransaction(sent, True).get("confirmations", 0) >= 1 for n in (A, B, C, Dn)),
                      120, "tx confirmed")
            check("F6 it is mined by a pool and confirmed on every node", ok)
            check("F6 the receiving wallet on another node sees the coins",
                  wait(lambda: wB.getreceivedbyaddress(addrB, 1) > 0, 30, "wallet B credit"))

        # ================================================================= F9
        phase("F9 verifychain, settlement across two pools")
        wait(lambda: A.rpc.getblockcount() >= need + 20, 300, "20 more blocks")
        with paused(rigA, rigB):
            check("F9 verifychain (level 4, 80 blocks) passes", B.rpc.verifychain(4, 80) is True)
            ok, why, snap = agree([A, B, C, Dn])
            check("F9 all four nodes still agree, after verifychain", ok, why)
            if snap:
                skip = {h for h, _ in rogue}
                obs = [o for o in snap["obligations"] if o["height"] <= snap["height"] - 60 and o["height"] not in skip]
                stuck = [o["height"] for o in obs if not o["spendable"]]
                paid = [o for o in obs if o["settled"]]
                check("F9 every pool block older than 60 is settled or owes nothing (two pools, two wallets)",
                      not stuck, f"unsettled: {stuck[:20]}")
                payees = {o["payee"] for o in paid}
                check("F9 payments went to holders (and creator or dev draws are honoured too)", "holder" in payees,
                      str(payees))
                print(f"   FLT {snap['height']} blocks: {len(paid)} settled by payment to {sorted(payees)}, "
                      f"{sum(o['pay'] for o in paid)} sats; settler A {setA.status()}, settler B {setB.status()}", flush=True)
            check("F9 no Bitcoin payment was wasted by either pool", not setA.st["lost"] and not setB.st["lost"],
                  json.dumps([setA.st["lost"], setB.st["lost"]]))

            # ============================================================= F10
            phase("F10 stall relief in real time")
            # Both template caches are warm here: A's pool polls getblocktemplate while paused, and
            # the aux block below is asked for now and again after the stall.
            ab1 = G1.rpc.createauxblock(addrG)
            tip_time = max(n.rpc.getblockheader(n.rpc.getbestblockhash())["time"] for n in (A, G1))
            while time.time() < tip_time + 6 * dF.target_spacing + 2:
                time.sleep(0.5)
            ab2 = G1.rpc.createauxblock(addrG)
            check("F10 a stalled merge-mined chain offers a fresh, easier aux block",
                  ab2["hash"] != ab1["hash"] and bits_to_target(int(ab2["bits"], 16)) > bits_to_target(int(ab1["bits"], 16)),
                  f"{ab1['bits']} -> {ab2['bits']}")
            t = A.rpc.getblocktemplate(GBT)
            tip = A.rpc.getblockcount()
            hdrs = [A.rpc.getblockheader(A.rpc.getblockhash(h)) for h in range(tip - dF.lwma_window, tip + 1)]
            times, bits = [x["time"] for x in hdrs], [int(x["bits"], 16) for x in hdrs]
            base, model = dF.next_bits(times, bits), dF.next_bits(times, bits, t["curtime"])
            check("F10 the template's nBits equals the model's relieved target", int(t["bits"], 16) == model and model != base,
                  f"node {t['bits']} model {model:08x} base {base:08x}")
            hdr, txs = block_from_gbt(t, rogue_spk)
            r = A.rpc.submitblock(ser_block(hdr, txs))
            bh = sha256d(hdr)[::-1].hex()
            ok = r is None and wait(lambda: all(n.rpc.getbestblockhash() == bh for n in (B, C, Dn)), 30, "relief block relayed")
            check("F10 every peer accepts the block mined at the relieved difficulty", ok, str(r))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hashfund", required=True)
    ap.add_argument("--bitcoind", required=True, help="stock Bitcoin Core bitcoind")
    ap.add_argument("--workdir", help="keep datadirs and logs here")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    f = Fleet(a)
    print(f"workdir {f.dir}", flush=True)
    t0 = time.time()
    try:
        f.run()
    except Exception as ex:
        traceback.print_exc()
        check("fleet run completed", False, repr(ex))
    finally:
        f.stop()
        failed = [n for n, ok in RESULTS.items() if not ok]
        print(f"\nfleet: {len(RESULTS) - len(failed)}/{len(RESULTS)} passed in {time.time() - t0:.0f}s"
              + (f"; failed: {failed}" if failed else ""), flush=True)
        if not a.workdir and not a.keep and not failed:
            shutil.rmtree(f.dir, ignore_errors=True)
        sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
