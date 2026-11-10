"""End-to-end harness against REAL binaries: hashfund (this fork) for two test
launches and stock Bitcoin Core bitcoind (regtest) as the merge-mining parent.

  python -m hashfun.tests.e2e_regtest --hashfund build/bin/hashfund --bitcoind /path/to/bitcoind

Phases, in order (each check prints PASS/FAIL):
  1  C++ and Python agree on launch id, genesis hash, chain id, graduation work
  2  block subsidies match the independent Python curve model, creator output paid
  3  consensus rejects: excess coinbase, missing creator output, wrong nBits
  4  auxpow before graduation rejected (createauxblock and a hand-built aux block)
  5  LWMA: node's next nBits == Python model for fast/slow mocktime sequences
  6  graduation height/work exact; crossing block mints up to G; tail afterwards
  7  merged mining through the pool against stock bitcoind (real CAuxPow::check)
  8  standalone pool mining on the second (presale) launch
  9  Electrum servers + HD wallet + maker: atomic swap BTC -> launch coins

--workdir keeps chains, wallets and results between invocations, so the phases
can be split across processes on hosts that cap a command's runtime:
  --workdir W --phases 1-6;  --workdir W --phases 7-8;  --workdir W --phases 9
Genesis is dated a day back and phases 1-6 run on mocktime, so the real-time
phases (7-9) start with every chain clock behind the wall clock.
"""
import argparse
import asyncio
import glob
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback

from hashfun import descriptor as D
from hashfun.auxpow import AuxTree, serialize_auxpow
from hashfun.crypto import sha256d, pubkey_from_priv, random_priv, hash160
from hashfun.electrum import ElectrumServer
from hashfun.miner import StratumMiner
from hashfun.rpc import RPC, RPCError
from hashfun.ser import (Tx, TxIn, TxOut, header_bytes, merkle_root, bits_to_target, work_from_bits, push_int, push,
                         address_to_script, varint)
from hashfun.stratum import LaunchSource, MergedSource, StratumServer
from hashfun.swap import KeyStore, Maker, NodeChain, relay_handler
from hashfun.wallet import Wallet, LAUNCH_COIN_BASE

COIN = 100_000_000
DAY = 86400
RESULTS = {}


def check(name, cond, detail=""):
    RESULTS[name] = bool(cond)
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""), flush=True)
    return cond


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def coins_to_sats(v) -> int:
    return round(v * COIN)


class Node:
    def __init__(self, binary, datadir, args, rpcport):
        self.binary, self.datadir = binary, datadir
        os.makedirs(datadir, exist_ok=True)
        self.errlog = os.path.join(datadir, "stderr.log")
        with open(self.errlog, "ab") as err:
            self.proc = subprocess.Popen([binary, f"-datadir={datadir}", "-server=1", "-listen=0", "-txindex=1",
                                          "-fallbackfee=0.0001", f"-rpcport={rpcport}", "-printtoconsole=0"] + args,
                                         stdout=subprocess.DEVNULL, stderr=err)
        self.url = f"http://127.0.0.1:{rpcport}"
        deadline = time.time() + 120
        while time.time() < deadline:
            if self.proc.poll() is not None:
                with open(self.errlog, "rb") as f:
                    tail = f.read()[-2000:].decode(errors="replace")
                raise RuntimeError(f"{os.path.basename(binary)} exited {self.proc.returncode}: {tail}")
            # The cookie lives in the network subdir (regtest/, launch_<ticker>_<id8>/); a stale one
            # from a killed run fails auth until the node rewrites it, so just keep retrying.
            for cookie in glob.glob(os.path.join(datadir, "*", ".cookie")):
                try:
                    rpc = RPC(self.url, cookie_file=cookie)
                    rpc.getblockcount()
                    self.rpc = rpc
                    return
                except Exception:
                    pass
            time.sleep(0.2)
        self.proc.kill()
        raise RuntimeError(f"{binary} did not start")

    def stop(self):
        try:
            self.rpc.stop()
            self.proc.wait(60)
        except Exception:
            self.proc.kill()


def open_wallet(rpc: RPC, name="w") -> RPC:
    try:
        rpc.loadwallet(name)
    except RPCError as e:
        if e.code == -18:  # not found
            rpc.createwallet(name)
        elif e.code != -35:  # already loaded
            raise
    return rpc.wallet(name)


def mk_launch(ticker, creator_spk, graduation_blocks, genesis_time):
    # pow limit 0x207FFFFF: ~2 expected hashes per block, so W_g ~ 2 * graduation_blocks.
    d = D.make(f"{ticker} e2e", ticker, creator_spk, 2 * graduation_blocks, test=True, pow_limit_bits=0x207FFFFF,
               target_spacing=10, lwma_window=10, genesis_time=genesis_time)
    d.ftl = 7200
    d.grind_genesis()
    return d


def solve(header76: bytes, target: int) -> bytes:
    n = 0
    while True:
        h = header76 + struct.pack("<I", n)
        if int.from_bytes(sha256d(h), "little") <= target:
            return h
        n += 1


def block_from_gbt(t, payout_spk, *, extra_value=0, drop_creator=False, bits=None, version=None, auxpow=b""):
    outs = [TxOut(t["coinbasevalue"] + extra_value, payout_spk)]
    if "creatorfee" in t and not drop_creator:
        outs.append(TxOut(t["creatorfee"]["amount"], bytes.fromhex(t["creatorfee"]["script"])))
    outs.append(TxOut(0, bytes.fromhex(t["default_witness_commitment"])))
    cb = Tx(version=2, vin=[TxIn(b"\0" * 32, 0xFFFFFFFF, push_int(t["height"]) + push(os.urandom(4)), 0xFFFFFFFF,
                                 [b"\0" * 32])], vout=outs)
    txs = [cb] + [Tx.parse(bytes.fromhex(x["data"])) for x in t["transactions"]]
    b = bits if bits is not None else int(t["bits"], 16)
    v = version if version is not None else t["version"]
    hdr = header_bytes(v, bytes.fromhex(t["previousblockhash"])[::-1], merkle_root([x.txid() for x in txs]),
                       t["curtime"], b, 0)
    if not auxpow:
        hdr = solve(hdr[:76], bits_to_target(b))
    return hdr, txs


def ser_block(hdr, txs, auxpow=b""):
    return (hdr + auxpow + varint(len(txs)) + b"".join(x.serialize() for x in txs)).hex()


def coinbase_total(blk) -> int:
    return sum(coins_to_sats(o["value"]) for o in blk["tx"][0]["vout"])


class E2E:
    def __init__(self, a):
        self.a = a
        self.dir = os.path.abspath(a.workdir) if a.workdir else tempfile.mkdtemp(prefix="hashfun-e2e-")
        os.makedirs(self.dir, exist_ok=True)
        self.state_file = os.path.join(self.dir, "state.json")
        if os.path.exists(self.state_file):
            with open(self.state_file) as f:
                self.st = json.load(f)
        else:
            g = int(time.time()) - DAY
            self.st = {"genesis_time": g, "T": g + 100, "creator_key": random_priv(), "results": {}, "done": []}
        self.creator_spk = b"\x00\x14" + hash160(pubkey_from_priv(self.st["creator_key"]))
        self.d = {}
        # GRAD graduates around block 36 of this script (after the LWMA burst); PRE never does.
        for ticker, grad_blocks in (("GRAD", 60), ("PRE", 10**7)):
            p = os.path.join(self.dir, f"{ticker}.json")
            if os.path.exists(p):
                self.d[ticker] = D.load(p)
            else:
                self.d[ticker] = mk_launch(ticker, self.creator_spk, grad_blocks, self.st["genesis_time"])
                with open(p, "w") as f:
                    f.write(self.d[ticker].dumps())
        self.d1, self.d2 = self.d["GRAD"], self.d["PRE"]
        self.nodes = []
        self.hdr_cache = {}
        self._loop = None

    # ------------------------------------------------------------ plumbing
    def save(self):
        self.st["results"].update(RESULTS)
        with open(self.state_file + ".tmp", "w") as f:
            json.dump(self.st, f, indent=1)
        os.replace(self.state_file + ".tmp", self.state_file)

    def start(self, mock: bool):
        a = self.a
        self.btc = Node(a.bitcoind, os.path.join(self.dir, "btc"), ["-regtest"], free_port())
        self.nodes.append(self.btc)
        self.n1 = Node(a.hashfund, os.path.join(self.dir, "n1"), [f"-launch={os.path.join(self.dir, 'GRAD.json')}"],
                       free_port())
        self.nodes.append(self.n1)
        self.n2 = Node(a.hashfund, os.path.join(self.dir, "n2"), [f"-launch={os.path.join(self.dir, 'PRE.json')}"],
                       free_port())
        self.nodes.append(self.n2)
        self.wb, self.w1, self.w2 = (open_wallet(n.rpc) for n in (self.btc, self.n1, self.n2))
        self.addr1 = self.w1.getnewaddress("", "bech32")
        self.spk1 = address_to_script(self.addr1, self.d1.hrp)
        self.btc_addr = self.wb.getnewaddress("", "bech32")
        if mock:
            self.n1.rpc.setmocktime(self.st["T"])

    def stop(self):
        for n in self.nodes:
            n.stop()

    @property
    def loop(self):
        if self._loop is None:
            self._loop = asyncio.new_event_loop()
            threading.Thread(target=self._loop.run_forever, daemon=True).start()
        return self._loop

    def step(self, dt):
        """Phases 1-6: advance GRAD's mocktime."""
        self.st["T"] += dt
        self.n1.rpc.setmocktime(self.st["T"])

    def header(self, h):
        if h not in self.hdr_cache:
            hh = self.n1.rpc.getblockheader(self.n1.rpc.getblockhash(h))
            self.hdr_cache[h] = (hh["time"], int(hh["bits"], 16), hh["version"])
        return self.hdr_cache[h]

    def rel_work(self, height):
        """Python's own chainwork above genesis, from the headers' nBits."""
        return sum(work_from_bits(self.header(h)[1]) for h in range(1, height + 1))

    def mine_paced(self, node, w, n, addr, spacing):
        """Mine n blocks spaced at the target, never behind the wall clock. A real-time burst
        on a 10 s LWMA chain would ratchet difficulty ~1.4x per block until the CPU miner stalls."""
        for _ in range(n):
            tip = node.rpc.getblockheader(node.rpc.getbestblockhash())
            node.rpc.setmocktime(max(int(time.time()), tip["time"] + spacing))
            w.generatetoaddress(1, addr)

    # ------------------------------------------------------------ phases
    def p1(self):
        d1, d2 = self.d1, self.d2
        i1 = self.n1.rpc.getlaunchinfo()
        check("1 launch id C++ == Python", i1["launch_id"] == d1.id_hex, f"{i1['launch_id']} vs {d1.id_hex}")
        check("1 genesis hash C++ == Python", i1["genesis_hash"] == d1.genesis_hash,
              f"{i1['genesis_hash']} vs {d1.genesis_hash}")
        check("1 chain id C++ == Python", i1["chain_id"] == d1.chain_id, f"{i1['chain_id']} vs {d1.chain_id}")
        check("1 graduation work C++ == Python", int(i1["curve"]["graduation_work"], 16) == d1.graduation_work,
              f"{i1['curve']['graduation_work']} vs {d1.graduation_work:x}")
        i2 = self.n2.rpc.getlaunchinfo()
        check("1 second launch id/genesis C++ == Python",
              i2["launch_id"] == d2.id_hex and i2["genesis_hash"] == d2.genesis_hash)

    def p2(self):
        d1, n1 = self.d1, self.n1
        ok, detail = True, ""
        for _ in range(12):
            self.step(d1.target_spacing)
            blk = n1.rpc.getblock(self.w1.generatetoaddress(1, self.addr1)[0], 2)
            h = blk["height"]
            model = d1.subsidy(self.rel_work(h - 1), int(blk["bits"], 16), h)
            total = coinbase_total(blk)
            creator = sum(coins_to_sats(o["value"]) for o in blk["tx"][0]["vout"]
                          if o["scriptPubKey"]["hex"] == self.creator_spk.hex())
            if ok and not (total == model and creator >= d1.creator_fee(model) > 0):
                ok, detail = False, f"h{h}: coinbase {total} model {model} creator {creator}/{d1.creator_fee(model)}"
        check("2 coinbase == Python curve subsidy, creator paid", ok, detail)
        info = n1.rpc.getlaunchinfo()
        w = self.rel_work(info["height"])
        check("2 relative work C++ == Python", int(info["work"], 16) == w, f"{info['work']} vs {w:x}")
        check("2 curve_supply == Python S(W)", info["curve_supply"] == d1.curve_supply(w),
              f"{info['curve_supply']} vs {d1.curve_supply(w)}")

    def p3(self):
        n1, spk = self.n1, self.spk1
        self.step(self.d1.target_spacing)
        t = n1.rpc.getblocktemplate({"rules": ["segwit"]})
        check("3 creatorfee advertised in GBT", t.get("creatorfee", {}).get("script") == self.creator_spk.hex(),
              json.dumps(t.get("creatorfee")))
        r = n1.rpc.submitblock(ser_block(*block_from_gbt(t, spk, extra_value=1)))
        check("3 reject excess coinbase", r == "bad-cb-amount", r)
        r = n1.rpc.submitblock(ser_block(*block_from_gbt(t, spk, drop_creator=True)))
        check("3 reject missing creator output", r == "bad-cb-creator-fee", r)
        r = n1.rpc.submitblock(ser_block(*block_from_gbt(t, spk, bits=0x2007FFFF)))
        check("3 reject wrong nBits", r == "bad-diffbits", r)
        r = n1.rpc.submitblock(ser_block(*block_from_gbt(t, spk)))
        check("3 accept the honest template block", r is None, r)

    def p4(self):
        d1, n1 = self.d1, self.n1
        if n1.rpc.getlaunchinfo()["graduated"]:
            check("4 chain still pre-graduation", False, "graduated early; raise GRAD graduation_blocks")
            return
        try:
            n1.rpc.createauxblock(self.addr1)
            check("4 createauxblock refused pre-graduation", False)
        except RPCError as e:
            check("4 createauxblock refused pre-graduation", "graduat" in (e.message or ""), e.message)
        t = n1.rpc.getblocktemplate({"rules": ["segwit"]})
        hdr, txs = block_from_gbt(t, self.spk1, version=t["version"] | 0x100, auxpow=b"pending")
        tree = AuxTree({d1.chain_id: sha256d(hdr)})
        pcb = Tx(version=1, vin=[TxIn(b"\0" * 32, 0xFFFFFFFF, push_int(1) + tree.commitment_push(), 0xFFFFFFFF)],
                 vout=[TxOut(0, b"\x6a")])
        phdr = solve(header_bytes(0x20000000, b"\x11" * 32, pcb.txid(), t["curtime"], 0x207FFFFF, 0)[:76],
                     bits_to_target(int(t["bits"], 16)))
        r = n1.rpc.submitblock(ser_block(hdr, txs, serialize_auxpow(pcb, [], [], 0, phdr)))
        check("4 hand-built auxpow block rejected pre-graduation", r == "auxpow-before-graduation", r)

    def p5(self):
        d1, n1 = self.d1, self.n1
        ok, detail = True, ""
        for step in [1] * 8 + [40] * 6:
            self.step(step)
            self.w1.generatetoaddress(1, self.addr1)
            tip = n1.rpc.getblockcount()
            hs = [self.header(h) for h in range(tip + 1)]
            model = d1.lwma_next_bits([x[0] for x in hs], [x[1] for x in hs])
            node = int(n1.rpc.getlaunchinfo()["next"]["bits"], 16)
            if ok and model != node:
                ok, detail = False, f"after h{tip}: node {node:08x} model {model:08x}"
        check("5 LWMA next bits C++ == Python", ok, detail)
        bits = [self.header(h)[1] for h in range(1, n1.rpc.getblockcount() + 1)]
        check("5 LWMA actually retargeted", len(set(bits)) > 3, f"{sorted(set(bits))}")

    def p6(self):
        d1, n1 = self.d1, self.n1
        for _ in range(5000):
            if n1.rpc.getlaunchinfo()["graduated"]:
                break
            self.step(d1.target_spacing)
            self.w1.generatetoaddress(1, self.addr1)
        info = n1.rpc.getlaunchinfo()
        tip = info["height"]
        works = [work_from_bits(self.header(h)[1]) for h in range(1, tip + 1)]
        acc, model_gh = 0, None
        for i, wk in enumerate(works, 1):
            acc += wk
            if acc >= d1.graduation_work:
                model_gh = i
                break
        check("6 graduation height C++ == Python", info["graduation_height"] == model_gh,
              f"{info['graduation_height']} vs {model_gh}")
        check("6 curve supply == G at graduation", info["curve_supply"] == d1.graduation_tokens,
              f"{info['curve_supply']} vs {d1.graduation_tokens}")
        if model_gh:
            cross = coinbase_total(n1.rpc.getblock(n1.rpc.getblockhash(model_gh), 2))
            expect = d1.graduation_tokens - d1.curve_supply(sum(works[:model_gh - 1]))
            check("6 crossing block mints exactly up to G", cross == expect, f"{cross} vs {expect}")
        self.step(d1.target_spacing)
        cbv = coinbase_total(n1.rpc.getblock(self.w1.generatetoaddress(1, self.addr1)[0], 2))
        check("6 post-graduation block pays tail", cbv == d1.tail_reward_at(tip + 1),
              f"{cbv} vs {d1.tail_reward_at(tip + 1)}")
        check("6 next block may be merge-mined", n1.rpc.getlaunchinfo()["next"]["auxpow_allowed"] is True)

    def p7(self):
        btc, n1, n2, d1, d2 = self.btc, self.n1, self.n2, self.d1, self.d2
        for n in (btc, n1, n2):
            n.rpc.setmocktime(0)
        port = free_port()
        src = MergedSource(btc.rpc, "bcrt", {"GRAD": {"rpc": n1.rpc, "hrp": d1.hrp, "payout": self.addr1},
                                             "PRE": {"rpc": n2.rpc, "hrp": d2.hrp,
                                                     "payout": self.w2.getnewaddress("", "bech32")}},
                           default_payout=self.btc_addr)
        asyncio.run_coroutine_threadsafe(StratumServer(src, "127.0.0.1", port, difficulty=1e-6,
                                                       poll_interval=0.2).serve(), self.loop)
        time.sleep(1)
        h_grad, h_btc, h_pre = n1.rpc.getblockcount(), btc.rpc.getblockcount(), n2.rpc.getblockcount()
        m = StratumMiner("127.0.0.1", port, self.btc_addr, batch=4096)
        t0 = time.time()
        while (n1.rpc.getblockcount() < h_grad + 3 or btc.rpc.getblockcount() < h_btc + 2) and time.time() - t0 < 90:
            asyncio.run_coroutine_threadsafe(m.run(duration=3), self.loop).result(60)
        tip = n1.rpc.getblockcount()
        aux = [h for h in range(h_grad + 1, tip + 1)
               if n1.rpc.getblockheader(n1.rpc.getblockhash(h))["version"] & 0x100]
        print(f"   GRAD +{tip - h_grad} ({len(aux)} merge-mined), BTC +{btc.rpc.getblockcount() - h_btc} "
              f"in {time.time() - t0:.0f}s", flush=True)
        check("7 merge-mined blocks accepted by hashfund", tip >= h_grad + 3 and aux, f"+{tip - h_grad}, aux {aux}")
        check("7 parent blocks accepted by stock bitcoind", btc.rpc.getblockcount() >= h_btc + 2)
        check("7 presale launch got no aux blocks", n2.rpc.getblockcount() == h_pre)

    def p8(self):
        n2, d2 = self.n2, self.d2
        n2.rpc.setmocktime(0)
        h_pre = n2.rpc.getblockcount()
        port = free_port()
        addr2 = self.w2.getnewaddress("", "bech32")
        asyncio.run_coroutine_threadsafe(StratumServer(LaunchSource(n2.rpc, d2.hrp, d2.ticker), "127.0.0.1", port,
                                                       difficulty=1e-6, poll_interval=0.2).serve(), self.loop)
        time.sleep(1)
        m = StratumMiner("127.0.0.1", port, addr2, batch=4096)
        t0 = time.time()
        while n2.rpc.getblockcount() < h_pre + 3 and time.time() - t0 < 60:
            asyncio.run_coroutine_threadsafe(m.run(duration=3), self.loop).result(60)
        check("8 pool-mined blocks accepted on presale launch", n2.rpc.getblockcount() >= h_pre + 3,
              f"+{n2.rpc.getblockcount() - h_pre}")

    def p9(self):
        btc, n1, d1, wb, w1 = self.btc, self.n1, self.d1, self.wb, self.w1
        btc.rpc.setmocktime(0)
        # Coinbase maturity on both chains. BTC regtest never retargets; GRAD is paced.
        wb.generatetoaddress(101, self.btc_addr)
        self.mine_paced(n1, w1, max(2, 102 - n1.rpc.getblockcount()), self.addr1, d1.target_spacing)
        print(f"   balances: BTC {wb.getbalance()}  GRAD {w1.getbalance()}", flush=True)
        ep = {}
        for name, n in (("BTC", btc), ("GRAD", n1)):
            ep[name] = free_port()
            asyncio.run_coroutine_threadsafe(ElectrumServer(n.rpc, "127.0.0.1", ep[name]).serve(), self.loop)
        time.sleep(2)
        wal = Wallet.create(os.path.join(self.dir, f"wallet-{int(time.time())}.json"))
        wal.add_chain("BTC", f"127.0.0.1:{ep['BTC']}", "bcrt", 1, "btc")
        wal.add_chain("GRAD", f"127.0.0.1:{ep['GRAD']}", d1.hrp, LAUNCH_COIN_BASE + d1.chain_id)
        wb.sendtoaddress(wal.chains["BTC"].address(0, 0), 5)
        wb.generatetoaddress(1, self.btc_addr)
        ks = KeyStore(os.path.join(self.dir, "maker_keys.json"))
        hp = 1000 / n1.rpc.getlaunchinfo()["hashes_per_coin"] * 1e12  # -> 1000 sats per GRAD
        cfg = {"defaults": {"hashprice_sats_per_th": hp, "spread": 0.02, "btc_confs": 1, "fork_confs": 2,
                            "init_lock_seconds": 3600, "part_lock_seconds": 900, "lock_margin_seconds": 300,
                            "safety": 1e12}}
        mk = Maker(NodeChain("BTC", wb, "bcrt"), {"GRAD": NodeChain("GRAD", w1, d1.hrp)}, ks, cfg,
                   os.path.join(self.dir, f"orders-{int(time.time())}.json"))
        from http.server import ThreadingHTTPServer
        rport = free_port()
        threading.Thread(target=ThreadingHTTPServer(("127.0.0.1", rport), relay_handler(mk)).serve_forever,
                         daemon=True).start()
        time.sleep(1)
        out = {}

        def taker():
            try:
                out["rec"] = wal.swap(f"http://127.0.0.1:{rport}", "GRAD", "buy", 100 * COIN, poll=1, log=print)
            except Exception as e:
                out["err"] = repr(e)
                traceback.print_exc()

        tt = threading.Thread(target=taker, daemon=True)
        tt.start()
        t0 = time.time()
        while tt.is_alive() and time.time() - t0 < 100:
            wb.generatetoaddress(1, self.btc_addr)
            self.mine_paced(n1, w1, 1, self.addr1, d1.target_spacing)
            mk.tick()
            time.sleep(1)
        tt.join(5)
        rec = out.get("rec") or {}
        check("9 taker redeemed launch coins", rec.get("state") == "done", out.get("err") or rec.get("state"))
        o = None
        for _ in range(20):
            o = list(mk.orders.values())[-1] if mk.orders else None
            if o and o.state == "done":
                break
            wb.generatetoaddress(1, self.btc_addr)
            self.mine_paced(n1, w1, 1, self.addr1, d1.target_spacing)
            mk.tick()
            time.sleep(1)
        check("9 maker redeemed BTC with revealed secret", o is not None and o.state == "done",
              o and f"{o.state}: {o.note}")


def parse_phases(s):
    out = []
    for part in s.split(","):
        lo, _, hi = part.partition("-")
        out += range(int(lo), int(hi or lo) + 1)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hashfund", required=True)
    ap.add_argument("--bitcoind", required=True, help="stock Bitcoin Core bitcoind")
    ap.add_argument("--workdir", help="persist chains, wallets and results here (lets --phases span runs)")
    ap.add_argument("--phases", default="1-9", help="e.g. 1-6 or 7,8 (in order, each once)")
    ap.add_argument("--keep", action="store_true", help="keep the temporary datadirs")
    a = ap.parse_args()
    phases = parse_phases(a.phases)
    e = E2E(a)
    print(f"workdir {e.dir}", flush=True)
    missing = [q for q in range(1, min(phases)) if q not in e.st["done"]] + \
              [q for q, nxt in zip(phases, phases[1:]) if nxt != q + 1]
    if missing:
        sys.exit(f"phases must run in order, each after its predecessors (missing/out of order: {missing})")
    t_all = time.time()
    try:
        e.start(mock=min(phases) <= 6)
        for p in phases:
            t0 = time.time()
            print(f"-- phase {p}", flush=True)
            ok = False
            try:
                getattr(e, f"p{p}")()
                ok = True
            except Exception as ex:
                traceback.print_exc()
                check(f"{p} phase completed", False, repr(ex))
            if ok:
                e.st["results"].pop(f"{p} phase completed", None)
                if p not in e.st["done"]:
                    e.st["done"].append(p)
            e.save()
            print(f"   phase {p}: {time.time() - t0:.1f}s", flush=True)
            if not ok:
                break
    finally:
        e.stop()
        e.save()
        if not a.workdir and not a.keep:
            shutil.rmtree(e.dir, ignore_errors=True)
        allres = e.st["results"]
        failed = [n for n, ok in allres.items() if not ok]
        print(f"\nthis run: {sum(RESULTS.values())}/{len(RESULTS)} passed in {time.time() - t_all:.0f}s; "
              f"workdir total: {len(allres) - len(failed)}/{len(allres)}" + (f"; failed: {failed}" if failed else ""))
        sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
