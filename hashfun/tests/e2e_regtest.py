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
  10 sats leg in detail on a third launch: curve blocks owe real BTC to a drawn payee; Bitcoin headers
     and SPV payment proofs ride in coinbases; unsettled coinbases cannot be spent
  11 the pool settles on its own: Settler relays headers, pays each drawn payee from a Bitcoin
     wallet and publishes the proofs while a stratum miner mines a fresh sats-leg launch

--workdir keeps chains, wallets and results between invocations, so the phases
can be split across processes on hosts that cap a command's runtime:
  --workdir W --phases 1-6;  --workdir W --phases 7-8;  --workdir W --phases 9;  ... --phases 10;  --phases 11
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
from hashfun import yieldmodel as Y
from hashfun.settler import Settler

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


def block_from_gbt(t, payout_spk, *, extra_value=0, drop_creator=False, bits=None, version=None, auxpow=b"",
                   extra_outs=(), extra_txs=(), cb_prefix=None):
    outs = [TxOut(t["coinbasevalue"] + extra_value, payout_spk)]
    if "creatorfee" in t and not drop_creator:
        outs.append(TxOut(t["creatorfee"]["amount"], bytes.fromhex(t["creatorfee"]["script"])))
    outs += list(extra_outs)
    commitment = bytes.fromhex(t["default_witness_commitment"])
    if extra_txs:  # the commitment covers every wtxid, so it has to be redone
        body = [Tx.parse(bytes.fromhex(x["data"])) for x in t["transactions"]] + list(extra_txs)
        wroot = merkle_root([b"\0" * 32] + [sha256d(x.serialize(witness=True)) for x in body])
        commitment = bytes.fromhex("6a24aa21a9ed") + sha256d(wroot + b"\0" * 32)
    outs.append(TxOut(0, commitment))
    if cb_prefix is None:  # a launch's coinbase starts with the height and the launch; the template says how
        cb_prefix = bytes.fromhex(t["launchcoinbase"]) if "launchcoinbase" in t else push_int(t["height"])
    cb = Tx(version=2, vin=[TxIn(b"\0" * 32, 0xFFFFFFFF, cb_prefix + push(os.urandom(4)), 0xFFFFFFFF,
                                 [b"\0" * 32])], vout=outs)
    txs = [cb] + [Tx.parse(bytes.fromhex(x["data"])) for x in t["transactions"]] + list(extra_txs)
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
        if mock:
            # Before the wallet exists: a wallet skips blocks stamped more than 2 h before its
            # birth time, and phases 1-6 stamp GRAD blocks a day in the past.
            self.n1.rpc.setmocktime(self.st["T"])
        self.wb, self.w1, self.w2 = (open_wallet(n.rpc) for n in (self.btc, self.n1, self.n2))
        self.addr1 = self.w1.getnewaddress("", "bech32")
        self.spk1 = address_to_script(self.addr1, self.d1.hrp)
        self.btc_addr = self.wb.getnewaddress("", "bech32")

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
        """Mine n launch blocks spaced at the target, never behind the wall clock. A real-time
        burst on a 10 s LWMA chain ratchets difficulty ~1.4x per block (phase 7 leaves GRAD at
        ~0.5-1M hashes/block), so while the next block costs >100k hashes the spacing is 6T,
        LWMA's solvetime cap, which unwinds it in a few blocks. generatetoaddress returns []
        when it runs out of tries, so every block is retried until it lands."""
        for _ in range(n):
            for _attempt in range(20):
                self.pace(node, spacing)
                if w.generatetoaddress(1, addr, 50_000_000):
                    break
            else:
                raise RuntimeError("paced mining made no progress")

    @staticmethod
    def pace(node, spacing):
        tip = node.rpc.getblockheader(node.rpc.getbestblockhash())
        heavy = int(node.rpc.getlaunchinfo()["next"]["work"], 16) > 100_000
        node.rpc.setmocktime(max(int(time.time()), tip["time"] + (6 if heavy else 1) * spacing))

    def settle_curve(self, node, d, payout_spk) -> bool:
        """Every launch has a sats leg, so curve coinbases are locked until their Bitcoin payment
        is proven. Run the Settler for all of this chain's curve blocks, carrying its headers and
        proofs in hand-built blocks, until every one of them is spendable."""
        settler = Settler(node.rpc, self.wb, os.path.join(self.dir, f"settler-{d.ticker}-{int(time.time())}.json"),
                          pay_depth=0)
        grad = node.rpc.getlaunchinfo()["graduation_height"]
        last = grad if grad > 0 else node.rpc.getblockcount()
        for h in range(1, last + 1):
            settler.add_block(h, node.rpc.getblockhash(h))
        for _ in range(40):
            if all(node.rpc.getmintobligation(h)["spendable"] for h in range(1, last + 1)):
                print(f"   {d.ticker}: {last} curve blocks settled, {settler.status()}", flush=True)
                return True
            outs = settler.coinbase_outputs()
            self.wb.generatetoaddress(1, self.btc_addr)
            self.pace(node, d.target_spacing)
            t = node.rpc.getblocktemplate({"rules": ["segwit"]})
            r = node.rpc.submitblock(ser_block(*block_from_gbt(t, payout_spk, extra_outs=outs)))
            if r is not None:
                raise RuntimeError(f"settlement block rejected: {r}")
        return False

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
        # Every coinbase names its launch right after the height, so no transaction exists on two launches.
        h, d1 = t["height"], self.d1
        check("3 the template's coinbase prefix is the height, then 16 bytes of the launch id (the rules' own arithmetic)",
              t.get("launchcoinbase") == d1.coinbase_prefix(h).hex() == (push_int(h) + push(d1.id[:16])).hex(),
              f"{t.get('launchcoinbase')} vs {d1.coinbase_prefix(h).hex()}")
        r = n1.rpc.submitblock(ser_block(*block_from_gbt(t, spk, cb_prefix=push_int(h))))
        check("3 reject a coinbase that does not name the launch", r == "bad-cb-launch-id", r)
        r = n1.rpc.submitblock(ser_block(*block_from_gbt(t, spk, cb_prefix=push_int(h) + push(self.d2.id[:16]))))
        check("3 reject a coinbase that names another launch", r == "bad-cb-launch-id", r)
        r = n1.rpc.submitblock(ser_block(*block_from_gbt(t, spk, cb_prefix=push_int(h) + push(d1.id[:15]))))
        check("3 reject a coinbase that names the launch by 15 bytes", r == "bad-cb-launch-id", r)
        r = n1.rpc.submitblock(ser_block(*block_from_gbt(t, spk, cb_prefix=push(d1.id[:16]) + push_int(h))))
        check("3 reject the launch before the height", r == "bad-cb-height", r)
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

        def run(steps):
            nonlocal ok, detail
            for step in steps:
                self.step(step)
                self.w1.generatetoaddress(1, self.addr1)
                tip = n1.rpc.getblockcount()
                hs = [self.header(h) for h in range(tip + 1)]
                model = d1.lwma_next_bits([x[0] for x in hs], [x[1] for x in hs])
                node = int(n1.rpc.getlaunchinfo()["next"]["bits"], 16)
                if ok and model != node:
                    ok, detail = False, f"after h{tip}: node {node:08x} model {model:08x}"

        run([1] * 8)
        # Stall relief: difficulty is now ~10x the floor. With no block for 3 x 6T the target
        # must be exactly 8x easier, the un-relieved bits must be refused, and the block connects.
        tip = n1.rpc.getblockcount()
        hs = [self.header(h) for h in range(tip + 1)]
        times, bits = [x[0] for x in hs], [x[1] for x in hs]
        base = d1.lwma_next_bits(times, bits)
        self.step(18 * d1.target_spacing)
        t = n1.rpc.getblocktemplate({"rules": ["segwit"]})
        want = d1.next_bits(times, bits, t["curtime"])
        check("5 stall relief: template nBits C++ == Python", int(t["bits"], 16) == want != base,
              f"node {t['bits']} model {want:08x} base {base:08x}")
        ratio = bits_to_target(want) / bits_to_target(base)
        check("5 stall relief: target 8x easier after 18T", abs(ratio - 8) < 0.01, f"{ratio}")
        r = n1.rpc.submitblock(ser_block(*block_from_gbt(t, self.spk1, bits=base)))
        check("5 stall relief: un-relieved nBits rejected", r == "bad-diffbits", r)
        model = d1.subsidy(self.rel_work(tip), want, tip + 1)
        check("5 stall relief: relieved block mints by its own work",
              t["coinbasevalue"] + t.get("creatorfee", {}).get("amount", 0) == model,
              f"{t['coinbasevalue']} + fee vs {model}")
        r = n1.rpc.submitblock(ser_block(*block_from_gbt(t, self.spk1)))
        check("5 stall relief: relieved block accepted", r is None, r)
        run([40] * 6)
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
        # A curve block's draw is seeded by the hash that carried the seed block's work. A merge-mined
        # block's own hash is not that (it can be re-rolled for free): its parent chain's block hash is.
        seeded = []
        for a_h in aux:
            ob = n1.rpc.getmintobligation(a_h - Y.DRAW_DELAY) if a_h > Y.DRAW_DELAY else None
            if not ob or not ob["curve"] or not ob["draw_known"]:
                continue
            parent = n1.rpc.getblock(n1.rpc.getblockhash(a_h), 1)["auxpow"]["parentblock"]
            parent_hash = sha256d(bytes.fromhex(parent)) if isinstance(parent, str) else bytes.fromhex(parent["hash"])[::-1]
            pay_amt, payee = Y.compute_draw(ob["owed"], d1.sats_min_payment, Y.draw_seed(d1.id, parent_hash))
            if payee == 0 and ob["earning"] == 0:
                pay_amt = 0
            seeded.append((ob["height"], (ob["pay"], ob["payee"]) == (pay_amt, ("holder", "creator", "dev")[payee])))
        check("7 a merge-mined block seeds the draw with its parent chain's block hash",
              len(seeded) >= 1 and all(ok for _, ok in seeded), str(seeded))
        check("7 presale launch got no aux blocks", n2.rpc.getblockcount() == h_pre)

    def p8(self):
        n1, n2, d1, d2 = self.n1, self.n2, self.d1, self.d2
        n1.rpc.setmocktime(0)
        n2.rpc.setmocktime(0)
        h_pre, h_grad = n2.rpc.getblockcount(), n1.rpc.getblockcount()
        port = free_port()
        addr2 = self.w2.getnewaddress("", "bech32")
        # PRE's own (presale) pool also carries GRAD: presale hash secures graduated launches.
        src = LaunchSource(n2.rpc, d2.hrp, d2.ticker,
                           children={"GRAD": {"rpc": n1.rpc, "hrp": d1.hrp, "payout": self.addr1}})
        asyncio.run_coroutine_threadsafe(StratumServer(src, "127.0.0.1", port, difficulty=1e-6,
                                                       poll_interval=0.2).serve(), self.loop)
        time.sleep(1)
        m = StratumMiner("127.0.0.1", port, addr2, batch=4096)
        t0 = time.time()
        while n2.rpc.getblockcount() < h_pre + 3 and time.time() - t0 < 60:
            asyncio.run_coroutine_threadsafe(m.run(duration=3), self.loop).result(60)
        check("8 pool-mined blocks accepted on presale launch", n2.rpc.getblockcount() >= h_pre + 3,
              f"+{n2.rpc.getblockcount() - h_pre}")
        via_pre = 0
        for h in range(h_grad + 1, n1.rpc.getblockcount() + 1):
            blk = n1.rpc.getblock(n1.rpc.getblockhash(h), 1)
            parent = (blk.get("auxpow") or {}).get("parentblock")
            if parent:
                version = parent["version"] if isinstance(parent, dict) else \
                    int.from_bytes(bytes.fromhex(parent)[:4], "little", signed=True)
                via_pre += version >> 16 == d2.chain_id
        print(f"   GRAD +{n1.rpc.getblockcount() - h_grad}, {via_pre} with a PRE header as AuxPoW parent", flush=True)
        check("8 presale blocks accepted as AuxPoW parents by a graduated launch", via_pre >= 1, f"{via_pre}")

    def p9(self):
        btc, n1, d1, wb, w1 = self.btc, self.n1, self.d1, self.wb, self.w1
        btc.rpc.setmocktime(0)
        # Coinbase maturity on both chains. BTC regtest never retargets; GRAD is paced.
        wb.generatetoaddress(101, self.btc_addr)
        self.mine_paced(n1, w1, max(2, 102 - n1.rpc.getblockcount()), self.addr1, d1.target_spacing)
        check("9 curve coinbases unlocked by proven Bitcoin payments (settler)", self.settle_curve(n1, d1, self.spk1))
        for _ in range(20):  # the maker needs mature launch coins before it can lock its leg
            if w1.getbalance() >= 1000:
                break
            self.mine_paced(n1, w1, 1, self.addr1, d1.target_spacing)
        print(f"   balances: BTC {wb.getbalance()}  GRAD {w1.getbalance()}  "
              f"(GRAD clock {n1.rpc.getblockheader(n1.rpc.getbestblockhash())['time'] - int(time.time()):+d}s)",
              flush=True)
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

    # ------------------------------------------------------------ phase 10: sats leg
    def p10(self):
        a, btc, wb = self.a, self.btc, self.wb
        btc.rpc.setmocktime(0)
        if wb.getbalance() < 10:
            wb.generatetoaddress(101, self.btc_addr)
        btc_script = lambda addr: bytes.fromhex(wb.getaddressinfo(addr)["scriptPubKey"])  # noqa: E731
        creator_btc, holder_btc = wb.getnewaddress("", "bech32"), wb.getnewaddress("", "bech32")
        NUM, SHIFT = 10_000, 0  # 2 hashes/block at the pow limit -> 20,000 sats per block, always due
        path = os.path.join(self.dir, "SATS.json")
        if os.path.exists(path):
            d = D.load(path)
        else:
            d = D.make("SATS e2e", "SATS", self.creator_spk, 10**6, test=True, pow_limit_bits=0x207FFFFF,
                       target_spacing=10, lwma_window=10, genesis_time=int(time.time()) - DAY)
            d.ftl = 7200
            d.btc_anchor_header = bytes.fromhex(btc.rpc.getblockheader(btc.rpc.getblockhash(0), False))
            d.sats_num, d.sats_shift, d.creator_btc_script = NUM, SHIFT, btc_script(creator_btc)
            D.validate(d)
            d.grind_genesis()
            with open(path, "w") as f:
                f.write(d.dumps())
        creator_btc_spk = d.creator_btc_script
        dev_spk = bytes.fromhex("5120c2cc659454f102e1b1ae85697405163154acc4a8946f6065f7821913ea29aa53")
        args = [f"-launch={path}", "-datacarriersize=1000000"]
        n3 = Node(a.hashfund, os.path.join(self.dir, "n3"), args, free_port())
        self.nodes.append(n3)
        T = [d.genesis_time + 100 + 10 * n3.rpc.getblockcount()]
        n3.rpc.setmocktime(T[0])
        w3 = open_wallet(n3.rpc)
        pay_addr = w3.getnewaddress("", "legacy")  # non-witness spends keep hand-built blocks simple
        pay_spk = bytes.fromhex(w3.getaddressinfo(pay_addr)["scriptPubKey"])
        reg = TxOut(0, Y.yield_tag_script(btc_script(holder_btc)))
        raw = lambda hexhash: bytes.fromhex(hexhash)[::-1]  # noqa: E731

        def mine(extra_outs=(), extra_txs=(), register=False, expect=None):
            T[0] += d.target_spacing
            n3.rpc.setmocktime(T[0])
            t = n3.rpc.getblocktemplate({"rules": ["segwit"]})
            hdr, txs = block_from_gbt(t, pay_spk, extra_outs=([reg] if register else []) + list(extra_outs),
                                      extra_txs=extra_txs)
            r = n3.rpc.submitblock(ser_block(hdr, txs))
            if r != expect:
                raise RuntimeError(f"submitblock: {r}")
            return txs[0]

        def relay_out():
            """HFH1 output carrying every Bitcoin header the launch has not seen yet."""
            have, tip = n3.rpc.getbtcrelay()["height"], btc.rpc.getblockcount()
            hdrs = b"".join(bytes.fromhex(btc.rpc.getblockheader(btc.rpc.getblockhash(h), False))
                            for h in range(have + 1, tip + 1))
            return [TxOut(0, Y.op_return(b"HFH1" + hdrs))] if hdrs else []

        def pay(height, *, to=None, amount=None, tag=None, lists=None, candidate=0):
            """Pay block `height`'s obligation on Bitcoin; returns (HFP1 output, obligation).
            lists: the tag lists the Bitcoin transaction carries, in order (default: one, with this block's tag)."""
            ob = n3.rpc.getmintobligation(height)
            script = to or bytes.fromhex(ob["pay_script"])
            lists = lists if lists is not None else [[bytes.fromhex(tag or ob["tag"])]]
            rawtx = Tx(version=2, vin=[], vout=[TxOut(amount or ob["pay"], script)] +
                       [TxOut(0, Y.payment_outputs_tag(tags)) for tags in lists])
            funded = wb.fundrawtransaction(rawtx.serialize(witness=False).hex(), {"changePosition": 1 + len(lists)}, False)
            txid = wb.sendrawtransaction(wb.signrawtransactionwithwallet(funded["hex"])["hex"])
            bh = wb.generatetoaddress(1, self.btc_addr)[0]
            txids = btc.rpc.getblock(bh, 1)["tx"]
            pos = txids.index(txid)
            level, idx, branch = [raw(x) for x in txids], pos, []
            while len(level) > 1:
                if len(level) % 2:
                    level.append(level[-1])
                branch.append(level[idx ^ 1])
                level = [sha256d(level[j] + level[j + 1]) for j in range(0, len(level), 2)]
                idx >>= 1
            nowit = Tx.parse(bytes.fromhex(btc.rpc.getrawtransaction(txid))).serialize(witness=False)
            proof = Y.PaymentProof(height, raw(bh), pos, branch, 0, candidate, nowit)
            return TxOut(0, Y.op_return(proof.payload())), ob

        base = n3.rpc.getblockcount()
        if base:
            raise RuntimeError("phase 10 needs a fresh SATS chain (new --workdir)")
        cbs = {}

        def mine_h(*a_, **kw):
            cb = mine(*a_, **kw)
            cbs[n3.rpc.getblockcount()] = cb
            return cb

        def obl(h):
            return n3.rpc.getmintobligation(h)

        for _ in range(14):  # draws for blocks 1..8 are now known
            mine_h()
        works = work_from_bits(0x207FFFFF)
        # The draw, recomputed here from the rules. A holder draw is over the coins live at the draw:
        # at first there are none (every coinbase is held until its block settles), and a holder
        # draw with nobody holding is owed to no one, which frees that block's coinbase.
        ok, detail, live = True, "", 0
        for h in range(1, 9):
            ob = obl(h)
            seed = Y.draw_seed(d.id, raw(n3.rpc.getblockhash(h + Y.DRAW_DELAY)))
            pay_amt, payee = Y.compute_draw(Y.owed(works, NUM, SHIFT), d.sats_min_payment, seed)
            if payee == 0 and live == 0:
                pay_amt = 0
            want = (True, Y.owed(works, NUM, SHIFT), True, pay_amt, ("holder", "creator", "dev")[payee],
                    Y.pay_tag(d.id, raw(ob["hash"])).hex(), False, pay_amt == 0, live)
            got = (ob["curve"], ob["owed"], ob["draw_known"], ob["pay"], ob["payee"], ob["tag"], ob["settled"],
                   ob["spendable"], ob["earning"])
            if got != want:
                ok, detail = False, f"h{h}: {got} vs {want}"
            if pay_amt == 0:  # released at its own draw: its earning outputs are live from here on
                live += sum(o.value for o in cbs[h].vout if o.value > 0 and Y.earns_yield(o.script_pubkey))
        check("10 obligation, draw, tag and the value earning at each draw: C++ == Python", ok, detail)
        check("10 no draw yet for a block younger than 6", obl(n3.rpc.getblockcount() - 2)["draw_known"] is False)
        free = [h for h in range(1, 9) if obl(h)["pay"] == 0]
        due = [h for h in range(1, 9) if obl(h)["pay"] > 0]
        first_holder = next((h for h in range(1, 9) if obl(h)["payee"] == "holder"), None)
        check("10 nobody holds yet: the first holder draw is owed to no one and frees its coinbase; nothing is paid to the creator for it",
              first_holder is None or (free == [first_holder] and "pay_script" not in obl(first_holder)
                                        and obl(first_holder)["spendable"]), f"free {free} first holder draw {first_holder}")
        before_holders = [h for h in due if first_holder is None or h < first_holder]
        check("10 creator and dev draws are due from the first block on, at the creator's and the dev's script",
              all(bytes.fromhex(obl(h)["pay_script"]) == (dev_spk if obl(h)["payee"] == "dev" else creator_btc_spk)
                  for h in before_holders), str(before_holders))
        obh = next((obl(h) for h in due if obl(h)["payee"] == "holder"), None)
        if obh:
            # No opt-in: the drawn coin is an output of an earlier coinbase that is free, paid at its own script.
            src_h = next((h for h in free if cbs[h].txid()[::-1].hex() == obh["coin"]["txid"]), None)
            out = cbs[src_h].vout[obh["coin"]["vout"]] if src_h else None
            check("10 holders earn without opting in: the drawn coin is a live earlier output, paid at its own script",
                  out is not None and obh["pay_script"] == out.script_pubkey.hex() and obh["coin"]["value"] == out.value
                  and out.script_pubkey in (pay_spk, self.creator_spk) and 0 < obh["coin"]["value"] <= obh["earning"],
                  json.dumps(obh))
        if len(due) < 4:
            raise RuntimeError(f"phase 10 needs four blocks with sats due among the first eight: {due}")
        t1, t2, t3, t4 = due[:4]

        mine_h(relay_out())
        check("10 Bitcoin headers relayed in a coinbase are tracked",
              n3.rpc.getbtcrelay()["height"] == btc.rpc.getblockcount()
              and n3.rpc.getbtcrelay()["best"] == btc.rpc.getbestblockhash(), json.dumps(n3.rpc.getbtcrelay()))

        # Payments that must NOT settle: wrong payee, one sat short, a tag for another block, a
        # proof that names a candidate (the payee is fixed: there is nothing to name), and a
        # transaction whose FIRST tag list is for another block with the right tag in a second
        # list (one output would then settle a block per list).
        ob1, ob2 = obl(t1), obl(t2)
        stranger = bytes.fromhex(wb.getaddressinfo(wb.getnewaddress("", "bech32"))["scriptPubKey"])
        t1_tag, t2_tag = bytes.fromhex(ob1["tag"]), bytes.fromhex(ob2["tag"])
        bad = [pay(t1, to=stranger)[0], pay(t1, amount=ob1["pay"] - 1)[0], pay(t1, tag=ob2["tag"])[0],
               pay(t1, candidate=1)[0], pay(t1, lists=[[t2_tag], [t1_tag]])[0]]
        mine_h(relay_out() + bad)
        check("10 wrong payee / underpayment / foreign tag / a named candidate / the tag in a second list do not settle",
              obl(t1)["settled"] is False)
        good1, _ = pay(t1)
        mine_h(relay_out() + [good1])
        o = obl(t1)
        check("10 SPV-proven Bitcoin payment settles the block", o["settled"] and o["spendable"], json.dumps(o))
        earning_before = n3.rpc.getlaunchinfo()["earning"]
        settle_block = n3.rpc.getbestblockhash()
        n3.rpc.invalidateblock(settle_block)
        undone = obl(t1)["settled"] is False and n3.rpc.getbtcrelay()["height"] < btc.rpc.getblockcount() \
            and n3.rpc.getlaunchinfo()["earning"] < earning_before
        n3.rpc.reconsiderblock(settle_block)
        check("10 reorg undoes and redoes settlement, header relay and the coinbase's release",
              undone and obl(t1)["settled"] and n3.rpc.getbtcrelay()["height"] == btc.rpc.getblockcount()
              and n3.rpc.getlaunchinfo()["earning"] == earning_before)
        cb_value = sum(o.value for o in cbs[t1].vout if o.value > 0 and Y.earns_yield(o.script_pubkey))
        check("10 a coinbase starts earning when its block settles, not before",
              earning_before == live + cb_value, f"{earning_before} vs {live} + {cb_value}")
        # One Bitcoin output cannot settle two blocks: t2's and t3's tags in two lists of one transaction.
        both, _ = pay(t2, lists=[[t2_tag], [bytes.fromhex(obl(t3)["tag"])]])
        ob3 = obl(t3)
        same_tx_for_t3 = None
        if ob3["pay_script"] == ob2["pay_script"] and ob3["pay"] <= ob2["pay"]:
            # the same Bitcoin transaction, offered as the proof for t3 as well
            pr = Y.PaymentProof.parse(Y.tagged_return(both.script_pubkey, b"HFP1")) if hasattr(Y.PaymentProof, "parse") else None
            if pr is not None:
                same_tx_for_t3 = TxOut(0, Y.op_return(Y.PaymentProof(t3, pr.btc_block, pr.tx_index, pr.branch, 0, 0, pr.raw_tx).payload()))
        mine_h(relay_out() + [both] + ([same_tx_for_t3] if same_tx_for_t3 else []))
        check("10 second block settled; the same payment does not settle a third block through a second tag list",
              obl(t2)["settled"] and obl(t3)["settled"] is False,
              "with the replayed proof" if same_tx_for_t3 else "payee or amount differ, replay not attempted")

        # an optional redirect: this coinbase's miner output is paid at another Bitcoin script when it is drawn
        mine_h(register=True)
        h_red = n3.rpc.getblockcount()
        redirected = cbs[h_red].txid()[::-1].hex()
        for _ in range(Y.DRAW_DELAY + 1):
            mine_h()
        if obl(h_red)["pay"] > 0:
            good, _ = pay(h_red)
            mine_h(relay_out() + [good])
        while n3.rpc.getblockcount() < 104:
            mine_h()
        seen = [o for o in (obl(h) for h in range(1, n3.rpc.getblockcount() - Y.DRAW_DELAY + 1))
                if o.get("coin", {}).get("txid") == redirected]
        if seen:  # the draws are random: usually some land on it
            check("10 an HFY1 redirect in a coinbase sends its miner output's yield to the named script; the creator's cut keeps its own",
                  all(o["pay_script"] == (btc_script(holder_btc).hex() if o["coin"]["vout"] == 0 else self.creator_spk.hex())
                      for o in seen), json.dumps(seen[0]))

        def spend(h, fee=10_000):
            cb = cbs[h]
            rawtx = w3.createrawtransaction([{"txid": cb.txid()[::-1].hex(), "vout": 0}],
                                            {pay_addr: (cb.vout[0].value - fee) / COIN})
            return w3.signrawtransactionwithwallet(rawtx)["hex"]

        r = n3.rpc.testmempoolaccept([spend(t4)])[0]
        check("10 mempool refuses to spend an unsettled coinbase",
              not r["allowed"] and r.get("reject-reason") == "bad-txns-unsettled-coinbase", json.dumps(r))
        try:
            mine(extra_txs=[Tx.parse(bytes.fromhex(spend(t4)))], expect="bad-txns-unsettled-coinbase")
            check("10 a block spending an unsettled coinbase is invalid", True)
        except RuntimeError as e:
            check("10 a block spending an unsettled coinbase is invalid", False, str(e))

        # The payee is fixed when the draw is made. Moving the coin afterwards changes nothing for
        # that draw, and a spent coin is never drawn again.
        while n3.rpc.getblockcount() < 200:
            mine_h()
        mine_cb = {cb.txid()[::-1].hex(): h for h, cb in cbs.items()}
        target, before = next(((h, o) for h, o in ((h, obl(h)) for h in range(1, 90))
                               if o.get("pay", 0) > 0 and not o["settled"] and o.get("coin", {}).get("vout") == 0
                               and o["coin"]["txid"] in mine_cb and mine_cb[o["coin"]["txid"]] + 101 < n3.rpc.getblockcount()),
                              (None, None))
        if target is None:
            raise RuntimeError("phase 10: no unsettled holder draw on a mature miner output")
        hc = mine_cb[before["coin"]["txid"]]
        txid = n3.rpc.sendrawtransaction(spend(hc))
        mine_h()
        moved_at = n3.rpc.getblockcount()
        check("10 a settled coinbase is spendable after maturity",
              n3.rpc.getrawtransaction(txid, True).get("confirmations", 0) >= 1)
        check("10 moving the drawn coin afterwards changes nothing: the payee was fixed at the draw",
              obl(target) == before, f"{json.dumps(before)} -> {json.dumps(obl(target))}")
        good, _ = pay(target)
        mine_h(relay_out() + [good])
        check("10 the payment to the drawn script settles", obl(target)["settled"], json.dumps(obl(target)))
        for _ in range(40):
            mine_h()
        later = [o for o in (obl(h) for h in range(moved_at - Y.DRAW_DELAY + 1, n3.rpc.getblockcount() - Y.DRAW_DELAY + 1))
                 if o.get("coin")]
        check("10 a spent coin is never drawn again: every later holder draw is on a coin that was unspent when it was made",
              len(later) > 5 and all((o["coin"]["txid"], o["coin"]["vout"]) != (before["coin"]["txid"], 0) for o in later),
              f"{len(later)} later holder draws")
        # A reorg that takes a settlement away must also take a spend of that coinbase out of the
        # mempool. Left there, it would make every block template invalid until the proof is mined again.
        u = next(h for h in range(1, 90) if obl(h).get("pay", 0) > 0 and not obl(h)["settled"])
        good, _ = pay(u)
        mine_h(relay_out() + [good])
        proof_block = n3.rpc.getbestblockhash()
        spend_u = n3.rpc.sendrawtransaction(spend(u))
        in_pool = spend_u in n3.rpc.getrawmempool()
        n3.rpc.invalidateblock(proof_block)
        evicted = spend_u not in n3.rpc.getrawmempool() and obl(u)["settled"] is False
        try:
            n3.rpc.getblocktemplate({"rules": ["segwit"]})
            template = ""
        except Exception as e:  # noqa: BLE001
            template = str(e)
        n3.rpc.reconsiderblock(proof_block)
        check("10 a reorg that undoes a settlement drops the spend of that coinbase from the mempool, and block templates keep working",
              in_pool and evicted and template == "" and obl(u)["settled"], f"in pool {in_pool}, evicted {evicted}, template: {template}")
        tip = n3.rpc.getblockcount()
        snap = [obl(h) for h in range(1, tip + 1)]
        relay, earning = n3.rpc.getbtcrelay(), n3.rpc.getlaunchinfo()["earning"]
        n3.stop()
        self.nodes.remove(n3)
        n3 = Node(a.hashfund, os.path.join(self.dir, "n3"), args, free_port())
        self.nodes.append(n3)
        n3.rpc.setmocktime(T[0])
        check("10 a restarted node rebuilds the same state from its blocks: every obligation, the relay, the earning value",
              [n3.rpc.getmintobligation(h) for h in range(1, tip + 1)] == snap and n3.rpc.getbtcrelay() == relay
              and n3.rpc.getlaunchinfo()["earning"] == earning)

    # ------------------------------------------------------------ phase 11: automatic settlement
    def p11(self):
        a, btc, wb = self.a, self.btc, self.wb
        btc.rpc.setmocktime(0)
        if wb.getbalance() < 10:
            wb.generatetoaddress(101, self.btc_addr)
        spk = lambda addr: bytes.fromhex(wb.getaddressinfo(addr)["scriptPubKey"])  # noqa: E731
        creator_btc, miner_btc = wb.getnewaddress("", "bech32"), wb.getnewaddress("", "bech32")
        tag = f"{int(time.time())}"
        path = os.path.join(self.dir, f"AUTO-{tag}.json")
        d = D.make("AUTO e2e", "AUTO", self.creator_spk, 10**9, test=True, pow_limit_bits=0x207FFFFF,
                   target_spacing=10, lwma_window=10, genesis_time=int(time.time()) - DAY)
        d.ftl = 7200
        d.btc_anchor_height = max(0, btc.rpc.getblockcount() - 450)  # a few coinbases of header catch-up
        d.btc_anchor_header = bytes.fromhex(btc.rpc.getblockheader(btc.rpc.getblockhash(d.btc_anchor_height), False))
        # 2 hashes/block at the floor -> 4,000 sats owed: a 40% lottery for 10,000. Real-time pool
        # mining ratchets difficulty, so later blocks owe more and pay in full.
        d.sats_num, d.sats_shift, d.creator_btc_script = 2000, 0, spk(creator_btc)
        D.validate(d)
        d.grind_genesis()
        with open(path, "w") as f:
            f.write(d.dumps())
        n4 = Node(a.hashfund, os.path.join(self.dir, f"n4-{tag}"), [f"-launch={path}"], free_port())
        self.nodes.append(n4)
        w4 = open_wallet(n4.rpc)
        miner_addr = w4.getnewaddress("", "bech32")
        settler = Settler(n4.rpc, wb, os.path.join(self.dir, f"settler-{tag}.json"), max_pay_sats=COIN, pay_depth=0)
        src = LaunchSource(n4.rpc, d.hrp, d.ticker, settler=settler, yield_hrp="bcrt")
        port = free_port()
        asyncio.run_coroutine_threadsafe(StratumServer(src, "127.0.0.1", port, difficulty=1e-6,
                                                       poll_interval=0.2).serve(), self.loop)
        time.sleep(1)
        m = StratumMiner("127.0.0.1", port, f"{miner_addr},{miner_btc}", batch=4096)
        FIRST = 8  # the first FIRST pool blocks must all end up spendable
        t0 = time.time()

        def obligations():
            return [n4.rpc.getmintobligation(h) for h in range(1, min(n4.rpc.getblockcount(), FIRST) + 1)]

        while time.time() - t0 < 110:
            asyncio.run_coroutine_threadsafe(m.run(duration=1.0), self.loop).result(60)
            wb.generatetoaddress(1, self.btc_addr)
            obs = obligations()
            if len(obs) == FIRST and all(o["spendable"] for o in obs):
                break
        obs = obligations()
        tip = n4.rpc.getblockcount()
        allobs = [n4.rpc.getmintobligation(h) for h in range(1, tip + 1)]
        paid = [o for o in allobs if o["settled"]]
        lottery_free = [o for o in allobs if o["draw_known"] and o["pay"] == 0]
        print(f"   AUTO: {tip} blocks in {time.time() - t0:.0f}s; settled by payment {len(paid)}, "
              f"nothing due {len(lottery_free)}, relay at {n4.rpc.getbtcrelay()['height']}/{btc.rpc.getblockcount()}, "
              f"settler {settler.status()}", flush=True)
        check("11 pool mined a sats-leg launch through stratum", tip >= FIRST, f"{tip} blocks")
        check("11 first blocks all spendable without manual steps", len(obs) == FIRST and all(o["spendable"] for o in obs),
              json.dumps([(o["height"], o.get("pay"), o["settled"]) for o in obs]))
        check("11 settler paid and proved at least one obligation on Bitcoin", len(paid) >= 1, f"{len(paid)}")
        check("11 settler relayed Bitcoin headers through coinbases",
              n4.rpc.getbtcrelay()["height"] >= btc.rpc.getblockcount() - 3, json.dumps(n4.rpc.getbtcrelay()))
        cb = n4.rpc.getblock(n4.rpc.getblockhash(2), 2)["tx"][0]
        check("11 miner's coinbase is registered for BTC yield at its Bitcoin address",
              any(o["scriptPubKey"]["hex"] == Y.yield_tag_script(spk(miner_btc)).hex() for o in cb["vout"]))
        holders = [o for o in allobs if o["draw_known"] and o["payee"] == "holder" and o.get("pay", 0) > 0]
        if holders:
            check("11 holder draws go to the miner's redirect address or the creator's own script",
                  all(o["pay_script"] in (spk(miner_btc).hex(), self.creator_spk.hex()) and o.get("coin") for o in holders),
                  json.dumps(holders[0]))


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
    ap.add_argument("--phases", default="1-11", help="e.g. 1-6 or 7,8 (in order, each once)")
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
