"""The two curves of a launch on one real node, by raw RPC: no settler, no pool, no other chain.

  python -m hashfun.tests.twin_regtest --hashfund build/bin/hashfund

What a block mints is checked three ways: the node's coinbase, hashfun/descriptor.py, and the
arithmetic written out in this file (S(W) = min(G, T0 * W // (V0 + W)) on the block's own curve).

  1  a new launch: both curves at zero, nothing graduated
  2  setminecurve: the node's own blocks go on the curve it names, one header bit says which
  3  blocks on both curves in a random order: each mints from its own curve only, and
     getlaunchinfo / getmintobligation say what the headers say
  4  getblocktemplate offers both curves; a block built for the curve the node is not mining is
     accepted; a QWEN-curve block that takes the BTC curve's larger subsidy is refused
  5  the QWEN curve sells out: the launch graduates on it, the crossing block mints only up to G,
     the BTC curve's unsold part is never minted, the tail starts
  6  after graduation the curve bit is refused in a header, and the node's own miner leaves it clear
  7  undo: the graduation block invalidated and reconsidered, then the node restarted: same state
"""
import argparse
import glob
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import time

from hashfun import descriptor as D
from hashfun.cli import free_port
from hashfun.crypto import sha256d
from hashfun.rpc import RPC, RPCError
from hashfun.ser import Tx, TxIn, TxOut, bits_to_target, header_bytes, merkle_root, push, varint, work_from_bits

COIN = 100_000_000
QWEN_BIT = 0x200
RESULTS = {}


def check(name, cond, detail=""):
    RESULTS[name] = bool(cond)
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""), flush=True)
    return cond


class Node:
    def __init__(self, binary, datadir, args):
        self.binary, self.datadir, self.args = binary, datadir, args
        os.makedirs(datadir, exist_ok=True)
        self.start()

    def start(self):
        port = free_port()
        self.err = os.path.join(self.datadir, "stderr.log")
        with open(self.err, "ab") as err:
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.datadir}", "-server=1", "-listen=0",
                                          "-fallbackfee=0.0001", f"-rpcport={port}", "-printtoconsole=0"] + self.args,
                                         stdout=subprocess.DEVNULL, stderr=err)
        url, deadline = f"http://127.0.0.1:{port}", time.time() + 120
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"hashfund exited {self.proc.returncode}: " + open(self.err, "rb").read()[-1500:].decode(errors="replace"))
            for cookie in glob.glob(os.path.join(self.datadir, "*", ".cookie")):
                try:
                    rpc = RPC(url, cookie_file=cookie)
                    rpc.getblockcount()
                    self.rpc = rpc
                    return
                except Exception:
                    pass
            time.sleep(0.2)
        self.proc.kill()
        raise RuntimeError("hashfund did not start")

    def stop(self):
        try:
            self.rpc.stop()
            self.proc.wait(60)
        except Exception:
            self.proc.kill()


def wallet(rpc):
    try:
        rpc.createwallet("w")
    except RPCError as e:
        if e.code == -4:  # it exists: this is a restart
            try:
                rpc.loadwallet("w")
            except RPCError as e2:
                if e2.code != -35:
                    raise
        else:
            raise
    return rpc.wallet("w")


def supply(d, w):
    """One curve's supply at curve work w, written out: the third opinion."""
    return min(d.graduation_tokens, d.virtual_tokens * w // (d.virtual_work + w))


def graduation_work(d):
    g, t0, v0 = d.graduation_tokens, d.virtual_tokens, d.virtual_work
    return -(-g * v0 // (t0 - g))


def build_block(t, payout_spk, *, version, value, creator):
    """A block from a template with this header version and this much to the miner."""
    outs = [TxOut(value, payout_spk)]
    if creator:
        outs.append(TxOut(creator["amount"], bytes.fromhex(creator["script"])))
    outs.append(TxOut(0, bytes.fromhex(t["default_witness_commitment"])))
    cb = Tx(version=2, vin=[TxIn(b"\0" * 32, 0xFFFFFFFF, bytes.fromhex(t["launchcoinbase"]) + push(os.urandom(4)), 0xFFFFFFFF,
                                 [b"\0" * 32])], vout=outs)
    bits = int(t["bits"], 16)
    hdr = header_bytes(version, bytes.fromhex(t["previousblockhash"])[::-1], merkle_root([cb.txid()]), t["curtime"], bits, 0)[:76]
    n = 0
    while int.from_bytes(sha256d(hdr + struct.pack("<I", n)), "little") > bits_to_target(bits):
        n += 1
    return (hdr + struct.pack("<I", n) + varint(1) + cb.serialize()).hex()


class Twin:
    def __init__(self, a):
        self.a = a
        self.dir = a.workdir or tempfile.mkdtemp(prefix="hashfun-twin-")
        os.makedirs(self.dir, exist_ok=True)
        spk = bytes.fromhex("0014" + "11" * 20)
        # About 40 blocks of work per curve at the easiest difficulty (2 expected hashes a block).
        self.d = D.make("Twin test", "TWT", spk, 80, test=True, pow_limit_bits=0x207FFFFF, target_spacing=10,
                        lwma_window=10, genesis_time=int(time.time()) - 86400)
        self.d.ftl = 7200
        self.d.grind_genesis()
        path = os.path.join(self.dir, "TWT.json")
        with open(path, "w") as f:
            f.write(self.d.dumps())
        self.T = self.d.genesis_time
        self.node = Node(a.hashfund, os.path.join(self.dir, "n"), [f"-launch={path}"])
        self.node.rpc.setmocktime(self.T)
        self.w = wallet(self.node.rpc)
        self.addr = self.w.getnewaddress()
        self.spk = bytes.fromhex(self.node.rpc.validateaddress(self.addr)["scriptPubKey"])
        self.wb = self.wq = 0     # this file's own sums of each curve's work
        self.blocks = []          # (height, curve, work, bits, minted)

    # -- helpers ---------------------------------------------------------------------------------
    def info(self):
        return self.node.rpc.getlaunchinfo()

    def tick(self):
        self.T += 10
        self.node.rpc.setmocktime(self.T)

    def account(self, blk):
        """Take a connected block (getblock verbosity 2) into this file's own sums; returns
        (curve, minted by the coinbase, what the three opinions say it had to mint)."""
        curve = "qwen" if blk["version"] & QWEN_BIT else "btc"
        bits = int(blk["bits"], 16)
        work = work_from_bits(bits)
        before = self.wq if curve == "qwen" else self.wb
        mine = supply(self.d, before + work) - supply(self.d, before)
        theirs = self.d.subsidy(self.wb, self.wq, curve, bits, blk["height"])
        minted = sum(round(o["value"] * COIN) for o in blk["tx"][0]["vout"])
        if curve == "qwen":
            self.wq += work
        else:
            self.wb += work
        self.blocks.append((blk["height"], curve, work, bits, minted))
        return curve, minted, mine, theirs

    def mine(self, curve):
        """One block by the node's own miner on `curve`."""
        self.tick()
        self.node.rpc.setminecurve(curve)
        for _ in range(20):
            got = self.w.generatetoaddress(1, self.addr, 50_000_000)
            if got:
                return self.node.rpc.getblock(got[0], 2)
            self.tick()
        raise RuntimeError("the node mined nothing")

    def curves_agree(self, info):
        """getlaunchinfo's curves against this file's sums."""
        c = info["curves"]
        gw = graduation_work(self.d)
        ok = int(c["btc"]["work"], 16) == self.wb and int(c["qwen"]["work"], 16) == self.wq
        ok &= c["btc"]["supply"] == supply(self.d, min(self.wb, gw)) and c["qwen"]["supply"] == supply(self.d, min(self.wq, gw))
        nb = [b for b in self.blocks if b[1] == "btc"]
        nq = [b for b in self.blocks if b[1] == "qwen"]
        ok &= c["btc"]["blocks"] == len(nb) and c["qwen"]["blocks"] == len(nq)
        ok &= c["btc"]["last_height"] == (nb[-1][0] if nb else 0) and c["qwen"]["last_height"] == (nq[-1][0] if nq else 0)
        return ok

    # -- the checks ------------------------------------------------------------------------------
    def run(self):
        d, rpc = self.d, self.node.rpc
        gw = graduation_work(d)

        i = self.info()
        c = i.get("curves", {})
        check("1 a new launch has two curves, both at zero",
              set(c) == {"btc", "qwen"} and all(int(c[x]["work"], 16) == 0 and c[x]["supply"] == 0 and c[x]["blocks"] == 0 for x in c), str(c)[:300])
        check("1 nothing has graduated", i.get("graduated_by") is None and not i["graduated"], str(i.get("graduated_by")))
        check("1 each curve names what it owes",
              (c["btc"]["owed_num"], c["btc"]["owed_shift"], c["qwen"]["owed_num"], c["qwen"]["owed_shift"])
              == (d.sats_num, d.sats_shift, d.qwen_num, d.qwen_shift), str(c)[:300])
        check("1 the node's graduation work is the formula's", int(i["curve"]["graduation_work"], 16) == gw == d.graduation_work)

        prev = rpc.setminecurve("qwen")
        check("2 setminecurve returns the curve it replaces", prev == "btc" and rpc.setminecurve("btc") == "qwen", str(prev))
        try:
            rpc.setminecurve("doge")
            refused = False
        except RPCError:
            refused = True
        check("2 setminecurve refuses a curve that does not exist", refused)

        b = self.mine("btc")
        curve, minted, mine, theirs = self.account(b)
        check("2 a block mined on the BTC curve has the bit clear and mints the curve's first coins",
              curve == "btc" and minted == mine == theirs > 0, f"{curve} {minted} {mine} {theirs}")
        b = self.mine("qwen")
        curve, minted, mine, theirs = self.account(b)
        check("2 a block mined on the QWEN curve has the bit set", curve == "qwen", hex(b["version"]))
        check("2 it mints from its own curve: the QWEN curve's first coins, whatever the BTC curve has sold",
              minted == mine == theirs == supply(d, self.wq), f"{minted} {mine} {theirs}")
        check("2 getlaunchinfo follows", self.curves_agree(self.info()), json.dumps(self.info()["curves"])[:400])

        rnd = random.Random(7)
        ok_mint = ok_info = ok_owed = True
        detail = ""
        for _ in range(14):
            x = rnd.choice(("btc", "qwen"))
            b = self.mine(x)
            curve, minted, mine, theirs = self.account(b)
            if not (curve == x and minted == mine == theirs):
                ok_mint, detail = False, f"height {b['height']} {curve}/{x}: coinbase {minted}, here {mine}, descriptor.py {theirs}"
            ok_info &= self.curves_agree(self.info())
            o = rpc.getmintobligation(b["height"])
            work = self.blocks[-1][2]
            num, shift = (d.qwen_num, d.qwen_shift) if curve == "qwen" else (d.sats_num, d.sats_shift)
            if not (o.get("quote") == curve and o["owed"] == (work * num) >> shift == d.owed(work, curve)):
                ok_owed, detail = False, f"height {b['height']}: {o}"
        check("3 fourteen blocks on the two curves in a random order: each mints from its own curve only", ok_mint, detail)
        check("3 getlaunchinfo's curves are this file's sums after every block", ok_info)
        check("3 getmintobligation names each block's quote and what it owes in it", ok_owed, detail)
        i = self.info()
        check("3 curve_supply is both curves' coins and progress the larger curve's",
              i["curve_supply"] == supply(d, self.wb) + supply(d, self.wq)
              and abs(i["progress"] - max(supply(d, self.wb), supply(d, self.wq)) / d.graduation_tokens) < 1e-9, f"{i['curve_supply']} {i['progress']}")
        cb, cq = i["curves"]["btc"], i["curves"]["qwen"]
        check("3 each curve has its own price point",
              abs(cb["hashes_per_coin"] / d.hashes_per_coin(self.wb) - 1) < 1e-9 and abs(cq["hashes_per_coin"] / d.hashes_per_coin(self.wq) - 1) < 1e-9
              and abs(cb["owed_per_coin"] / d.price_per_coin(self.wb, "btc") - 1) < 1e-9 and abs(cq["owed_per_coin"] / d.price_per_coin(self.wq, "qwen") - 1) < 1e-9,
              f"{cb['hashes_per_coin']} {cq['hashes_per_coin']} {cb['owed_per_coin']} {cq['owed_per_coin']}")

        # 4. Templates. Put the QWEN curve ahead first, so that the BTC curve's next block mints more.
        while supply(d, self.wq + 2) - supply(d, self.wq) >= supply(d, self.wb + 2) - supply(d, self.wb):
            self.account(self.mine("qwen"))
        rpc.setminecurve("btc")
        self.tick()
        t = rpc.getblocktemplate({"rules": ["segwit"]})
        lc = t.get("launchcurves", {})
        bits = int(t["bits"], 16)
        want = {x: d.subsidy(self.wb, self.wq, x, bits, t["height"]) for x in ("btc", "qwen")}
        fee = {x: want[x] * d.creator_fee_bps // 10000 for x in want}
        check("4 the template offers both curves: versions one bit apart, each with its own subsidy",
              set(lc) == {"btc", "qwen"} and lc["qwen"]["version"] == lc["btc"]["version"] | QWEN_BIT and not lc["btc"]["version"] & QWEN_BIT
              and all(lc[x]["coinbasevalue"] + lc[x].get("creatorfee", {}).get("amount", 0) == want[x] for x in lc)
              and all(lc[x].get("creatorfee", {}).get("amount", 0) == fee[x] for x in lc), json.dumps(lc)[:400] + f" want {want}")
        check("4 the top of the template is the node's mining curve",
              t.get("launchcurve") == "btc" and t["version"] == lc["btc"]["version"] and t["coinbasevalue"] == lc["btc"]["coinbasevalue"], str(t.get("launchcurve")))
        check("4 (the two curves differ here)", want["btc"] > want["qwen"], str(want))
        greedy = build_block(t, self.spk, version=lc["qwen"]["version"], value=lc["btc"]["coinbasevalue"], creator=lc["btc"].get("creatorfee"))
        r = rpc.submitblock(greedy)
        check("4 a QWEN-curve block that takes the BTC curve's subsidy is refused", r == "bad-cb-amount", str(r))
        other = build_block(t, self.spk, version=lc["qwen"]["version"], value=lc["qwen"]["coinbasevalue"], creator=lc["qwen"].get("creatorfee"))
        r = rpc.submitblock(other)
        b = rpc.getblock(rpc.getbestblockhash(), 2)
        curve, minted, mine, theirs = self.account(b)
        check("4 a block built for the curve the node is not mining is accepted",
              r is None and curve == "qwen" and minted == mine == theirs, f"{r} {curve} {minted} {mine}")

        # 5. The QWEN curve sells out.
        btc_sold = supply(d, self.wb)
        crossing = None
        for _ in range(400):
            if self.wq >= gw:
                break
            before = supply(d, self.wq)
            b = self.mine("qwen")
            curve, minted, mine, theirs = self.account(b)
            if not minted == mine == theirs:
                check("5 every block up to graduation mints the formula", False, f"height {b['height']}: {minted} {mine} {theirs}")
                break
            if self.wq >= gw:
                crossing = (b, before, minted)
        i = self.info()
        check("5 the QWEN curve sold out and the launch graduated on it",
              crossing is not None and i["graduated"] and i.get("graduated_by") == "qwen" and i["curves"]["qwen"]["supply"] == d.graduation_tokens,
              f"{i.get('graduated_by')} {i['curves']['qwen']}")
        check("5 the crossing block minted only up to G", crossing is not None and crossing[1] + crossing[2] == d.graduation_tokens,
              str(crossing and (crossing[1], crossing[2])))
        grad_hash, grad_height = crossing[0]["hash"], crossing[0]["height"]
        frozen = dict(i["curves"]["btc"]), dict(i["curves"]["qwen"]), i["curve_supply"]
        tails = []
        for x in ("btc", "qwen", "btc"):
            b = self.mine(x)
            tails.append((b["version"] & QWEN_BIT, sum(round(o["value"] * COIN) for o in b["tx"][0]["vout"]), b["height"]))
        i = self.info()
        check("5 the tail starts: later blocks mint the tail reward", all(v == d.tail_reward_at(h) for _, v, h in tails), str(tails))
        check("5 what the BTC curve had not sold is never minted: both curves' supplies stand still",
              i["curves"]["btc"]["supply"] == frozen[0]["supply"] == btc_sold < d.graduation_tokens
              and i["curves"]["qwen"]["supply"] == d.graduation_tokens and i["curve_supply"] == frozen[2] == btc_sold + d.graduation_tokens,
              f"{i['curves']['btc']['supply']} {btc_sold} {i['curve_supply']}")
        check("6 after graduation the node's own miner leaves the curve bit clear, whatever curve it is set to", not any(v for v, _, _ in tails), str(tails))
        self.tick()
        t = rpc.getblocktemplate({"rules": ["segwit"]})
        check("6 a template after graduation offers no curves", "launchcurves" not in t, str(t.get("launchcurves"))[:200])
        late = build_block(t, self.spk, version=t["version"] | QWEN_BIT, value=t["coinbasevalue"], creator=t.get("creatorfee"))
        r = rpc.submitblock(late)
        check("6 a block that claims the QWEN curve after graduation is refused in its header", r == "bad-curve-version", str(r))

        # 7. Undo and restart.
        after = self.info()
        tip = rpc.getbestblockhash()
        rpc.invalidateblock(grad_hash)
        i = self.info()
        back = (not i["graduated"] and i.get("graduated_by") is None and rpc.getblockcount() == grad_height - 1
                and i["curves"]["qwen"]["supply"] == crossing[1] and i["curves"]["btc"]["supply"] == btc_sold
                and i["curves"]["qwen"]["blocks"] == frozen[1]["blocks"] - 1)
        check("7 with the graduation block invalidated the launch is one block short of graduating again", back,
              f"{i['graduated']} {rpc.getblockcount()} {i['curves']['qwen']}")
        rpc.reconsiderblock(grad_hash)
        i = self.info()
        check("7 reconsidered: the same state as before", rpc.getbestblockhash() == tip and i["curves"] == after["curves"] and i["curve_supply"] == after["curve_supply"],
              json.dumps(i["curves"])[:300])
        self.node.stop()
        self.node.start()
        self.node.rpc.setmocktime(self.T)
        i = self.info()
        check("7 after a restart: the same state", self.node.rpc.getbestblockhash() == tip and i["curves"] == after["curves"]
              and i.get("graduated_by") == "qwen" and i["curve_supply"] == after["curve_supply"], json.dumps(i["curves"])[:300])

    def close(self):
        self.node.stop()
        if not self.a.workdir:
            shutil.rmtree(self.dir, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hashfund", required=True)
    ap.add_argument("--workdir", help="keep the chain here instead of a temporary directory")
    a = ap.parse_args()
    t = Twin(a)
    try:
        t.run()
    finally:
        t.close()
    bad = [k for k, v in RESULTS.items() if not v]
    print(f"\n{len(RESULTS) - len(bad)}/{len(RESULTS)} checks passed" + (f"; FAILED: {bad}" if bad else ""))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
