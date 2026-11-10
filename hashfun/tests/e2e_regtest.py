"""End-to-end harness against REAL binaries: hashfund (this fork) for two test
launches and stock Bitcoin Core bitcoind (regtest) as the merge-mining parent.

  python -m hashfun.tests.e2e_regtest --hashfund build/bin/hashfund --bitcoind /path/to/bitcoind

Checks, in order (each prints PASS/FAIL):
  1  C++ and Python agree on launch id, genesis hash, chain id, magic-derived ports
  2  block subsidies match the independent Python curve model, creator output paid
  3  consensus rejects: excess coinbase, missing creator output, wrong nBits
  4  LWMA: node's next nBits == Python model for fast/slow mocktime sequences
  5  auxpow before graduation rejected (createauxblock and a hand-built aux block)
  6  graduation height/work exact; curve supply == G; tail afterwards
  7  merged mining through the pool against stock bitcoind (real CAuxPow::check)
  8  standalone pool mining on the second (presale) launch
  9  Electrum servers + HD wallet + maker: atomic swap BTC -> launch coins
"""
import argparse
import asyncio
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

from hashfun import descriptor as D
from hashfun.auxpow import AuxTree, serialize_auxpow
from hashfun.crypto import sha256d, pubkey_from_priv, random_priv, hash160
from hashfun.electrum import ElectrumServer
from hashfun.miner import StratumMiner
from hashfun.rpc import RPC, RPCError
from hashfun.ser import (Tx, TxIn, TxOut, header_bytes, merkle_root, merkle_branch_for_first, bits_to_target,
                         work_from_bits, push_int, push, segwit_encode, address_to_script, varint)
from hashfun.stratum import LaunchSource, MergedSource, StratumServer
from hashfun.swap import KeyStore, Maker, NodeChain, relay_handler
from hashfun.wallet import Wallet, LAUNCH_COIN_BASE

COIN = 100_000_000
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond)))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""), flush=True)
    return cond


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Node:
    def __init__(self, binary, datadir, args, cookie_rel, rpcport):
        self.binary, self.datadir, self.args = binary, datadir, args
        os.makedirs(datadir, exist_ok=True)
        self.proc = subprocess.Popen([binary, f"-datadir={datadir}", "-server=1", "-listen=0", "-txindex=1",
                                      "-fallbackfee=0.0001", f"-rpcport={rpcport}", "-printtoconsole=0"] + args,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.url = f"http://127.0.0.1:{rpcport}"
        cookie = os.path.join(datadir, cookie_rel, ".cookie")
        for _ in range(300):
            if self.proc.poll() is not None:
                raise RuntimeError(f"{binary} exited: {self.proc.stderr.read().decode()[-2000:]}")
            if os.path.exists(cookie):
                try:
                    self.rpc = RPC(self.url, cookie_file=cookie)
                    self.rpc.getblockcount()
                    return
                except Exception:
                    pass
            time.sleep(0.2)
        raise RuntimeError(f"{binary} did not start")

    def stop(self):
        try:
            self.rpc.stop()
            self.proc.wait(30)
        except Exception:
            self.proc.kill()


def mk_launch(ticker, creator_spk, graduation_blocks):
    d = D.make(f"{ticker} e2e", ticker, creator_spk, 2 * graduation_blocks, test=True, pow_limit_bits=0x207FFFFF,
               target_spacing=10, lwma_window=10, genesis_time=1_800_000_000)
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hashfund", required=True)
    ap.add_argument("--bitcoind", required=True, help="stock Bitcoin Core bitcoind")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    tmp = tempfile.mkdtemp(prefix="hashfun-e2e-")
    nodes = []
    T = 1_800_000_100
    try:
        creator_key = random_priv()
        creator_spk = b"\x00\x14" + hash160(pubkey_from_priv(creator_key))
        d1 = mk_launch("GRAD", creator_spk, graduation_blocks=40)
        d2 = mk_launch("PRE", creator_spk, graduation_blocks=10**7)
        paths = {}
        for d in (d1, d2):
            p = os.path.join(tmp, f"{d.ticker}.json")
            with open(p, "w") as f:
                f.write(d.dumps())
            paths[d.ticker] = p
        btc = Node(a.bitcoind, os.path.join(tmp, "btc"), ["-regtest"], "regtest", free_port())
        nodes.append(btc)
        n1 = Node(a.hashfund, os.path.join(tmp, "n1"), [f"-launch={paths['GRAD']}"], d1.datadir_name, free_port())
        n2 = Node(a.hashfund, os.path.join(tmp, "n2"), [f"-launch={paths['PRE']}"], d2.datadir_name, free_port())
        nodes += [n1, n2]
        for n in (btc, n1, n2):
            n.rpc.createwallet("w")
            n.rpc.setmocktime(T)
        w1, w2, wb = n1.rpc.wallet("w"), n2.rpc.wallet("w"), btc.rpc.wallet("w")

        # 1 identity
        i1 = n1.rpc.getlaunchinfo()
        check("1 launch id C++ == Python", i1["launch_id"] == d1.id_hex, f"{i1['launch_id']} vs {d1.id_hex}")
        check("1 genesis hash C++ == Python", i1["genesis_hash"] == d1.genesis_hash)
        check("1 chain id C++ == Python", i1["chain_id"] == d1.chain_id)
        check("1 graduation work C++ == Python", int(i1["curve"]["graduation_work"], 16) == d1.graduation_work)

        # 2 subsidies across mocktime-stepped blocks
        addr1 = w1.getnewaddress("", "bech32")
        hdrs = []
        ok = True
        for k in range(12):
            T += d1.target_spacing
            n1.rpc.setmocktime(T)
            bh = w1.generatetoaddress(1, addr1)[0]
            blk = n1.rpc.getblock(bh, 2)
            hdrs.append(blk)
            h = blk["height"]
            w_prev = sum(work_from_bits(int(x["bits"], 16)) for x in hdrs[:-1])
            model = d1.subsidy(w_prev, int(blk["bits"], 16), h)
            cb = blk["tx"][0]
            total = round(sum(o["value"] for o in cb["vout"]) * COIN)
            creator = round(sum(o["value"] for o in cb["vout"] if o["scriptPubKey"]["hex"] == creator_spk.hex()) * COIN)
            ok &= total == model and creator >= d1.creator_fee(model)
        check("2 coinbase == Python curve subsidy, creator paid", ok)
        info = n1.rpc.getlaunchinfo()
        check("2 curve_supply == Python S(W)", info["curve_supply"] == d1.curve_supply(int(info["work"], 16)))

        # 3 consensus rejects
        spk = address_to_script(addr1, d1.hrp)
        t = n1.rpc.getblocktemplate({"rules": ["segwit"]})
        check("3 creatorfee advertised in GBT", t.get("creatorfee", {}).get("script") == creator_spk.hex())
        r = n1.rpc.submitblock(ser_block(*block_from_gbt(t, spk, extra_value=1)))
        check("3 reject excess coinbase", r == "bad-cb-amount", r)
        r = n1.rpc.submitblock(ser_block(*block_from_gbt(t, spk, drop_creator=True, extra_value=t.get("creatorfee", {}).get("amount", 0) * 0)))
        check("3 reject missing creator output", r == "bad-cb-creator-fee", r)
        r = n1.rpc.submitblock(ser_block(*block_from_gbt(t, spk, bits=0x2007FFFF)))
        check("3 reject wrong nBits", r == "bad-diffbits", r)

        # 4 LWMA cross-check: fast then slow mocktime steps
        ok = True
        for step in [1] * 8 + [40] * 6:
            T += step
            n1.rpc.setmocktime(T)
            w1.generatetoaddress(1, addr1)
            tip = n1.rpc.getblockcount()
            times, bits = [], []
            for h in range(0, tip + 1):
                hh = n1.rpc.getblockheader(n1.rpc.getblockhash(h))
                times.append(hh["time"])
                bits.append(int(hh["bits"], 16))
            model = d1.lwma_next_bits(times, bits)
            node = int(n1.rpc.getlaunchinfo()["next"]["bits"], 16)
            ok &= model == node
        check("4 LWMA next bits C++ == Python", ok)

        # 5 auxpow before graduation
        try:
            n1.rpc.createauxblock(addr1)
            check("5 createauxblock refused pre-graduation", False)
        except RPCError as e:
            check("5 createauxblock refused pre-graduation", "graduat" in e.message, e.message)
        t = n1.rpc.getblocktemplate({"rules": ["segwit"]})
        hdr, txs = block_from_gbt(t, spk, version=t["version"] | 0x100, auxpow=b"pending")
        aux_hash = sha256d(hdr)
        tree = AuxTree({d1.chain_id: aux_hash})
        pcb = Tx(version=1, vin=[TxIn(b"\0" * 32, 0xFFFFFFFF, push_int(1) + tree.commitment_push(), 0xFFFFFFFF)],
                 vout=[TxOut(0, b"\x6a")])
        phdr = solve(header_bytes(0x20000000, b"\x11" * 32, pcb.txid(), T, 0x207FFFFF, 0)[:76],
                     bits_to_target(int(t["bits"], 16)))
        ap_bytes = serialize_auxpow(pcb, [], [], 0, phdr)
        r = n1.rpc.submitblock(ser_block(hdr, txs, ap_bytes))
        check("5 hand-built auxpow block rejected pre-graduation", r == "auxpow-before-graduation", r)

        # 6 graduate
        while not n1.rpc.getlaunchinfo()["graduated"]:
            T += d1.target_spacing
            n1.rpc.setmocktime(T)
            w1.generatetoaddress(1, addr1)
        info = n1.rpc.getlaunchinfo()
        tip = info["height"]
        works = [work_from_bits(int(n1.rpc.getblockheader(n1.rpc.getblockhash(h))["bits"], 16)) for h in range(1, tip + 1)]
        model_gh = next(i + 1 for i in range(len(works)) if sum(works[:i + 1]) >= d1.graduation_work)
        check("6 graduation height C++ == Python", info["graduation_height"] == model_gh, f"{info['graduation_height']} vs {model_gh}")
        check("6 curve supply == G at graduation", info["curve_supply"] == d1.graduation_tokens)
        T += d1.target_spacing
        n1.rpc.setmocktime(T)
        bh = w1.generatetoaddress(1, addr1)[0]
        cbv = round(sum(o["value"] for o in n1.rpc.getblock(bh, 2)["tx"][0]["vout"]) * COIN)
        check("6 post-graduation block pays tail", cbv == d1.tail_reward_at(tip + 1), f"{cbv} vs {d1.tail_reward_at(tip + 1)}")

        # 7 merged mining through the pool vs stock bitcoind
        for n in (btc, n1, n2):
            n.rpc.setmocktime(0)
        loop = asyncio.new_event_loop()
        threading.Thread(target=loop.run_forever, daemon=True).start()
        port = free_port()
        btc_addr = wb.getnewaddress("", "bech32")
        src = MergedSource(btc.rpc, "bcrt", {"GRAD": {"rpc": n1.rpc, "hrp": d1.hrp, "payout": addr1},
                                             "PRE": {"rpc": n2.rpc, "hrp": d2.hrp, "payout": w2.getnewaddress("", "bech32")}},
                           default_payout=btc_addr)
        asyncio.run_coroutine_threadsafe(StratumServer(src, "127.0.0.1", port, difficulty=1e-6, poll_interval=0.2).serve(), loop)
        time.sleep(1)
        h_grad, h_btc, h_pre = n1.rpc.getblockcount(), btc.rpc.getblockcount(), n2.rpc.getblockcount()
        m = StratumMiner("127.0.0.1", port, btc_addr, batch=4096)
        t0 = time.time()
        while (n1.rpc.getblockcount() < h_grad + 3 or btc.rpc.getblockcount() < h_btc + 2) and time.time() - t0 < 180:
            asyncio.run_coroutine_threadsafe(m.run(duration=3), loop).result(60)
        aux_ok = any(int(n1.rpc.getblockheader(n1.rpc.getblockhash(h))["version"]) & 0x100
                     for h in range(h_grad + 1, n1.rpc.getblockcount() + 1))
        check("7 merge-mined blocks accepted by hashfund", n1.rpc.getblockcount() >= h_grad + 3 and aux_ok)
        check("7 parent blocks accepted by stock bitcoind", btc.rpc.getblockcount() >= h_btc + 2)
        check("7 presale launch got no aux blocks", n2.rpc.getblockcount() == h_pre)

        # 8 standalone pool on the presale launch
        port2 = free_port()
        addr2 = w2.getnewaddress("", "bech32")
        asyncio.run_coroutine_threadsafe(
            StratumServer(LaunchSource(n2.rpc, d2.hrp, d2.ticker), "127.0.0.1", port2, difficulty=1e-6,
                          poll_interval=0.2).serve(), loop)
        time.sleep(1)
        m2 = StratumMiner("127.0.0.1", port2, addr2, batch=4096)
        t0 = time.time()
        while n2.rpc.getblockcount() < h_pre + 3 and time.time() - t0 < 180:
            asyncio.run_coroutine_threadsafe(m2.run(duration=3), loop).result(60)
        check("8 pool-mined blocks accepted on presale launch", n2.rpc.getblockcount() >= h_pre + 3)

        # 9 swap BTC -> GRAD through electrum + wallet + maker (needs coinbase maturity on both chains)
        wb.generatetoaddress(110, btc_addr)
        w1.generatetoaddress(110, addr1)
        ep = {}
        for name, n in (("BTC", btc), ("GRAD", n1)):
            ep[name] = free_port()
            asyncio.run_coroutine_threadsafe(ElectrumServer(n.rpc, "127.0.0.1", ep[name]).serve(), loop)
        time.sleep(3)
        wal = Wallet.create(os.path.join(tmp, "wallet.json"))
        wal.add_chain("BTC", f"127.0.0.1:{ep['BTC']}", "bcrt", 1, "btc")
        wal.add_chain("GRAD", f"127.0.0.1:{ep['GRAD']}", d1.hrp, LAUNCH_COIN_BASE + d1.chain_id)
        wb.sendtoaddress(wal.chains["BTC"].address(0, 0), 5)
        wb.generatetoaddress(1, btc_addr)
        ks = KeyStore(os.path.join(tmp, "maker_keys.json"))
        hp = 1000 / n1.rpc.getlaunchinfo()["hashes_per_coin"] * 1e12
        cfg = {"defaults": {"hashprice_sats_per_th": hp, "spread": 0.02, "btc_confs": 1, "fork_confs": 2,
                            "init_lock_seconds": 3600, "part_lock_seconds": 900, "lock_margin_seconds": 300,
                            "safety": 1e12}}
        mk = Maker(NodeChain("BTC", wb, "bcrt"), {"GRAD": NodeChain("GRAD", w1, d1.hrp)}, ks, cfg,
                   os.path.join(tmp, "orders.json"))
        from http.server import ThreadingHTTPServer
        rport = free_port()
        threading.Thread(target=ThreadingHTTPServer(("127.0.0.1", rport), relay_handler(mk)).serve_forever,
                         daemon=True).start()
        time.sleep(3)
        out = {}
        tt = threading.Thread(target=lambda: out.update(rec=wal.swap(f"http://127.0.0.1:{rport}", "GRAD", "buy",
                                                                       100 * COIN, poll=1, log=print)), daemon=True)
        tt.start()
        for _ in range(120):
            if not tt.is_alive():
                break
            wb.generatetoaddress(1, btc_addr)
            w1.generatetoaddress(1, addr1)
            mk.tick()
            time.sleep(1)
        tt.join(5)
        rec = out.get("rec") or {}
        check("9 taker redeemed launch coins", rec.get("state") == "done", rec.get("state"))
        for _ in range(30):
            o = list(mk.orders.values())[-1] if mk.orders else None
            if o and o.state == "done":
                break
            wb.generatetoaddress(1, btc_addr)
            w1.generatetoaddress(1, addr1)
            mk.tick()
            time.sleep(1)
        check("9 maker redeemed BTC with revealed secret", o is not None and o.state == "done", o and o.note)
    finally:
        for n in nodes:
            n.stop()
        if not a.keep:
            shutil.rmtree(tmp, ignore_errors=True)
        failed = [n for n, ok in RESULTS if not ok]
        print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} passed" + (f"; failed: {failed}" if failed else ""))
        sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
