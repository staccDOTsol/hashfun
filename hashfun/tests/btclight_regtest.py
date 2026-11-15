"""hashfun.btclight against a real node: a regtest bitcoind, two Electrum servers over it
(hashfun.electrum), and every answer of the light object held against the node's own.

    python -m hashfun.tests.btclight_regtest --bitcoind PATH

What it covers: each call the tools make on a Bitcoin RPC object (chain, headers, transactions,
outputs, fees, broadcast), a payment found through its script's history and proven, what spent an
output, the wallet of one key paying the way the settler pays (a real node judges the signatures),
and a reorganisation. Prints one line per check and exits 1 if any failed.

Then the callers themselves (once SP/twin/light-integration.patch is applied; before that the part
is skipped and says so): a WatchSettler and a paying Settler driven through the light object
against a launch stand-in whose relay and proof verdicts are the reference model's
(yieldmodel.BtcChain, verify_btc_payment), descriptor.check_anchor, and the site's balance,
broadcast, transaction, output, time and spender paths over HTTP, each held against the same
question put to the node. A Bitcoin reorganisation under a found payment included.
"""
import argparse
import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

from hashfun import btclight as L
from hashfun.electrum import ElectrumServer
from hashfun.rpc import RPC, RPCError
from hashfun.ser import Tx, TxOut, merkle_branch, root_from_branch

COIN = 100_000_000
FAILED = []


def check(name, ok, detail=""):
    print(("ok    " if ok else "FAIL  ") + name + (f": {detail}" if detail else ""), flush=True)
    if not ok:
        FAILED.append(name)


def same(name, light, node, detail=None):
    check(name, light == node, detail if light == node else f"light {light!r} != node {node!r}")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def sats(v) -> int:
    return round(v * COIN)


def wait(cond, what, seconds=30):
    t = time.time()
    while time.time() - t < seconds:
        if cond():
            return
        time.sleep(0.2)
    raise RuntimeError(f"timed out waiting for {what}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bitcoind", required=True)
    ap.add_argument("--hashfund")  # taken and unused, so the suite runner can pass the same flags to every test
    a = ap.parse_args()
    work = tempfile.mkdtemp(prefix="btclight-")
    rpcport = free_port()
    proc = subprocess.Popen([a.bitcoind, "-regtest", f"-datadir={work}", f"-rpcport={rpcport}", f"-port={free_port()}",
                             "-rpcuser=u", "-rpcpassword=p", "-fallbackfee=0.0002", "-listen=0", "-printtoconsole=0"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    node = RPC(f"http://u:p@127.0.0.1:{rpcport}")
    skipped = False
    try:
        wait(lambda: _up(node), "bitcoind")
        run(node, work)
        from hashfun import settler as S
        if hasattr(S, "_where"):
            integrate(node, work)
        else:
            skipped = True
            print("SKIP  the callers (settler, site, anchor check) through btclight: the integration patch is not "
                  "applied to this tree", flush=True)
    finally:
        try:
            node.stop()
        except Exception:  # noqa: BLE001
            proc.terminate()
        proc.wait(30)
        shutil.rmtree(work, ignore_errors=True)
    print(("btclight: all passed" + (" (callers skipped)" if skipped else "")) if not FAILED else
          f"btclight: {len(FAILED)} FAILED: " + "; ".join(FAILED))
    return 1 if FAILED else 0


def _up(node):
    try:
        node.getblockcount()
        return True
    except (OSError, RPCError):
        return False


def run(node, work):
    node.createwallet("w")
    node.createwallet("r")
    w, r = node.wallet("w"), node.wallet("r")
    a1 = w.getnewaddress("", "bech32")
    w.generatetoaddress(110, a1)
    ports = [free_port(), free_port()]
    for p in ports:
        srv = ElectrumServer(node, "127.0.0.1", p)
        threading.Thread(target=lambda s=srv: asyncio.run(s.serve()), daemon=True).start()
    dead = free_port()

    def served():
        try:
            for p in ports:
                socket.create_connection(("127.0.0.1", p), timeout=1).close()
            return True
        except OSError:
            return False
    wait(served, "the Electrum servers")
    # a server that is not there is named first: the two that are make the quorum
    btc = L.connect(f"electrum://127.0.0.1:{dead},127.0.0.1:{ports[0]},127.0.0.1:{ports[1]}?net=regtest&poll=0&timeout=5")

    def settled():
        """Wait until both Electrum servers have indexed the node's tip and mempool."""
        tip, pool = node.getblockcount(), set(node.getrawmempool())
        for p in ports:
            one = L.connect(f"electrum://127.0.0.1:{p}?net=regtest&poll=0")
            wait(lambda: one.servers[0].call("blockchain.headers.subscribe")["height"] == tip, "an Electrum server's tip")
            for txid in pool:
                wait(lambda: _has(one, txid), "an Electrum server's mempool")
            one.close()

    def mine(n=1):
        hashes = w.generatetoaddress(n, a1)
        settled()
        return hashes

    # ---- the chain
    tip = node.getblockcount()
    same("getblockcount", btc.getblockcount(), tip)
    same("getbestblockhash", btc.getbestblockhash(), node.getbestblockhash())
    for h in (0, 1, 57, tip):
        bh = node.getblockhash(h)
        same(f"getblockhash {h}", btc.getblockhash(h), bh)
        same(f"getblockheader {h} as bytes", btc.getblockheader(bh, False), node.getblockheader(bh, False))
        mine_, theirs = btc.getblockheader(bh), node.getblockheader(bh)
        keys = ["hash", "confirmations", "height", "version", "versionHex", "merkleroot", "time", "mediantime", "nonce", "bits"] + \
               (["previousblockhash"] if h else []) + (["nextblockhash"] if h < tip else [])
        same(f"getblockheader {h}", {k: mine_.get(k) for k in keys}, {k: theirs.get(k) for k in keys})
    li, ni = btc.getblockchaininfo(), node.getblockchaininfo()
    same("getblockchaininfo", {k: li[k] for k in ("chain", "blocks", "headers", "bestblockhash", "mediantime")},
         {k: ni[k] for k in ("chain", "blocks", "headers", "bestblockhash", "mediantime")})
    for bad, code in ((lambda: btc.getblockhash(tip + 1), -8), (lambda: btc.getblockheader("00" * 32), -5)):
        try:
            bad()
            check("out of range and unknown blocks are errors", False)
        except RPCError as e:
            same(f"an error with the node's code {code}", e.code, code)
    # what descriptor.check_anchor and btc_anchor_from_rpc ask
    height = btc.getblockcount() - 6
    hdr = btc.getblockheader(btc.getblockhash(height), False)
    period = btc.getblockheader(btc.getblockhash(height - height % 2016))["time"]
    same("an anchor as `launch new` takes it", (height, hdr, period),
         (tip - 6, node.getblockheader(node.getblockhash(tip - 6), False), node.getblockheader(node.getblockhash(0))["time"]))

    # ---- transactions and outputs
    a2 = r.getnewaddress("", "bech32m")
    spk2 = node.validateaddress(a2)["scriptPubKey"]
    t1 = w.sendtoaddress(a2, 1.5)
    t2 = w.sendtoaddress(a2, 0.25)
    b1 = mine()[0]
    t3 = w.sendtoaddress(a2, 0.1)   # stays in the mempool
    settled()
    same("getrawtransaction", btc.getrawtransaction(t1), node.getrawtransaction(t1, False, b1))
    lv, nv = btc.getrawtransaction(t1, True), node.getrawtransaction(t1, True, b1)
    same("getrawtransaction verbose", _tx_view(lv), _tx_view(nv))
    same("a transaction in the mempool has no confirmations", "confirmations" in btc.getrawtransaction(t3, True), False)
    try:
        btc.getrawtransaction("ab" * 32)
        check("an unknown transaction is an error", False)
    except RPCError as e:
        same("an unknown transaction is error -5", e.code, -5)
    n1 = next(o["n"] for o in nv["vout"] if o["scriptPubKey"]["hex"] == spk2)
    lo, no = btc.gettxout(t1, n1), node.gettxout(t1, n1)
    same("gettxout", (sats(lo["value"]), lo["scriptPubKey"]["hex"], lo["confirmations"], lo["bestblock"], lo["coinbase"]),
         (sats(no["value"]), no["scriptPubKey"]["hex"], no["confirmations"], no["bestblock"], no["coinbase"]))
    n3 = next(o["n"] for o in node.getrawtransaction(t3, True)["vout"] if o["scriptPubKey"]["hex"] == spk2)
    same("gettxout of an output in the mempool", btc.gettxout(t3, n3)["confirmations"], node.gettxout(t3, n3)["confirmations"])
    same("gettxout without the mempool", btc.gettxout(t3, n3, False), node.gettxout(t3, n3, False))
    spent_in = nv["vin"][0]
    same("gettxout of a spent output", btc.gettxout(spent_in["txid"], spent_in["vout"]), node.gettxout(spent_in["txid"], spent_in["vout"]))
    cb = node.getblock(b1, 2)["tx"][0]  # too young to have been spent
    same("gettxout of a coinbase", btc.gettxout(cb["txid"], 0)["coinbase"], True)
    spk1 = node.validateaddress(a1)["scriptPubKey"]
    ls, ns = btc.scantxoutset("start", [f"raw({spk2})", f"raw({spk1})"]), node.scantxoutset("start", [f"raw({spk2})", f"raw({spk1})"])
    same("scantxoutset", (ls["height"], ls["bestblock"], sats(ls["total_amount"]), _unspents(ls)),
         (ns["height"], ns["bestblock"], sats(ns["total_amount"]), _unspents(ns)))
    utip, ures = btc.unspent([spk2])
    same("unspent: confirmed outputs proven, the mempool's with height 0",
         sorted((u["tx_hash"], u["value"], u["height"], u.get("proven")) for u in ures[spk2]),
         sorted([(t1, 150_000_000, tip + 1, True), (t2, 25_000_000, tip + 1, True), (t3, 10_000_000, 0, None)]))
    same("estimatesmartfee where the node has no estimate", "feerate" in btc.estimatesmartfee(2), "feerate" in node.estimatesmartfee(2))
    raw3 = node.getrawtransaction(t3)
    same("decoderawtransaction", _tx_view(btc.decoderawtransaction(raw3), confs=False), _tx_view(node.decoderawtransaction(raw3), confs=False))

    # ---- a payment as the sats leg makes it: found through the script's history, and proven
    pay_addr = r.getnewaddress("", "bech32")
    pay_script = node.validateaddress(pay_addr)["scriptPubKey"]
    tag = "5a" * 20
    raw = w.createrawtransaction([], [{pay_addr: 0.0007}, {"data": "4846" + tag}])
    signed = w.signrawtransactionwithwallet(w.fundrawtransaction(raw, {"changePosition": 2})["hex"])["hex"]
    paid = btc.sendrawtransaction(signed)          # sent through the light object
    same("sendrawtransaction reaches the node's mempool", paid in node.getrawmempool(), True)
    same("payments_to: nothing before a block has it", btc.payments_to(pay_script), [])
    for _ in range(3):                             # company in the block, so the branch has more than one step
        w.sendtoaddress(w.getnewaddress(), 0.01)
    b2 = mine()[0]
    found = btc.payments_to(pay_script)
    blk = node.getblock(b2, 2)
    theirs = next(t for t in blk["tx"] if t["txid"] == paid)
    check("payments_to finds it", len(found) == 1 and found[0]["txid"] == paid, f"{len(found)} found")
    d = found[0]
    same("the transaction as getblock(hash, 2) lists it",
         (d["txid"], d["hex"], [(sats(o["value"]), o["scriptPubKey"]["hex"]) for o in d["vout"]]),
         (theirs["txid"], theirs["hex"], [(sats(o["value"]), o["scriptPubKey"]["hex"]) for o in theirs["vout"]]))
    txids = [bytes.fromhex(t["txid"])[::-1] for t in blk["tx"]]
    pos = [t["txid"] for t in blk["tx"]].index(paid)
    same("its block, height, position and branch", (d["blockhash"], d["height"], d["pos"], d["branch"], d["confirmations"]),
         (b2, blk["height"], pos, merkle_branch(txids, pos), 1))
    check("the branch leads to the node's merkle root",
          root_from_branch(bytes.fromhex(paid)[::-1], d["branch"], d["pos"]) == bytes.fromhex(blk["merkleroot"])[::-1],
          f"{len(d['branch'])} steps, {len(txids)} transactions in the block")
    # the settler's own reading of it (settler.WatchSettler._match, in short)
    data = bytes.fromhex(d["vout"][1]["scriptPubKey"]["hex"])
    check("the tag list binds output 0", data[:2] == bytes([0x6A, 22]) and data[2:4] == b"HF" and data[4:24].hex() == tag
          and d["vout"][0]["scriptPubKey"]["hex"] == pay_script and round(d["vout"][0]["value"] * 1e8) == 70_000)
    p = btc.txproof(paid, b2)
    same("txproof by block", (p["height"], p["pos"], p["branch"], p["hex"]), (blk["height"], pos, merkle_branch(txids, pos), theirs["hex"]))
    same("txproof without the block", btc.txproof(paid)["blockhash"], b2)
    same("the header of the payment's block", btc.getblockheader(b2)["confirmations"], 1)
    same("payments_to from a later block on", btc.payments_to(pay_script, min_height=blk["height"] + 1), [])

    # ---- what spent an output
    same("find_spend of an unspent output", btc.find_spend(paid, 0), None)
    sweep = r.sendall([a1], None, None, None, {"inputs": [{"txid": paid, "vout": 0}]})["txid"]
    settled()
    got = btc.find_spend(paid, 0)
    same("find_spend in the mempool", got and (got.txid_hex(), [w_.hex() for w_ in got.vin[0].witness]),
         (sweep, node.getrawtransaction(sweep, True)["vin"][0]["txinwitness"]))
    mine()
    same("find_spend in a block", btc.find_spend(paid, 0).txid_hex(), sweep)
    same("gettxout after the spend", btc.gettxout(paid, 0), None)

    # ---- a refusal carries the node's reason
    clash = w.createrawtransaction([{"txid": spent_in["txid"], "vout": spent_in["vout"]}], [{a1: 0.001}])
    clash = w.signrawtransactionwithwallet(clash)["hex"]
    try:
        node.sendrawtransaction(clash)
        reason = None
    except RPCError as e:
        reason = e.message
    try:
        btc.sendrawtransaction(clash)
        check("a spent input is refused", False)
    except RPCError as e:
        check("a refused transaction says why, as the node does", e.code == -26 and reason and reason.split()[0] in str(e), str(e)[:160])

    # ---- the wallet of one key, paying the way the settler pays
    keyfile = os.path.join(work, "light.key")
    with open(keyfile, "w") as f:
        f.write("11" * 31 + "42")
    lw = btc.wallet(keyfile)
    check("the key's address is a regtest address", lw.address.startswith("bcrt1q"), lw.address)
    w.sendtoaddress(lw.address, 0.004)
    w.sendtoaddress(lw.address, 0.001)
    mine()
    same("its balance", sats(lw.getbalance()), 500_000)
    payee = r.getnewaddress("", "bech32m")
    payee_spk = bytes.fromhex(node.validateaddress(payee)["scriptPubKey"])

    def settler_pay(amount, tagbyte):
        outs = [TxOut(amount, payee_spk), TxOut(0, bytes([0x6A, 22]) + b"HF" + bytes([tagbyte]) * 20)]
        rawtx = Tx(version=2, vin=[], vout=outs).serialize(witness=False).hex()
        funded = lw.fundrawtransaction(rawtx, {"changePosition": len(outs)}, False)
        sig = lw.signrawtransactionwithwallet(funded["hex"])
        return sig, lw.decoderawtransaction(sig["hex"])["txid"]
    sig, txid = settler_pay(120_000, 1)
    verdict = node.testmempoolaccept([sig["hex"]])[0]
    check("a real node accepts what it signed", sig["complete"] and verdict["allowed"] and verdict["txid"] == txid, str(verdict)[:200])
    tx = Tx.parse(bytes.fromhex(sig["hex"]))
    same("outputs as asked: the payee, the tag list, change last",
         ([o.value for o in tx.vout[:2]], tx.vout[0].script_pubkey, len(tx.vout)), ([120_000, 0], payee_spk, 3))
    same("sendrawtransaction of its own payment", lw.sendrawtransaction(sig["hex"]), txid)
    settled()
    same("gettransaction before a block", lw.gettransaction(txid)["confirmations"], 0)
    sig2, txid2 = settler_pay(370_000, 2)   # needs the change of the first, which is in no block yet
    v2 = node.testmempoolaccept([sig2["hex"]])[0]
    check("a second payment spends the first one's change", v2["allowed"] and
          (bytes.fromhex(txid)[::-1], 2) in {(i.prev_txid, i.prev_vout) for i in Tx.parse(bytes.fromhex(sig2["hex"])).vin}, str(v2)[:200])
    lw.sendrawtransaction(sig2["hex"])
    try:
        settler_pay(100_000, 3)
        check("nothing left: insufficient funds", False)
    except RPCError as e:
        same("nothing left: error -4", e.code, -4)
    b3 = mine()[0]
    g = lw.gettransaction(txid)
    same("gettransaction in a block", (g["confirmations"], g["blockhash"], g["hex"]), (1, b3, sig["hex"]))
    blk3 = node.getblock(b3, 1)
    pos3 = blk3["tx"].index(txid)
    same("the proof of its payment", (lw.txproof(txid, g["blockhash"])["pos"], lw.txproof(txid, b3)["branch"]),
         (pos3, merkle_branch([bytes.fromhex(t)[::-1] for t in blk3["tx"]], pos3)))
    same("the payee was paid", sorted(sats(u["amount"]) for u in node.scantxoutset("start", [f"raw({payee_spk.hex()})"])["unspents"]),
         [120_000, 370_000])
    fresh = btc.wallet(keyfile)  # the settler after a restart: it has the id and the bytes it stored, nothing else
    same("gettransaction from a wallet that did not sign it", fresh.gettransaction(txid2)["confirmations"], 1)
    same("sending a payment that is in a block again", fresh.sendrawtransaction(sig2["hex"]), txid2)
    try:
        fresh.gettransaction("cd" * 32)
        check("a transaction nobody knows is error -5", False)
    except RPCError as e:
        same("a transaction nobody knows is error -5", e.code, -5)

    # ---- a reorganisation
    before = btc.getblockcount()
    node.invalidateblock(b3)
    # The payments return to the mempool and are mined again on the new branch. (To another address:
    # the same block again, in the same second, would be the block the node was just told is invalid.)
    w.generatetoaddress(2, w.getnewaddress("", "bech32"))
    settled()
    same("after a reorg: the tip", (btc.getblockcount(), btc.getbestblockhash()), (before + 1, node.getbestblockhash()))
    same("the block that left has -1 confirmations", btc.getblockheader(b3)["confirmations"], -1)
    g2 = lw.gettransaction(txid)
    new_tip = node.getblockcount()  # (the node keeps no transaction index: look in the two new blocks)
    now_in = next((bh for bh in (node.getblockhash(new_tip - 1), node.getblockhash(new_tip))
                   if txid in node.getblock(bh, 1)["tx"]), None)
    check("the node mined the payment again on the new branch", now_in is not None)
    same("the payment is where the node has it now", g2.get("blockhash"), now_in)
    check("and no longer in the block that left", g2.get("blockhash") != b3)
    if now_in:
        nb = node.getblock(now_in, 1)
        p2 = lw.txproof(txid)
        same("its proof is for the new block", (p2["blockhash"], p2["pos"], p2["branch"]),
             (now_in, nb["tx"].index(txid), merkle_branch([bytes.fromhex(t)[::-1] for t in nb["tx"]], nb["tx"].index(txid))))
        try:
            lw.txproof(txid, b3)
            check("no proof against the block that left", False)
        except RPCError as e:
            same("no proof against the block that left", e.code, -5)
    same("payments_to after the reorg", [(d["txid"], d["blockhash"]) for d in btc.payments_to(payee_spk.hex())
                                         if d["txid"] == txid], [(txid, now_in)] if now_in else [])

    # ---- what a node can do and Electrum servers cannot is said, not guessed
    for name, call in (("getblock", lambda: btc.getblock(b2, 2)), ("getrawmempool", lambda: btc.getrawmempool()),
                       ("sendtoaddress", lambda: btc.sendtoaddress(a1, 1))):
        try:
            call()
            check(f"{name} is not answered", False)
        except L.NotAvailable as e:
            check(f"{name} is not answered, and says so", not isinstance(e, RPCError), str(e)[:90])
    same("the server that is not there was passed over, the other two never failed",
         [s.strikes > 0 for s in btc.servers], [True, False, False])
    btc.close()


# ------------------------------------------------------------------ the callers, through the light object
class _Launch:
    """What the settlers ask a hashfund node. Its Bitcoin header tree and its verdict on a proof are
    the reference model's (what the node runs)."""

    def __init__(self, anchor_header: bytes, anchor_height: int, confs=1):
        from hashfun import yieldmodel as Y
        self.Y = Y
        self.relay = Y.BtcChain(anchor_header, anchor_height, 0, True)
        self.confs, self.tip, self.obs, self.owner = confs, 30, {}, "0014" + "77" * 20

    def owe(self, height, pay, pay_script, payee="holder"):
        bh = (b"%064d" % height).decode()
        self.obs[height] = {"height": height, "hash": bh, "curve": True, "quote": "btc", "owed": pay, "draw_known": True,
                            "settled": False, "deadline_height": 700,
                            "tag": self.Y.pay_tag(b"\x42" * 32, bytes.fromhex(bh)[::-1]).hex(), "pay": pay, "payee": payee,
                            "pay_script": pay_script}
        return bh

    def owe_new(self, pay, pay_script):
        """A new block that owes, with the six blocks on top that make its draw known."""
        h = self.tip + 1
        self.owe(h, pay, pay_script)
        self.tip = h + 6
        return h

    def getblockcount(self):
        return self.tip

    def getmintobligation(self, h):
        if h > self.tip:
            raise RPCError({"code": -8, "message": "Block height out of range"})
        return dict(self.obs.get(h) or {"height": h, "hash": (b"%064d" % h).decode(), "curve": True, "quote": "btc", "owed": 0,
                                         "draw_known": True, "settled": False, "deadline_height": 700, "tag": "00" * 20,
                                         "pay": 0, "payee": "holder"})

    def getlaunchinfo(self):
        return {"graduated": False, "height": self.tip, "descriptor": {"settle_deadline": 720}}

    def getbtcrelay(self):
        n = self.relay.nodes[self.relay.best]
        return {"height": n.height, "best": self.relay.best[::-1].hex(), "anchor_height": self.relay.anchor_height,
                "confirmations_required": self.confs}

    def getblockhash(self, h):
        return (b"%064d" % h).decode()

    def getblock(self, _bh, _v):
        return {"tx": [{"vout": [{"value": 1.0, "scriptPubKey": {"hex": self.owner}}]}]}

    def mine(self, outs):
        """A launch block carrying a settler's coinbase outputs: headers first, then proofs, as consensus reads them."""
        Y, took = self.Y, {"headers": 0, "settled": [], "refused": []}
        for o in outs:
            data = Y.tagged_return(o.script_pubkey, b"HFH1")
            if data is not None:
                for h in Y.parse_btc_headers(data) or []:
                    took["headers"] += self.relay.accept(h)[0]
                continue
            data = Y.tagged_return(o.script_pubkey, b"HFP1")
            if data is not None:
                pr = Y.PaymentProof.parse(data)
                ob = self.obs[pr.mint_height]
                n = self.relay.nodes.get(pr.btc_block)
                if n is None or self.relay.confirmations(pr.btc_block) < self.confs or pr.candidate != 0:
                    took["refused"].append((pr.mint_height, "block unknown to the relay or not deep enough"))
                    continue
                ok, err = Y.verify_btc_payment(pr, n.merkle_root, bytes.fromhex(ob["tag"]), bytes.fromhex(ob["pay_script"]),
                                               ob["pay"])
                if ok and not ob["settled"]:
                    ob["settled"] = True
                    took["settled"].append(pr.mint_height)
                elif not ok:
                    took["refused"].append((pr.mint_height, err))
        self.tip += 1
        return took


def _http(base, path, body=None):
    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="GET" if body is None else "POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def integrate(node, work):
    from hashfun import descriptor as D, web
    from hashfun.settler import Settler, WatchSettler
    print("-- the callers through btclight", flush=True)
    node.createwallet("iw")
    node.createwallet("ir")
    w, r = node.wallet("iw"), node.wallet("ir")
    a1 = w.getnewaddress("", "bech32")
    w.generatetoaddress(101, a1)
    ports = [free_port(), free_port()]
    for p in ports:
        srv = ElectrumServer(node, "127.0.0.1", p)
        threading.Thread(target=lambda s=srv: asyncio.run(s.serve()), daemon=True).start()

    def port_open(p):
        try:
            socket.create_connection(("127.0.0.1", p), timeout=1).close()
            return True
        except OSError:
            return False
    wait(lambda: all(port_open(p) for p in ports), "the Electrum servers")
    url = f"electrum://127.0.0.1:{ports[0]},127.0.0.1:{ports[1]}?net=regtest&poll=0"
    btc = L.open_rpc(url)
    check("open_rpc: an electrum:// URL is the light object, anything else a node's RPC",
          L.is_light(btc) and not L.is_light(L.open_rpc("http://u:p@127.0.0.1:1")) and not L.is_light(node))

    def settled():
        tip, pool = node.getblockcount(), set(node.getrawmempool())
        for p in ports:
            one = L.connect(f"electrum://127.0.0.1:{p}?net=regtest&poll=0")
            wait(lambda: one.servers[0].call("blockchain.headers.subscribe")["height"] == tip, "an Electrum server's tip")
            for txid in pool:
                wait(lambda: _has(one, txid), "an Electrum server's mempool")
            one.close()

    def mine(n=1, to=None):
        hs = w.generatetoaddress(n, to or a1)
        settled()
        return hs

    addr_of = {}

    def new_script(wallet=r):
        a = wallet.getnewaddress("", "bech32")
        spk = node.validateaddress(a)["scriptPubKey"]
        addr_of[spk] = a
        return spk

    def pay_as_a_user(obs):
        """One Bitcoin transaction from the node's wallet paying obligations: output i, tag i."""
        outs = [{addr_of[ob["pay_script"]]: ob["pay"] / 1e8} for ob in obs] + [{"data": "4846" + "".join(ob["tag"] for ob in obs)}]
        raw = w.createrawtransaction([], outs)
        return w.sendrawtransaction(w.signrawtransactionwithwallet(w.fundrawtransaction(raw, {"changePosition": len(outs)})["hex"])["hex"])
    settled()

    # ---- the anchor: descriptor.check_anchor and btc_anchor_from_rpc through the light object
    anchor_h = node.getblockcount() - 2
    anchor_hdr = node.getblockheader(node.getblockhash(anchor_h), False)
    check("btc_anchor_from_rpc", D.btc_anchor_from_rpc(btc) == D.btc_anchor_from_rpc(node), str(D.btc_anchor_from_rpc(btc)[0]))

    class Anchor:  # what check_anchor reads of a launch
        header = bytes.fromhex(anchor_hdr)

        @classmethod
        def anchor(cls, quote):
            return anchor_h, cls.header, 0

        @staticmethod
        def quote_regtest(quote):
            return True
    try:
        D.check_anchor(Anchor, btc)
        check("check_anchor accepts the true anchor", True)
    except D.DescriptorError as e:
        check("check_anchor accepts the true anchor", False, str(e))
    Anchor.header = bytes.fromhex(node.getblockheader(node.getblockhash(anchor_h - 1), False))
    try:
        D.check_anchor(Anchor, btc)
        check("check_anchor refuses a header from another height", False)
    except D.DescriptorError as e:
        check("check_anchor refuses a header from another height", "wrong height" in str(e), str(e)[:90])

    # ---- A. the settler that watches (the site's): users pay, it finds the payments and proves them
    launch = _Launch(bytes.fromhex(anchor_hdr), anchor_h)
    P, Pb = new_script(), new_script()
    launch.owe(10, 5000, P)
    launch.owe(11, 7000, Pb)
    ws = WatchSettler(launch, btc, os.path.join(work, "watch.json"))
    took = launch.mine(ws.coinbase_outputs())
    check("watch: Bitcoin headers relayed from the light object's chain", took["headers"] == 2 and
          launch.getbtcrelay()["best"] == node.getbestblockhash(), str(took))
    check("watch: two blocks are due", [d["height"] for d in ws.due()] == [10, 11] and not any(d["paid"] for d in ws.due()))
    paid = pay_as_a_user([launch.obs[10], launch.obs[11]])
    settled()
    launch.mine(ws.coinbase_outputs())
    check("watch: a payment in no block yet is not a payment", not ws.st["paid"])
    b1 = mine()[0]
    outs = ws.coinbase_outputs()
    check("watch: the payment is found through the script's history",
          {k: (v["txid"], v["vout"], v["sats"], v["blockhash"]) for k, v in ws.st["paid"].items()} ==
          {f"10:{launch.obs[10]['hash']}": (paid, 0, 5000, b1), f"11:{launch.obs[11]['hash']}": (paid, 1, 7000, b1)})
    took = launch.mine(outs)
    check("watch: both proofs satisfy the reference verifier", took["settled"] == [10, 11] and not took["refused"], str(took))
    launch.mine(ws.coinbase_outputs())
    launch.mine(ws.coinbase_outputs())   # (a settled block leaves the list one round after its proof is seen settled)
    check("watch: nothing is due or waiting afterwards", ws.status()["due"] == 0 and ws.status()["paid_awaiting_proof"] == 0,
          str(ws.status()))
    P2, P3 = new_script(), new_script()
    ha, hb = launch.owe_new(9000, P2), launch.owe_new(4000, P3)
    launch.mine(ws.coinbase_outputs())
    check("watch: the new blocks are due", [d["height"] for d in ws.due()] == [ha, hb], str([d["height"] for d in ws.due()]))
    short = dict(launch.obs[ha], pay=8999)
    elsewhere = dict(launch.obs[hb], pay_script=new_script())
    pay_as_a_user([short])
    pay_as_a_user([elsewhere])
    pay_as_a_user([dict(launch.obs[hb], tag=launch.obs[ha]["tag"])])
    mine()
    took = launch.mine(ws.coinbase_outputs())
    check("watch: short, misdirected and mistagged payments are not payments", not ws.st["paid"] and not took["settled"] and
          len(btc.payments_to(P2)) == 1 and len(btc.payments_to(P3)) == 1, str(took))
    good = pay_as_a_user([launch.obs[ha], launch.obs[hb]])
    bx = mine()[0]
    outs = ws.coinbase_outputs()   # found, proof built, and this launch block is never mined
    check("watch: found in the block about to disappear", {v["blockhash"] for v in ws.st["paid"].values()} == {bx} and
          len(ws.st["paid"]) == 2 and len(outs) == 3, f"{len(outs)} coinbase outputs: the header and two proofs")
    node.invalidateblock(bx)
    w.generatetoaddress(2, w.getnewaddress("", "bech32"))
    settled()
    tipnow = node.getblockcount()
    by = next(bh for bh in (node.getblockhash(tipnow - 1), node.getblockhash(tipnow)) if good in node.getblock(bh, 1)["tx"])
    took = launch.mine(ws.coinbase_outputs())    # sees the block gone: forgets the payment, relays the new branch
    took2 = launch.mine(ws.coinbase_outputs())   # finds it again where it is now, and proves that
    took3 = launch.mine(ws.coinbase_outputs())
    seen = took["settled"] + took2["settled"] + took3["settled"]
    check("watch: after a Bitcoin reorg the payment is proven in its new block", sorted(seen) == [ha, hb] and
          not (took["refused"] + took2["refused"] + took3["refused"]) and launch.relay.confirmations(bytes.fromhex(by)[::-1]) >= 1,
          f"{took} {took2} {took3}")
    stale = launch.mine(outs)  # the proofs built before the reorg, mined now: that block is not on the relay's best chain
    check("watch: the proofs for the block that left count for nothing", not stale["settled"] and
          launch.relay.confirmations(bytes.fromhex(bx)[::-1]) == 0, str(stale))

    # ---- B. the settler that pays, from a key and Electrum servers
    keyfile = os.path.join(work, "pay.key")
    with open(keyfile, "w") as f:
        f.write("22" * 31 + "07")
    lw = btc.wallet(keyfile)
    w.sendtoaddress(lw.address, 0.01)
    mine()
    Q1, Q2 = new_script(), new_script()
    h14, h15 = launch.owe(14, 6000, Q1), launch.owe(15, 8000, Q2, payee="creator")
    state = os.path.join(work, "pay.json")
    s = Settler(launch, lw, state, pay_depth=0)
    s.add_block(14, h14)
    s.add_block(15, h15)
    launch.mine(s.coinbase_outputs())
    pays = {v["txid"] for v in s.st["paid"].values()}
    check("pay: one Bitcoin transaction pays both blocks, and the node has it", len(pays) == 1 and pays <= set(node.getrawmempool()),
          str(pays))
    txid = next(iter(pays))
    decoded = node.getrawtransaction(txid, True)
    check("pay: output i pays the drawn script, tag i binds it",
          [(round(o["value"] * 1e8), o["scriptPubKey"]["hex"]) for o in decoded["vout"][:3]] ==
          [(6000, Q1), (8000, Q2), (0, "6a2a4846" + launch.obs[14]["tag"] + launch.obs[15]["tag"])])
    s2 = Settler(launch, btc.wallet(keyfile), state, pay_depth=0)   # a restart before the payment is in a block
    launch.mine(s2.coinbase_outputs())
    launch.mine(s2.coinbase_outputs())
    pool_pays = [t for t in node.getrawmempool()
                 if any(o["scriptPubKey"]["hex"] in (Q1, Q2) for o in node.getrawtransaction(t, True)["vout"])]
    check("pay: after a restart it waits for its payment, it does not pay again", pool_pays == [txid] and not s2.st["lost"],
          str(s2.status()))
    mine()
    took = launch.mine(s2.coinbase_outputs())
    check("pay: both proofs satisfy the reference verifier", took["settled"] == [14, 15] and not took["refused"], str(took))
    launch.mine(s2.coinbase_outputs())
    check("pay: settled, nothing lost", s2.status()["awaiting_payment_or_proof"] == 0 and s2.status()["lost_payments"] == 0,
          str(s2.status()))
    got = {u["scriptPubKey"]: round(u["amount"] * 1e8) for u in node.scantxoutset("start", [f"raw({Q1})", f"raw({Q2})"])["unspents"]}
    check("pay: the payees hold exactly what was owed", got == {Q1: 6000, Q2: 8000}, str(got))
    h16 = launch.owe(16, 3000, Q1)
    s2.add_block(16, h16)
    launch.mine(s2.coinbase_outputs())
    mine()
    s3 = Settler(launch, btc.wallet(keyfile), state, pay_depth=0)
    took = launch.mine(s3.coinbase_outputs())
    check("pay: a later block, paid from the change, proven by a settler that started afterwards",
          took["settled"] == [16] and not s3.st["lost"], str(took))
    try:
        Settler(launch, btc, os.path.join(work, "nokey.json"), pay_depth=0)._pay([launch.obs[16]])
        check("pay: without a key nothing is paid, and it says why", False)
    except L.NotAvailable as e:
        check("pay: without a key nothing is paid, and it says why", "holds no key" in str(e))

    # ---- C. the site, over HTTP, through the light object; the same questions to a site on the node
    class Reg:
        data = {}
    site_n, site_l = web.Site(node, Reg()), web.Site(btc, Reg(), btc_index=btc)
    hp = free_port()
    web.serve(site_l, "127.0.0.1", hp)
    base = f"http://127.0.0.1:{hp}/api"
    wait(lambda: port_open(hp), "the site")
    check("site: the network", (site_l.btc_chain, site_l.btc_hrp) == (site_n.btc_chain, site_n.btc_hrp), site_l.btc_chain)
    for spk in (Q1, P, node.validateaddress(lw.address)["scriptPubKey"]):
        code, x = _http(base, f"/chain/btc/address/{addr_of.get(spk) or lw.address}")
        y = site_n.btc_address(spk)
        conf = sorted((u["txid"], u["vout"], u["value"], u["confirmations"]) for u in x["utxos"] if u["confirmations"] > 0)
        check(f"site: balance of {spk[:12]}.. over HTTP", code == 200 and (x["balance"], conf) ==
              (y["balance"], sorted((u["txid"], u["vout"], u["value"], u["confirmations"]) for u in y["utxos"])), f"{x.get('balance')} sats")
    site_l.scan["btc"].refresh({Q1, Q2})
    check("site: sats behind bids (KeyScan through the light object)", site_l.scan["btc"].sats == {Q1: 9000, Q2: 8000},
          str(site_l.scan["btc"].sats))
    code, tl = _http(base, f"/chain/btc/tx/{txid}")
    check("site: a transaction over HTTP", code == 200 and tl == _site_tx(node, txid), f"{tl.get('confirmations')} confirmations")
    code, ol = _http(base, f"/chain/btc/txout/{txid}/0")
    check("site: an output over HTTP", code == 200 and ol == site_n.txout("btc", txid, 0), str(ol))
    code, cl = _http(base, "/chain/btc/time")
    check("site: the chain's time over HTTP", code == 200 and cl == site_n.chain_time("btc"), str(cl))
    # the broadcast path: a transaction the browser signed, sent through the site
    sweep = r.createrawtransaction([{"txid": txid, "vout": 0}], [{a1: 0.00005}])
    sweep = r.signrawtransactionwithwallet(sweep)["hex"]
    code, sent = _http(base, "/chain/btc/tx", {"hex": sweep})
    check("site: broadcast over HTTP reaches the node", code == 200 and sent.get("txid") in node.getrawmempool(), str(sent))
    code, again = _http(base, "/chain/btc/tx", {"hex": r.signrawtransactionwithwallet(
        r.createrawtransaction([{"txid": txid, "vout": 0}], [{a1: 0.000055}]))["hex"]})  # a lower fee: no replacement
    check("site: a double spend is refused with the node's reason and code", code == 400 and again.get("code") == -26 and
          any(w in again.get("error", "") for w in ("fee", "conflict", "replacement", "spent")), str(again)[:160])
    settled()
    code, sp = _http(base, f"/chain/btc/spender/{txid}/0")
    check("site: what spent an output, from the mempool", code == 200 and sp == site_n.spender("btc", txid, 0) and
          sp["txid"] == sent.get("txid"), str(sp)[:120])
    mine()
    code, sp = _http(base, f"/chain/btc/spender/{txid}/0")
    check("site: what spent an output, from a block", code == 200 and sp == site_n.spender("btc", txid, 0))
    code, none = _http(base, f"/chain/btc/spender/{txid}/1")
    check("site: an unspent output has no spender", code == 200 and none is None and site_n.spender("btc", txid, 1) is None)
    code, x = _http(base, f"/chain/btc/address/{addr_of[Q1]}")
    check("site: a balance after a spend", code == 200 and x["balance"] == site_n.btc_address(Q1)["balance"] == 3000,
          f"{x.get('balance')} sats")
    btc.close()


def _site_tx(node, txid):
    """Site.tx as a site on the node gives it; the node here has no transaction index, so it is built from the block."""
    tip = node.getblockcount()
    for h in range(tip, tip - 20, -1):
        bh = node.getblockhash(h)
        if txid in node.getblock(bh, 1)["tx"]:
            t = node.getrawtransaction(txid, True, bh)
            return {"txid": t["txid"], "confirmations": t.get("confirmations", 0), "hex": t["hex"],
                    "vout": [{"n": o["n"], "value": sats(o["value"]), "script": o["scriptPubKey"]["hex"]} for o in t["vout"]],
                    "vin": [{"txid": i.get("txid"), "vout": i.get("vout"), "witness": i.get("txinwitness", [])} for i in t["vin"]]}


def _has(one, txid):
    try:
        one.servers[0].call("blockchain.transaction.get", txid)
        return True
    except L.ElectrumError:
        return False


def _tx_view(t, confs=True):
    v = {"txid": t["txid"], "hash": t["hash"], "version": t["version"], "size": t["size"], "vsize": t["vsize"],
         "locktime": t["locktime"],
         "vin": [(i.get("txid"), i.get("vout"), i.get("coinbase"), i.get("txinwitness"), i["sequence"]) for i in t["vin"]],
         "vout": [(o["n"], sats(o["value"]), o["scriptPubKey"]["hex"]) for o in t["vout"]]}
    if confs:
        v.update(hex=t["hex"], confirmations=t.get("confirmations"), blockhash=t.get("blockhash"), blocktime=t.get("blocktime"))
    return v


def _unspents(scan):
    return sorted((u["txid"], u["vout"], u["scriptPubKey"], sats(u["amount"]), u["height"]) for u in scan["unspents"])


if __name__ == "__main__":
    sys.exit(main())
