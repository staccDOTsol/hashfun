"""The no-install path, end to end on regtest: a visitor asks the site to mine a block for them, the
server's CPU mines it to their address, they pay that block's sats from their own Bitcoin wallet
(as their browser wallet would: one tagged transaction), the site's settler sees the payment and
proves it, and their coins unlock. Plus the public stratum: an outside miner with only a launch
address as username gets the coinbase.

python -m hashfun.tests.sitepool_regtest --hashfund build/bin/hashfund --bitcoind PATH
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

from hashfun import yieldmodel as Y
from hashfun.crypto import hash160, pubkey_from_priv, random_priv
from hashfun.rpc import RPC
from hashfun.ser import Tx, TxOut, segwit_encode
from hashfun.tests.e2e_regtest import free_port

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  [{detail}]"), flush=True)


def wait(pred, timeout, what):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            v = pred()
            if v:
                return v
        except Exception:
            pass
        time.sleep(0.5)
    raise TimeoutError(what)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hashfund", required=True)
    ap.add_argument("--bitcoind", required=True)
    a = ap.parse_args()
    w = tempfile.mkdtemp(prefix="hashfun-sitepool-")
    env = dict(os.environ, HASHFUN_HOME=os.path.join(w, "home"), HASHFUND=os.path.abspath(a.hashfund))
    hf = [sys.executable, "-m", "hashfun.cli"]
    procs = []
    try:
        bp = free_port()
        procs.append(subprocess.Popen([a.bitcoind, "-regtest", f"-datadir={w}", "-server=1", "-listen=0", f"-rpcport={bp}",
                                       "-fallbackfee=0.0001", "-printtoconsole=0"]))
        cookie = os.path.join(w, "regtest", ".cookie")
        btc_url = f"http://127.0.0.1:{bp}"
        wait(lambda: os.path.exists(cookie) and RPC(btc_url, cookie_file=cookie).getblockcount() >= 0, 60, "bitcoind")
        btc = RPC(btc_url, cookie_file=cookie)
        btc.createwallet("w")
        wb = btc.wallet("w")
        ba = wb.getnewaddress("", "bech32")
        wb.generatetoaddress(110, ba)

        def addr(hrp):
            return segwit_encode(hrp, 0, hash160(pubkey_from_priv(random_priv())))

        subprocess.run(hf + ["launch", "new", "--name", "Site pool", "--ticker", "SPL", "--creator-address", addr("spl"),
                             "--graduation-hashes", "1e9", "--pow-limit", "207fffff", "--spacing", "5", "--window", "10",
                             "--test", "--btc-rpc", btc_url, "--btc-cookie", cookie, "--sats-total", "0.5",
                             "--creator-btc-address", wb.getnewaddress("", "bech32"), "--btc-hrp", "bcrt",
                             "-o", os.path.join(w, "spl.json")], env=env, check=True, capture_output=True)
        d = json.load(open(os.path.join(w, "spl.json")))
        hrp = d["hrp"]
        subprocess.run(hf + ["node", "add", os.path.join(w, "spl.json")], env=env, check=True, capture_output=True)
        subprocess.run(hf + ["node", "up"], env=env, check=True, capture_output=True)
        site_port = free_port()
        op_priv = random_priv()
        op_pub = pubkey_from_priv(op_priv)
        log = open(os.path.join(w, "web.log"), "w")
        procs.append(subprocess.Popen(hf + ["web", "--btc-rpc", btc_url, "--btc-cookie", cookie, "--listen", f"127.0.0.1:{site_port}",
                                            "--pool", "--pool-host", "127.0.0.1", "--operator-pubkey", op_pub.hex(),
                                            "--pool-cut-bps", "500"], env=env, stdout=log, stderr=subprocess.STDOUT))
        base = f"http://127.0.0.1:{site_port}/api"

        def get(path):
            return json.load(urllib.request.urlopen(base + path, timeout=20))

        def post(path, body):
            req = urllib.request.Request(base + path, json.dumps(body).encode(), {"Content-Type": "application/json"})
            return json.load(urllib.request.urlopen(req, timeout=20))

        coin = wait(lambda: (get("/coin/SPL").get("pool") or None) and get("/coin/SPL"), 120, "the site serving SPL with a pool")
        check("the site runs a pool for the launch, with a public stratum port", coin["pool"]["stratum_port"] == coin["p2p_port"] + 2,
              coin["pool"])
        reg = json.load(open(os.path.join(w, "home", "launches.json")))
        e = reg["SPL"]
        os.environ["HASHFUN_HOME"] = env["HASHFUN_HOME"]
        from hashfun.cli import Registry
        launch = Registry().rpc("SPL")
        h0 = launch.getblockcount()

        # 1. a visitor asks for two blocks; nobody else mines
        me = addr(hrp)
        r = post("/coin/SPL/queue", {"address": me, "blocks": 2})
        check("the queue takes the visitor's launch address", r["position"] == 0 and r["queue"] == 2, r)
        try:
            post("/coin/SPL/queue", {"address": "bcrt1qnotthislaunch0000000000000000000000000", "blocks": 1})
            check("an address of another chain is refused", False)
        except urllib.error.HTTPError as err:
            check("an address of another chain is refused", err.code == 400)
        try:
            wait(lambda: launch.getblockcount() >= h0 + 2 and get("/coin/SPL")["pool"]["queue"] == 0, 90, "two blocks for the visitor")
        except TimeoutError:
            print("state:", h0, launch.getblockcount(), get("/coin/SPL")["pool"], launch.getblockchaininfo())
            raise
        mine_script = launch.validateaddress(me)["scriptPubKey"]
        op_addr = segwit_encode(hrp, 0, hash160(op_pub))
        op_script = launch.validateaddress(op_addr)["scriptPubKey"]
        cbs = []
        for h in range(h0 + 1, launch.getblockcount() + 1):
            cb = launch.getblock(launch.getblockhash(h), 2)["tx"][0]
            if cb["vout"][0]["scriptPubKey"]["hex"] == mine_script:
                cbs.append((h, cb))
        check("the server's CPU mined exactly two blocks paying the visitor, output 0", len(cbs) == 2, [h for h, _ in cbs])
        h1, cb1 = cbs[0]
        total = sum(round(o["value"] * 1e8) for o in cb1["vout"] if o["scriptPubKey"]["hex"] in (mine_script, op_script))
        cut = next((round(o["value"] * 1e8) for o in cb1["vout"] if o["scriptPubKey"]["hex"] == op_script), 0)
        check("the operator's share is 5% of the block's reward, output 1", cb1["vout"][1]["scriptPubKey"]["hex"] == op_script
              and abs(cut - total * 500 // 10000) <= 1, (cut, total))

        # 2. the draws come: the site lists what the visitor owes
        ext = addr(hrp)
        port = coin["pool"]["stratum_port"]
        from hashfun.miner import StratumMiner
        import asyncio
        res = asyncio.run(StratumMiner("127.0.0.1", port, ext).run(25))
        hs = [h for h in range(h0 + 1, launch.getblockcount() + 1)
              if launch.getblock(launch.getblockhash(h), 2)["tx"][0]["vout"][0]["scriptPubKey"]["hex"] ==
              launch.validateaddress(ext)["scriptPubKey"]]
        check("an outside miner on the public stratum gets the coinbase at its username's address, no cut", len(hs) >= 6 and all(
            not any(o["scriptPubKey"]["hex"] == op_script for o in launch.getblock(launch.getblockhash(h), 2)["tx"][0]["vout"]) for h in hs),
            (len(hs), res))
        # By now coins are held and the difficulty has risen, so blocks owe real sats. The visitor
        # asks again; the outside miner then leaves, and the server alone mines the blocks that
        # carry the draws (it mines while a block that owes waits for its draw).
        due = None
        for _ in range(4):
            post("/coin/SPL/queue", {"address": me, "blocks": 3})
            wait(lambda: get("/coin/SPL")["pool"]["queue"] == 0, 300, "three more blocks for the visitor")
            try:
                due = wait(lambda: [x for x in get(f"/coin/SPL/due?address={me}") if x["pay"] > 0] or None, 90, "dues")
                break
            except TimeoutError:
                continue  # every draw said nothing is due (the lottery under the minimum payment): ask again
        if not due:
            raise TimeoutError("the visitor's dues")
        cb_heights = set(h for h in range(1, launch.getblockcount() + 1)
                         if launch.getblock(launch.getblockhash(h), 2)["tx"][0]["vout"][0]["scriptPubKey"]["hex"] == mine_script)
        check("the site lists the visitor's drawn blocks with what each owes and to which script",
              all(x["height"] in cb_heights and x["pay_script"] and len(x["tag"]) == 40 for x in due), due)

        check("until paid, those coinbases are locked", all(not launch.getmintobligation(x["height"])["spendable"] for x in due))

        # 3. the visitor pays from their own wallet: one transaction, output i <-> tag i
        outs = [TxOut(x["pay"], bytes.fromhex(x["pay_script"])) for x in due]
        outs.append(TxOut(0, Y.payment_outputs_tag([bytes.fromhex(x["tag"]) for x in due])))
        raw = Tx(version=2, vin=[], vout=outs).serialize(witness=False).hex()
        funded = wb.fundrawtransaction(raw, {"changePosition": len(outs)})
        txid = wb.sendrawtransaction(wb.signrawtransactionwithwallet(funded["hex"])["hex"])
        wb.generatetoaddress(2, ba)
        # nobody mines now: the server's CPU mines the blocks that carry the proof, to the operator
        settled = wait(lambda: all(launch.getmintobligation(x["height"])["settled"] for x in due) or None, 180,
                       "the site's settler proving the visitor's payment")
        check("the site's settler found the payment on Bitcoin and proved it: the blocks are settled", settled, txid)
        check("the visitor's coinbases are spendable now", all(launch.getmintobligation(x["height"])["spendable"] for x in due))
        check("settled blocks leave the visitor's list", wait(lambda: not [x for x in get(f"/coin/SPL/due?address={me}")
                                                                           if x["height"] in [y["height"] for y in due]] or None, 60, "list"))

        # 4. the same from a real browser: the page asks for a block, shows what it owes, and pays
        #    from the page's own key after one top-up from the (stand-in) wallet
        from playwright.sync_api import sync_playwright
        from hashfun.tests.web_regtest import MOCK, SIG, page_key
        btc.createwallet("u")
        wu = btc.wallet("u")
        uaddr = wu.getnewaddress("", "bech32")
        wb.sendtoaddress(uaddr, 1)
        wb.generatetoaddress(1, ba)
        pw = sync_playwright().start()
        browser = pw.chromium.launch()
        page = browser.new_context(viewport={"width": 1440, "height": 1000}).new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("dialog", lambda dlg: dlg.accept())
        page.expose_function("__hf_sign", lambda m: SIG)
        page.expose_function("__hf_send", lambda to, sats: wu.sendtoaddress(to, f"{int(sats) / 1e8:.8f}"))
        page.add_init_script(MOCK % (uaddr, uaddr))
        pub = pubkey_from_priv(page_key())
        page_launch = segwit_encode(hrp, 0, hash160(pub))
        page_script = launch.validateaddress(page_launch)["scriptPubKey"]
        page.goto(f"http://127.0.0.1:{site_port}/#/c/SPL", wait_until="domcontentloaded")
        page.click(".sides >> text=mine")
        page.wait_for_selector("#mineme", timeout=30000)
        check("the coin page offers to mine a block and shows the public stratum",
              f":{coin['pool']['stratum_port']}" in page.locator("pre.code").inner_text())
        got = None
        for _ in range(5):
            page.click("#mineme")
            wait(lambda: get("/coin/SPL")["pool"]["queue"] == 0, 300, "the page's block")
            try:
                got = wait(lambda: page.locator("#paydue").count() > 0, 90, "the pay button")
                break
            except TimeoutError:
                continue
        check("after its block is drawn the page shows what it owes and a pay button", bool(got), page.locator(".pad").first.inner_text()[:300])
        def pwait(pred, timeout, what):  # like wait, but lets the browser's events (the confirm dialog, the wallet call) run
            t0 = time.time()
            while time.time() - t0 < timeout:
                try:
                    v = pred()
                    if v:
                        return v
                except Exception:
                    pass
                page.wait_for_timeout(500)
            raise TimeoutError(what)
        page.click("#paydue")   # the page's key is empty: it asks to top up from the wallet (accepted), then says to pay again
        pwait(lambda: wu.listtransactions("*", 5) and any(t["category"] == "send" for t in wu.listtransactions("*", 5)), 60, "the top-up")
        wb.generatetoaddress(1, ba)
        page_due = [x for x in get(f"/coin/SPL/due?address={page_launch}") if x["pay"] > 0]
        pwait(lambda: page.locator("#paydue").count() > 0, 60, "pay button again")
        page.click("#paydue")
        pwait(lambda: len(btc.getrawmempool()) > 0, 60, "the page's payment in the mempool")
        wb.generatetoaddress(2, ba)
        ok = pwait(lambda: all(launch.getmintobligation(x["height"])["settled"] for x in page_due[:3]) or None, 240, "the page's blocks settled")
        check("the page paid its blocks' sats from its own key and they are settled", ok and page_due, page_due)
        check("the page's coins are in its address, spendable", any(
            launch.getblock(launch.getblockhash(x["height"]), 2)["tx"][0]["vout"][0]["scriptPubKey"]["hex"] == page_script
            and launch.getmintobligation(x["height"])["spendable"] for x in page_due))
        check("no page errors", not errors, errors[:3])
        browser.close()
        pw.stop()
    except BaseException:
        try:
            print('--- the site log, last lines'); print(''.join(open(os.path.join(w, 'web.log')).readlines()[-40:]))
        except OSError:
            pass
        raise
    finally:
        for p in procs:
            p.terminate()
        subprocess.run(hf + ["node", "down"], env=env, capture_output=True)
        for p in procs:
            try:
                p.wait(20)
            except Exception:
                p.kill()
        shutil.rmtree(w, ignore_errors=True)
    ok = all(v for _, v in RESULTS)
    print(f"sitepool: {sum(v for _, v in RESULTS)}/{len(RESULTS)} passed")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
