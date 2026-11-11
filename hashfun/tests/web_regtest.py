"""Browser end to end: the real site (`hashfun web`), real hashfund nodes, a real pool with its
settler, a real swap maker and stock bitcoind (regtest), driven through Chromium with Playwright.
The only stand-in is the wallet: a mock `window.unisat` whose sendBitcoin pays from a regtest
wallet and whose signMessage returns a fixed signature (the UniSat extension cannot run here).

  python -m hashfun.tests.web_regtest --hashfund build/bin/hashfund --bitcoind /path/to/bitcoind [--shots DIR]

  W1 board lists the launch, live
  W2 connect: the page derives its key from the wallet signature; no key leaves the browser
  W3 coin page follows the chain: blocks, payouts, price
  W4 the launch form creates a new chain; it shows up at block 0 and takes a mined block
  W5 buy in the browser: BTC to coins by atomic swap, filled on the unconfirmed lock (instant)
  W6 a bigger buy (waits for a Bitcoin confirmation), bag and odds on the page
  W7 hold to earn: a later block pays the buyer's key on Bitcoin; Bags shows it; sweep to the wallet
  W8 sell in the browser: coins to BTC by atomic swap, paid to the wallet address
"""
import argparse
import asyncio
import base64
import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import traceback
import urllib.request

from hashfun import descriptor as D
from hashfun.crypto import hash160, pubkey_from_priv, random_priv, sha256
from hashfun.ser import address_to_script, segwit_encode
from hashfun.settler import Settler
from hashfun.tests.e2e_regtest import RESULTS, check, free_port, open_wallet, COIN, DAY
from hashfun.tests.fleet_regtest import FNode, BtcTicker, Rig, wait, mine_gbt, FLOOR_BITS

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SIG = "H" + base64.b64encode(hashlib.sha256(b"hashfun web test wallet").digest() * 2).decode()
MOCK = """(() => { window.unisat = {  // like the extension, it remembers that this site was connected
  requestAccounts: async () => { localStorage.setItem('mock_on', '1'); return ['%s']; },
  getAccounts: async () => (localStorage.getItem('mock_on') ? ['%s'] : []),
  signMessage: async (m) => window.__hf_sign(m), sendBitcoin: async (to, sats) => window.__hf_send(to, sats),
  getNetwork: async () => 'regtest' }; })();"""


class Handle:
    def __init__(self, rpc):
        self.rpc = rpc


def page_key() -> int:
    """The key the page derives from SIG (btc.js keyFromSignature)."""
    k = sha256(b"hashfun-key-v1" + SIG.encode())
    while not 1 <= int.from_bytes(k, "big") < N:
        k = sha256(k)
    return int.from_bytes(k, "big")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hashfund", required=True)
    ap.add_argument("--bitcoind", required=True)
    ap.add_argument("--workdir")
    ap.add_argument("--shots", help="save screenshots here")
    a = ap.parse_args()
    work = os.path.abspath(a.workdir) if a.workdir else tempfile.mkdtemp(prefix="hashfun-web-")
    os.makedirs(work, exist_ok=True)
    os.environ["HASHFUN_HOME"] = os.path.join(work, "home")
    os.environ["HASHFUND"] = os.path.abspath(a.hashfund)
    from hashfun.cli import Registry
    from hashfun.web import Site, serve, build_maker
    print(f"workdir {work}", flush=True)
    t0 = time.time()
    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True).start()
    reg, btc, rig, ticker, browser, pw = Registry(), None, None, None, None, None
    errors = []

    def get(path):
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api{path}", timeout=60) as r:
            return json.loads(r.read())

    def shot(page, name):
        if a.shots:
            os.makedirs(a.shots, exist_ok=True)
            page.screenshot(path=os.path.join(a.shots, name + ".png"), full_page=True)

    try:
        # ---- Bitcoin, wallets
        btc = FNode(a.bitcoind, os.path.join(work, "btc"), ["-regtest", "-listen=0"], free_port(), "btc")
        wb, wu = open_wallet(btc.rpc), open_wallet(btc.rpc, "user")
        btc_addr = wb.getnewaddress("", "bech32")
        wb.generatetoaddress(110, btc_addr)
        user_addr = wu.getnewaddress("", "bech32")
        wb.sendtoaddress(user_addr, 2)
        wb.generatetoaddress(1, btc_addr)
        ticker = BtcTicker(wb, btc_addr, 2.0)
        ticker.start()
        bspk = lambda x: bytes.fromhex(wb.getaddressinfo(x)["scriptPubKey"])  # noqa: E731

        # ---- the launch: production mode, CPU-sized, never graduates during the test
        creator_spk = b"\x00\x14" + hash160(pubkey_from_priv(random_priv()))
        d = D.make("Rig Cat", "RIGCAT", creator_spk, 10**10, test=False, btc_regtest=True, pow_limit_bits=FLOOR_BITS,
                   target_spacing=2, lwma_window=15, genesis_time=int(time.time()) - 2 * DAY,
                   creator_btc_script=bspk(wb.getnewaddress("", "bech32")), _validate=False)
        d.sats_num, d.sats_shift = 1, 2
        D.validate(d)
        d.grind_genesis()
        path = os.path.join(work, "rigcat.json")
        with open(path, "w") as f:
            f.write(d.dumps())
        local = ["-listen=0", "-fallbackfee=0.0001"]
        reg.add(path)
        reg.up("RIGCAT", ["-minewithoutpeers", *local])
        rpc = reg.rpc("RIGCAT")
        w = open_wallet(rpc)
        payout = w.getnewaddress("", "bech32")
        settler = Settler(rpc, wb, os.path.join(work, "settler.json"), max_pay_sats=COIN)
        rig = Rig(loop, Handle(rpc), d, payout, wb.getnewaddress("", "bech32"), settler)
        rig.start()

        # ---- maker + site
        cfg = {"btc": {"wallet": "w", "hrp": "bcrt"},
               "defaults": {"hashprice_sats_per_th": 2.5e11, "spread": 0.03, "btc_confs": 1, "fork_confs": 2,
                            "init_lock_seconds": 7200, "part_lock_seconds": 1800, "lock_margin_seconds": 3600,
                            "instant_max_sats": 100_000, "safety": 1e6, "quote_ttl": 600}}
        with open(os.path.join(work, "maker.json"), "w") as f:
            json.dump(cfg, f)
        maker = build_maker(os.path.join(work, "maker.json"), reg, btc.rpc)
        site = Site(btc.rpc, reg, maker, allow_launch=True, launch_args=local)
        port = free_port()
        serve(site, "127.0.0.1", port)
        url = f"http://127.0.0.1:{port}/"

        # ---- browser with a mock UniSat backed by the "user" regtest wallet
        from playwright.sync_api import sync_playwright
        pw = sync_playwright().start()
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1440, "height": 1000})
        page = ctx.new_page()
        page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
        page.on("console", lambda m: errors.append(f"console: {m.text}")
                if m.type == "error" and "Failed to load resource" not in m.text else None)  # polled 404s are expected
        sent = []

        def send(to, amount):
            txid = wu.sendtoaddress(to, f"{int(amount) / COIN:.8f}")
            sent.append((to, int(amount), txid))
            return txid
        page.expose_function("__hf_sign", lambda m: SIG)
        page.expose_function("__hf_send", send)
        page.add_init_script(MOCK % (user_addr, user_addr))
        key = page_key()
        pub = pubkey_from_priv(key)
        my_launch = segwit_encode(d.hrp, 0, hash160(pub))
        my_btc = segwit_encode("bcrt", 0, hash160(pub))

        # ================================================================= W1
        print("-- W1 board", flush=True)
        page.goto(url, wait_until="domcontentloaded")
        ok = wait(lambda: page.locator("a.card", has_text="$RIGCAT").count() >= 1, 60, "card on the board")
        check("W1 the board lists the launch", ok)
        h1 = get("/board")[0]["height"]
        ok = wait(lambda: get("/board")[0]["height"] > h1 and page.locator("a.card.hot").count() >= 0, 30, "board height moves")
        check("W1 the board follows the chain", ok and "gets its own" in page.locator("h1").inner_text().lower())

        # ================================================================= W2
        print("-- W2 connect", flush=True)
        page.click("#wallet")
        ok = wait(lambda: page.locator("#wallet").inner_text().startswith(user_addr[:6]), 20, "wallet shown")
        stored = page.evaluate(f"localStorage.getItem('hf_key_{user_addr}')")
        check("W2 connect derives the page key from the wallet signature", ok and stored == f"{key:064x}", str(stored)[:16])

        # ================================================================= W3
        print("-- W3 coin page", flush=True)
        page.goto(url + "#/c/RIGCAT", wait_until="domcontentloaded")
        ok = wait(lambda: page.locator(".tr:not(.head)").count() >= 5, 60, "block rows")
        check("W3 the coin page lists blocks as they arrive", ok)
        ok = wait(lambda: page.locator(".tr b.l", has_text="sats").count() >= 1, 180, "a settled holder payout row")
        check("W3 settled BTC payouts to holders show up on the page", ok)
        check("W3 the maker's price is on the page", wait(lambda: page.locator("#price").inner_text() not in ("", "0"), 30, "price"),
              page.locator("#price").inner_text())

        # ================================================================= W4
        print("-- W4 launch form", flush=True)
        page.goto(url + "#/launch", wait_until="domcontentloaded")
        page.fill("#name", "Toaster Miner")
        page.fill("#ticker", "toast")
        shot(page, "launch")
        page.click("#launch-go")
        ok = wait(lambda: page.evaluate("location.hash") == "#/c/TOAST" and "TOASTER MINER" in page.locator("h1").inner_text().upper(),
                  120, "the new coin's page")
        check("W4 the launch form creates a chain and opens its page", ok, page.evaluate("location.hash"))
        toy = reg.rpc("TOAST")
        info = toy.getlaunchinfo() if toy else {}
        check("W4 the new chain is production-mode, anchored, with the creator's scripts from the page",
              bool(toy) and info["height"] == 0 and info["descriptor"]["test"] is False
              and info["descriptor"]["creator_script"] == (b"\x00\x14" + hash160(pub)).hex()
              and info["descriptor"]["creator_btc_script"] == address_to_script(user_addr, "bcrt").hex(), json.dumps(info)[:200])
        if toy:
            mine_gbt(Handle(toy), b"\x00\x14" + hash160(pub))
            check("W4 a block mined on it shows on the board",
                  wait(lambda: any(c["ticker"] == "TOAST" and c.get("height") == 1 for c in get("/board")), 30, "TOAST at 1"))

        # ================================================================= W5
        print("-- W5 buy (instant)", flush=True)
        def can_quote():
            try:
                return get("/quote?ticker=RIGCAT&side=buy&sats=50000")["amount"] > 0
            except Exception:
                return False
        wait(can_quote, 600, "maker inventory (first coinbases matured and settled)")
        print(f"   maker holds {w.getbalances()['mine']['trusted']} RIGCAT at block {rpc.getblockcount()} (+{time.time() - t0:.0f}s)", flush=True)
        page.goto(url + "#/c/RIGCAT", wait_until="domcontentloaded")
        page.wait_for_selector("#go")
        page.click("button.ghost:has-text('50k')")
        ok = wait(lambda: page.locator("#q-get").inner_text() != "…" and page.locator("#go").is_enabled(), 30, "quote")
        check("W5 the page gets a quote and offers an instant fill", ok and page.locator(".kv b.l", has_text="instant").count() == 1)
        page.click("#go")
        ok = wait(lambda: page.locator(".flow.done").count() == 1, 180, "swap done")
        note = page.locator(".flow").inner_text()[:300] if not ok else ""
        check("W5 the buy completes in the browser", ok, note)
        shot(page, "bought")
        wait(lambda: get(f"/coin/RIGCAT/address/{my_launch}")["balance"] > 0, 30, "the claim confirms")
        bal = get(f"/coin/RIGCAT/address/{my_launch}")["balance"]
        check("W5 the coins are at the page's own key on the launch chain", bal > 0 and len(sent) == 1, f"{bal}")
        check("W5 the wallet paid exactly the quoted sats into a swap contract, not to the site",
              len(sent) == 1 and sent[0][0].startswith("bcrt1q") and len(sent[0][0]) == 64 and sent[0][1] <= 50_000, str(sent[:1]))
        page.click(".flow >> text=Close")

        # ================================================================= W6
        print("-- W6 bigger buy", flush=True)
        wait(lambda: rpc.getblockcount() >= 150, 600, "more inventory")
        inv = int(w.getbalances()["mine"]["trusted"] * COIN)
        q1 = get("/quote?ticker=RIGCAT&side=buy&sats=50000")
        spend = int(inv * 0.8) * q1["price"] // COIN
        page.reload(wait_until="domcontentloaded")
        page.wait_for_selector("#amt")
        page.fill("#amt", str(spend))
        ok = wait(lambda: page.locator("#go").is_enabled() and page.locator(".kv", has_text="1 Bitcoin confirmation").count() >= 1, 30, "quote")
        check("W6 above the instant cap the page says a Bitcoin confirmation is needed", ok, f"spend {spend}")
        page.click("#go")
        ok = wait(lambda: page.locator(".flow.done").count() == 1, 240, "big swap done")
        check("W6 a buy above the instant cap completes after a Bitcoin confirmation", ok,
              page.locator(".flow").inner_text()[:300] if not ok else "")
        page.click(".flow >> text=Close")
        wait(lambda: get(f"/coin/RIGCAT/address/{my_launch}")["balance"] > bal, 30, "the second claim confirms")
        me = get(f"/coin/RIGCAT/address/{my_launch}")
        share = me["balance"] / me["earning_supply"]
        ok = wait(lambda: page.locator("#odds").count() == 1 and page.locator("#odds").inner_text().lower().startswith("1 in"), 30, "odds")
        check("W6 the page shows the bag and its odds per block", ok and me["balance"] > bal, f"share {share:.3f}")
        print(f"   bag {me['balance'] / COIN:.2f} RIGCAT = {share * 100:.1f}% of the earning supply", flush=True)
        shot(page, "coin")

        # ================================================================= W7
        print("-- W7 hold to earn, sweep", flush=True)
        ok = wait(lambda: get(f"/chain/btc/address/{my_btc}")["balance"] > 0, 420, "a block pays the page's key on Bitcoin")
        won = get(f"/chain/btc/address/{my_btc}")
        check("W7 holding earned real BTC: a later block's draw paid the page's key on Bitcoin", ok, f"share {share:.3f}")
        page.goto(url + "#/bags", wait_until="domcontentloaded")
        ok = wait(lambda: page.locator("#yield").inner_text().replace(",", "").isdigit()
                  and int(page.locator("#yield").inner_text().replace(",", "")) >= 10_000, 60, "yield on Bags")
        check("W7 Bags shows the sats won", ok, page.locator("#yield").inner_text())
        shot(page, "bags")
        wait(lambda: any(u["confirmations"] > 0 for u in get(f"/chain/btc/address/{my_btc}")["utxos"]), 30, "payout confirmed")
        page.reload(wait_until="domcontentloaded")
        wait(lambda: page.locator("#sweep").is_enabled(), 30, "sweep enabled")
        before = wu.getbalances()["mine"]
        page.click("#sweep")
        ok = wait(lambda: sum(wu.getbalances()["mine"].values()) > sum(before.values()), 60, "sweep arrives")
        check("W7 sweeping moves the payouts to the wallet address", ok and won["balance"] > 0, json.dumps(won)[:200])

        # ================================================================= W8
        print("-- W8 sell", flush=True)
        page.goto(url + "#/c/RIGCAT", wait_until="domcontentloaded")
        page.wait_for_selector("#go")
        page.click(".sides >> text=sell")
        page.wait_for_selector("#amt")
        amount = round(me["balance"] / COIN * 0.25, 2)
        page.fill("#amt", str(amount))
        ok = wait(lambda: page.locator("#go").is_enabled() and page.locator("#q-get").inner_text() not in ("…", "0"), 30, "sell quote")
        before = sum(wu.getbalances()["mine"].values())
        page.click("#go")
        ok = wait(lambda: page.locator(".flow.done").count() == 1, 240, "sell done")
        check("W8 the sell completes in the browser", ok, page.locator(".flow").inner_text()[:300] if not ok else "")
        shot(page, "sold")
        ok = wait(lambda: sum(wu.getbalances()["mine"].values()) > before, 60, "sale proceeds arrive")
        left = get(f"/coin/RIGCAT/address/{my_launch}")["balance"]
        check("W8 the BTC lands at the wallet address and the bag shrank", ok and left < me["balance"], f"{left} < {me['balance']}")

        # ---- the rest of the site, for the record
        page.click(".flow >> text=Close")
        page.goto(url, wait_until="domcontentloaded")
        wait(lambda: page.locator(".feed b.l").count() >= 1, 30, "payout feed")
        shot(page, "board")
        phone = browser.new_context(viewport={"width": 390, "height": 844})
        pp = phone.new_page()
        pp.add_init_script(MOCK % (user_addr, user_addr))
        pp.goto(url + "#/c/RIGCAT", wait_until="domcontentloaded")
        ok = wait(lambda: pp.locator(".tr:not(.head)").count() >= 5, 30, "phone coin page")
        wide = pp.evaluate("document.documentElement.scrollWidth")
        check("W9 the coin page fits a phone without sideways scrolling", ok and wide <= 392, f"scrollWidth {wide}")
        shot(pp, "phone")
        orders = {o.state for o in maker.orders.values()}
        wait(lambda: all(o.state == "done" for o in maker.orders.values()), 60, "maker settles its side")
        check("W9 the maker redeemed its side of every swap", {o.state for o in maker.orders.values()} == {"done"}, str(orders))
        check("W9 no JavaScript errors on any page", not errors, "; ".join(errors)[:400])
    except Exception as ex:
        traceback.print_exc()
        check("web run completed", False, repr(ex))
    finally:
        for fn in ((lambda: browser.close()) if browser else None, (lambda: pw.stop()) if pw else None,
                   (lambda: rig.stop()) if rig else None, (lambda: ticker.halt.set()) if ticker else None):
            if fn:
                try:
                    fn()
                except Exception:
                    pass
        for t in list(reg.data):
            try:
                reg.down(t)
            except BaseException:
                pass
        if btc:
            btc.stop()
        failed = [n for n, ok in RESULTS.items() if not ok]
        print(f"\nweb: {len(RESULTS) - len(failed)}/{len(RESULTS)} passed in {time.time() - t0:.0f}s"
              + (f"; failed: {failed}" if failed else ""), flush=True)
        if not a.workdir and not failed:
            shutil.rmtree(work, ignore_errors=True)
        os._exit(1 if failed else 0)


if __name__ == "__main__":
    main()
