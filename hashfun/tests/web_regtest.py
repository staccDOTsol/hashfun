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
  P1 peer to peer, a second browser and no house maker: one holder posts a signed offer (coins for
     sats), the other takes half of it from the coin page's Book tab
  P2 coin for coin: a holder of a second chain's coin swaps it for the first, no Bitcoin involved
  P3 a bid in sats paid from the hashfun key, taken with coins
  P4 the maker's browser goes away after the taker locked: the taker's coins come back by themselves

Pictures: the first launch commits to a picture and a blurb (the site serves and shows them); the
launch form uploads one, the page shrinks it, and the new chain's launch id commits to the result.
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

from hashfun import book as BK
from hashfun import descriptor as D
from hashfun import meta as M
from hashfun.crypto import hash160, pubkey_from_priv, random_priv, sha256
from hashfun.ser import address_to_script, segwit_encode
from hashfun.settler import Settler
from hashfun.tests.e2e_regtest import RESULTS, check, free_port, open_wallet, COIN, DAY
from hashfun.tests.fleet_regtest import FNode, BtcTicker, Rig, wait, mine_gbt, FLOOR_BITS
from hashfun.tests.test_book import png

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


SIG2 = "H" + base64.b64encode(hashlib.sha256(b"hashfun web test wallet two").digest() * 2).decode()
PICTURE = png(16, 16)


def noise_png(w: int, h: int) -> bytes:
    """A picture far over the launch form's limit, and one that does not compress: the page has to
    crop it and step down in size and quality until it fits."""
    import struct
    import zlib

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    raw = b"".join(b"\x00" + os.urandom(3 * w) for _ in range(h))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + \
        chunk(b"IDAT", zlib.compress(raw, 1)) + chunk(b"IEND", b"")


def page_key(sig: str = SIG) -> int:
    """The key the page derives from the wallet's signature (btc.js keyFromSignature)."""
    k = sha256(b"hashfun-key-v1" + sig.encode())
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
    reg, btc, rig, rig2, ticker, browser, pw = Registry(), None, None, None, None, None, None
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
        wu2, ws2 = open_wallet(btc.rpc, "user2"), open_wallet(btc.rpc, "settle2")
        btc_addr = wb.getnewaddress("", "bech32")
        wb.generatetoaddress(110, btc_addr)
        user_addr, user2_addr = wu.getnewaddress("", "bech32"), wu2.getnewaddress("", "bech32")
        wb.sendtoaddress(user_addr, 2)
        wb.sendtoaddress(user2_addr, 2)
        wb.sendtoaddress(ws2.getnewaddress("", "bech32"), 5)
        wb.generatetoaddress(1, btc_addr)
        ticker = BtcTicker(wb, btc_addr, 2.0)
        ticker.start()
        bspk = lambda x: bytes.fromhex(wb.getaddressinfo(x)["scriptPubKey"])  # noqa: E731

        # ---- the launch: production mode, CPU-sized, never graduates during the test
        creator_spk = b"\x00\x14" + hash160(pubkey_from_priv(random_priv()))
        d = D.make("Rig Cat", "RIGCAT", creator_spk, 10**10, test=False, btc_regtest=True, pow_limit_bits=FLOOR_BITS,
                   target_spacing=2, lwma_window=15, genesis_time=int(time.time()) - 2 * DAY,
                   creator_btc_script=bspk(wb.getnewaddress("", "bech32")), _validate=False,
                   metadata=M.from_image(PICTURE, description="The cat that mines.\nSecond line.", x="https://x.com/rigcat"))
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
        # Two chains are mined here on two cores: each rig takes half a core (difficulty follows).
        rig = Rig(loop, Handle(rpc), d, payout, wb.getnewaddress("", "bech32"), settler, duty=0.5)
        rig.start()

        # ---- a second launch, mined from the start, so that two different coins exist to swap
        d2 = D.make("Moon Dog", "MOON", b"\x00\x14" + hash160(pubkey_from_priv(random_priv())), 10**10, test=False,
                    btc_regtest=True, pow_limit_bits=FLOOR_BITS, target_spacing=2, lwma_window=15,
                    genesis_time=int(time.time()) - 2 * DAY, creator_btc_script=bspk(wb.getnewaddress("", "bech32")), _validate=False)
        d2.sats_num, d2.sats_shift = 1, 2
        D.validate(d2)
        d2.grind_genesis()
        path2 = os.path.join(work, "moon.json")
        with open(path2, "w") as f:
            f.write(d2.dumps())
        reg.add(path2)
        reg.up("MOON", ["-minewithoutpeers", *local])
        rpc2 = reg.rpc("MOON")
        w2 = open_wallet(rpc2)
        settler2 = Settler(rpc2, ws2, os.path.join(work, "settler2.json"), max_pay_sats=COIN)
        rig2 = Rig(loop, Handle(rpc2), d2, w2.getnewaddress("", "bech32"), ws2.getnewaddress("", "bech32"), settler2, duty=0.5)
        rig2.start()

        # ---- maker + site
        cfg = {"btc": {"wallet": "w", "hrp": "bcrt"},
               "defaults": {"hashprice_sats_per_th": 2.5e11, "spread": 0.03, "btc_confs": 1, "fork_confs": 2,
                            "init_lock_seconds": 7200, "part_lock_seconds": 1800, "lock_margin_seconds": 3600,
                            "instant_max_sats": 100_000, "safety": 1e6, "quote_ttl": 600}}
        with open(os.path.join(work, "maker.json"), "w") as f:
            json.dump(cfg, f)
        maker = build_maker(os.path.join(work, "maker.json"), reg, btc.rpc)
        maker.forks.pop("MOON", None)  # the house maker trades the first coin only; MOON moves peer to peer
        site = Site(btc.rpc, reg, maker, allow_launch=True, launch_args=local, book_path=os.path.join(work, "book.json"),
                    book_confs=2, book_lock=240, book_min_lock=20)
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
        board_of = lambda t: next(c for c in get("/board") if c["ticker"] == t)  # noqa: E731
        loaded = "(sel) => { const i = [...document.querySelectorAll(sel)]; return i.length > 0 && i.every((x) => x.complete && x.naturalWidth > 0); }"

        # ================================================================= W1
        print("-- W1 board", flush=True)
        page.goto(url, wait_until="domcontentloaded")
        ok = wait(lambda: page.locator("a.card", has_text="$RIGCAT").count() >= 1, 60, "card on the board")
        check("W1 the board lists the launch", ok)
        h1 = board_of("RIGCAT")["height"]
        ok = wait(lambda: board_of("RIGCAT")["height"] > h1 and page.locator("a.card.hot").count() >= 0, 30, "board height moves")
        check("W1 the board follows the chain", ok and "gets its own" in page.locator("h1").inner_text().lower())
        ok = wait(lambda: page.evaluate(loaded, "a.card img.tile.pic"), 30, "the launch's picture on its card")
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{board_of('RIGCAT')['image']}", timeout=30) as r:
            served, ctype, cache = r.read(), r.headers["Content-Type"], r.headers["Cache-Control"]
        check("W1 the board shows the launch's picture: the committed bytes, typed and cacheable forever",
              ok and served == PICTURE and ctype == "image/png" and "immutable" in cache
              and board_of("RIGCAT")["meta"] == d.meta.hex() and "image" not in board_of("MOON"), f"{ctype} {cache} {len(served)}")

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
        blurb = page.locator("#blurb").inner_text() if page.locator("#blurb").count() else ""
        check("W3 the coin page shows the committed picture, blurb and link",
              page.evaluate(loaded, "img.tile.pic.big") and "The cat that mines." in blurb and "Second line." in blurb
              and page.locator("a.ghost[href='https://x.com/rigcat']").count() == 1, blurb[:80])

        # ================================================================= W4
        print("-- W4 launch form", flush=True)
        page.goto(url + "#/launch", wait_until="domcontentloaded")
        page.fill("#name", "Toaster Miner")
        page.fill("#ticker", "toast")
        meme = os.path.join(work, "meme.png")
        with open(meme, "wb") as f:
            f.write(noise_png(640, 480))  # about 900 KB of noise
        page.set_input_files("#pic", meme)
        ok_pic = wait(lambda: page.locator("label.drop.has img").count() == 1, 60, "the page shrinks the picture")
        page.fill("#desc", "Burns bread, mines blocks.")
        page.fill("input[aria-label='X link']", "https://x.com/toastminer")
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
        tm = None
        try:
            tm = M.check(reg.desc("TOAST"))
        except M.MetaError as e:
            print(f"   {e}", flush=True)
        check("W4 the launch id commits to the picture the page made (cropped, re-encoded, under 48 KB) and to the blurb",
              ok_pic and tm is not None and info.get("descriptor", {}).get("meta") == tm.hash().hex()
              and tm.image_type in ("image/webp", "image/jpeg") and 0 < len(tm.image) <= 48000
              and tm.description == "Burns bread, mines blocks." and tm.x == "https://x.com/toastminer",
              f"{tm and tm.image_type} {tm and len(tm.image)}")
        check("W4 the new coin's page shows that picture",
              wait(lambda: page.evaluate(loaded, "img.tile.pic.big"), 30, "picture on the coin page")
              and "Burns bread" in page.locator("#blurb").inner_text())
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

        # ================================================================= P1
        print("-- P1 peer to peer: coins for sats, a second browser, no house maker", flush=True)
        house = len(maker.orders)
        key2 = page_key(SIG2)
        pub2 = pubkey_from_priv(key2)
        ctx2 = browser.new_context(viewport={"width": 1440, "height": 1000})
        page2 = ctx2.new_page()
        page2.on("pageerror", lambda e: errors.append(f"pageerror(2): {e}"))
        page2.on("console", lambda m: errors.append(f"console(2): {m.text}")
                 if m.type == "error" and "Failed to load resource" not in m.text else None)
        sent2 = []

        def send2(to, amount):
            txid = wu2.sendtoaddress(to, f"{int(amount) / COIN:.8f}")
            sent2.append((to, int(amount), txid))
            return txid
        page2.expose_function("__hf_sign", lambda m: SIG2)
        page2.expose_function("__hf_send", send2)
        page2.add_init_script(MOCK % (user2_addr, user2_addr))
        page2.goto(url, wait_until="domcontentloaded")
        page2.click("#wallet")
        wait(lambda: page2.locator("#wallet").inner_text().startswith(user2_addr[:6]), 20, "second wallet shown")
        cat2, my2_btc = segwit_encode(d.hrp, 0, hash160(pub2)), segwit_encode("bcrt", 0, hash160(pub2))
        moon1, moon2 = segwit_encode(d2.hrp, 0, hash160(pub)), segwit_encode(d2.hrp, 0, hash160(pub2))
        bal_of = lambda t, addr: get(f"/coin/{t}/address/{addr}")["balance"]  # noqa: E731
        sats_of = lambda wallet: int(round(sum(wallet.getbalances()["mine"].values()) * COIN))  # noqa: E731
        recs_of = lambda pg: pg.evaluate("Object.values(JSON.parse(localStorage.getItem('hf_p2p') || '{}'))")  # noqa: E731
        flow_text = lambda pg: pg.locator(".flow").inner_text()[:300] if pg.locator(".flow").count() else "no flow window"  # noqa: E731

        def post(pg, give_text, want_text, listed, what):
            """Fill the offer form and post; the page's view of its own balance can be a poll behind."""
            for _ in range(4):
                pg.fill("#po-give", give_text)
                pg.fill("#po-want", want_text)
                wait(lambda: pg.locator("#po-go").is_enabled(), 10, "post enabled")
                pg.click("#po-go")
                if wait(listed, 8, what):
                    return True
                print("   the page said: " + (pg.locator("#po-err").inner_text() if pg.locator("#po-err").count() else "(nothing)"), flush=True)
            return False

        # user 1 offers 40% of its bag for 60,000 sats
        page.goto(url + "#/swap/RIGCAT/btc", wait_until="domcontentloaded")
        page.wait_for_selector("#po-give")
        give = round(bal_of("RIGCAT", my_launch) / COIN * 0.4, 2)
        ok = post(page, str(give), "60000", lambda: len(get("/book")["orders"]) == 1, "the offer is listed")
        o = (get("/book")["orders"] or [{}])[0]
        check("P1 an offer signed in the page is listed: live, backed by the maker's coins, checkable by any taker",
              ok and o.get("maker") == pub.hex() and (o["give_ticker"], o["get_ticker"], o["get_amount"]) == ("RIGCAT", "BTC", 60_000)
              and o["give_amount"] == round(give * COIN) and BK.verify(o["maker"], BK.order_text(o), o["sig"]), json.dumps(o)[:240])
        # user 2 finds it on the coin page's Book tab and takes half
        page2.goto(url + "#/c/RIGCAT", wait_until="domcontentloaded")
        page2.wait_for_selector("#tab-book")
        page2.click("#tab-book")
        ok = wait(lambda: page2.locator("#book a[data-order]").count() == 1, 30, "the offer on the Book tab")
        shot(page2, "book")
        page2.click("#book a[data-order]")
        page2.wait_for_selector("#sw-amt")
        page2.fill("#sw-amt", "30000")
        ok = ok and wait(lambda: page2.locator("#sw-go").is_enabled() and "$RIGCAT" in page2.locator("#sw-get").inner_text(), 15, "take form")
        shot(page2, "swap")
        wu_before, t_swap = sats_of(wu), time.time()
        page2.click("#sw-go")
        ok2 = wait(lambda: page2.locator(".flow.done").count() == 1, 240, "peer-to-peer swap done")
        check("P1 the Book tab leads to the offer and a partial take completes in the second browser", ok and ok2,
              "" if ok2 else flow_text(page2) + " | " + json.dumps(recs_of(page2))[:300])
        print(f"   swapped in {time.time() - t_swap:.0f}s", flush=True)
        shot(page2, "swapped")
        expect = o.get("give_amount", 0) * 30_000 // 60_000
        wait(lambda: bal_of("RIGCAT", cat2) > 0, 30, "the taker's claim confirms")
        got = bal_of("RIGCAT", cat2)
        check("P1 the taker holds the coins at its own key: its share of the offer, less the claim fee",
              0 < expect - got <= 2000, f"{got} vs {expect}")
        check("P1 the taker's wallet paid 30,000 sats into a swap contract and nothing else",
              len(sent2) == 1 and sent2[0][1] == 30_000 and len(sent2[0][0]) == 64, str(sent2))
        ok = wait(lambda: sats_of(wu) > wu_before + 20_000 and all(f["state"] == "done" for f in list(site.book.fills.values())), 90,
                  "the maker's sats arrive")
        rest = (get("/book")["orders"] or [{}])[0]
        check("P1 the maker's page locked by itself, then claimed the sats to its wallet; the rest of the offer stays up",
              ok and rest.get("remaining_get") == 30_000 and rest.get("remaining") == o["give_amount"] - expect
              and [f["state"] for f in list(site.book.fills.values())] == ["done"],
              f"{sats_of(wu) - wu_before} sats, {[f['state'] for f in list(site.book.fills.values())]}, {json.dumps(rest)[:120]}")
        check("P1 the house maker took no part", len(maker.orders) == house)
        if page2.locator(".flow").count():
            page2.click(".flow >> text=Close")

        # ================================================================= P2
        print("-- P2 coin for coin", flush=True)
        wait(lambda: w2.getbalances()["mine"]["trusted"] >= 20, 600, "MOON matured and settled at its rig")
        w2.sendtoaddress(moon2, 12)
        ok = wait(lambda: bal_of("MOON", moon2) == 12 * COIN
                  and all(u["spendable"] for u in get(f"/coin/MOON/address/{moon2}")["utxos"]), 60, "user 2 holds MOON")
        page2.goto(url + "#/swap/MOON/RIGCAT", wait_until="domcontentloaded")
        page2.wait_for_selector("#po-give")
        ok = ok and post(page2, "5", "3", lambda: any(x["give_ticker"] == "MOON" for x in get("/book")["orders"]), "the MOON offer is listed")
        page.goto(url + "#/swap/RIGCAT/MOON", wait_until="domcontentloaded")
        ok = ok and wait(lambda: page.locator("#sw-go").count() == 1 and page.locator("#sw-go").is_enabled(), 30, "the MOON offer on user 1's page")
        cat1_before, cat2_before, n1, n2 = bal_of("RIGCAT", my_launch), bal_of("RIGCAT", cat2), len(sent), len(sent2)
        t_swap = time.time()
        page.click("#sw-go")
        ok2 = wait(lambda: page.locator(".flow.done").count() == 1, 240, "coin for coin done")
        check("P2 a coin swaps for another chain's coin, page to page", ok and ok2,
              "" if ok2 else flow_text(page) + " | " + json.dumps(recs_of(page))[:300])
        print(f"   swapped in {time.time() - t_swap:.0f}s", flush=True)
        wait(lambda: bal_of("MOON", moon1) > 0 and bal_of("RIGCAT", cat2) > cat2_before, 90, "both claims confirm")
        m1, c2, c1 = bal_of("MOON", moon1), bal_of("RIGCAT", cat2), bal_of("RIGCAT", my_launch)
        check("P2 each side now holds the other chain's coin at its own key",
              0 < 5 * COIN - m1 <= 2000 and 0 < cat2_before + 3 * COIN - c2 <= 2000 and 0 < cat1_before - 3 * COIN - c1 <= 2000,
              f"MOON {m1}, RIGCAT {c2 - cat2_before}, paid {cat1_before - c1}")
        check("P2 no Bitcoin moved and the house maker took no part",
              (len(sent), len(sent2)) == (n1, n2) and len(maker.orders) == house, f"{len(sent)} {len(sent2)}")
        if page.locator(".flow").count():
            page.click(".flow >> text=Close")

        # ================================================================= P3
        print("-- P3 a bid in sats from the hashfun key", flush=True)
        page2.on("dialog", lambda dlg: dlg.accept("150000"))
        page2.goto(url + "#/swap/btc/RIGCAT", wait_until="domcontentloaded")
        page2.wait_for_selector("#po-give")
        page2.click("text=Deposit from UniSat")
        ok = wait(lambda: len(sent2) == n2 + 1 and sent2[-1][0] == my2_btc
                  and any(u["confirmations"] > 0 for u in get(f"/chain/btc/address/{my2_btc}")["utxos"]), 60, "the deposit confirms at the hashfun key")
        ok = ok and post(page2, "100000", "4", lambda: any(x["give_ticker"] == "BTC" for x in get("/book")["orders"]), "the bid is listed")
        # the same sats cannot be promised twice: 150,000 at the key, 100,000 already offered
        page2.fill("#po-give", "100000")
        page2.fill("#po-want", "4")
        page2.click("#po-go")
        twice = wait(lambda: page2.locator("#po-err").count() == 1 and "other open offers" in page2.locator("#po-err").inner_text(), 15, "second bid refused")
        check("P3 the page refuses to offer the same sats twice", twice and sum(x["give_ticker"] == "BTC" for x in get("/book")["orders"]) == 1)
        page.goto(url + "#/swap/RIGCAT/btc", wait_until="domcontentloaded")
        ok = ok and wait(lambda: page.locator("#sw-go").count() == 1 and page.locator("#sw-go").is_enabled(), 30, "the bid on user 1's page")
        wu_before, cat2_before = sats_of(wu), bal_of("RIGCAT", cat2)
        page.click("#sw-go")
        ok2 = wait(lambda: page.locator(".flow.done").count() == 1, 240, "bid taken")
        check("P3 a bid funded from the bidder's hashfun key on Bitcoin is taken with coins", ok and ok2,
              "" if ok2 else flow_text(page) + " | " + json.dumps(recs_of(page))[:300])
        ok = wait(lambda: sats_of(wu) > wu_before + 80_000 and bal_of("RIGCAT", cat2) > cat2_before, 90, "both claims")
        check("P3 the seller's sats land at its wallet address and the bidder's coins at its key",
              ok and 0 < cat2_before + 4 * COIN - bal_of("RIGCAT", cat2) <= 2000 and len(maker.orders) == house,
              f"{sats_of(wu) - wu_before} sats, {bal_of('RIGCAT', cat2) - cat2_before} units")
        if page.locator(".flow").count():
            page.click(".flow >> text=Close")

        # ================================================================= P4
        print("-- P4 the maker disappears after the taker locked", flush=True)
        site.book_lock, site.book_confs = 40, 6  # a lock short enough to see its refund; pages read this at load
        page2.reload(wait_until="domcontentloaded")
        page2.goto(url + "#/swap/MOON/RIGCAT", wait_until="domcontentloaded")
        page2.wait_for_selector("#po-give")
        ok = post(page2, "2", "1", lambda: any(x["lock"] == 40 for x in get("/book")["orders"]), "the short-lock offer is listed")
        short = next((x for x in get("/book")["orders"] if x["lock"] == 40), {"id": "none"})
        page.goto(url + "#/swap/RIGCAT/MOON", wait_until="domcontentloaded")
        sel = f"button.offer[data-order='{short['id']}']"
        ok = ok and wait(lambda: page.locator(sel).count() == 1, 30, "the offer on user 1's page")
        page.click(sel)
        wait(lambda: page.locator("#sw-go").is_enabled(), 10, "take enabled")
        cat1_before, moon1_before = bal_of("RIGCAT", my_launch), bal_of("MOON", moon1)
        t_take = time.time()
        page.click("#sw-go")
        ok = ok and wait(lambda: any(f["order"] == short["id"] and f["state"] == "taker_locked" for f in list(site.book.fills.values())), 60,
                         "the taker locked")
        ctx2.close()  # the maker's browser is gone before its page locked anything
        locked = wait(lambda: bal_of("RIGCAT", my_launch) <= cat1_before - COIN, 30, "the taker's lock confirms")
        check("P4 the taker's coins sit in the contract while the maker is gone", ok and locked)
        ok = wait(lambda: any(r["state"] == "refunded" for r in recs_of(page)), 300, "the taker's page refunds itself")
        print(f"   refunded {time.time() - t_take:.0f}s after the take (lock 40 s, so the taker's timelock is 100 s)", flush=True)
        wait(lambda: bal_of("RIGCAT", my_launch) > cat1_before - 5000, 60, "the refund confirms")
        back = bal_of("RIGCAT", my_launch)
        check("P4 after the timelock the taker's page takes its coins back by itself: only fees are gone",
              ok and 0 < cat1_before - back <= 5000 and bal_of("MOON", moon1) == moon1_before
              and not any(f["order"] == short["id"] and f["state"] in ("maker_locked", "claimed", "done") for f in list(site.book.fills.values())),
              f"lost {cat1_before - back}; {[r['state'] for r in recs_of(page)]}")
        if page.locator(".flow").count():
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
                   (lambda: rig.stop()) if rig else None, (lambda: rig2.stop()) if rig2 else None,
                   (lambda: ticker.halt.set()) if ticker else None):
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
