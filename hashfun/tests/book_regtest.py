"""The peer-to-peer swap engine at its real settings, against real nodes, on a clock the test moves.

web_regtest runs the engine in browsers with 40 s to 4 min locks because it cannot wait hours.
Here the same engine (hashfun/web/src/book.js, hosted by node: tests/enginehost.mjs) runs with the
shipped defaults: 4 h for the maker's lock, 8 h 10 min for the taker's, 6 confirmations on the coin
and 1 on Bitcoin. Stock bitcoind (regtest) and a hashfund test launch both run on mock time, the
board's clock and the traders' clocks are the same variable, and every transaction is validated by
the nodes: a refund the test tries before its timelock is refused by consensus, not by the engine.

  H1 the headless maker and taker (`hashfun book`, real clock): post, run, take; encrypted key file
  S1 coin for sats, shipped defaults: both contracts carry the timelocks the page promises
  S2 the maker vanishes after the taker locked: nothing before 8 h 10 min, refund after
  S3 the taker vanishes after the maker locked: maker refunds after 4 h 10 min, taker after 8 h 10 min
  S4 the taker shows up too close to the maker's refund: it does not claim; both refund
  S5 the taker's lock confirms too late: the maker does not lock
  S6 sats for coin (the bid side), shipped defaults
  S7 a dishonest taker: a contract with a shorter timelock, an underfunded lock, a lock on another
     script. The maker's engine locks for none of them
  S8 a dishonest maker: a contract that refunds early, an underfunded lock. The taker's engine
     claims neither and takes its own lock back

Needs node (18+), hashfund and a stock bitcoind:
  python3 -m hashfun.tests.book_regtest --hashfund build/bin/hashfund --bitcoind /path/to/bitcoind
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

from hashfun import book as K
from hashfun.crypto import ecdsa_sign, hash160, pubkey_from_priv, random_priv, sha256, sha256d
from hashfun.htlc import Contract, refund_tx
from hashfun.rpc import RPCError
from hashfun.ser import address_to_script, script_to_address, segwit_encode
from hashfun.settler import Settler
from hashfun.tests.e2e_regtest import COIN, RESULTS, block_from_gbt, check, free_port, mk_launch, open_wallet, ser_block
from hashfun.tests.fleet_regtest import FNode, wait

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(os.path.dirname(HERE), "web")
DAY = 86400
LOCK = 14400          # the shipped default: the maker's lock; the taker's is twice that plus 10 min
FUNDED = 45           # launch-chain blocks whose coinbases the rig can hand out
T_INIT = 2 * LOCK + 600


def sign(priv: int, text: str) -> str:
    r, s = ecdsa_sign(priv, sha256d(text.encode()))
    return f"{r:064x}{s:064x}"


class Host:
    """The node process holding the traders (tests/enginehost.mjs)."""

    def __init__(self):
        self.p = subprocess.Popen(["node", os.path.join(HERE, "enginehost.mjs")], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=sys.stderr, text=True, cwd=WEB)

    def __call__(self, op, **kw):
        self.p.stdin.write(json.dumps({"op": op, **kw}) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError("engine host died")
        out = json.loads(line)
        if not out["ok"]:
            raise RuntimeError(out["error"])
        return out.get("result")

    def stop(self):
        try:
            self.p.stdin.close()
            self.p.wait(5)
        except Exception:
            self.p.kill()


class Rig:
    def __init__(self, a, work):
        self.a, self.work = a, work
        self.T = None  # None: everything runs on the real clock

    # ---- time
    def now(self) -> float:
        return time.time() if self.T is None else float(self.T)

    def clock(self, t=None, dt=0):
        """Move every clock at once: both nodes, the board, every trader."""
        self.T = int(t if t is not None else self.T + dt)
        self.btc.rpc.setmocktime(self.T)
        self.rpc.setmocktime(self.T)
        self.host("clock", t=self.T)

    def mine_tt(self, n=1):
        for _ in range(n):
            self.clock(dt=10)
            for _try in range(30):
                if self.w.generatetoaddress(1, self.addr, 50_000_000):
                    break
            else:
                raise RuntimeError("no launch block")
        self.sync()

    def mine_btc(self, n=1):
        for _ in range(n):
            self.clock(dt=30)
            self.wb.generatetoaddress(1, self.btc_addr)

    def sync(self):
        """The site reads the launch chain through an index that polls: wait for it."""
        tip = self.rpc.getblockcount()
        wait(lambda: self.get("/coin/TT")["height"] == tip, 30, "site index at the tip")

    def get(self, path):
        with urllib.request.urlopen(self.url + "api" + path, timeout=60) as r:
            return json.loads(r.read())

    def past(self, chain, when):
        """Move the clocks to `when` and mine until that chain's median time has passed it."""
        self.clock(t=when)
        (self.mine_btc if chain == "btc" else self.mine_tt)(7)
        mtp = self.get(f"/chain/{chain}/time")["mediantime"]
        assert mtp > when - 1, (mtp, when)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hashfund", required=True)
    ap.add_argument("--bitcoind", required=True)
    ap.add_argument("--workdir")
    a = ap.parse_args()
    work = os.path.abspath(a.workdir) if a.workdir else tempfile.mkdtemp(prefix="hashfun-book-")
    os.makedirs(work, exist_ok=True)
    os.environ["HASHFUN_HOME"] = os.path.join(work, "home")
    os.environ["HASHFUND"] = os.path.abspath(a.hashfund)
    from hashfun.cli import Registry
    from hashfun.web import Site, serve
    reg, rig, t0 = Registry(), Rig(a, work), time.time()
    rig.btc = rig.host = None
    try:
        # ---------------------------------------------------------------- chains
        rig.btc = FNode(a.bitcoind, os.path.join(work, "btc"), ["-regtest", "-listen=0"], free_port(), "btc")
        rig.wb = wb = open_wallet(rig.btc.rpc)
        rig.btc_addr = wb.getnewaddress("", "bech32")
        wb.generatetoaddress(110, rig.btc_addr)
        g = int(time.time()) - DAY
        d = mk_launch("TT", b"\x00\x14" + hash160(pubkey_from_priv(random_priv())), 10**7, g)
        path = os.path.join(work, "tt.json")
        with open(path, "w") as f:
            f.write(d.dumps())
        reg.add(path)
        reg.up("TT", ["-listen=0", "-fallbackfee=0.0001"])
        rig.rpc = rpc = reg.rpc("TT")
        t = g + 100
        rpc.setmocktime(t)  # before the wallet exists (a wallet skips blocks stamped long before its birth)
        rig.w = w = open_wallet(rpc)
        rig.addr = w.getnewaddress("", "bech32")
        spk = address_to_script(rig.addr, d.hrp)
        for _ in range(100 + FUNDED):  # 100 to mature the first coinbases, the rest to have coins to hand out
            t += d.target_spacing
            rpc.setmocktime(t)
            while not w.generatetoaddress(1, rig.addr, 50_000_000):
                pass
        # every block on the curve owes sats: pay and prove the first ones so their coinbases can be spent
        settler = Settler(rpc, wb, os.path.join(work, "settler.json"), pay_depth=0)
        for h in range(1, FUNDED + 1):
            settler.add_block(h, rpc.getblockhash(h))
        for _ in range(2 * FUNDED):
            if all(rpc.getmintobligation(h)["spendable"] for h in range(1, FUNDED + 1)):
                break
            outs = settler.coinbase_outputs()
            wb.generatetoaddress(1, rig.btc_addr)
            t += d.target_spacing
            rpc.setmocktime(t)
            r = rpc.submitblock(ser_block(*block_from_gbt(rpc.getblocktemplate({"rules": ["segwit"]}), spk, extra_outs=outs)))
            if r is not None:
                raise RuntimeError(f"settlement block rejected: {r}")
        have = w.getbalances()["mine"]["trusted"]
        print(f"   TT at {rpc.getblockcount()}, rig wallet holds {have} spendable TT", flush=True)

        # ---------------------------------------------------------------- site, on the shipped defaults
        site = Site(rig.btc.rpc, reg, None, book_path=os.path.join(work, "book.json"))
        site.book.now = rig.now
        port = free_port()
        serve(site, "127.0.0.1", port)
        rig.url = url = f"http://127.0.0.1:{port}/"
        wait(lambda: rig.get("/coin/TT").get("height") == rpc.getblockcount(), 60, "site up")
        cfg = rig.get("/config")
        check("the site proposes the shipped defaults: 4 h lock, 6 confirmations on the coin",
              cfg["book"] == {"confs": 6, "lock": LOCK}, str(cfg["book"]))
        rig.host = host = Host()

        # bring the launch chain to the present (it was mined a day in the past), then both nodes onto one clock
        rig.clock(t=int(time.time()))
        rig.mine_tt(12)
        rig.mine_btc(1)

        def fund(addr_tt=None, coins=0, addr_btc=None, sats=0):
            if coins:
                w.sendtoaddress(addr_tt, coins)
            if sats:
                wb.sendtoaddress(addr_btc, f"{sats / COIN:.8f}")
            rig.mine_tt(1)
            rig.mine_btc(1)

        # ================================================================= H1
        print("-- H1 the headless maker and taker (hashfun book), real clock", flush=True)
        maker_cjs = os.path.join(WEB, "maker.cjs")
        dir_m, dir_t = os.path.join(work, "bot-m"), os.path.join(work, "bot-t")

        def bot(d_, *args, pw=None, wait_=True):
            env = {**os.environ, "HASHFUN_SITE": url.rstrip("/"), "HASHFUN_BOOK_DIR": d_}
            if pw is not None:
                env["HASHFUN_BOOK_PASSWORD"] = pw
            p = subprocess.Popen(["node", maker_cjs, *args], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 stdin=subprocess.DEVNULL)
            if not wait_:
                return p
            out, err = p.communicate(timeout=240)
            return p.returncode, out, err
        rc, out, err = bot(dir_m, "key", pw="correct horse")
        km = json.loads(out)
        rc2, out2, _ = bot(dir_t, "key", "--no-encrypt")
        kt = json.loads(out2)
        raw = json.load(open(os.path.join(dir_m, "key.json")))
        rc3, _, err3 = bot(dir_m, "balances", pw="wrong")
        check("H1 the bot's key file is encrypted with the password, readable only with it, mode 600",
              rc == 0 and rc2 == 0 and "priv" not in raw and raw.get("kdf") == "scrypt" and rc3 != 0 and "wrong password" in err3
              and (os.stat(os.path.join(dir_m, "key.json")).st_mode & 0o777) == 0o600
              and "priv" in json.load(open(os.path.join(dir_t, "key.json"))), err3.strip()[:120])
        # from here to the end of H1 the chains follow the real clock: the bots are separate processes
        halt = threading.Event()

        def tick_chains():
            while not halt.is_set():
                try:
                    rig.clock(t=max(rig.T + 1, int(time.time())))
                    while not w.generatetoaddress(1, rig.addr, 50_000_000):
                        pass
                    wb.generatetoaddress(1, rig.btc_addr)
                except (RPCError, OSError) as e:
                    print(f"   miner: {e}", flush=True)
                halt.wait(1.0)
        rig.T, site.book.now = int(time.time()), time.time
        w.sendtoaddress(km["send_coins_to"]["TT"], 30)
        wb.sendtoaddress(kt["send_sats_to"], "0.00200000")
        miner = threading.Thread(target=tick_chains, daemon=True)
        miner.start()
        ok = wait(lambda: json.loads(bot(dir_m, "balances", pw="correct horse")[1]).get("TT") == 30
                  and json.loads(bot(dir_t, "balances")[1]).get("sats") == 200_000, 60, "bots funded")
        rc, out, err = bot(dir_m, "post", "--give", "TT", "--get", "btc", "--give-amount", "5", "--get-amount", "30000", pw="correct horse")
        oid = out.split()[0] if out.split() else ""
        runner = bot(dir_m, "run", pw="correct horse", wait_=False)
        listed = wait(lambda: any(o["id"] == oid for o in rig.get("/book")["orders"]), 30, "the bot's offer is listed")
        check("H1 an offer posted from the command line is on the board while `hashfun book run` is up", ok and rc == 0 and listed, err.strip()[:200])
        t_take = time.time()
        rc, out, err = bot(dir_t, "take", oid[:12])
        print(f"   take: exit {rc} in {time.time() - t_take:.0f}s", flush=True)
        done = wait(lambda: all(f["state"] == "done" for f in list(site.book.fills.values())) and len(site.book.fills) == 1, 60, "both sides done")
        # "done" is the claim broadcast; the balance counts it once a block holds it
        wait(lambda: json.loads(bot(dir_m, "balances", pw="correct horse")[1]).get("sats", 0) > 0, 30, "the maker's claim confirmed")
        bal_t, bal_m = json.loads(bot(dir_t, "balances")[1]), json.loads(bot(dir_m, "balances", pw="correct horse")[1])
        check("H1 `hashfun book take` swaps against the running bot: coins at the taker's key, sats at the maker's",
              rc == 0 and done and 4.9999 < bal_t["TT"] <= 5 and 160_000 < bal_t["sats"] < 170_000
              and 24.999 < bal_m["TT"] <= 25 and 20_000 < bal_m["sats"] <= 30_000, f"{bal_t} {bal_m} {err.strip()[:200]}")
        # the same key directory, used by two commands at once
        rc_p, out_p, err_p = bot(dir_m, "post", "--give", "TT", "--get", "btc", "--give-amount", "3", "--get-amount", "20000", pw="correct horse")
        oid2 = out_p.split()[0] if out_p.split() else ""
        listed2 = wait(lambda: any(o["id"] == oid2 for o in rig.get("/book")["orders"]), 30, "the second offer is listed")
        rc_own, _, err_own = bot(dir_m, "take", oid2[:12], pw="correct horse")
        rc2, _, err2 = bot(dir_t, "take", oid2[:12])
        mine2 = bot(dir_m, "swaps", pw="correct horse")[1]
        check("H1 an offer posted while the bot runs is served by it; a take from the bot's own key directory is refused as busy",
              rc_p == 0 and listed2 and rc_own != 0 and "busy" in err_own and rc2 == 0 and mine2.count("maker") == 2,
              f"{rc_p} {listed2} {rc_own} {err_own.strip()[:80]} | {rc2} {err2.strip()[:120]} | {mine2.strip()[:160]}")
        runner.send_signal(2)
        try:
            runner.wait(20)
        except subprocess.TimeoutExpired:
            runner.kill()
        gone = wait(lambda: not any(o["maker"] == km["pubkey"] for o in rig.get("/book")["orders"]), 40, "delisted")
        check("H1 with the bot stopped its offers leave the board within the liveness window", gone and runner.returncode == 0,
              str(runner.returncode))
        halt.set()
        miner.join(10)

        # ================================================================= S1
        print("-- S1 coin for sats on the shipped defaults (mock clock from here on)", flush=True)
        site.book.now = rig.now
        rig.clock(t=max(rig.T, int(time.time())) + 5)
        keys = {n: random_priv() for n in ("M", "T", "X")}
        P = {n: pubkey_from_priv(k).hex() for n, k in keys.items()}
        A = {n: host("new", name=n, priv=f"{k:064x}", site=url.rstrip("/")) for n, k in keys.items()}
        fund(A["M"]["coins"]["TT"], 60, A["T"]["btc"], 400_000)
        fund(A["T"]["coins"]["TT"], 20, A["M"]["btc"], 200_000)
        rig.mine_btc(1)
        bal = lambda n, c: host("balance", name=n, chain=c)  # noqa: E731
        rec = lambda n, fid: next(r for r in host("recs", name=n) if r["id"] == fid)  # noqa: E731
        contract = lambda r: Contract.parse(bytes.fromhex(r["my"]["contract"]))  # noqa: E731

        def offer(give="TT", get="btc", give_amount=10 * COIN, get_amount=50_000):
            for old in host("mine", name="M"):   # one offer at a time: the page refuses to promise the same coins twice
                host("cancel", name="M", order=old["id"])
            o = host("post", name="M", give=give, get=get, give_amount=give_amount, get_amount=get_amount)
            wait(lambda: any(x["id"] == o["id"] for x in rig.get("/book")["orders"]), 20, "offer listed")
            return o

        def take(o, amount=None, taker="T"):
            host("tick", name="M")  # heartbeat: the maker is live
            return host("take", name=taker, order=o["id"], amount=amount, tick=["M"])

        o = offer()
        check("S1 the offer carries the defaults: 4 h lock, 1 confirmation asked on the taker's sats",
              (o["lock"], o["confs"]) == (LOCK, 1), f"{o['lock']} {o['confs']}")
        m_coins, t_sats, m_sats, t_coins, at = bal("M", "TT"), bal("T", "btc"), bal("M", "btc"), bal("T", "TT"), rig.T
        r = take(o)
        ct = contract(r)
        check("S1 the taker's lock: to the maker's key, refundable 8 h 10 min from now",
              r["state"] == "locked" and ct.locktime == at + T_INIT and ct.recipient_pub.hex() == P["M"]
              and ct.refund_pub.hex() == P["T"] and ct.secret_hash == sha256(bytes.fromhex(r["secret"])), f"{ct.locktime - at}")
        host("tick", name="M")
        check("S1 the maker does not lock on an unconfirmed payment", rec("M", r["id"])["state"] == "accepted", rec("M", r["id"])["state"])
        rig.mine_btc(1)
        host("tick", name="M")
        rm = rec("M", r["id"])
        cm = contract(rm) if rm["state"] == "locked" else None
        check("S1 the maker's lock: to the taker's key, same hash, refundable 4 h 10 min from the take",
              cm is not None and cm.locktime == at + T_INIT - LOCK and cm.recipient_pub.hex() == P["T"]
              and cm.refund_pub.hex() == P["M"] and cm.secret_hash == ct.secret_hash, rm["state"] + " " + rm.get("note", ""))
        rig.mine_tt(5)
        host("tick", name="T")
        check("S1 the taker does not claim at 5 confirmations", rec("T", r["id"])["state"] == "locked", rec("T", r["id"]).get("note", ""))
        rig.mine_tt(1)
        host("tick", name="T")
        rig.mine_tt(1)
        host("tick", name="M")
        rig.mine_btc(1)
        rig.sync()
        check("S1 at 6 confirmations the taker claims and the maker claims with the revealed secret",
              rec("T", r["id"])["state"] == "done" and rec("M", r["id"])["state"] == "done"
              and 0 < t_coins + 10 * COIN - bal("T", "TT") <= 2000 and 0 < m_sats + 50_000 - bal("M", "btc") <= 12_000
              and bal("M", "TT") <= m_coins - 10 * COIN and bal("T", "btc") <= t_sats - 50_000,
              f"{rec('T', r['id'])['state']} {rec('M', r['id'])['state']} {rec('M', r['id']).get('note', '')}")

        # ================================================================= S2
        print("-- S2 the maker vanishes after the taker locked", flush=True)
        o = offer()
        t_sats, at = bal("T", "btc"), rig.T
        r = take(o)
        host("drop", name="M")
        rig.mine_btc(1)
        lock_out = wb.gettxout(r["my"]["txid"], r["my"]["vout"])
        rig.past("btc", at + T_INIT - 900)
        host("tick", name="T")
        early = refund_tx(contract(r), bytes.fromhex(r["my"]["txid"])[::-1], r["my"]["vout"], 50_000,
                          address_to_script(A["T"]["btc"], "bcrt"), 400, keys["T"])
        try:
            rig.btc.rpc.sendrawtransaction(early.serialize().hex())
            refused = ""
        except RPCError as e:
            refused = str(e)
        check("S2 8 hours in, the taker's sats are still locked: the page waits and Bitcoin itself refuses the refund",
              rec("T", r["id"])["state"] == "locked" and "non-final" in refused and lock_out is not None
              and wb.gettxout(r["my"]["txid"], r["my"]["vout"]) is not None, refused[:80])
        rig.past("btc", at + T_INIT + 1)
        host("tick", name="T")
        rig.mine_btc(1)
        back = bal("T", "btc")
        check("S2 past 8 h 10 min the taker's engine takes its sats back by itself: only fees are gone",
              rec("T", r["id"])["state"] == "refunded" and 0 < t_sats - back <= 20_000, f"{t_sats - back}")
        host("back", name="M")
        m_coins = bal("M", "TT")
        host("tick", name="M")
        check("S2 the maker, back later, locks nothing for a swap that is over",
              rec("M", r["id"])["state"] == "released" and bal("M", "TT") == m_coins, rec("M", r["id"])["state"])

        # ================================================================= S3
        print("-- S3 the taker vanishes after the maker locked", flush=True)
        o = offer()
        m_coins, t_sats, at = bal("M", "TT"), bal("T", "btc"), rig.T
        r = take(o)
        rig.mine_btc(1)
        host("tick", name="M")
        host("drop", name="T")
        rig.mine_tt(6)
        rig.past("TT", at + T_INIT - LOCK - 300)
        host("tick", name="M")
        check("S3 just under 4 h 10 min the maker's coins are still locked", rec("M", r["id"])["state"] == "locked")
        rig.past("TT", at + T_INIT - LOCK + 1)
        host("tick", name="M")
        rig.mine_tt(1)
        check("S3 past 4 h 10 min the maker's engine takes its coins back and frees that part of the offer",
              rec("M", r["id"])["state"] == "refunded" and 0 < m_coins - bal("M", "TT") <= 3000
              and site.book.fills[r["id"]]["state"] == "failed", f"{m_coins - bal('M', 'TT')} {site.book.fills[r['id']]['state']}")
        host("back", name="T")
        host("tick", name="T")
        check("S3 the taker, back before its own timelock, finds no lock to claim and does nothing",
              rec("T", r["id"])["state"] == "locked", rec("T", r["id"]).get("note", ""))
        rig.past("btc", at + T_INIT + 1)
        host("tick", name="T")
        rig.mine_btc(1)
        check("S3 past 8 h 10 min the taker's sats come back too: nobody lost more than fees",
              rec("T", r["id"])["state"] == "refunded" and 0 < t_sats - bal("T", "btc") <= 20_000, f"{t_sats - bal('T', 'btc')}")

        # ================================================================= S4
        print("-- S4 the taker shows up too close to the maker's refund", flush=True)
        o = offer()
        m_coins, t_sats, at = bal("M", "TT"), bal("T", "btc"), rig.T
        r = take(o)
        rig.mine_btc(1)
        host("tick", name="M")
        rig.mine_tt(6)
        m_lock = rec("M", r["id"])["my"]
        rig.past("TT", at + T_INIT - LOCK - 500)  # inside the 10 min the engine keeps clear on a 10 s chain
        host("tick", name="T")
        note = rec("T", r["id"]).get("note", "")
        check("S4 with the maker's lock confirmed but its refund 8 minutes away, the taker does not reveal the secret",
              rec("T", r["id"])["state"] == "locked" and "too close" in note and rpc.gettxout(m_lock["txid"], m_lock["vout"]) is not None, note)
        rig.past("TT", at + T_INIT - LOCK + 1)
        host("tick", name="M")
        rig.past("btc", at + T_INIT + 1)
        host("tick", name="T")
        rig.mine_btc(1)
        rig.mine_tt(1)
        check("S4 both locks go back to their owners",
              rec("M", r["id"])["state"] == "refunded" and rec("T", r["id"])["state"] == "refunded"
              and 0 < m_coins - bal("M", "TT") <= 3000 and 0 < t_sats - bal("T", "btc") <= 20_000)

        # ================================================================= S5
        print("-- S5 the taker's lock confirms too late", flush=True)
        o = offer()
        m_coins, t_sats, at = bal("M", "TT"), bal("T", "btc"), rig.T
        r = take(o)
        host("tick", name="M")
        rig.clock(t=at + T_INIT - LOCK - LOCK // 2 + 60)  # the maker's lock would now last under 2 h
        rig.mine_btc(1)
        host("tick", name="M")
        check("S5 the maker's engine will not lock with less than half its lock left for the taker to claim in",
              rec("M", r["id"])["state"] == "released" and "too late" in rec("M", r["id"]).get("note", "") and bal("M", "TT") == m_coins
              and site.book.fills[r["id"]]["state"] == "failed", rec("M", r["id"]).get("note", ""))
        rig.past("btc", at + T_INIT + 1)
        host("tick", name="T")
        rig.mine_btc(1)
        check("S5 the taker gets its sats back after its timelock", rec("T", r["id"])["state"] == "refunded"
              and 0 < t_sats - bal("T", "btc") <= 20_000)

        # ================================================================= S6
        print("-- S6 sats for coin: a bid, shipped defaults", flush=True)
        for old in host("mine", name="M"):
            host("cancel", name="M", order=old["id"])
        o = host("post", name="M", give="btc", get="TT", give_amount=40_000, get_amount=8 * COIN)
        pend = rig.get("/book?maker=" + P["M"])["orders"]
        ok = wait(lambda: any(x["id"] == o["id"] for x in rig.get("/book")["orders"]), 30, "the bid is listed once its sats are seen")
        check("S6 a bid is listed only after the board has seen the sats behind it",
              ok and (o["lock"], o["confs"]) == (LOCK, 6), f"{o['confs']} {[x.get('backed') for x in pend]}")
        m_sats, t_coins, t_sats, m_coins, at = bal("M", "btc"), bal("T", "TT"), bal("T", "btc"), bal("M", "TT"), rig.T
        r = take(o)
        rig.mine_tt(5)
        host("tick", name="M")
        five = rec("M", r["id"])["state"]
        rig.mine_tt(1)
        host("tick", name="M")
        rig.mine_btc(1)
        host("tick", name="T")
        rig.mine_btc(1)
        host("tick", name="M")
        rig.mine_tt(1)
        rig.mine_btc(1)
        ct, cm = contract(rec("T", r["id"])), contract(rec("M", r["id"]))
        check("S6 the maker waits for 6 confirmations on the coins, then both claim; timelocks 8 h 10 min and 4 h 10 min",
              five == "accepted" and rec("T", r["id"])["state"] == "done" and rec("M", r["id"])["state"] == "done"
              and (ct.locktime, cm.locktime) == (at + T_INIT, at + T_INIT - LOCK)
              and 0 < t_sats + 40_000 - bal("T", "btc") <= 12_000 and 0 < m_coins + 8 * COIN - bal("M", "TT") <= 2000,
              f"{five} {rec('T', r['id'])['state']} {rec('M', r['id'])['state']} {rec('T', r['id']).get('note', '')}")

        # ================================================================= S7
        print("-- S7 a dishonest taker", flush=True)
        o = offer(give_amount=30 * COIN, get_amount=150_000)

        def raw_take(amount):
            """A take signed by X outside the engine, so X can then misbehave."""
            secret = os.urandom(32)
            tk = {"order": o["id"], "taker": P["X"], "get_amount": amount, "secret_hash": sha256(secret).hex(),
                  "locktime": rig.T + T_INIT, "ts": rig.T}
            req = urllib.request.Request(url + "api/book/take", json.dumps({**tk, "sig": sign(keys["X"], K.take_text(tk))}).encode(),
                                         {"Content-Type": "application/json"})
            f = json.loads(urllib.request.urlopen(req, timeout=30).read())
            host("tick", name="M")
            return f, tk

        def note(priv, fid, kind, **body):
            m = {"from": pubkey_from_priv(priv).hex(), "kind": kind, "body": body, "sig": sign(priv, K.note_text(fid, kind, body))}
            req = urllib.request.Request(url + f"api/book/fill/{fid}", json.dumps(m).encode(), {"Content-Type": "application/json"})
            return json.loads(urllib.request.urlopen(req, timeout=30).read())

        def pay(script: bytes, sats_):
            """Fund a P2WSH from the rig's Bitcoin wallet; the outpoint."""
            spk_ = b"\x00\x20" + sha256(script)
            txid = wb.sendtoaddress(script_to_address(spk_, "bcrt"), f"{sats_ / COIN:.8f}")
            tx = wb.gettransaction(txid, True, True)["decoded"]
            return txid, next(v["n"] for v in tx["vout"] if v["scriptPubKey"]["hex"] == spk_.hex())
        m_coins = bal("M", "TT")
        cases = []
        for name in ("shorter timelock", "underfunded", "another script"):
            f, tk = raw_take(50_000)
            honest = Contract(bytes.fromhex(tk["secret_hash"]), bytes.fromhex(P["M"]), bytes.fromhex(P["X"]), tk["locktime"])
            if name == "shorter timelock":   # X could refund while the maker's coins are still claimable
                bad = Contract(honest.secret_hash, honest.recipient_pub, honest.refund_pub, tk["locktime"] - 2 * LOCK)
                txid, vout = pay(bad.script(), 50_000)
                told = bad.script().hex()
            elif name == "underfunded":
                txid, vout = pay(honest.script(), 49_000)
                told = honest.script().hex()
            else:                            # the right contract in the message, the money somewhere X controls
                txid, vout = pay(Contract(honest.secret_hash, bytes.fromhex(P["X"]), honest.refund_pub, tk["locktime"]).script(), 50_000)
                told = honest.script().hex()
            note(keys["X"], f["id"], "locked", contract=told, txid=txid, vout=vout)
            cases.append((name, f["id"]))
        rig.mine_btc(2)
        for _ in range(3):
            host("tick", name="M")
        states = {name: (rec("M", fid)["state"], rec("M", fid).get("note", ""), site.book.fills[fid]["state"]) for name, fid in cases}
        check("S7 the maker's engine locks for none of them: a shorter timelock, a short payment, a payment to another script",
              all(s[0] == "released" and s[2] == "failed" for s in states.values()) and bal("M", "TT") == m_coins, str(states))
        f, tk = raw_take(50_000)   # and the honest version of the same take is served
        honest = Contract(bytes.fromhex(tk["secret_hash"]), bytes.fromhex(P["M"]), bytes.fromhex(P["X"]), tk["locktime"])
        txid, vout = pay(honest.script(), 50_000)
        note(keys["X"], f["id"], "locked", contract=honest.script().hex(), txid=txid, vout=vout)
        rig.mine_btc(1)
        host("tick", name="M")
        check("S7 the same take done honestly is locked for", rec("M", f["id"])["state"] == "locked", rec("M", f["id"]).get("note", ""))

        # ================================================================= S8
        print("-- S8 a dishonest maker", flush=True)
        results = []
        for name in ("refunds early", "underfunded"):
            o = offer()
            t_sats, at = bal("T", "btc"), rig.T
            r = take(o)
            host("drop", name="M")   # from here the "maker" is the test, signing with the maker's key
            rig.mine_btc(1)
            honest = Contract(bytes.fromhex(r["secret_hash"]), bytes.fromhex(P["T"]), bytes.fromhex(P["M"]), r["locktime"] - LOCK)
            if name == "refunds early":  # the maker could take its coins back minutes after the taker reveals the secret
                bad = Contract(honest.secret_hash, honest.recipient_pub, honest.refund_pub, rig.T + 900)
                spk_, told, coins_ = b"\x00\x20" + sha256(bad.script()), bad.script().hex(), 10
            else:
                spk_, told, coins_ = b"\x00\x20" + sha256(honest.script()), honest.script().hex(), 9.99
            txid = w.sendtoaddress(script_to_address(spk_, d.hrp), coins_)
            vout = next(v["n"] for v in w.gettransaction(txid, True, True)["decoded"]["vout"] if v["scriptPubKey"]["hex"] == spk_.hex())
            note(keys["M"], r["id"], "locked", contract=told, txid=txid, vout=vout)
            rig.mine_tt(7)
            host("tick", name="T")
            unclaimed = rpc.gettxout(txid, vout) is not None and rec("T", r["id"])["state"] == "locked"
            rig.past("btc", at + T_INIT + 1)
            host("tick", name="T")
            rig.mine_btc(1)
            results.append((name, unclaimed, rec("T", r["id"])["state"], t_sats - bal("T", "btc"), rec("T", r["id"]).get("note", "")))
            host("back", name="M")
            host("tick", name="M")
        check("S8 the taker's engine claims neither a lock that refunds early nor a short one, and takes its own sats back",
              all(u and st == "refunded" and 0 < lost <= 20_000 for _, u, st, lost, _ in results), str(results))
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        check("book run completed", False, str(e))
    finally:
        for fn in ((lambda: rig.host.stop()) if rig.host else None, lambda: reg.down("TT"), (lambda: rig.btc.stop()) if rig.btc else None):
            if fn:
                try:
                    fn()
                except Exception as e:  # noqa: BLE001
                    print(f"shutdown: {e}", flush=True)
        if not a.workdir:
            shutil.rmtree(work, ignore_errors=True)
    passed = sum(1 for v in RESULTS.values() if v)
    print(f"\nbook: {passed}/{len(RESULTS)} passed in {time.time() - t0:.0f}s", flush=True)
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
