"""Integration tests of the Python stack against the in-process chain simulator:
pool + miner, merged mining with graduation gating, the strata proxy, the
Electrum server + HD wallet (incl. reorg), and atomic swaps (buy, sell, refund)
between the wallet and the maker bot through the relay."""
import asyncio
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

from hashfun import descriptor as D
from hashfun.crypto import pubkey_from_priv, random_priv
from hashfun.electrum import ElectrumServer
from hashfun.miner import StratumMiner
from hashfun.proxy import StrataProxy
from hashfun.ser import segwit_encode, hash160, p2wpkh_script, address_to_script
from hashfun.stratum import LaunchSource, MergedSource, StratumServer
from hashfun.swap import KeyStore, Maker, NodeChain, relay_handler
from hashfun.tests.sim import SimChain, Block, Clock
from hashfun.tests.test_core import test_launch
from hashfun.wallet import Wallet, LAUNCH_COIN_BASE

COIN = 100_000_000


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def addr(hrp):
    return segwit_encode(hrp, 0, hash160(pubkey_from_priv(random_priv())))


class Loop:
    """Background asyncio loop for servers."""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.t = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.t.start()

    def spawn(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def run(self, coro, timeout=120):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)


def small_launch(ticker="TST", graduation_blocks=30, **kw):
    # pow limit 0x207fffff => 2 hashes of work per block; W_g ~= 2 * graduation_blocks
    g, t0 = 11_086_000 * COIN, 15_000_000 * COIN
    v0 = max(1, (2 * graduation_blocks) * (t0 - g) // g)
    d = test_launch(ticker=ticker, hrp=ticker.lower(), virtual_work=v0, lwma_window=10, **kw)
    d.grind_genesis()
    return d


def curve_consistent(case, chain: SimChain):
    d = chain.launch
    minted_curve = 0
    for h in range(1, chain.height + 1):
        b = chain.blocks[h]
        sub = chain.subsidy(h, b.bits)
        cb_total = sum(o.value for o in b.txs[0].vout)
        case.assertLessEqual(cb_total, sub + 10**6)
        if d.creator_fee_bps:
            paid = sum(o.value for o in b.txs[0].vout if o.script_pubkey == d.creator_script)
            case.assertGreaterEqual(paid, d.creator_fee(sub))
        if chain.rel_work(h - 1) < d.graduation_work:
            minted_curve += sub
    case.assertEqual(minted_curve, d.curve_supply(chain.rel_work()))


class PoolTests(unittest.TestCase):
    def test_pool_miner_blocks_follow_curve(self):
        d = small_launch(graduation_blocks=1000)
        chain = SimChain("TST", d)
        L = Loop()
        port = free_port()
        srv = StratumServer(LaunchSource(chain, d.hrp, d.ticker), "127.0.0.1", port, difficulty=1e-6, poll_interval=0.05)
        L.spawn(srv.serve())
        time.sleep(0.3)
        miner_addr = addr(d.hrp)
        m = StratumMiner("127.0.0.1", port, miner_addr, batch=4096)
        t0 = time.time()
        while chain.height < 6 and time.time() - t0 < 90:
            L.run(m.run(duration=2))
        self.assertGreaterEqual(chain.height, 6, f"only {chain.height} blocks")
        spk = address_to_script(miner_addr, d.hrp)
        for h in range(1, chain.height + 1):
            cb = chain.blocks[h].txs[0]
            self.assertEqual(cb.vout[0].script_pubkey, spk)
            self.assertEqual(cb.vout[1].script_pubkey, d.creator_script)
        curve_consistent(self, chain)
        self.assertTrue(any(e["kind"] == "block" and e["result"] is None for e in srv.events))

    def test_merged_mining_only_after_graduation(self):
        btc = SimChain("BTC")
        grad = small_launch("GRAD", graduation_blocks=8)
        pre = small_launch("PRE", graduation_blocks=10_000)
        cg, cp = SimChain("GRAD", grad), SimChain("PRE", pre)
        cg.mine(12)
        self.assertTrue(cg.graduated())
        self.assertFalse(cp.graduated())
        # a merge-mined block on an ungraduated launch is invalid by consensus
        b = cp.build_block(p2wpkh_script(pubkey_from_priv(5)), aux=True)
        b.auxpow = b"\x00"
        self.assertEqual(cp.connect(b), "auxpow-before-graduation")

        L = Loop()
        port = free_port()
        children = {"GRAD": {"rpc": cg, "hrp": grad.hrp, "payout": addr(grad.hrp)},
                    "PRE": {"rpc": cp, "hrp": pre.hrp, "payout": addr(pre.hrp)}}
        src = MergedSource(btc, "bcrt", children, default_payout=addr("bcrt"))
        srv = StratumServer(src, "127.0.0.1", port, difficulty=1e-6, poll_interval=0.05)
        L.spawn(srv.serve())
        time.sleep(0.3)
        h0_grad, h0_pre = cg.height, cp.height
        m = StratumMiner("127.0.0.1", port, addr("bcrt"), batch=4096)
        t0 = time.time()
        while (cg.height < h0_grad + 3 or btc.height < 3) and time.time() - t0 < 90:
            L.run(m.run(duration=2))
        self.assertGreaterEqual(cg.height, h0_grad + 3)
        self.assertGreaterEqual(btc.height, 3)
        self.assertEqual(cp.height, h0_pre)
        aux_blocks = [b for b in cg.blocks[h0_grad + 1:] if b.auxpow]
        self.assertTrue(aux_blocks)
        for b in aux_blocks:
            self.assertEqual(sum(o.value for o in b.txs[0].vout), cg.subsidy(cg.index[b.hash], b.bits))
        # post-graduation blocks pay the tail, pre-graduation curve total is exactly G
        self.assertEqual(grad.curve_supply(cg.rel_work()), grad.graduation_tokens)
        curve_consistent(self, cg)


class ProxyTests(unittest.TestCase):
    def test_weighted_split(self):
        L = Loop()
        ports, strata = [], []
        for t, w in (("AAA", 3), ("BBB", 1)):
            d = small_launch(t, graduation_blocks=10**6)
            c = SimChain(t, d)
            p = free_port()
            L.spawn(StratumServer(LaunchSource(c, d.hrp, t), "127.0.0.1", p, difficulty=1e-5, poll_interval=0.05).serve())
            strata.append({"name": t, "url": f"127.0.0.1:{p}", "user": addr(d.hrp), "weight": w})
        time.sleep(0.3)
        pport = free_port()
        proxy = StrataProxy(strata, f"127.0.0.1:{pport}", slice_seconds=0.15)
        L.spawn(proxy.serve())
        time.sleep(0.3)
        m = StratumMiner("127.0.0.1", pport, "anyone", batch=2048)
        L.run(m.run(duration=12), timeout=60)
        st = proxy.stats()
        self.assertGreater(m.accepted, 30)
        self.assertAlmostEqual(st["AAA"]["delivered"], 0.75, delta=0.15)
        self.assertAlmostEqual(st["BBB"]["delivered"], 0.25, delta=0.15)


class WalletSwapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.L = Loop()
        clock = Clock()
        cls.btc = SimChain("BTC", clock=clock)
        cls.fd = small_launch("SWP", graduation_blocks=50)
        cls.fork = SimChain("SWP", cls.fd, clock=clock)
        cls.ports = {}
        for name, c in (("BTC", cls.btc), ("SWP", cls.fork)):
            p = free_port()
            cls.ports[name] = p
            cls.L.spawn(ElectrumServer(c, "127.0.0.1", p).serve())
        time.sleep(0.5)
        cls.tmp = tempfile.mkdtemp()
        cls.w = Wallet.create(os.path.join(cls.tmp, "w.json"))
        cls.w.add_chain("BTC", f"127.0.0.1:{cls.ports['BTC']}", "bcrt", 1, "btc")
        cls.w.add_chain("SWP", f"127.0.0.1:{cls.ports['SWP']}", cls.fd.hrp, LAUNCH_COIN_BASE + cls.fd.chain_id)
        # fund taker wallet on both chains, maker node wallets on both chains
        cls.btc.mine(3, address_to_script(cls.w.chains["BTC"].address(0, 0), "bcrt"))
        cls.fork.mine(3, address_to_script(cls.w.chains["SWP"].address(0, 0), cls.fd.hrp))
        cls.btc.mine(3)
        cls.fork.mine(3)
        cls.sync()

    @classmethod
    def sync(cls, t=6):
        deadline = time.time() + t
        while time.time() < deadline:
            try:
                if all(cls.w.chains[n].tip() == c.height for n, c in (("BTC", cls.btc), ("SWP", cls.fork))):
                    return
            except Exception:
                pass
            time.sleep(0.1)

    def mine_both(self, n=1):
        self.btc.mine(n)
        self.fork.mine(n)
        self.sync()

    def test_1_balance_send_and_reorg(self):
        bal = self.w.chains["BTC"].balance()
        self.assertEqual(bal["confirmed"], sum(self.btc.blocks[h].txs[0].vout[0].value for h in (1, 2, 3)))
        dest = addr("bcrt")
        txid = self.w.chains["BTC"].send(dest, 5 * COIN)
        self.assertIn(bytes.fromhex(txid)[::-1], self.btc.mempool)
        self.btc.mine(1)
        self.sync()
        self.assertTrue(any(o.script_pubkey == address_to_script(dest, "bcrt") and o.value == 5 * COIN
                            for o, _, _ in self.btc.utxos.values()))
        # reorg the send out and back: electrum index must follow
        h = self.btc.height
        self.btc.rewind_to(h - 1)
        self.btc.mine(2)
        self.sync()
        hist = self.w.chains["BTC"].ec.call("blockchain.scripthash.get_history",
                                            __import__("hashlib").sha256(address_to_script(dest, "bcrt")).digest()[::-1].hex())
        self.assertTrue(hist and hist[0]["height"] in (0, self.btc.height - 1, self.btc.height))

    def _maker(self, lock_init=7200, lock_part=1800, fork_confs=2):
        ks = KeyStore(os.path.join(self.tmp, f"ks{time.time()}.json"))
        # pick a hashprice that puts the curve at ~1000 sats/coin right now
        hp = 1000 / self.fork.getlaunchinfo()["hashes_per_coin"] * 1e12
        cfg = {"defaults": {"hashprice_sats_per_th": hp, "spread": 0.02, "btc_confs": 1, "fork_confs": fork_confs,
                            "init_lock_seconds": lock_init, "part_lock_seconds": lock_part,
                            "lock_margin_seconds": 600, "safety": 1e9}}
        mk = Maker(NodeChain("BTC", self.btc, "bcrt"), {"SWP": NodeChain("SWP", self.fork, self.fd.hrp)}, ks, cfg,
                   os.path.join(self.tmp, f"orders{time.time()}.json"))
        port = free_port()
        srv = ThreadingHTTPServer(("127.0.0.1", port), relay_handler(mk))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return mk, f"http://127.0.0.1:{port}", srv

    def _run_taker(self, mk, relay, side, amount, maker_on=True, max_rounds=80):
        out = {}

        def taker():
            out["rec"] = self.w.swap(relay, "SWP", side, amount, wait=True, poll=0.2, log=lambda *_: None)
        t = threading.Thread(target=taker, daemon=True)
        t.start()
        for _ in range(max_rounds):
            if not t.is_alive():
                break
            time.sleep(0.3)
            self.mine_both()
            if maker_on:
                mk.tick()
            else:
                self.btc.advance(900)
                self.fork.advance(900)
        t.join(5)
        return out.get("rec")

    def test_2_swap_buy(self):
        mk, relay, srv = self._maker()
        before = self.w.chains["SWP"].balance()["confirmed"]
        amount = 1000 * COIN
        rec = self._run_taker(mk, relay, "buy", amount)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["state"], "done", rec)
        for _ in range(20):
            o = list(mk.orders.values())[-1]
            if o.state == "done":
                break
            self.mine_both()
            mk.tick()
        self.assertEqual(o.state, "done", o.note)
        self.mine_both()
        after = self.w.chains["SWP"].balance()["confirmed"]
        self.assertGreater(after - before, amount - 10_000)
        srv.shutdown()

    def test_3_swap_sell(self):
        mk, relay, srv = self._maker()
        before = self.w.chains["BTC"].balance()["confirmed"]
        rec = self._run_taker(mk, relay, "sell", 500 * COIN)
        self.assertEqual(rec["state"], "done", rec)
        for _ in range(20):
            o = list(mk.orders.values())[-1]
            if o.state == "done":
                break
            self.mine_both()
            mk.tick()
        self.assertEqual(o.state, "done", o.note)
        self.mine_both()
        self.assertGreater(self.w.chains["BTC"].balance()["confirmed"], before)
        srv.shutdown()

    def test_4_refund_when_maker_disappears(self):
        mk, relay, srv = self._maker(lock_init=3600, lock_part=600)
        before = self.w.chains["BTC"].balance()
        rec = self._run_taker(mk, relay, "buy", 100 * COIN, maker_on=False, max_rounds=60)
        self.assertEqual(rec["state"], "refunded", rec)
        self.mine_both()
        after = self.w.chains["BTC"].balance()
        self.assertGreater(after["confirmed"] + after["unconfirmed"],
                           before["confirmed"] + before["unconfirmed"] - 20_000)
        srv.shutdown()


if __name__ == "__main__":
    unittest.main()


class BoardTests(unittest.TestCase):
    def test_board_api_over_sim(self):
        from hashfun.board import Board, LaunchIndexer
        d = small_launch("BRD", graduation_blocks=20)
        c = SimChain("BRD", d)
        c.mine(25)
        b = Board({"launches": []})
        ix = LaunchIndexer(c)
        b.indexers = [ix]
        ix.poll()
        self.assertIsNone(ix.error, ix.error)
        lst = b.api("/api/launches")["launches"]
        self.assertEqual(lst[0]["ticker"], "BRD")
        self.assertTrue(lst[0]["graduated"])
        self.assertIn("hashrate", lst[0])
        det = b.api("/api/launch/" + d.id_hex[:16])
        self.assertEqual(len(det["blocks"]), 25)
        self.assertEqual(det["blocks"][-1]["height"], 25)
        self.assertEqual(det["blocks"][0]["payouts"][1]["address"], segwit_encode(d.hrp, 0, d.creator_script[2:]))
