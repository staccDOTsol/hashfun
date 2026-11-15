"""Integration tests of the Python stack against the in-process chain simulator:
pool + miner, merged mining with graduation gating, the strata proxy, the
Electrum server + HD wallet (incl. reorg), and atomic swaps (buy, sell, refund)
between the wallet and the maker bot through the relay."""
import asyncio
import json
import os
import socket
import struct
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

from hashfun import descriptor as D
from hashfun.crypto import pubkey_from_priv, random_priv, sha256d
from hashfun.electrum import ElectrumServer
from hashfun.miner import StratumMiner
from hashfun.proxy import StrataProxy
from hashfun.ser import segwit_encode, hash160, p2wpkh_script, address_to_script, bits_to_target
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
    # pow limit 0x207fffff => 2 hashes of work per block; W_g ~= 2 * graduation_blocks (on one curve)
    g, t0 = 8_869_000 * COIN, 12_000_000 * COIN
    v0 = max(1, (2 * graduation_blocks) * (t0 - g) // g)
    d = test_launch(ticker=ticker, hrp=ticker.lower(), virtual_work=v0, lwma_window=10, **kw)
    d.grind_genesis()
    return d


def curve_consistent(case, chain: SimChain):
    """Every block minted what its own curve gives for its work, and each curve's mints add up to
    what that curve's work stands for (as of the block that graduated the launch, if one did)."""
    d = chain.launch
    minted = {"btc": 0, "qwen": 0}
    for h in range(1, chain.height + 1):
        b = chain.blocks[h]
        curve = D.curve_of_version(b.version)
        sub = chain.subsidy(h, b.bits, curve)
        cb_total = sum(o.value for o in b.txs[0].vout)
        case.assertLessEqual(cb_total, sub + 10**6)
        if d.creator_fee_bps:
            paid = sum(o.value for o in b.txs[0].vout if o.script_pubkey == d.creator_script)
            case.assertGreaterEqual(paid, d.creator_fee(sub))
        if not chain.graduated(h - 1):
            minted[curve] += sub
        else:
            case.assertEqual(curve, "btc", "no block is on the QWEN curve once the launch has graduated")
    graduated_at = next((h for h in range(1, chain.height + 1) if chain.graduated(h)), chain.height)
    wb, wq = chain.works_at(graduated_at)
    case.assertEqual((minted["btc"], minted["qwen"]), (d.curve_supply(wb), d.curve_supply(wq)))
    return minted


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

    def test_a_miner_started_before_its_pool_listens_waits_for_it(self):
        """`hashfun mine` starts a pool and a miner together, and the pool opens its port only once its
        node has given it a first template: a miner that is refused tries again, it does not end."""
        d = small_launch(graduation_blocks=1000)
        chain = SimChain("TST", d)
        L = Loop()
        port = free_port()
        srv = StratumServer(LaunchSource(chain, d.hrp, d.ticker), "127.0.0.1", port, difficulty=1e-6, poll_interval=0.05)
        self.assertFalse(srv.listening)
        m = StratumMiner("127.0.0.1", port, addr(d.hrp), batch=4096, max_shares=1)
        fut = L.spawn(m.run(duration=30))
        time.sleep(1.0)
        self.assertFalse(fut.done(), "nothing listens yet: the miner is still knocking")
        L.spawn(srv.serve())
        res = fut.result(60)
        self.assertTrue(srv.listening)
        self.assertGreaterEqual(res["accepted"], 1)
        self.assertGreaterEqual(chain.height, 1)

    def test_a_miner_mines_the_curve_its_username_names(self):
        """Two miners on one pool, one per curve: each one's blocks are on its own curve (the bit in
        the header, the mint from that curve's own work), and a name that asks for a curve that does
        not exist gets no work rather than the other curve's."""
        d = small_launch(graduation_blocks=1000)
        chain = SimChain("TST", d)
        L = Loop()
        port = free_port()
        src = LaunchSource(chain, d.hrp, d.ticker)                         # the pool's default curve: BTC
        srv = StratumServer(src, "127.0.0.1", port, difficulty=1e-6, poll_interval=0.05)
        L.spawn(srv.serve())
        time.sleep(0.3)
        on_btc, on_qwen, named_btc = addr(d.hrp), addr(d.hrp), addr(d.hrp)
        miners = [StratumMiner("127.0.0.1", port, on_btc, batch=4096),
                  StratumMiner("127.0.0.1", port, on_qwen + "/qwen,bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080.rig1", batch=4096),
                  StratumMiner("127.0.0.1", port, named_btc + "/btc", batch=4096)]
        want = {address_to_script(a, d.hrp): c for a, c in ((on_btc, "btc"), (on_qwen, "qwen"), (named_btc, "btc"))}
        t0, seen = time.time(), {}
        while (len(seen) < 3 or min(seen.values()) < 2) and time.time() - t0 < 120:
            for m in miners:
                L.run(m.run(duration=1))
            seen = {}
            for b in chain.blocks[1:]:
                seen[b.txs[0].vout[0].script_pubkey] = seen.get(b.txs[0].vout[0].script_pubkey, 0) + 1
        self.assertEqual(set(seen), set(want), "every miner found blocks")
        for b in chain.blocks[1:]:
            self.assertEqual(D.curve_of_version(b.version), want[b.txs[0].vout[0].script_pubkey])
        minted = curve_consistent(self, chain)
        self.assertTrue(minted["btc"] > 0 and minted["qwen"] > 0)
        wb, wq = chain.works_at()
        from hashfun.ser import work_from_bits
        self.assertEqual((wb, wq), (sum(work_from_bits(b.bits) for b in chain.blocks[1:] if not b.version & 0x200),
                                    sum(work_from_bits(b.bits) for b in chain.blocks[1:] if b.version & 0x200)))
        self.assertEqual({e["curve"] for e in srv.events if e["kind"] == "block" and e["result"] is None}, {"btc", "qwen"})
        info = chain.getlaunchinfo()
        self.assertEqual((info["curves"]["btc"]["supply"], info["curves"]["qwen"]["supply"]), (minted["btc"], minted["qwen"]))
        # a curve that is not one: refused at the door
        async def ask(user):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write((json.dumps({"id": 1, "method": "mining.subscribe", "params": []}) + "\n").encode())
            await r.readline()
            w.write((json.dumps({"id": 2, "method": "mining.authorize", "params": [user, "x"]}) + "\n").encode())
            answer = json.loads(await r.readline())
            w.close()
            return answer
        refused = L.run(ask(addr(d.hrp) + "/doge"))
        self.assertEqual(refused["result"], False)
        self.assertIn("'doge' is not a curve", refused["error"][1])
        self.assertEqual(L.run(ask(addr(d.hrp) + "/QWEN"))["result"], True)
        # the pool's own default can be the QWEN curve
        self.assertEqual(LaunchSource(chain, d.hrp, d.ticker, curve="qwen").curve_of(addr(d.hrp)), "qwen")
        with self.assertRaises(ValueError):
            LaunchSource(chain, d.hrp, d.ticker, curve="doge")

    def test_after_graduation_there_is_no_curve_to_choose(self):
        d = small_launch("GRD", graduation_blocks=4)
        chain = SimChain("GRD", d)
        chain.mine(1)                                                       # one block on the BTC curve,
        on_qwen = 0
        while not chain.graduated():                                        # then the QWEN curve until it has sold out
            self.assertIn("launchcurves", chain.getblocktemplate())
            chain.mine(1, curve="qwen")
            on_qwen += 1
        wb, wq = chain.works_at()
        self.assertTrue(wq >= d.graduation_work > wb > 0)
        info = chain.getlaunchinfo()
        self.assertEqual((info["graduated_by"], info["curves"]["qwen"]["blocks"], info["curves"]["btc"]["blocks"]),
                         ("qwen", on_qwen, 1))
        self.assertLess(info["curve_supply"], 2 * d.graduation_tokens)      # the BTC curve's rest is never minted
        self.assertEqual(info["curves"]["qwen"]["supply"], d.graduation_tokens)
        chain.mine(2, curve="qwen")                                         # the miner still says qwen: its blocks are tail blocks
        self.assertTrue(all(not b.version & 0x200 for b in chain.blocks[-2:]))
        self.assertNotIn("launchcurves", chain.getblocktemplate())
        b = chain.build_block(p2wpkh_script(pubkey_from_priv(5)))
        b.header = (int.from_bytes(b.header[:4], "little") | 0x200).to_bytes(4, "little") + b.header[4:]
        nonce = 0                                                           # a block with work, so that the bit is all that is wrong
        while int.from_bytes(sha256d(b.header[:76] + struct.pack("<I", nonce)), "little") > bits_to_target(b.bits):
            nonce += 1
        b.header = b.header[:76] + struct.pack("<I", nonce)
        self.assertEqual(chain.connect(b), "bad-curve-version")
        src = LaunchSource(chain, d.hrp, d.ticker)
        L = Loop()
        self.assertTrue(L.run(src.refresh()))
        job = src.make_job("1", addr(d.hrp) + "/qwen", True)
        self.assertEqual((job.version & 0x200, job.ctx["curve"]), (0, None))
        curve_consistent(self, chain)

    def test_the_site_queue_mines_each_buyer_a_block_on_the_curve_they_chose(self):
        from hashfun.sitepool import QUEUE_USER, QueueSource
        d = small_launch("QUE", graduation_blocks=1000)
        chain = SimChain("QUE", d)
        operator, alice, bob = addr(d.hrp), addr(d.hrp), addr(d.hrp)
        L = Loop()
        port = free_port()
        src = QueueSource(chain, d.hrp, d.ticker, operator=operator, cut_bps=500, curves=("btc", "qwen"))
        srv = StratumServer(src, "127.0.0.1", port, difficulty=1e-6, poll_interval=0.05)
        L.spawn(srv.serve())
        time.sleep(0.3)
        self.assertEqual((src.enqueue(alice, 2, "qwen"), src.enqueue(bob, 1, "btc"), src.enqueue(alice, 5, "btc")), (0, 2, 0))
        self.assertEqual((src.queue, src.queued()), ([(alice, "qwen"), (alice, "qwen"), (bob, "btc"), (alice, "btc")],
                                                     {"btc": 2, "qwen": 2}))   # three blocks an address, whatever the curves
        for bad, why in (((alice, 1, "doge"), "not a curve"), ((alice, 1, "btc"), "already waits"), (("bc1qnotours", 1, "btc"), "")):
            with self.assertRaises(Exception) as e:
                src.enqueue(*bad)
            self.assertIn(why, str(e.exception))
        m = StratumMiner("127.0.0.1", port, QUEUE_USER, batch=4096)
        t0 = time.time()
        while src.queue and time.time() - t0 < 120:
            L.run(m.run(duration=1))
        self.assertEqual(src.queue, [])
        paid = [(b.txs[0].vout[0].script_pubkey, D.curve_of_version(b.version)) for b in chain.blocks[1:5]]
        spk = lambda a: address_to_script(a, d.hrp)  # noqa: E731
        self.assertEqual(paid, [(spk(alice), "qwen"), (spk(alice), "qwen"), (spk(bob), "btc"), (spk(alice), "btc")])
        for h in range(1, 5):                                               # the operator's share is output 1, of that curve's mint
            b = chain.blocks[h]
            value = chain.subsidy(h, b.bits, D.curve_of_version(b.version)) - d.creator_fee(chain.subsidy(h, b.bits, D.curve_of_version(b.version)))
            self.assertEqual((b.txs[0].vout[0].value, b.txs[0].vout[1].value, b.txs[0].vout[1].script_pubkey),
                             (value - value * 500 // 10_000, value * 500 // 10_000, spk(operator)))
        curve_consistent(self, chain)
        # a site with no Qwencoin node mines the BTC curve only, and says why
        btc_only = QueueSource(chain, d.hrp, d.ticker, curves=("btc",))
        with self.assertRaisesRegex(ValueError, "cannot mine the QWEN curve: it has no Qwencoin node"):
            btc_only.enqueue(alice, 1, "qwen")
        self.assertIn("cannot settle blocks on the QWEN curve", btc_only.check_username(alice + "/qwen"))
        self.assertIsNone(btc_only.check_username(alice))
        self.assertIsNone(btc_only.check_username(QUEUE_USER))
        self.assertEqual(btc_only.enqueue(alice, 1), 0)

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


    def test_presale_hash_secures_graduated_launches(self):
        # A pool mining PRE's curve commits GRAD's aux block in its PRE coinbase: every share
        # that meets GRAD's target extends GRAD with a PRE header as the AuxPoW parent.
        grad = small_launch("GRAD", graduation_blocks=8)
        pre = small_launch("PRE", graduation_blocks=10_000)
        other = small_launch("OTH", graduation_blocks=10_000)
        cg, cp, co = SimChain("GRAD", grad), SimChain("PRE", pre), SimChain("OTH", other)
        cg.mine(12)
        self.assertTrue(cg.graduated())
        L = Loop()
        port = free_port()
        children = {"GRAD": {"rpc": cg, "hrp": grad.hrp, "payout": addr(grad.hrp)},
                    "OTH": {"rpc": co, "hrp": other.hrp, "payout": addr(other.hrp)},
                    "PRE": {"rpc": cp, "hrp": pre.hrp, "payout": addr(pre.hrp)}}
        src = LaunchSource(cp, pre.hrp, pre.ticker, children=children)
        self.assertNotIn("PRE", src.auxset.children)  # a chain never merge-mines itself
        srv = StratumServer(src, "127.0.0.1", port, difficulty=1e-6, poll_interval=0.05)
        L.spawn(srv.serve())
        time.sleep(0.3)
        h_grad, h_oth = cg.height, co.height
        m = StratumMiner("127.0.0.1", port, addr(pre.hrp), batch=4096)
        t0 = time.time()
        while (cg.height < h_grad + 3 or cp.height < 3) and time.time() - t0 < 90:
            L.run(m.run(duration=2))
        self.assertGreaterEqual(cp.height, 3)
        self.assertGreaterEqual(cg.height, h_grad + 3)
        self.assertEqual(co.height, h_oth, "an ungraduated launch must not be merge-mined")
        aux_blocks = [b for b in cg.blocks[h_grad + 1:] if b.auxpow]
        self.assertTrue(aux_blocks)
        pre_chain_id = pre.chain_id
        for b in aux_blocks:
            parent_version = int.from_bytes(b.auxpow[-80:-76], "little", signed=True)
            self.assertEqual(parent_version >> 16, pre_chain_id, "the AuxPoW parent is a PRE header")
        curve_consistent(self, cp)
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
        # What the proxy decides is the miner's time: three quarters of it to the pool of weight 3.
        # That is what is measured. The work each pool then accepts follows the time only roughly
        # on a test chain: nearly every share is a block there, a pool whose tip has just moved
        # turns down what was still being hashed on the old one, and the busier pool's tip moves
        # more often. So of the work only this is asked: both pools got some, the heavier not less.
        self.assertAlmostEqual(st["AAA"]["time"], 0.75, delta=0.06)
        self.assertAlmostEqual(st["BBB"]["time"], 0.25, delta=0.06)
        self.assertGreater(st["AAA"]["delivered"], 0.4)
        self.assertGreater(st["BBB"]["delivered"], 0.05)


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

    def test_1b_btc_yield_lands_on_launch_keys_and_is_claimable(self):
        # The sats leg pays holders on Bitcoin at their launch scriptPubKey. The wallet holds
        # launch coins at SWP key 0/0, so BTC sent to that same script is its yield.
        launch_key = self.w.chains["SWP"].key(0, 0)
        launch_spk = address_to_script(self.w.chains["SWP"].address(0, 0), self.fd.hrp)
        self.assertEqual(launch_spk, address_to_script(segwit_encode("bcrt", 0, launch_spk[2:]), "bcrt"))
        self.assertEqual(self.w.yield_balance(), {})
        self.btc.mine(2, launch_spk)  # two "yield payments"
        self.btc.mine(1)
        self.sync()
        paid = sum(self.btc.blocks[h].txs[0].vout[0].value for h in (self.btc.height - 2, self.btc.height - 1))
        self.assertEqual(self.w.yield_balance(), {"SWP": paid})
        self.assertNotIn(launch_key.pub(), [k.pub() for k in self.w.chains["BTC"].used_keys()])
        before = self.w.chains["BTC"].balance()["confirmed"]
        txid = self.w.claim_yield(feerate=2)
        self.assertIn(bytes.fromhex(txid)[::-1], self.btc.mempool)
        self.btc.mine(1)
        self.sync()
        after = self.w.chains["BTC"].balance()["confirmed"]
        self.assertTrue(paid - 1000 < after - before <= paid, (before, after, paid))
        self.assertEqual(self.w.yield_balance(), {})
        self.assertIsNone(self.w.claim_yield())

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


class SettlerRelays(unittest.TestCase):
    """What the settler puts into a coinbase for the launch's two header relays, with a wallet on a
    chain, with only a node of it (it relays, and pays nothing there), and with neither."""

    class Chain:
        """A quote chain's node, as far as relaying asks it: a list of headers (height = position). It
        has no wallet calls at all: a settler that tried to pay through it would fail the test."""

        def __init__(self, n, salt):
            self.headers = [bytes([salt, h % 256]) * 40 for h in range(n)]
            self.asked = []

        def getblockcount(self):
            return len(self.headers) - 1

        def getblockhash(self, height):
            return f"{self.headers[height][0]:02x}{height:062x}"

        def getblockheader(self, block_hash, verbose=True):
            self.asked.append(int(block_hash[2:], 16))
            return self.headers[int(block_hash[2:], 16)].hex()

    class Launch:
        """The launch node: where each relay stands, and one block of ours on the QWEN curve that owes."""

        def __init__(self, btc, qwen, at):
            self.chains, self.at = {"btc": btc, "qwen": qwen}, dict(at)

        def _relay(self, quote):
            h = self.at[quote]
            return {"height": h, "best": self.chains[quote].getblockhash(h), "anchor_height": 0, "confirmations_required": 1}

        def getbtcrelay(self):
            return self._relay("btc")

        def getqwenrelay(self):
            return self._relay("qwen")

        def getlaunchinfo(self):
            return {"graduated": False, "height": 20}

        def getblockcount(self):
            return 20

        def getmintobligation(self, height):
            return {"height": height, "hash": "ab" * 32, "curve": True, "quote": "qwen", "owed": 7000, "draw_known": True,
                    "draw_height": height + 6, "settled": False, "spendable": False, "deadline_height": height + 110,
                    "tag": "cd" * 20, "pay": 7000, "payee": "creator", "pay_script": "0014" + "33" * 20, "earning": 0}

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hf-settler-")
        self.btc, self.qwen = self.Chain(40, 0xB1), self.Chain(40, 0xC2)
        self.launch = self.Launch(self.btc, self.qwen, {"btc": 10, "qwen": 10})

    def settler(self, *wallets, **kw):
        from hashfun.settler import Settler
        return Settler(self.launch, *wallets, os.path.join(self.tmp, f"s{len(os.listdir(self.tmp))}.json"), pay_depth=0, **kw)

    def relayed(self, outs):
        """{tag: [heights]} of the header outputs."""
        from hashfun import yieldmodel as Y
        got = {}
        for o in outs:
            for tag, chain in ((b"HFH1", self.btc), (b"HFH2", self.qwen)):
                data = Y.tagged_return(o.script_pubkey, tag)
                if data is not None:
                    got[tag.decode()] = [chain.headers.index(h) for h in Y.parse_btc_headers(data)]
        return got

    def test_a_chain_with_only_a_node_is_relayed_and_never_paid(self):
        s = self.settler(None, qwen_node=self.qwen)
        self.assertEqual(self.relayed(s.relay_outputs()), {"HFH2": list(range(11, 19))})  # the oldest eight it lacks
        self.assertEqual((s.status()["wallets"], s.status()["relays"]), ([], ["qwen"]))
        # a block of ours on the QWEN curve: it owes, and this settler has nothing to pay it with
        s.add_block(12, "ab" * 32)
        with self.assertLogs("hashfun.settler", level="ERROR") as said:
            outs = s.coinbase_outputs()
            s.coinbase_outputs()
        self.assertEqual(len(said.output), 1)                                  # said once
        self.assertIn("this settler has no Qwencoin wallet", said.output[0])
        self.assertEqual((s.st["paid"], s.st["mine"]), ({}, [[12, "ab" * 32]]))  # not paid, not forgotten
        self.assertEqual(self.relayed(outs), {"HFH2": list(range(11, 19))})

    def test_each_chain_by_its_wallet_or_its_node(self):
        both = self.settler(self.btc, qwen_node=self.qwen)                     # a Bitcoin wallet, a Qwencoin node
        self.assertEqual(self.relayed(both.relay_outputs()), {"HFH1": list(range(11, 40)), "HFH2": list(range(11, 19))})
        self.assertEqual((both.status()["wallets"], both.status()["relays"]), (["btc"], ["btc", "qwen"]))
        other = self.settler(None, qwen_wallet=self.qwen, btc_node=self.btc)   # the other way round
        self.assertEqual(self.relayed(other.relay_outputs()), {"HFH1": list(range(11, 40)), "HFH2": list(range(11, 19))})
        self.assertEqual((other.status()["wallets"], other.status()["relays"]), (["qwen"], ["btc", "qwen"]))
        one = self.settler(self.btc)                                           # one wallet and nothing of the other chain
        self.assertEqual(self.relayed(one.relay_outputs()), {"HFH1": list(range(11, 40))})
        self.assertEqual(one.status()["relays"], ["btc"])
        self.assertEqual(self.settler(None).relay_outputs(), [])               # nothing of either
        # a node given next to a wallet is the one the headers are read from
        spare = self.Chain(40, 0xC2)
        s = self.settler(None, qwen_wallet=self.qwen, qwen_node=spare)
        self.qwen.asked.clear()
        self.assertEqual(self.relayed(s.relay_outputs()), {"HFH2": list(range(11, 19))})
        self.assertEqual((self.qwen.asked, spare.asked), ([], list(range(11, 19))))

    def test_qwencoin_headers_go_eight_to_a_block_oldest_first(self):
        s = self.settler(None, qwen_node=self.qwen)
        seen = []
        while True:
            got = self.relayed(s.relay_outputs()).get("HFH2", [])
            if not got:
                break
            self.assertLessEqual(len(got), 8)
            seen += got
            self.launch.at["qwen"] = got[-1]  # the node took them
        self.assertEqual(seen, list(range(11, 40)))


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
