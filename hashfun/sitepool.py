"""The site's own mining, so that nobody needs to install anything to get a coin.

For every launch the site serves it runs:

  - a public stratum endpoint (one port per launch, P2P port + 2). Anyone points SHA-256 hash at
    it with their launch address as the username and the blocks they find pay that address
    directly, as on any solo pool.
  - a queue of buyers. "Mine me a block" on the page puts the visitor's launch address in it;
    the server's own CPU mines (only while the queue is not empty) and each block it finds pays
    the address at the head of the queue, less the operator's share.

Whoever a block pays owes that block's sats, as consensus says, and pays them from their own
wallet on the page (one Bitcoin transaction, tagged). The WatchSettler sees the payment on
Bitcoin and publishes the proof in a later block: the site holds no Bitcoin and no coins of
anyone's, and pays nothing.
"""
import asyncio
import logging
import os
import threading
import time
from typing import Dict, List, Optional

from .miner import StratumMiner
from .ser import TxOut, address_to_script
from .settler import WatchSettler
from .stratum import Job, LaunchSource, StratumServer

log = logging.getLogger("hashfun.sitepool")

QUEUE_USER = "@queue"
MAX_QUEUE = 50
MAX_PER_ADDRESS = 3


class QueueSource(LaunchSource):
    """A LaunchSource whose jobs for QUEUE_USER pay the head of the buyers' queue."""

    def __init__(self, *a, operator: Optional[str] = None, cut_bps: int = 0, **kw):
        super().__init__(*a, **kw)
        self.queue: List[str] = []
        self.operator, self.cut_bps = operator, max(0, min(5000, cut_bps))
        self.qlock = threading.Lock()

    def payout_script(self, username: str) -> bytes:
        if username == QUEUE_USER:
            with self.qlock:
                if self.queue:
                    return address_to_script(self.queue[0], self.hrp)
            if self.operator:  # a block to carry draws and proofs nobody else is mining for
                return address_to_script(self.operator, self.hrp)
            raise RuntimeError("nobody is queued")
        return super().payout_script(username)

    def make_job(self, job_id: str, username: str, clean: bool) -> Job:
        job = super().make_job(job_id, username, clean)
        if username != QUEUE_USER:
            return job
        with self.qlock:
            owner = self.queue[0] if self.queue else None
        job.ctx["queue_owner"] = owner
        if owner and self.operator and self.cut_bps:
            # Rebuild the coinbase with the operator's share as output 1 (output 0 stays the buyer:
            # a yield redirect only ever applies to output 0).
            t = self.tmpl
            cut = t["coinbasevalue"] * self.cut_bps // 10_000
            return self._job_with_outputs(job_id, clean, [
                TxOut(t["coinbasevalue"] - cut, address_to_script(owner, self.hrp)),
                TxOut(cut, address_to_script(self.operator, self.hrp))], owner)
        return job

    def _job_with_outputs(self, job_id, clean, first: List[TxOut], owner: str) -> Job:
        from .stratum import _cb_prefix, _gbt_txs, coinbase_parts, merkle_branch_for_first
        t = self.tmpl
        outs = list(first)
        if "creatorfee" in t:
            outs.append(TxOut(t["creatorfee"]["amount"], bytes.fromhex(t["creatorfee"]["script"])))
        outs += self.settle_outs
        has_commit = "default_witness_commitment" in t
        if has_commit:
            outs.append(TxOut(0, bytes.fromhex(t["default_witness_commitment"])))
        extra, auxctx = self.auxset.commit()
        c1, c2 = coinbase_parts(t["height"], outs, extra=extra, prefix=_cb_prefix(t))
        txids, datas = _gbt_txs(t)
        return Job(job_id, self, bytes.fromhex(t["previousblockhash"])[::-1], c1, c2,
                   merkle_branch_for_first([b"\0" * 32] + txids), t["version"], int(t["bits"], 16), t["curtime"],
                   t["height"], datas, has_commit, clean,
                   {"target": int(t["target"], 16), "fixed_ntime": True, "queue_owner": owner, **auxctx})

    async def on_solution(self, job, header, coinbase, hash_int):
        evs = await super().on_solution(job, header, coinbase, hash_int)
        owner = job.ctx.get("queue_owner")
        if owner and any(e.get("kind") == "block" and e.get("result") is None for e in evs or []):
            with self.qlock:
                if self.queue and self.queue[0] == owner:
                    self.queue.pop(0)
            self.last_full = 0  # the next job pays the next in line
        return evs

    def enqueue(self, address: str, blocks: int = 1) -> int:
        address_to_script(address, self.hrp)  # refuses anything that is not this launch's address
        with self.qlock:
            have = self.queue.count(address)
            n = max(0, min(blocks, MAX_PER_ADDRESS - have, MAX_QUEUE - len(self.queue)))
            if n == 0:
                raise ValueError("the queue is full, or this address already waits for its blocks")
            self.queue.extend([address] * n)
            return self.queue.index(address)


class SitePools:
    """One asyncio loop in a thread: a stratum server and a settler per launch, and one CPU miner
    per launch that runs only while someone is queued."""

    def __init__(self, site, operator: Dict[str, str] = None, cut_bps: int = 0, cpu: bool = True,
                 host: str = "0.0.0.0", duty: float = 1.0):
        self.site, self.cut_bps, self.cpu, self.host, self.duty = site, cut_bps, cpu, host, duty
        self.operator = operator if operator is not None else {}
        self.pools: Dict[str, dict] = {}
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(lambda _l, c: log.error("pool: %s %r", c.get("message"), c.get("exception")))
        threading.Thread(target=self.loop.run_forever, daemon=True, name="sitepool").start()

    def port_of(self, ticker: str) -> int:
        e = self.site.reg.data.get(ticker) or {}
        return (e.get("p2pport") or self.site.reg.desc(ticker).p2p) + 2

    def ensure(self, ticker: str, rpc, d):
        """Start the pool of a launch the site serves (idempotent)."""
        if ticker in self.pools:
            return
        state = os.path.join(os.path.dirname(self.site.reg.get(ticker)["descriptor"]), "site-settler.json")
        settler = WatchSettler(rpc, self.site.btc, state)
        src = QueueSource(rpc, d.hrp, ticker, settler=settler, yield_hrp=self.site.btc_hrp,
                          operator=self.operator.get(ticker), cut_bps=self.cut_bps)
        port = self.port_of(ticker)
        srv = StratumServer(src, self.host, port)
        p = {"src": src, "srv": srv, "settler": settler, "port": port, "miner": None}
        self.pools[ticker] = p
        asyncio.run_coroutine_threadsafe(srv.serve(), self.loop)
        if self.cpu:
            asyncio.run_coroutine_threadsafe(self._drive(ticker), self.loop)
        log.info("[%s] stratum on %s:%d", ticker, self.host, port)

    async def _drive(self, ticker: str):
        """Run the CPU miner while the queue is not empty."""
        p = self.pools[ticker]
        while True:
            try:
                await self._drive_once(p)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("[%s] miner", ticker)
                await asyncio.sleep(5)

    async def _drive_once(self, p):
        while True:
            await asyncio.sleep(1)
            if p["src"].tmpl is None or not await asyncio.to_thread(self._wanted, p):
                continue
            m = StratumMiner("127.0.0.1", p["port"], QUEUE_USER, duty=self.duty)
            p["miner"] = m
            task = asyncio.ensure_future(m.run())
            while not task.done() and await asyncio.to_thread(self._wanted, p):
                await asyncio.sleep(1)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                log.warning("[%s] miner stopped: %s", p["src"].ticker, e)
            p["miner"] = None

    def _wanted(self, p) -> bool:
        """Mine now? For a queued visitor; and, with an operator address to pay, while a block
        someone owes for waits for its draw or a payment waits for its proof (on a quiet launch
        nobody else would mine the blocks that carry them)."""
        if p["src"].queue:
            return True
        if not p["src"].operator:
            return False
        try:
            return p["settler"].needs_blocks()
        except Exception:
            return False

    def info(self, ticker: str) -> Optional[dict]:
        p = self.pools.get(ticker)
        if not p:
            return None
        src = p["src"]
        return {"stratum_port": p["port"], "queue": len(src.queue), "mining": p["miner"] is not None,
                "cut_bps": src.cut_bps if src.operator else 0, "settler": p["settler"].status()}

    def enqueue(self, ticker: str, address: str, blocks: int = 1) -> dict:
        p = self.pools.get(ticker)
        if not p:
            raise KeyError("this site does not mine that launch")
        pos = p["src"].enqueue(address, blocks)
        return {"position": pos, "queue": len(p["src"].queue), "at": time.time()}

    def due(self, ticker: str, script_hex: str) -> List[dict]:
        p = self.pools.get(ticker)
        if not p:
            raise KeyError("this site does not mine that launch")
        return p["settler"].due(script_hex)
