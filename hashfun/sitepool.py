"""The site's own mining, so that nobody needs to install anything to get a coin.

For every launch the site serves it runs:

  - a public stratum endpoint (one port per launch, P2P port + 2). Anyone points SHA-256 hash at
    it with their launch address as the username and the blocks they find pay that address
    directly, as on any solo pool. "ADDRESS/btc" or "ADDRESS/qwen" picks the curve.
  - a queue of buyers. "Mine me a block" on the page puts the visitor's launch address in it, with
    the curve the visitor chose; the server's own CPU mines (only while the queue is not empty) and
    each block it finds pays the address at the head of the queue, on that entry's curve, less the
    operator's share.

Whoever a block pays owes what that block owes, as consensus says: sats on Bitcoin for a block on
the BTC curve, qwen on Qwencoin for one on the QWEN curve, paid from their own wallet on the page
(one transaction on that chain, tagged). The WatchSettler sees the payment and publishes the proof
in a later block: the site holds no Bitcoin, no qwen and no coins of anyone's, and pays nothing.
A site without a Qwencoin node could not see a payment made there, so it mines the BTC curve only.
"""
import asyncio
import logging
import os
import threading
import time
from typing import Dict, List, Optional, Tuple

from .miner import StratumMiner
from .ser import TxOut, address_to_script
from .settler import CHAIN_NAME, WatchSettler
from .stratum import CURVES, Job, LaunchSource, StratumServer, split_username

log = logging.getLogger("hashfun.sitepool")

QUEUE_USER = "@queue"
MAX_QUEUE = 50
MAX_PER_ADDRESS = 3


class QueueSource(LaunchSource):
    """A LaunchSource whose jobs for QUEUE_USER pay the head of the buyers' queue, on its curve."""

    def __init__(self, *a, operator: Optional[str] = None, cut_bps: int = 0, curves=("btc",), **kw):
        """curves: the curves this pool can mine and see settled (those the site has a node of the
        quote chain for). Nobody is queued or served on any other."""
        super().__init__(*a, **kw)
        self.queue: List[Tuple[str, str]] = []  # (launch address, curve), first in line first
        self.curves = tuple(c for c in CURVES if c in curves)
        self.operator, self.cut_bps = operator, max(0, min(5000, cut_bps))
        self.qlock = threading.Lock()

    def head(self) -> Optional[Tuple[str, str]]:
        with self.qlock:
            return self.queue[0] if self.queue else None

    def queued(self) -> Dict[str, int]:
        with self.qlock:
            return {c: sum(1 for _, x in self.queue if x == c) for c in CURVES}

    def check_username(self, username: str) -> Optional[str]:
        if username == QUEUE_USER:
            return None
        why = super().check_username(username)
        if why:
            return why
        curve = split_username(username)[1] or self.curve
        if curve not in self.curves:
            return (f"this site cannot settle blocks on the {curve.upper()} curve (it has no {CHAIN_NAME[curve]} node to see "
                    f"their payments on): mine {' or '.join('ADDRESS/' + c for c in self.curves)}")
        return None

    def curve_of(self, username: str) -> str:
        if username == QUEUE_USER:
            head = self.head()
            return head[1] if head else self.curve
        return super().curve_of(username)

    def payout_script(self, username: str) -> bytes:
        if username == QUEUE_USER:
            head = self.head()
            if head:
                return address_to_script(head[0], self.hrp)
            if self.operator:  # a block to carry draws and proofs nobody else is mining for
                return address_to_script(self.operator, self.hrp)
            raise RuntimeError("nobody is queued")
        return super().payout_script(username)

    def make_job(self, job_id: str, username: str, clean: bool) -> Job:
        if username != QUEUE_USER:
            return super().make_job(job_id, username, clean)
        owner = self.head()
        if owner is None:
            job = super().make_job(job_id, username, clean)  # the operator's own block, on the pool's curve
            job.ctx["queue_owner"] = None
            return job
        address, curve = owner
        value = self.curve_values(curve)["coinbasevalue"]
        cut = value * self.cut_bps // 10_000 if self.operator and self.cut_bps else 0
        # The operator's share is output 1; output 0 stays the buyer (a yield redirect only ever
        # applies to output 0).
        payout = [TxOut(value - cut, address_to_script(address, self.hrp))]
        if cut:
            payout.append(TxOut(cut, address_to_script(self.operator, self.hrp)))
        return self.build_job(job_id, clean, curve, payout, ctx={"queue_owner": owner})

    async def on_solution(self, job, header, coinbase, hash_int):
        evs = await super().on_solution(job, header, coinbase, hash_int)
        owner = job.ctx.get("queue_owner")
        if owner and any(e.get("kind") == "block" and e.get("result") is None for e in evs or []):
            with self.qlock:
                if self.queue and self.queue[0] == tuple(owner):
                    self.queue.pop(0)
            self.last_full = 0  # the next job pays the next in line
        return evs

    def enqueue(self, address: str, blocks: int = 1, curve: str = "btc") -> int:
        """Put an address in line for `blocks` blocks on `curve`. Returns its place in the queue.
        ValueError: that curve cannot be mined here, or there is no room."""
        if curve not in CURVES:
            raise ValueError(f"'{curve}' is not a curve: btc or qwen")
        if curve not in self.curves:
            raise ValueError(f"this site cannot mine the {curve.upper()} curve: it has no {CHAIN_NAME[curve]} node, and "
                             "could not see what such a block owes being paid")
        if self.tmpl is not None and not self.on_curves():
            raise ValueError("this coin has graduated: its curves are closed and there is nothing left to mine this way")
        address_to_script(address, self.hrp)  # refuses anything that is not this launch's address
        with self.qlock:
            have = sum(1 for a, _ in self.queue if a == address)
            n = max(0, min(blocks, MAX_PER_ADDRESS - have, MAX_QUEUE - len(self.queue)))
            if n == 0:
                raise ValueError("the queue is full, or this address already waits for its blocks")
            was_empty = not self.queue
            self.queue.extend([(address, curve)] * n)
            place = next(i for i, (a, _) in enumerate(self.queue) if a == address)
        if was_empty:
            self.last_full = self.last_push = 0  # the miner may be on the operator's job: hand it the buyer's now
        return place


class SitePools:
    """One asyncio loop in a thread: a stratum server and a settler per launch, and one CPU miner
    per launch that runs only while someone is queued."""

    def __init__(self, site, operator: Dict[str, str] = None, cut_bps: int = 0, cpu: bool = True,
                 host: str = "0.0.0.0", duty: float = 1.0):
        """site: what the pools read of it: `reg`, `btc` and `btc_hrp`, and `qwen` (the RPC of the
        site's Qwencoin node, or None / not there: then only the BTC curve is mined here)."""
        self.site, self.cut_bps, self.cpu, self.host, self.duty = site, cut_bps, cpu, host, duty
        self.operator = operator if operator is not None else {}
        self.pools: Dict[str, dict] = {}
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(lambda _l, c: log.error("pool: %s %r", c.get("message"), c.get("exception")))
        threading.Thread(target=self.loop.run_forever, daemon=True, name="sitepool").start()

    def curves(self) -> List[str]:
        """The curves this site can mine and see settled: those whose quote chain it has a node of."""
        return [c for c in CURVES if getattr(self.site, c, None) is not None]

    def port_of(self, ticker: str) -> int:
        e = self.site.reg.data.get(ticker) or {}
        return (e.get("p2pport") or self.site.reg.desc(ticker).p2p) + 2

    def ensure(self, ticker: str, rpc, d):
        """Start the pool of a launch the site serves (idempotent)."""
        if ticker in self.pools:
            return
        state = os.path.join(os.path.dirname(self.site.reg.get(ticker)["descriptor"]), "site-settler.json")
        curves = self.curves()
        settler = WatchSettler(rpc, getattr(self.site, "btc", None), state, qwen=getattr(self.site, "qwen", None))
        src = QueueSource(rpc, d.hrp, ticker, settler=settler, yield_hrp=self.site.btc_hrp,
                          operator=self.operator.get(ticker), cut_bps=self.cut_bps, curves=curves,
                          curve=curves[0] if curves else "btc")
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
        if p["src"].head():
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
        queues = src.queued()
        return {"stratum_port": p["port"], "queue": sum(queues.values()), "queues": queues, "curves": list(src.curves),
                "mining": p["miner"] is not None, "cut_bps": src.cut_bps if src.operator else 0,
                "settler": p["settler"].status()}

    def enqueue(self, ticker: str, address: str, blocks: int = 1, curve: str = "btc") -> dict:
        """Queue an address for blocks on a curve. KeyError: the site does not mine that launch.
        ValueError: the curve cannot be mined here (no node of its chain, graduated, not a curve),
        or the queue has no room."""
        p = self.pools.get(ticker)
        if not p:
            raise KeyError("this site does not mine that launch")
        pos = p["src"].enqueue(address, blocks, curve)
        return {"position": pos, "queue": sum(p["src"].queued().values()), "at": time.time(), "curve": curve}

    def due(self, ticker: str, script_hex: str) -> List[dict]:
        """What the blocks paying that script owe and have not paid: each with `quote` ("btc" or
        "qwen": the chain to pay on), `pay` in base units of that quote, `pay_script`, `tag`, `key`,
        `paid`, `height`, `deadline_height`."""
        p = self.pools.get(ticker)
        if not p:
            raise KeyError("this site does not mine that launch")
        return p["settler"].due(script_hex)
