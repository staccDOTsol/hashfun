"""Stratum v1 pool for hashfun launches, with merged mining.

Two job sources share one stratum frontend:

  LaunchSource  - direct (standalone) mining of one launch chain via GBT.
                  Coinbase: miner payout + mandatory creator output + witness
                  commitment. Solo/non-custodial: each miner's coinbase pays the
                  address it authorized with.
  MergedSource  - BTC parent (stock bitcoind GBT) with an AuxPoW commitment to
                  every *graduated* launch in the parent coinbase. A share that
                  meets a child's target is submitted there via submitauxblock;
                  one that meets BTC's target goes to bitcoind.

Usernames: "<payout_address>[.<worker>]". For merged mining the parent payout is
the username address; child payouts default to the pool config's aux_payout map
and can be overridden: "<btc_addr>,<TICKER>=<addr>,...".
"""
import asyncio
import json
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .auxpow import AuxTree, serialize_auxpow, check_auxpow
from .crypto import sha256d
from .yieldmodel import yield_tag_script
from .rpc import RPC, RPCError
from .ser import (Tx, TxIn, TxOut, varint, push, push_int, merkle_branch_for_first, root_from_branch,
                  bits_to_target, header_bytes, address_to_script, Reader)

log = logging.getLogger("hashfun.pool")

DIFF1_TARGET = 0xFFFF * 2**208
EN1_SIZE = 4
EN2_SIZE = 4


def swap32_words(b: bytes) -> bytes:
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b), 4))


def target_for_difficulty(diff: float) -> int:
    return min(int(DIFF1_TARGET / diff), 2**256 - 1)


def difficulty_for_target(target: int) -> float:
    return DIFF1_TARGET / max(target, 1)


def coinbase_parts(height: int, outputs: List[TxOut], extra: bytes = b"", tag: bytes = b"/hashfun/") -> (bytes, bytes):
    """Split a non-witness coinbase so that coinb1 + extranonce(8) + coinb2 is the tx."""
    script_len = len(push_int(height)) + len(extra) + 1 + EN1_SIZE + EN2_SIZE + len(push(tag))
    if script_len > 100:
        raise ValueError("coinbase scriptSig too long")
    coinb1 = (struct.pack("<i", 2) + b"\x01" + b"\x00" * 32 + b"\xff\xff\xff\xff" + varint(script_len) +
              push_int(height) + extra + bytes([EN1_SIZE + EN2_SIZE]))
    coinb2 = push(tag) + b"\xff\xff\xff\xff" + varint(len(outputs))
    for o in outputs:
        coinb2 += struct.pack("<q", o.value) + varint(len(o.script_pubkey)) + o.script_pubkey
    coinb2 += struct.pack("<I", 0)
    return coinb1, coinb2


def witness_coinbase(coinbase_nonwit: bytes, with_witness: bool) -> Tx:
    tx = Tx.parse(coinbase_nonwit)
    if with_witness:
        tx.vin[0].witness = [b"\x00" * 32]
    return tx


@dataclass
class Job:
    job_id: str
    source: "JobSource"
    prev_le: bytes
    coinb1: bytes
    coinb2: bytes
    branch: List[bytes]
    version: int
    bits: int
    ntime: int
    height: int
    txs_hex: List[str]
    has_commitment: bool
    clean: bool
    ctx: dict = field(default_factory=dict)

    def notify_params(self):
        return [self.job_id, swap32_words(self.prev_le).hex(), self.coinb1.hex(), self.coinb2.hex(),
                [b.hex() for b in self.branch], f"{self.version & 0xFFFFFFFF:08x}", f"{self.bits:08x}",
                f"{self.ntime:08x}", self.clean]

    def assemble(self, en1: bytes, en2: bytes, ntime: int, nonce: int, version: Optional[int] = None):
        cb = self.coinb1 + en1 + en2 + self.coinb2
        root = root_from_branch(sha256d(cb), self.branch, 0)
        hdr = header_bytes(self.version if version is None else version, self.prev_le, root, ntime, self.bits, nonce)
        return hdr, cb

    def block_hex(self, header: bytes, coinbase_nonwit: bytes) -> str:
        cbtx = witness_coinbase(coinbase_nonwit, self.has_commitment)
        return (header + varint(1 + len(self.txs_hex)) + cbtx.serialize(witness=True)).hex() + "".join(self.txs_hex)


class JobSource:
    name = "source"

    def __init__(self):
        self.version_tag = 0  # bumps when a new prevhash arrives (clean jobs)
        self.template_tag = 0  # bumps on any template change

    async def refresh(self) -> bool:
        raise NotImplementedError

    def make_job(self, job_id: str, username: str, clean: bool) -> Job:
        raise NotImplementedError

    async def on_solution(self, job: Job, header: bytes, coinbase: bytes, hash_int: int) -> List[dict]:
        raise NotImplementedError


def _gbt_txs(tmpl):
    return [bytes.fromhex(t["txid"])[::-1] for t in tmpl["transactions"]], [t["data"] for t in tmpl["transactions"]]


class AuxSet:
    """Graduated launches merge-mined on top of whatever parent a source is mining.

    The parent only has to be a SHA256d header whose coinbase carries the commitment and whose
    chain id differs from the child's, so it can be a BTC block (MergedSource) or a presale
    block of another launch (LaunchSource): hash paid for one launch's curve secures every
    graduated launch for free."""

    def __init__(self, children: Optional[Dict[str, dict]] = None):
        """children: ticker -> {"rpc": RPC, "hrp": str, "payout": address}"""
        self.children = children or {}
        self.aux: Dict[str, dict] = {}

    async def collect(self) -> bool:
        """Fetch aux work from every graduated child. True if the set changed."""
        aux = {}
        for ticker, c in self.children.items():
            try:
                info = await asyncio.to_thread(c["rpc"].getlaunchinfo)
                if info["graduated"]:
                    aux[ticker] = await asyncio.to_thread(c["rpc"].createauxblock, c["payout"])
            except Exception as e:  # a child node being down must not stop the parent
                log.debug("[%s] no aux block: %s", ticker, e)
        changed = {k: v["hash"] for k, v in aux.items()} != {k: v["hash"] for k, v in self.aux.items()}
        self.aux = aux
        return changed

    def commit(self) -> (bytes, dict):
        """(scriptSig commitment push, job ctx entries) for the current aux set."""
        if not self.aux:
            return b"", {"tree": None, "chain_map": {}, "aux": {}}
        leaves, chain_map = {}, {}
        for ticker, ab in self.aux.items():
            leaves[ab["chainid"]] = bytes.fromhex(ab["hash"])[::-1]
            chain_map[ab["chainid"]] = ticker
        tree = AuxTree(leaves)
        return tree.commitment_push(), {"tree": tree, "chain_map": chain_map,
                                        "aux": {k: dict(v) for k, v in self.aux.items()}}

    async def submit(self, job, header: bytes, coinbase: bytes, hash_int: int) -> List[dict]:
        events = []
        tree = job.ctx.get("tree")
        if not tree:
            return events
        cbtx = witness_coinbase(coinbase, job.has_commitment)
        for cid, ticker in job.ctx["chain_map"].items():
            ab = job.ctx["aux"][ticker]
            if hash_int > bits_to_target(int(ab["bits"], 16)):
                continue
            chain_branch, idx = tree.branch(cid)
            apow = serialize_auxpow(cbtx, job.branch, chain_branch, idx, header)
            ok, why = check_auxpow(bytes.fromhex(ab["hash"])[::-1], cid, apow)
            if not ok:
                log.error("[%s] local auxpow check failed: %s", ticker, why)
                continue
            try:
                res = await asyncio.to_thread(self.children[ticker]["rpc"].submitauxblock, ab["hash"], apow.hex())
            except RPCError as e:
                res = str(e)
            ev = {"chain": ticker, "kind": "auxblock", "height": ab["height"], "hash": ab["hash"], "result": res}
            events.append(ev)
            log.info("[%s] merge-mined block %s at %d: %s", ticker, ab["hash"], ab["height"], res)
        return events


class LaunchSource(JobSource):
    def __init__(self, rpc: RPC, hrp: str, ticker: str, default_payout: str = None,
                 children: Optional[Dict[str, dict]] = None, settler=None, yield_hrp: str = "bc"):
        """settler: hashfun.settler.Settler for launches with a sats leg (pays and proves the
        Bitcoin owed by the blocks this pool finds). Miners who log in as
        "<launch address>,<bitcoin address>" get their coinbase registered for BTC yield."""
        super().__init__()
        self.auxset = AuxSet({k: v for k, v in (children or {}).items() if k != ticker})
        self.settler, self.yield_hrp = settler, yield_hrp
        self.settle_outs: List[TxOut] = []
        self.rpc, self.hrp, self.ticker = rpc, hrp, ticker
        self.name = ticker
        self.default_payout = default_payout
        self.tmpl = None
        self.prev = None
        self.last_full = 0
        self.last_push = 0
        self.refresh_secs = 3
        self.blocks_found = []

    async def refresh(self) -> bool:
        best = await asyncio.to_thread(self.rpc.getbestblockhash)
        now = time.time()
        aux_changed = await self.auxset.collect()
        if aux_changed:
            self.last_full = self.last_push = 0
        # nBits depends on the template's own time (stall relief doubles the target every 6T
        # without a block), so an unchanged tip still needs a fresh template every few seconds.
        if best == self.prev and now - self.last_full < self.refresh_secs:
            return False
        tmpl = await asyncio.to_thread(self.rpc.getblocktemplate, {"rules": ["segwit"]})
        self.last_full = now
        settle_changed = False
        if self.settler:
            try:
                outs = await asyncio.to_thread(self.settler.coinbase_outputs)
            except Exception as e:  # the Bitcoin node being down must not stop mining
                log.warning("[%s] settler: %s", self.ticker, e)
                outs = self.settle_outs
            settle_changed = [o.script_pubkey for o in outs] != [o.script_pubkey for o in self.settle_outs]
            self.settle_outs = outs
        if (self.tmpl and tmpl["previousblockhash"] == self.prev and tmpl["bits"] == self.tmpl["bits"]
                and not settle_changed and now - self.last_push < 30):
            return False  # same job, nothing to push
        self.last_push = now
        if tmpl["previousblockhash"] != self.prev or aux_changed:
            self.version_tag += 1
        self.prev = tmpl["previousblockhash"]
        self.tmpl = tmpl
        self.template_tag += 1
        return True

    def payout_script(self, username: str) -> bytes:
        addr = username.split(".")[0].split(",")[0] if username else self.default_payout
        try:
            return address_to_script(addr, self.hrp)
        except Exception:
            if self.default_payout:
                return address_to_script(self.default_payout, self.hrp)
            raise

    def make_job(self, job_id: str, username: str, clean: bool) -> Job:
        t = self.tmpl
        outs = [TxOut(t["coinbasevalue"], self.payout_script(username))]
        if "creatorfee" in t:
            outs.append(TxOut(t["creatorfee"]["amount"], bytes.fromhex(t["creatorfee"]["script"])))
        yield_script = self.yield_script(username)
        if yield_script:
            outs.append(TxOut(0, yield_tag_script(yield_script)))
        outs += self.settle_outs
        has_commit = "default_witness_commitment" in t
        if has_commit:
            outs.append(TxOut(0, bytes.fromhex(t["default_witness_commitment"])))
        extra, auxctx = self.auxset.commit()
        c1, c2 = coinbase_parts(t["height"], outs, extra=extra)
        txids, datas = _gbt_txs(t)
        return Job(job_id, self, bytes.fromhex(t["previousblockhash"])[::-1], c1, c2,
                   merkle_branch_for_first([b"\0" * 32] + txids), t["version"], int(t["bits"], 16), t["curtime"],
                   t["height"], datas, has_commit, clean,
                   {"target": int(t["target"], 16), "fixed_ntime": True, **auxctx})

    def yield_script(self, username: str) -> Optional[bytes]:
        """Bitcoin scriptPubKey from "<launch address>,<bitcoin address>[.worker]", if given."""
        parts = (username or "").split(".")[0].split(",")
        if len(parts) < 2 or not parts[1]:
            return None
        try:
            return address_to_script(parts[1], self.yield_hrp)
        except Exception:
            return None

    async def on_solution(self, job, header, coinbase, hash_int):
        aux_events = await self.auxset.submit(job, header, coinbase, hash_int)
        self.blocks_found.extend(aux_events)
        if aux_events:
            self.last_full = 0
        if hash_int > job.ctx["target"]:
            return aux_events
        res = await asyncio.to_thread(self.rpc.submitblock, job.block_hex(header, coinbase))
        h = sha256d(header)[::-1].hex()
        ev = {"chain": self.ticker, "kind": "block", "height": job.height, "hash": h, "result": res}
        self.blocks_found.append(ev)
        self.last_full = 0
        if res is None and self.settler:
            self.settler.add_block(job.height, h)
        log.info("[%s] block %s at %d: %s", self.ticker, h, job.height, res or "accepted")
        return [ev]


class MergedSource(JobSource):
    """BTC parent + AuxPoW commitments to graduated launches."""

    def __init__(self, parent: RPC, parent_hrp: str, children: Dict[str, dict], default_payout: str = None):
        """children: ticker -> {"rpc": RPC, "hrp": str, "payout": address}"""
        super().__init__()
        self.name = "BTC+aux"
        self.parent, self.parent_hrp = parent, parent_hrp
        self.auxset = AuxSet(children)
        self.default_payout = default_payout
        self.tmpl = None
        self.prev = None
        self.last_full = 0
        self.blocks_found = []

    @property
    def children(self):
        return self.auxset.children

    @property
    def aux(self):
        return self.auxset.aux

    async def refresh(self) -> bool:
        best = await asyncio.to_thread(self.parent.getbestblockhash)
        aux_changed = await self.auxset.collect()
        now = time.time()
        if best == self.prev and not aux_changed and now - self.last_full < 30:
            return False
        tmpl = await asyncio.to_thread(self.parent.getblocktemplate, {"rules": ["segwit"]})
        self.last_full = now
        if tmpl["previousblockhash"] != self.prev or aux_changed:
            self.version_tag += 1
        self.prev = tmpl["previousblockhash"]
        self.tmpl = tmpl
        self.template_tag += 1
        return True

    def make_job(self, job_id: str, username: str, clean: bool) -> Job:
        t = self.tmpl
        parts = (username or "").split(".")[0].split(",")
        addr = parts[0] or self.default_payout
        try:
            spk = address_to_script(addr, self.parent_hrp)
        except Exception:
            spk = address_to_script(self.default_payout, self.parent_hrp)
        outs = [TxOut(t["coinbasevalue"], spk)]
        has_commit = "default_witness_commitment" in t
        if has_commit:
            outs.append(TxOut(0, bytes.fromhex(t["default_witness_commitment"])))
        extra, auxctx = self.auxset.commit()
        c1, c2 = coinbase_parts(t["height"], outs, extra=extra)
        txids, datas = _gbt_txs(t)
        return Job(job_id, self, bytes.fromhex(t["previousblockhash"])[::-1], c1, c2,
                   merkle_branch_for_first([b"\0" * 32] + txids), t["version"], int(t["bits"], 16), t["curtime"],
                   t["height"], datas, has_commit, clean, {"target": int(t["target"], 16), **auxctx})

    async def on_solution(self, job, header, coinbase, hash_int):
        events = await self.auxset.submit(job, header, coinbase, hash_int)
        if hash_int <= job.ctx["target"]:
            res = await asyncio.to_thread(self.parent.submitblock, job.block_hex(header, coinbase))
            h = sha256d(header)[::-1].hex()
            ev = {"chain": "BTC", "kind": "block", "height": job.height, "hash": h, "result": res}
            events.append(ev)
            log.info("[BTC] parent block %s at %d: %s", h, job.height, res or "accepted")
        self.blocks_found.extend(events)
        if events:
            self.last_full = 0
        return events


class Session:
    _en1_counter = 0

    def __init__(self, server, reader, writer):
        Session._en1_counter += 1
        self.server, self.reader, self.writer = server, reader, writer
        self.en1 = struct.pack(">I", Session._en1_counter & 0xFFFFFFFF)
        self.username = None
        self.difficulty = server.difficulty
        self.subscribed = False
        self.extranonce_sub = False
        self.jobs: Dict[str, Job] = {}
        self.seen = set()
        self.shares = 0
        self.rejects = 0
        self.work = 0.0
        self.peer = writer.get_extra_info("peername")

    def send(self, obj):
        self.writer.write((json.dumps(obj) + "\n").encode())

    def notify(self, method, params):
        self.send({"id": None, "method": method, "params": params})

    def push_job(self, clean: bool):
        if not self.subscribed or not self.username or self.server.source.tmpl is None:
            return
        job = self.server.source.make_job(self.server.next_job_id(), self.username, clean)
        if clean:
            self.jobs.clear()
            self.seen.clear()
        self.jobs[job.job_id] = job
        while len(self.jobs) > 16:
            self.jobs.pop(next(iter(self.jobs)))
        self.notify("mining.notify", job.notify_params())

    async def handle(self, msg):
        mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or []
        if method == "mining.subscribe":
            self.subscribed = True
            self.send({"id": mid, "result": [[["mining.set_difficulty", "hf"], ["mining.notify", "hf"]],
                                             self.en1.hex(), EN2_SIZE], "error": None})
        elif method == "mining.extranonce.subscribe":
            self.extranonce_sub = True
            self.send({"id": mid, "result": True, "error": None})
        elif method == "mining.configure":
            # Version rolling would overwrite the auxpow chain ID bits (16..28).
            self.send({"id": mid, "result": {"version-rolling": False}, "error": None})
        elif method == "mining.authorize":
            self.username = params[0] if params else ""
            self.send({"id": mid, "result": True, "error": None})
            self.notify("mining.set_difficulty", [self.difficulty])
            self.push_job(True)
        elif method == "mining.suggest_difficulty":
            if params:
                self.difficulty = max(self.server.min_difficulty, float(params[0]))
                self.notify("mining.set_difficulty", [self.difficulty])
            self.send({"id": mid, "result": True, "error": None})
        elif method == "mining.submit":
            ok, err = await self.submit(params)
            self.send({"id": mid, "result": ok, "error": err})
        else:
            self.send({"id": mid, "result": None, "error": [20, f"unknown method {method}", None]})

    async def submit(self, params):
        if len(params) < 5:
            return False, [20, "bad params", None]
        _, job_id, en2_hex, ntime_hex, nonce_hex = params[:5]
        job = self.jobs.get(job_id)
        if job is None:
            self.rejects += 1
            return False, [21, "stale job", None]
        try:
            en2 = bytes.fromhex(en2_hex)
            ntime, nonce = int(ntime_hex, 16), int(nonce_hex, 16)
        except ValueError:
            return False, [20, "bad hex", None]
        if len(en2) != EN2_SIZE:
            return False, [20, "bad extranonce2 size", None]
        key = (job_id, en2_hex, ntime_hex, nonce_hex)
        if key in self.seen:
            self.rejects += 1
            return False, [22, "duplicate share", None]
        self.seen.add(key)
        if job.ctx.get("fixed_ntime") and ntime != job.ntime:
            return False, [20, "ntime rolling is not allowed on launch chains", None]
        if not (job.ntime - 600 <= ntime <= job.ntime + 7200):
            return False, [20, "ntime out of range", None]
        header, cb = job.assemble(self.en1, en2, ntime, nonce)
        h = int.from_bytes(sha256d(header), "little")
        if h > target_for_difficulty(self.difficulty):
            self.rejects += 1
            return False, [23, "low difficulty share", None]
        self.shares += 1
        self.work += self.difficulty
        self.server.record_share(self, job, self.difficulty)
        events = await job.source.on_solution(job, header, cb, h)
        if events:
            self.server.events.extend(events)
            asyncio.get_running_loop().create_task(self.server.poll_once(force=True))
        return True, None


class StratumServer:
    def __init__(self, source: JobSource, host="0.0.0.0", port=3333, difficulty=1.0, min_difficulty=1e-9,
                 poll_interval=1.0, stats_path=None):
        self.source, self.host, self.port = source, host, port
        self.difficulty, self.min_difficulty = difficulty, min_difficulty
        self.poll_interval = poll_interval
        self.sessions: List[Session] = []
        self.events: List[dict] = []
        self.share_log: Dict[str, float] = {}
        self._job = 0
        self._last_version_tag = -1
        self.stats_path = stats_path
        self.started = time.time()

    def next_job_id(self) -> str:
        self._job += 1
        return f"{self._job:x}"

    def record_share(self, sess, job, diff):
        user = (sess.username or "?").split(".")[0]
        self.share_log[user] = self.share_log.get(user, 0.0) + diff

    def stats(self):
        return {"source": self.source.name, "uptime": time.time() - self.started,
                "sessions": [{"user": s.username, "shares": s.shares, "rejects": s.rejects, "work": s.work,
                              "difficulty": s.difficulty} for s in self.sessions],
                "work_by_user": self.share_log, "events": self.events[-200:]}

    async def poll_once(self, force=False):
        try:
            if force:
                self.source.last_full = 0
            changed = await self.source.refresh()
        except Exception as e:  # node hiccup: keep serving last template
            log.warning("template refresh failed: %s", e)
            return
        if changed:
            clean = self.source.version_tag != self._last_version_tag
            self._last_version_tag = self.source.version_tag
            for s in list(self.sessions):
                try:
                    s.push_job(clean)
                except Exception as e:
                    log.warning("push_job failed: %s", e)
        if self.stats_path:
            tmp = self.stats_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.stats(), f)
            os.replace(tmp, self.stats_path)

    async def _poller(self):
        while True:
            await self.poll_once()
            await asyncio.sleep(self.poll_interval)

    async def _client(self, reader, writer):
        s = Session(self, reader, writer)
        self.sessions.append(s)
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                await s.handle(msg)
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            self.sessions.remove(s)
            writer.close()

    async def serve(self):
        await self.poll_once()
        server = await asyncio.start_server(self._client, self.host, self.port)
        log.info("stratum %s listening on %s:%d", self.source.name, self.host, self.port)
        asyncio.get_running_loop().create_task(self._poller())
        async with server:
            await server.serve_forever()
