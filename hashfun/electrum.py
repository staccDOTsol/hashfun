"""Electrum-protocol (1.4) server for hashfun launches and BTC, backed by a node's
RPC. Indexes scripthash history/UTXOs from raw blocks (auxpow-aware), tracks the
mempool, handles reorgs with per-block undo, and pushes header/scripthash
notifications. Enough of the protocol for light wallets: headers, scripthash
balance/history/listunspent/subscribe, transaction get/broadcast/get_merkle,
fee estimates.

Run one per chain:  python -m hashfun.electrum --rpc URL --port 50001
"""
import asyncio
import hashlib
import json
import logging
import os
import pickle
import time
from typing import Dict, List, Set

from .crypto import sha256, sha256d
from .rpc import RPC, RPCError
from .ser import Tx, Reader, merkle_branch
from .swap import iter_block_txs

log = logging.getLogger("hashfun.electrum")
PROTOCOL = "1.4"


def scripthash(spk: bytes) -> str:
    return sha256(spk)[::-1].hex()


class Index:
    def __init__(self, rpc: RPC, path: str = None, undo_depth=200):
        self.rpc, self.path, self.undo_depth = rpc, path, undo_depth
        self.headers: List[bytes] = []
        self.hashes: List[str] = []
        self.history: Dict[str, List] = {}
        self.utxos: Dict[tuple, tuple] = {}  # (txid, n) -> (sh, value, height)
        self.sh_utxos: Dict[str, Set[tuple]] = {}
        self.tx_height: Dict[str, int] = {}
        self.undo: Dict[int, dict] = {}
        self.mempool: Dict[str, Tx] = {}
        self.mempool_sh: Dict[str, Set[str]] = {}
        self.mempool_fee: Dict[str, int] = {}
        if path and os.path.exists(path):
            with open(path, "rb") as f:
                st = pickle.load(f)
            self.__dict__.update({k: v for k, v in st.items()})
            self.rpc = rpc

    def save(self):
        if not self.path:
            return
        st = {k: v for k, v in self.__dict__.items() if k not in ("rpc", "mempool", "mempool_sh", "mempool_fee", "path")}
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as f:
            pickle.dump(st, f)
        os.replace(tmp, self.path)

    @property
    def height(self):
        return len(self.headers) - 1

    def _add_block(self, height: int, bhash: str, raw: bytes, touched: Set[str]):
        undo = {"added": [], "spent": [], "txids": []}
        for tx in iter_block_txs(raw):
            txid = tx.txid_hex()
            undo["txids"].append(txid)
            self.tx_height[txid] = height
            shs = set()
            for i in tx.vin:
                key = (i.prev_txid[::-1].hex(), i.prev_vout)
                u = self.utxos.pop(key, None)
                if u:
                    undo["spent"].append((key, u))
                    self.sh_utxos.get(u[0], set()).discard(key)
                    shs.add(u[0])
            for n, o in enumerate(tx.vout):
                if not o.script_pubkey or o.script_pubkey[0] == 0x6A:
                    continue
                sh = scripthash(o.script_pubkey)
                key = (txid, n)
                self.utxos[key] = (sh, o.value, height)
                self.sh_utxos.setdefault(sh, set()).add(key)
                undo["added"].append(key)
                shs.add(sh)
            for sh in shs:
                self.history.setdefault(sh, []).append((height, txid))
                touched.add(sh)
        self.headers.append(raw[:80])
        self.hashes.append(bhash)
        self.undo[height] = undo
        self.undo.pop(height - self.undo_depth, None)

    def _rollback(self, touched: Set[str]):
        height = self.height
        undo = self.undo.pop(height)
        for key in undo["added"]:
            u = self.utxos.pop(key, None)
            if u:
                self.sh_utxos.get(u[0], set()).discard(key)
                touched.add(u[0])
        for key, u in undo["spent"]:
            self.utxos[key] = u
            self.sh_utxos.setdefault(u[0], set()).add(key)
            touched.add(u[0])
        txids = set(undo["txids"])
        for sh in list(touched):
            self.history[sh] = [h for h in self.history.get(sh, []) if not (h[0] == height and h[1] in txids)]
        for t in txids:
            self.tx_height.pop(t, None)
        self.headers.pop()
        self.hashes.pop()

    def sync(self) -> (bool, Set[str]):
        touched: Set[str] = set()
        changed = False
        tip = self.rpc.getblockcount()
        # reorg: walk back until our hash matches the node's
        while self.hashes and (self.height > tip or self.rpc.getblockhash(self.height) != self.hashes[-1]):
            if self.height not in self.undo:
                raise RuntimeError("reorg deeper than undo window; delete the index and resync")
            self._rollback(touched)
            changed = True
        while self.height < tip:
            h = self.height + 1
            bh = self.rpc.getblockhash(h)
            raw = bytes.fromhex(self.rpc.getblock(bh, 0))
            self._add_block(h, bh, raw, touched)
            changed = True
        return changed, touched

    def sync_mempool(self) -> Set[str]:
        touched = set()
        txids = set(self.rpc.getrawmempool())
        for gone in set(self.mempool) - txids:
            for sh in self.mempool_sh.pop(gone, set()):
                touched.add(sh)
            self.mempool.pop(gone, None)
            self.mempool_fee.pop(gone, None)
        for txid in txids - set(self.mempool):
            try:
                tx = Tx.parse(bytes.fromhex(self.rpc.getrawtransaction(txid)))
            except RPCError:
                continue
            self.mempool[txid] = tx
            shs = set()
            vin_total = 0
            for i in tx.vin:
                key = (i.prev_txid[::-1].hex(), i.prev_vout)
                if key in self.utxos:
                    shs.add(self.utxos[key][0])
                    vin_total += self.utxos[key][1]
                elif key[0] in self.mempool:
                    o = self.mempool[key[0]].vout[key[1]]
                    shs.add(scripthash(o.script_pubkey))
                    vin_total += o.value
            for o in tx.vout:
                if o.script_pubkey and o.script_pubkey[0] != 0x6A:
                    shs.add(scripthash(o.script_pubkey))
            self.mempool_fee[txid] = max(0, vin_total - sum(o.value for o in tx.vout))
            self.mempool_sh[txid] = shs
            touched |= shs
        return touched

    # ------------------------------------------------------------ queries
    def mempool_entries(self, sh):
        out = []
        for txid, shs in self.mempool_sh.items():
            if sh in shs:
                tx = self.mempool[txid]
                unconf_parent = any(i.prev_txid[::-1].hex() in self.mempool for i in tx.vin)
                out.append({"tx_hash": txid, "height": -1 if unconf_parent else 0, "fee": self.mempool_fee.get(txid, 0)})
        return sorted(out, key=lambda e: (e["height"] == 0, e["tx_hash"]))

    def get_history(self, sh):
        conf = [{"tx_hash": t, "height": h} for h, t in self.history.get(sh, [])]
        return conf + self.mempool_entries(sh)

    def status(self, sh):
        hist = self.get_history(sh)
        if not hist:
            return None
        return hashlib.sha256("".join(f"{e['tx_hash']}:{e['height']}:" for e in hist).encode()).hexdigest()

    def listunspent(self, sh):
        out = [{"tx_hash": k[0], "tx_pos": k[1], "height": v[2], "value": v[1]}
               for k in self.sh_utxos.get(sh, set()) for v in [self.utxos[k]]]
        spent_in_mempool = {(i.prev_txid[::-1].hex(), i.prev_vout) for tx in self.mempool.values() for i in tx.vin}
        out = [u for u in out if (u["tx_hash"], u["tx_pos"]) not in spent_in_mempool]
        for txid, tx in self.mempool.items():
            for n, o in enumerate(tx.vout):
                if o.script_pubkey and scripthash(o.script_pubkey) == sh and (txid, n) not in spent_in_mempool:
                    out.append({"tx_hash": txid, "tx_pos": n, "height": 0, "value": o.value})
        return sorted(out, key=lambda u: (u["height"] or 1 << 30, u["tx_hash"], u["tx_pos"]))

    def balance(self, sh):
        conf = sum(self.utxos[k][1] for k in self.sh_utxos.get(sh, set()))
        unconf = sum(u["value"] for u in self.listunspent(sh) if u["height"] == 0) - \
            sum(self.utxos[k][1] for k in self.sh_utxos.get(sh, set())
                if any(i.prev_txid[::-1].hex() == k[0] and i.prev_vout == k[1] for tx in self.mempool.values() for i in tx.vin))
        return {"confirmed": conf, "unconfirmed": unconf}


class ElectrumServer:
    def __init__(self, rpc: RPC, host="0.0.0.0", port=50001, index_path=None, banner="hashfun electrum"):
        self.rpc, self.host, self.port, self.banner = rpc, host, port, banner
        self.index = Index(rpc, index_path)
        self.sessions = set()
        self.genesis = None

    async def poll(self):
        last_save = 0
        while True:
            try:
                changed, touched = await asyncio.to_thread(self.index.sync)
                touched |= await asyncio.to_thread(self.index.sync_mempool)
                if changed:
                    for s in self.sessions:
                        if s.headers_sub:
                            s.notify("blockchain.headers.subscribe", [self.header_info(self.index.height)])
                if touched:
                    for s in self.sessions:
                        for sh in touched & s.subs:
                            s.notify("blockchain.scripthash.subscribe", [sh, self.index.status(sh)])
                if time.time() - last_save > 30:
                    await asyncio.to_thread(self.index.save)
                    last_save = time.time()
            except Exception as e:
                log.warning("sync error: %s", e)
            await asyncio.sleep(1)

    def header_info(self, h):
        return {"height": h, "hex": self.index.headers[h].hex()}

    async def dispatch(self, s, method, p):
        ix = self.index
        if method == "server.version":
            return ["hashfun-electrum 0.1", PROTOCOL]
        if method == "server.banner":
            return self.banner
        if method == "server.donation_address":
            return ""
        if method == "server.ping":
            return None
        if method == "server.peers.subscribe":
            return []
        if method == "server.features":
            return {"genesis_hash": ix.hashes[0] if ix.hashes else None, "hosts": {}, "protocol_max": PROTOCOL,
                    "protocol_min": PROTOCOL, "pruning": None, "server_version": "hashfun-electrum 0.1",
                    "hash_function": "sha256"}
        if method == "blockchain.headers.subscribe":
            s.headers_sub = True
            return self.header_info(ix.height)
        if method == "blockchain.block.header":
            return ix.headers[int(p[0])].hex()
        if method == "blockchain.block.headers":
            start, count = int(p[0]), min(int(p[1]), 2016)
            hs = ix.headers[start:start + count]
            return {"count": len(hs), "hex": b"".join(hs).hex(), "max": 2016}
        if method == "blockchain.estimatefee":
            try:
                r = await asyncio.to_thread(self.rpc.estimatesmartfee, int(p[0]))
                return r.get("feerate", -1)
            except RPCError:
                return -1
        if method == "blockchain.relayfee":
            return (await asyncio.to_thread(self.rpc.getnetworkinfo))["relayfee"]
        if method == "blockchain.scripthash.get_balance":
            return ix.balance(p[0])
        if method == "blockchain.scripthash.get_history":
            return ix.get_history(p[0])
        if method == "blockchain.scripthash.get_mempool":
            return ix.mempool_entries(p[0])
        if method == "blockchain.scripthash.listunspent":
            return ix.listunspent(p[0])
        if method == "blockchain.scripthash.subscribe":
            s.subs.add(p[0])
            return ix.status(p[0])
        if method == "blockchain.scripthash.unsubscribe":
            had = p[0] in s.subs
            s.subs.discard(p[0])
            return had
        if method == "blockchain.transaction.get":
            txid, verbose = p[0], bool(p[1]) if len(p) > 1 else False
            if txid in ix.mempool:
                raw = ix.mempool[txid].serialize().hex()
            else:
                h = ix.tx_height.get(txid)
                if h is None:
                    raise ValueError("unknown transaction")
                raw = await asyncio.to_thread(self.rpc.getrawtransaction, txid, False, ix.hashes[h])
            if verbose:
                return await asyncio.to_thread(self.rpc.decoderawtransaction, raw)
            return raw
        if method == "blockchain.transaction.broadcast":
            txid = await asyncio.to_thread(self.rpc.sendrawtransaction, p[0])
            touched = await asyncio.to_thread(ix.sync_mempool)
            for sess in self.sessions:
                for sh in touched & sess.subs:
                    sess.notify("blockchain.scripthash.subscribe", [sh, ix.status(sh)])
            return txid
        if method == "blockchain.transaction.get_merkle":
            txid, h = p[0], int(p[1])
            blk = await asyncio.to_thread(self.rpc.getblock, ix.hashes[h], 1)
            txids = blk["tx"]
            pos = txids.index(txid)
            br = merkle_branch([bytes.fromhex(t)[::-1] for t in txids], pos)
            return {"block_height": h, "merkle": [b[::-1].hex() for b in br], "pos": pos}
        raise ValueError(f"unknown method {method}")

    async def _client(self, reader, writer):
        s = _Session(writer)
        self.sessions.add(s)
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    req = json.loads(line)
                except json.JSONDecodeError:
                    continue
                reqs = req if isinstance(req, list) else [req]
                resps = []
                for r in reqs:
                    try:
                        res = await self.dispatch(s, r.get("method"), r.get("params") or [])
                        resps.append({"jsonrpc": "2.0", "id": r.get("id"), "result": res})
                    except Exception as e:
                        resps.append({"jsonrpc": "2.0", "id": r.get("id"), "error": {"code": 1, "message": str(e)}})
                s.send(resps if isinstance(req, list) else resps[0])
                await writer.drain()
        except ConnectionError:
            pass
        finally:
            self.sessions.discard(s)
            writer.close()

    async def serve(self):
        await asyncio.to_thread(self.index.sync)
        server = await asyncio.start_server(self._client, self.host, self.port)
        log.info("electrum server on %s:%d (height %d)", self.host, self.port, self.index.height)
        asyncio.get_running_loop().create_task(self.poll())
        async with server:
            await server.serve_forever()


class _Session:
    def __init__(self, writer):
        self.writer = writer
        self.subs: Set[str] = set()
        self.headers_sub = False

    def send(self, obj):
        self.writer.write((json.dumps(obj) + "\n").encode())

    def notify(self, method, params):
        self.send({"jsonrpc": "2.0", "method": method, "params": params})


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="hashfun Electrum-protocol server")
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=50001)
    ap.add_argument("--index", help="index file for fast restarts")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    asyncio.run(ElectrumServer(RPC(a.rpc), a.host, a.port, a.index).serve())


if __name__ == "__main__":
    main()
