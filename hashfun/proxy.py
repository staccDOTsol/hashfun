"""Strata proxy: point hash at a weighted set of launches ("strata set").

Each downstream miner gets its own upstream session per pool; the proxy
time-slices the miner across upstreams by weight (SHA-256 has no switching
cost) using deficit scheduling, re-pushing extranonce/difficulty/job on every
switch. Shares are routed back to the upstream that issued the job. Delivered
work (share difficulty) is accounted per upstream so the realised split can be
compared with the requested weights.

Config (JSON):
  {"listen": "0.0.0.0:3334", "slice_seconds": 5,
   "strata": [{"name": "CNDH", "url": "127.0.0.1:3333", "user": "<addr>", "weight": 3}, ...]}
"""
import asyncio
import json
import logging
import time
from typing import Dict, List

log = logging.getLogger("hashfun.proxy")


class Upstream:
    def __init__(self, cfg, index):
        self.cfg, self.index = cfg, index
        self.name = cfg.get("name", cfg["url"])
        self.weight = float(cfg.get("weight", 1))
        self.en1, self.en2_size, self.diff = None, 4, 1.0
        self.last_notify = None
        self._id = 0
        self._pending = {}
        self.on_notify = None
        self.ready = asyncio.Event()

    async def connect(self, user_override=None):
        host, port = self.cfg["url"].rsplit(":", 1)
        self.reader, self.writer = await asyncio.open_connection(host, int(port))
        self.task = asyncio.get_running_loop().create_task(self._read())
        sub = await self.request("mining.subscribe", ["hashfun-proxy/0.1"])
        _, en1, en2size = sub["result"]
        self.en1, self.en2_size = en1, en2size
        await self.request("mining.extranonce.subscribe", [])
        await self.request("mining.authorize", [user_override or self.cfg["user"], self.cfg.get("password", "x")])

    async def request(self, method, params):
        self._id += 1
        fut = asyncio.get_running_loop().create_future()
        self._pending[self._id] = fut
        self.writer.write((json.dumps({"id": self._id, "method": method, "params": params}) + "\n").encode())
        await self.writer.drain()
        return await asyncio.wait_for(fut, 30)

    async def _read(self):
        while True:
            line = await self.reader.readline()
            if not line:
                log.warning("upstream %s closed", self.name)
                return
            msg = json.loads(line)
            m = msg.get("method")
            if m == "mining.set_difficulty":
                self.diff = float(msg["params"][0])
            elif m == "mining.set_extranonce":
                self.en1, self.en2_size = msg["params"][0], int(msg["params"][1])
            elif m == "mining.notify":
                self.last_notify = msg["params"]
                self.ready.set()
                if self.on_notify:
                    self.on_notify(self)
            elif msg.get("id") in self._pending:
                self._pending.pop(msg["id"]).set_result(msg)

    def close(self):
        try:
            self.task.cancel()
            self.writer.close()
        except Exception:
            pass


class DownstreamSession:
    def __init__(self, proxy, reader, writer):
        self.proxy, self.reader, self.writer = proxy, reader, writer
        self.ups: List[Upstream] = []
        self.active: Upstream = None
        self.given: Dict[int, float] = {}
        self.work: Dict[int, float] = {}
        self.slice_start = time.time()
        self.authorized = False
        self.user = None

    def send(self, obj):
        self.writer.write((json.dumps(obj) + "\n").encode())

    def _push(self, up: Upstream, clean=True):
        if up.last_notify is None:
            return
        self.send({"id": None, "method": "mining.set_extranonce", "params": [up.en1, up.en2_size]})
        self.send({"id": None, "method": "mining.set_difficulty", "params": [up.diff]})
        p = list(up.last_notify)
        p[0] = f"{up.index}:{p[0]}"
        p[8] = clean
        self.send({"id": None, "method": "mining.notify", "params": p})

    def _on_up_notify(self, up):
        if up is self.active:
            self._push(up, clean=bool(up.last_notify[8]))

    def pick(self):
        now = time.time()
        if self.active is not None:
            self.given[self.active.index] = self.given.get(self.active.index, 0) + (now - self.slice_start)
        self.slice_start = now
        ready = [u for u in self.ups if u.last_notify is not None]
        if not ready:
            return None
        total_w = sum(u.weight for u in ready)
        total_t = sum(self.given.get(u.index, 0) for u in ready) + 1e-9
        # deficit: entitlement minus time already given
        best = max(ready, key=lambda u: u.weight / total_w * total_t - self.given.get(u.index, 0) + u.weight * 1e-6)
        return best

    async def scheduler(self):
        while True:
            nxt = self.pick()
            if nxt is not None and nxt is not self.active:
                self.active = nxt
                self._push(nxt, clean=True)
            await asyncio.sleep(self.proxy.slice_seconds)

    async def handle(self, msg):
        mid, m, p = msg.get("id"), msg.get("method"), msg.get("params") or []
        if m == "mining.subscribe":
            # Downstream en1 is replaced via set_extranonce on every switch.
            self.send({"id": mid, "result": [[["mining.set_difficulty", "px"], ["mining.notify", "px"]], "00000000", 4],
                       "error": None})
        elif m == "mining.extranonce.subscribe":
            self.send({"id": mid, "result": True, "error": None})
        elif m == "mining.configure":
            self.send({"id": mid, "result": {"version-rolling": False}, "error": None})
        elif m == "mining.authorize":
            self.user = p[0] if p else ""
            for i, cfg in enumerate(self.proxy.strata):
                up = Upstream(cfg, i)
                up.on_notify = self._on_up_notify
                await up.connect()
                self.ups.append(up)
            self.authorized = True
            self.send({"id": mid, "result": True, "error": None})
            for u in self.ups:
                try:
                    await asyncio.wait_for(u.ready.wait(), 10)
                except asyncio.TimeoutError:
                    log.warning("no job from %s yet", u.name)
            asyncio.get_running_loop().create_task(self.scheduler())
        elif m == "mining.submit":
            try:
                idx, job = p[1].split(":", 1)
                up = self.ups[int(idx)]
            except (ValueError, IndexError):
                self.send({"id": mid, "result": False, "error": [21, "unknown job", None]})
                return
            params = [up.cfg["user"], job] + list(p[2:])
            try:
                res = await up.request("mining.submit", params)
            except asyncio.TimeoutError:
                self.send({"id": mid, "result": False, "error": [20, "upstream timeout", None]})
                return
            if res.get("result"):
                self.work[up.index] = self.work.get(up.index, 0) + up.diff
                self.proxy.work[up.name] = self.proxy.work.get(up.name, 0) + up.diff
            self.send({"id": mid, "result": res.get("result"), "error": res.get("error")})
        else:
            self.send({"id": mid, "result": None, "error": [20, f"unknown method {m}", None]})

    def close(self):
        for u in self.ups:
            u.close()


class StrataProxy:
    def __init__(self, strata, listen="0.0.0.0:3334", slice_seconds=5.0):
        self.strata, self.slice_seconds = strata, slice_seconds
        self.host, port = listen.rsplit(":", 1)
        self.port = int(port)
        self.work: Dict[str, float] = {}
        self.sessions: List[DownstreamSession] = []

    def stats(self):
        total = sum(self.work.values()) or 1
        want = sum(float(s.get("weight", 1)) for s in self.strata)
        return {s.get("name", s["url"]): {"weight": float(s.get("weight", 1)) / want,
                                         "delivered": self.work.get(s.get("name", s["url"]), 0) / total}
                for s in self.strata}

    async def _client(self, reader, writer):
        s = DownstreamSession(self, reader, writer)
        self.sessions.append(s)
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                await s.handle(json.loads(line))
                await writer.drain()
        except (ConnectionError, json.JSONDecodeError):
            pass
        finally:
            s.close()
            self.sessions.remove(s)
            writer.close()

    async def serve(self):
        server = await asyncio.start_server(self._client, self.host, self.port)
        log.info("strata proxy on %s:%d -> %s", self.host, self.port, [s.get("name") for s in self.strata])
        async with server:
            await server.serve_forever()


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="hashfun strata proxy")
    ap.add_argument("config")
    a = ap.parse_args(argv)
    cfg = json.load(open(a.config))
    logging.basicConfig(level=logging.INFO)
    asyncio.run(StrataProxy(cfg["strata"], cfg.get("listen", "0.0.0.0:3334"), cfg.get("slice_seconds", 5)).serve())


if __name__ == "__main__":
    main()
