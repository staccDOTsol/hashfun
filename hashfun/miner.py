"""Reference stratum v1 CPU miner (sha256d). Slow; for regtest/test launches and
for exercising the pool and the strata proxy. Supports set_difficulty,
set_extranonce and clean jobs."""
import asyncio
import hashlib
import json
import logging
import os
import struct
import time

from .crypto import sha256d
from .ser import root_from_branch, header_bytes
from .stratum import swap32_words, target_for_difficulty

log = logging.getLogger("hashfun.miner")


class StratumMiner:
    def __init__(self, host, port, username, password="x", batch=20000, max_shares=None):
        self.host, self.port, self.username, self.password = host, port, username, password
        self.batch, self.max_shares = batch, max_shares
        self.en1, self.en2_size = b"", 4
        self.diff = 1.0
        self.job = None
        self.job_seq = 0
        self.accepted = self.rejected = self.hashes = 0
        self._id = 0
        self._pending = {}
        self.en2_counter = int.from_bytes(os.urandom(2), "big") << 16

    async def _send(self, method, params):
        self._id += 1
        fut = asyncio.get_running_loop().create_future()
        self._pending[self._id] = fut
        self.writer.write((json.dumps({"id": self._id, "method": method, "params": params}) + "\n").encode())
        await self.writer.drain()
        return fut

    async def _reader(self):
        while True:
            line = await self.reader.readline()
            if not line:
                raise ConnectionError("pool closed connection")
            msg = json.loads(line)
            if msg.get("method"):
                self._on_notification(msg["method"], msg.get("params") or [])
            elif msg.get("id") in self._pending:
                fut = self._pending.pop(msg["id"])
                if not fut.done():  # cancelled while the reply was in flight
                    fut.set_result(msg)

    def _on_notification(self, method, p):
        if method == "mining.set_difficulty":
            self.diff = float(p[0])
        elif method == "mining.set_extranonce":
            self.en1, self.en2_size = bytes.fromhex(p[0]), int(p[1])
        elif method == "mining.notify":
            job_id, prevhash, c1, c2, branch, version, nbits, ntime, clean = p[:9]
            self.job = {"id": job_id, "prev_le": swap32_words(bytes.fromhex(prevhash)), "c1": bytes.fromhex(c1),
                        "c2": bytes.fromhex(c2), "branch": [bytes.fromhex(b) for b in branch],
                        "version": int(version, 16), "bits": int(nbits, 16), "ntime": int(ntime, 16)}
            self.job_seq += 1

    def _scan(self, job, en2: bytes, start: int, count: int, target: int):
        cb = job["c1"] + self.en1 + en2 + job["c2"]
        root = root_from_branch(sha256d(cb), job["branch"], 0)
        version = job["version"]
        if version >= 2**31:
            version -= 2**32
        hdr = header_bytes(version, job["prev_le"], root, job["ntime"], job["bits"], 0)[:76]
        mid = hashlib.sha256(hdr[:64])
        tail = hdr[64:]
        found = []
        for nonce in range(start, start + count):
            h = mid.copy()
            h.update(tail + struct.pack("<I", nonce))
            d = hashlib.sha256(h.digest()).digest()
            if int.from_bytes(d, "little") <= target:
                found.append(nonce)
        return found

    async def run(self, duration=None):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        rt = asyncio.get_running_loop().create_task(self._reader())
        sub = await (await self._send("mining.subscribe", ["hashfun-miner/0.1"]))
        _, en1, en2_size = sub["result"]
        self.en1, self.en2_size = bytes.fromhex(en1), en2_size
        await (await self._send("mining.extranonce.subscribe", []))
        await (await self._send("mining.authorize", [self.username, self.password]))
        t0 = time.time()
        try:
            while duration is None or time.time() - t0 < duration:
                if self.max_shares is not None and self.accepted >= self.max_shares:
                    break
                if rt.done():
                    rt.result()
                job = self.job
                if not job:
                    await asyncio.sleep(0.05)
                    continue
                seq = self.job_seq
                self.en2_counter = (self.en2_counter + 1) % (1 << (8 * self.en2_size))
                en2 = self.en2_counter.to_bytes(self.en2_size, "big")
                target = target_for_difficulty(self.diff)
                start = 0
                while start < 2**32 and seq == self.job_seq:
                    found = await asyncio.to_thread(self._scan, job, en2, start, self.batch, target)
                    self.hashes += self.batch
                    for nonce in found:
                        res = await (await self._send("mining.submit", [self.username, job["id"], en2.hex(),
                                                                         f"{job['ntime']:08x}", f"{nonce:08x}"]))
                        if res.get("result"):
                            self.accepted += 1
                        else:
                            self.rejected += 1
                    start += self.batch
                    if duration is not None and time.time() - t0 >= duration:
                        break
                    if self.max_shares is not None and self.accepted >= self.max_shares:
                        break
        finally:
            rt.cancel()
            self.writer.close()
        return {"accepted": self.accepted, "rejected": self.rejected, "hashes": self.hashes,
                "seconds": time.time() - t0}


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="hashfun reference stratum CPU miner")
    ap.add_argument("--url", default="127.0.0.1:3333")
    ap.add_argument("--user", required=True, help="payout address (solo pool) or proxy user")
    ap.add_argument("--duration", type=float)
    a = ap.parse_args(argv)
    host, port = a.url.rsplit(":", 1)
    logging.basicConfig(level=logging.INFO)
    print(asyncio.run(StratumMiner(host, int(port), a.user).run(a.duration)))


if __name__ == "__main__":
    main()
