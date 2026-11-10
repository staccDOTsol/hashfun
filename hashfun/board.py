"""hashfun board: indexer + JSON API + static UI over every launch node.

Config (JSON):
  {"listen": "127.0.0.1:8700",
   "launches": [{"rpc": "http://u:p@127.0.0.1:20001"}, ...],
   "hashprice_sats_per_th": 50,          # optional, to show BTC prices
   "pool_stats": ["/path/pool-stats.json"]}  # optional
"""
import json
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .rpc import RPC
from .ser import Tx, script_to_address, work_from_bits
from .swap import iter_block_txs

log = logging.getLogger("hashfun.board")
HERE = os.path.dirname(os.path.abspath(__file__))


class LaunchIndexer:
    def __init__(self, rpc: RPC, keep=500):
        self.rpc, self.keep = rpc, keep
        self.info = None
        self.blocks = []  # newest last
        self.hash_at = {}
        self.error = None

    def poll(self):
        try:
            info = self.rpc.getlaunchinfo()
            tip = info["height"]
            # drop blocks no longer on the active chain
            while self.blocks and (self.blocks[-1]["height"] > tip or
                                   self.rpc.getblockhash(self.blocks[-1]["height"]) != self.blocks[-1]["hash"]):
                self.blocks.pop()
            start = max(1, tip - self.keep + 1, self.blocks[-1]["height"] + 1 if self.blocks else 1)
            for h in range(start, tip + 1):
                bh = self.rpc.getblockhash(h)
                hdr = self.rpc.getblockheader(bh)
                raw = bytes.fromhex(self.rpc.getblock(bh, 0))
                cb = next(iter_block_txs(raw))
                hrp = info["hrp"]
                payouts = [{"address": script_to_address(o.script_pubkey, hrp), "value": o.value}
                           for o in cb.vout if o.value > 0]
                version = int.from_bytes(raw[:4], "little", signed=True)
                self.blocks.append({"height": h, "hash": bh, "time": hdr["time"], "bits": hdr["bits"],
                                    "work": work_from_bits(int(hdr["bits"], 16)),
                                    "coinbase_value": sum(o.value for o in cb.vout), "payouts": payouts,
                                    "auxpow": bool(version & 0x100), "ntx": hdr["nTx"]})
            self.blocks = self.blocks[-self.keep:]
            self.info = info
            self.error = None
        except Exception as e:
            self.error = str(e)

    def summary(self):
        if not self.info:
            return {"error": self.error}
        i = dict(self.info)
        recent = self.blocks[-60:]
        if len(recent) >= 2:
            span = max(1, recent[-1]["time"] - recent[0]["time"])
            i["hashrate"] = sum(b["work"] for b in recent[1:]) / span
            i["block_interval"] = span / (len(recent) - 1)
        i["error"] = self.error
        return i


class Board:
    def __init__(self, cfg):
        self.cfg = cfg
        self.indexers = [LaunchIndexer(RPC(l["rpc"])) for l in cfg["launches"]]

    def loop(self):
        while True:
            for ix in self.indexers:
                ix.poll()
            time.sleep(self.cfg.get("poll_seconds", 3))

    def api(self, path):
        if path == "/api/launches":
            return {"hashprice_sats_per_th": self.cfg.get("hashprice_sats_per_th"),
                    "launches": [ix.summary() for ix in self.indexers]}
        if path.startswith("/api/launch/"):
            lid = path.split("/")[3]
            for ix in self.indexers:
                if ix.info and ix.info["launch_id"].startswith(lid):
                    return {"info": ix.summary(), "blocks": ix.blocks[-200:]}
            return None
        if path == "/api/pools":
            out = []
            for p in self.cfg.get("pool_stats", []):
                try:
                    out.append(json.load(open(p)))
                except (OSError, json.JSONDecodeError):
                    pass
            return out
        return None


def handler(board: Board):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.startswith("/api/"):
                obj = board.api(self.path.split("?")[0])
                body = json.dumps(obj).encode()
                self.send_response(200 if obj is not None else 404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
            else:
                with open(os.path.join(HERE, "board.html"), "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return H


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="hashfun board")
    ap.add_argument("config")
    a = ap.parse_args(argv)
    cfg = json.load(open(a.config))
    logging.basicConfig(level=logging.INFO)
    b = Board(cfg)
    threading.Thread(target=b.loop, daemon=True).start()
    host, port = cfg.get("listen", "127.0.0.1:8700").rsplit(":", 1)
    log.info("board on http://%s:%s", host, port)
    ThreadingHTTPServer((host, int(port)), handler(b)).serve_forever()


if __name__ == "__main__":
    main()
