"""hashfun-pool: run a stratum pool from a JSON config.

Standalone launch mining:
  {"mode": "launch", "listen": "0.0.0.0:3333", "difficulty": 65536,
   "launch": {"rpc": "http://u:p@127.0.0.1:20001", "hrp": "cndh", "ticker": "CNDH", "default_payout": "cndh1..."},
   "stats": "pool-stats.json"}

Merged mining (BTC parent + every graduated launch):
  {"mode": "merged", "listen": "0.0.0.0:3335", "difficulty": 65536,
   "parent": {"rpc": "http://u:p@127.0.0.1:8332", "hrp": "bc", "default_payout": "bc1..."},
   "children": {"CNDH": {"rpc": "http://u:p@127.0.0.1:20001", "hrp": "cndh", "payout": "cndh1..."}}}
"""
import argparse
import asyncio
import json
import logging

from .rpc import RPC
from .stratum import LaunchSource, MergedSource, StratumServer


def main(argv=None):
    ap = argparse.ArgumentParser(prog="hashfun-pool", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("config")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    cfg = json.load(open(a.config))
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(asctime)s %(name)s %(message)s")
    if cfg["mode"] == "launch":
        l = cfg["launch"]
        src = LaunchSource(RPC(l["rpc"]), l["hrp"], l["ticker"], l.get("default_payout"))
    elif cfg["mode"] == "merged":
        p = cfg["parent"]
        children = {t: {"rpc": RPC(c["rpc"]), "hrp": c["hrp"], "payout": c["payout"]} for t, c in cfg["children"].items()}
        src = MergedSource(RPC(p["rpc"]), p["hrp"], children, p.get("default_payout"))
    else:
        raise SystemExit("mode must be 'launch' or 'merged'")
    host, port = cfg.get("listen", "0.0.0.0:3333").rsplit(":", 1)
    asyncio.run(StratumServer(src, host, int(port), difficulty=float(cfg.get("difficulty", 1.0)),
                              stats_path=cfg.get("stats")).serve())


if __name__ == "__main__":
    main()
