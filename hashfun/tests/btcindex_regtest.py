"""The site's Bitcoin balances from an Electrum index (electrs, Fulcrum) agree with the UTXO-set scan;
the scan takes over when the index is down. Rule set 3: the site's Qwencoin balances (a second stock
bitcoind plays the regtest Qwencoin, tests/qwenreg.py) come from that node's own scan and never mix
with Bitcoin's, although one address string names the same key on both chains.
python -m hashfun.tests.btcindex_regtest --bitcoind PATH"""
import os, sys, tempfile, time, threading, subprocess, asyncio, shutil
from hashfun.tests.e2e_regtest import Node, free_port
from hashfun.rpc import RPC
from hashfun import web
from hashfun.electrum import ElectrumServer
from hashfun.tests.qwenreg import QwenNode
import argparse
_ap = argparse.ArgumentParser(); _ap.add_argument('--bitcoind', required=True); _ap.add_argument('--hashfund')
btcd = _ap.parse_args().bitcoind
w = tempfile.mkdtemp()
b = Node(btcd, os.path.join(w, "b"), ["-regtest", "-fallbackfee=0.0002"], free_port())
b.rpc.createwallet("w"); wb = b.rpc.wallet("w")
a1 = wb.getnewaddress("", "bech32"); b.rpc.createwallet("r"); a2 = b.rpc.wallet("r").getnewaddress("", "bech32m")
wb.generatetoaddress(101, a1)
wb.sendtoaddress(a2, 1.5); wb.sendtoaddress(a2, 0.25); wb.generatetoaddress(1, a1); wb.sendtoaddress(a2, 0.1)  # one unconfirmed
ep = free_port()
srv = ElectrumServer(b.rpc, "127.0.0.1", ep)
threading.Thread(target=lambda: asyncio.run(srv.serve()), daemon=True).start()
time.sleep(3)
class Reg: data = {}
s_scan = web.Site(b.rpc, Reg())
s_idx = web.Site(b.rpc, Reg(), btc_index=web.BtcIndex(f"127.0.0.1:{ep}"))
ok = True
for addr in (a1, a2):
    spk = b.rpc.validateaddress(addr)["scriptPubKey"]
    t0 = time.time(); x = s_idx.btc_address(spk); ti = time.time() - t0
    t0 = time.time(); y = s_scan.btc_address(spk); ts = time.time() - t0
    conf_x = sorted((u["txid"], u["vout"], u["value"]) for u in x["utxos"] if u["confirmations"] > 0)
    conf_y = sorted((u["txid"], u["vout"], u["value"]) for u in y["utxos"])
    same = conf_x == conf_y
    print(addr[:12], "index:", len(x["utxos"]), "utxos", x["balance"], f"{ti*1000:.0f} ms | scan:", len(y["utxos"]), y["balance"], f"{ts*1000:.0f} ms | confirmed same:", same, "| unconfirmed via index:", sum(1 for u in x["utxos"] if u["confirmations"] == 0))
    ok &= same
# bids path
for s in (s_idx,):
    s.scan["btc"].wanted = {b.rpc.validateaddress(a2)["scriptPubKey"]}
    s.scan_bids()
    print("bid sats via index (confirmed only):", s.scan["btc"].sats)
# fallback: kill the index, ask again
s_idx.btc_index.port = free_port(); s_idx.btc_index.sock.close(); s_idx.btc_index.sock = None
y = s_idx.btc_address(b.rpc.validateaddress(a2)["scriptPubKey"]); print("index down -> fallback scan balance:", y["balance"])
ok &= y["balance"] > 0 and bool(s_idx.scan["btc"].sats) and all(v > 0 for v in s_idx.scan["btc"].sats.values())
# Qwencoin: the same address string on the other chain
q = QwenNode(btcd, os.path.join(w, "q"))
wq = q.funded_wallet()
wq.sendtoaddress(a2, 0.7); wq.sendtoaddress(a2, 0.05); q.mine(1)
s_q = web.Site(b.rpc, Reg(), btc_index=web.BtcIndex(f"127.0.0.1:{ep}"), qwen=q.rpc)
spk2 = b.rpc.validateaddress(a2)["scriptPubKey"]
on_q, on_b = s_q.outside_address("qwen", spk2), s_q.outside_address("btc", spk2)
same_q = sorted(u["value"] for u in on_q["utxos"]) == [5_000_000, 70_000_000]
print("qwen:", s_q.qwen_id, "| key on Qwencoin:", on_q["balance"], "| the same string on Bitcoin:", on_b["balance"])
s_q.scan["qwen"].wanted = {spk2}
s_q.scan_bids()
print("bid QWEN via the Qwencoin scan:", s_q.scan["qwen"].sats, "| bid sats:", s_q.scan["btc"].sats)
try:
    s_scan.outside_address("qwen", spk2); refused = False
except ValueError:
    refused = True
ok &= (s_q.qwen_id == "qwen:regtest" and same_q and on_q["balance"] == 75_000_000 and on_b["balance"] == y["balance"]
       and s_q.scan["qwen"].sats.get(spk2) == 75_000_000 and refused)
print("qwen scan:", "ok" if ok else "MISMATCH", "| a site without a Qwencoin node refuses the question:", refused)
q.stop(); b.stop(); shutil.rmtree(w, ignore_errors=True)
print("btcindex: all passed" if ok else "btcindex: MISMATCH")
sys.exit(0 if ok else 1)
