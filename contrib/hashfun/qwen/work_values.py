"""Work values of the fetched headers by the project's own numpy reference (hashformer/work.py) over
the real table, written into the vectors file; every one must be under its target."""
import json, sys, time
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[3])  # a checkout of https://github.com/staccDOTsol/qwencoin
from hashformer import work

def target(bits):
    e, m = bits >> 24, bits & 0x007fffff
    return m >> (8 * (3 - e)) if e <= 3 else m << (8 * (e - 3))

path, table = sys.argv[1], sys.argv[2]
d = json.load(open(path))
t = work.Table(table)
t0 = time.time()
for i, r in enumerate(d["headers"]):
    v = work.pow_hash(t, bytes.fromhex(r["header"]))
    r["work"] = v[::-1].hex()  # as the node prints a uint256
    assert int.from_bytes(v, "little") <= target(r["bits"]), (r["height"], r["work"])
    if i % 20 == 0:
        print(i, r["height"], r["work"][:20], f"{time.time() - t0:.0f}s", flush=True)
g = d["headers"][0]
assert g["height"] == 0 and g["work"] == "0083bfd7a2ae5796c139f180b33630684eb71751e4b2b3153ffe288da7739d1d", g["work"]
json.dump(d, open(path, "w"), indent=0)
print("all", len(d["headers"]), "under their targets; genesis value matches the chain's constant;", f"{time.time() - t0:.0f}s")
