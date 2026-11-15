"""Real Qwencoin main-chain headers from the chain's public explorer (ord's JSON), checked here:
SHA256d of the 80 bytes rebuilt from the fields equals the hash the explorer gives, and each header's
prev is the hash of the one below it."""
import hashlib, json, struct, sys, time, urllib.request

BASE = "https://aichat.fyi"

def get(path):
    for attempt in range(6):
        try:
            req = urllib.request.Request(BASE + path, headers={"Accept": "application/json", "User-Agent": "hashfun-test-vectors/1"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except Exception as e:  # the pod is small: wait and ask again
            time.sleep(1 + attempt * 2)
            last = e
    raise last

def header80(d):
    return (struct.pack("<i", d["version"]) + bytes.fromhex(d["prev"])[::-1] + bytes.fromhex(d["merkle_root"])[::-1]
            + struct.pack("<III", d["time"], d["bits"], d["nonce"]))

def main(out):
    tip = int(get("/r/blockheight"))
    ranges = [(0, 14), (1996, 2044), (4016, 4054), (6030, tip)]
    heights = sorted({h for a, b in ranges for h in range(a, b + 1)})
    rows = []
    for h in heights:
        b = get(f"/r/blockinfo/{h}")
        d = {"height": b["height"], "version": b["version"], "prev": b.get("previous_block") or "00" * 32,
             "merkle_root": b["merkle_root"], "time": b["timestamp"], "bits": b["bits"], "nonce": b["nonce"], "hash": b["hash"]}
        raw = header80(d)
        got = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
        assert got == d["hash"], (h, got, d["hash"])
        d["header"] = raw.hex()
        rows.append(d)
        time.sleep(0.05)
    by = {r["height"]: r for r in rows}
    for r in rows:
        if r["height"] - 1 in by:
            assert r["prev"] == by[r["height"] - 1]["hash"], r["height"]
    json.dump({"source": BASE, "tip_when_fetched": tip, "ranges": ranges, "headers": rows}, open(out, "w"), indent=0)
    print(len(rows), "headers, tip", tip)

main(sys.argv[1])
