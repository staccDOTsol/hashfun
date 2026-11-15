"""Qwencoin's work table, for the QWEN leg of a launch that follows the real Qwencoin.

On Qwencoin a header's proof of work is not its hash. It is a pass through the MLP weights of
Qwen3.5-0.8B at 16-bit fixed point: value = SHA256(fold(net(seed, nonce)) XOR seed) with
seed = SHA256d(header with nNonce = 0) (https://github.com/staccDOTsol/qwencoin, exec/qwork.h).
Whoever checks a Qwencoin header needs those weights: a file of 528,482,328 bytes that every
Qwencoin node has, and that hashfund maps at start (-qwork=FILE) to check the Qwencoin headers
relayed into a launch. One copy serves every launch on the machine.

  hashfun qwork path      where the tools keep it ($HASHFUN_HOME/qwork.bin)
  hashfun qwork check     is it there and is it the chain's table (size, SHA-256)?
  hashfun qwork fetch     download it (resumed if interrupted), check it, put it in place

Nothing else in the tools needs the table: a launch file's Qwencoin anchor is checked by asking a
Qwencoin node, and the node checks the anchor's work itself when it starts. `work_value` below is
the pass in Python, for tests and for anyone who wants to see a header's value without a node: it
needs numpy and a second or so per header.
"""
import argparse
import hashlib
import os
import struct
import sys
import time
import urllib.error
import urllib.request
from typing import Callable, Optional

TABLE_URL = "https://huggingface.co/staccs/qwencoin/resolve/main/qwork.bin"
TABLE_BYTES = 528_482_328
TABLE_SHA256 = "8f53884f7727e80b86f3ddf288d3c3f0f998f1c63b8cd4f0bdad182ddd3f2c03"
TABLE_FNV64 = 0x33A548A33925D201  # what a Qwencoin node, and hashfund, compare at start
MAGIC = b"QWRK1\0\0\0"
LAYERS, N, M = 24, 1024, 3584
M64 = (1 << 64) - 1


def default_path() -> str:
    """Where the tools keep the table: $HASHFUN_QWORK if set, else qwork.bin in $HASHFUN_HOME (~/.hashfun)."""
    forced = os.environ.get("HASHFUN_QWORK")
    if forced:
        return os.path.abspath(os.path.expanduser(forced))
    home = os.path.expanduser(os.environ.get("HASHFUN_HOME", "~/.hashfun"))
    return os.path.join(home, "qwork.bin")


def quick_problem(path: str) -> Optional[str]:
    """What is wrong with the file at a glance (missing, wrong size, not a table), or None. No hashing:
    the node compares the whole file's checksum itself at start."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return f"{path} is not there"
    if size != TABLE_BYTES:
        return f"{path} is {size:,} bytes, the table is {TABLE_BYTES:,} (an interrupted download?)"
    with open(path, "rb") as f:
        head = f.read(24)
    if head[:8] != MAGIC or struct.unpack("<III", head[8:20]) != (LAYERS, N, M):
        return f"{path} is not a Qwencoin work table (QWRK1, 24 layers of 3584 x 1024)"
    return None


def sha256_of(path: str, progress: Optional[Callable[[int], None]] = None) -> str:
    h, done = hashlib.sha256(), 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 22)
            if not chunk:
                return h.hexdigest()
            h.update(chunk)
            done += len(chunk)
            if progress:
                progress(done)


def problem(path: str) -> Optional[str]:
    """What is wrong with the file, the SHA-256 of all of it included, or None: it is the chain's table."""
    quick = quick_problem(path)
    if quick:
        return quick
    got = sha256_of(path)
    if got != TABLE_SHA256:
        return f"{path} has SHA-256 {got}, the chain's table has {TABLE_SHA256}"
    return None


def fetch(path: Optional[str] = None, url: str = TABLE_URL, say: Callable[[str], None] = lambda s: None,
          attempts: int = 8) -> str:
    """Download the table to `path` (default_path()), resuming a partial download, and put it in place
    only once all of it has the chain's SHA-256. Returns the path. Raises RuntimeError with what went
    wrong; a partial download is kept for the next try, one with the wrong contents is removed."""
    path = path or default_path()
    if quick_problem(path) is None:
        if sha256_of(path) == TABLE_SHA256:
            say(f"{path}: already there, and it is the chain's table")
            return path
        say(f"{path}: not the chain's table; fetching it again")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    part = path + ".part"
    last_error = None
    for attempt in range(attempts):
        have = os.path.getsize(part) if os.path.exists(part) else 0
        if have > TABLE_BYTES:
            os.remove(part)
            have = 0
        if have < TABLE_BYTES:
            req = urllib.request.Request(url, headers={"User-Agent": "hashfun-qwork/1", **({"Range": f"bytes={have}-"} if have else {})})
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    if have and r.status != 206:  # the server sent the whole file again
                        have = 0
                    say(f"fetching the Qwencoin work table: {TABLE_BYTES / 2**20:.0f} MB to {path}"
                        + (f" (resuming at {have / 2**20:.0f} MB)" if have else ""))
                    shown = time.time()
                    with open(part, "ab" if have else "wb") as f:
                        while True:
                            chunk = r.read(1 << 20)
                            if not chunk:
                                break
                            f.write(chunk)
                            have += len(chunk)
                            if time.time() - shown >= 5:
                                shown = time.time()
                                say(f"  {have / 2**20:.0f} of {TABLE_BYTES / 2**20:.0f} MB")
            except (urllib.error.URLError, OSError, ValueError) as e:
                last_error = e
                say(f"  the download stopped ({e}); trying again from where it was")
                time.sleep(min(30, 2 ** attempt))
                continue
            if have < TABLE_BYTES:
                last_error = RuntimeError(f"the server closed the connection at {have:,} of {TABLE_BYTES:,} bytes")
                continue
        got = sha256_of(part)
        if got != TABLE_SHA256:
            os.remove(part)
            raise RuntimeError(f"what {url} served has SHA-256 {got}, the chain's table has {TABLE_SHA256}: nothing was "
                               "put in place")
        os.replace(part, path)
        say(f"{path}: the chain's table (SHA-256 {TABLE_SHA256[:16]}...)")
        return path
    raise RuntimeError(f"could not fetch {url}: {last_error}. What was received is kept in {part}; run it again, or copy "
                       "qwork.bin from a Qwencoin node's folder to " + path)


# ---------------------------------------------------------------- the pass, in Python (tests, curiosity)
def seed(header: bytes) -> bytes:
    """SHA256d of the header with its nonce zeroed: shared by all nonces of one block template."""
    return hashlib.sha256(hashlib.sha256(header[:76] + bytes(4)).digest()).digest()


def _rotl(x: int, k: int) -> int:
    return (x << k | x >> (64 - k)) & M64


def _mix64(z: int) -> int:
    z = (z ^ z >> 30) * 0xBF58476D1CE4E5B9 & M64
    z = (z ^ z >> 27) * 0x94D049BB133111EB & M64
    return z ^ z >> 31


def expand(h0: bytes, nonce: int, n: int = N) -> list:
    """The start state: n values of +1 / -1 from the seed and the nonce (xoshiro256** from a mixed seed)."""
    w = struct.unpack("<4Q", h0)
    a = w[0] ^ (nonce << 32 | nonce)
    s = [_mix64(a), _mix64((w[1] + a) & M64), _mix64(w[2] ^ _rotl(a, 21)), _mix64((w[3] + _rotl(a, 42)) & M64)]
    if not any(s):
        s[0] = 1
    x = []
    for _ in range(n // 64):
        r = _rotl(s[1] * 5 & M64, 7) * 9 & M64
        t = s[1] << 17 & M64
        s[2] ^= s[0]
        s[3] ^= s[1]
        s[1] ^= s[2]
        s[0] ^= s[3]
        s[2] ^= t
        s[3] = _rotl(s[3], 45)
        x.extend(1 if r >> b & 1 else -1 for b in range(64))
    return x


class Table:
    """The table mapped for the Python pass. Needs numpy."""

    def __init__(self, path: Optional[str] = None):
        import numpy as np  # not a dependency of the tools: only this class uses it
        self.np = np
        path = path or default_path()
        quick = quick_problem(path)
        if quick:
            raise RuntimeError(quick)
        self.w = np.memmap(path, dtype="<i2", mode="r", offset=24)

    def layer(self, l: int):
        k = N * M
        a = self.w[l * 3 * k:(l + 1) * 3 * k]
        return a[:k].reshape(M, N), a[k:2 * k].reshape(M, N), a[2 * k:].reshape(N, M)

    def evaluate(self, h0: bytes, nonce: int) -> bytes:
        """The pass, in exact integers: the 32 folded bytes."""
        np = self.np
        x = np.array(expand(h0, nonce), dtype=np.int32)
        for l in range(LAYERS):
            g, u, d = self.layer(l)
            a = np.where(((g.astype(np.int32) @ x) > 0) == ((u.astype(np.int32) @ x) > 0), 1, -1).astype(np.int32)
            x = np.where((d.astype(np.int32) @ a) > 0, 1, -1).astype(np.int32)
        bits = np.packbits((x > 0).astype(np.uint8), bitorder="little")
        return bytes(np.bitwise_xor.reduce(bits.reshape(-1, 32), axis=0))

    def work_value(self, header: bytes) -> int:
        """A Qwencoin header's proof-of-work value, as the number the node compares with the target."""
        h0 = seed(header)
        out = self.evaluate(h0, struct.unpack("<I", header[76:80])[0])
        return int.from_bytes(hashlib.sha256(bytes(a ^ b for a, b in zip(out, h0))).digest(), "little")


def work_value(header: bytes, table: Optional[Table] = None) -> int:
    return (table or Table()).work_value(header)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hashfun qwork", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, text in (("path", "print where the table is kept"), ("check", "is the table there, and is it the chain's?"),
                       ("fetch", "download the table (528 MB, resumed if interrupted) and check it")):
        p = sub.add_parser(name, help=text)
        p.add_argument("--file", help="another place than $HASHFUN_HOME/qwork.bin")
        if name == "fetch":
            p.add_argument("--url", default=TABLE_URL, help="where to fetch it from (default: the Qwencoin project's repository)")
    a = ap.parse_args(argv)
    path = os.path.abspath(os.path.expanduser(a.file)) if a.file else default_path()
    if a.cmd == "path":
        print(path)
        return 0
    if a.cmd == "check":
        why = problem(path)
        if why:
            print(f"{why}. Get it with `hashfun qwork fetch`, or copy qwork.bin from a Qwencoin node's folder.", file=sys.stderr)
            return 1
        print(f"{path}: the Qwencoin work table ({TABLE_BYTES:,} bytes, SHA-256 {TABLE_SHA256})")
        return 0
    try:
        fetch(path, a.url, say=lambda s: print(s, file=sys.stderr, flush=True))
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        return 1
    print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
