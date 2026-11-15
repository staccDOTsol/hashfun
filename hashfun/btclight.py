"""Bitcoin through Electrum servers, for a machine that holds no Bitcoin node.

    btc = connect("electrums://HOST:PORT,HOST:PORT")      # TLS; electrum:// is plain TCP

The object answers the calls the tools make on a Bitcoin Core RPC object (hashfun.rpc.RPC) with the
same names, arguments and result shapes, so it goes wherever such an object goes: the site, the
settlers, descriptor.check_anchor, `launch new`. Its answers come from servers nobody here runs, so
nothing is believed that can be checked:

  headers        its own chain of headers, grown from a block hash written in this file (the newest
                 one the node itself ships). Every header links to the one below it, meets its own
                 bits, carries the bits Bitcoin's retarget rule gives at its height and a time past
                 the median of the eleven before it. Of the chains the servers offer, the one with
                 the most work is kept. Heights, block hashes and confirmations are read from that
                 chain and from nothing else.
  transactions   bytes fetched by id are hashed, and refused unless they hash to that id.
  inclusion      a merkle branch is folded up to the merkle root of the header at that height in
                 the chain above before a transaction is called confirmed or a proof is handed out.
  the rest       which outputs of a script are unspent, and that nothing more exists (no other
                 history, no spender), is not something a server can prove. Those questions go to
                 `agree` servers (2 when 2 are configured). What they agree on is the answer; what
                 they keep disagreeing on is an error (Disagreement), never an empty answer.

What an Electrum server cannot be asked at all (whole blocks, what is in the mempool) is not
answered: getblock and getrawmempool raise NotAvailable. The callers that read blocks have a call of
their own here instead: payments_to (payments to a script, each one proven), txproof (where a
transaction sits in its block), find_spend (what spent an output), unspent (a script's outputs).

With a key it is also the wallet of the settler that pays: wallet(FILE) reads one key (64 hex digits
or WIF) and fundrawtransaction, signrawtransactionwithwallet and gettransaction then work on that
key's P2WPKH address, the way the paying Settler calls them.

Errors: hashfun.rpc.RPCError with Bitcoin Core's codes where Core would raise one (-5 not found, -8
out of range, -4 insufficient funds, -26 a transaction the network refused, with the server's
reason). Unreachable (a ConnectionError) when no server gave a usable answer. Disagreement,
NotAvailable and NotProven are LightErrors (RuntimeErrors), never RPCErrors, so no caller reads
them as "not found".

Standard library only. Safe to share between threads: each server connection carries one exchange
at a time, and the header chain and the caches are changed under a lock.

    python -m hashfun.btclight check electrums://HOST:PORT,HOST:PORT     what each server does, timed
"""
import json
import logging
import os
import socket
import ssl
import struct
import threading
import time
from collections import OrderedDict
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .crypto import der_sig, ecdsa_sign, hash160, pubkey_from_priv, sha256, sha256d
from .rpc import RPCError
from .ser import (Reader, Tx, TxIn, TxOut, b58check_decode, bip143_sighash, bits_to_target, p2wpkh_script,
                  p2wpkh_script_code, root_from_branch, segwit_encode, target_to_bits, work_from_bits)

log = logging.getLogger("hashfun.btclight")

COIN = 100_000_000
CLIENT = "hashfun-btclight"
PROTOCOL = "1.4"
MAX_LINE = 48 << 20        # bytes of one answer: 2016 headers are 0.3 MB, a large transaction 8 MB
MAX_BACKFILL = 150_000     # headers kept below the checkpoint, at most
DUST = 546


class Unreachable(ConnectionError):
    """No Electrum server gave a usable answer: none answered, or what they sent did not check out."""


class LightError(RuntimeError):
    """What this module raises besides RPCError and Unreachable: a question it will not answer with
    what it has. Never an RPCError, so no caller reads it as "not found"."""


class Disagreement(LightError):
    """The servers say different things about something that cannot be proven (what is unspent)."""


class NotAvailable(LightError):
    """A call no Electrum server can answer, or one that needs a key this object was not given."""


class NotProven(LightError):
    """A server says a transaction is in a block and no server could prove it."""


class ElectrumError(RuntimeError):
    """A server answered a request with an error. .message is what it said."""

    def __init__(self, error):
        self.message = error.get("message", str(error)) if isinstance(error, dict) else str(error)
        super().__init__(self.message)


class _Lie(Exception):
    """What a server sent is provably not true (or not well formed). Never leaves this module."""


# ---------------------------------------------------------------------------------------- rules
class Rules:
    """The header rules of a Bitcoin network and where its chain is taken up.

    checkpoint: (height, block hash) the chain here grows from. known: more (height: hash) pairs the
    chain must pass through when it reaches them (in either direction)."""

    def __init__(self, chain: str, hrp: str, limit_bits: int, checkpoint: Tuple[int, str], retarget: bool = True,
                 interval: int = 2016, timespan: int = 14 * 24 * 3600, known: Optional[Dict[int, str]] = None):
        self.chain, self.hrp, self.limit_bits, self.retarget = chain, hrp, limit_bits, retarget
        self.interval, self.timespan = interval, timespan
        self.checkpoint = (int(checkpoint[0]), checkpoint[1].lower())
        self.known = {int(h): x.lower() for h, x in (known or {}).items()}
        self.known[self.checkpoint[0]] = self.checkpoint[1]


# The block hashes Bitcoin Core carries for its own snapshots (src/kernel/chainparams.cpp of the
# node this package ships): the root of everything this module believes about the main network.
MAIN = Rules("main", "bc", 0x1D00FFFF,
             checkpoint=(965_000, "00000000000000000001595977e6000ce56129f5c9b4073e31ccc30b90b97da9"),
             known={840_000: "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
                    880_000: "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880",
                    910_000: "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
                    935_000: "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee"})
# Regtest: anybody's chain from the regtest genesis block is a regtest chain. No retargeting.
REGTEST = Rules("regtest", "bcrt", 0x207FFFFF, retarget=False,
                checkpoint=(0, "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"))
NETS = {"main": MAIN, "regtest": REGTEST}


def _hh(header: bytes) -> str:
    """A header's block hash as RPC prints it."""
    return sha256d(header)[::-1].hex()


def _htime(header: bytes) -> int:
    return struct.unpack_from("<I", header, 68)[0]


def _hbits(header: bytes) -> int:
    return struct.unpack_from("<I", header, 72)[0]


def _hprev(header: bytes) -> str:
    return header[4:36][::-1].hex()


def _target(bits: int) -> int:
    try:
        return bits_to_target(bits)
    except ValueError:
        return 0


def scripthash(script: bytes) -> str:
    return sha256(script)[::-1].hex()


class HeaderChain:
    """The best chain of headers from `base` up, each one checked before it is put here."""

    STALE = 5000

    def __init__(self, rules: Rules):
        self.rules = rules
        self.base: Optional[int] = None
        self.headers: List[bytes] = []
        self.hashes: List[str] = []
        self.index: Dict[str, int] = {}
        self.stale: "OrderedDict[str, int]" = OrderedDict()  # hashes that were on the best chain and left it

    @property
    def height(self) -> int:
        return self.base + len(self.headers) - 1

    def has(self, h: int) -> bool:
        return self.base is not None and self.base <= h <= self.height

    def header_at(self, h: int) -> bytes:
        return self.headers[h - self.base]

    def hash_at(self, h: int) -> str:
        return self.hashes[h - self.base]

    def start(self, height: int, header: bytes):
        self.base, self.headers, self.hashes = height, [header], [_hh(header)]
        self.index = {self.hashes[0]: height}

    def prepend(self, low: int, headers: List[bytes]):
        hashes = [_hh(x) for x in headers]
        self.headers[0:0], self.hashes[0:0], self.base = headers, hashes, low
        for i, x in enumerate(hashes):
            self.index[x] = low + i

    def adopt(self, fork: int, new: List[bytes]):
        for h in range(fork + 1, self.height + 1):
            x = self.hash_at(h)
            del self.index[x]
            self.stale[x] = h
        while len(self.stale) > self.STALE:
            self.stale.popitem(last=False)
        del self.headers[fork + 1 - self.base:]
        del self.hashes[fork + 1 - self.base:]
        for hdr in new:
            x = _hh(hdr)
            self.headers.append(hdr)
            self.hashes.append(x)
            self.index[x] = self.height
            self.stale.pop(x, None)

    def work_above(self, fork: int) -> int:
        return sum(work_from_bits(_hbits(self.header_at(h))) for h in range(fork + 1, self.height + 1))

    def mtp(self, h: int) -> int:
        """Median time of the block at h and the ten below it (as far as they are held)."""
        times = sorted(_htime(self.header_at(k)) for k in range(max(self.base, h - 10), h + 1))
        return times[len(times) // 2]


# ------------------------------------------------------------------------------------ one server
class _Server:
    """One connection to one Electrum server. One exchange at a time (its lock); it reconnects by
    itself, and remembers for how long it is not worth asking."""

    def __init__(self, host: str, port: int, tls: bool, timeout: float = 12.0, proxy: Optional[str] = None,
                 verify: bool = False):
        self.host, self.port, self.tls, self.timeout, self.proxy, self.verify = host, port, tls, timeout, proxy, verify
        self.label = f"{host}:{port}"
        self.lock = threading.Lock()
        self.sock, self.buf, self.id = None, b"", 0
        self.version = None
        self.down_until, self.strikes = 0.0, 0
        self.no_get_height = False

    # health
    def alive(self) -> bool:
        return time.monotonic() >= self.down_until

    def fail(self, why):
        self.strikes += 1
        self.down_until = time.monotonic() + min(120.0, 5.0 * 2 ** min(self.strikes - 1, 5))
        log.warning("Electrum server %s: %s (not asked for %.0f s)", self.label, why, self.down_until - time.monotonic())

    def lied(self, why):
        self.strikes += 1
        self.down_until = time.monotonic() + min(900.0, 60.0 * 2 ** min(self.strikes - 1, 4))
        log.error("Electrum server %s sent something that does not check out: %s (not asked for %.0f s)", self.label, why,
                  self.down_until - time.monotonic())

    def good(self):
        self.strikes, self.down_until = 0, 0.0

    # wire
    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock, self.buf = None, b""

    def _connect(self):
        if self.proxy:
            p = urlparse(self.proxy if "://" in self.proxy else "http://" + self.proxy)
            sock = socket.create_connection((p.hostname, p.port or 8080), timeout=self.timeout)
            sock.sendall(f"CONNECT {self.host}:{self.port} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n\r\n".encode())
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = sock.recv(4096)
                if not chunk or len(head) > 65536:
                    sock.close()
                    raise ConnectionError(f"the proxy closed the tunnel to {self.label}")
                head += chunk
            status = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            if " 200" not in status:
                sock.close()
                raise ConnectionError(f"the proxy refused a tunnel to {self.label}: {status}")
        else:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.tls:
            # Electrum servers mostly carry certificates they signed themselves, and nothing here
            # rests on who the server is: what it sends is checked against proof of work.
            ctx = ssl.create_default_context()
            if not self.verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        sock.settimeout(self.timeout)
        self.sock, self.buf = sock, b""
        got = self._round([("server.version", [CLIENT, PROTOCOL])])[0]
        if isinstance(got, ElectrumError):
            raise ConnectionError(f"{self.label} does not speak Electrum protocol {PROTOCOL}: {got.message}")
        self.version = got

    def _round(self, calls):
        ids, out = [], b""
        for method, params in calls:
            self.id += 1
            ids.append(self.id)
            out += json.dumps({"jsonrpc": "2.0", "id": self.id, "method": method, "params": list(params)}).encode() + b"\n"
        self.sock.sendall(out)
        want, got = set(ids), {}
        deadline = time.monotonic() + self.timeout * (2 + len(calls) / 20)
        while len(got) < len(ids):
            while b"\n" not in self.buf:
                if time.monotonic() > deadline:
                    raise socket.timeout(f"{self.label} did not finish its answer in time")
                chunk = self.sock.recv(1 << 16)
                if not chunk:
                    raise ConnectionError(f"{self.label} closed the connection")
                self.buf += chunk
                if len(self.buf) > MAX_LINE:
                    raise ConnectionError(f"{self.label} sent an answer of more than {MAX_LINE >> 20} MB")
            line, self.buf = self.buf.split(b"\n", 1)
            try:
                msg = json.loads(line)
            except ValueError:
                raise ConnectionError(f"{self.label} sent a line that is not JSON")
            if isinstance(msg, dict) and msg.get("id") in want:  # notifications (no id) are skipped
                got[msg["id"]] = msg
        return [ElectrumError(got[i]["error"]) if got[i].get("error") else got[i].get("result") for i in ids]

    def batch(self, calls) -> list:
        """One answer per call, in order: its result, or an ElectrumError (not raised). OSError when
        the server could not be talked to. A connection found dead is opened again once; a server
        that is slow is not asked twice."""
        with self.lock:
            for attempt in (0, 1):
                fresh = self.sock is None
                try:
                    if fresh:
                        self._connect()
                    return self._round(calls)
                except (OSError, ValueError) as e:
                    self.close()
                    if fresh or attempt or isinstance(e, socket.timeout):
                        raise

    def call(self, method, *params):
        r = self.batch([(method, params)])[0]
        if isinstance(r, ElectrumError):
            raise r
        return r


# ------------------------------------------------------------------------------------ the object
def _parse_tx(raw: bytes, witness: Optional[bool] = None) -> Tx:
    """A transaction from its bytes. witness=False: the bytes are without witness data, even when
    there are no inputs (what the settler hands fundrawtransaction): never read a segwit marker."""
    if witness is False:
        r = Reader(raw)
        version = r.i32()
        vin = []
        for _ in range(r.varint()):
            txid, n = r.read(32), r.u32()
            sig = r.varbytes()
            vin.append(TxIn(txid, n, sig, r.u32()))
        vout = [TxOut(struct.unpack("<q", r.read(8))[0], r.varbytes()) for _ in range(r.varint())]
        lock = r.u32()
        if not r.done():
            raise ValueError("trailing bytes")
        return Tx(version, vin, vout, lock)
    return Tx.parse(raw)


def _is_coinbase(tx: Tx) -> bool:
    return len(tx.vin) == 1 and tx.vin[0].prev_txid == b"\0" * 32 and tx.vin[0].prev_vout == 0xFFFFFFFF


def _decode(tx: Tx, raw: bytes) -> dict:
    """decoderawtransaction's shape, with the fields the tools read."""
    vin = []
    for i in tx.vin:
        if _is_coinbase(tx):
            e = {"coinbase": i.script_sig.hex(), "sequence": i.sequence}
        else:
            e = {"txid": i.prev_txid[::-1].hex(), "vout": i.prev_vout, "scriptSig": {"hex": i.script_sig.hex()},
                 "sequence": i.sequence}
        if i.witness:
            e["txinwitness"] = [w.hex() for w in i.witness]
        vin.append(e)
    return {"txid": tx.txid_hex(), "hash": tx.wtxid()[::-1].hex(), "version": tx.version, "size": len(raw),
            "vsize": tx.vsize(), "locktime": tx.locktime, "vin": vin, "hex": raw.hex(),
            "vout": [{"value": o.value / COIN, "sats": o.value, "n": n, "scriptPubKey": {"hex": o.script_pubkey.hex()}}
                     for n, o in enumerate(tx.vout)]}


_ALREADY = ("already in block chain", "already in the block chain", "already known", "already-known", "already-in-mempool",
            "already in mempool", "already in utxo set", "already exists", "already have transaction", "txn-already")


def _read_key(text: str) -> int:
    """A private key from 64 hex digits or WIF."""
    t = text.strip()
    if len(t) == 64:
        try:
            k = int(t, 16)
        except ValueError:
            k = 0
    else:
        raw = b58check_decode(t)
        if raw[0] not in (0x80, 0xEF) or len(raw) not in (33, 34) or (len(raw) == 34 and raw[33] != 1):
            raise ValueError("not a WIF private key")
        if len(raw) == 33:
            raise ValueError("an uncompressed key: this wallet pays from P2WPKH, which needs a compressed one")
        k = int.from_bytes(raw[1:33], "big")
    if not 1 <= k < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
        raise ValueError("not a private key (64 hex digits or WIF)")
    return k


class BtcLight:
    """See the module text. servers: (host, port, tls) triples."""

    def __init__(self, servers: Iterable[Tuple[str, int, bool]], rules: Rules = MAIN, agree: int = 2, timeout: float = 12.0,
                 poll: float = 5.0, proxy: Optional[str] = None, tls_verify: bool = False, low_hint: Optional[int] = None,
                 fee_cap: int = 300, fallback_fee: int = 2):
        self.servers = [_Server(h, p, t, timeout, proxy, tls_verify) for h, p, t in servers]
        if not self.servers:
            raise ValueError("no Electrum server was named")
        self.rules, self.agree, self.poll = rules, max(1, agree), poll
        self.fee_cap, self.fallback_fee = fee_cap, fallback_fee
        self.chain = HeaderChain(rules)
        self._low_hint = low_hint
        self._lock = threading.RLock()       # the chain and the caches
        self._sync_lock = threading.Lock()   # one thread grows the chain at a time
        self._synced_at: Optional[float] = None
        self._txs: "OrderedDict[str, bytes]" = OrderedDict()
        self._proofs: "OrderedDict[Tuple[str, str], Tuple[int, int, List[bytes]]]" = OrderedDict()
        self._key: Optional[int] = None
        self._init_wallet()

    def _init_wallet(self):
        self._pub = pubkey_from_priv(self._key) if self._key else None
        self._script = p2wpkh_script(self._pub) if self._key else None
        self._ours: "OrderedDict[str, bytes]" = OrderedDict()   # transactions this wallet signed
        self._reserved: Dict[Tuple[str, int], Tuple[str, float, bool]] = {}  # outpoint -> (spender, when, broadcast)
        self._pending: Dict[Tuple[str, int], int] = {}          # outputs of ours no server lists yet -> value
        self._wlock = threading.RLock()

    # ------------------------------------------------------------------ servers
    def _quorum(self) -> int:
        return min(self.agree, len(self.servers))

    def _order(self) -> List[_Server]:
        live = [s for s in self.servers if s.alive()]
        return live or sorted(self.servers, key=lambda s: s.down_until)

    def _none(self, what: str, said: List[str]) -> Unreachable:
        return Unreachable(f"no Electrum server gave a usable answer ({what}): " + ("; ".join(said) or "none configured"))

    def close(self):
        for s in self.servers:
            with s.lock:
                s.close()

    # ------------------------------------------------------------------ the header chain
    def _fetch(self, s: _Server, lo: int, hi: int) -> List[bytes]:
        out, h = [], lo
        while h <= hi:
            r = s.call("blockchain.block.headers", h, min(2016, hi - h + 1))
            try:
                blob, n = bytes.fromhex(r["hex"]), int(r["count"])
            except (TypeError, KeyError, ValueError):
                raise _Lie("headers not in the protocol's form")
            if n <= 0 or len(blob) != 80 * n or n > hi - h + 1:
                raise _Lie(f"{n} headers in {len(blob)} bytes where up to {hi - h + 1} from height {h} were asked for")
            out += [blob[i:i + 80] for i in range(0, len(blob), 80)]
            h += n
        return out

    def _expected_bits(self, h: int, get) -> int:
        r = self.rules
        if not r.retarget:
            return r.limit_bits
        if h % r.interval:
            return _hbits(get(h - 1))
        span = min(max(_htime(get(h - 1)) - _htime(get(h - r.interval)), r.timespan // 4), r.timespan * 4)
        return target_to_bits(min(_target(_hbits(get(h - 1))) * span // r.timespan, _target(r.limit_bits)))

    def _check(self, fork: int, new: List[bytes]):
        """Are `new` valid headers for heights fork+1.. on top of the chain held up to `fork`?"""
        ch = self.chain

        def get(h):
            return ch.header_at(h) if h <= fork else new[h - fork - 1]
        prev, now = ch.hash_at(fork), time.time()
        for i, hdr in enumerate(new):
            h = fork + 1 + i
            if _hprev(hdr) != prev:
                raise _Lie(f"header {h} does not link to the one below it")
            bits = _hbits(hdr)
            if self.rules.retarget and h - self.rules.interval < ch.base and h % self.rules.interval == 0:
                raise _Lie(f"header {h} retargets from a period this chain does not hold")
            if bits != self._expected_bits(h, get):
                raise _Lie(f"header {h} has bits {bits:#x} where the rules give {self._expected_bits(h, get):#x}")
            x = sha256d(hdr)
            if int.from_bytes(x, "little") > _target(bits):
                raise _Lie(f"header {h} does not meet its own bits")
            times = sorted(_htime(get(k)) for k in range(max(ch.base, h - 11), h))
            if (len(times) == 11 or ch.base == 0) and _htime(hdr) <= times[len(times) // 2]:
                raise _Lie(f"header {h} has a time not past the median of the ones before it")
            if _htime(hdr) > now + 7200:
                raise _Lie(f"header {h} is stamped more than two hours ahead")
            prev = x[::-1].hex()
            if self.rules.known.get(h, prev) != prev:
                raise _Lie(f"header {h} is not block {self.rules.known[h]}")

    def _down(self, s: _Server, low: int):
        """Take the chain down to `low`: the headers below hang from the lowest one held by its
        previous-block hash, each from the one above it."""
        ch = self.chain
        got = self._fetch(s, low, ch.base - 1)
        if len(got) != ch.base - low:
            raise _Lie("fewer headers than asked for")
        want = _hprev(ch.header_at(ch.base))
        for i in range(len(got) - 1, -1, -1):
            x = sha256d(got[i])
            if x[::-1].hex() != want:
                raise _Lie(f"header {low + i} is not the block the one above it names")
            if int.from_bytes(x, "little") > _target(_hbits(got[i])):
                raise _Lie(f"header {low + i} does not meet its own bits")
            if self.rules.known.get(low + i, want) != want:
                raise _Lie(f"header {low + i} is not block {self.rules.known[low + i]}")
            want = _hprev(got[i])
        with self._lock:
            ch.prepend(low, got)

    def _start(self, s: _Server):
        cph, cphash = self.rules.checkpoint
        try:
            hdr = bytes.fromhex(s.call("blockchain.block.header", cph))
        except (TypeError, ValueError):
            raise _Lie("a header that is not hex")
        if len(hdr) != 80 or _hh(hdr) != cphash:
            raise _Lie(f"its block {cph} is not {cphash}: another network, or another chain")
        with self._lock:
            self.chain.start(cph, hdr)

    def _floor(self) -> int:
        """How far down the chain has to reach before headers above the checkpoint can be judged:
        the start of the checkpoint's difficulty period, and eleven timestamps."""
        cph = self.rules.checkpoint[0]
        low = min(cph - cph % self.rules.interval, cph - 11) if self.rules.retarget else cph
        if self._low_hint is not None and self._low_hint < low and cph - self._low_hint <= MAX_BACKFILL:
            low = self._low_hint - (self._low_hint % self.rules.interval if self.rules.retarget else 0)
        return max(0, low)

    def _fork(self, s: _Server, start: int) -> int:
        """The highest height at which the server's chain is the one held here."""
        ch, cph = self.chain, self.rules.checkpoint[0]
        h, step, high = start, 1, None
        while True:
            try:
                hdr = bytes.fromhex(s.call("blockchain.block.header", h))
            except (TypeError, ValueError):
                raise _Lie("a header that is not hex")
            if len(hdr) == 80 and _hh(hdr) == ch.hash_at(h):
                break
            if h <= cph:
                raise _Lie(f"its chain does not hold block {cph} of this one ({ch.hash_at(cph)})")
            high, h, step = h, max(cph, h - step), step * 2
        if high is None:
            return h
        fork = h
        for i, hdr in enumerate(self._fetch(s, h + 1, high)):
            if _hh(hdr) != ch.hash_at(h + 1 + i):
                break
            fork = h + 1 + i
        return fork

    def _sync_from(self, s: _Server):
        ch = self.chain
        if ch.base is None:
            self._start(s)
        if ch.base > self._floor():
            self._down(s, self._floor())
        tip = s.call("blockchain.headers.subscribe")
        try:
            th, thdr = int(tip["height"]), bytes.fromhex(tip["hex"])
        except (TypeError, KeyError, ValueError):
            raise _Lie("a tip not in the protocol's form")
        if len(thdr) != 80 or th < self.rules.checkpoint[0]:
            raise _Lie(f"its tip is at {th}, below block {self.rules.checkpoint[0]} of this chain")
        if th <= ch.height and ch.hash_at(th) == _hh(thdr):
            return  # on the chain held here, at its tip or behind it
        fork = self._fork(s, min(ch.height, th))
        if th <= fork:
            return
        if th - fork > 400_000:
            raise _Lie("a chain hundreds of thousands of blocks past the checkpoint")
        new = self._fetch(s, fork + 1, th)
        self._check(fork, new)
        if sum(work_from_bits(_hbits(x)) for x in new) > ch.work_above(fork):
            with self._lock:
                if fork < ch.height:
                    log.warning("Bitcoin reorganised at %d: %d blocks left the best chain (%s says so, and its chain has "
                                "more work)", fork + 1, ch.height - fork, s.label)
                ch.adopt(fork, new)

    def _sync(self, force: bool = False):
        """Bring the chain up to what the servers have. At most every `poll` seconds."""
        def fresh():
            return self._synced_at is not None and time.monotonic() - self._synced_at < self.poll
        if not force and fresh():
            return
        with self._sync_lock:
            if not force and fresh():
                return
            ok, said = 0, []
            for s in self._order():
                try:
                    self._sync_from(s)
                    s.good()
                    ok += 1
                except _Lie as e:
                    s.lied(e)
                    said.append(f"{s.label}: {e}")
                except ElectrumError as e:
                    s.fail(e.message)
                    said.append(f"{s.label}: {e.message}")
                except OSError as e:
                    s.fail(e)
                    said.append(f"{s.label}: {e}")
                if ok >= self._quorum():
                    break
            if not ok:
                raise self._none("the chain of headers", said)
            self._synced_at = time.monotonic()

    def _ensure_low(self, h: int):
        ch = self.chain
        if h >= ch.base:
            return
        if self.rules.checkpoint[0] - h > MAX_BACKFILL:
            raise NotAvailable(f"block {h} is more than {MAX_BACKFILL} below block {self.rules.checkpoint[0]}, where this "
                               "chain of headers is taken up: blocks that old are not kept")
        with self._sync_lock:
            said = []
            for s in self._order():
                if h >= ch.base:
                    return
                try:
                    self._down(s, h)
                    return
                except _Lie as e:
                    s.lied(e)
                    said.append(f"{s.label}: {e}")
                except ElectrumError as e:
                    s.fail(e.message)
                    said.append(f"{s.label}: {e.message}")
                except OSError as e:
                    s.fail(e)
                    said.append(f"{s.label}: {e}")
            raise self._none(f"headers down to {h}", said)

    # ------------------------------------------------------------------ what can be proven
    def _remember(self, cache: OrderedDict, key, value, limit: int):
        with self._lock:
            cache[key] = value
            cache.move_to_end(key)
            while len(cache) > limit:
                cache.popitem(last=False)

    @staticmethod
    def _txid_ok(raw: bytes, txid: str) -> bool:
        try:
            return Tx.parse(raw).txid_hex() == txid
        except (ValueError, struct.error, IndexError):
            return False

    def _raw_tx(self, txid: str) -> bytes:
        """The bytes of a transaction, hashed here. RPCError -5 when the servers asked know none."""
        txid = txid.lower()
        with self._lock:
            if txid in self._txs:
                return self._txs[txid]
            if txid in self._ours:
                return self._ours[txid]
        said, unknown = [], 0
        for s in self._order():
            try:
                got = s.call("blockchain.transaction.get", txid)
                raw = bytes.fromhex(got)
            except ElectrumError as e:
                unknown += 1
                said.append(f"{s.label}: {e.message[:120]}")
                if unknown >= self._quorum():
                    break
                continue
            except OSError as e:
                s.fail(e)
                said.append(f"{s.label}: {e}")
                continue
            except (TypeError, ValueError):
                s.lied(f"transaction {txid} came back as something that is not hex")
                said.append(f"{s.label}: not hex")
                continue
            if not self._txid_ok(raw, txid):
                s.lied(f"the bytes it gave for transaction {txid} do not hash to it")
                said.append(f"{s.label}: bytes that do not hash to the id")
                continue
            self._remember(self._txs, txid, raw, 4000)
            return raw
        if unknown >= self._quorum():
            raise RPCError({"code": -5, "message": f"No such mempool or blockchain transaction {txid} "
                                                   f"({unknown} Electrum server{'s' * (unknown != 1)} asked)"})
        # "not there" is believed from `agree` servers: fewer said it, and the rest gave nothing usable
        raise self._none(f"transaction {txid}: {unknown} of the {self._quorum()} servers needed say it does not exist", said)

    def _proof(self, txid: str, height: int, reach: bool = False) -> Tuple[int, List[bytes]]:
        """(position, branch) of a transaction in the block at `height` of the chain held here,
        checked against that block's merkle root. NotProven when no server can show it. reach: a
        block below the headers held is reached for first (up to MAX_BACKFILL below the checkpoint)."""
        ch = self.chain
        if reach and ch.base is not None and 0 <= height < ch.base and self.rules.checkpoint[0] - height <= MAX_BACKFILL:
            self._ensure_low(height)
        if not ch.has(height):
            raise NotProven(f"transaction {txid}: block {height} is not on the chain of headers held here")
        hdr, bh = ch.header_at(height), ch.hash_at(height)
        with self._lock:
            hit = self._proofs.get((txid, bh))
        if hit:
            return hit[1], hit[2]
        said = []
        for s in self._order():
            try:
                r = s.call("blockchain.transaction.get_merkle", txid, height)
            except ElectrumError as e:
                said.append(f"{s.label}: {e.message[:120]}")
                continue
            except OSError as e:
                s.fail(e)
                said.append(f"{s.label}: {e}")
                continue
            try:
                pos, branch = int(r["pos"]), [bytes.fromhex(x)[::-1] for x in r["merkle"]]
                if pos < 0 or len(branch) > 32 or pos >> len(branch) or any(len(b) != 32 for b in branch):
                    raise ValueError
            except (TypeError, KeyError, ValueError):
                s.lied(f"a merkle branch for {txid} that is not in the protocol's form")
                said.append(f"{s.label}: malformed branch")
                continue
            if root_from_branch(bytes.fromhex(txid)[::-1], branch, pos) != hdr[36:68]:
                # A lie, or a server that sits on another block at that height for a moment: either way
                # nothing is taken from it, and it is asked again after a short pause.
                s.fail(f"its merkle branch for {txid} does not lead to the merkle root of block {height} ({bh})")
                said.append(f"{s.label}: a branch that does not reach the block's merkle root")
                continue
            self._remember(self._proofs, (txid, bh), (height, pos, branch), 8000)
            return pos, branch
        raise NotProven(f"transaction {txid} is not shown to be in block {height}: " + "; ".join(said))

    def _history(self, script: bytes) -> Dict[str, int]:
        """{txid: height} of everything that touches a script, as `agree` servers list it (height 0:
        not in a block yet). What one lists and another leaves out is kept: the caller proves each
        entry it uses, so only an entry no server lists can be missing."""
        sh = scripthash(script)
        out: Dict[str, int] = {}
        answered, said = 0, []
        for s in self._order():
            try:
                hist = s.call("blockchain.scripthash.get_history", sh)
                rows = [(str(e["tx_hash"]).lower(), int(e["height"])) for e in hist]
                if any(len(t) != 64 for t, _ in rows):
                    raise ValueError
            except ElectrumError as e:
                said.append(f"{s.label}: {e.message[:120]}")
                continue
            except OSError as e:
                s.fail(e)
                said.append(f"{s.label}: {e}")
                continue
            except (TypeError, KeyError, ValueError):
                s.lied("a history that is not in the protocol's form")
                said.append(f"{s.label}: malformed history")
                continue
            for t, h in rows:
                out[t] = max(out.get(t, 0), h if h > 0 else 0)
            answered += 1
            if answered >= self._quorum():
                return out
        raise self._none(f"the history of a script: {answered} of the {self._quorum()} answers needed", said)

    def _height_of_tx(self, txid: str, tx: Tx, scripts: Iterable[bytes] = ()) -> Optional[int]:
        """The height of the block a transaction is in, proven; 0: a server lists it and it is in no
        block as far as can be shown; None: the servers were asked and none lists it. Unreachable
        when they could not be asked: not knowing is never reported as "not there". scripts: more
        scripts whose history would list it."""
        ch = self.chain
        for s in self._order():  # servers that have the call say it in one round trip
            if s.no_get_height:
                continue
            try:
                h = s.call("blockchain.transaction.get_height", txid)
            except ElectrumError as e:
                if "unknown method" in e.message.lower() or "not found" not in e.message.lower():
                    s.no_get_height = True
                continue
            except OSError as e:
                s.fail(e)
                continue
            if isinstance(h, int) and not isinstance(h, bool) and h > 0 and ch.has(h):
                try:
                    self._proof(txid, h)
                    return h
                except NotProven:
                    pass
            break
        tried, asked, down = 0, 0, None
        for script in list(scripts) + [o.script_pubkey for o in tx.vout if o.script_pubkey and o.script_pubkey[0] != 0x6A]:
            if tried >= 3:
                break
            tried += 1
            try:
                h = self._history(script).get(txid)
            except Unreachable as e:
                down = e
                continue
            asked += 1
            if h is None:
                continue
            if h > 0:
                try:
                    self._proof(txid, h)
                except NotProven as e:  # listed in a block nobody can show it in (yet): not confirmed as far as this goes
                    log.info("%s", e)
                    return 0
            return h
        if not asked and down is not None:
            raise down
        return None

    def _utxos(self, scripts: List[str], prove: bool = True) -> Tuple[int, Dict[str, List[dict]]]:
        """(tip, {script hex: outputs}) in the servers' form (tx_hash, tx_pos, value, height; height
        0: not in a block yet). The confirmed ones are what `agree` servers both list. With `prove`
        each one's transaction is fetched and hashed and must pay that script that value, and it is
        shown to be in its block where the headers held reach that block (`proven`: True); an output
        older than those headers has `proven`: False and rests on the servers agreeing."""
        self._sync()
        shs = [scripthash(bytes.fromhex(x)) for x in scripts]
        need, last = self._quorum(), None
        for attempt in range(4):
            if attempt:
                time.sleep(0.4 * attempt)
            views, said = [], []
            for s in self._order():
                try:
                    res = s.batch([("blockchain.headers.subscribe", [])] + [("blockchain.scripthash.listunspent", [x]) for x in shs])
                    bad = next((r for r in res if isinstance(r, ElectrumError)), None)
                    if bad is not None:
                        said.append(f"{s.label}: {bad.message[:120]}")
                        continue
                    tip = int(res[0]["height"])
                    lists = [{(str(u["tx_hash"]).lower(), int(u["tx_pos"])): (int(u["value"]), max(0, int(u["height"])))
                              for u in r} for r in res[1:]]
                except OSError as e:
                    s.fail(e)
                    said.append(f"{s.label}: {e}")
                    continue
                except (TypeError, KeyError, ValueError):
                    s.lied("unspent outputs that are not in the protocol's form")
                    said.append(f"{s.label}: malformed list")
                    continue
                views.append((s, tip, lists))
                if len(views) >= need:
                    break
            if len(views) < need:
                raise self._none(f"unspent outputs: {len(views)} of the {need} answers needed", said)
            common = min(v[1] for v in views)

            def settled(lists):
                return [{k: v for k, v in one.items() if 0 < v[1] <= common} for one in lists]
            first = settled(views[0][2])
            last = next(((v[0], settled(v[2])) for v in views[1:] if settled(v[2]) != first), None)
            if last is None:
                break
        else:
            other, theirs = last
            diff = []
            for script, a, b in zip(scripts, first, theirs):
                for k in sorted(set(a.items()) ^ set(b.items()))[:3]:
                    diff.append(f"{k[0][0]}:{k[0][1]} of script {script[:16]}..")
            raise Disagreement(f"{views[0][0].label} and {other.label} list different unspent outputs ({', '.join(diff[:6])}); "
                               "neither can be proven right, so neither is believed")
        out: Dict[str, List[dict]] = {}
        for i, script in enumerate(scripts):
            merged: Dict[Tuple[str, int], Tuple[int, int]] = {}
            for _s, _tip, lists in views:
                for k, v in lists[i].items():
                    if k not in merged or v[1] > merged[k][1]:
                        merged[k] = v
            rows = []
            for (txid, n), (value, height) in merged.items():
                if height > self.chain.height:
                    height = 0  # a block the chain here has not taken yet: not confirmed as far as this goes
                row = {"tx_hash": txid, "tx_pos": n, "value": value, "height": height}
                if height > 0 and prove:
                    row["proven"] = self._prove_output(txid, n, height, bytes.fromhex(script), value)
                rows.append(row)
            out[script] = sorted(rows, key=lambda u: (u["height"] or 1 << 30, u["tx_hash"], u["tx_pos"]))
        return self.chain.height, out

    def _prove_output(self, txid: str, n: int, height: int, script: bytes, value: int) -> bool:
        tx = Tx.parse(self._raw_tx(txid))
        if n >= len(tx.vout) or tx.vout[n].script_pubkey != script or tx.vout[n].value != value:
            raise Disagreement(f"the servers list output {txid}:{n} as {value} sats to a script, and the transaction itself "
                               "says otherwise")
        if not self.chain.has(height):
            return False  # older than the headers held: its place in a block is not looked at
        self._proof(txid, height)
        return True

    # ------------------------------------------------------------------ the calls of a Bitcoin RPC object
    def call(self, method, *params):
        return getattr(self, method)(*params)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def missing(*_a, **_k):
            raise NotAvailable(f"{name}: not a call this object answers. It reaches Bitcoin through Electrum servers "
                               "(hashfun/btclight.py lists what it answers); this one needs a Bitcoin Core node")
        return missing

    def getblockcount(self) -> int:
        self._sync()
        return self.chain.height

    def getbestblockhash(self) -> str:
        self._sync()
        return self.chain.hash_at(self.chain.height)

    def getblockhash(self, height: int) -> str:
        self._sync()
        height = int(height)
        if height < 0 or height > self.chain.height:
            raise RPCError({"code": -8, "message": "Block height out of range"})
        self._ensure_low(height)
        return self.chain.hash_at(height)

    def getblockheader(self, blockhash: str, verbose=True):
        self._sync()
        ch, blockhash = self.chain, str(blockhash).lower()
        with self._lock:
            h = ch.index.get(blockhash)
            gone = ch.stale.get(blockhash) if h is None else None
            if h is not None:
                hdr, tip = ch.header_at(h), ch.height
                mtp = ch.mtp(h)
                nxt = ch.hash_at(h + 1) if h < tip else None
        if h is None and gone is None:
            raise RPCError({"code": -5, "message": "Block not found"})
        if h is None:
            if not verbose:
                raise RPCError({"code": -5, "message": "Block not found (it left the best chain)"})
            return {"hash": blockhash, "confirmations": -1, "height": gone}
        if not verbose:
            return hdr.hex()
        out = {"hash": blockhash, "confirmations": tip - h + 1, "height": h, "version": struct.unpack_from("<i", hdr)[0],
               "versionHex": hdr[0:4][::-1].hex(), "merkleroot": hdr[36:68][::-1].hex(), "time": _htime(hdr),
               "mediantime": mtp, "nonce": struct.unpack_from("<I", hdr, 76)[0], "bits": f"{_hbits(hdr):08x}",
               "previousblockhash": _hprev(hdr)}
        if nxt:
            out["nextblockhash"] = nxt
        return out

    def getblockchaininfo(self) -> dict:
        self._sync()
        ch = self.chain
        with self._lock:
            tip = ch.height
            return {"chain": self.rules.chain, "blocks": tip, "headers": tip, "bestblockhash": ch.hash_at(tip),
                    "mediantime": ch.mtp(tip), "time": _htime(ch.header_at(tip)), "initialblockdownload": False,
                    "pruned": True, "light": [s.label for s in self.servers]}

    def getblock(self, blockhash, verbosity=1):
        raise NotAvailable("getblock: an Electrum server does not hand out blocks. Ask this object instead: txproof(txid, "
                           "blockhash) for where a transaction sits in its block, payments_to(script) for payments to a "
                           "script, find_spend(txid, vout) for what spent an output")

    def getrawmempool(self, *_a):
        raise NotAvailable("getrawmempool: an Electrum server does not list its mempool. find_spend(txid, vout) says what "
                           "spent an output, in a block or not")

    def decoderawtransaction(self, hexstring: str, iswitness=None) -> dict:
        raw = bytes.fromhex(hexstring)
        try:
            tx = _parse_tx(raw, iswitness)
        except (ValueError, struct.error, IndexError):
            try:
                tx = _parse_tx(raw, False)
            except (ValueError, struct.error, IndexError):
                raise RPCError({"code": -22, "message": "TX decode failed"})
        return _decode(tx, raw)

    def getrawtransaction(self, txid: str, verbose=False, blockhash=None):
        raw = self._raw_tx(txid)
        if not verbose:
            return raw.hex()
        self._sync()
        tx = Tx.parse(raw)
        out = _decode(tx, raw)
        h = self._height_of_tx(txid.lower(), tx)
        if h:
            with self._lock:
                if self.chain.has(h):
                    out.update(blockhash=self.chain.hash_at(h), confirmations=self.chain.height - h + 1,
                               blocktime=_htime(self.chain.header_at(h)), time=_htime(self.chain.header_at(h)))
        return out

    def gettxout(self, txid: str, n: int, include_mempool=True):
        txid, n = txid.lower(), int(n)
        try:
            tx = Tx.parse(self._raw_tx(txid))
        except RPCError:
            return None
        if n >= len(tx.vout):
            return None
        o = tx.vout[n]
        tip, res = self._utxos([o.script_pubkey.hex()], prove=False)
        u = next((u for u in res[o.script_pubkey.hex()] if u["tx_hash"] == txid and u["tx_pos"] == n), None)
        if u is None or (u["height"] == 0 and not include_mempool):
            return None
        if u["height"] > 0:
            self._proof(txid, u["height"], reach=True)  # NotProven: no confirmations are made up for it
        return {"bestblock": self.chain.hash_at(tip), "confirmations": tip - u["height"] + 1 if u["height"] > 0 else 0,
                "value": o.value / COIN, "sats": o.value, "scriptPubKey": {"hex": o.script_pubkey.hex()},
                "coinbase": _is_coinbase(tx)}

    def scantxoutset(self, action: str, scanobjects=None) -> dict:
        """The confirmed outputs of scripts, each given as raw(HEX), in scantxoutset's shape."""
        if action != "start":
            raise NotAvailable("scantxoutset: only 'start'")
        scripts = []
        for o in scanobjects or []:
            d = (o.get("desc") if isinstance(o, dict) else o).split("#")[0].strip()
            if not (d.startswith("raw(") and d.endswith(")")):
                raise NotAvailable(f"scantxoutset: only raw(HEX) descriptors can be asked of Electrum servers, not {d[:24]}")
            scripts.append(d[4:-1].lower())
        tip, res = self._utxos(scripts)
        unspents = [{"txid": u["tx_hash"], "vout": u["tx_pos"], "scriptPubKey": s, "desc": f"raw({s})",
                     "amount": u["value"] / COIN, "sats": u["value"], "height": u["height"]}
                    for s in scripts for u in res[s] if u["height"] > 0]
        return {"success": True, "height": tip, "bestblock": self.chain.hash_at(tip), "unspents": unspents,
                "total_amount": sum(u["sats"] for u in unspents) / COIN}

    def estimatesmartfee(self, conf_target=2, _mode=None) -> dict:
        """The highest estimate among the servers asked, capped at fee_cap sat/vB: one server alone
        cannot make a payment wait, and none can make it cost more than the cap."""
        best = None
        for s in self._order()[:self._quorum()]:
            try:
                r = s.call("blockchain.estimatefee", int(conf_target))
            except ElectrumError:
                continue
            except OSError as e:
                s.fail(e)
                continue
            if isinstance(r, (int, float)) and r > 0:
                best = max(best or 0, float(r))
        if best is None:
            return {"errors": ["Insufficient data or no feerate found"], "blocks": int(conf_target)}
        return {"feerate": min(best, self.fee_cap * 1000 / COIN), "blocks": int(conf_target)}

    def _seen(self, txid: str, tx: Tx) -> bool:
        """Does a server show this transaction, in a block or waiting for one? Unreachable when that
        could not be asked."""
        return self._height_of_tx(txid, tx, [self._script] if self._script else ()) is not None

    def sendrawtransaction(self, hexstring: str, _maxfeerate=None) -> str:
        raw = bytes.fromhex(hexstring)
        try:
            tx = Tx.parse(raw)
        except (ValueError, struct.error, IndexError):
            raise RPCError({"code": -22, "message": "TX decode failed"})
        txid = tx.txid_hex()
        took, refused, said = 0, [], []
        for s in self._order():
            try:
                s.call("blockchain.transaction.broadcast", hexstring)
                took += 1
            except ElectrumError as e:
                if any(a in e.message.lower() for a in _ALREADY):
                    took += 1
                else:
                    refused.append(f"{s.label}: {e.message.split(hexstring[:40])[0].strip()[:300]}")
            except OSError as e:
                s.fail(e)
                said.append(f"{s.label}: {e}")
            if took >= self._quorum():
                break
        if not took and not refused:
            raise self._none("sending a transaction", said)
        if not took:
            # Refused everywhere. A transaction whose inputs are gone is refused like that too when it
            # is the one that spent them, so look for it before calling it refused (an index a moment
            # behind its node gets a second look).
            gone = any(w in r.lower() for r in refused for w in ("missing", "spent", "orphan", "conflict"))
            for wait in ((0.0, 1.5, 3.0) if gone else (0.0,)):
                time.sleep(wait)
                self._sync(force=wait > 0)
                if self._seen(txid, tx):
                    took = 1
                    break
        if not took:
            raise RPCError({"code": -26, "message": refused[0]})
        self._remember(self._txs, txid, raw, 4000)
        self._sent(txid, tx)
        return txid

    # ------------------------------------------------------------------ what block scanners ask instead
    def unspent(self, scripts: Iterable[str]) -> Tuple[int, Dict[str, List[dict]]]:
        """(tip height, {script hex: [{tx_hash, tx_pos, value, height}]}): confirmed outputs, each
        proven to be in its block, and the ones not in a block yet with height 0. The same shape the
        site's Electrum index (web.BtcIndex.unspent) gives."""
        return self._utxos([s.lower() for s in scripts])

    def txproof(self, txid: str, blockhash: Optional[str] = None) -> dict:
        """Where a confirmed transaction sits in its block: {txid, hex, height, blockhash,
        confirmations, pos, branch (32-byte hashes, internal byte order, as the launch chain's proof
        takes them)}. RPCError -5 when it is in no block of the best chain."""
        txid = txid.lower()
        raw = self._raw_tx(txid)
        self._sync()
        if blockhash is not None:
            h = self.chain.index.get(str(blockhash).lower())
            if h is None:
                raise RPCError({"code": -5, "message": f"Block {blockhash} is not on the best chain"})
        else:
            h = self._height_of_tx(txid, Tx.parse(raw))
            if not h:
                raise RPCError({"code": -5, "message": f"Transaction {txid} is not in a block"})
        try:
            pos, branch = self._proof(txid, h, reach=True)
        except NotProven as e:
            raise RPCError({"code": -5, "message": str(e)})
        with self._lock:
            return {"txid": txid, "hex": raw.hex(), "height": h, "blockhash": self.chain.hash_at(h),
                    "confirmations": self.chain.height - h + 1, "pos": pos, "branch": list(branch)}

    def payments_to(self, script_hex: str, min_height: int = 0, limit: int = 2000) -> List[dict]:
        """Every confirmed transaction with an output paying a script, from block min_height up, in
        the order of the chain. Each was fetched and hashed and is proven to be in its block. An
        entry is a transaction as getblock(hash, 2) lists it (txid, hex, vout with value and
        scriptPubKey.hex) plus height, blockhash, confirmations, pos and branch (as txproof).
        What a server lists and cannot be proven is left out and said in the log."""
        self._sync()
        script = bytes.fromhex(script_hex)
        hist = self._history(script)
        rows = sorted((h, t) for t, h in hist.items() if h > 0 and h >= min_height and self.chain.has(h))
        if len(rows) > limit:
            raise NotAvailable(f"{len(rows)} transactions touch that script from block {min_height} up: ask with a higher "
                               f"min_height (the limit is {limit})")
        out = []
        for h, txid in rows:
            try:
                raw = self._raw_tx(txid)
                tx = Tx.parse(raw)
                if not any(o.script_pubkey == script for o in tx.vout):
                    continue  # it spends from the script: not a payment to it
                pos, branch = self._proof(txid, h)
            except (RPCError, NotProven) as e:
                log.warning("a transaction listed for script %s.. is left out: %s", script_hex[:16], e)
                continue
            with self._lock:
                if not self.chain.has(h):
                    continue
                d = _decode(tx, raw)
                d.update(height=h, blockhash=self.chain.hash_at(h), confirmations=self.chain.height - h + 1, pos=pos,
                         branch=list(branch))
            out.append(d)
        return sorted(out, key=lambda d: (d["height"], d["pos"]))

    def find_spend(self, txid: str, vout: int) -> Optional[Tx]:
        """The transaction that spends an output, in a block or not, or None. A spender in a block
        is proven to be there. One that is in no block yet is whatever a server says it is: its bytes
        hash to its id and name the output, and nothing checked its signatures, so a secret read out
        of it has to be checked against its hash by whoever uses it."""
        txid, vout = txid.lower(), int(vout)
        self._sync()
        tx = Tx.parse(self._raw_tx(txid))
        if vout >= len(tx.vout):
            return None
        prev = bytes.fromhex(txid)[::-1]
        hist = self._history(tx.vout[vout].script_pubkey)
        for t, h in sorted(hist.items(), key=lambda kv: (kv[1] == 0, -kv[1])):
            if t == txid:
                continue
            try:
                cand = Tx.parse(self._raw_tx(t))
            except RPCError:
                continue
            if not any(i.prev_txid == prev and i.prev_vout == vout for i in cand.vin):
                continue
            if h > 0:
                try:
                    self._proof(t, h)
                except NotProven as e:
                    log.warning("a spender of %s:%d is left out: %s", txid, vout, e)
                    continue
            return cand
        return None

    # ------------------------------------------------------------------ the wallet of one key
    def wallet(self, keyfile: str) -> "BtcLight":
        """This object with a key to pay from: a file holding a private key as 64 hex digits or WIF.
        (Where a Bitcoin Core RPC object takes a wallet's name.)"""
        path = os.path.expanduser(str(keyfile))
        try:
            with open(path) as f:
                key = _read_key(f.read())
        except OSError as e:
            raise NotAvailable(f"the key to pay Bitcoin from could not be read: {e}. Through Electrum servers the wallet is "
                               "a file with one private key (64 hex digits or WIF), named where a Bitcoin Core wallet's name "
                               "goes")
        return self.with_key(key)

    def with_key(self, key: int) -> "BtcLight":
        w = BtcLight.__new__(BtcLight)
        w.__dict__.update(self.__dict__)
        w._key = key
        w._init_wallet()
        return w

    @property
    def address(self) -> Optional[str]:
        return segwit_encode(self.rules.hrp, 0, hash160(self._pub)) if self._key else None

    def getnewaddress(self, *_a) -> str:
        """The key's one address (a wallet of one key has no other to give)."""
        self._need_key("getnewaddress")
        return self.address

    def _need_key(self, what: str):
        if not self._key:
            raise NotAvailable(f"{what}: this object holds no key. Through Electrum servers the wallet that pays is one "
                               "private key in a file: btc.wallet(FILE)")

    def _sent(self, txid: str, tx: Tx):
        """A transaction went out through here: its inputs are spent as far as this wallet goes, and
        what it pays the wallet can be spent before a server lists it."""
        if not self._key:
            return
        with self._wlock:
            mine = False
            for i in tx.vin:
                k = (i.prev_txid[::-1].hex(), i.prev_vout)
                if k in self._reserved or k in self._pending:
                    mine = True
                    self._reserved[k] = (txid, time.time(), True)
                    self._pending.pop(k, None)
            if mine:
                for n, o in enumerate(tx.vout):
                    if o.script_pubkey == self._script:
                        self._pending[(txid, n)] = o.value

    def _spendable(self) -> List[dict]:
        """The wallet's outputs that can fund a payment now: confirmed and proven, plus its own
        change that waits for a block, minus what it has already put into a transaction."""
        _tip, res = self._utxos([self._script.hex()])
        listed = {(u["tx_hash"], u["tx_pos"]): u for u in res[self._script.hex()]}
        now = time.time()
        with self._wlock:
            for k, (spender, when, sent) in list(self._reserved.items()):
                # signed and never sent: free again after ten minutes. Sent: until no server lists the output any more.
                # (sent, and after an hour the servers still list the output: the transaction never reached them)
                if (not sent and now - when > 600) or (sent and now - when > (3600 if k in listed else 600)):
                    del self._reserved[k]
            for k in list(self._pending):
                if k in listed and listed[k]["height"] > 0:
                    del self._pending[k]
            out = [u for k, u in listed.items() if k not in self._reserved and (u["height"] > 0 or k in self._pending)]
            have = {(u["tx_hash"], u["tx_pos"]) for u in out}
            out += [{"tx_hash": t, "tx_pos": n, "value": v, "height": 0} for (t, n), v in self._pending.items()
                    if (t, n) not in have and (t, n) not in self._reserved]
        return out

    def getbalance(self, *_a) -> float:
        self._need_key("getbalance")
        return sum(u["value"] for u in self._spendable()) / COIN

    def fundrawtransaction(self, hexstring: str, options: Optional[dict] = None, iswitness=None) -> dict:
        """Add inputs from the key's address, and change back to it, to a transaction that has its
        outputs. options: changePosition (default: last), feeRate / fee_rate are not read: the fee
        is estimatesmartfee(2), at least 1 and at most fee_cap sat/vB."""
        self._need_key("fundrawtransaction")
        try:
            tx = _parse_tx(bytes.fromhex(hexstring), False if iswitness is None else iswitness)
        except (ValueError, struct.error, IndexError):
            raise RPCError({"code": -22, "message": "TX decode failed"})
        if tx.vin:
            raise NotAvailable("fundrawtransaction: a transaction that already has inputs")
        est = self.estimatesmartfee(2)
        rate = max(1, min(self.fee_cap, int(est["feerate"] * COIN / 1000 + 0.999999))) if "feerate" in est else self.fallback_fee
        need = sum(o.value for o in tx.vout)
        coins = sorted(self._spendable(), key=lambda u: (u["height"] == 0, -u["value"]))
        pos = (options or {}).get("changePosition", len(tx.vout))
        if not 0 <= pos <= len(tx.vout):
            raise RPCError({"code": -8, "message": "changePosition out of bounds"})
        picked, total = [], 0
        for u in coins:
            picked.append(u)
            total += u["value"]
            trial = Tx(tx.version, [TxIn(bytes.fromhex(p["tx_hash"])[::-1], p["tx_pos"], b"", 0xFFFFFFFD,
                                         [b"\0" * 72, b"\0" * 33]) for p in picked], list(tx.vout), tx.locktime)
            fee_bare = rate * trial.vsize()
            trial.vout.insert(pos, TxOut(0, self._script))
            fee_change = rate * trial.vsize()
            if total >= need + fee_change + DUST:
                change = total - need - fee_change
                break
            if total >= need + fee_bare:
                change = 0  # what is left would not pay for an output of its own: it goes to the fee
                break
        else:
            raise RPCError({"code": -4, "message": f"Insufficient funds: {total} sats at {self.address} that can be spent "
                                                   f"now, and the payment needs {need} and its fee"})
        out = Tx(tx.version, [TxIn(bytes.fromhex(p["tx_hash"])[::-1], p["tx_pos"], b"", 0xFFFFFFFD) for p in picked],
                 list(tx.vout), tx.locktime)
        if change:
            out.vout.insert(pos, TxOut(change, self._script))
        return {"hex": out.serialize().hex(), "fee": (total - need - change) / COIN, "changepos": pos if change else -1}

    def signrawtransactionwithwallet(self, hexstring: str, *_a) -> dict:
        self._need_key("signrawtransactionwithwallet")
        try:
            tx = _parse_tx(bytes.fromhex(hexstring))
        except (ValueError, struct.error, IndexError):
            raise RPCError({"code": -22, "message": "TX decode failed"})
        done = bool(tx.vin)
        for idx, i in enumerate(tx.vin):
            k = (i.prev_txid[::-1].hex(), i.prev_vout)
            with self._wlock:
                value = self._pending.get(k)
            if value is None:
                try:  # the amount is signed over, so it is read from the transaction itself, hashed here
                    prev = Tx.parse(self._raw_tx(k[0]))
                except RPCError:
                    done = False
                    continue
                if k[1] >= len(prev.vout) or prev.vout[k[1]].script_pubkey != self._script:
                    done = False
                    continue
                value = prev.vout[k[1]].value
            sig = der_sig(*ecdsa_sign(self._key, bip143_sighash(tx, idx, p2wpkh_script_code(self._pub), value))) + b"\x01"
            i.witness = [sig, self._pub]
        raw = tx.serialize()
        if done:
            txid = tx.txid_hex()
            with self._wlock:
                self._ours[txid] = raw
                while len(self._ours) > 500:
                    self._ours.popitem(last=False)
                for i in tx.vin:
                    k = (i.prev_txid[::-1].hex(), i.prev_vout)
                    if k not in self._reserved or not self._reserved[k][2]:
                        self._reserved[k] = (txid, time.time(), False)
        return {"hex": raw.hex(), "complete": done}

    def gettransaction(self, txid: str, *_a) -> dict:
        """{txid, confirmations, hex, and blockhash / blockheight once it is in a block}. A
        transaction this wallet signed that no server shows is sent again and reported with 0
        confirmations (a Bitcoin Core wallet does the same with its own). RPCError -5 for one that
        neither this wallet nor any server asked knows."""
        txid = txid.lower()
        self._sync()
        with self._wlock:
            own = self._ours.get(txid)
        try:
            raw = own or self._raw_tx(txid)
        except RPCError:
            raise RPCError({"code": -5, "message": "Invalid or non-wallet transaction id"})
        tx = Tx.parse(raw)
        h = self._height_of_tx(txid, tx, [self._script] if self._script else ())
        out = {"txid": txid, "confirmations": 0, "hex": raw.hex()}
        if h:
            with self._lock:
                if self.chain.has(h):
                    out.update(confirmations=self.chain.height - h + 1, blockhash=self.chain.hash_at(h), blockheight=h)
        elif h is None and own:
            try:
                self.sendrawtransaction(raw.hex())
            except (RPCError, Unreachable) as e:
                log.warning("payment %s is not shown by any server and could not be sent again: %s", txid, e)
        elif h is None:
            # Its bytes were seen once and no server lists it now: to a wallet that did not sign it,
            # that is a transaction it does not know. (The settler then sends the copy it stored.)
            raise RPCError({"code": -5, "message": "Invalid or non-wallet transaction id"})
        return out


# ------------------------------------------------------------------------------------ connect
def is_light_url(url) -> bool:
    return isinstance(url, str) and url.startswith(("electrum://", "electrums://"))


def is_light(rpc) -> bool:
    """Is this Bitcoin handle the object of this module? (Not hasattr: a hashfun.rpc.RPC answers
    every attribute name with a call.)"""
    return isinstance(rpc, BtcLight)


def open_rpc(url: str, cookie_file: Optional[str] = None, anchor=None, **kw):
    """What stands behind a --btc-rpc URL: this module's object for electrum:// and electrums://,
    a Bitcoin Core RPC object for anything else."""
    if is_light_url(url):
        return connect(url, anchor=anchor, **kw)
    from .rpc import RPC
    return RPC(url, cookie_file=cookie_file)


def connect(url: str, anchor=None, **kw) -> BtcLight:
    """The object for `electrums://HOST:PORT,HOST:PORT` (TLS) or `electrum://HOST:PORT,...` (plain TCP).

    A port left out is 50002 (TLS) or 50001. After the hosts, optionally: ?net=regtest (default
    main), ?agree=N (how many servers must say the same of what cannot be proven: default 2, or 1
    with one server), ?timeout=SECONDS, ?proxy=http://HOST:PORT (an HTTP CONNECT proxy; also
    $HASHFUN_ELECTRUM_PROXY), ?verify=1 (check the servers' TLS certificates against the system's
    authorities). The same as keyword arguments.

    anchor: (height, ...) of the lowest block that will be asked about, for instance a launch's
    Bitcoin anchor (height, header, period time): the headers are fetched down to there at the start
    instead of at the first question. It is never taken as true: the chain grows from the block hash
    written in this file, and descriptor.check_anchor asks about the anchor like about any block.
    Nothing is sent before the first call on the object."""
    if not is_light_url(url):
        raise ValueError(f"{url}: not electrum://HOST:PORT,... or electrums://HOST:PORT,...")
    scheme, _, rest = url.partition("://")
    tls = scheme == "electrums"
    hosts, _, query = rest.partition("?")
    q = {k: v[-1] for k, v in parse_qs(query).items()}
    q.update({k: v for k, v in kw.items() if v is not None})
    servers = []
    for part in hosts.strip("/").split(","):  # (several hosts, some in brackets: more than urlparse takes)
        part = part.strip()
        if not part:
            continue
        host, _, port = part.rpartition(":") if ":" in part and not part.endswith("]") else (part, "", "")
        if not host:
            host, port = part, ""
        try:
            servers.append((host.strip("[]"), int(port) if port else (50002 if tls else 50001), tls))
        except ValueError:
            raise ValueError(f"{url}: {part} is not HOST:PORT")
    if not servers:
        raise ValueError(f"{url}: no Electrum server named")
    net = q.get("net", "main")
    rules = net if isinstance(net, Rules) else NETS.get(net)
    if rules is None:
        raise ValueError(f"{url}: net={net} is not one of {', '.join(NETS)}")
    low = None
    if anchor is not None:
        low = int(getattr(anchor, "btc_anchor_height", None) if hasattr(anchor, "btc_anchor_height") else
                  anchor[0] if isinstance(anchor, (tuple, list)) else anchor)
    light = BtcLight(servers, rules, agree=int(q.get("agree", 2)), timeout=float(q.get("timeout", 12)),
                     poll=float(q.get("poll", 5)), proxy=q.get("proxy") or os.environ.get("HASHFUN_ELECTRUM_PROXY") or None,
                     tls_verify=str(q.get("verify", "")).lower() in ("1", "true", "yes"), low_hint=low,
                     fee_cap=int(q.get("fee_cap", 300)))
    if q.get("key"):
        light = light.wallet(q["key"])
    return light


# ------------------------------------------------------------------------------------ a look at servers
def check(url: str, deep: bool = True, out=print) -> bool:
    """What each server of the URL does, one at a time and timed: the handshake, its tip, the
    headers from the checkpoint up (every rule checked), and one old transaction fetched, hashed and
    proven. Then all of them together. Reads only."""
    base = connect(url)
    good = []
    for srv in base.servers:
        one = BtcLight([(srv.host, srv.port, srv.tls)], base.rules, agree=1, timeout=srv.timeout, proxy=srv.proxy,
                       tls_verify=srv.verify)
        s = one.servers[0]
        try:
            t0 = time.time()
            with s.lock:
                s._connect()
            t1 = time.time()
            tip = s.call("blockchain.headers.subscribe")
            t2 = time.time()
            one._sync(force=True)
            t3 = time.time()
            ch = one.chain
            line = (f"{s.label}: {s.version[0] if isinstance(s.version, list) else s.version}, handshake {1000 * (t1 - t0):.0f} ms, "
                    f"tip {tip['height']} in {1000 * (t2 - t1):.0f} ms, {ch.height - ch.base + 1} headers "
                    f"{ch.base}..{ch.height} checked in {t3 - t2:.1f} s")
            for h in sorted(base.rules.known):
                if ch.has(h):
                    assert ch.hash_at(h) == base.rules.known[h]
            if deep:
                low = min(base.rules.known)
                t4 = time.time()
                one._ensure_low(low)
                txid = s.call("blockchain.transaction.id_from_pos", low, 0)
                raw = one._raw_tx(txid)
                pos, branch = one._proof(txid, low)
                t5 = time.time()
                tx = Tx.parse(raw)
                line += (f"; down to block {low} ({ch.hash_at(low)[:20]}..) and its first transaction {txid[:16]}.. "
                         f"({len(raw)} bytes, {sum(o.value for o in tx.vout) / COIN:.8f} BTC, branch of {len(branch)}) "
                         f"hashed and proven in {t5 - t4:.1f} s")
                assert pos == 0 and _is_coinbase(tx)
            fee = one.estimatesmartfee(2)
            line += f"; fee for 2 blocks {fee.get('feerate', 'none')}"
            out("ok    " + line)
            good.append(srv)
        except Exception as e:  # noqa: BLE001  (a report: whatever went wrong is the finding)
            out(f"FAIL  {s.label}: {type(e).__name__}: {e}")
        finally:
            one.close()
    if len(good) >= 2:
        both = BtcLight([(g.host, g.port, g.tls) for g in good[:2]], base.rules, agree=2, timeout=good[0].timeout,
                        proxy=good[0].proxy, tls_verify=good[0].verify)
        try:
            t0 = time.time()
            info = both.getblockchaininfo()
            script = "0014" + sha256(b"hashfun btclight check")[:20].hex()  # nothing was ever paid to it: both must say so
            tip, res = both.unspent([script])
            out(f"ok    {good[0].label} + {good[1].label}: tip {info['blocks']} {info['bestblockhash'][:20]}.., median time "
                f"{info['mediantime']}, and they agree on a script's unspent outputs ({len(res[script])}), {time.time() - t0:.1f} s")
        except Exception as e:  # noqa: BLE001
            out(f"FAIL  {good[0].label} + {good[1].label}: {type(e).__name__}: {e}")
            return False
        finally:
            both.close()
    return bool(good)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="python -m hashfun.btclight", description="Bitcoin through Electrum servers")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("check", help="what each server does, timed (reads only)")
    p.add_argument("url", help="electrums://HOST:PORT,HOST:PORT or electrum://...")
    p.add_argument("--shallow", action="store_true", help="leave out the old transaction (it needs 125,000 more headers)")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    return 0 if check(a.url, deep=not a.shallow) else 1


if __name__ == "__main__":
    raise SystemExit(main())
