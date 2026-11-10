"""Hashing, secp256k1 ECDSA (RFC6979, low-S, DER) and BIP32. Stdlib only."""
import hashlib
import hmac
import os


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _ripemd160_py(msg: bytes) -> bytes:
    # Pure-Python RIPEMD-160 for builds whose OpenSSL dropped it.
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    r1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
          3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
          4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
    r2 = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    s1 = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
          11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
          9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
    s2 = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
    k1 = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    k2 = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]

    def f(j, x, y, z):
        if j < 16:
            return x ^ y ^ z
        if j < 32:
            return (x & y) | (~x & z)
        if j < 48:
            return (x | ~y) ^ z
        if j < 64:
            return (x & z) | (y & ~z)
        return x ^ (y | ~z)

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    ml = len(msg) * 8
    msg = msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64) + ml.to_bytes(8, "little")
    for i in range(0, len(msg), 64):
        X = [int.from_bytes(msg[i + 4 * j:i + 4 * j + 4], "little") for j in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            t = (rol((al + (f(j, bl, cl, dl) & 0xFFFFFFFF) + X[r1[j]] + k1[j // 16]) & 0xFFFFFFFF, s1[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t
            t = (rol((ar + (f(79 - j, br, cr, dr) & 0xFFFFFFFF) + X[r2[j]] + k2[j // 16]) & 0xFFFFFFFF, s2[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t
        t = (h[1] + cl + dr) & 0xFFFFFFFF
        h[1] = (h[2] + dl + er) & 0xFFFFFFFF
        h[2] = (h[3] + el + ar) & 0xFFFFFFFF
        h[3] = (h[4] + al + br) & 0xFFFFFFFF
        h[4] = (h[0] + bl + cr) & 0xFFFFFFFF
        h[0] = t
    return b"".join(x.to_bytes(4, "little") for x in h)


def ripemd160(b: bytes) -> bytes:
    try:
        return hashlib.new("ripemd160", b).digest()
    except (ValueError, TypeError):
        return _ripemd160_py(b)


def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))


# ---------------------------------------------------------------- secp256k1
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _jac_double(p):
    X, Y, Z = p
    if Y == 0:
        return (0, 0, 0)
    S = 4 * X * Y * Y % P
    M = 3 * X * X % P
    X2 = (M * M - 2 * S) % P
    Y2 = (M * (S - X2) - 8 * Y**4) % P
    return (X2, Y2, 2 * Y * Z % P)


def _jac_add(p, q):
    if p[2] == 0:
        return q
    if q[2] == 0:
        return p
    X1, Y1, Z1 = p
    X2, Y2, Z2 = q
    Z1s, Z2s = Z1 * Z1 % P, Z2 * Z2 % P
    U1, U2 = X1 * Z2s % P, X2 * Z1s % P
    S1, S2 = Y1 * Z2s * Z2 % P, Y2 * Z1s * Z1 % P
    if U1 == U2:
        return _jac_double(p) if S1 == S2 else (0, 0, 0)
    H, R = (U2 - U1) % P, (S2 - S1) % P
    H2 = H * H % P
    H3 = H * H2 % P
    U1H2 = U1 * H2 % P
    X3 = (R * R - H3 - 2 * U1H2) % P
    Y3 = (R * (U1H2 - X3) - S1 * H3) % P
    return (X3, Y3, H * Z1 * Z2 % P)


def _to_affine(p):
    if p[2] == 0:
        return None
    zi = pow(p[2], P - 2, P)
    return (p[0] * zi * zi % P, p[1] * zi * zi * zi % P)


def point_mul(k: int, pt=G):
    r = (0, 0, 0)
    q = (pt[0], pt[1], 1)
    while k:
        if k & 1:
            r = _jac_add(r, q)
        q = _jac_double(q)
        k >>= 1
    return _to_affine(r)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return _to_affine(_jac_add((a[0], a[1], 1), (b[0], b[1], 1)))


def ser_point(pt, compressed=True) -> bytes:
    x, y = pt
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def parse_point(b: bytes):
    if len(b) == 33 and b[0] in (2, 3):
        x = int.from_bytes(b[1:], "big")
        y2 = (pow(x, 3, P) + 7) % P
        y = pow(y2, (P + 1) // 4, P)
        if y * y % P != y2:
            raise ValueError("invalid point")
        if (y & 1) != (b[0] & 1):
            y = P - y
        return (x, y)
    if len(b) == 65 and b[0] == 4:
        x, y = int.from_bytes(b[1:33], "big"), int.from_bytes(b[33:], "big")
        if (y * y - x**3 - 7) % P:
            raise ValueError("invalid point")
        return (x, y)
    raise ValueError("bad pubkey encoding")


def pubkey_from_priv(priv: int, compressed=True) -> bytes:
    return ser_point(point_mul(priv), compressed)


def _rfc6979_k(priv: int, h: bytes):
    x = priv.to_bytes(32, "big")
    V = b"\x01" * 32
    K = b"\x00" * 32
    K = hmac.new(K, V + b"\x00" + x + h, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + x + h, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k = int.from_bytes(V, "big")
        if 1 <= k < N:
            yield k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


def ecdsa_sign(priv: int, msg32: bytes):
    z = int.from_bytes(msg32, "big")
    for k in _rfc6979_k(priv, msg32):
        R = point_mul(k)
        r = R[0] % N
        if r == 0:
            continue
        s = pow(k, N - 2, N) * (z + r * priv) % N
        if s == 0:
            continue
        if s > N // 2:
            s = N - s
        return r, s


def ecdsa_verify(pub: bytes, msg32: bytes, r: int, s: int) -> bool:
    if not (1 <= r < N and 1 <= s < N):
        return False
    Q = parse_point(pub)
    z = int.from_bytes(msg32, "big")
    w = pow(s, N - 2, N)
    pt = point_add(point_mul(z * w % N), point_mul(r * w % N, Q))
    return pt is not None and pt[0] % N == r


def der_sig(r: int, s: int) -> bytes:
    def enc(i):
        b = i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    body = enc(r) + enc(s)
    return b"\x30" + bytes([len(body)]) + body


def parse_der(sig: bytes):
    if sig[0] != 0x30:
        raise ValueError("not DER")
    rl = sig[3]
    r = int.from_bytes(sig[4:4 + rl], "big")
    sl = sig[5 + rl]
    s = int.from_bytes(sig[6 + rl:6 + rl + sl], "big")
    return r, s


def random_priv() -> int:
    while True:
        k = int.from_bytes(os.urandom(32), "big")
        if 1 <= k < N:
            return k


# ---------------------------------------------------------------- BIP32
HARD = 0x80000000


class XPriv:
    def __init__(self, key: int, chain: bytes, depth=0, fpr=b"\0\0\0\0", child=0):
        self.key, self.chain, self.depth, self.fpr, self.child = key, chain, depth, fpr, child

    @classmethod
    def from_seed(cls, seed: bytes):
        I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        return cls(int.from_bytes(I[:32], "big"), I[32:])

    def pub(self) -> bytes:
        return pubkey_from_priv(self.key)

    def ckd(self, i: int) -> "XPriv":
        if i >= HARD:
            data = b"\x00" + self.key.to_bytes(32, "big") + i.to_bytes(4, "big")
        else:
            data = self.pub() + i.to_bytes(4, "big")
        I = hmac.new(self.chain, data, hashlib.sha512).digest()
        il = int.from_bytes(I[:32], "big")
        if il >= N:
            raise ValueError("invalid child")
        k = (il + self.key) % N
        return XPriv(k, I[32:], self.depth + 1, hash160(self.pub())[:4], i)

    def derive(self, path: str) -> "XPriv":
        node = self
        for part in path.split("/"):
            if part in ("m", ""):
                continue
            hard = part.endswith("'") or part.endswith("h")
            idx = int(part.rstrip("'h"))
            node = node.ckd(idx + HARD if hard else idx)
        return node

    def serialize(self, version=bytes.fromhex("0488ade4")) -> bytes:
        return (version + bytes([self.depth]) + self.fpr + self.child.to_bytes(4, "big") + self.chain +
                b"\x00" + self.key.to_bytes(32, "big"))

    def serialize_pub(self, version=bytes.fromhex("0488b21e")) -> bytes:
        return (version + bytes([self.depth]) + self.fpr + self.child.to_bytes(4, "big") + self.chain + self.pub())
