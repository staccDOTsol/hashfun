var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod2, isNodeMode, target) => (target = mod2 != null ? __create(__getProtoOf(mod2)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod2 || !mod2.__esModule ? __defProp(target, "default", { value: mod2, enumerable: true }) : target,
  mod2
));

// src/maker.mjs
var import_node_fs = __toESM(require("node:fs"), 1);
var import_node_os = __toESM(require("node:os"), 1);
var import_node_path = __toESM(require("node:path"), 1);
var import_node_crypto = __toESM(require("node:crypto"), 1);
var import_node_readline = __toESM(require("node:readline"), 1);

// node_modules/@noble/secp256k1/index.js
var B256 = 2n ** 256n;
var P = B256 - 0x1000003d1n;
var N = B256 - 0x14551231950b75fc4402da1732fc9bebfn;
var Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
var Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
var CURVE = { p: P, n: N, a: 0n, b: 7n, Gx, Gy };
var fLen = 32;
var crv = (x) => mod(mod(x * x) * x + CURVE.b);
var err = (m = "") => {
  throw new Error(m);
};
var big = (n) => typeof n === "bigint";
var str = (s) => typeof s === "string";
var fe = (n) => big(n) && 0n < n && n < P;
var ge = (n) => big(n) && 0n < n && n < N;
var isu8 = (a) => a instanceof Uint8Array || a != null && typeof a === "object" && a.constructor.name === "Uint8Array";
var au8 = (a, l) => (
  // assert is Uint8Array (of specific length)
  !isu8(a) || typeof l === "number" && l > 0 && a.length !== l ? err("Uint8Array expected") : a
);
var u8n = (data) => new Uint8Array(data);
var toU8 = (a, len) => au8(str(a) ? h2b(a) : u8n(au8(a)), len);
var mod = (a, b = P) => {
  let r = a % b;
  return r >= 0n ? r : b + r;
};
var isPoint = (p) => p instanceof Point ? p : err("Point expected");
var Point = class _Point {
  constructor(px, py, pz) {
    this.px = px;
    this.py = py;
    this.pz = pz;
  }
  //3d=less inversions
  static fromAffine(p) {
    return p.x === 0n && p.y === 0n ? _Point.ZERO : new _Point(p.x, p.y, 1n);
  }
  static fromHex(hex2) {
    hex2 = toU8(hex2);
    let p = void 0;
    const head = hex2[0], tail = hex2.subarray(1);
    const x = slcNum(tail, 0, fLen), len = hex2.length;
    if (len === 33 && [2, 3].includes(head)) {
      if (!fe(x))
        err("Point hex invalid: x not FE");
      let y = sqrt(crv(x));
      const isYOdd = (y & 1n) === 1n;
      const headOdd = (head & 1) === 1;
      if (headOdd !== isYOdd)
        y = mod(-y);
      p = new _Point(x, y, 1n);
    }
    if (len === 65 && head === 4)
      p = new _Point(x, slcNum(tail, fLen, 2 * fLen), 1n);
    return p ? p.ok() : err("Point is not on curve");
  }
  static fromPrivateKey(k) {
    return G.mul(toPriv(k));
  }
  // Create point from a private key.
  get x() {
    return this.aff().x;
  }
  // .x, .y will call expensive toAffine:
  get y() {
    return this.aff().y;
  }
  // should be used with care.
  equals(other) {
    const { px: X1, py: Y1, pz: Z1 } = this;
    const { px: X2, py: Y2, pz: Z2 } = isPoint(other);
    const X1Z2 = mod(X1 * Z2), X2Z1 = mod(X2 * Z1);
    const Y1Z2 = mod(Y1 * Z2), Y2Z1 = mod(Y2 * Z1);
    return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
  }
  negate() {
    return new _Point(this.px, mod(-this.py), this.pz);
  }
  // Flip point over y coord
  double() {
    return this.add(this);
  }
  // Point doubling: P+P, complete formula.
  add(other) {
    const { px: X1, py: Y1, pz: Z1 } = this;
    const { px: X2, py: Y2, pz: Z2 } = isPoint(other);
    const { a, b } = CURVE;
    let X3 = 0n, Y3 = 0n, Z3 = 0n;
    const b3 = mod(b * 3n);
    let t0 = mod(X1 * X2), t1 = mod(Y1 * Y2), t2 = mod(Z1 * Z2), t3 = mod(X1 + Y1);
    let t4 = mod(X2 + Y2);
    t3 = mod(t3 * t4);
    t4 = mod(t0 + t1);
    t3 = mod(t3 - t4);
    t4 = mod(X1 + Z1);
    let t5 = mod(X2 + Z2);
    t4 = mod(t4 * t5);
    t5 = mod(t0 + t2);
    t4 = mod(t4 - t5);
    t5 = mod(Y1 + Z1);
    X3 = mod(Y2 + Z2);
    t5 = mod(t5 * X3);
    X3 = mod(t1 + t2);
    t5 = mod(t5 - X3);
    Z3 = mod(a * t4);
    X3 = mod(b3 * t2);
    Z3 = mod(X3 + Z3);
    X3 = mod(t1 - Z3);
    Z3 = mod(t1 + Z3);
    Y3 = mod(X3 * Z3);
    t1 = mod(t0 + t0);
    t1 = mod(t1 + t0);
    t2 = mod(a * t2);
    t4 = mod(b3 * t4);
    t1 = mod(t1 + t2);
    t2 = mod(t0 - t2);
    t2 = mod(a * t2);
    t4 = mod(t4 + t2);
    t0 = mod(t1 * t4);
    Y3 = mod(Y3 + t0);
    t0 = mod(t5 * t4);
    X3 = mod(t3 * X3);
    X3 = mod(X3 - t0);
    t0 = mod(t3 * t1);
    Z3 = mod(t5 * Z3);
    Z3 = mod(Z3 + t0);
    return new _Point(X3, Y3, Z3);
  }
  mul(n, safe = true) {
    if (!safe && n === 0n)
      return I;
    if (!ge(n))
      err("invalid scalar");
    if (this.equals(G))
      return wNAF(n).p;
    let p = I, f2 = G;
    for (let d = this; n > 0n; d = d.double(), n >>= 1n) {
      if (n & 1n)
        p = p.add(d);
      else if (safe)
        f2 = f2.add(d);
    }
    return p;
  }
  mulAddQUns(R, u1, u2) {
    return this.mul(u1, false).add(R.mul(u2, false)).ok();
  }
  // to private keys. Doesn't use Shamir trick
  toAffine() {
    const { px: x, py: y, pz: z } = this;
    if (this.equals(I))
      return { x: 0n, y: 0n };
    if (z === 1n)
      return { x, y };
    const iz = inv(z);
    if (mod(z * iz) !== 1n)
      err("invalid inverse");
    return { x: mod(x * iz), y: mod(y * iz) };
  }
  assertValidity() {
    const { x, y } = this.aff();
    if (!fe(x) || !fe(y))
      err("Point invalid: x or y");
    return mod(y * y) === crv(x) ? (
      // y² = x³ + ax + b, must be equal
      this
    ) : err("Point invalid: not on curve");
  }
  multiply(n) {
    return this.mul(n);
  }
  // Aliases to compress code
  aff() {
    return this.toAffine();
  }
  ok() {
    return this.assertValidity();
  }
  toHex(isCompressed = true) {
    const { x, y } = this.aff();
    const head = isCompressed ? (y & 1n) === 0n ? "02" : "03" : "04";
    return head + n2h(x) + (isCompressed ? "" : n2h(y));
  }
  toRawBytes(isCompressed = true) {
    return h2b(this.toHex(isCompressed));
  }
};
Point.BASE = new Point(Gx, Gy, 1n);
Point.ZERO = new Point(0n, 1n, 0n);
var { BASE: G, ZERO: I } = Point;
var padh = (n, pad) => n.toString(16).padStart(pad, "0");
var b2h = (b) => Array.from(b).map((e) => padh(e, 2)).join("");
var h2b = (hex2) => {
  const l = hex2.length;
  if (!str(hex2) || l % 2)
    err("hex invalid 1");
  const arr = u8n(l / 2);
  for (let i = 0; i < arr.length; i++) {
    const j = i * 2;
    const h = hex2.slice(j, j + 2);
    const b = Number.parseInt(h, 16);
    if (Number.isNaN(b) || b < 0)
      err("hex invalid 2");
    arr[i] = b;
  }
  return arr;
};
var b2n = (b) => BigInt("0x" + (b2h(b) || "0"));
var slcNum = (b, from, to) => b2n(b.slice(from, to));
var n2b = (num) => {
  return big(num) && num >= 0n && num < B256 ? h2b(padh(num, 2 * fLen)) : err("bigint expected");
};
var n2h = (num) => b2h(n2b(num));
var concatB = (...arrs) => {
  const r = u8n(arrs.reduce((sum, a) => sum + au8(a).length, 0));
  let pad = 0;
  arrs.forEach((a) => {
    r.set(a, pad);
    pad += a.length;
  });
  return r;
};
var inv = (num, md = P) => {
  if (num === 0n || md <= 0n)
    err("no inverse n=" + num + " mod=" + md);
  let a = mod(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {
    const q = b / a, r = b % a;
    const m = x - u * q, n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  return b === 1n ? mod(x, md) : err("no inverse");
};
var sqrt = (n) => {
  let r = 1n;
  for (let num = n, e = (P + 1n) / 4n; e > 0n; e >>= 1n) {
    if (e & 1n)
      r = r * num % P;
    num = num * num % P;
  }
  return mod(r * r) === n ? r : err("sqrt invalid");
};
var toPriv = (p) => {
  if (!big(p))
    p = b2n(toU8(p, fLen));
  return ge(p) ? p : err("private key out of range");
};
var moreThanHalfN = (n) => n > N >> 1n;
var getPublicKey = (privKey, isCompressed = true) => {
  return Point.fromPrivateKey(privKey).toRawBytes(isCompressed);
};
var Signature = class _Signature {
  constructor(r, s, recovery) {
    this.r = r;
    this.s = s;
    this.recovery = recovery;
    this.assertValidity();
  }
  // constructed outside.
  static fromCompact(hex2) {
    hex2 = toU8(hex2, 64);
    return new _Signature(slcNum(hex2, 0, fLen), slcNum(hex2, fLen, 2 * fLen));
  }
  assertValidity() {
    return ge(this.r) && ge(this.s) ? this : err();
  }
  // 0 < r or s < CURVE.n
  addRecoveryBit(rec) {
    return new _Signature(this.r, this.s, rec);
  }
  hasHighS() {
    return moreThanHalfN(this.s);
  }
  normalizeS() {
    return this.hasHighS() ? new _Signature(this.r, mod(this.s, N), this.recovery) : this;
  }
  recoverPublicKey(msgh) {
    const { r, s, recovery: rec } = this;
    if (![0, 1, 2, 3].includes(rec))
      err("recovery id invalid");
    const h = bits2int_modN(toU8(msgh, fLen));
    const radj = rec === 2 || rec === 3 ? r + N : r;
    if (radj >= P)
      err("q.x invalid");
    const head = (rec & 1) === 0 ? "02" : "03";
    const R = Point.fromHex(head + n2h(radj));
    const ir = inv(radj, N);
    const u1 = mod(-h * ir, N);
    const u2 = mod(s * ir, N);
    return G.mulAddQUns(R, u1, u2);
  }
  toCompactRawBytes() {
    return h2b(this.toCompactHex());
  }
  // Uint8Array 64b compact repr
  toCompactHex() {
    return n2h(this.r) + n2h(this.s);
  }
  // hex 64b compact repr
};
var bits2int = (bytes2) => {
  const delta = bytes2.length * 8 - 256;
  const num = b2n(bytes2);
  return delta > 0 ? num >> BigInt(delta) : num;
};
var bits2int_modN = (bytes2) => {
  return mod(bits2int(bytes2), N);
};
var i2o = (num) => n2b(num);
var cr = () => (
  // We support: 1) browsers 2) node.js 19+ 3) deno, other envs with crypto
  typeof globalThis === "object" && "crypto" in globalThis ? globalThis.crypto : void 0
);
var _hmacSync;
var optS = { lowS: true };
var optV = { lowS: true };
var prepSig = (msgh, priv, opts2 = optS) => {
  if (["der", "recovered", "canonical"].some((k) => k in opts2))
    err("sign() legacy options not supported");
  let { lowS } = opts2;
  if (lowS == null)
    lowS = true;
  const h1i = bits2int_modN(toU8(msgh));
  const h1o = i2o(h1i);
  const d = toPriv(priv);
  const seed = [i2o(d), h1o];
  let ent = opts2.extraEntropy;
  if (ent) {
    if (ent === true)
      ent = etc.randomBytes(fLen);
    const e = toU8(ent);
    if (e.length !== fLen)
      err();
    seed.push(e);
  }
  const m = h1i;
  const k2sig = (kBytes) => {
    const k = bits2int(kBytes);
    if (!ge(k))
      return;
    const ik = inv(k, N);
    const q = G.mul(k).aff();
    const r = mod(q.x, N);
    if (r === 0n)
      return;
    const s = mod(ik * mod(m + mod(d * r, N), N), N);
    if (s === 0n)
      return;
    let normS = s;
    let rec = (q.x === r ? 0 : 2) | Number(q.y & 1n);
    if (lowS && moreThanHalfN(s)) {
      normS = mod(-s, N);
      rec ^= 1;
    }
    return new Signature(r, normS, rec);
  };
  return { seed: concatB(...seed), k2sig };
};
function hmacDrbg(asynchronous) {
  let v = u8n(fLen);
  let k = u8n(fLen);
  let i = 0;
  const reset = () => {
    v.fill(1);
    k.fill(0);
    i = 0;
  };
  const _e = "drbg: tried 1000 values";
  if (asynchronous) {
    const h = (...b) => etc.hmacSha256Async(k, v, ...b);
    const reseed = async (seed = u8n()) => {
      k = await h(u8n([0]), seed);
      v = await h();
      if (seed.length === 0)
        return;
      k = await h(u8n([1]), seed);
      v = await h();
    };
    const gen = async () => {
      if (i++ >= 1e3)
        err(_e);
      v = await h();
      return v;
    };
    return async (seed, pred) => {
      reset();
      await reseed(seed);
      let res = void 0;
      while (!(res = pred(await gen())))
        await reseed();
      reset();
      return res;
    };
  } else {
    const h = (...b) => {
      const f2 = _hmacSync;
      if (!f2)
        err("etc.hmacSha256Sync not set");
      return f2(k, v, ...b);
    };
    const reseed = (seed = u8n()) => {
      k = h(u8n([0]), seed);
      v = h();
      if (seed.length === 0)
        return;
      k = h(u8n([1]), seed);
      v = h();
    };
    const gen = () => {
      if (i++ >= 1e3)
        err(_e);
      v = h();
      return v;
    };
    return (seed, pred) => {
      reset();
      reseed(seed);
      let res = void 0;
      while (!(res = pred(gen())))
        reseed();
      reset();
      return res;
    };
  }
}
var sign = (msgh, priv, opts2 = optS) => {
  const { seed, k2sig } = prepSig(msgh, priv, opts2);
  return hmacDrbg(false)(seed, k2sig);
};
var verify = (sig, msgh, pub, opts2 = optV) => {
  let { lowS } = opts2;
  if (lowS == null)
    lowS = true;
  if ("strict" in opts2)
    err("verify() legacy options not supported");
  let sig_, h, P2;
  const rs = sig && typeof sig === "object" && "r" in sig;
  if (!rs && toU8(sig).length !== 2 * fLen)
    err("signature must be 64 bytes");
  try {
    sig_ = rs ? new Signature(sig.r, sig.s).assertValidity() : Signature.fromCompact(sig);
    h = bits2int_modN(toU8(msgh));
    P2 = pub instanceof Point ? pub.ok() : Point.fromHex(pub);
  } catch (e) {
    return false;
  }
  if (!sig_)
    return false;
  const { r, s } = sig_;
  if (lowS && moreThanHalfN(s))
    return false;
  let R;
  try {
    const is = inv(s, N);
    const u1 = mod(h * is, N);
    const u2 = mod(r * is, N);
    R = G.mulAddQUns(P2, u1, u2).aff();
  } catch (error) {
    return false;
  }
  if (!R)
    return false;
  const v = mod(R.x, N);
  return v === r;
};
var hashToPrivateKey = (hash2) => {
  hash2 = toU8(hash2);
  const minLen = fLen + 8;
  if (hash2.length < minLen || hash2.length > 1024)
    err("expected proper params");
  const num = mod(b2n(hash2), N - 1n) + 1n;
  return n2b(num);
};
var etc = {
  hexToBytes: h2b,
  bytesToHex: b2h,
  // share API with noble-curves.
  concatBytes: concatB,
  bytesToNumberBE: b2n,
  numberToBytesBE: n2b,
  mod,
  invert: inv,
  // math utilities
  hmacSha256Async: async (key, ...msgs) => {
    const c = cr();
    const s = c && c.subtle;
    if (!s)
      return err("etc.hmacSha256Async not set");
    const k = await s.importKey("raw", key, { name: "HMAC", hash: { name: "SHA-256" } }, false, ["sign"]);
    return u8n(await s.sign("HMAC", k, concatB(...msgs)));
  },
  hmacSha256Sync: _hmacSync,
  // For TypeScript. Actual logic is below
  hashToPrivateKey,
  randomBytes: (len = 32) => {
    const crypto3 = cr();
    if (!crypto3 || !crypto3.getRandomValues)
      err("crypto.getRandomValues must be defined");
    return crypto3.getRandomValues(u8n(len));
  }
};
Object.defineProperties(etc, { hmacSha256Sync: {
  configurable: false,
  get() {
    return _hmacSync;
  },
  set(f2) {
    if (!_hmacSync)
      _hmacSync = f2;
  }
} });
var W = 8;
var precompute = () => {
  const points = [];
  const windows = 256 / W + 1;
  let p = G, b = p;
  for (let w = 0; w < windows; w++) {
    b = p;
    points.push(b);
    for (let i = 1; i < 2 ** (W - 1); i++) {
      b = b.add(p);
      points.push(b);
    }
    p = b.double();
  }
  return points;
};
var Gpows = void 0;
var wNAF = (n) => {
  const comp = Gpows || (Gpows = precompute());
  const neg = (cnd, p2) => {
    let n2 = p2.negate();
    return cnd ? n2 : p2;
  };
  let p = I, f2 = G;
  const windows = 1 + 256 / W;
  const wsize = 2 ** (W - 1);
  const mask = BigInt(2 ** W - 1);
  const maxNum = 2 ** W;
  const shiftBy = BigInt(W);
  for (let w = 0; w < windows; w++) {
    const off = w * wsize;
    let wbits = Number(n & mask);
    n >>= shiftBy;
    if (wbits > wsize) {
      wbits -= maxNum;
      n += 1n;
    }
    const off1 = off, off2 = off + Math.abs(wbits) - 1;
    const cnd1 = w % 2 !== 0, cnd2 = wbits < 0;
    if (wbits === 0) {
      f2 = f2.add(neg(cnd1, comp[off1]));
    } else {
      p = p.add(neg(cnd2, comp[off2]));
    }
  }
  return { p, f: f2 };
};

// node_modules/@noble/hashes/esm/_assert.js
function number(n) {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error(`positive integer expected, not ${n}`);
}
function isBytes(a) {
  return a instanceof Uint8Array || a != null && typeof a === "object" && a.constructor.name === "Uint8Array";
}
function bytes(b, ...lengths) {
  if (!isBytes(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error(`Uint8Array expected of length ${lengths}, not of length=${b.length}`);
}
function hash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new Error("Hash should be wrapped by utils.wrapConstructor");
  number(h.outputLen);
  number(h.blockLen);
}
function exists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function output(out, instance) {
  bytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error(`digestInto() expects output buffer of length at least ${min}`);
  }
}

// node_modules/@noble/hashes/esm/utils.js
var createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
var rotr = (word, shift) => word << 32 - shift | word >>> shift;
var rotl = (word, shift) => word << shift | word >>> 32 - shift >>> 0;
var isLE = new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68;
function utf8ToBytes(str2) {
  if (typeof str2 !== "string")
    throw new Error(`utf8ToBytes expected string, got ${typeof str2}`);
  return new Uint8Array(new TextEncoder().encode(str2));
}
function toBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  bytes(data);
  return data;
}
var Hash = class {
  // Safe version that clones internal state
  clone() {
    return this._cloneInto();
  }
};
var toStr = {}.toString;
function wrapConstructor(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}

// node_modules/@noble/hashes/esm/_md.js
function setBigUint64(view, byteOffset, value, isLE2) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE2);
  const _32n = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE2 ? 4 : 0;
  const l = isLE2 ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE2);
  view.setUint32(byteOffset + l, wl, isLE2);
}
var Chi = (a, b, c) => a & b ^ ~a & c;
var Maj = (a, b, c) => a & b ^ a & c ^ b & c;
var HashMD = class extends Hash {
  constructor(blockLen, outputLen, padOffset, isLE2) {
    super();
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE2;
    this.finished = false;
    this.length = 0;
    this.pos = 0;
    this.destroyed = false;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    exists(this);
    const { view, buffer, blockLen } = this;
    data = toBytes(data);
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    exists(this);
    output(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE2 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    this.buffer.subarray(pos).fill(0);
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i = pos; i < blockLen; i++)
      buffer[i] = 0;
    setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE2);
    this.process(view, 0);
    const oview = createView(out);
    const len = this.outputLen;
    if (len % 4)
      throw new Error("_sha2: outputLen should be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE2);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to || (to = new this.constructor());
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.length = length;
    to.pos = pos;
    to.finished = finished;
    to.destroyed = destroyed;
    if (length % blockLen)
      to.buffer.set(buffer);
    return to;
  }
};

// node_modules/@noble/hashes/esm/sha256.js
var SHA256_K = /* @__PURE__ */ new Uint32Array([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_IV = /* @__PURE__ */ new Uint32Array([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
var SHA256 = class extends HashMD {
  constructor() {
    super(64, 32, 8, false);
    this.A = SHA256_IV[0] | 0;
    this.B = SHA256_IV[1] | 0;
    this.C = SHA256_IV[2] | 0;
    this.D = SHA256_IV[3] | 0;
    this.E = SHA256_IV[4] | 0;
    this.F = SHA256_IV[5] | 0;
    this.G = SHA256_IV[6] | 0;
    this.H = SHA256_IV[7] | 0;
  }
  get() {
    const { A, B, C, D, E, F, G: G2, H } = this;
    return [A, B, C, D, E, F, G2, H];
  }
  // prettier-ignore
  set(A, B, C, D, E, F, G2, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G2 | 0;
    this.H = H | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W22 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W22, 17) ^ rotr(W22, 19) ^ W22 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D, E, F, G: G2, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G2) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G2;
      G2 = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G2 = G2 + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D, E, F, G2, H);
  }
  roundClean() {
    SHA256_W.fill(0);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    this.buffer.fill(0);
  }
};
var sha256 = /* @__PURE__ */ wrapConstructor(() => new SHA256());

// node_modules/@noble/hashes/esm/ripemd160.js
var Rho = /* @__PURE__ */ new Uint8Array([7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8]);
var Id = /* @__PURE__ */ new Uint8Array(new Array(16).fill(0).map((_, i) => i));
var Pi = /* @__PURE__ */ Id.map((i) => (9 * i + 5) % 16);
var idxL = [Id];
var idxR = [Pi];
for (let i = 0; i < 4; i++)
  for (let j of [idxL, idxR])
    j.push(j[i].map((k) => Rho[k]));
var shifts = /* @__PURE__ */ [
  [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
  [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
  [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
  [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
  [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5]
].map((i) => new Uint8Array(i));
var shiftsL = /* @__PURE__ */ idxL.map((idx, i) => idx.map((j) => shifts[i][j]));
var shiftsR = /* @__PURE__ */ idxR.map((idx, i) => idx.map((j) => shifts[i][j]));
var Kl = /* @__PURE__ */ new Uint32Array([
  0,
  1518500249,
  1859775393,
  2400959708,
  2840853838
]);
var Kr = /* @__PURE__ */ new Uint32Array([
  1352829926,
  1548603684,
  1836072691,
  2053994217,
  0
]);
function f(group, x, y, z) {
  if (group === 0)
    return x ^ y ^ z;
  else if (group === 1)
    return x & y | ~x & z;
  else if (group === 2)
    return (x | ~y) ^ z;
  else if (group === 3)
    return x & z | y & ~z;
  else
    return x ^ (y | ~z);
}
var R_BUF = /* @__PURE__ */ new Uint32Array(16);
var RIPEMD160 = class extends HashMD {
  constructor() {
    super(64, 20, 8, true);
    this.h0 = 1732584193 | 0;
    this.h1 = 4023233417 | 0;
    this.h2 = 2562383102 | 0;
    this.h3 = 271733878 | 0;
    this.h4 = 3285377520 | 0;
  }
  get() {
    const { h0, h1, h2, h3, h4 } = this;
    return [h0, h1, h2, h3, h4];
  }
  set(h0, h1, h2, h3, h4) {
    this.h0 = h0 | 0;
    this.h1 = h1 | 0;
    this.h2 = h2 | 0;
    this.h3 = h3 | 0;
    this.h4 = h4 | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      R_BUF[i] = view.getUint32(offset, true);
    let al = this.h0 | 0, ar = al, bl = this.h1 | 0, br = bl, cl = this.h2 | 0, cr2 = cl, dl = this.h3 | 0, dr = dl, el = this.h4 | 0, er = el;
    for (let group = 0; group < 5; group++) {
      const rGroup = 4 - group;
      const hbl = Kl[group], hbr = Kr[group];
      const rl = idxL[group], rr = idxR[group];
      const sl = shiftsL[group], sr = shiftsR[group];
      for (let i = 0; i < 16; i++) {
        const tl = rotl(al + f(group, bl, cl, dl) + R_BUF[rl[i]] + hbl, sl[i]) + el | 0;
        al = el, el = dl, dl = rotl(cl, 10) | 0, cl = bl, bl = tl;
      }
      for (let i = 0; i < 16; i++) {
        const tr = rotl(ar + f(rGroup, br, cr2, dr) + R_BUF[rr[i]] + hbr, sr[i]) + er | 0;
        ar = er, er = dr, dr = rotl(cr2, 10) | 0, cr2 = br, br = tr;
      }
    }
    this.set(this.h1 + cl + dr | 0, this.h2 + dl + er | 0, this.h3 + el + ar | 0, this.h4 + al + br | 0, this.h0 + bl + cr2 | 0);
  }
  roundClean() {
    R_BUF.fill(0);
  }
  destroy() {
    this.destroyed = true;
    this.buffer.fill(0);
    this.set(0, 0, 0, 0, 0);
  }
};
var ripemd160 = /* @__PURE__ */ wrapConstructor(() => new RIPEMD160());

// node_modules/@noble/hashes/esm/hmac.js
var HMAC = class extends Hash {
  constructor(hash2, _key) {
    super();
    this.finished = false;
    this.destroyed = false;
    hash(hash2);
    const key = toBytes(_key);
    this.iHash = hash2.create();
    if (typeof this.iHash.update !== "function")
      throw new Error("Expected instance of class which extends utils.Hash");
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    pad.set(key.length > blockLen ? hash2.create().update(key).digest() : key);
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54;
    this.iHash.update(pad);
    this.oHash = hash2.create();
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54 ^ 92;
    this.oHash.update(pad);
    pad.fill(0);
  }
  update(buf) {
    exists(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out) {
    exists(this);
    bytes(out, this.outputLen);
    this.finished = true;
    this.iHash.digestInto(out);
    this.oHash.update(out);
    this.oHash.digestInto(out);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to || (to = Object.create(Object.getPrototypeOf(this), {}));
    const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
};
var hmac = (hash2, key, message) => new HMAC(hash2, key).update(message).digest();
hmac.create = (hash2, key) => new HMAC(hash2, key);

// src/btc.js
etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, etc.concatBytes(...m));
var sha256d = (b) => sha256(sha256(b));
var hash160 = (b) => ripemd160(sha256(b));
var hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
var unhex = (s) => {
  if (s.length % 2 || /[^0-9a-fA-F]/.test(s)) throw new Error("bad hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(2 * i, 2), 16);
  return out;
};
var cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};
var rev = (b) => Uint8Array.from(b).reverse();
var eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
var utf8 = (s) => new TextEncoder().encode(s);
var u32 = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
};
var u64 = (n) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
};
var varint = (n) => {
  if (n < 253) return Uint8Array.of(n);
  if (n <= 65535) return Uint8Array.of(253, n & 255, n >> 8);
  return cat(Uint8Array.of(254), u32(n));
};
var varbytes = (b) => cat(varint(b.length), b);
var push = (d) => {
  if (d.length < 76) return cat(Uint8Array.of(d.length), d);
  if (d.length <= 255) return cat(Uint8Array.of(76, d.length), d);
  return cat(Uint8Array.of(77, d.length & 255, d.length >> 8), d);
};
var scriptNum = (n) => {
  if (n === 0) return new Uint8Array(0);
  const out = [];
  let v = Math.abs(n);
  while (v > 0) {
    out.push(v % 256);
    v = Math.floor(v / 256);
  }
  if (out[out.length - 1] & 128) out.push(n < 0 ? 128 : 0);
  else if (n < 0) out[out.length - 1] |= 128;
  return Uint8Array.from(out);
};
var pushInt = (n) => n === 0 ? Uint8Array.of(0) : n >= 1 && n <= 16 ? Uint8Array.of(80 + n) : push(scriptNum(n));
var p2wpkh = (pub) => cat(Uint8Array.of(0, 20), hash160(pub));
var p2wsh = (ws) => cat(Uint8Array.of(0, 32), sha256(ws));
var p2pkhCode = (pub) => cat(Uint8Array.of(118, 169, 20), hash160(pub), Uint8Array.of(136, 172));
var CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
var polymod = (v) => {
  const G2 = [996825010, 642813549, 513874426, 1027748829, 705979059];
  let c = 1;
  for (const x of v) {
    const t = c >>> 25;
    c = (c & 33554431) << 5 ^ x;
    for (let i = 0; i < 5; i++) if (t >> i & 1) c ^= G2[i];
  }
  return c >>> 0;
};
var hrpExpand = (h) => [...h].map((c) => c.charCodeAt(0) >> 5).concat([0], [...h].map((c) => c.charCodeAt(0) & 31));
var bits = (data, from, to, pad) => {
  let acc = 0, n = 0;
  const out = [], max = (1 << to) - 1;
  for (const v of data) {
    acc = acc << from | v;
    n += from;
    while (n >= to) {
      n -= to;
      out.push(acc >> n & max);
    }
  }
  if (pad) {
    if (n) out.push(acc << to - n & max);
  } else if (n >= from || acc << to - n & max) throw new Error("bad padding");
  return out;
};
var segwitEncode = (hrp, ver, prog) => {
  const data = [ver].concat(bits(prog, 8, 5, true));
  const k = ver === 0 ? 1 : 734539939;
  const pm = polymod(hrpExpand(hrp).concat(data, [0, 0, 0, 0, 0, 0])) ^ k;
  const sum = [0, 1, 2, 3, 4, 5].map((i) => pm >> 5 * (5 - i) & 31);
  return hrp + "1" + data.concat(sum).map((d) => CH[d]).join("");
};
var segwitDecode = (hrp, addr) => {
  const a = addr.toLowerCase();
  if (a !== addr && addr.toUpperCase() !== addr) throw new Error("mixed case");
  const pos = a.lastIndexOf("1");
  if (pos < 1 || a.slice(0, pos) !== hrp) throw new Error("wrong network for this address");
  const data = [...a.slice(pos + 1)].map((c) => {
    const i = CH.indexOf(c);
    if (i < 0) throw new Error("bad character");
    return i;
  });
  const pm = polymod(hrpExpand(hrp).concat(data));
  const ver = data[0];
  if (pm !== (ver === 0 ? 1 : 734539939)) throw new Error("bad checksum");
  const prog = Uint8Array.from(bits(data.slice(1, -6), 5, 8, false));
  if (ver > 16 || prog.length < 2 || prog.length > 40 || ver === 0 && prog.length !== 20 && prog.length !== 32) throw new Error("bad witness program");
  return { ver, prog };
};
var B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
var b58check = (s) => {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error("bad base58");
    n = n * 58n + BigInt(i);
  }
  let h = n.toString(16);
  if (h.length % 2) h = "0" + h;
  const lead = s.match(/^1*/)[0].length;
  const raw = cat(new Uint8Array(lead), n === 0n ? new Uint8Array(0) : unhex(h));
  const body = raw.slice(0, -4);
  if (raw.length < 5 || !eq(sha256d(body).slice(0, 4), raw.slice(-4))) throw new Error("bad base58 checksum");
  return body;
};
var addressToScript = (addr, net) => {
  if (addr.toLowerCase().startsWith(net.hrp + "1")) {
    const { ver, prog } = segwitDecode(net.hrp, addr);
    return cat(Uint8Array.of(ver ? 80 + ver : 0, prog.length), prog);
  }
  const b = b58check(addr);
  if (b.length !== 21) throw new Error("bad address");
  if (b[0] === net.p2pkh) return cat(Uint8Array.of(118, 169, 20), b.slice(1), Uint8Array.of(136, 172));
  if (b[0] === net.p2sh) return cat(Uint8Array.of(169, 20), b.slice(1), Uint8Array.of(135));
  throw new Error("address is for another network");
};
var ser = (tx, withWitness) => {
  const ins = tx.vin.map((i) => cat(rev(unhex(i.txid)), u32(i.vout), varbytes(new Uint8Array(0)), u32(i.sequence)));
  const outs = tx.vout.map((o) => cat(u64(o.value), varbytes(o.script)));
  const wit = withWitness && tx.vin.some((i) => i.witness && i.witness.length);
  return cat(
    u32(tx.version),
    wit ? Uint8Array.of(0, 1) : new Uint8Array(0),
    varint(ins.length),
    ...ins,
    varint(outs.length),
    ...outs,
    ...wit ? tx.vin.map((i) => cat(varint((i.witness || []).length), ...(i.witness || []).map(varbytes))) : [],
    u32(tx.locktime)
  );
};
var txHex = (tx) => hex(ser(tx, true));
var txid = (tx) => hex(rev(sha256d(ser(tx, false))));
var sighash = (tx, idx, scriptCode, amount) => {
  const prevouts = sha256d(cat(...tx.vin.map((i2) => cat(rev(unhex(i2.txid)), u32(i2.vout)))));
  const seqs = sha256d(cat(...tx.vin.map((i2) => u32(i2.sequence))));
  const outs = sha256d(cat(...tx.vout.map((o) => cat(u64(o.value), varbytes(o.script)))));
  const i = tx.vin[idx];
  return sha256d(cat(
    u32(tx.version),
    prevouts,
    seqs,
    rev(unhex(i.txid)),
    u32(i.vout),
    varbytes(scriptCode),
    u64(amount),
    u32(i.sequence),
    outs,
    u32(tx.locktime),
    u32(1)
  ));
};
var der = (sig) => {
  const part = (n) => {
    let h = n.toString(16);
    if (h.length % 2) h = "0" + h;
    let b = unhex(h);
    if (b[0] & 128) b = cat(Uint8Array.of(0), b);
    return cat(Uint8Array.of(2, b.length), b);
  };
  const body = cat(part(sig.r), part(sig.s));
  return cat(Uint8Array.of(48, body.length), body, Uint8Array.of(1));
};
var pubkey = (priv) => getPublicKey(priv, true);
var sign2 = (priv, digest) => der(sign(digest, priv, { lowS: true }));
var signP2wpkh = (priv, utxos, outputs) => {
  const pub = pubkey(priv);
  const tx = { version: 2, locktime: 0, vin: utxos.map((u) => ({ txid: u.txid, vout: u.vout, sequence: 4294967293, witness: [] })), vout: outputs };
  tx.vin.forEach((i, n) => {
    i.witness = [sign2(priv, sighash(tx, n, p2pkhCode(pub), utxos[n].value)), pub];
  });
  return tx;
};
var contractScript = (c) => cat(
  Uint8Array.of(99, 130),
  pushInt(32),
  Uint8Array.of(136, 168),
  push(c.secretHash),
  Uint8Array.of(136),
  push(c.recipientPub),
  Uint8Array.of(103),
  pushInt(c.locktime),
  Uint8Array.of(177, 117),
  push(c.refundPub),
  Uint8Array.of(104, 172)
);
var parseContract = (script) => {
  try {
    if (script.length < 110 || script.length > 120 || script[6] !== 32 || script[40] !== 33 || script[74] !== 103) throw 0;
    const n = script[75];
    if (n < 1 || n > 5 || script[76 + n + 2] !== 33) throw 0;
    let locktime = 0;
    for (let i = n - 1; i >= 0; i--) locktime = locktime * 256 + script[76 + i];
    const c = { secretHash: script.slice(7, 39), recipientPub: script.slice(41, 74), locktime, refundPub: script.slice(79 + n, 112 + n) };
    if (!eq(contractScript(c), script)) throw 0;
    return c;
  } catch (e) {
    throw new Error("not a hashfun swap contract");
  }
};
var htlcSpend = (c, prev, amount, dest, fee, locktime, sequence, priv, mid) => {
  if (amount - fee <= 546) throw new Error("fee leaves nothing to collect");
  const ws = contractScript(c);
  const tx = { version: 2, locktime, vin: [{ txid: prev.txid, vout: prev.vout, sequence, witness: [] }], vout: [{ value: amount - fee, script: dest }] };
  tx.vin[0].witness = [sign2(priv, sighash(tx, 0, ws, amount)), ...mid, ws];
  return tx;
};
var redeemTx = (c, prev, amount, dest, fee, priv, secret) => {
  if (!eq(pubkey(priv), c.recipientPub)) throw new Error("this key cannot redeem the contract");
  if (secret.length !== 32 || !eq(sha256(secret), c.secretHash)) throw new Error("secret does not match the contract");
  return htlcSpend(c, prev, amount, dest, fee, 0, 4294967295, priv, [secret, Uint8Array.of(1)]);
};
var refundTx = (c, prev, amount, dest, fee, priv) => {
  if (!eq(pubkey(priv), c.refundPub)) throw new Error("this key cannot refund the contract");
  return htlcSpend(c, prev, amount, dest, fee, c.locktime, 4294967294, priv, [new Uint8Array(0)]);
};
var randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));
var signText = (priv, text) => sign(sha256d(utf8(text)), priv, { lowS: true }).toCompactHex();
var verifyText = (pubHex, text, sigHex) => {
  try {
    return /^[0-9a-f]{128}$/.test(sigHex) && verify(sigHex, sha256d(utf8(text)), unhex(pubHex), { lowS: false });
  } catch (e) {
    return false;
  }
};
var secretFromWitness = (witnesses, secretHash) => {
  for (const w of witnesses) for (const item of w) if (item.length === 64 && eq(sha256(unhex(item)), secretHash)) return unhex(item);
  return null;
};

// src/book.js
var orderText = (o) => ["hashfun-order-v1", o.maker, o.give, o.give_amount, o.get, o.get_amount, o.min_get, o.expiry, o.nonce, o.lock, o.confs].join("\n");
var takeText = (t) => ["hashfun-take-v1", t.order, t.taker, t.get_amount, t.secret_hash, t.locktime, t.ts].join("\n");
var noteText = (fill, kind, body) => ["hashfun-fill-v1", fill, kind, ...Object.keys(body).sort().map((k) => `${k}=${body[k]}`)].join("\n");
var aliveText = (maker, ts) => `hashfun-alive-v1
${maker}
${ts}`;
var cancelText = (order) => `hashfun-cancel-v1
${order}`;
var textId = (text) => hex(sha256d(utf8(text))).slice(0, 32);
var giveFor = (o, getAmount) => Number(BigInt(o.give_amount) * BigInt(getAmount) / BigInt(o.get_amount));
var FINAL = ["done", "failed", "released", "refunded"];
async function findOutput(api2, chain2, txid2, scriptHex) {
  const tx = await api2(`/chain/${chain2}/tx/${txid2}`).catch(() => null);
  const hit = tx && tx.vout.find((x) => x.script === scriptHex);
  if (hit) return hit.n;
  for (let n = 0; n < 6; n++) {
    const o = await api2(`/chain/${chain2}/txout/${txid2}/${n}`).catch(() => null);
    if (o && o.script === scriptHex) return n;
  }
  return null;
}
var CLAIM_VB = 180;
var REFUND_VB = 170;
var MIN_OUTPUT = 2e3;
var sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function createBook(env) {
  const { api: api2, W: W3, cfg: cfg2 } = env;
  const ms = () => env.now ? env.now() : Date.now();
  const now = () => Math.floor(ms() / 1e3);
  const mineOnly = (k) => `${k}_${hex(W3.pub).slice(0, 16)}`;
  const load = (k) => {
    try {
      return W3.pub ? JSON.parse(env.store.getItem(mineOnly(k)) || "{}") : {};
    } catch (e) {
      return {};
    }
  };
  const save = (k, v) => env.store.setItem(mineOnly(k), JSON.stringify(v));
  const recs = () => load("hf_p2p");
  const put = (rec) => {
    rec.updated = ms();
    const all = recs();
    all[rec.id] = rec;
    save("hf_p2p", all);
    if (env.onChange) env.onChange(rec);
    return rec;
  };
  const pubHex = () => hex(W3.pub);
  const sign3 = (text) => signText(W3.key, text);
  const nameOf = (id) => id === cfg2().btc_id ? "btc" : Object.keys(cfg2().launches).find((t) => cfg2().launches[t].id === id);
  const idOf = (name) => name === "btc" ? cfg2().btc_id : cfg2().launches[name].id;
  const label = (name) => name === "btc" ? "sats" : "$" + name;
  const myScript = () => p2wpkh(W3.pub);
  const addrOn = (name) => segwitEncode(name === "btc" ? cfg2().btc.hrp : cfg2().launches[name].hrp, 0, hash160(W3.pub));
  const destOn = (name) => name === "btc" ? addressToScript(W3.addr, cfg2().btc) : myScript();
  const spacing = (name) => name === "btc" ? 600 : cfg2().launches[name].target_spacing || 60;
  const confsFor = (name) => name === "btc" ? 1 : cfg2().book.confs;
  const margin = (name, lock) => Math.min(Math.max(600, 6 * spacing(name)), Math.floor(lock / 4));
  let btcCache = null;
  const utxos = async (name) => {
    let list;
    if (name === "btc") {
      if (!btcCache || ms() - btcCache.t > (cfg2().btc.chain === "main" ? 12e4 : 3e3)) btcCache = { t: ms(), list: (await api2(`/chain/btc/address/${addrOn("btc")}`)).utxos.filter((u) => u.confirmations > 0) };
      list = btcCache.list;
    } else list = (await api2(`/coin/${name}/address/${addrOn(name)}`)).utxos.filter((u) => u.spendable);
    const spent = load("hf_spent");
    return list.filter((u) => !spent[`${name}:${u.txid}:${u.vout}`]);
  };
  const balance = async (name) => (await utxos(name)).reduce((a, u) => a + u.value, 0);
  const markSpent = (keys) => {
    const s = load("hf_spent"), t = ms();
    for (const k of Object.keys(s)) if (t - s[k] > 6 * 36e5) delete s[k];
    keys.forEach((k) => {
      s[k] = t;
    });
    save("hf_spent", s);
  };
  const buildLock = async (name, spk, amount) => {
    const t = await api2(`/chain/${name}/time`);
    const pool = (await utxos(name)).sort((a, b) => b.value - a.value), sel = [];
    let sum = 0, fee = 0;
    for (const u of pool) {
      sel.push(u);
      sum += u.value;
      fee = t.feerate * (90 + 68 * sel.length);
      if (sum >= amount + fee) break;
    }
    if (sum < amount + fee) throw new Error(`not enough spendable ${label(name)} at your hashfun key`);
    const outs = [{ value: amount, script: spk }];
    if (sum - amount - fee > 600) outs.push({ value: sum - amount - fee, script: myScript() });
    const tx = signP2wpkh(W3.key, sel, outs);
    return { hex: txHex(tx), txid: txid(tx), vout: 0, spends: sel.map((u) => `${name}:${u.txid}:${u.vout}`) };
  };
  const txout = (name, o) => api2(`/chain/${name}/txout/${o.txid}/${o.vout}`);
  const worth = async (name, amount) => amount >= MIN_OUTPUT && amount >= 4 * CLAIM_VB * (await api2(`/chain/${name}/time`)).feerate;
  const broadcast = async (name, hex2, outpoint) => {
    try {
      return (await api2(`/chain/${name}/tx`, { hex: hex2 })).txid;
    } catch (e) {
      if (outpoint && await txout(name, outpoint).catch(() => null)) return outpoint.txid;
      throw e;
    }
  };
  const note = (fill, kind, body = {}) => api2(`/book/fill/${fill}`, { from: pubHex(), kind, body, sig: sign3(noteText(fill, kind, body)) });
  const findNote = (f2, kind, from) => (f2.notes || []).find((n) => n.kind === kind && n.from === from && verifyText(from, noteText(f2.id, kind, n.body), n.sig));
  const contractOf = (rec, mine2) => {
    const takerSide = rec.role === "taker" === mine2;
    const taker = unhex(rec.taker), maker = unhex(rec.order.maker);
    return contractScript({
      secretHash: unhex(rec.secret_hash),
      recipientPub: takerSide ? maker : taker,
      refundPub: takerSide ? taker : maker,
      locktime: takerSide ? rec.locktime : rec.locktime - rec.order.lock
    });
  };
  async function post({ give, get, give_amount, get_amount, min_get, ttl }) {
    if (!(give_amount >= MIN_OUTPUT) || !(get_amount >= MIN_OUTPUT)) throw new Error("too small: both sides need at least " + MIN_OUTPUT + " base units");
    const needLock = 12 * spacing(give) + 6 * spacing(get);
    if (cfg2().btc.chain !== "regtest" && cfg2().book.lock < needLock) throw new Error(`this site's swap lock (${cfg2().book.lock} s) is too short for this pair: it needs ${needLock} s`);
    const promised = (await mine().catch(() => [])).filter((x) => x.give === idOf(give)).reduce((a, x) => a + x.remaining, 0);
    let have = await balance(give);
    if (have < give_amount + promised && give === "btc") {
      btcCache = null;
      have = await balance(give);
    }
    if (have < give_amount + promised) throw new Error(`your hashfun key holds ${have} in spendable ${label(give)}: less than this offer${promised ? " plus your other open offers" : ""}`);
    const floor = Math.max(MIN_OUTPUT, Math.ceil(MIN_OUTPUT * get_amount / give_amount));
    const o = {
      maker: pubHex(),
      give: idOf(give),
      give_amount,
      get: idOf(get),
      get_amount,
      min_get: Math.min(get_amount, Math.max(min_get || 0, floor)),
      expiry: now() + (ttl || 86400),
      nonce: hex(randomBytes(8)),
      lock: cfg2().book.lock,
      confs: confsFor(get)
    };
    o.sig = sign3(orderText(o));
    const r = await api2("/book/order", o);
    const kept = load("hf_orders");
    kept[r.id] = o;
    save("hf_orders", kept);
    return r;
  }
  async function cancel(id) {
    await api2("/book/cancel", { order: id, sig: sign3(cancelText(id)) });
    const kept = load("hf_orders");
    delete kept[id];
    save("hf_orders", kept);
  }
  const mine = () => api2(`/book?maker=${pubHex()}`).then((r) => r.orders);
  const makerUsed = (orderId) => Object.values(recs()).filter((r) => r.role === "maker" && r.order.id === orderId && !["released", "failed", "refunded"].includes(r.state)).reduce((a, r) => a + r.give_amount, 0);
  const committed = (name) => Object.values(recs()).filter((r) => r.role === "maker" && r.give === name && r.state === "accepted").reduce((a, r) => a + r.give_amount, 0);
  async function answer(f2) {
    const o = load("hf_orders")[f2.order];
    const refuse = (why) => note(f2.id, "reject", { why }).catch(() => {
    });
    if (!o) return refuse("unknown order");
    if (!verifyText(f2.taker, takeText(f2), f2.sig) || textId(takeText(f2)) !== f2.id) return refuse("bad signature");
    if (giveFor(o, f2.get_amount) !== f2.give_amount || f2.get_amount < o.min_get || f2.give_amount < MIN_OUTPUT) return refuse("bad amount");
    const t = now();
    if (o.expiry <= t) return refuse("order expired");
    if (f2.locktime < t + 2 * o.lock || f2.locktime > t + 3 * o.lock + 600) return refuse("bad timelock");
    if (makerUsed(f2.order) + f2.give_amount > o.give_amount) return refuse("order is taken");
    const give = nameOf(o.give), get = nameOf(o.get);
    if (!give || !get) return refuse("chain not followed here");
    if (!await worth(give, f2.give_amount) || !await worth(get, f2.get_amount)) return refuse("too small for the network fee");
    if (await balance(give) < f2.give_amount + committed(give)) return refuse("maker is out of coins");
    const rec = {
      id: f2.id,
      role: "maker",
      order: { ...o, id: f2.order },
      give,
      get,
      give_amount: f2.give_amount,
      get_amount: f2.get_amount,
      secret_hash: f2.secret_hash,
      locktime: f2.locktime,
      taker: f2.taker,
      state: "accepted",
      until: t + (get === "btc" ? 300 : 120),
      created: ms(),
      my: {},
      their: {}
    };
    put(rec);
    await note(f2.id, "accept", { until: rec.until });
  }
  let session = null;
  async function heartbeat() {
    const orders = load("hf_orders"), t = now();
    for (const [id, o] of Object.entries(orders)) if (o.expiry <= t) delete orders[id];
    save("hf_orders", orders);
    if (!Object.keys(orders).length && !Object.values(recs()).some((r2) => r2.role === "maker" && !FINAL.includes(r2.state))) return;
    const signed = () => {
      const ts = now();
      return { maker: pubHex(), ts, sig: sign3(aliveText(pubHex(), ts)) };
    };
    let r;
    try {
      r = await api2("/book/alive", session ? { maker: pubHex(), session } : signed());
    } catch (e) {
      r = await api2("/book/alive", signed());
    }
    session = r.session;
    for (const f2 of r.fills) if (f2.state === "requested" && !recs()[f2.id]) await answer(f2).catch(() => {
    });
  }
  async function take(order, getAmount, ui = () => {
  }) {
    if (!verifyText(order.maker, orderText(order), order.sig) || textId(orderText(order)) !== order.id) throw new Error("that order is not signed by its maker");
    const give = nameOf(order.give), get = nameOf(order.get);
    if (!give || !get) throw new Error("this site does not follow one of those chains");
    const giveAmount = giveFor(order, getAmount);
    if (getAmount < order.min_get) throw new Error("too small for this order");
    if (!await worth(give, giveAmount) || !await worth(get, getAmount)) throw new Error("too small to be worth the network fee");
    const viaWallet = get === "btc" && env.unisat();
    if (!viaWallet && await balance(get) < getAmount) throw new Error(`you hold less than that in spendable ${label(get)}`);
    const secret = randomBytes(32), hash2 = sha256(secret);
    const t = await api2(`/chain/${get}/time`);
    const locktime = Math.max(now(), t.mediantime) + 2 * order.lock + Math.min(600, Math.floor(order.lock / 2));
    const tk = { order: order.id, taker: pubHex(), get_amount: getAmount, secret_hash: hex(hash2), locktime, ts: now() };
    const rec = {
      id: textId(takeText(tk)),
      role: "taker",
      order,
      give,
      get,
      give_amount: giveAmount,
      get_amount: getAmount,
      secret: hex(secret),
      secret_hash: hex(hash2),
      locktime,
      taker: pubHex(),
      state: "requested",
      created: ms(),
      my: {},
      their: {}
    };
    put(rec);
    ui("ask", rec);
    const fail = (why) => {
      rec.state = "failed";
      rec.note = why;
      put(rec);
      note(rec.id, "abort").catch(() => {
      });
      throw new Error(why);
    };
    await api2("/book/take", { ...tk, sig: sign3(takeText(tk)) }).catch((e) => fail(e.message || String(e)));
    for (let i = 0; ; i++) {
      const f2 = await api2(`/book/fill/${rec.id}`);
      const ok = f2.state === "accepted" && findNote(f2, "accept", order.maker);
      if (ok) {
        rec.until = Number(ok.body.until);
        break;
      }
      if (f2.state === "rejected") fail("the maker said no: " + ((findNote(f2, "reject", order.maker) || { body: {} }).body.why || "no reason given"));
      if (f2.state !== "requested" || i > 45) fail("the maker did not answer; try another order");
      await sleep(700);
    }
    rec.state = "accepted";
    put(rec);
    if (now() > rec.until - 10) fail("too slow: the maker's offer lapsed");
    ui("lock", rec);
    try {
      await lockMine(rec, 90);
    } catch (e) {
      if (!rec.my.txid) fail(e.message || String(e));
      throw e;
    }
    ui("wait", rec);
    return rec;
  }
  async function lockMine(rec, tries = 1) {
    const name = rec.role === "taker" ? rec.get : rec.give, amount = rec.role === "taker" ? rec.get_amount : rec.give_amount;
    const script = contractOf(rec, true), spk = p2wsh(script);
    rec.my.contract = hex(script);
    if (!rec.my.txid) {
      if (rec.role === "taker" && name === "btc" && env.unisat()) {
        rec.my.address = segwitEncode(cfg2().btc.hrp, 0, spk.slice(2));
        rec.state = "locking";
        put(rec);
        rec.my.txid = await env.unisat().sendBitcoin(rec.my.address, amount);
        put(rec);
      } else {
        const tx = await buildLock(name, spk, amount);
        Object.assign(rec.my, { txid: tx.txid, vout: 0, hex: tx.hex });
        rec.state = "locking";
        put(rec);
        markSpent(tx.spends);
        if (name === "btc") btcCache = null;
      }
    }
    if (rec.my.hex) await broadcast(name, rec.my.hex, rec.my);
    for (let i = 0; rec.my.vout == null; i++) {
      const n = await findOutput(api2, name, rec.my.txid, hex(spk));
      if (n != null) rec.my.vout = n;
      else if (i >= tries) throw new Error("your payment has not reached this site's Bitcoin node yet; this swap resumes by itself when it does");
      else await sleep(1e3);
    }
    rec.state = "locked";
    put(rec);
    await tellLocked(rec);
  }
  const tellLocked = (rec) => note(rec.id, "locked", { contract: rec.my.contract, txid: rec.my.txid, vout: rec.my.vout }).catch((e) => {
    rec.note = "could not tell the other side about your lock: " + (e.message || e);
    put(rec);
  });
  async function refundIfDue(rec) {
    const name = rec.role === "taker" ? rec.get : rec.give, c = parseContract(unhex(rec.my.contract));
    const t = await api2(`/chain/${name}/time`);
    if (t.mediantime <= c.locktime) return false;
    const out = await txout(name, rec.my);
    if (!out) return false;
    const tx = refundTx(c, rec.my, out.value, destOn(name), REFUND_VB * t.feerate, W3.key);
    rec.refund_txid = (await api2(`/chain/${name}/tx`, { hex: txHex(tx) })).txid;
    rec.state = "refunded";
    rec.note = "the other side stopped; your lock came back";
    put(rec);
    return true;
  }
  async function claim(rec, name, outpoint, script, secret) {
    const c = parseContract(script), t = await api2(`/chain/${name}/time`), out = await txout(name, outpoint);
    if (!out) {
      if (rec.claim_txid) return;
      throw new Error("the lock to claim is gone");
    }
    const tx = redeemTx(c, outpoint, out.value, destOn(name), CLAIM_VB * t.feerate, W3.key, secret);
    rec.claim_txid = txid(tx);
    rec.got = out.value - CLAIM_VB * t.feerate;
    put(rec);
    await api2(`/chain/${name}/tx`, { hex: txHex(tx) });
  }
  async function stepTaker(rec) {
    if (rec.state === "requested" || rec.state === "accepted") {
      rec.state = "failed";
      rec.note = "interrupted before anything was locked";
      put(rec);
      return void note(rec.id, "abort").catch(() => {
      });
    }
    if (rec.state === "locking") {
      if (rec.my.hex && now() > rec.locktime && !await txout(rec.get, rec.my).catch(() => 1)) {
        rec.state = "failed";
        rec.note = "the lock was never accepted by the network";
        return void put(rec);
      }
      if (!rec.my.txid) {
        const seen2 = rec.my.address ? await api2(`/chain/btc/address/${rec.my.address}`).catch(() => null) : null;
        if (seen2 && seen2.utxos.length) {
          rec.my.txid = seen2.utxos[0].txid;
          rec.my.vout = seen2.utxos[0].vout;
          put(rec);
        } else if (ms() - rec.updated > 18e4) {
          rec.state = "failed";
          rec.note = "the payment was not made";
          return void put(rec);
        } else return;
      }
      return void await lockMine(rec);
    }
    if (rec.state !== "locked") return;
    if (await refundIfDue(rec)) return;
    const f2 = await api2(`/book/fill/${rec.id}`).catch(() => null);
    if (f2 && f2.state === "accepted") await tellLocked(rec);
    const n = f2 && findNote(f2, "locked", rec.order.maker);
    if (!n) {
      const why = f2 && findNote(f2, "fail", rec.order.maker);
      rec.note = why ? `the maker would not lock (${why.body.why}); your lock comes back after its timelock` : "waiting for the maker to lock";
      return void put(rec);
    }
    const expect = contractOf(rec, false);
    if (n.body.contract !== hex(expect)) {
      rec.note = "the maker locked a different contract; your lock comes back after its timelock";
      return void put(rec);
    }
    const their = { txid: n.body.txid, vout: Number(n.body.vout) }, out = await txout(rec.give, their);
    if (!out || out.script !== hex(p2wsh(expect)) || out.value < rec.give_amount) {
      rec.note = "the maker's lock is not on the chain (yet)";
      return void put(rec);
    }
    const t = await api2(`/chain/${rec.give}/time`), need = confsFor(rec.give);
    if (t.mediantime + margin(rec.give, rec.order.lock) >= rec.locktime - rec.order.lock) {
      rec.note = "too close to the maker's refund to claim safely; your lock comes back after its timelock";
      return void put(rec);
    }
    if (out.confirmations < need) {
      rec.note = `${out.confirmations} of ${need} confirmations on the maker's lock`;
      return void put(rec);
    }
    rec.their = their;
    await claim(rec, rec.give, their, expect, unhex(rec.secret));
    rec.state = "done";
    rec.note = "";
    put(rec);
    note(rec.id, "claimed", { txid: rec.claim_txid }).catch(() => {
    });
  }
  async function stepMaker(rec) {
    const f2 = await api2(`/book/fill/${rec.id}`).catch(() => null);
    if (rec.state === "accepted") {
      const n = f2 && findNote(f2, "locked", rec.taker);
      const giveUp = async (why, tell) => {
        rec.state = "released";
        rec.note = why;
        put(rec);
        if (tell) await note(rec.id, tell, tell === "fail" ? { why } : {}).catch(() => {
        });
      };
      if (!n) {
        if (f2 && FINAL.concat(["expired", "aborted", "rejected"]).includes(f2.state)) return giveUp("the taker did not lock");
        if (now() > rec.until + 20) return giveUp("the taker did not lock in time", "release");
        return;
      }
      const expect = contractOf(rec, false);
      if (n.body.contract !== hex(expect)) return giveUp("wrong contract", "fail");
      const their = { txid: n.body.txid, vout: Number(n.body.vout) }, out = await txout(rec.get, their);
      if (!out) {
        if (now() > rec.until + 600) return giveUp("lock never appeared", "fail");
        return;
      }
      if (out.script !== hex(p2wsh(expect)) || out.value < rec.get_amount) return giveUp("wrong lock", "fail");
      if (out.confirmations < rec.order.confs) {
        rec.note = `${out.confirmations} of ${rec.order.confs} confirmations on the taker's lock`;
        return void put(rec);
      }
      if (rec.locktime - rec.order.lock - now() < rec.order.lock / 2) return giveUp("too late to lock safely", "fail");
      rec.their = their;
      put(rec);
      return void await lockMine(rec);
    }
    if (rec.state === "locking") return void await lockMine(rec);
    if (rec.state !== "locked") return;
    if (f2 && f2.state === "taker_locked") await tellLocked(rec);
    let secret = null;
    const sp = await api2(`/chain/${rec.give}/spender/${rec.my.txid}/${rec.my.vout}`).catch(() => null);
    if (sp) secret = secretFromWitness(sp.witness, unhex(rec.secret_hash));
    const said = f2 && findNote(f2, "claimed", rec.taker);
    if (!secret && said && /^[0-9a-f]{64}$/.test(said.body.txid)) {
      const tx = await api2(`/chain/${rec.give}/tx/${said.body.txid}`).catch(() => null);
      if (tx) secret = secretFromWitness(tx.vin.map((i) => i.witness), unhex(rec.secret_hash));
    }
    if (secret) {
      rec.secret = hex(secret);
      put(rec);
      await claim(rec, rec.get, rec.their, contractOf(rec, false), secret);
      rec.state = "done";
      rec.note = "";
      put(rec);
      return void note(rec.id, "done").catch(() => {
      });
    }
    if (await refundIfDue(rec)) await note(rec.id, "fail", { why: "refunded" }).catch(() => {
    });
  }
  let busy = false;
  async function tick() {
    if (busy || !W3.key) return;
    busy = true;
    try {
      await heartbeat().catch(() => {
      });
      for (const rec of Object.values(recs())) {
        if (FINAL.includes(rec.state) || rec.taker === void 0) continue;
        if (rec.role === "taker" && taking.has(rec.id)) continue;
        try {
          await (rec.role === "taker" ? stepTaker(rec) : stepMaker(rec));
        } catch (e) {
          const r = recs()[rec.id];
          if (r && r.note !== (e.message || String(e))) {
            r.note = e.message || String(e);
            put(r);
          }
        }
      }
    } finally {
      busy = false;
    }
  }
  const taking = /* @__PURE__ */ new Set();
  const takeGuarded = async (order, amount, ui) => {
    let id = null;
    try {
      return await take(order, amount, (k, rec) => {
        if (rec && !id) {
          id = rec.id;
          taking.add(id);
        }
        if (ui) ui(k, rec);
      });
    } finally {
      if (id) taking.delete(id);
    }
  };
  function start(every = 2500) {
    const beat = () => {
      tick();
      try {
        const w = new Worker(URL.createObjectURL(new Blob([`setInterval(() => postMessage(0), ${every})`], { type: "text/javascript" })));
        w.onmessage = () => tick();
        w.onerror = () => {
          w.terminate();
          setInterval(tick, every);
        };
      } catch (e) {
        setInterval(tick, every);
      }
    };
    const hold = () => new Promise(() => beat());
    if (typeof navigator !== "undefined" && navigator.locks) navigator.locks.request("hashfun-book", hold);
    else hold();
  }
  const pending = () => Object.values(recs()).some((r) => r.taker && ["locking", "locked"].includes(r.state));
  return { pending, post, cancel, mine, take: takeGuarded, tick, start, recs, balance, nameOf, idOf, addrOn, confsFor, list: (q = "") => api2("/book" + q).then((r) => r.orders) };
}

// src/maker.mjs
var HELP = `hashfun book: peer-to-peer offers and swaps without a browser tab

  hashfun book key                         create the key (first run); show where to send coins and sats
  hashfun book balances
  hashfun book post --give CAT --get btc --give-amount 1000 --get-amount 50000 [--hours 24]
  hashfun book offers | cancel ID | swaps
  hashfun book take ID [--pay AMOUNT]      take someone's offer, paying from the key
  hashfun book run                         keep offers live: answer takes, lock, claim, refund

  --site URL             the hashfun site (default http://127.0.0.1:8080, or $HASHFUN_SITE)
  --dir DIR              where the key and swap records live (default ~/.hashfun/book, or $HASHFUN_BOOK_DIR)
  --btc-payout ADDRESS   send the sats you earn there instead of keeping them at the key

Amounts: sats for Bitcoin, whole coins (decimals allowed) for launch coins.
The key file is encrypted with a password ($HASHFUN_BOOK_PASSWORD, or asked for); --no-encrypt on
first use stores it in the clear. Everything the key holds is in play: fund it with what you mean
to trade. An offer is listed only while "run" is running, and "run" finishes or refunds its swaps.
Offers can be posted and cancelled while "run" is up. One "run" or "take" at a time per key directory.`;
var COIN = 1e8;
var die = (msg) => {
  console.error("hashfun book: " + msg);
  process.exit(1);
};
var argv = process.argv.slice(process.argv[2] === "book" ? 3 : 2);
var opts = {};
var words = [];
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a.startsWith("--")) {
    const k = a.slice(2);
    if (["no-encrypt", "help", "once"].includes(k)) opts[k] = true;
    else opts[k] = argv[++i];
  } else words.push(a);
}
var cmd = words[0];
var site = (opts.site || process.env.HASHFUN_SITE || "http://127.0.0.1:8080").replace(/\/+$/, "");
var dir = opts.dir || process.env.HASHFUN_BOOK_DIR || import_node_path.default.join(import_node_os.default.homedir(), ".hashfun", "book");
if (!cmd || opts.help || !["key", "balances", "post", "offers", "cancel", "swaps", "take", "run"].includes(cmd)) {
  console.log(HELP);
  process.exit(cmd && !opts.help ? 1 : 0);
}
var ask = (q) => new Promise((res) => {
  const rl = import_node_readline.default.createInterface({ input: process.stdin, output: process.stderr, terminal: true });
  rl.stdoutMuted = false;
  rl._writeToOutput = (s) => {
    if (!rl.stdoutMuted) rl.output.write(s);
  };
  rl.question(q, (a) => {
    rl.close();
    process.stderr.write("\n");
    res(a);
  });
  rl.stdoutMuted = true;
});
var password = async (confirm) => {
  if (process.env.HASHFUN_BOOK_PASSWORD !== void 0) return process.env.HASHFUN_BOOK_PASSWORD;
  if (!process.stdin.isTTY) die("the key file is encrypted: set HASHFUN_BOOK_PASSWORD");
  const p = await ask("password for the book key: ");
  if (confirm && p !== await ask("again: ")) die("the two passwords differ");
  return p;
};
var KDF = { N: 32768, r: 8, p: 1, maxmem: 2 ** 27 };
var seal = (priv, pass) => {
  const salt = import_node_crypto.default.randomBytes(16), nonce = import_node_crypto.default.randomBytes(12);
  const c = import_node_crypto.default.createCipheriv("chacha20-poly1305", import_node_crypto.default.scryptSync(pass, salt, 32, KDF), nonce, { authTagLength: 16 });
  const ct = Buffer.concat([c.update(Buffer.from(priv)), c.final()]);
  return { v: 1, kdf: "scrypt", salt: salt.toString("hex"), nonce: nonce.toString("hex"), ct: ct.toString("hex"), tag: c.getAuthTag().toString("hex") };
};
var unseal = (j, pass) => {
  const d = import_node_crypto.default.createDecipheriv("chacha20-poly1305", import_node_crypto.default.scryptSync(pass, Buffer.from(j.salt, "hex"), 32, KDF), Buffer.from(j.nonce, "hex"), { authTagLength: 16 });
  d.setAuthTag(Buffer.from(j.tag, "hex"));
  try {
    return new Uint8Array(Buffer.concat([d.update(Buffer.from(j.ct, "hex")), d.final()]));
  } catch (e) {
    return die("wrong password for " + import_node_path.default.join(dir, "key.json"));
  }
};
async function loadKey() {
  const f2 = import_node_path.default.join(dir, "key.json");
  if (import_node_fs.default.existsSync(f2)) {
    const j = JSON.parse(import_node_fs.default.readFileSync(f2, "utf8"));
    return j.priv ? unhex(j.priv) : unseal(j, await password(false));
  }
  if (cmd !== "key") die(`no key in ${dir} yet: run "hashfun book key" first`);
  import_node_fs.default.mkdirSync(dir, { recursive: true, mode: 448 });
  let priv;
  for (; ; ) {
    priv = randomBytes(32);
    try {
      pubkey(priv);
      break;
    } catch (e) {
    }
  }
  const body = opts["no-encrypt"] ? { v: 1, priv: hex(priv) } : seal(priv, await password(true));
  import_node_fs.default.writeFileSync(f2, JSON.stringify(body), { mode: 384 });
  console.error(`new key written to ${f2}${opts["no-encrypt"] ? " (NOT encrypted)" : ""}. Back this file up: it is the only copy.`);
  return priv;
}
var api = async (p, body) => {
  let r;
  try {
    r = await fetch(site + "/api" + p, body ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) } : void 0);
  } catch (e) {
    throw new Error(`cannot reach ${site}: ${e.cause ? e.cause.code || e.cause.message : e.message}`);
  }
  const j = await r.json().catch(() => ({ error: "bad response" }));
  if (!r.ok) throw new Error(j.error || "request failed");
  return j;
};
var stateFile = import_node_path.default.join(dir, "state.json");
var readState = () => {
  try {
    return JSON.parse(import_node_fs.default.readFileSync(stateFile, "utf8"));
  } catch (e) {
    return {};
  }
};
var seen = {};
var isMap = (x) => !!x && typeof x === "object" && !Array.isArray(x);
var merge = (base, mine, theirs) => {
  const out = { ...theirs };
  for (const k of /* @__PURE__ */ new Set([...Object.keys(base), ...Object.keys(mine)])) {
    const was = JSON.stringify(base[k]), is = JSON.stringify(mine[k]);
    if (was === is) continue;
    if (is === void 0) delete out[k];
    else out[k] = mine[k];
  }
  return out;
};
var locked = (fn) => {
  const lock = stateFile + ".lock";
  for (let i = 0; ; i++) {
    try {
      import_node_fs.default.writeFileSync(lock, String(process.pid), { flag: "wx" });
      break;
    } catch (e) {
      try {
        if (Date.now() - import_node_fs.default.statSync(lock).mtimeMs > 1e4) import_node_fs.default.rmSync(lock, { force: true });
      } catch (e2) {
      }
      if (i > 800) throw new Error(`cannot lock ${stateFile}`);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
    }
  }
  try {
    return fn();
  } finally {
    import_node_fs.default.rmSync(lock, { force: true });
  }
};
var store = {
  getItem: (k) => {
    const v = readState()[k];
    seen[k] = v;
    return v === void 0 ? null : v;
  },
  setItem: (k, v) => locked(() => {
    const state = readState();
    let text = v;
    if (state[k] !== seen[k]) {
      let base, mine, theirs;
      try {
        base = JSON.parse(seen[k] || "{}");
        mine = JSON.parse(v);
        theirs = JSON.parse(state[k] || "{}");
      } catch (e) {
        base = null;
      }
      if (isMap(base) && isMap(mine) && isMap(theirs)) text = JSON.stringify(merge(base, mine, theirs));
    }
    state[k] = text;
    seen[k] = text;
    import_node_fs.default.mkdirSync(dir, { recursive: true, mode: 448 });
    const tmp = `${stateFile}.${process.pid}.tmp`;
    import_node_fs.default.writeFileSync(tmp, JSON.stringify(state), { mode: 384 });
    import_node_fs.default.renameSync(tmp, stateFile);
  })
};
var engine = (what) => {
  const lock = import_node_path.default.join(dir, "run.lock");
  try {
    import_node_fs.default.writeFileSync(lock, `${process.pid} ${what}`, { flag: "wx" });
  } catch (e) {
    const [pid, who] = import_node_fs.default.readFileSync(lock, "utf8").split(" ");
    let alive = true;
    try {
      process.kill(Number(pid), 0);
    } catch (e2) {
      alive = false;
    }
    if (alive) die(`this key is busy: "hashfun book ${who || "run"}" (pid ${pid}) is working its swaps. ${what === "take" ? "Take from another key (--dir), or stop it first" : "One at a time per key directory"}`);
    import_node_fs.default.writeFileSync(lock, `${process.pid} ${what}`);
  }
  process.on("exit", () => {
    try {
      if (import_node_fs.default.readFileSync(lock, "utf8").startsWith(`${process.pid} `)) import_node_fs.default.rmSync(lock, { force: true });
    } catch (e) {
    }
  });
};
var W2 = { key: null, pub: null, addr: null };
var cfg = null;
var names = () => ["btc", ...Object.keys(cfg.launches)];
var norm = (x) => String(x || "").toLowerCase() === "btc" ? "btc" : String(x || "").toUpperCase();
var chain = (x, what) => {
  const n = norm(x);
  if (!names().includes(n)) die(`${what}: ${x || "(missing)"} is not on this site (${names().join(", ")})`);
  return n;
};
var toUnits = (n, x) => {
  const v = Number(x);
  if (!(v > 0)) die(`amount ${x}: a positive number`);
  return Math.round(n === "btc" ? v : v * COIN);
};
var show = (n, v) => n === "btc" ? `${v} sats` : `${v / COIN} $${n}`;
var log = (...a) => console.log((/* @__PURE__ */ new Date()).toISOString().slice(11, 19), ...a);
var told = {};
var book = createBook({ api, W: W2, cfg: () => cfg, store, unisat: () => null, onChange: (r) => {
  const line = `${r.role} ${r.id.slice(0, 8)} ${r.state}${r.note ? ": " + r.note : ""}`;
  if (told[r.id] !== line) {
    told[r.id] = line;
    log(line + (r.state === "done" ? ` (+${show(r.role === "taker" ? r.give : r.get, r.got)})` : ""));
  }
} });
var describe = (o) => `${o.id}  give ${show(book.nameOf(o.give), o.remaining)} for ${show(book.nameOf(o.get), o.remaining_get)}${o.backed === false ? "  (not listed: the site has not seen the coins behind it yet)" : ""}`;
(async () => {
  W2.key = await loadKey();
  W2.pub = pubkey(W2.key);
  cfg = await api("/config");
  W2.addr = opts["btc-payout"] || book.addrOn("btc");
  try {
    addressToScript(W2.addr, cfg.btc);
  } catch (e) {
    die(`--btc-payout ${W2.addr}: not an address on this site's Bitcoin network`);
  }
  if (cmd === "key") {
    console.log(JSON.stringify({ pubkey: hex(W2.pub), site, send_sats_to: book.addrOn("btc"), send_coins_to: Object.fromEntries(Object.keys(cfg.launches).map((t) => [t, book.addrOn(t)])) }, null, 2));
  } else if (cmd === "balances") {
    const out = {};
    for (const n of names()) out[n === "btc" ? "sats" : n] = n === "btc" ? await book.balance(n) : await book.balance(n) / COIN;
    console.log(JSON.stringify(out, null, 2));
  } else if (cmd === "post") {
    const give = chain(opts.give, "--give"), get = chain(opts.get, "--get");
    const r = await book.post({ give, get, give_amount: toUnits(give, opts["give-amount"]), get_amount: toUnits(get, opts["get-amount"]), ttl: opts.hours ? Math.round(Number(opts.hours) * 3600) : void 0 }).catch((e) => die(e.message));
    console.log(describe(r));
    console.error('It is listed only while "hashfun book run" is running.');
  } else if (cmd === "offers") {
    for (const o of await book.mine()) console.log(describe(o));
  } else if (cmd === "cancel") {
    await book.cancel(words[1] || die("cancel ID")).catch((e) => die(e.message));
    console.log("cancelled");
  } else if (cmd === "swaps") {
    for (const r of Object.values(book.recs()).sort((a, b) => a.created - b.created)) console.log(`${r.id.slice(0, 8)}  ${r.role}  ${r.state}${r.note ? "  " + r.note : ""}`);
  } else if (cmd === "take") {
    engine("take");
    const o = (await book.list()).find((x) => x.id === words[1] || x.id.startsWith(words[1] || "?")) || die("no such offer on the board right now");
    const pay = book.nameOf(o.get);
    const rec = await book.take(o, opts.pay ? Math.min(o.remaining_get, toUnits(pay, opts.pay)) : o.remaining_get).catch((e) => die(e.message));
    while (!FINAL.includes((book.recs()[rec.id] || {}).state)) {
      await book.tick();
      await new Promise((r) => setTimeout(r, 2e3));
    }
    process.exit(book.recs()[rec.id].state === "done" ? 0 : 2);
  } else if (cmd === "run") {
    engine("run");
    let stop = false;
    const bye = () => {
      if (stop) process.exit(1);
      stop = true;
      if (book.pending()) console.error('a swap is in progress: finishing it first (Ctrl-C again to quit anyway; "run" resumes it later)');
    };
    process.on("SIGINT", bye);
    process.on("SIGTERM", bye);
    log(`key ${hex(W2.pub).slice(0, 16)}\u2026 on ${site}; ${(await book.mine().catch(() => [])).length} open offer(s)`);
    let last = 0;
    while (!(stop && !book.pending())) {
      if (Date.now() - last > 3e4) {
        cfg = await api("/config").catch(() => cfg);
        last = Date.now();
      }
      await book.tick();
      if (opts.once) break;
      await new Promise((r) => setTimeout(r, 2500));
    }
  }
  process.exit(0);
})().catch((e) => die(e.message || String(e)));
/*! Bundled license information:

@noble/secp256k1/index.js:
  (*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) *)

@noble/hashes/esm/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
