// Bitcoin-format primitives for the browser: the same bytes hashfun/ser.py and hashfun/htlc.py
// produce (tests/test_web_js.py checks that byte for byte).
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { hmac } from '@noble/hashes/hmac';

secp.etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, secp.etc.concatBytes(...m));

export { sha256 };
export const sha256d = (b) => sha256(sha256(b));
export const hash160 = (b) => ripemd160(sha256(b));
export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
export const unhex = (s) => {
  if (s.length % 2 || /[^0-9a-fA-F]/.test(s)) throw new Error('bad hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(2 * i, 2), 16);
  return out;
};
export const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
export const rev = (b) => Uint8Array.from(b).reverse();
export const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
export const utf8 = (s) => new TextEncoder().encode(s);

const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
export const varint = (n) => {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 255, n >> 8);
  return cat(Uint8Array.of(0xfe), u32(n));
};
const varbytes = (b) => cat(varint(b.length), b);

// ---------------------------------------------------------------- script
export const push = (d) => {
  if (d.length < 0x4c) return cat(Uint8Array.of(d.length), d);
  if (d.length <= 0xff) return cat(Uint8Array.of(0x4c, d.length), d);
  return cat(Uint8Array.of(0x4d, d.length & 255, d.length >> 8), d);
};
export const scriptNum = (n) => {
  if (n === 0) return new Uint8Array(0);
  const out = [];
  let v = Math.abs(n);
  while (v > 0) { out.push(v % 256); v = Math.floor(v / 256); }
  if (out[out.length - 1] & 0x80) out.push(n < 0 ? 0x80 : 0);
  else if (n < 0) out[out.length - 1] |= 0x80;
  return Uint8Array.from(out);
};
// ser.py push_int: OP_0, OP_1..OP_16 for small values, else a minimal script-number push.
export const pushInt = (n) => (n === 0 ? Uint8Array.of(0) : n >= 1 && n <= 16 ? Uint8Array.of(0x50 + n) : push(scriptNum(n)));
export const p2wpkh = (pub) => cat(Uint8Array.of(0, 20), hash160(pub));
export const p2wsh = (ws) => cat(Uint8Array.of(0, 32), sha256(ws));
const p2pkhCode = (pub) => cat(Uint8Array.of(0x76, 0xa9, 20), hash160(pub), Uint8Array.of(0x88, 0xac));

// ---------------------------------------------------------------- addresses
const CH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const polymod = (v) => {
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let c = 1;
  for (const x of v) {
    const t = c >>> 25;
    c = ((c & 0x1ffffff) << 5) ^ x;
    for (let i = 0; i < 5; i++) if ((t >> i) & 1) c ^= G[i];
  }
  return c >>> 0;
};
const hrpExpand = (h) => [...h].map((c) => c.charCodeAt(0) >> 5).concat([0], [...h].map((c) => c.charCodeAt(0) & 31));
const bits = (data, from, to, pad) => {
  let acc = 0, n = 0;
  const out = [], max = (1 << to) - 1;
  for (const v of data) {
    acc = (acc << from) | v; n += from;
    while (n >= to) { n -= to; out.push((acc >> n) & max); }
  }
  if (pad) { if (n) out.push((acc << (to - n)) & max); } else if (n >= from || ((acc << (to - n)) & max)) throw new Error('bad padding');
  return out;
};
export const segwitEncode = (hrp, ver, prog) => {
  const data = [ver].concat(bits(prog, 8, 5, true));
  const k = ver === 0 ? 1 : 0x2bc830a3;
  const pm = polymod(hrpExpand(hrp).concat(data, [0, 0, 0, 0, 0, 0])) ^ k;
  const sum = [0, 1, 2, 3, 4, 5].map((i) => (pm >> (5 * (5 - i))) & 31);
  return hrp + '1' + data.concat(sum).map((d) => CH[d]).join('');
};
export const segwitDecode = (hrp, addr) => {
  const a = addr.toLowerCase();
  if (a !== addr && addr.toUpperCase() !== addr) throw new Error('mixed case');
  const pos = a.lastIndexOf('1');
  if (pos < 1 || a.slice(0, pos) !== hrp) throw new Error('wrong network for this address');
  const data = [...a.slice(pos + 1)].map((c) => { const i = CH.indexOf(c); if (i < 0) throw new Error('bad character'); return i; });
  const pm = polymod(hrpExpand(hrp).concat(data));
  const ver = data[0];
  if (pm !== (ver === 0 ? 1 : 0x2bc830a3)) throw new Error('bad checksum');
  const prog = Uint8Array.from(bits(data.slice(1, -6), 5, 8, false));
  if (ver > 16 || prog.length < 2 || prog.length > 40 || (ver === 0 && prog.length !== 20 && prog.length !== 32)) throw new Error('bad witness program');
  return { ver, prog };
};
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const b58check = (s) => {
  let n = 0n;
  for (const c of s) { const i = B58.indexOf(c); if (i < 0) throw new Error('bad base58'); n = n * 58n + BigInt(i); }
  let h = n.toString(16); if (h.length % 2) h = '0' + h;
  const lead = s.match(/^1*/)[0].length;
  const raw = cat(new Uint8Array(lead), n === 0n ? new Uint8Array(0) : unhex(h));
  const body = raw.slice(0, -4);
  if (raw.length < 5 || !eq(sha256d(body).slice(0, 4), raw.slice(-4))) throw new Error('bad base58 checksum');
  return body;
};
// net: { hrp, p2pkh, p2sh } (version bytes only matter for legacy addresses).
export const addressToScript = (addr, net) => {
  if (addr.toLowerCase().startsWith(net.hrp + '1')) {
    const { ver, prog } = segwitDecode(net.hrp, addr);
    return cat(Uint8Array.of(ver ? 0x50 + ver : 0, prog.length), prog);
  }
  const b = b58check(addr);
  if (b.length !== 21) throw new Error('bad address');
  if (b[0] === net.p2pkh) return cat(Uint8Array.of(0x76, 0xa9, 20), b.slice(1), Uint8Array.of(0x88, 0xac));
  if (b[0] === net.p2sh) return cat(Uint8Array.of(0xa9, 20), b.slice(1), Uint8Array.of(0x87));
  throw new Error('address is for another network');
};
export const scriptToAddress = (spk, hrp) => {
  if (spk.length >= 4 && spk.length <= 42 && spk[1] === spk.length - 2 && (spk[0] === 0 || (spk[0] >= 0x51 && spk[0] <= 0x60))) {
    return segwitEncode(hrp, spk[0] ? spk[0] - 0x50 : 0, spk.slice(2));
  }
  return null;
};

// ---------------------------------------------------------------- transactions
// tx: { version, locktime, vin: [{ txid (hex, display order), vout, sequence, witness: [bytes], scriptSig? }], vout: [{ value, script }] }
const ser = (tx, withWitness) => {
  const ins = tx.vin.map((i) => cat(rev(unhex(i.txid)), u32(i.vout), varbytes(i.scriptSig || new Uint8Array(0)), u32(i.sequence)));
  const outs = tx.vout.map((o) => cat(u64(o.value), varbytes(o.script)));
  const wit = withWitness && tx.vin.some((i) => i.witness && i.witness.length);
  return cat(u32(tx.version), wit ? Uint8Array.of(0, 1) : new Uint8Array(0), varint(ins.length), ...ins, varint(outs.length), ...outs,
    ...(wit ? tx.vin.map((i) => cat(varint((i.witness || []).length), ...(i.witness || []).map(varbytes))) : []), u32(tx.locktime));
};
export const txHex = (tx) => hex(ser(tx, true));
export const txid = (tx) => hex(rev(sha256d(ser(tx, false))));
export const sighash = (tx, idx, scriptCode, amount) => {
  const prevouts = sha256d(cat(...tx.vin.map((i) => cat(rev(unhex(i.txid)), u32(i.vout)))));
  const seqs = sha256d(cat(...tx.vin.map((i) => u32(i.sequence))));
  const outs = sha256d(cat(...tx.vout.map((o) => cat(u64(o.value), varbytes(o.script)))));
  const i = tx.vin[idx];
  return sha256d(cat(u32(tx.version), prevouts, seqs, rev(unhex(i.txid)), u32(i.vout), varbytes(scriptCode), u64(amount),
    u32(i.sequence), outs, u32(tx.locktime), u32(1)));
};
const der = (sig) => {
  const part = (n) => { let h = n.toString(16); if (h.length % 2) h = '0' + h; let b = unhex(h); if (b[0] & 0x80) b = cat(Uint8Array.of(0), b); return cat(Uint8Array.of(2, b.length), b); };
  const body = cat(part(sig.r), part(sig.s));
  return cat(Uint8Array.of(0x30, body.length), body, Uint8Array.of(1));
};
export const pubkey = (priv) => secp.getPublicKey(priv, true);
const sign = (priv, digest) => der(secp.sign(digest, priv, { lowS: true }));

// Spend P2WPKH coins of one key. utxos: [{ txid, vout, value }]; outputs: [{ value, script }].
export const signP2wpkh = (priv, utxos, outputs) => {
  const pub = pubkey(priv);
  const tx = { version: 2, locktime: 0, vin: utxos.map((u) => ({ txid: u.txid, vout: u.vout, sequence: 0xfffffffd, witness: [] })), vout: outputs };
  tx.vin.forEach((i, n) => { i.witness = [sign(priv, sighash(tx, n, p2pkhCode(pub), utxos[n].value)), pub]; });
  return tx;
};

// ---------------------------------------------------------------- PSBT (BIP 174)
// The page signs with its own key everywhere but one place: coins that sit at the wallet's own
// address on Qwencoin (QWEN it was paid there, or moved there) can only be moved by the wallet's
// key. A Qwencoin transaction is a Bitcoin-format transaction, so the wallet signs it as a PSBT
// and the site hands the result to its Qwencoin node. Nothing here signs; it writes the request
// and reads the answer.
const kv = (type, value, keydata = new Uint8Array(0)) => cat(varint(1 + keydata.length), Uint8Array.of(type), keydata, varbytes(value));
// Which kind of output a wallet address is: p2wpkh, p2sh (taken to wrap p2wpkh), p2tr or legacy.
export const scriptKind = (spk) => (spk.length === 22 && spk[0] === 0 && spk[1] === 20 ? 'p2wpkh' : spk.length === 34 && spk[0] === 0x51 && spk[1] === 32 ? 'p2tr'
  : spk.length === 23 && spk[0] === 0xa9 && spk[22] === 0x87 ? 'p2sh' : spk.length === 25 && spk[0] === 0x76 ? 'p2pkh' : 'other');
// inputs: [{ txid, vout, value }], all paying `script` (the wallet address); pub: the wallet's
// compressed public key (needed for p2sh-wrapped and taproot addresses). outputs: [{ value, script }].
export const psbtHex = (inputs, script, outputs, pub) => {
  const kind = scriptKind(script);
  if (kind === 'p2pkh' || kind === 'other') throw new Error('an address of this kind (legacy) cannot be spent from this page: it would need the whole earlier transaction, which the site may not have');
  let extra = new Uint8Array(0);
  if (kind === 'p2sh') {
    const redeem = p2wpkh(pub);
    if (!eq(hash160(redeem), script.slice(2, 22))) throw new Error('this address is not a wrapped segwit address of the wallet key');
    extra = kv(0x04, redeem);
  } else if (kind === 'p2tr') extra = kv(0x17, pub.slice(1));
  const tx = { version: 2, locktime: 0, vin: inputs.map((u) => ({ txid: u.txid, vout: u.vout, sequence: 0xfffffffd, witness: [] })), vout: outputs };
  return hex(cat(unhex('70736274ff'), kv(0x00, ser(tx, false)), Uint8Array.of(0),
    ...inputs.map((u) => cat(kv(0x01, cat(u64(u.value), varbytes(script))), extra, Uint8Array.of(0))), ...outputs.map(() => Uint8Array.of(0))));
};
const reader = (b) => {
  let o = 0;
  const take = (n) => { if (o + n > b.length) throw new Error('truncated'); const x = b.slice(o, o + n); o += n; return x; };
  const vi = () => { const f = take(1)[0]; if (f < 0xfd) return f; const n = f === 0xfd ? 2 : f === 0xfe ? 4 : 8; return take(n).reduce((a, x, i) => a + x * 256 ** i, 0); };
  return { take, vi, bytes: () => take(vi()), end: () => o >= b.length, u32: () => new DataView(take(4).buffer).getUint32(0, true), u64: () => Number(new DataView(take(8).buffer).getBigUint64(0, true)) };
};
const psbtMap = (r) => { // one key-value map: [{ type, key, value }]
  const out = [];
  for (;;) { const klen = r.vi(); if (klen === 0) return out; const k = r.take(klen); out.push({ type: k[0], key: k.slice(1), value: r.bytes() }); }
};
const stack = (b) => { const r = reader(b), out = []; for (let n = r.vi(); n > 0; n--) out.push(r.bytes()); return out; };
// The network transaction a signed PSBT holds, and the transaction it was asked for: the page
// broadcasts only if the wallet signed exactly what it was given (same inputs, same outputs).
export const txFromPsbt = (psbt) => {
  try {
    const r = reader(unhex(psbt));
    if (hex(r.take(5)) !== '70736274ff') throw 0;
    const g = psbtMap(r).find((e) => e.type === 0 && e.key.length === 0);
    const t = reader(g.value), tx = { version: t.u32(), vin: [], vout: [], locktime: 0 };
    for (let n = t.vi(); n > 0; n--) { const prev = t.take(32); tx.vin.push({ txid: hex(rev(prev)), vout: t.u32(), scriptSig: t.bytes(), sequence: t.u32(), witness: [] }); }
    for (let n = t.vi(); n > 0; n--) tx.vout.push({ value: t.u64(), script: t.bytes() });
    tx.locktime = t.u32();
    for (const i of tx.vin) {
      const m = psbtMap(r), get = (type) => m.find((e) => e.type === type);
      const fw = get(0x08), fs = get(0x07), part = get(0x02), key = get(0x13), redeem = get(0x04);
      if (fw || fs) { i.witness = fw ? stack(fw.value) : []; i.scriptSig = fs ? fs.value : new Uint8Array(0); } // finalized by the wallet
      else if (key) i.witness = [key.value]; // taproot key path, not finalized
      else if (part) { i.witness = [part.value, part.key]; i.scriptSig = redeem ? push(redeem.value) : new Uint8Array(0); } // one signature and its key
      else throw 0;
    }
    return { hex: txHex(tx), txid: txid(tx), tx };
  } catch (e) { throw new Error('the wallet did not return a signed transaction'); }
};
export const sameSpend = (tx, inputs, outputs) => tx.vin.length === inputs.length && tx.vin.every((i, n) => i.txid === inputs[n].txid && i.vout === inputs[n].vout)
  && tx.vout.length === outputs.length && tx.vout.every((o, n) => o.value === outputs[n].value && eq(o.script, outputs[n].script));

// ---------------------------------------------------------------- HTLC (hashfun/htlc.py)
export const contractScript = (c) => cat(Uint8Array.of(0x63, 0x82), pushInt(32), Uint8Array.of(0x88, 0xa8), push(c.secretHash),
  Uint8Array.of(0x88), push(c.recipientPub), Uint8Array.of(0x67), pushInt(c.locktime), Uint8Array.of(0xb1, 0x75), push(c.refundPub),
  Uint8Array.of(0x68, 0xac));
export const parseContract = (script) => {
  try {
    if (script.length < 110 || script.length > 120 || script[6] !== 32 || script[40] !== 33 || script[74] !== 0x67) throw 0;
    const n = script[75];
    if (n < 1 || n > 5 || script[76 + n + 2] !== 33) throw 0;
    let locktime = 0;
    for (let i = n - 1; i >= 0; i--) locktime = locktime * 256 + script[76 + i];
    const c = { secretHash: script.slice(7, 39), recipientPub: script.slice(41, 74), locktime, refundPub: script.slice(79 + n, 112 + n) };
    if (!eq(contractScript(c), script)) throw 0;
    return c;
  } catch (e) {
    throw new Error('not a hashfun swap contract');
  }
};
const htlcSpend = (c, prev, amount, dest, fee, locktime, sequence, priv, mid) => {
  if (amount - fee <= 546) throw new Error('fee leaves nothing to collect');
  const ws = contractScript(c);
  const tx = { version: 2, locktime, vin: [{ txid: prev.txid, vout: prev.vout, sequence, witness: [] }], vout: [{ value: amount - fee, script: dest }] };
  tx.vin[0].witness = [sign(priv, sighash(tx, 0, ws, amount)), ...mid, ws];
  return tx;
};
export const redeemTx = (c, prev, amount, dest, fee, priv, secret) => {
  if (!eq(pubkey(priv), c.recipientPub)) throw new Error('this key cannot redeem the contract');
  if (secret.length !== 32 || !eq(sha256(secret), c.secretHash)) throw new Error('secret does not match the contract');
  return htlcSpend(c, prev, amount, dest, fee, 0, 0xffffffff, priv, [secret, Uint8Array.of(1)]);
};
export const refundTx = (c, prev, amount, dest, fee, priv) => {
  if (!eq(pubkey(priv), c.refundPub)) throw new Error('this key cannot refund the contract');
  return htlcSpend(c, prev, amount, dest, fee, c.locktime, 0xfffffffe, priv, [new Uint8Array(0)]);
};

// ---------------------------------------------------------------- the hashfun key
// One key per wallet, derived from a signature only that wallet can make. It holds launch coins
// (P2WPKH on every launch chain) and receives BTC yield (the same script on Bitcoin).
export const KEY_MESSAGE = 'hashfun key v1\n\nSigning this unlocks your hashfun key in this browser. It holds your launch coins and receives your BTC payouts. Only sign it on a site you trust.';
export const keyFromSignature = (sigB64) => {
  let k = sha256(cat(utf8('hashfun-key-v1'), utf8(sigB64)));
  while (!secp.utils.isValidPrivateKey(k)) k = sha256(k);
  return k;
};
export const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

// ---------------------------------------------------------------- signed text (hashfun/book.py)
// Orders and swap messages are short texts signed with the hashfun key: ECDSA over SHA256d of the
// text, r || s as 64 bytes of hex.
export const signText = (priv, text) => secp.sign(sha256d(utf8(text)), priv, { lowS: true }).toCompactHex();
export const verifyText = (pubHex, text, sigHex) => {
  try { return /^[0-9a-f]{128}$/.test(sigHex) && secp.verify(sigHex, sha256d(utf8(text)), unhex(pubHex), { lowS: false }); } catch (e) { return false; }
};
// The secret a swap's claim revealed: the 32-byte witness item that hashes to the contract's hash.
export const secretFromWitness = (witnesses, secretHash) => {
  for (const w of witnesses) for (const item of w) if (item.length === 64 && eq(sha256(unhex(item)), secretHash)) return unhex(item);
  return null;
};

// ---------------------------------------------------------------- launch metadata (hashfun/meta.py)
export const imageType = (d) => {
  const at = (o, s) => [...s].every((c, i) => d[o + i] === c.charCodeAt(0));
  if (d[0] === 0x89 && at(1, 'PNG\r\n\x1a\n')) return 'image/png';
  if (d[0] === 0xff && d[1] === 0xd8 && d[2] === 0xff) return 'image/jpeg';
  if (at(0, 'GIF87a') || at(0, 'GIF89a')) return 'image/gif';
  if (at(0, 'RIFF') && at(8, 'WEBP')) return 'image/webp';
  return null;
};
// m: { description, image_type, image (bytes), website, x, telegram }. What the descriptor's
// `meta` field must equal: the page checks the site committed to the picture it was given.
export const metaHash = (m) => sha256(cat(utf8('hashfun-meta\x01'), varbytes(utf8(m.description || '')), varbytes(utf8(m.image_type || '')),
  varbytes(m.image || new Uint8Array(0)), ...['website', 'x', 'telegram'].map((k) => varbytes(utf8(m[k] || '')))));
export const b64 = (bytes) => { let s = ''; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000)); return btoa(s); };
