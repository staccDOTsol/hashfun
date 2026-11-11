// hashfun book: peer-to-peer atomic swaps between any two chains the site follows (Bitcoin and
// every launch). This file is a trader's whole stack: it signs orders, answers takes, builds,
// checks and funds the swap contracts, and claims or refunds them. The server relays signed
// messages and reads chains (hashfun/book.py); it never sees a key and never holds a coin.
//
// A swap, taker first:   take -> accept -> taker locks -> maker locks -> taker claims -> maker claims
// Each side's own lock goes back to it after its timelock if the other side stops.
//
// Everything here is driven by tick(): every record of a swap in progress lives in localStorage
// and is advanced one step at a time, so a reload, a closed tab or a crash loses nothing. A
// record is written before any transaction it describes is broadcast.
import * as B from './btc.js';

export const orderText = (o) => ['hashfun-order-v1', o.maker, o.give, o.give_amount, o.get, o.get_amount, o.min_get, o.expiry, o.nonce, o.lock, o.confs].join('\n');
export const takeText = (t) => ['hashfun-take-v1', t.order, t.taker, t.get_amount, t.secret_hash, t.locktime, t.ts].join('\n');
export const noteText = (fill, kind, body) => ['hashfun-fill-v1', fill, kind, ...Object.keys(body).sort().map((k) => `${k}=${body[k]}`)].join('\n');
export const aliveText = (maker, ts) => `hashfun-alive-v1\n${maker}\n${ts}`;
export const cancelText = (order) => `hashfun-cancel-v1\n${order}`;
export const textId = (text) => B.hex(B.sha256d(B.utf8(text))).slice(0, 32);
// What a taker paying getAmount receives: pro rata, rounded down.
export const giveFor = (o, getAmount) => Number((BigInt(o.give_amount) * BigInt(getAmount)) / BigInt(o.get_amount));

export const FINAL = ['done', 'failed', 'released', 'refunded'];
// Which output of a transaction pays a script. The transaction itself can only be read while it
// is unconfirmed unless the node keeps a transaction index (most Bitcoin nodes do not), so once
// it is in a block the unspent outputs are probed one by one instead.
export async function findOutput(api, chain, txid, scriptHex) {
  const tx = await api(`/chain/${chain}/tx/${txid}`).catch(() => null);
  const hit = tx && tx.vout.find((x) => x.script === scriptHex);
  if (hit) return hit.n;
  for (let n = 0; n < 6; n++) { const o = await api(`/chain/${chain}/txout/${txid}/${n}`).catch(() => null); if (o && o.script === scriptHex) return n; }
  return null;
}
const CLAIM_VB = 180, REFUND_VB = 170;
const MIN_OUTPUT = 2000; // a lock smaller than this is not worth its own claim fee
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = () => Math.floor(Date.now() / 1000);

// env: { api(path, body), W: { key, pub, addr }, cfg(): site config, store: localStorage-like,
//        unisat(): the wallet or null, onChange(rec) }
export function createBook(env) {
  const { api, W, cfg } = env;
  const load = (k) => { try { return JSON.parse(env.store.getItem(k) || '{}'); } catch (e) { return {}; } };
  const save = (k, v) => env.store.setItem(k, JSON.stringify(v));
  const recs = () => load('hf_p2p');
  const put = (rec) => { rec.updated = Date.now(); const all = recs(); all[rec.id] = rec; save('hf_p2p', all); if (env.onChange) env.onChange(rec); return rec; };
  const pubHex = () => B.hex(W.pub);
  const sign = (text) => B.signText(W.key, text);

  // The API speaks "btc" and tickers; signed orders name chains by id (btc:<net> or the launch id).
  const nameOf = (id) => (id === cfg().btc_id ? 'btc' : Object.keys(cfg().launches).find((t) => cfg().launches[t].id === id));
  const idOf = (name) => (name === 'btc' ? cfg().btc_id : cfg().launches[name].id);
  const label = (name) => (name === 'btc' ? 'sats' : '$' + name);
  const myScript = () => B.p2wpkh(W.pub);
  const addrOn = (name) => B.segwitEncode(name === 'btc' ? cfg().btc.hrp : cfg().launches[name].hrp, 0, B.hash160(W.pub));
  // Bitcoin goes to the wallet's own address; launch coins stay at the hashfun key.
  const destOn = (name) => (name === 'btc' ? B.addressToScript(W.addr, cfg().btc) : myScript());
  const spacing = (name) => (name === 'btc' ? 600 : cfg().launches[name].target_spacing || 60);
  const confsFor = (name) => (name === 'btc' ? 1 : cfg().book.confs);
  // How long before the maker's refund opens a taker stops claiming: a claim that confirms after
  // the maker has refunded would hand the maker the secret and both sides of the swap.
  const margin = (name, lock) => Math.min(Math.max(600, 6 * spacing(name)), Math.floor(lock / 4));

  // ---------------------------------------------------------------- coins of the hashfun key
  let btcCache = null;
  const utxos = async (name) => {
    let list;
    if (name === 'btc') { // a UTXO-set scan on the site's node: about a minute on mainnet, so keep the answer a while
      if (!btcCache || Date.now() - btcCache.t > (cfg().btc.chain === 'main' ? 120000 : 3000)) btcCache = { t: Date.now(), list: (await api(`/chain/btc/address/${addrOn('btc')}`)).utxos.filter((u) => u.confirmations > 0) };
      list = btcCache.list;
    } else list = (await api(`/coin/${name}/address/${addrOn(name)}`)).utxos.filter((u) => u.spendable);
    const spent = load('hf_spent'); // outputs our own unconfirmed transactions already spend
    return list.filter((u) => !spent[`${name}:${u.txid}:${u.vout}`]);
  };
  const balance = async (name) => (await utxos(name)).reduce((a, u) => a + u.value, 0);
  const markSpent = (keys) => { const s = load('hf_spent'), t = Date.now(); for (const k of Object.keys(s)) if (t - s[k] > 6 * 3600e3) delete s[k]; keys.forEach((k) => { s[k] = t; }); save('hf_spent', s); };
  const buildLock = async (name, spk, amount) => {
    const t = await api(`/chain/${name}/time`);
    const pool = (await utxos(name)).sort((a, b) => b.value - a.value), sel = [];
    let sum = 0, fee = 0;
    for (const u of pool) { sel.push(u); sum += u.value; fee = t.feerate * (90 + 68 * sel.length); if (sum >= amount + fee) break; }
    if (sum < amount + fee) throw new Error(`not enough spendable ${label(name)} at your hashfun key`);
    const outs = [{ value: amount, script: spk }];
    if (sum - amount - fee > 600) outs.push({ value: sum - amount - fee, script: myScript() });
    const tx = B.signP2wpkh(W.key, sel, outs);
    return { hex: B.txHex(tx), txid: B.txid(tx), vout: 0, spends: sel.map((u) => `${name}:${u.txid}:${u.vout}`) };
  };
  const txout = (name, o) => api(`/chain/${name}/txout/${o.txid}/${o.vout}`);
  // A lock is only worth making if claiming it costs a small part of it at today's fees.
  const worth = async (name, amount) => amount >= MIN_OUTPUT && amount >= 4 * CLAIM_VB * (await api(`/chain/${name}/time`)).feerate;
  // Broadcast; "already known" is success when the node really has the output.
  const broadcast = async (name, hex, outpoint) => {
    try { return (await api(`/chain/${name}/tx`, { hex })).txid; } catch (e) {
      if (outpoint && (await txout(name, outpoint).catch(() => null))) return outpoint.txid;
      throw e;
    }
  };

  // ---------------------------------------------------------------- messages
  const note = (fill, kind, body = {}) => api(`/book/fill/${fill}`, { from: pubHex(), kind, body, sig: sign(noteText(fill, kind, body)) });
  const findNote = (f, kind, from) => (f.notes || []).find((n) => n.kind === kind && n.from === from && B.verifyText(from, noteText(f.id, kind, n.body), n.sig));
  const contractOf = (rec, mine) => {
    // Both contracts are fully determined by the take: nothing in them is negotiable afterwards.
    const takerSide = (rec.role === 'taker') === mine; // the taker's lock, on the chain the maker wants
    const taker = B.unhex(rec.taker), maker = B.unhex(rec.order.maker);
    return B.contractScript({ secretHash: B.unhex(rec.secret_hash), recipientPub: takerSide ? maker : taker, refundPub: takerSide ? taker : maker,
      locktime: takerSide ? rec.locktime : rec.locktime - rec.order.lock });
  };

  // ---------------------------------------------------------------- maker: orders
  async function post({ give, get, give_amount, get_amount, min_get, ttl }) {
    if (!(give_amount >= MIN_OUTPUT) || !(get_amount >= MIN_OUTPUT)) throw new Error('too small: both sides need at least ' + MIN_OUTPUT + ' base units');
    // A taker may claim my lock right up to its timelock as that chain's clock (median of the last
    // 11 blocks, so about 6 blocks behind) sees it; I then need time to claim theirs. The lock has
    // to cover both. Test networks mine on demand and are exempt.
    const needLock = 12 * spacing(give) + 6 * spacing(get);
    if (cfg().btc.chain !== 'regtest' && cfg().book.lock < needLock) throw new Error(`this site's swap lock (${cfg().book.lock} s) is too short for this pair: it needs ${needLock} s`);
    // Everything I already offer from this chain counts: an offer is a promise the page must keep.
    const promised = (await mine().catch(() => [])).filter((x) => x.give === idOf(give)).reduce((a, x) => a + x.remaining, 0);
    let have = await balance(give);
    if (have < give_amount + promised && give === 'btc') { btcCache = null; have = await balance(give); } // a deposit may have just confirmed
    if (have < give_amount + promised) throw new Error(`your hashfun key holds ${have} in spendable ${label(give)}: less than this offer${promised ? ' plus your other open offers' : ''}`);
    // The smallest take: both pieces of it must be worth locking.
    const floor = Math.max(MIN_OUTPUT, Math.ceil((MIN_OUTPUT * get_amount) / give_amount));
    const o = { maker: pubHex(), give: idOf(give), give_amount, get: idOf(get), get_amount, min_get: Math.min(get_amount, Math.max(min_get || 0, floor)),
      expiry: now() + (ttl || 86400), nonce: B.hex(B.randomBytes(8)), lock: cfg().book.lock, confs: confsFor(get) };
    o.sig = sign(orderText(o));
    const r = await api('/book/order', o);
    const kept = load('hf_orders'); kept[r.id] = o; save('hf_orders', kept);
    return r;
  }
  async function cancel(id) {
    await api('/book/cancel', { order: id, sig: sign(cancelText(id)) });
    const kept = load('hf_orders'); delete kept[id]; save('hf_orders', kept);
  }
  const mine = () => api(`/book?maker=${pubHex()}`).then((r) => r.orders);
  const makerUsed = (orderId) => Object.values(recs()).filter((r) => r.role === 'maker' && r.order.id === orderId && !['released', 'failed', 'refunded'].includes(r.state)).reduce((a, r) => a + r.give_amount, 0);
  const committed = (name) => Object.values(recs()).filter((r) => r.role === 'maker' && r.give === name && r.state === 'accepted').reduce((a, r) => a + r.give_amount, 0);

  // A take arrived for one of my orders: check it against the order I signed and say yes or no.
  async function answer(f) {
    const o = load('hf_orders')[f.order];
    const refuse = (why) => note(f.id, 'reject', { why }).catch(() => {});
    if (!o) return refuse('unknown order');
    if (!B.verifyText(f.taker, takeText(f), f.sig) || textId(takeText(f)) !== f.id) return refuse('bad signature');
    if (giveFor(o, f.get_amount) !== f.give_amount || f.get_amount < o.min_get || f.give_amount < MIN_OUTPUT) return refuse('bad amount');
    const t = now();
    if (o.expiry <= t) return refuse('order expired');
    if (f.locktime < t + 2 * o.lock || f.locktime > t + 3 * o.lock + 600) return refuse('bad timelock');
    if (makerUsed(f.order) + f.give_amount > o.give_amount) return refuse('order is taken');
    const give = nameOf(o.give), get = nameOf(o.get);
    if (!give || !get) return refuse('chain not followed here');
    if (!(await worth(give, f.give_amount)) || !(await worth(get, f.get_amount))) return refuse('too small for the network fee');
    if ((await balance(give)) < f.give_amount + committed(give)) return refuse('maker is out of coins');
    const rec = { id: f.id, role: 'maker', order: { ...o, id: f.order }, give, get, give_amount: f.give_amount, get_amount: f.get_amount, secret_hash: f.secret_hash,
      locktime: f.locktime, taker: f.taker, state: 'accepted', until: t + (get === 'btc' ? 300 : 120), created: Date.now(), my: {}, their: {} };
    put(rec); // the reservation is ours before the board hears of it
    await note(f.id, 'accept', { until: rec.until });
  }

  let session = null;
  async function heartbeat() {
    const orders = load('hf_orders'), t = now();
    for (const [id, o] of Object.entries(orders)) if (o.expiry <= t) delete orders[id];
    save('hf_orders', orders);
    if (!Object.keys(orders).length && !Object.values(recs()).some((r) => r.role === 'maker' && !FINAL.includes(r.state))) return;
    const signed = () => ({ maker: pubHex(), ts: now(), sig: sign(aliveText(pubHex(), now())) });
    let r;
    try { r = await api('/book/alive', session ? { maker: pubHex(), session } : signed()); } catch (e) { r = await api('/book/alive', signed()); }
    session = r.session;
    for (const f of r.fills) if (f.state === 'requested' && !recs()[f.id]) await answer(f).catch(() => {});
  }

  // ---------------------------------------------------------------- taker: take an order
  async function take(order, getAmount, ui = () => {}) {
    if (!B.verifyText(order.maker, orderText(order), order.sig) || textId(orderText(order)) !== order.id) throw new Error('that order is not signed by its maker');
    const give = nameOf(order.give), get = nameOf(order.get);
    if (!give || !get) throw new Error('this site does not follow one of those chains');
    const giveAmount = giveFor(order, getAmount);
    if (getAmount < order.min_get) throw new Error('too small for this order');
    if (!(await worth(give, giveAmount)) || !(await worth(get, getAmount))) throw new Error('too small to be worth the network fee');
    const viaWallet = get === 'btc' && env.unisat(); // Bitcoin is paid from the wallet; coins from the hashfun key
    if (!viaWallet && (await balance(get)) < getAmount) throw new Error(`you hold less than that in spendable ${label(get)}`);
    const secret = B.randomBytes(32), hash = B.sha256(secret);
    const t = await api(`/chain/${get}/time`);
    const locktime = Math.max(now(), t.mediantime) + 2 * order.lock + Math.min(600, Math.floor(order.lock / 2));
    const tk = { order: order.id, taker: pubHex(), get_amount: getAmount, secret_hash: B.hex(hash), locktime, ts: now() };
    const rec = { id: textId(takeText(tk)), role: 'taker', order, give, get, give_amount: giveAmount, get_amount: getAmount, secret: B.hex(secret), secret_hash: B.hex(hash),
      locktime, taker: pubHex(), state: 'requested', created: Date.now(), my: {}, their: {} };
    put(rec); // the secret is on disk before anyone hears its hash
    ui('ask', rec);
    const fail = (why) => { rec.state = 'failed'; rec.note = why; put(rec); note(rec.id, 'abort').catch(() => {}); throw new Error(why); };
    await api('/book/take', { ...tk, sig: sign(takeText(tk)) }).catch((e) => fail(e.message || String(e))); // e.g. the offer just went
    for (let i = 0; ; i++) { // the maker's page answers within seconds, or it is gone
      const f = await api(`/book/fill/${rec.id}`);
      const ok = f.state === 'accepted' && findNote(f, 'accept', order.maker);
      if (ok) { rec.until = Number(ok.body.until); break; }
      if (f.state === 'rejected') fail('the maker said no: ' + ((findNote(f, 'reject', order.maker) || { body: {} }).body.why || 'no reason given'));
      if (f.state !== 'requested' || i > 45) fail('the maker did not answer; try another order');
      await sleep(700);
    }
    rec.state = 'accepted'; put(rec);
    if (now() > rec.until - 10) fail('too slow: the maker\'s offer lapsed');
    ui('lock', rec);
    try { await lockMine(rec, 90); } catch (e) {
      if (!rec.my.txid) fail(e.message || String(e)); // nothing left this page: nothing is at risk
      throw e;
    }
    ui('wait', rec);
    return rec;
  }

  // Fund my side of a swap. The record holds the signed transaction before it is broadcast.
  async function lockMine(rec, tries = 1) {
    const name = rec.role === 'taker' ? rec.get : rec.give, amount = rec.role === 'taker' ? rec.get_amount : rec.give_amount;
    const script = contractOf(rec, true), spk = B.p2wsh(script);
    rec.my.contract = B.hex(script);
    if (!rec.my.txid) {
      if (rec.role === 'taker' && name === 'btc' && env.unisat()) { // the wallet builds and sends this one
        rec.my.address = B.segwitEncode(cfg().btc.hrp, 0, spk.slice(2)); rec.state = 'locking'; put(rec);
        rec.my.txid = await env.unisat().sendBitcoin(rec.my.address, amount); put(rec);
      } else {
        const tx = await buildLock(name, spk, amount);
        Object.assign(rec.my, { txid: tx.txid, vout: 0, hex: tx.hex }); rec.state = 'locking'; put(rec);
        markSpent(tx.spends); if (name === 'btc') btcCache = null;
      }
    }
    if (rec.my.hex) await broadcast(name, rec.my.hex, rec.my);
    for (let i = 0; rec.my.vout == null; i++) { // sent by the wallet: find which output is the lock
      const n = await findOutput(api, name, rec.my.txid, B.hex(spk));
      if (n != null) rec.my.vout = n; else if (i >= tries) throw new Error('your payment has not reached this site\'s Bitcoin node yet; this swap resumes by itself when it does'); else await sleep(1000);
    }
    rec.state = 'locked'; put(rec); // from here the refund path is armed, whatever the board says
    await tellLocked(rec);
  }
  const tellLocked = (rec) => note(rec.id, 'locked', { contract: rec.my.contract, txid: rec.my.txid, vout: rec.my.vout }).catch((e) => { rec.note = 'could not tell the other side about your lock: ' + (e.message || e); put(rec); });

  // ---------------------------------------------------------------- one step of one swap
  async function refundIfDue(rec) {
    const name = rec.role === 'taker' ? rec.get : rec.give, c = B.parseContract(B.unhex(rec.my.contract));
    const t = await api(`/chain/${name}/time`);
    if (t.mediantime <= c.locktime) return false;
    const out = await txout(name, rec.my);
    if (!out) return false; // spent: claimed by the other side (the maker's step looks for the secret)
    const tx = B.refundTx(c, rec.my, out.value, destOn(name), REFUND_VB * t.feerate, W.key);
    rec.refund_txid = (await api(`/chain/${name}/tx`, { hex: B.txHex(tx) })).txid;
    rec.state = 'refunded'; rec.note = 'the other side stopped; your lock came back'; put(rec);
    return true;
  }
  async function claim(rec, name, outpoint, script, secret) {
    const c = B.parseContract(script), t = await api(`/chain/${name}/time`), out = await txout(name, outpoint);
    if (!out) { if (rec.claim_txid) return; throw new Error('the lock to claim is gone'); } // gone because we claimed it
    const tx = B.redeemTx(c, outpoint, out.value, destOn(name), CLAIM_VB * t.feerate, W.key, secret);
    rec.claim_txid = B.txid(tx); rec.got = out.value - CLAIM_VB * t.feerate; put(rec);
    await api(`/chain/${name}/tx`, { hex: B.txHex(tx) });
  }

  async function stepTaker(rec) {
    if (rec.state === 'requested' || rec.state === 'accepted') { // the page went away mid-handshake; nothing was locked
      rec.state = 'failed'; rec.note = 'interrupted before anything was locked'; put(rec);
      return void note(rec.id, 'abort').catch(() => {});
    }
    if (rec.state === 'locking') {
      if (rec.my.hex && now() > rec.locktime && !(await txout(rec.get, rec.my).catch(() => 1))) { rec.state = 'failed'; rec.note = 'the lock was never accepted by the network'; return void put(rec); }
      if (!rec.my.txid) { // the wallet may or may not have paid: look at the contract's address
        const seen = rec.my.address ? await api(`/chain/btc/address/${rec.my.address}`).catch(() => null) : null;
        if (seen && seen.utxos.length) { rec.my.txid = seen.utxos[0].txid; rec.my.vout = seen.utxos[0].vout; put(rec); } else if (Date.now() - rec.updated > 180000) { rec.state = 'failed'; rec.note = 'the payment was not made'; return void put(rec); } else return;
      }
      return void (await lockMine(rec));
    }
    if (rec.state !== 'locked') return;
    if (await refundIfDue(rec)) return;
    const f = await api(`/book/fill/${rec.id}`).catch(() => null);
    if (f && f.state === 'accepted') await tellLocked(rec); // the board never heard of our lock
    const n = f && findNote(f, 'locked', rec.order.maker);
    if (!n) {
      const why = f && findNote(f, 'fail', rec.order.maker);
      rec.note = why ? `the maker would not lock (${why.body.why}); your lock comes back after its timelock` : 'waiting for the maker to lock';
      return void put(rec);
    }
    const expect = contractOf(rec, false);
    if (n.body.contract !== B.hex(expect)) { rec.note = 'the maker locked a different contract; your lock comes back after its timelock'; return void put(rec); }
    const their = { txid: n.body.txid, vout: Number(n.body.vout) }, out = await txout(rec.give, their);
    if (!out || out.script !== B.hex(B.p2wsh(expect)) || out.value < rec.give_amount) { rec.note = 'the maker\'s lock is not on the chain (yet)'; return void put(rec); }
    const t = await api(`/chain/${rec.give}/time`), need = confsFor(rec.give);
    // Reveal the secret only while the maker cannot refund for a good while yet.
    if (t.mediantime + margin(rec.give, rec.order.lock) >= rec.locktime - rec.order.lock) { rec.note = 'too close to the maker\'s refund to claim safely; your lock comes back after its timelock'; return void put(rec); }
    if (out.confirmations < need) { rec.note = `${out.confirmations} of ${need} confirmations on the maker's lock`; return void put(rec); }
    rec.their = their;
    await claim(rec, rec.give, their, expect, B.unhex(rec.secret));
    rec.state = 'done'; rec.note = ''; put(rec);
    note(rec.id, 'claimed', { txid: rec.claim_txid }).catch(() => {});
  }

  async function stepMaker(rec) {
    const f = await api(`/book/fill/${rec.id}`).catch(() => null);
    if (rec.state === 'accepted') {
      const n = f && findNote(f, 'locked', rec.taker);
      const giveUp = async (why, tell) => { rec.state = 'released'; rec.note = why; put(rec); if (tell) await note(rec.id, tell, tell === 'fail' ? { why } : {}).catch(() => {}); };
      if (!n) {
        if (f && FINAL.concat(['expired', 'aborted', 'rejected']).includes(f.state)) return giveUp('the taker did not lock');
        if (now() > rec.until + 20) return giveUp('the taker did not lock in time', 'release');
        return;
      }
      const expect = contractOf(rec, false); // the taker's lock, exactly as the take defines it
      if (n.body.contract !== B.hex(expect)) return giveUp('wrong contract', 'fail');
      const their = { txid: n.body.txid, vout: Number(n.body.vout) }, out = await txout(rec.get, their);
      if (!out) { if (now() > rec.until + 600) return giveUp('lock never appeared', 'fail'); return; }
      if (out.script !== B.hex(B.p2wsh(expect)) || out.value < rec.get_amount) return giveUp('wrong lock', 'fail');
      if (out.confirmations < rec.order.confs) { rec.note = `${out.confirmations} of ${rec.order.confs} confirmations on the taker's lock`; return void put(rec); }
      // My lock must leave the taker time to claim, and me the order's full lock to claim after.
      if (rec.locktime - rec.order.lock - now() < rec.order.lock / 2) return giveUp('too late to lock safely', 'fail');
      rec.their = their; put(rec);
      return void (await lockMine(rec));
    }
    if (rec.state === 'locking') return void (await lockMine(rec));
    if (rec.state !== 'locked') return;
    if (f && f.state === 'taker_locked') await tellLocked(rec);
    // Has the taker claimed? Then the secret is public: take the other side.
    let secret = null;
    const sp = await api(`/chain/${rec.give}/spender/${rec.my.txid}/${rec.my.vout}`).catch(() => null);
    if (sp) secret = B.secretFromWitness(sp.witness, B.unhex(rec.secret_hash));
    const said = f && findNote(f, 'claimed', rec.taker);
    if (!secret && said && /^[0-9a-f]{64}$/.test(said.body.txid)) { // deeper than the spender scan looks
      const tx = await api(`/chain/${rec.give}/tx/${said.body.txid}`).catch(() => null);
      if (tx) secret = B.secretFromWitness(tx.vin.map((i) => i.witness), B.unhex(rec.secret_hash));
    }
    if (secret) {
      rec.secret = B.hex(secret); put(rec);
      await claim(rec, rec.get, rec.their, contractOf(rec, false), secret);
      rec.state = 'done'; rec.note = ''; put(rec);
      return void note(rec.id, 'done').catch(() => {});
    }
    if (await refundIfDue(rec)) await note(rec.id, 'fail', { why: 'refunded' }).catch(() => {}); // frees that part of the offer on the board
  }

  let busy = false;
  async function tick() {
    if (busy || !W.key) return;
    busy = true;
    try {
      await heartbeat().catch(() => {});
      for (const rec of Object.values(recs())) {
        if (FINAL.includes(rec.state) || rec.taker === undefined) continue;
        if (rec.role === 'taker' && taking.has(rec.id)) continue; // take() is driving it right now
        try { await (rec.role === 'taker' ? stepTaker(rec) : stepMaker(rec)); } catch (e) { const r = recs()[rec.id]; if (r && r.note !== (e.message || String(e))) { r.note = e.message || String(e); put(r); } }
      }
    } finally { busy = false; }
  }
  const taking = new Set();
  const takeGuarded = async (order, amount, ui) => {
    let id = null;
    try { return await take(order, amount, (k, rec) => { if (rec && !id) { id = rec.id; taking.add(id); } if (ui) ui(k, rec); }); } finally { if (id) taking.delete(id); }
  };
  // One tab runs the engine: two tabs answering the same take would lock twice. Browsers slow a
  // hidden tab's timers to as little as one a minute, which would take a maker with the site in a
  // background tab off the board, so the beat comes from a worker (worker timers are not slowed).
  // Holding the lock for the tab's life also keeps the browser from freezing the tab.
  function start(ms = 2500) {
    const beat = () => {
      tick();
      try {
        const w = new Worker(URL.createObjectURL(new Blob([`setInterval(() => postMessage(0), ${ms})`], { type: 'text/javascript' })));
        w.onmessage = () => tick();
        w.onerror = () => { w.terminate(); setInterval(tick, ms); };
      } catch (e) { setInterval(tick, ms); }
    };
    const hold = () => new Promise(() => beat()); // never settles: the lock is ours until the tab closes
    if (typeof navigator !== 'undefined' && navigator.locks) navigator.locks.request('hashfun-book', hold); else hold();
  }

  // A swap this page still has to act on: closing the tab now could cost its owner the other side.
  const pending = () => Object.values(recs()).some((r) => r.taker && ['locking', 'locked'].includes(r.state));
  return { pending, post, cancel, mine, take: takeGuarded, tick, start, recs, balance, nameOf, idOf, addrOn, confsFor, list: (q = '') => api('/book' + q).then((r) => r.orders) };
}
