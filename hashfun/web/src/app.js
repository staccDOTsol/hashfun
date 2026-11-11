// hashfun site: board, coin page, launch form, bags, the peer-to-peer book, and atomic swaps signed
// in the browser.
// Keys never leave the page: the server only reads chains and broadcasts what is signed here.
import * as B from './btc.js';
import { createBook, findOutput } from './book.js';

const O = '#FF9A1F', L = '#C7F23E', WHT = '#F2F0EC', K = '#0A0A0B';
const COIN = 1e8;
const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------- dom
const mk = (ns) => (tag, attrs, ...kids) => {
  const e = ns ? document.createElementNS(ns, tag) : document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'class' && !ns) e.className = v;
    else if (k === 'value' && !ns) e.value = v;
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat(Infinity)) if (kid != null && kid !== false) e.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return e;
};
const h = mk(null), s = mk('http://www.w3.org/2000/svg');
const fmt = (n, d = 0) => Number(n).toLocaleString('en-US', { minimumFractionDigits: d, maximumFractionDigits: d });
const coins = (v) => fmt(v / COIN, v / COIN >= 1000 ? 0 : 2);
const btc = (v) => (v / COIN).toFixed(v >= COIN / 100 ? 4 : 6);
const short = (a) => (a && a.length > 14 ? a.slice(0, 6) + '…' + a.slice(-4) : a || '');
const ago = (t) => { const d = Math.max(0, Math.floor(Date.now() / 1000 - t)); return d < 3 ? 'now' : d < 90 ? d + 's' : d < 5400 ? Math.floor(d / 60) + 'm' : d < 129600 ? Math.floor(d / 3600) + 'h' : Math.floor(d / 86400) + 'd'; };
const price = (p) => (p >= 100 ? fmt(p) : p >= 1 ? p.toFixed(2) : p >= 0.01 ? p.toFixed(4) : p.toPrecision(2));
const hashrate = (x) => { const u = ['H/s', 'kH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s', 'EH/s']; let i = 0; while (x >= 1000 && i < 6) { x /= 1000; i++; } return x.toFixed(x < 10 ? 1 : 0) + ' ' + u[i]; };
const tile = (t, big, img) => {
  // The launch's own picture when it has one (committed by its genesis block), else two letters.
  const src = img === undefined ? (cfg.launches[t] || {}).image : img;
  if (src) return h('img', { class: 'tile pic' + (big ? ' big' : ''), src, alt: '', loading: 'lazy' });
  const combos = [[L, K, L], [O, K, O], [WHT, K, WHT], [K, O, O], [K, L, L], [K, WHT, WHT]];
  const c = combos[[...t].reduce((a, ch) => a + ch.charCodeAt(0), 0) % combos.length];
  return h('span', { class: 'tile' + (big ? ' big' : ''), 'aria-hidden': 'true', style: `background:${c[0]};color:${c[1]};border-color:${c[2]}` }, t.slice(0, 2));
};
let toastTimer;
const toast = (msg, bad) => { const t = $('toast'); t.textContent = msg; t.className = 'show' + (bad ? ' bad' : ''); clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.className = ''; }, bad ? 7000 : 3500); };

// ---------------------------------------------------------------- api
const api = async (path, body) => {
  const r = await fetch('/api' + path, body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : undefined);
  const j = await r.json().catch(() => ({ error: 'bad response' }));
  if (!r.ok) throw new Error(j.error || 'request failed');
  return j;
};
let cfg = { btc: { hrp: 'bc' }, launches: {} };

// ---------------------------------------------------------------- wallet
const W = { addr: null, key: null, pub: null };
const launchAddr = (t) => B.segwitEncode(cfg.launches[t].hrp, 0, B.hash160(W.pub));
const btcAddr = () => B.segwitEncode(cfg.btc.hrp, 0, B.hash160(W.pub));
const paintWallet = () => { const b = $('wallet'); b.textContent = W.addr ? short(W.addr) : 'CONNECT UNISAT'; b.className = 'm wallet' + (W.addr ? ' on' : ''); };
async function connect(ask = true) {
  const u = window.unisat;
  if (!u) { if (ask) throw new Error('UniSat wallet not found in this browser'); return false; }
  const accts = ask ? await u.requestAccounts() : await u.getAccounts();
  if (!accts || !accts.length) return false;
  let k = localStorage.getItem('hf_key_' + accts[0]);
  if (!k) {
    if (!ask) return false;
    k = B.hex(B.keyFromSignature(await u.signMessage(B.KEY_MESSAGE)));
    localStorage.setItem('hf_key_' + accts[0], k);
  }
  W.addr = accts[0]; W.key = B.unhex(k); W.pub = B.pubkey(W.key);
  B.addressToScript(W.addr, cfg.btc); // throws if the wallet is on another network
  paintWallet();
  return true;
}
const needWallet = async () => { if (!W.key && !(await connect(true))) throw new Error('wallet not connected'); };

// ---------------------------------------------------------------- swaps
const swaps = () => JSON.parse(localStorage.getItem('hf_swaps') || '{}');
const saveSwap = (rec) => { const all = swaps(); all[rec.id] = rec; localStorage.setItem('hf_swaps', JSON.stringify(all)); };
const HTLC_VB = 180;
const chainOf = (rec, leg) => ((rec.side === 'buy') === (leg === 'init') ? 'btc' : rec.ticker);

async function startSwap(ticker, side, q, ui) {
  await needWallet();
  if (side === 'buy' && q.btc_amount > q.max_btc) throw new Error('above the maker\'s limit of ' + fmt(q.max_btc) + ' sats per order');
  const secret = B.randomBytes(32), hash = B.sha256(secret);
  const rec = { id: B.hex(hash).slice(0, 16), ticker, side, q, secret: B.hex(secret), state: 'created', created: Date.now() };
  const initChain = chainOf(rec, 'init');
  const t = await api(`/chain/${initChain}/time`);
  const c = { secretHash: hash, recipientPub: B.unhex(q.maker_pub), refundPub: W.pub, locktime: Math.max(q.min_init_locktime, t.mediantime + q.part_lock_seconds * 2) + 600 };
  const script = B.contractScript(c), spk = B.p2wsh(script);
  rec.contract = B.hex(script); rec.locktime = c.locktime;
  saveSwap(rec); // before any money moves: the secret and the refund path must survive a reload
  ui.step('sign');
  if (side === 'buy') {
    rec.init_txid = await window.unisat.sendBitcoin(B.segwitEncode(cfg.btc.hrp, 0, spk.slice(2)), q.btc_amount);
    saveSwap(rec);
    for (let i = 0; rec.init_vout == null; i++) {
      const n = await findOutput(api, 'btc', rec.init_txid, B.hex(spk));
      if (n != null) rec.init_vout = n; else if (i > 120) throw new Error('your payment has not reached this site\'s Bitcoin node yet; reopen this swap from Bags in a minute'); else await sleep(1000);
    }
  } else {
    const me = await api(`/coin/${ticker}/address/${launchAddr(ticker)}`);
    const pool = me.utxos.filter((u) => u.spendable).sort((a, b) => b.value - a.value), sel = [];
    let sum = 0, fee = 0;
    for (const u of pool) { sel.push(u); sum += u.value; fee = t.feerate * (90 + 68 * sel.length); if (sum >= q.amount + fee) break; }
    if (sum < q.amount + fee) throw new Error('not enough spendable coins (fresh coinbases need 100 blocks)');
    const outs = [{ value: q.amount, script: spk }];
    if (sum - q.amount - fee > 600) outs.push({ value: sum - q.amount - fee, script: B.p2wpkh(W.pub) });
    rec.init_txid = (await api(`/chain/${ticker}/tx`, { hex: B.txHex(B.signP2wpkh(W.key, sel, outs)) })).txid;
    rec.init_vout = 0;
  }
  rec.state = 'locked'; saveSwap(rec);
  ui.step('locked');
  const order = await api('/orders', { quote_id: q.quote_id, ticker, side, secret_hash: B.hex(hash), taker_pub: B.hex(W.pub), contract: rec.contract, txid: rec.init_txid, vout: rec.init_vout });
  rec.order_id = order.id; saveSwap(rec);
  return finishSwap(rec, ui);
}

// Drive a swap from "our side is locked" to done. Safe to call again after a reload.
async function finishSwap(rec, ui) {
  await needWallet();
  const secret = B.unhex(rec.secret), init = B.parseContract(B.unhex(rec.contract));
  const part = chainOf(rec, 'part'), want = rec.side === 'buy' ? rec.q.amount : rec.q.btc_amount;
  const needConfs = rec.side === 'buy' ? rec.q.fork_confs : Math.max(1, rec.q.btc_confs);
  ui.step('maker');
  for (;;) {
    const o = await api(`/orders/${rec.order_id}`);
    if (o.state === 'rejected') throw new Error('the maker rejected the order: ' + o.note);
    if (o.state === 'participated' || o.state === 'done') {
      const pc = B.parseContract(B.unhex(o.part_contract));
      if (!B.eq(pc.recipientPub, W.pub) || !B.eq(pc.secretHash, init.secretHash)) throw new Error('the maker\'s contract does not pay this wallet; refund after the timelock');
      const out = await api(`/chain/${part}/txout/${o.part_txid}/${o.part_vout}`);
      const now = await api(`/chain/${part}/time`);
      // Reveal the secret only while the maker cannot refund yet and our own lock outlives theirs.
      const safe = pc.locktime < init.locktime && now.mediantime + 600 < pc.locktime;
      if (out && out.script === B.hex(B.p2wsh(B.unhex(o.part_contract))) && out.value >= want && safe) {
        ui.note(`${out.confirmations} of ${needConfs} confirmations on the maker's lock`);
        if (out.confirmations >= needConfs) {
          ui.step('claim');
          const dest = part === 'btc' ? B.addressToScript(W.addr, cfg.btc) : B.p2wpkh(W.pub);
          const tx = B.redeemTx(pc, { txid: o.part_txid, vout: o.part_vout }, out.value, dest, HTLC_VB * now.feerate, W.key, secret);
          rec.redeem_txid = (await api(`/chain/${part}/tx`, { hex: B.txHex(tx) })).txid;
          rec.got = out.value - HTLC_VB * now.feerate; rec.state = 'done'; saveSwap(rec);
          ui.step('done');
          return rec;
        }
      } else if (out && !safe) ui.note('waiting: not safe to claim right now');
    } else ui.note(o.note || 'waiting for the maker');
    const t = await api(`/chain/${chainOf(rec, 'init')}/time`);
    if (t.mediantime > init.locktime) { rec.state = 'refundable'; saveSwap(rec); throw new Error('the swap timed out; refund it from Bags'); }
    await sleep(1500);
  }
}

async function refundSwap(rec) {
  await needWallet();
  const c = B.parseContract(B.unhex(rec.contract)), chain = chainOf(rec, 'init');
  const out = await api(`/chain/${chain}/txout/${rec.init_txid}/${rec.init_vout}`);
  if (!out) throw new Error('nothing to refund: the lock is already spent');
  const t = await api(`/chain/${chain}/time`);
  if (t.mediantime <= c.locktime) throw new Error('refund opens ' + new Date(c.locktime * 1000).toLocaleString());
  const dest = chain === 'btc' ? B.addressToScript(W.addr, cfg.btc) : B.p2wpkh(W.pub);
  const tx = B.refundTx(c, { txid: rec.init_txid, vout: rec.init_vout }, out.value, dest, 170 * t.feerate, W.key);
  rec.refund_txid = (await api(`/chain/${chain}/tx`, { hex: B.txHex(tx) })).txid;
  rec.state = 'refunded'; saveSwap(rec);
  return rec;
}

// The flow window: connect, sign, swap legs, done.
function flow(title, run) {
  const legs = [['sign', 'Lock your side'], ['locked', 'Order placed with the maker'], ['maker', 'Maker locks the other side'], ['claim', 'Claim'], ['done', 'Done']];
  const m = $('modal'), note = h('p', { class: 'm muted', style: 'min-height:20px;font-size:13px' });
  const list = h('ol', { class: 'legs' }, legs.map(([k, label]) => h('li', { 'data-k': k }, h('i'), label)));
  const box = h('div', { class: 'flow busy' }, h('span', { class: 'lab o' }, 'Atomic swap'), h('h2', { class: 'd h2' }, title), list, note);
  const close = () => { m.hidden = true; m.replaceChildren(); route(); };
  const ui = {
    step(k) { const i = legs.findIndex((x) => x[0] === k); [...list.children].forEach((li, n) => { li.className = n < i ? 'ok' : n === i ? 'now' : ''; }); note.textContent = ''; },
    note(t) { note.textContent = t; },
  };
  m.replaceChildren(box); m.hidden = false;
  ui.step('sign');
  run(ui).then((rec) => {
    box.className = 'flow done';
    box.replaceChildren(h('span', { class: 'lab', style: 'color:#0A0A0B' }, 'Swap complete'), h('h2', { class: 'd', style: 'font-size:clamp(64px,14vw,150px);line-height:.88' }, rec.side === 'buy' ? "You're in" : 'Sold'),
      h('div', { class: 'd', style: 'font-size:40px;line-height:1' }, rec.side === 'buy' ? `+${coins(rec.got)} $${rec.ticker}` : `+${fmt(rec.got)} sats`),
      h('p', { style: 'font-size:17px;font-weight:500' }, rec.side === 'buy' ? 'From now on every block on this curve is a draw for real BTC, weighted by your bag.' : 'The sats are on their way to your UniSat address.'),
      h('div', { class: 'row', style: 'gap:12px' }, h('a', { class: 'btn', style: 'background:#0A0A0B;color:#C7F23E;box-shadow:none', href: '#/bags', onclick: close }, 'See your bags'), h('button', { class: 'ghost', style: 'border-color:#0A0A0B;color:#0A0A0B;min-height:56px', type: 'button', onclick: close }, 'Close')));
  }).catch((e) => {
    box.className = 'flow';
    note.className = 'err'; note.textContent = e.message || String(e);
    box.append(h('p', { class: 'muted', style: 'font-size:13px' }, 'If your side was already locked it is safe: open Bags to resume the swap, or to refund it after the timelock.'), h('button', { class: 'ghost', type: 'button', onclick: close }, 'Close'));
  });
}

// ---------------------------------------------------------------- views
let timer = null, viewToken = 0;
const every = (ms, fn) => { const tok = viewToken; const tick = async () => { if (tok !== viewToken) return; try { await fn(); } catch (e) { /* keep polling */ } if (tok === viewToken) timer = setTimeout(tick, ms); }; tick(); };
const status = (c) => (c.graduated ? ['graduated', 'pill full'] : c.progress >= 0.75 ? ['graduating', 'pill l'] : c.progress < 0.1 ? ['new', 'pill w'] : ['on the curve', 'pill']);
const meter = (p, cls) => h('div', { class: 'meter ' + (cls || ''), role: 'img', 'aria-label': `Curve ${(p * 100).toFixed(1)} percent mined` }, h('i', { style: `width:${Math.min(100, p * 100)}%` }));
const paidHolders = (c) => btc((c.paid && c.paid.holder) || 0);

function board(view) {
  let filter = 'all', query = '', last = {};
  const grid = h('div', { class: 'grid' }), feed = h('div', { class: 'feed' }), spot = h('div', { style: 'flex:4 1 340px;min-width:0' });
  const filters = [['all', 'All'], ['curve', 'On the curve'], ['new', 'New'], ['close', 'Graduating'], ['grad', 'Graduated']];
  const fbar = h('div', { class: 'row', style: 'gap:8px;align-items:center' });
  const paintFilters = () => fbar.replaceChildren(...filters.map(([k, label]) => h('button', { class: 'ghost' + (filter === k ? ' on' : ''), type: 'button', 'aria-pressed': String(filter === k), onclick: () => { filter = k; paintFilters(); paint(); } }, label)),
    h('label', { class: 'field', style: 'min-height:44px' }, h('span', { class: 'lab' }, 'Search'), h('input', { type: 'search', value: query, style: 'min-height:40px;font-size:14px;width:140px', oninput: (e) => { query = e.target.value.toUpperCase().replace('$', ''); paint(); } })));
  let data = [];
  const paint = () => {
    const match = (c) => (filter === 'all' || (filter === 'curve' && !c.graduated) || (filter === 'new' && !c.graduated && c.progress < 0.1) || (filter === 'close' && !c.graduated && c.progress >= 0.75) || (filter === 'grad' && c.graduated)) && (!query || c.ticker.includes(query) || c.name.toUpperCase().includes(query));
    const live = data.filter((c) => c.height != null);
    const cards = live.filter(match).map((c) => {
      const [st, cls] = status(c), hot = last[c.ticker] != null && last[c.ticker] !== c.height;
      return h('a', { class: 'card' + (hot ? ' hot' : ''), href: `#/c/${c.ticker}` },
        h('div', { style: 'display:flex;align-items:center;gap:12px' }, tile(c.ticker, false, c.image || null), h('div', { style: 'flex:1;min-width:0' }, h('div', { style: 'font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis' }, c.name), h('div', { class: 'm muted', style: 'font-size:12px' }, `$${c.ticker} · ${short(c.creator)} · ${ago(c.genesis_time)}`)), h('span', { class: cls }, st)),
        h('div', { class: 'col', style: 'gap:6px' }, h('div', { class: 'between' }, h('span', { class: 'd ' + (c.graduated || c.progress >= 0.75 ? 'l' : 'o'), style: 'font-size:30px;line-height:1' }, (c.progress * 100).toFixed(1) + '%'), h('span', { class: 'm muted', style: 'font-size:12px' }, c.graduated ? 'merge-mined with Bitcoin' : 'of the curve mined')), meter(c.progress, c.graduated || c.progress >= 0.75 ? 'l' : '')),
        h('div', { style: 'display:flex;justify-content:space-between;gap:10px' }, h('span', { class: 'stat' }, 'sats owed per coin', h('b', null, price(c.sats_leg_per_coin))), h('span', { class: 'stat' }, 'paid to holders', h('b', { class: 'l' }, paidHolders(c) + ' BTC')), h('span', { class: 'stat', style: 'text-align:right' }, 'last block', h('b', null, ago(c.last_block_time)))));
    });
    grid.replaceChildren(...(cards.length ? cards : [h('div', { class: 'panel pad col' }, h('span', { class: 'd', style: 'font-size:30px' }, 'Nothing here yet'), h('a', { href: '#/launch' }, 'Launch the first one'))]));
    live.forEach((c) => { last[c.ticker] = c.height; });
    const top = live.filter((c) => !c.graduated).sort((a, b) => b.progress - a.progress)[0];
    spot.replaceChildren(top ? h('a', { class: 'card', style: 'border-color:#C7F23E;padding:22px', href: `#/c/${top.ticker}` }, h('div', { class: 'between lab l' }, 'Closest to graduation', h('span', null, h('span', { class: 'dot' }), ' ', ago(top.last_block_time))),
      h('div', { style: 'display:flex;align-items:center;gap:14px' }, tile(top.ticker, false, top.image || null), h('div', null, h('div', { style: 'font-size:20px;font-weight:700' }, top.name), h('div', { class: 'm muted', style: 'font-size:13px' }, `$${top.ticker} · by ${short(top.creator)}`))),
      h('div', { class: 'd l', style: 'font-size:clamp(64px,9vw,104px);line-height:.9' }, (top.progress * 100).toFixed(1) + '%'), meter(top.progress, 'l tall'),
      h('p', { class: 'soft' }, `${coins(top.curve_tokens - top.curve_supply)} coins left on the curve. After that Bitcoin's own miners can secure it.`), h('span', { class: 'btn lime', style: 'box-shadow:none' }, 'Ape in')) : '');
    const pays = live.flatMap((c) => (c.recent || []).map((p) => ({ ...p, t: c.ticker }))).sort((a, b) => b.time - a.time).slice(0, 6);
    feed.replaceChildren(...(pays.length ? pays.map((p) => h('div', null, h('div', { class: 'm between' }, h('b', { class: 'l', style: 'font-size:16px' }, `+${fmt(p.pay)} sats`), h('span', { class: 'muted', style: 'font-size:12px' }, ago(p.time))), h('span', { class: 'm muted', style: 'font-size:12px' }, `${short(p.pay_to)} holding `, h('span', { style: 'color:#F2F0EC' }, '$' + p.t)))) : [h('div', { class: 'muted' }, 'No payouts yet.')]));
  };
  paintFilters();
  view.replaceChildren(
    h('section', { class: 'row', style: 'padding:48px 0 56px' },
      h('div', { class: 'col', style: 'flex:5 1 420px;gap:20px' }, h('p', { class: 'lab o' }, 'Proof-of-work memecoins, paid in BTC'), h('h1', { class: 'd h1' }, 'Every meme', h('br'), 'gets its own', h('br'), h('span', { class: 'o' }, 'Bitcoin.')),
        h('p', { class: 'soft', style: 'max-width:500px;font-size:18px' }, 'Launch a coin and a new proof-of-work chain starts at block zero. Buy with sats or with hash. Hold it, and every block can pay you real BTC.'),
        h('div', { class: 'row', style: 'gap:14px;align-items:center' }, h('a', { class: 'btn', href: '#/launch' }, 'Launch a coin'), h('a', { class: 'ghost', style: 'min-height:56px', href: '#how' }, 'How it works')),
        h('p', { class: 'm muted', style: 'font-size:12px' }, 'No premine. No bridge. No custodian. No floor.')),
      spot,
      h('div', { class: 'panel', style: 'flex:3 1 280px;min-width:0' }, h('div', { class: 'between lab', style: 'padding:14px 16px;border-bottom:1px solid #2C2C31' }, 'BTC paid to holders', h('span', { class: 'l' }, h('span', { class: 'dot' }), ' live')), feed, h('p', { class: 'muted', style: 'padding:12px 16px;font-size:13px' }, 'Each block on a curve owes BTC. One holder is drawn by bag size and paid on Bitcoin.'))),
    h('section', { class: 'col', style: 'gap:20px;padding-bottom:64px' }, h('div', { class: 'between', style: 'align-items:center' }, h('h2', { class: 'd h2' }, 'The board'), fbar), grid),
    h('section', { id: 'how', class: 'col', style: 'gap:20px' }, h('h2', { class: 'd h2' }, 'How it works'), h('div', { class: 'grid', style: 'grid-template-columns:repeat(auto-fit,minmax(min(260px,100%),1fr))' },
      [['1', 'Launch', O, 'Name, ticker, target. A new proof-of-work chain starts at block zero. Nobody holds a coin until work is done.'], ['2', 'Buy is mint', O, 'Swap sats with a miner or point your own hash. Coins are minted along a curve: the more work done, the higher the price.'], ['3', 'Hold is earn', L, 'Every curve block owes BTC. 80% goes to a holder drawn by bag size, 10% to the creator, 10% to hashfun. No staking, no opt in.'], ['4', 'Graduate', L, 'Curve sold out: the chain opens to merge-mining with Bitcoin. Trade by atomic swap, wallet to wallet.']]
        .map(([n, t, c, body]) => h('div', { class: 'panel pad col', style: 'gap:10px' }, h('span', { class: 'd', style: `font-size:44px;line-height:1;color:${c}` }, n), h('span', { class: 'd', style: 'font-size:24px' }, t), h('p', { class: 'soft' }, body))))));
  every(1500, async () => { data = await api('/board'); paint(); });
}

function coin(view, ticker) {
  let d = null, orders = [], tab = 'blocks', side = 'buy', spend = 50000, sell = 0, q = null, qerr = '', me = null, seen = 0, wonAt = 0;
  const head = h('section'), blurb = h('div'), stats = h('div'), chart = h('div', { class: 'panel chart' }), prog = h('div', { class: 'panel pad col', style: 'gap:10px' }), tabsBox = h('div', { class: 'panel' }), trade = h('div', { class: 'trade' }), bag = h('div');
  const quote = async () => {
    q = null; qerr = '';
    paintQuote(); // the quote on screen is gone the moment a new one is asked for
    if (side === 'sell' && !(sell > 0)) { qerr = 'Enter how many coins to sell.'; return paintQuote(); }
    try { q = await api(side === 'sell' ? `/quote?ticker=${ticker}&side=sell&amount=${Math.round(sell * COIN)}` : `/quote?ticker=${ticker}&side=buy&sats=${spend}`); } catch (e) { qerr = e.message; }
    paintQuote();
  };
  let qt;
  const later = () => { q = null; qerr = ''; paintQuote(); clearTimeout(qt); qt = setTimeout(quote, 350); };
  const out = h('div', { class: 'col', style: 'gap:10px' });
  const paintQuote = () => {
    if (side === 'mine') return;
    const shown = q, sd = side; // a click trades exactly the quote that was on screen
    const go = () => shown && flow(`${sd === 'buy' ? 'Buy' : 'Sell'} $${ticker}`, (ui) => startSwap(ticker, sd, shown, ui));
    const leg = d ? d.sats_leg_per_coin : 0, share = q && q.price ? Math.min(1, leg / q.price) : 0;
    out.replaceChildren(
      h('span', { class: 'lab' }, 'You get about'),
      h('div', { style: 'display:flex;align-items:baseline;gap:10px' }, h('span', { class: 'd ' + (side === 'buy' ? 'o' : ''), id: 'q-get', style: 'font-size:52px;line-height:1' }, q ? (side === 'buy' ? coins(q.amount) : fmt(q.btc_amount)) : '…'), h('span', { class: 'm' }, side === 'buy' ? '$' + ticker : 'sats')),
      q ? h('div', null, h('div', { class: 'kv' }, h('span', null, 'Price'), h('span', null, price(q.price) + ' sats per coin')), h('div', { class: 'kv' }, h('span', null, 'Speed'), side === 'buy' ? h('b', { class: q.instant ? 'l' : '' }, q.instant ? 'instant' : `${q.btc_confs} Bitcoin confirmation${q.btc_confs === 1 ? '' : 's'}`) : h('span', null, 'after 1 Bitcoin confirmation')),
        side === 'buy' ? h('div', { class: 'kv' }, h('span', null, 'Where the sats go'), h('span', { style: 'text-align:right' }, `${Math.round((1 - share) * 100)}% hash, ${Math.round(share * 80)}% holders, ${Math.round(share * 10)}% creator, ${Math.round(share * 10)}% hashfun`)) : null) : h('p', { class: qerr ? 'err' : 'muted', style: 'font-size:13px' }, qerr || 'asking the maker'),
      h('button', { class: 'btn wide' + (side === 'sell' ? ' white' : ''), id: 'go', type: 'button', disabled: !q || !(q.amount > 0), onclick: go }, side === 'buy' ? 'Buy with UniSat' : 'Sell to the maker'),
      h('p', { class: 'muted', style: 'font-size:13px' }, side === 'buy' ? 'Atomic swap, wallet to wallet. The coins land in your wallet, or your sats come back after the timelock.' : 'There is no reserve and no floor: you sell to a bid, by atomic swap. Coins you sell stop earning.'));
  };
  const paintTrade = () => {
    const sides = h('div', { class: 'sides' }, ['buy', 'sell', 'mine'].map((k) => h('button', { type: 'button', class: side === k ? 'on' : '', 'aria-pressed': String(side === k), onclick: () => { side = k; paintTrade(); if (k !== 'mine') quote(); } }, k)));
    let body;
    if (side === 'mine') {
      const desc = d ? 'data:application/json,' + encodeURIComponent(JSON.stringify(d.descriptor, null, 2)) : '#';
      body = h('div', { class: 'pad col', style: 'gap:14px' }, h('p', { class: 'soft' }, 'The cheapest way in: no maker in between. Point SHA-256 hash at this coin and blocks pay you directly.'),
        h('a', { class: 'ghost', href: desc, download: `${ticker.toLowerCase()}.json` }, 'Download the descriptor'),
        h('pre', { class: 'code' }, `npm i -g hashfun\nhashfun node add ${ticker.toLowerCase()}.json\nhashfun node up ${ticker}\nhashfun mine ${ticker} \\\n  --payout ${W.pub ? launchAddr(ticker) : '[YOUR ' + ticker + ' ADDRESS]'} \\\n  --btc-rpc [YOUR BITCOIN NODE]`),
        h('p', { class: 'muted', style: 'font-size:13px' }, 'Each block you mine owes BTC to the drawn holder. The miner pays it from its own Bitcoin wallet, automatically, before the coins unlock.'));
    } else if (!cfg.maker) {
      body = h('div', { class: 'pad col' }, h('p', { class: 'soft' }, 'No instant maker on this site right now. Trade it peer to peer, or mine it.'), h('a', { class: 'btn wide', href: `#/swap/btc/${ticker}` }, 'Open the book'));
    } else {
      const input = side === 'buy' ? h('input', { class: 'big', id: 'amt', inputmode: 'numeric', value: fmt(spend), oninput: (e) => { spend = Math.min(1e9, parseInt(e.target.value.replace(/\D/g, '') || '0', 10)); later(); } })
        : h('input', { class: 'big', id: 'amt', inputmode: 'decimal', value: sell || '', placeholder: '0', oninput: (e) => { sell = Math.max(0, parseFloat(e.target.value) || 0); later(); } });
      body = h('div', { class: 'pad col' }, h('div', { class: 'col', style: 'gap:8px' }, h('label', { class: 'lab', for: 'amt' }, side === 'buy' ? 'You pay' : 'You sell'), h('div', { class: 'field' }, input, h('span', { class: 'm muted' }, side === 'buy' ? 'sats' : '$' + ticker)),
        side === 'buy' ? h('div', { style: 'display:grid;grid-template-columns:repeat(4,1fr);gap:8px' }, [10000, 50000, 100000, 500000].map((v) => h('button', { class: 'ghost' + (spend === v ? ' pick' : ''), type: 'button', onclick: () => { spend = v; paintTrade(); quote(); } }, v / 1000 + 'k')))
          : h('span', { class: 'm muted', style: 'font-size:12px' }, me ? `Your bag: ${coins(me.balance)}` : 'Connect to see your bag')), out);
    }
    trade.replaceChildren(sides, body);
    paintQuote();
  };
  const paintBag = () => {
    if (!W.pub) return bag.replaceChildren(h('div', { class: 'bag pad col' }, h('span', { class: 'lab' }, 'Your bag'), h('p', { class: 'soft' }, 'Connect to see your bag and your odds.'), h('button', { class: 'ghost', type: 'button', onclick: () => connect(true).then(route).catch((e) => toast(e.message, true)) }, 'Connect UniSat')));
    const bal = me ? me.balance : 0, odds = me && me.earning_supply ? (bal / me.earning_supply) * 0.8 : 0, won = Date.now() - wonAt < 6000;
    bag.replaceChildren(h('div', { class: 'bag pad col' + (won ? ' won' : '') }, h('div', { class: 'between lab' }, 'Your bag', h('span', null, short(launchAddr(ticker)))),
      won ? h('div', { class: 'd', style: 'font-size:48px;line-height:.95' }, 'You won') : h('div', null, h('div', { class: 'm muted', style: 'font-size:12px' }, d && d.graduated ? 'Payouts ended at graduation' : 'Your odds, every block'), h('div', { class: 'd l', id: 'odds', style: 'font-size:48px;line-height:.95' }, odds > 0 && !(d && d.graduated) ? '1 in ' + fmt(Math.max(1, Math.round(1 / odds))) : 'none yet')),
      h('div', { class: 'stat' }, 'holding', h('b', { id: 'bal' }, coins(bal) + ' $' + ticker)), h('span', { class: 'muted', style: 'font-size:13px' }, 'Payouts go straight to your key on Bitcoin. Nothing to claim, nothing to stake.')));
  };
  const paint = () => {
    const [st, cls] = status(d);
    head.replaceChildren(h('div', { class: 'between', style: 'align-items:center;padding-top:28px' }, h('div', { style: 'display:flex;align-items:center;gap:16px;min-width:0' }, tile(ticker, true, d.image || null), h('div', { class: 'col', style: 'gap:6px' }, h('h1', { class: 'd', style: 'font-size:clamp(36px,5vw,54px);line-height:.95' }, d.name), h('div', { class: 'm muted row', style: 'gap:6px 14px;font-size:13px' }, h('b', { style: 'color:#F2F0EC' }, '$' + ticker), [`by ${short(d.creator)}`, `launched ${ago(d.genesis_time)} ago`, `id ${d.id.slice(0, 6)}…${d.id.slice(-4)}`, `block ${fmt(d.height)}`, hashrate(d.hashrate)].map((x) => h('span', null, x))))), h('span', { class: cls, style: 'padding:8px 12px;font-size:12px' }, st)));
    const links = Object.entries(d.links || {}).filter(([, u]) => /^https:\/\//.test(u));
    blurb.replaceChildren(...(d.description || links.length ? [h('div', { class: 'col', style: 'gap:10px;padding-top:16px;max-width:820px' }, d.description ? h('p', { class: 'soft', id: 'blurb', style: 'white-space:pre-line;overflow-wrap:anywhere' }, d.description) : null,
      links.length ? h('div', { class: 'row', style: 'gap:8px' }, links.map(([k, u]) => h('a', { class: 'ghost', href: u, target: '_blank', rel: 'noopener noreferrer nofollow' }, k === 'x' ? 'X' : k))) : null)] : []));
    stats.replaceChildren(h('div', { class: 'between', style: 'align-items:flex-end' }, h('div', { style: 'display:flex;align-items:baseline;gap:12px' }, h('span', { class: 'd o', id: 'price', style: 'font-size:clamp(56px,9vw,96px);line-height:.9' }, price(q && q.price && side !== 'sell' ? q.price : d.sats_leg_per_coin)), h('span', { class: 'm muted' }, q && q.price && side !== 'sell' ? 'sats per coin' : 'sats owed per coin mined')),
      h('div', { class: 'row', style: 'gap:10px 28px' }, h('span', { class: 'stat' }, 'paid to holders', h('b', { class: 'l', style: 'font-size:16px' }, paidHolders(d) + ' BTC')), h('span', { class: 'stat' }, 'still to be won', h('b', { class: 'l', style: 'font-size:16px' }, btc(Math.max(0, d.sats_total * (d.graduated ? 0 : 1) - (d.graduated ? 0 : d.paid.holder + d.paid.creator + d.paid.dev))) + ' BTC')), h('span', { class: 'stat' }, 'holders', h('b', { style: 'font-size:16px' }, fmt(d.holders))))));
    const ser = d.series, vals = ser.map((p) => p[1]), hi = Math.max(...vals, 0), lo = Math.min(...vals, hi), pad = Math.max((hi - lo) * 0.12, hi * 0.002) || 1;
    const top = hi + pad, bot = Math.max(0, lo - pad), x0 = ser.length ? ser[0][0] : 0, x1 = ser.length ? ser[ser.length - 1][0] : 1;
    const yOf = (p) => 280 - ((p - bot) / (top - bot)) * 260;
    const pts = ser.map(([hgt, p]) => `${(10 + ((hgt - x0) / Math.max(1, x1 - x0)) * 860).toFixed(1)},${yOf(p).toFixed(1)}`).join(' ');
    const gOn = d.sats_leg_at_graduation <= top, gy = yOf(d.sats_leg_at_graduation).toFixed(1);
    chart.replaceChildren(h('div', { class: 'lab l', style: 'padding:10px 12px;border-bottom:1px solid #2C2C31' }, `Sats owed per coin: ${price(d.sats_leg_per_coin)} now, ${price(d.sats_leg_at_graduation)} at graduation`), h('div', { style: 'position:relative' }, s('svg', { viewBox: '0 0 900 300', preserveAspectRatio: 'none', role: 'img', 'aria-label': 'Sats owed per coin since launch, rising with the work done' },
      [20, 85, 150, 215, 280].map((y) => s('line', { x1: 0, x2: 900, y1: y, y2: y, stroke: '#1F1F23', 'vector-effect': 'non-scaling-stroke' })),
      gOn ? s('line', { x1: 0, x2: 900, y1: gy, y2: gy, stroke: L, 'stroke-width': 2, 'stroke-dasharray': '8 8', 'vector-effect': 'non-scaling-stroke' }) : null,
      pts ? s('polygon', { points: `${pts} 870,280 10,280`, fill: O, opacity: 0.14 }) : null, pts ? s('polyline', { points: pts, fill: 'none', stroke: O, 'stroke-width': 3, 'stroke-linejoin': 'round', 'vector-effect': 'non-scaling-stroke' }) : null),
    h('span', { class: 'm muted', style: 'position:absolute;left:10px;top:12px;font-size:11px' }, price(top)), h('span', { class: 'm muted', style: 'position:absolute;left:10px;top:264px;font-size:11px' }, price(bot))),
    h('div', { class: 'm muted between', style: 'padding:8px 12px;border-top:1px solid #2C2C31;font-size:11px' }, h('span', null, 'block ' + fmt(x0)), h('span', null, 'price only moves when work is done'), h('span', null, 'block ' + fmt(x1))));
    prog.replaceChildren(h('div', { class: 'between' }, h('span', { style: 'display:flex;align-items:baseline;gap:10px' }, h('span', { class: 'd l', style: 'font-size:40px;line-height:1' }, (d.progress * 100).toFixed(1) + '%'), h('span', { class: 'lab' }, 'of the curve mined')), h('span', { class: 'm', style: 'font-size:13px' }, d.graduated ? `graduated at block ${fmt(d.graduation_height)}` : `${coins(d.curve_tokens - d.curve_supply)} coins left`)), meter(d.progress, 'l tall'),
      h('p', { class: 'muted', style: 'font-size:13px' }, 'When the curve is fully mined the chain opens to merge-mining: Bitcoin miners can secure it at no extra cost, and the BTC payouts to holders end.'));
    const mine = W.pub ? launchAddr(ticker) : null, myBtc = W.pub ? btcAddr() : null;
    let content;
    if (tab === 'blocks') {
      const cols = 'grid-template-columns:90px 56px 130px minmax(0,1fr) minmax(0,1.6fr)';
      content = h('div', { class: 'table' }, h('div', null, h('div', { class: 'tr head', style: cols }, h('span', null, 'Block'), h('span', null, 'Age'), h('span', null, 'Miner'), h('span', null, 'Minted'), h('span', null, 'BTC paid to')),
        d.blocks.map((b) => { const you = b.pay_to && b.pay_to === myBtc && b.pay > 0; return h('div', { class: 'tr' + (you ? ' you' : '') + (b.height > seen && seen ? ' new' : ''), style: cols }, h('b', null, fmt(b.height)), h('span', { class: 'muted' }, ago(b.time)), h('span', { class: 'muted' }, b.miner === mine ? 'you' : short(b.miner)), h('span', { class: 'o' }, `+${coins(b.minted)}`),
          h('b', { class: b.settled && b.payee === 'holder' ? 'l' : b.settled ? '' : 'muted', style: 'white-space:nowrap;overflow:hidden;text-overflow:ellipsis' }, !b.curve || !b.owed ? (b.auxpow ? 'merge-mined' : 'nothing owed') : !b.draw_known ? `draw in ${Math.max(1, b.height + 6 - d.height)} blocks` : !b.pay ? 'no payout this block' : `${b.settled ? '+' : 'owes '}${fmt(b.pay)} sats · ${you ? 'YOU' : b.payee === 'holder' ? 'holder ' + short(b.pay_to) : b.payee === 'dev' ? 'hashfun' : 'creator'}`)); })));
    } else if (tab === 'holders') {
      const cols = 'grid-template-columns:40px minmax(0,1.4fr) minmax(0,1fr) 90px 130px', max = d.top_holders.length ? d.top_holders[0].value : 1;
      content = h('div', { class: 'table' }, h('div', null, h('div', { class: 'tr head', style: cols }, h('span', null, '#'), h('span', null, 'Holder'), h('span', null, 'Bag'), h('span', null, 'Share'), h('span', null, 'Odds per block')),
        d.top_holders.map((x, i) => h('div', { class: 'tr' + (x.address === mine ? ' you' : ''), style: cols }, h('span', { class: 'muted' }, i + 1), h('b', null, x.address === mine ? 'you' : short(x.address) + (x.address === d.creator ? ' (creator)' : '')), h('span', { style: 'display:flex;align-items:center;gap:10px' }, h('i', { style: `display:block;height:10px;width:${Math.max(4, Math.round((x.value / max) * 120))}px;background:${O}` }), coins(x.value)), h('span', null, ((x.value / d.earning_supply) * 100).toFixed(2) + '%'), h('span', { class: 'l' }, d.graduated ? 'ended' : '1 in ' + fmt(Math.max(1, Math.round(d.earning_supply / x.value / 0.8))))))));
    } else if (tab === 'book') {
      content = bookTab(ticker, orders);
    } else {
      const de = d.descriptor;
      content = h('div', { class: 'pad', style: 'display:grid;grid-template-columns:repeat(auto-fit,minmax(min(280px,100%),1fr));gap:0 32px' }, [['Total supply', coins(d.total_tokens)], ['On the curve', `${coins(d.curve_tokens)} (${((d.curve_tokens / d.total_tokens) * 100).toFixed(2)}%)`], ['Premine', '0'], ['Creator fee', `${d.creator_fee_bps / 100}% of minted coins`], ['BTC owed over the curve', btc(d.sats_total) + ' BTC'], ['BTC split', '80 holders / 10 creator / 10 hashfun'], ['Block time', d.target_spacing + ' s'], ['Floor or reserve', 'none'], ['Creator BTC address', short(d.creator_btc)], ['Bitcoin anchor height', fmt(de.btc_anchor_height)], ['Launch id', d.id.slice(0, 10) + '…' + d.id.slice(-6)], ['Picture and description', d.meta ? `sha256 ${d.meta.slice(0, 10)}…, fixed by the genesis block` : 'none']].map(([k, v]) => h('div', { class: 'kv' }, h('span', null, k), h('span', null, v))));
    }
    tabsBox.replaceChildren(h('div', { class: 'tabs' }, ['blocks', 'holders', 'book', 'about'].map((k) => h('button', { type: 'button', class: tab === k ? 'on' : '', id: 'tab-' + k, 'aria-pressed': String(tab === k), onclick: () => { tab = k; paint(); } }, k))), content);
    if (myBtc && seen && d.blocks.some((b) => b.pay_to === myBtc && b.settled && b.pay > 0 && b.height > seen - 40 && !sessionStorage.getItem('won' + ticker + b.height))) { d.blocks.filter((b) => b.pay_to === myBtc && b.settled && b.pay > 0).forEach((b) => sessionStorage.setItem('won' + ticker + b.height, '1')); wonAt = Date.now(); }
    seen = d.height;
    paintBag();
  };
  view.replaceChildren(h('p', { class: 'muted', style: 'padding-top:28px' }, 'Loading $' + ticker));
  let built = false;
  every(1000, async () => {
    d = await api('/coin/' + ticker);
    if (d.height == null) { view.replaceChildren(h('p', { class: 'err', style: 'padding-top:28px' }, d.error || 'This launch is not running here.')); return; }
    if (W.pub) me = await api(`/coin/${ticker}/address/${launchAddr(ticker)}`).catch(() => me);
    orders = await book.list().catch(() => orders);
    if (!built) {
      built = true;
      view.replaceChildren(head, blurb, h('div', { class: 'row', style: 'align-items:flex-start;margin-top:24px' }, h('div', { class: 'col', style: 'flex:999 1 560px;gap:20px' }, stats, chart, prog, tabsBox), h('aside', { class: 'col side', style: 'flex:1 1 380px;gap:20px' }, trade, bag)));
      paintTrade();
      if (cfg.maker) quote();
    }
    paint();
  });
}

function launchForm(view) {
  // The CPU preset is for trying things out (a laptop can mine it; so can anyone else, cheaply).
  const grads = [['CPU test', 'minutes of one core', 5e7, 0x1f01ffff], ['Degen', '1 rig-day', 1.728e19], ['Standard', '100 rig-days', 1.728e21], ['Monster', '10,000 rig-days', 1.728e23]];
  const potsFor = (g) => (grads[g][3] ? [0.001, 0.01, 0.1, 1] : [0.1, 0.5, 1, 5]);
  const st = { name: '', ticker: '', grad: cfg.btc.chain === 'regtest' ? 0 : 1, pot: 0, fee: 1, busy: false, err: '', pic: null, desc: '', x: '', telegram: '', website: '' };
  const pickPicture = async (file) => {
    if (!file) return;
    try { const p = await squarePicture(file); if (st.pic) URL.revokeObjectURL(st.pic.url); st.pic = { ...p, url: URL.createObjectURL(new Blob([p.image], { type: p.image_type })) }; st.err = ''; } catch (e) { st.err = e.message; }
    paint(); paintPrev();
  };
  st.pot = potsFor(st.grad)[1];
  const prev = h('div'), form = h('div', { class: 'col', style: 'flex:999 1 520px;gap:28px' });
  const paintPrev = () => prev.replaceChildren(h('span', { class: 'lab' }, 'On the board'), h('div', { class: 'card', style: 'border-color:#FF9A1F;margin-top:8px' }, h('div', { style: 'display:flex;align-items:center;gap:12px' }, tile(st.ticker || '??', false, st.pic ? st.pic.url : null), h('div', { style: 'flex:1;min-width:0' }, h('div', { style: 'font-weight:700' }, st.name || 'Your coin'), h('div', { class: 'm muted', style: 'font-size:12px' }, `$${st.ticker || 'TICKER'} · ${W.addr ? short(W.addr) : 'you'} · now`)), h('span', { class: 'pill w' }, 'new')), h('span', { class: 'd o', style: 'font-size:30px;line-height:1' }, '0.0%'), meter(0)),
    h('div', { class: 'panel', style: 'margin-top:20px;padding:4px 16px' }, [['Total supply', '15,000,000'], ['On the curve', '11,087,138'], ['Premine', '0'], ['Price, first coin to graduation', '14.7x'], ['To holders, in BTC', (st.pot * 0.8).toFixed(3) + ' BTC'], ['To you, in BTC', (st.pot * 0.1).toFixed(3) + ' BTC'], ['To you, in coins', fmt(Math.round(110871.38 * st.fee)) + ' ' + (st.ticker || 'coins')]].map(([k, v]) => h('div', { class: 'kv' }, h('span', null, k), h('b', null, v)))),
    h('p', { class: 'muted', style: 'margin-top:16px;font-size:13px' }, 'No floor and no reserve: the BTC goes to holders as the curve is mined, not into a pool. After graduation the chain is merge-mined with Bitcoin and trades by atomic swap.'));
  const submit = async () => {
    st.err = '';
    try {
      if (!/^[A-Z0-9]{2,10}$/.test(st.ticker)) throw new Error('Ticker: 2 to 10 letters or digits.');
      if (!st.name.trim()) throw new Error('Give it a name.');
      await needWallet();
      st.busy = true; paint();
      const g = grads[st.grad];
      const meta = { description: st.desc.trim(), image_type: st.pic ? st.pic.image_type : '', image: st.pic ? st.pic.image : new Uint8Array(0), x: st.x.trim(), telegram: st.telegram.trim(), website: st.website.trim() };
      for (const k of ['x', 'telegram', 'website']) if (meta[k] && !/^https:\/\/[^\s"'<>]+$/.test(meta[k])) throw new Error(`The ${k === 'x' ? 'X' : k} link has to start with https://`);
      const hasMeta = Boolean(meta.description || st.pic || meta.x || meta.telegram || meta.website);
      const metadata = Object.fromEntries(Object.entries({ ...meta, image: st.pic ? B.b64(st.pic.image) : '' }).filter(([, v]) => v));
      const r = await api('/launch', { name: st.name.trim(), ticker: st.ticker, graduation_hashes: g[2], sats_total: Math.round(st.pot * COIN), creator_fee_bps: Math.round(st.fee * 100), creator_script: B.hex(B.p2wpkh(W.pub)), creator_btc_address: W.addr, ...(g[3] ? { pow_limit_bits: g[3] } : {}), ...(hasMeta ? { metadata } : {}) });
      // The launch id must commit to exactly the picture and words given here, nothing swapped in.
      if (hasMeta && r.meta !== B.hex(B.metaHash(meta))) throw new Error('This site did not commit the launch to the picture and text you gave it. Do not promote this chain.');
      for (let i = 0; i < 60 && !cfg.launches[r.ticker]; i++) { await sleep(500); cfg = await api('/config').catch(() => cfg); }
      location.hash = '#/c/' + r.ticker;
    } catch (e) { st.busy = false; st.err = e.message; paint(); }
  };
  const paint = () => {
    form.replaceChildren(
      h('div', { class: 'col' }, h('span', { class: 'd', style: 'font-size:26px' }, h('span', { class: 'o' }, '1 '), 'The meme'), h('div', { class: 'row', style: 'gap:14px' },
        h('div', { class: 'col', style: 'flex:2 1 260px;gap:6px' }, h('label', { class: 'lab', for: 'name' }, 'Name'), h('div', { class: 'field' }, h('input', { id: 'name', maxlength: 64, value: st.name, oninput: (e) => { st.name = e.target.value; paintPrev(); } }))),
        h('div', { class: 'col', style: 'flex:1 1 160px;gap:6px' }, h('label', { class: 'lab', for: 'ticker' }, 'Ticker'), h('div', { class: 'field' }, h('input', { id: 'ticker', class: 'm', maxlength: 10, value: st.ticker, oninput: (e) => { st.ticker = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, ''); e.target.value = st.ticker; $('launch-go').textContent = `Launch $${st.ticker || 'TICKER'}`; paintPrev(); } })))),
        h('div', { class: 'row', style: 'gap:14px;align-items:stretch' },
          h('label', { class: 'drop' + (st.pic ? ' has' : ''), for: 'pic', ondragover: (e) => e.preventDefault(), ondrop: (e) => { e.preventDefault(); pickPicture(e.dataTransfer.files[0]); } },
            st.pic ? h('img', { src: st.pic.url, alt: '' }) : h('span', { class: 'd', style: 'font-size:22px' }, 'Drop the meme'), h('span', { class: 'm muted', style: 'font-size:11px' }, st.pic ? `${(st.pic.image.length / 1024).toFixed(1)} KB, fixed forever` : 'PNG, JPEG, GIF or WebP'),
            h('input', { id: 'pic', type: 'file', accept: 'image/png,image/jpeg,image/gif,image/webp', onchange: (e) => pickPicture(e.target.files[0]) })),
          h('div', { class: 'col', style: 'flex:1 1 300px;gap:10px' }, h('label', { class: 'lab', for: 'desc' }, 'The pitch (optional)'), h('div', { class: 'field', style: 'align-items:stretch' }, h('textarea', { id: 'desc', maxlength: 280, rows: 3, placeholder: 'One or two lines.', oninput: (e) => { st.desc = e.target.value; } }, st.desc)),
            h('div', { style: 'display:grid;grid-template-columns:repeat(auto-fit,minmax(min(150px,100%),1fr));gap:8px' }, [['x', 'X link'], ['telegram', 'Telegram link'], ['website', 'Website']].map(([k, label]) => h('div', { class: 'field', style: 'min-height:44px' }, h('input', { 'aria-label': label, placeholder: label, value: st[k], style: 'min-height:40px;font-size:13px', oninput: (e) => { st[k] = e.target.value; } })))))),
        h('span', { class: 'muted', style: 'font-size:13px' }, 'The picture, pitch and links are hashed into the launch id, so the genesis block pins them. Nobody can change them later, you included.')),
      h('div', { class: 'col' }, h('span', { class: 'd', style: 'font-size:26px' }, h('span', { class: 'o' }, '2 '), 'The curve'), h('span', { class: 'lab' }, 'Hash it takes to graduate'),
        h('div', { style: 'display:grid;grid-template-columns:repeat(auto-fit,minmax(min(150px,100%),1fr));gap:10px' }, grads.map((g, i) => h('button', { type: 'button', class: 'ghost' + (st.grad === i ? ' pick' : ''), style: 'flex-direction:column;align-items:flex-start;gap:4px;min-height:76px;padding:12px 14px;text-transform:none', 'aria-pressed': String(st.grad === i), onclick: () => { st.grad = i; if (!potsFor(i).includes(st.pot)) st.pot = potsFor(i)[1]; paint(); paintPrev(); } }, h('span', { class: 'd', style: 'font-size:22px' }, g[0]), h('span', null, g[1])))),
        h('span', { class: 'muted', style: 'font-size:13px' }, 'One rig is a 200 TH/s ASIC. More hash to graduate means a longer, pricier curve.'), h('span', { class: 'lab' }, 'BTC paid out over the curve'),
        h('div', { style: 'display:grid;grid-template-columns:repeat(4,1fr);gap:10px' }, potsFor(st.grad).map((p) => h('button', { type: 'button', class: 'ghost' + (st.pot === p ? ' pick' : ''), style: 'min-height:56px;font-size:15px', 'aria-pressed': String(st.pot === p), onclick: () => { st.pot = p; paint(); paintPrev(); } }, p + ' BTC'))),
        h('span', { class: 'muted', style: 'font-size:13px' }, 'Miners owe this in total while the curve is mined. Each block pays one address: a holder 80% of the time, you 10%, hashfun 10%.')),
      h('div', { class: 'col' }, h('span', { class: 'd', style: 'font-size:26px' }, h('span', { class: 'o' }, '3 '), 'Your cut'), h('div', { class: 'between' }, h('label', { class: 'lab', for: 'fee' }, 'Creator fee, in coins'), h('span', { class: 'd o', style: 'font-size:26px' }, st.fee + '%')),
        h('input', { id: 'fee', type: 'range', min: 0, max: 10, step: 0.5, value: st.fee, style: 'width:100%;min-height:44px;accent-color:#FF9A1F', oninput: (e) => { st.fee = parseFloat(e.target.value); e.target.parentNode.querySelector('.between .d').textContent = st.fee + '%'; paintPrev(); } }),
        h('span', { class: 'muted', style: 'font-size:13px' }, 'A slice of every block\'s freshly minted coins, paid as it is mined. Never up front. 10% is the hard cap.'), h('div', { class: 'panel pad m between', style: 'font-size:13px' }, h('span', { class: 'muted' }, 'Your BTC lands at'), h('b', null, W.addr ? short(W.addr) + ' (UniSat)' : 'connect your wallet'))),
      h('div', { class: 'col', style: 'gap:12px' }, h('button', { class: 'btn', id: 'launch-go', type: 'button', style: 'min-height:68px;font-size:28px', disabled: st.busy, onclick: submit }, st.busy ? 'Starting the chain…' : `Launch $${st.ticker || 'TICKER'}`), st.err ? h('p', { class: 'err' }, st.err) : null,
        cfg.allow_launch ? h('p', { class: 'muted', style: 'font-size:13px' }, 'Free. The hash of this form, picture included, becomes the launch id, so anyone can check the chain against it.') : h('p', { class: 'err', style: 'font-size:13px' }, 'This site does not create launches. Use the CLI: hashfun launch new')));
  };
  paint(); paintPrev();
  view.replaceChildren(h('div', { class: 'col', style: 'gap:12px;padding:40px 0 32px' }, h('h1', { class: 'd h1' }, 'Launch a ', h('span', { class: 'o' }, 'coin')), h('p', { class: 'soft', style: 'max-width:640px;font-size:18px' }, 'One form. A new proof-of-work chain starts at block zero and nobody holds a coin, you included.')),
    h('div', { class: 'row', style: 'align-items:flex-start;gap:32px' }, form, h('aside', { style: 'flex:1 1 420px;min-width:0' }, prev)));
}

function bags(view) {
  if (!W.pub) return view.replaceChildren(h('div', { class: 'col', style: 'padding:48px 0;align-items:flex-start' }, h('h1', { class: 'd h1' }, 'Your bags'), h('p', { class: 'soft' }, 'Connect to see what you hold and what it has paid you.'), h('button', { class: 'btn', type: 'button', onclick: () => connect(true).then(route).catch((e) => toast(e.message, true)) }, 'Connect UniSat')));
  const big = h('span', { class: 'd l', id: 'yield', style: 'font-size:clamp(72px,12vw,148px);line-height:.9' }, '…'), sweepBox = h('div', { class: 'col' }), table = h('div', { class: 'table panel' }), swapBox = h('div', { class: 'col' }), p2pBox = h('div', { class: 'col' });
  let y = null;
  const sweep = async () => {
    try {
      const t = await api('/chain/btc/time'), us = y.utxos.filter((u) => u.confirmations > 0);
      const fee = t.feerate * (54 + 68 * us.length), total = us.reduce((a, u) => a + u.value, 0);
      if (total - fee < 600) throw new Error('not enough to cover the network fee yet');
      const tx = B.signP2wpkh(W.key, us, [{ value: total - fee, script: B.addressToScript(W.addr, cfg.btc) }]);
      const r = await api('/chain/btc/tx', { hex: B.txHex(tx) });
      toast(`Swept ${fmt(total - fee)} sats to ${short(W.addr)} in ${short(r.txid)}`);
      y = { balance: 0, utxos: [] }; paintYield();
    } catch (e) { toast(e.message, true); }
  };
  const paintYield = () => {
    big.textContent = y ? fmt(y.balance) : '…';
    sweepBox.replaceChildren(h('span', { class: 'lab' }, 'Waiting at your hashfun key'), h('span', { class: 'm muted', style: 'font-size:12px' }, `${btcAddr()} on Bitcoin, the same key that holds your coins`),
      h('button', { class: 'btn wide', id: 'sweep', type: 'button', disabled: !y || !y.utxos.some((u) => u.confirmations > 0), onclick: sweep }, 'Sweep to UniSat'), h('span', { class: 'muted', style: 'font-size:13px' }, 'Payouts are ordinary Bitcoin transactions to your key. Nothing to claim; sweeping only moves them to your main wallet.'),
      h('button', { class: 'ghost', type: 'button', onclick: () => { if (confirm('Anyone who sees this key can take your coins and payouts. Show it?')) prompt('hashfun key (hex). Keep it offline.', B.hex(W.key)); } }, 'Back up this key'));
  };
  const paintSwaps = () => {
    const open = Object.values(swaps()).filter((r) => r.state !== 'done' && r.state !== 'refunded' && r.init_txid).sort((a, b) => b.created - a.created);
    swapBox.replaceChildren(...(open.length ? [h('h2', { class: 'd', style: 'font-size:32px' }, 'Open swaps'), ...open.map((r) => h('div', { class: 'panel pad between', style: 'align-items:center' }, h('span', { class: 'm' }, `${r.side} $${r.ticker} · ${fmt(r.q.btc_amount)} sats · ${r.state}`),
      h('span', { class: 'row', style: 'gap:8px' }, r.order_id ? h('button', { class: 'ghost', type: 'button', onclick: () => flow(`Resume $${r.ticker}`, (ui) => finishSwap(r, ui)) }, 'Resume') : null, h('button', { class: 'ghost', type: 'button', onclick: () => refundSwap(r).then((x) => { toast('Refunded in ' + short(x.refund_txid)); paintSwaps(); }).catch((e) => toast(e.message, true)) }, 'Refund'))))] : []));
  };
  paintYield(); paintSwaps();
  view.replaceChildren(h('section', { class: 'row', style: 'padding:40px 0 32px;align-items:stretch' }, h('div', { class: 'col', style: 'flex:3 1 480px;gap:10px' }, h('h1', { class: 'd', style: 'font-size:44px;line-height:1' }, 'Your bags'), h('span', { class: 'lab l' }, h('span', { class: 'dot' }), ' BTC won just by holding'), h('div', { style: 'display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 16px' }, big, h('span', { class: 'd l', style: 'font-size:44px' }, 'sats')), h('p', { class: 'soft' }, 'Every block on a curve you hold is another draw.')),
    h('div', { class: 'panel pad', style: 'flex:2 1 340px;border:2px solid #F2F0EC' }, sweepBox)),
  h('section', { class: 'col', style: 'gap:14px' }, h('h2', { class: 'd', style: 'font-size:32px' }, 'Holdings'), table), h('section', { style: 'margin-top:32px' }, swapBox), h('section', { class: 'col', style: 'margin-top:32px;gap:14px' }, p2pBox));
  api(`/chain/btc/address/${btcAddr()}`).then((r) => { y = r; paintYield(); }).catch((e) => toast(e.message, true));
  every(2500, async () => {
    cfg = await api('/config');
    const list = await api('/board'), cols = 'grid-template-columns:minmax(0,2fr) minmax(0,1fr) minmax(0,1.2fr) minmax(0,1fr) 110px';
    const rows = await Promise.all(list.filter((c) => c.height != null && cfg.launches[c.ticker]).map(async (c) => ({ c, me: await api(`/coin/${c.ticker}/address/${launchAddr(c.ticker)}`) })));
    const mine = rows.filter((r) => r.me.balance > 0);
    p2pBox.replaceChildren(...p2pLists(await book.mine().catch(() => [])));
    table.replaceChildren(h('div', null, h('div', { class: 'tr head', style: cols }, h('span', null, 'Coin'), h('span', null, 'Bag'), h('span', null, 'Odds per block'), h('span', null, 'Status'), h('span')),
      mine.length ? mine.map(({ c, me }) => h('div', { class: 'tr', style: cols + ';min-height:72px' }, h('span', { style: 'display:flex;align-items:center;gap:12px;min-width:0' }, tile(c.ticker), h('span', { class: 'col', style: 'gap:2px' }, h('b', { style: 'font-family:Inter,sans-serif;font-size:15px' }, c.name), h('span', { class: 'muted' }, '$' + c.ticker))), h('span', null, coins(me.balance)), h('b', { class: c.graduated ? 'muted' : 'l' }, c.graduated ? 'payouts ended' : '1 in ' + fmt(Math.max(1, Math.round(me.earning_supply / me.balance / 0.8)))), h('span', { class: 'muted' }, status(c)[0]), h('a', { class: 'ghost', href: `#/c/${c.ticker}` }, 'Trade')))
        : h('div', { class: 'pad muted' }, 'No coins yet. Pick one on the board.')));
  });
}

// ---------------------------------------------------------------- peer-to-peer book
// Holders trade with each other: any coin for sats, any coin for any other coin. The page signs
// offers, answers takes and runs the swap (book.js); the site only passes signed messages along.
const told = new Set();
const book = createBook({ api, W, cfg: () => cfg, store: localStorage, unisat: () => window.unisat, onChange: (r) => {
  if (r.role === 'maker' && r.state === 'done' && !told.has(r.id)) { told.add(r.id); toast(`Your offer filled: +${amt(r.get, r.got)}`); }
} });
const amt = (n, v) => (n === 'btc' ? fmt(v) + ' sats' : coins(v) + ' $' + n);
const unitOf = (n) => (n === 'btc' ? 'sats' : '$' + n);
const chainLabel = (n) => (n === 'btc' ? 'Bitcoin' : '$' + n);
const toUnits = (n, x) => Math.round(n === 'btc' ? x : x * COIN);
const fromUnits = (n, v) => (n === 'btc' ? v : v / COIN);
const dur = (sec) => (sec >= 7200 ? Math.round(sec / 3600) + ' hours' : Math.max(1, Math.round(sec / 60)) + ' minutes');
// The price in the units people quote: sats per coin when Bitcoin is one side.
const rate = (pay, get, payAmt, getAmt) => (pay === 'btc' ? `${price((payAmt / getAmt) * COIN)} sats per coin` : get === 'btc' ? `${price((getAmt / payAmt) * COIN)} sats per coin` : `1 $${get} = ${price(payAmt / getAmt)} $${pay}`);
const assetTile = (n) => (n === 'btc' ? h('span', { class: 'tile', 'aria-hidden': 'true', style: 'background:#FF9A1F;color:#0A0A0B;border-color:#FF9A1F' }, 'B') : tile(n));
const swapState = (r) => ({ requested: 'asking the maker', accepted: 'about to lock', locking: 'locking', locked: r.role === 'taker' ? 'waiting for the maker' : 'waiting for the taker to claim', done: 'done', failed: 'did not happen', released: 'the taker did not lock', refunded: 'refunded' }[r.state] || r.state);

// A picture for a launch: at most 48 KB, square. Small files go in untouched (animations
// survive); big ones are cropped to the middle and re-encoded here, before anything is hashed.
async function squarePicture(file) {
  const raw = new Uint8Array(await file.arrayBuffer()), kind = B.imageType(raw);
  if (!kind) throw new Error('PNG, JPEG, GIF or WebP only.');
  if (raw.length <= 48000) return { image: raw, image_type: kind };
  if (kind === 'image/gif') throw new Error('That GIF is over 48 KB, and an animation has to fit as it is.');
  const bmp = await createImageBitmap(file), side = Math.min(bmp.width, bmp.height);
  for (const [px, q] of [[400, 0.86], [400, 0.7], [256, 0.8], [256, 0.6], [160, 0.6]]) {
    const c = h('canvas', { width: px, height: px }), g = c.getContext('2d');
    g.fillStyle = K; g.fillRect(0, 0, px, px);
    g.drawImage(bmp, (bmp.width - side) / 2, (bmp.height - side) / 2, side, side, 0, 0, px, px);
    for (const type of ['image/webp', 'image/jpeg']) {
      const blob = await new Promise((r) => c.toBlob(r, type, q));
      if (!blob || blob.type !== type || blob.size > 48000) continue;
      const out = new Uint8Array(await blob.arrayBuffer());
      if (B.imageType(out) === type) return { image: out, image_type: type };
    }
  }
  throw new Error('Could not shrink that picture enough.');
}

// The coin page's Book tab: who is selling this coin for sats and who is buying it, best first.
function bookTab(ticker, orders) {
  const id = (cfg.launches[ticker] || {}).id, cols = 'grid-template-columns:minmax(0,1.3fr) minmax(0,1fr) minmax(0,1fr) 48px';
  const side = (title, list, pay, get, word) => h('div', { style: 'flex:1 1 340px;min-width:0' }, h('div', { class: 'lab', style: 'padding:14px 16px 8px' }, title),
    h('div', { class: 'tr head', style: cols }, h('span', null, 'Price'), h('span', null, 'Coins'), h('span', null, 'Sats'), h('span')),
    list.length ? list.map((o) => { const c = get === 'btc' ? o.remaining_get : o.remaining, sats = get === 'btc' ? o.remaining : o.remaining_get;
      return h('a', { class: 'tr', style: cols, href: `#/swap/${pay}/${get}/${o.id}`, 'data-order': o.id }, h('b', null, price((sats / c) * COIN)), h('span', null, coins(c)), h('span', { class: 'muted' }, fmt(sats)), h('span', { class: word === 'buy' ? 'o' : 'l' }, word)); })
      : h('div', { class: 'pad muted', style: 'font-size:13px' }, 'Nobody yet.'));
  const sellers = orders.filter((o) => o.give === id && o.get === cfg.btc_id), buyers = orders.filter((o) => o.get === id && o.give === cfg.btc_id);
  const others = orders.filter((o) => (o.give === id || o.get === id) && o.give !== cfg.btc_id && o.get !== cfg.btc_id).length;
  return h('div', { id: 'book' }, h('div', { class: 'row', style: 'gap:0' }, side(`Selling $${ticker}`, sellers, 'btc', ticker, 'buy'), side(`Buying $${ticker}`, buyers, ticker, 'btc', 'sell')),
    h('div', { class: 'pad between', style: 'align-items:center;border-top:1px solid #2C2C31' }, h('span', { class: 'muted', style: 'font-size:13px;flex:1 1 280px' }, `Holders trading with each other by atomic swap: no custody, no listing, prices in sats per coin.${others ? ` ${others} more offer${others === 1 ? '' : 's'} against other coins.` : ''}`),
      h('span', { class: 'row', style: 'gap:8px' }, h('a', { class: 'ghost', href: `#/swap/${ticker}/btc` }, `Sell $${ticker}`), h('a', { class: 'ghost', href: `#/swap/btc/${ticker}` }, `Bid for $${ticker}`), h('a', { class: 'ghost', href: `#/swap/${ticker}` }, 'Other coins'))));
}

// Offers of mine and swaps of mine, for Bags and the Swap page.
function p2pLists(myOrders) {
  const nm = (id) => book.nameOf(id) || '?', out = [];
  const rs = Object.values(book.recs()).filter((r) => r.taker).sort((a, b) => b.created - a.created).slice(0, 12);
  if (myOrders.length) out.push(h('h2', { class: 'd', style: 'font-size:32px' }, 'Your offers'), ...myOrders.map((o) => h('div', { class: 'panel pad between', 'data-offer': o.id, style: 'align-items:center' },
    h('span', { class: 'm' }, `give ${amt(nm(o.give), o.remaining)} for ${amt(nm(o.get), o.remaining_get)}`, h('span', { class: 'muted' }, o.remaining < o.give_amount ? ' · partly filled' : '')),
    h('button', { class: 'ghost', type: 'button', onclick: () => book.cancel(o.id).then(() => { toast('Offer cancelled'); route(); }).catch((e) => toast(e.message, true)) }, 'Cancel'))));
  if (rs.length) out.push(h('h2', { class: 'd', style: 'font-size:32px' }, 'Peer-to-peer swaps'), ...rs.map((r) => {
    const pays = r.role === 'taker' ? [r.get, r.get_amount] : [r.give, r.give_amount], gets = r.role === 'taker' ? [r.give, r.give_amount] : [r.get, r.get_amount];
    return h('div', { class: 'panel pad between', 'data-p2p': r.state, 'data-role': r.role, style: 'align-items:center' }, h('span', { class: 'm' }, `${amt(...pays)} for ${amt(...gets)}`),
      h('span', { class: 'm ' + (r.state === 'done' ? 'l' : 'muted'), style: 'font-size:12px;text-align:right;flex:1 1 200px' }, swapState(r) + (r.note ? ' · ' + r.note : '')));
  }));
  return out;
}

// The window a peer-to-peer swap runs in. It only watches: the engine does the work, so closing
// it changes nothing.
function flowP2P(title, run) {
  const legs = [['ask', "The maker's page answers"], ['lock', 'Lock your side'], ['wait', 'The maker locks the other side'], ['claim', 'Claim'], ['done', 'Done']];
  const m = $('modal'), note = h('p', { class: 'm muted', id: 'p2p-note', style: 'min-height:20px;font-size:13px' });
  const list = h('ol', { class: 'legs' }, legs.map(([k, label]) => h('li', { 'data-k': k }, h('i'), label)));
  let open = true, id = null;
  const close = () => { open = false; m.hidden = true; m.replaceChildren(); route(); };
  const box = h('div', { class: 'flow busy' }, h('span', { class: 'lab o' }, 'Peer-to-peer atomic swap'), h('h2', { class: 'd h2' }, title), list, note,
    h('p', { class: 'muted', style: 'font-size:13px' }, 'You can close this. The swap finishes by itself while this site is open in a tab, and your side comes back by itself if the other side stops.'), h('button', { class: 'ghost', type: 'button', onclick: close }, 'Close'));
  const step = (k) => { const i = legs.findIndex((x) => x[0] === k); [...list.children].forEach((li, n) => { li.className = n < i ? 'ok' : n === i ? 'now' : ''; }); };
  const fail = (msg) => { box.className = 'flow'; note.className = 'err'; note.textContent = msg; };
  m.replaceChildren(box); m.hidden = false; step('ask');
  run((k, rec) => { if (rec) id = rec.id; step(k); }).then((rec) => { id = rec.id; }).catch((e) => { if (!id || !book.recs()[id] || book.recs()[id].state === 'failed') fail(e.message || String(e)); });
  (async () => {
    while (open) {
      const r = id && book.recs()[id];
      if (r && r.state === 'done') {
        box.className = 'flow done';
        box.replaceChildren(h('span', { class: 'lab', style: 'color:#0A0A0B' }, 'Swap complete'), h('h2', { class: 'd', style: 'font-size:clamp(64px,14vw,150px);line-height:.88' }, 'Swapped'),
          h('div', { class: 'd', id: 'p2p-got', style: 'font-size:40px;line-height:1' }, '+' + amt(r.give, r.got)), h('p', { style: 'font-size:17px;font-weight:500' }, "Straight from another holder's key to yours. Nobody held anything in between."),
          h('div', { class: 'row', style: 'gap:12px' }, h('a', { class: 'btn', style: 'background:#0A0A0B;color:#C7F23E;box-shadow:none', href: '#/bags', onclick: close }, 'See your bags'), h('button', { class: 'ghost', style: 'border-color:#0A0A0B;color:#0A0A0B;min-height:56px', type: 'button', onclick: close }, 'Close')));
        return;
      }
      if (r && (r.state === 'refunded' || r.state === 'failed')) return fail(r.note || swapState(r));
      if (r) { if (note.className !== 'err') note.textContent = r.note || ''; if (r.state === 'locked') step('wait'); else if (r.state === 'locking' || r.state === 'accepted') step('lock'); }
      await sleep(500);
    }
  })();
}

// Swap anything for anything: take the best offer, or leave your own.
function swap(view, a, b, pick) {
  const norm = (x) => ((x || '').toLowerCase() === 'btc' ? 'btc' : (x || '').toUpperCase());
  const all = ['btc', ...Object.keys(cfg.launches).sort()];
  const pay = all.includes(norm(a)) ? norm(a) : 'btc';
  const get = all.includes(norm(b)) && norm(b) !== pay ? norm(b) : (pay === 'btc' ? all.find((n) => n !== 'btc') : 'btc');
  if (!get) return view.replaceChildren(h('div', { class: 'col', style: 'padding:48px 0;align-items:flex-start' }, h('h1', { class: 'd h1' }, 'Swap'), h('p', { class: 'soft' }, 'No coins here yet. Launch one first.'), h('a', { class: 'btn', href: '#/launch' }, 'Launch a coin')));
  const st = { sel: pick || null, payIn: '', giveIn: '', wantIn: '', perr: '', seen: '' };
  let offers = [], rivals = [], mine = [], bal = null;
  const picker = (cur, other, id, label, onpick) => h('div', { class: 'col', style: 'flex:1 1 260px;gap:6px' }, h('label', { class: 'lab', for: id }, label), h('div', { class: 'field' }, assetTile(cur),
    h('select', { id, onchange: (e) => onpick(e.target.value) }, all.filter((n) => n !== other).map((n) => h('option', { value: n, selected: n === cur }, n === 'btc' ? 'Bitcoin (sats)' : `${cfg.launches[n].name} ($${n})`)))));
  const offersBox = h('div', { class: 'panel', style: 'flex:3 1 420px;min-width:0' }), takeBox = h('div', { class: 'trade' }), postBox = h('div', { class: 'panel' }), mineBox = h('section', { class: 'col', style: 'gap:14px;margin-top:32px' });
  const balEl = h('span', { class: 'm muted', id: 'sw-bal', style: 'font-size:12px' }), rivalEl = h('span', { class: 'm muted', style: 'font-size:12px' });
  const kv = (k, v) => h('div', { class: 'kv' }, h('span', null, k), h('span', { style: 'text-align:right' }, v));

  const paintOffers = () => offersBox.replaceChildren(h('div', { class: 'between lab', style: 'padding:14px 16px;border-bottom:1px solid #2C2C31' }, `${chainLabel(get)} on offer for ${unitOf(pay)}`, h('span', { class: 'l' }, h('span', { class: 'dot' }), ` ${offers.length} live`)),
    ...(offers.length ? offers.map((o) => h('button', { type: 'button', class: 'offer' + (st.sel === o.id ? ' on' : ''), 'data-order': o.id, 'aria-pressed': String(st.sel === o.id), onclick: () => { st.sel = o.id; st.payIn = ''; st.seen = ''; paintOffers(); paintTake(); } },
      h('span', { class: 'd', style: 'font-size:26px;line-height:1' }, rate(pay, get, o.remaining_get, o.remaining)), h('span', { class: 'm', style: 'font-size:13px' }, `up to ${amt(get, o.remaining)} for ${amt(pay, o.remaining_get)}`),
      h('span', { class: 'm muted', style: 'font-size:12px' }, `from ${short(o.maker)}${W.pub && o.maker === B.hex(W.pub) ? ' (you)' : ''}, online now`)))
      : [h('div', { class: 'pad col' }, h('span', { class: 'd', style: 'font-size:26px' }, 'No offers this way yet'), h('p', { class: 'muted', style: 'font-size:13px' }, 'Leave your own: it is live the moment you sign it.'))]));

  const paintTake = () => {
    const o = offers.find((x) => x.id === st.sel);
    if (!o) return takeBox.replaceChildren(h('div', { class: 'pad col' }, h('span', { class: 'lab' }, 'Take an offer'), h('p', { class: 'soft' }, offers.length ? 'Pick an offer.' : 'Nothing to take in this direction right now.')));
    const max = o.remaining_get, own = W.pub && o.maker === B.hex(W.pub);
    const payUnits = () => (st.payIn === '' ? max : Math.min(max, toUnits(pay, parseFloat(st.payIn) || 0)));
    const outEl = h('span', { class: 'd o', id: 'sw-get', style: 'font-size:48px;line-height:1' });
    const go = async () => { try { await needWallet(); } catch (e) { return toast(e.message, true); } const p = payUnits(); flowP2P(`${chainLabel(get)} for ${unitOf(pay)}`, (ui) => book.take(o, p, ui)); };
    const btn = h('button', { class: 'btn wide', id: 'sw-go', type: 'button', onclick: go }, own ? 'Your own offer' : 'Swap now');
    const upd = () => { const p = payUnits(), g = Math.floor(o.give_amount * (p / o.get_amount)); outEl.textContent = amt(get, g); btn.disabled = Boolean(own) || !(p >= o.min_get) || !(g > 0); };
    takeBox.replaceChildren(h('div', { class: 'pad col' }, h('label', { class: 'lab', for: 'sw-amt' }, 'You pay'),
      h('div', { class: 'field' }, h('input', { class: 'big', id: 'sw-amt', inputmode: 'decimal', value: st.payIn, placeholder: String(fromUnits(pay, max)), oninput: (e) => { st.payIn = e.target.value.replace(/,/g, ''); upd(); } }), h('span', { class: 'm muted' }, unitOf(pay))),
      h('span', { class: 'lab' }, 'You get'), outEl,
      h('div', null, kv('Price', rate(pay, get, o.get_amount, o.give_amount)), kv('Smallest take', amt(pay, o.min_get)),
        kv('Speed', `${o.confs} confirmation${o.confs === 1 ? '' : 's'} on ${chainLabel(pay)}, then ${book.confsFor(get)} on ${chainLabel(get)}`), kv('If the maker stops', `your side comes back after ${dur(2 * o.lock + Math.min(600, Math.floor(o.lock / 2)))}`)),
      btn, h('p', { class: 'muted', style: 'font-size:13px' }, pay === 'btc' ? 'Paid from UniSat into a contract only the maker can claim, and only by handing you the coins.' : 'Locked from your hashfun key into a contract only the maker can claim, and only by paying you.')));
    upd();
  };

  const paintPost = () => {
    const g = () => toUnits(pay, parseFloat(st.giveIn) || 0), w = () => toUnits(get, parseFloat(st.wantIn) || 0);
    const rateEl = h('span', { class: 'm', id: 'po-rate', style: 'font-size:13px' });
    const post = async () => {
      st.perr = '';
      try { await needWallet(); await book.post({ give: pay, get, give_amount: g(), get_amount: w() }); st.giveIn = st.wantIn = ''; toast('Your offer is live'); await refresh(); } catch (e) { st.perr = e.message; }
      paintPost();
    };
    const deposit = async () => {
      try { await needWallet(); const n = parseInt(prompt('Sats to move from UniSat to your hashfun key (your offers are paid from there):', '100000') || '0', 10); if (n > 0) { await window.unisat.sendBitcoin(btcAddr(), n); toast('On its way. It counts after 1 confirmation.'); } } catch (e) { toast(e.message, true); }
    };
    const btn = h('button', { class: 'btn wide white', id: 'po-go', type: 'button', onclick: post }, 'Post offer');
    const upd = () => { const ok = g() > 0 && w() > 0; rateEl.textContent = ok ? rate(get, pay, w(), g()) : 'Set both sides: the price is what you make it.'; btn.disabled = !ok; };
    postBox.replaceChildren(h('div', { class: 'pad col' }, h('span', { class: 'lab' }, 'Or leave your own offer'),
      h('div', { class: 'field' }, h('input', { id: 'po-give', inputmode: 'decimal', 'aria-label': 'You give', placeholder: 'You give', value: st.giveIn, oninput: (e) => { st.giveIn = e.target.value.replace(/,/g, ''); upd(); } }), h('span', { class: 'm muted' }, unitOf(pay))),
      h('div', { class: 'field' }, h('input', { id: 'po-want', inputmode: 'decimal', 'aria-label': 'You want', placeholder: 'You want', value: st.wantIn, oninput: (e) => { st.wantIn = e.target.value.replace(/,/g, ''); upd(); } }), h('span', { class: 'm muted' }, unitOf(get))),
      rateEl, rivalEl, h('div', { class: 'between', style: 'align-items:center' }, balEl, pay === 'btc' ? h('button', { class: 'ghost', type: 'button', onclick: deposit }, 'Deposit from UniSat') : null),
      btn, st.perr ? h('p', { class: 'err', id: 'po-err' }, st.perr) : null,
      h('p', { class: 'muted', style: 'font-size:13px' }, 'Signed by your hashfun key and live while this site is open in a tab (a background tab is fine): your page locks your side by itself when someone takes it, and claims the other side. Nothing leaves your key until someone takes it. Keep the tab open until a swap in progress is done.')));
    upd();
  };

  const refresh = async () => {
    const list = await book.list();
    offers = list.filter((o) => o.give === book.idOf(get) && o.get === book.idOf(pay));
    rivals = list.filter((o) => o.give === book.idOf(pay) && o.get === book.idOf(get));
    if (W.pub) { mine = await book.mine().catch(() => mine); bal = await book.balance(pay).catch(() => bal); }
    if (!offers.some((o) => o.id === st.sel)) st.sel = offers.length ? offers[0].id : null;
    const o = offers.find((x) => x.id === st.sel), sig = o ? `${o.id}:${o.remaining}` : '';
    paintOffers();
    if (sig !== st.seen) { st.seen = sig; paintTake(); } // not on every poll: the amount box keeps its focus
    balEl.textContent = W.pub ? `At your hashfun key: ${bal == null ? '…' : amt(pay, bal)}` : 'Connect to post an offer';
    rivalEl.textContent = rivals.length ? `Best offer this way now: ${rate(get, pay, rivals[0].get_amount, rivals[0].give_amount)}` : 'Nobody else is offering this way.';
    mineBox.replaceChildren(...p2pLists(mine));
  };

  view.replaceChildren(h('div', { class: 'col', style: 'gap:12px;padding:40px 0 28px' }, h('h1', { class: 'd h1' }, 'Swap ', h('span', { class: 'o' }, 'anything')), h('p', { class: 'soft', style: 'max-width:680px;font-size:18px' }, 'Every coin here is its own Bitcoin-style chain, so any of them swaps for any other, or for sats, wallet to wallet. No pool, no bridge, no listing: one holder and another.')),
    h('div', { class: 'row', style: 'align-items:flex-end;gap:14px;margin-bottom:24px' }, picker(pay, null, 'sw-pay', 'You pay with', (v) => { location.hash = `#/swap/${v}/${v === get ? pay : get}`; }),
      h('button', { class: 'ghost', type: 'button', style: 'min-height:60px', 'aria-label': 'Swap direction', onclick: () => { location.hash = `#/swap/${get}/${pay}`; } }, 'flip'),
      picker(get, pay, 'sw-get-asset', 'You get', (v) => { location.hash = `#/swap/${pay}/${v}`; })),
    h('div', { class: 'row', style: 'align-items:flex-start' }, offersBox, h('div', { class: 'col side', style: 'flex:2 1 360px;gap:20px' }, takeBox, postBox)), mineBox);
  paintOffers(); paintTake(); paintPost();
  every(1500, refresh);
}

// ---------------------------------------------------------------- router
function route() {
  viewToken++; clearTimeout(timer);
  const view = $('view'), parts = location.hash.replace(/^#\/?/, '').split('/');
  const name = parts[0] === 'c' && parts[1] ? 'coin' : parts[0] === 'launch' ? 'launch' : parts[0] === 'bags' ? 'bags' : parts[0] === 'swap' ? 'swap' : 'board';
  document.querySelectorAll('nav a').forEach((a) => a.classList.toggle('on', a.dataset.nav === name));
  if (name === 'coin') coin(view, parts[1].toUpperCase()); else if (name === 'launch') launchForm(view); else if (name === 'bags') bags(view); else if (name === 'swap') swap(view, parts[1], parts[2], parts[3]); else board(view);
  if (location.hash === '#how') setTimeout(() => { const e = $('how'); if (e) e.scrollIntoView(); }, 50);
}

(async () => {
  try { cfg = await api('/config'); } catch (e) { toast('The site API is not reachable: ' + e.message, true); }
  $('wallet').addEventListener('click', () => (W.addr ? (location.hash = '#/bags') : connect(true).then(route).catch((e) => toast(e.message, true))));
  await connect(false).catch(() => false);
  paintWallet();
  book.start(); // answers takes on your offers and finishes or refunds your swaps while a tab is open
  // Mid-swap the page still has work to do (claim, or refund after the timelock): say so before it is closed.
  window.addEventListener('beforeunload', (e) => { if (book.pending()) { e.preventDefault(); e.returnValue = ''; } });
  window.addEventListener('hashchange', route);
  route();
})();
