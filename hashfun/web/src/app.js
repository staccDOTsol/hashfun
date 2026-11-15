// hashfun site: board, coin page, launch form, bags, the peer-to-peer book, and atomic swaps signed
// in the browser.
// Keys never leave the page: the server only reads chains and broadcasts what is signed here.
//
// Every coin has two curves: a block mined on the BTC curve owes sats on Bitcoin, one mined on the
// QWEN curve owes QWEN on Qwencoin (contrib/hashfun/TWIN.md). Qwencoin kept Bitcoin's address
// form, so a key's address is the same string on both chains: every address and every amount on
// this page is shown with the chain it is on.
import * as B from './btc.js';
import { createBook, findOutput, FINAL } from './book.js';
// The pitch: one source for the words (contrib/hashfun/PITCH.md). The page says them where
// someone arriving needs them; it does not rephrase them.
import PITCH from '../static/pitch.json';

// A coin's address for link previews is a path (/c/TICKER: the server answers it with that coin's
// tags). The page itself routes by fragment: opened at the path, it moves to the fragment form.
const deep = typeof location !== 'undefined' && !location.hash && location.pathname.match(/\/c\/([A-Za-z0-9]{2,10})$/);
if (deep) location.replace(new URL('#/c/' + deep[1].toUpperCase(), document.baseURI).href);

// The browser's storage, or a stand-in that lasts until the page is closed where the browser
// refuses it (blocked site data, some private windows): the page works either way.
const storage = (name) => {
  try { const st = window[name]; st.setItem('hf_probe', '1'); st.removeItem('hf_probe'); return st; } catch (e) {
    const m = new Map();
    return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => { m.set(k, String(v)); }, removeItem: (k) => { m.delete(k); } };
  }
};
const LS = storage('localStorage'), SS = storage('sessionStorage');

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
const since = (t) => { const a = ago(t); return a === 'now' ? 'just now' : a + ' ago'; };
const ago = (t) => { const d = Math.max(0, Math.floor(Date.now() / 1000 - t)); return d < 3 ? 'now' : d < 90 ? d + 's' : d < 5400 ? Math.floor(d / 60) + 'm' : d < 129600 ? Math.floor(d / 3600) + 'h' : Math.floor(d / 86400) + 'd'; };
const price = (p) => (p >= 100 ? fmt(p) : p >= 1 ? p.toFixed(2) : p >= 0.01 ? p.toFixed(4) : p > 0 ? Number(p.toPrecision(2)).toFixed(12).replace(/0+$/, '') : '0');
// QWEN, from its base units (1 QWEN = 100,000,000, as a bitcoin is to its sats), exact to the last one.
const qwen = (v) => { const x = v / COIN; return x >= 1000 ? fmt(x) : x >= 1 ? fmt(x, 2) : x.toFixed(8).replace(/\.?0+$/, ''); };
// The two curves of a coin, named by what a block on them owes. `owe`: an amount of that quote;
// `point`: a curve's price point, in base units of its quote per coin.
const CURVES = ['btc', 'qwen'];
const Q = { btc: { curve: 'BTC curve', chain: 'Bitcoin', unit: 'sats', per: 'sats per coin', color: '#FF9A1F' }, qwen: { curve: 'QWEN curve', chain: 'Qwencoin', unit: 'QWEN', per: 'QWEN sats per coin', color: '#F2F0EC' } };
const owe = (quote, v) => (quote === 'qwen' ? qwen(v) + ' QWEN' : fmt(v) + ' sats');
const pct = (p) => (p * 100).toFixed(1) + '%';
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
// Relative, like every link this page makes: the site may be served under a path of another
// server's domain (hashfun web --base-path).
const api = async (path, body) => {
  const r = await fetch('api' + path, body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : undefined);
  const j = await r.json().catch(() => ({ error: 'bad response' }));
  if (!r.ok) throw new Error(j.error || 'request failed');
  return j;
};
let cfg = { btc: { hrp: 'bc' }, qwen: null, launches: {} };

// ---------------------------------------------------------------- wallet
const W = { addr: null, key: null, pub: null };
const launchAddr = (t) => B.segwitEncode(cfg.launches[t].hrp, 0, B.hash160(W.pub));
const btcAddr = () => B.segwitEncode(cfg.btc.hrp, 0, B.hash160(W.pub));
// The hashfun key on an outside chain: Bitcoin or Qwencoin. One key, and where the two networks
// share an address form one string; what sits at it on one chain is not on the other.
const keyAddr = (chain) => B.segwitEncode(cfg[chain].hrp, 0, B.hash160(W.pub));
const where = (chain) => `${keyAddr(chain)} on ${Q[chain].chain}`;
const paintWallet = () => { const b = $('wallet'); b.textContent = W.addr ? short(W.addr) : 'CONNECT UNISAT'; b.className = 'm wallet' + (W.addr ? ' on' : ''); };
// UniSat runs on several chains, and Fractal's addresses look exactly like Bitcoin's: a payment
// from the wrong one would fund a swap contract on a chain this site never looks at. So the
// wallet's chain is checked at connect and again before every payment. (Read from the extension's
// source, unisat-wallet/wallet: getChain() -> { enum }, switchChain(enum), older builds only getNetwork().)
const WALLET_CHAIN = { main: 'BITCOIN_MAINNET', test: 'BITCOIN_TESTNET', testnet4: 'BITCOIN_TESTNET4', signet: 'BITCOIN_SIGNET' };
async function rightChain(u, ask) {
  const want = WALLET_CHAIN[cfg.btc.chain];
  if (!want) return true; // regtest: no real wallet runs there, only test doubles
  const wrong = () => new Error(`Switch UniSat to ${want.replace(/_/g, ' ').toLowerCase()}: this site is on that network`);
  if (!u.getChain) { if (((await u.getNetwork()) === 'livenet') !== (cfg.btc.chain === 'main')) throw wrong(); return true; }
  let c = await u.getChain();
  if (c.enum !== want) { if (!ask) return false; c = await u.switchChain(want).catch(() => { throw wrong(); }); }
  if (!c || c.enum !== want) throw wrong();
  return true;
}
// ---------------------------------------------------------------- mining from the page
// The site's pool mines a block that pays the visitor's address, on the curve the visitor picked.
// The visitor then pays what that block owes themselves, to the script the draw fixed: one
// transaction on the block's own quote chain (Bitcoin for the BTC curve, Qwencoin for the QWEN
// curve) from the page's key, output i bound to block i by the tag list. Nobody holds anything
// for anybody.
async function payDues(dues, quote) {
  const group = dues.slice(0, 3), need = group.reduce((a, x) => a + x.pay, 0);
  const t = await api(`/chain/${quote}/time`);
  const us = (await api(`/chain/${quote}/address/${keyAddr(quote)}`)).utxos.filter((u) => u.confirmations > 0).sort((a, b) => b.value - a.value);
  const sel = []; let total = 0, fee = 0;
  for (const u of us) {
    sel.push(u); total += u.value;
    fee = t.feerate * (11 + 68 * sel.length + 43 * group.length + 12 + 20 * group.length + 31);
    if (total >= need + fee) break;
  }
  if (total < need + fee) {
    const gap = need + fee - total + 1000;
    if (quote === 'qwen') throw new Error(`Paying takes ${owe('qwen', need + fee)} at your hashfun key on Qwencoin and it holds ${owe('qwen', total)}. Send at least ${owe('qwen', gap)} to ${where('qwen')}, then pay again after 1 confirmation there.`);
    if (confirm(`Paying takes ${fmt(need + fee)} sats at your hashfun key on Bitcoin and it holds ${fmt(total)}. Move ${fmt(gap)} sats there from UniSat now? It counts after 1 confirmation.`)) await walletPay(btcAddr(), gap);
    throw new Error('Top-up on its way. Pay again after 1 confirmation.');
  }
  const outs = group.map((x) => ({ value: x.pay, script: B.unhex(x.pay_script) }));
  outs.push({ value: 0, script: B.cat(Uint8Array.of(0x6a), B.push(B.cat(B.utf8('HF'), ...group.map((x) => B.unhex(x.tag))))) });
  if (total - need - fee >= 600) outs.push({ value: total - need - fee, script: B.p2wpkh(W.pub) });
  return (await api(`/chain/${quote}/tx`, { hex: B.txHex(B.signP2wpkh(W.key, sel, outs)) })).txid;
}

let mineCurve = 'btc'; // the curve the mine panel asks for; kept while the page is open
function minePanel(ticker, d, repaint) {
  const pool = d.pool, box = h('div', { class: 'col', style: 'gap:10px' });
  const can = (pool.curves || ['btc']).filter((x) => x !== 'qwen' || cfg.qwen), open = !d.graduated;
  if (!can.includes(mineCurve)) mineCurve = can[0] || 'btc';
  const paidKey = `hf-paid-${ticker}`;
  const paid = () => { try { return JSON.parse(LS.getItem(paidKey) || '{}'); } catch (e) { return {}; } };
  const load = async () => {
    if (!W.pub) return box.replaceChildren();
    try {
      const sent = paid(), all = await api(`/coin/${ticker}/due?address=${launchAddr(ticker)}`);
      const parts = CURVES.map((quote) => {
        const mine = all.filter((x) => (x.quote || 'btc') === quote);
        const dues = mine.filter((x) => !x.paid && !sent[x.key]), waiting = mine.filter((x) => x.paid || sent[x.key]);
        const sum = dues.reduce((a, x) => a + x.pay, 0), now = dues.slice(0, 3).reduce((a, x) => a + x.pay, 0);
        return [dues.length ? h('div', { class: 'col', style: 'gap:8px', 'data-dues': quote },
          h('p', {}, `${dues.length > 1 ? dues.length + ' of your blocks' : 'Your block'} on the ${Q[quote].curve} owe${dues.length > 1 ? '' : 's'} ${owe(quote, sum)}, on ${Q[quote].chain}. Pay and the coins unlock; unpaid by block ${dues[0].deadline_height}, they are gone.`),
          h('button', { class: 'btn wide' + (quote === 'qwen' ? ' white' : ''), id: 'paydue' + (quote === 'qwen' ? '-qwen' : ''), type: 'button', onclick: async () => {
            try { const txid = await payDues(dues, quote); const m = paid(); dues.slice(0, 3).forEach((x) => { m[x.key] = txid; }); LS.setItem(paidKey, JSON.stringify(m)); toast(`Paid in ${short(txid)} on ${Q[quote].chain}. Unlocks after ${d.curves[quote].confs} confirmation${d.curves[quote].confs === 1 ? '' : 's'} there.`); load(); } catch (e) { toast(e.message, true); }
          } }, `Pay ${owe(quote, now)} on ${Q[quote].chain}`),
          quote === 'qwen' ? h('p', { class: 'm muted', style: 'font-size:12px' }, `Paid from your hashfun key on Qwencoin: ${keyAddr('qwen')}. Send QWEN there on Qwencoin first.`) : null) : null,
        waiting.length ? h('p', { class: 'muted', style: 'font-size:13px' }, `${waiting.length} payment${waiting.length > 1 ? 's' : ''} on ${Q[quote].chain} waiting for ${d.curves[quote].confs} confirmation${d.curves[quote].confs === 1 ? '' : 's'} there.`) : null];
      });
      box.replaceChildren(...parts.flat().filter(Boolean));
    } catch (e) { box.replaceChildren(); }
  };
  load();
  const iv = setInterval(() => { if (!box.isConnected) clearInterval(iv); else load(); }, 8000);
  const ask = async () => {
    try {
      await needWallet();
      const r = await api(`/coin/${ticker}/queue`, { address: launchAddr(ticker), blocks: 1, curve: mineCurve });
      toast(r.position ? `Queued on the ${Q[mineCurve].curve}: ${r.position} ahead of you.` : `Mining your block on the ${Q[mineCurve].curve} now.`);
      repaint();
    } catch (e) { toast(e.message, true); }
  };
  const waitingOn = (x) => (pool.queues ? pool.queues[x] || 0 : x === 'btc' ? pool.queue : 0);
  const pick = h('div', { style: 'display:grid;grid-template-columns:1fr 1fr;gap:8px', role: 'group', 'aria-label': 'Curve to mine on' }, CURVES.map((x) => {
    const c = d.curves[x], on = mineCurve === x, ok = can.includes(x);
    return h('button', { type: 'button', class: 'ghost' + (on ? ' pick' : ''), id: 'curve-' + x, disabled: !ok, 'aria-pressed': String(on), style: 'flex-direction:column;align-items:flex-start;gap:4px;min-height:76px;padding:10px 12px;text-transform:none' + (ok ? '' : ';opacity:.5'), onclick: () => { mineCurve = x; repaint(); } },
      h('span', { class: 'd', style: 'font-size:20px' }, Q[x].curve), h('span', null, ok ? `${price(c.price)} ${Q[x].per}` : 'not mined on this site'), h('span', null, ok ? `owed in ${Q[x].unit} on ${Q[x].chain}` : 'no Qwencoin node here'));
  }));
  return h('div', { class: 'pad col', style: 'gap:14px' },
    h('p', { class: 'soft', id: 'mine-pitch' }, PITCH.mine),
    h('p', { class: 'muted', style: 'font-size:13px' }, 'Pick the curve: the block pays your address, and what it owes is paid in that curve\'s coin, straight to whoever its draw named. Then the coins unlock.'),
    open ? pick : null,
    h('button', { class: 'btn wide', id: 'mineme', type: 'button', disabled: !open, onclick: ask }, !open ? 'Graduated: the curves are closed' : waitingOn(mineCurve) ? `Mine me a block (${waitingOn(mineCurve)} waiting)` : 'Mine me a block'),
    open && d.curves[mineCurve].next ? h('p', { class: 'm', id: 'mine-next', style: 'font-size:13px' }, `The next block on the ${Q[mineCurve].curve}: +${coins(d.curves[mineCurve].next.mint)} $${ticker}, owing up to ${owe(mineCurve, d.curves[mineCurve].next.owed)}.`) : null,
    open ? h('p', { class: 'muted', style: 'font-size:13px' }, mineCurve === 'qwen' ? `A block on the QWEN curve owes QWEN, paid on Qwencoin from your hashfun key (${W.pub ? keyAddr('qwen') : 'connect to see it'}). It needs QWEN there before you can pay.` : 'A block on the BTC curve owes sats, paid on Bitcoin from your hashfun key; the page tops it up from UniSat when you pay.') : null,
    box,
    h('p', { class: 'muted', style: 'font-size:13px' }, pool.cut_bps ? `The site keeps ${pool.cut_bps / 100}% of each block it mines for you, in coins.` : 'The site keeps nothing of the block.'),
    h('p', { class: 'muted', style: 'font-size:13px' }, 'Have hash? Point it here, your address as the username, and every block you find is yours whole. Add /btc or /qwen to the username to pick the curve:'),
    h('pre', { class: 'code' }, `stratum+tcp://${location.hostname}:${pool.stratum_port}\nuser: ${W.pub ? launchAddr(ticker) : '[YOUR ' + ticker + ' ADDRESS]'}/${mineCurve}`));
}

// Every payment the page asks the wallet for goes through here.
async function walletPay(address, sats) {
  const u = window.unisat;
  await rightChain(u, true);
  const accts = await u.getAccounts();
  if (!accts || accts[0] !== W.addr) throw new Error('UniSat is on another account than this page. Reload and connect again.');
  return u.sendBitcoin(address, sats);
}
// QWEN that sits at the wallet's own address on Qwencoin (a creator's share paid there, QWEN moved
// there) can only be moved by the wallet's key. A Qwencoin transaction is a Bitcoin-format
// transaction: the page writes it as a PSBT, the wallet signs it, the page checks that what came
// back spends and pays exactly what it asked for, and the site hands it to its Qwencoin node.
// vbytes per input by address kind, for the fee.
const IN_VB = { p2wpkh: 68, p2sh: 91, p2tr: 58 };
async function walletMoveQwen(to) {
  const u = window.unisat;
  if (!u || !u.signPsbt) throw new Error('This wallet cannot sign a transaction the page hands it.');
  await rightChain(u, true);
  const accts = await u.getAccounts();
  if (!accts || accts[0] !== W.addr) throw new Error('UniSat is on another account than this page. Reload and connect again.');
  const script = B.addressToScript(W.addr, cfg.qwen), kind = B.scriptKind(script), dest = B.addressToScript(to, cfg.qwen);
  if (!IN_VB[kind]) throw new Error('QWEN at a legacy address cannot be moved from this page. Any Qwencoin wallet holding that key can move it.');
  const us = (await api(`/chain/qwen/address/${W.addr}`)).utxos.filter((x) => x.confirmations > 0);
  const t = await api('/chain/qwen/time'), total = us.reduce((a, x) => a + x.value, 0), fee = t.feerate * (11 + IN_VB[kind] * us.length + 43);
  if (!us.length || total - fee < 600) throw new Error('Nothing at your wallet address on Qwencoin to move (after the network fee).');
  const outs = [{ value: total - fee, script: dest }];
  const pub = kind === 'p2wpkh' ? null : B.unhex(await u.getPublicKey());
  if (!confirm(`Move ${owe('qwen', total - fee)} from ${W.addr} on Qwencoin to ${to} on Qwencoin?\n\nUniSat will show it as a Bitcoin transaction of ${((total - fee) / COIN).toFixed(8)} BTC: the two chains write transactions the same way. It is signed for Qwencoin outputs and sent to this site's Qwencoin node only.`)) throw new Error('Not sent.');
  const signed = B.txFromPsbt(await u.signPsbt(B.psbtHex(us, script, outs, pub), { autoFinalized: true }));
  if (!B.sameSpend(signed.tx, us, outs)) throw new Error('The wallet returned a different transaction than the one this page asked for. Nothing was sent.');
  return { txid: (await api('/chain/qwen/tx', { hex: signed.hex })).txid, value: total - fee };
}
// QWEN at the hashfun key on Qwencoin: the page signs this one itself.
async function keyMoveQwen(to) {
  const dest = B.addressToScript(to, cfg.qwen);
  const us = (await api(`/chain/qwen/address/${keyAddr('qwen')}`)).utxos.filter((x) => x.confirmations > 0);
  const t = await api('/chain/qwen/time'), total = us.reduce((a, x) => a + x.value, 0), fee = t.feerate * (11 + 68 * us.length + 43);
  if (!us.length || total - fee < 600) throw new Error('Nothing at your hashfun key on Qwencoin to send (after the network fee).');
  return { txid: (await api('/chain/qwen/tx', { hex: B.txHex(B.signP2wpkh(W.key, us, [{ value: total - fee, script: dest }])) })).txid, value: total - fee };
}
async function connect(ask = true) {
  const u = window.unisat;
  if (!u) { if (ask) throw new Error('UniSat wallet not found in this browser'); return false; }
  const accts = ask ? await u.requestAccounts() : await u.getAccounts();
  if (!accts || !accts.length) return false;
  if (!(await rightChain(u, ask))) return false;
  let k = LS.getItem('hf_key_' + accts[0]);
  if (!k) {
    if (!ask) return false;
    k = B.hex(B.keyFromSignature(await u.signMessage(B.KEY_MESSAGE)));
    LS.setItem('hf_key_' + accts[0], k);
  }
  W.addr = accts[0]; W.key = B.unhex(k); W.pub = B.pubkey(W.key);
  B.addressToScript(W.addr, cfg.btc); // throws if the wallet is on another network
  paintWallet();
  return true;
}
const needWallet = async () => { if (!W.key && !(await connect(true))) throw new Error('wallet not connected'); };

// ---------------------------------------------------------------- swaps
// Swap records belong to the key that made them: another wallet account in the same browser
// cannot finish or refund them, so it does not see them.
const swapsKey = () => 'hf_swaps_' + (W.pub ? B.hex(W.pub).slice(0, 16) : 'none');
const swaps = () => JSON.parse(LS.getItem(swapsKey()) || '{}');
const saveSwap = (rec) => { const all = swaps(); all[rec.id] = rec; LS.setItem(swapsKey(), JSON.stringify(all)); };
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
    rec.init_txid = await walletPay(B.segwitEncode(cfg.btc.hrp, 0, spk.slice(2)), q.btc_amount);
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
const meter = (p, cls, label) => h('div', { class: 'meter ' + (cls || ''), role: 'img', 'aria-label': `${label || 'Curve'} ${(p * 100).toFixed(1)} percent mined` }, h('i', { style: `width:${Math.min(100, p * 100)}%` }));
// What holders were paid, on both chains: "0.0123 BTC + 4.2 QWEN".
const paidHolders = (c) => { const b = c.curves.btc.paid.holder, q = c.curves.qwen.paid.holder; return btc(b) + ' BTC' + (q ? ' + ' + qwen(q) + ' QWEN' : ''); };
const point = (c, x) => `${price(c.curves[x].price)} ${x === 'qwen' ? 'QWEN sats' : 'sats'}`;
// The QWEN price a coin's two curves imply, and what kind of number it is (web.py CoinIndex.implied).
const KIND = {
  'two-sided': ['two-sided', 'pill l', 'Both curves were mined in the last 100 blocks. Whoever mints picks the cheaper curve, so the two prices buy the same coin and their ratio is a price.'],
  floor: ['floor', 'pill', 'Only the BTC curve was mined lately. Were QWEN worth less than this, the QWEN curve would be the cheaper way in: to the people mining, QWEN is worth at least this.'],
  ceiling: ['ceiling', 'pill', 'Only the QWEN curve was mined lately. Were QWEN worth more than this, the BTC curve would be the cheaper way in: to the people mining, QWEN is worth at most this.'],
  start: ['start', 'pill w', 'No block yet: this is the ratio of the two starting prices, which the creator set. It becomes a price once both curves are mined.'],
  history: ['at graduation', 'pill w', 'The curves closed at graduation: this is where their two prices stood.'],
};
const perQwen = (x) => (x >= 100 ? fmt(Math.round(x)) : price(x));
// The same number where there is no room for all of it (a card on the board).
const compact = (x) => (x >= 1e9 ? (x / 1e9).toPrecision(3) + 'B' : x >= 1e6 ? (x / 1e6).toPrecision(3) + 'M' : x >= 1e4 ? (x / 1e3).toPrecision(3) + 'k' : perQwen(x));

function board(view) {
  let filter = 'all', query = '', last = {};
  const grid = h('div', { class: 'grid' }), feed = h('div', { class: 'feed' }), spot = h('div', { style: 'flex:4 1 340px;min-width:0' }), strip = h('section', { id: 'qwen-strip', style: 'padding-bottom:40px' });
  // The pitch, above the coins: whole on a first visit and on an empty board, one line after
  // that, never gone. Whether it has been seen is a convenience kept in this browser, nothing more.
  const pitch = h('section', { id: 'pitch', style: 'padding:40px 0 32px' });
  let pitchOpen = !LS.getItem('hf_pitch'), firstPaint = true;
  LS.setItem('hf_pitch', '1');
  const paintPitch = () => {
    const live = data.filter((c) => c.height != null), empty = !firstPaint && !live.length, open = pitchOpen || empty;
    const top = live.filter((c) => !c.graduated).sort((a, b) => b.progress - a.progress)[0] || live[0];
    const [w1, w2] = [PITCH.what.slice(0, PITCH.what.indexOf('.') + 1), PITCH.what.slice(PITCH.what.indexOf('.') + 1).trim()];
    pitch.setAttribute('data-open', open ? '1' : '0');
    if (!open) return pitch.replaceChildren(h('div', { class: 'panel between', style: 'align-items:center;padding:12px 16px;gap:8px 20px' },
      h('span', { style: 'display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 14px' }, h('span', { class: 'd', id: 'pitch-what', style: 'font-size:22px;line-height:1.1' }, w1 + ' ', h('span', { class: 'o' }, w2)), h('span', { class: 'm l', style: 'font-size:13px' }, PITCH.tagline)),
      h('button', { class: 'ghost', id: 'pitch-open', type: 'button', 'aria-expanded': 'false', onclick: () => { pitchOpen = true; paintPitch(); } }, 'What is this')));
    const pk = qw && qw.pockets, parts = PITCH.pockets.split('{n}'), addAt = parts[1].lastIndexOf('Add yours');
    pitch.replaceChildren(h('div', { class: 'row', style: 'align-items:flex-start;gap:28px' },
      h('div', { class: 'col', style: 'flex:5 1 520px;gap:22px' },
        h('h1', { class: 'd h1', id: 'pitch-what' }, w1, h('br'), h('span', { class: 'o' }, w2)),
        h('ol', { id: 'pitch-facts', style: 'list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(min(220px,100%),1fr));gap:12px' },
          [['fact_chain', O], ['fact_prices', WHT], ['fact_holders', L]].map(([k, c], i) => h('li', { class: 'panel pad col', style: `gap:8px;border-top:3px solid ${c}`, 'data-fact': k }, h('span', { class: 'd', 'aria-hidden': 'true', style: `font-size:30px;line-height:1;color:${c}` }, i + 1), h('p', { class: 'soft' }, PITCH[k])))),
        h('div', { class: 'row', style: 'gap:14px;align-items:center' },
          top ? h('a', { class: 'btn', id: 'way-mine', href: `#/c/${top.ticker}/mine` }, 'Mine a coin') : null,
          h('a', { class: top ? 'btn white' : 'btn', id: 'way-make', href: '#/launch' }, 'Make a coin'),
          empty ? h('span', { class: 'm muted', style: 'font-size:13px' }, 'No coin here yet. The first one is yours to make.') : h('a', { class: 'ghost', style: 'min-height:56px', href: '#how' }, 'How it works'),
          pitchOpen && !empty && !firstPaint ? h('button', { class: 'ghost', id: 'pitch-hide', type: 'button', style: 'min-height:56px', onclick: () => { pitchOpen = false; paintPitch(); } }, 'Hide') : null)),
      h('aside', { class: 'col', id: 'pitch-why', style: 'flex:3 1 320px;gap:14px;padding:20px;border:2px solid #C7F23E;background:#131315' },
        h('div', { class: 'col', style: 'gap:10px' }, h('span', { class: 'lab l' }, PITCH.tagline), h('p', { style: 'font-size:17px;line-height:1.5' }, PITCH.why)),
        pk ? h('p', { class: 'm', id: 'pitch-pockets', style: 'font-size:13px;padding-top:12px;border-top:1px solid #2C2C31' }, parts[0], h('b', { class: 'l', style: 'font-size:16px' }, fmt(pk.n)), parts[1].slice(0, addAt), h('a', { href: pk.add, target: '_blank', rel: 'noopener noreferrer' }, 'Add yours'), parts[1].slice(addAt + 9)) : null)));
  };
  const filters = [['all', 'All'], ['curve', 'On the curves'], ['new', 'New'], ['close', 'Graduating'], ['grad', 'Graduated']];
  const fbar = h('div', { class: 'row', style: 'gap:8px;align-items:center' });
  const paintFilters = () => fbar.replaceChildren(...filters.map(([k, label]) => h('button', { class: 'ghost' + (filter === k ? ' on' : ''), type: 'button', 'aria-pressed': String(filter === k), onclick: () => { filter = k; paintFilters(); paint(); } }, label)),
    h('label', { class: 'field', style: 'min-height:44px' }, h('span', { class: 'lab' }, 'Search'), h('input', { type: 'search', value: query, style: 'min-height:40px;font-size:14px;width:140px', oninput: (e) => { query = e.target.value.toUpperCase().replace('$', ''); paint(); } })));
  let data = [], qw = null, pocketsWas, hadCoins = null;
  // QWEN across the site: what the coins' curves imply (the median of those with both curves being
  // mined) and, beside it, what the BTC/QWEN book says. Neither is made from the other.
  const paintStrip = () => {
    if (!qw) return strip.replaceChildren();
    const imp = qw.implied, each = imp.each || [], floors = each.filter((x) => x.kind === 'floor').map((x) => x.sats_per_qwen), ceils = each.filter((x) => x.kind === 'ceiling').map((x) => x.sats_per_qwen);
    const bounds = [floors.length ? `at least ${perQwen(Math.max(...floors))}` : '', ceils.length ? `at most ${perQwen(Math.min(...ceils))}` : ''].filter(Boolean).join(', ');
    const bk = qw.book || {}, side = (k, o) => h('span', { class: 'stat' }, k, h('b', { id: 'qwen-' + k }, o ? perQwen(o.price) + ' sats' : 'none'));
    strip.replaceChildren(h('div', { class: 'panel pad row', style: 'align-items:center;gap:14px 32px;border:2px solid #F2F0EC' },
      h('div', { style: 'display:flex;align-items:center;gap:14px' }, assetTile('qwen'), h('div', { class: 'col', style: 'gap:2px' }, h('span', { class: 'lab' }, 'QWEN, as the curves imply it'),
        h('span', { style: 'display:flex;align-items:baseline;gap:10px;flex-wrap:wrap' }, h('span', { class: 'd l', id: 'qwen-implied', style: 'font-size:40px;line-height:1' }, imp.sats_per_qwen != null ? `1 QWEN = ${perQwen(imp.sats_per_qwen)}` : 'No two-sided price yet'), imp.sats_per_qwen != null ? h('span', { class: 'm' }, 'sats') : null))),
      h('p', { class: 'muted', style: 'flex:1 1 280px;font-size:13px' }, imp.sats_per_qwen != null ? `The median over ${imp.launches} of ${imp.of} coin${imp.of === 1 ? '' : 's'} on their curves whose BTC curve and QWEN curve were both mined in the last 100 blocks. Whoever mints picks the cheaper curve; that is all that sets it.`
        : `A coin implies a QWEN price while both of its curves are being mined; none is right now.${bounds ? ` One-sided so far: QWEN is worth ${bounds} sats to the people mining.` : ''}`),
      qw.node ? h('div', { class: 'row', style: 'gap:10px 24px;align-items:center' }, h('span', { class: 'lab' }, 'BTC/QWEN book'), side('bid', bk.bid), side('ask', bk.ask), h('a', { class: 'ghost', href: '#/swap/btc/qwen' }, 'Trade QWEN'))
        : h('span', { class: 'm muted', style: 'font-size:12px' }, 'This site has no Qwencoin node: QWEN is not traded or paid here.')));
  };
  const paint = () => {
    const match = (c) => (filter === 'all' || (filter === 'curve' && !c.graduated) || (filter === 'new' && !c.graduated && c.progress < 0.1) || (filter === 'close' && !c.graduated && c.progress >= 0.75) || (filter === 'grad' && c.graduated)) && (!query || c.ticker.includes(query) || c.name.toUpperCase().includes(query));
    const live = data.filter((c) => c.height != null);
    const cards = live.filter(match).map((c) => {
      const [st, cls] = status(c), hot = last[c.ticker] != null && last[c.ticker] !== c.height, imp = c.implied;
      return h('a', { class: 'card' + (hot ? ' hot' : ''), href: `#/c/${c.ticker}` },
        h('div', { style: 'display:flex;align-items:center;gap:12px' }, tile(c.ticker, false, c.image || null), h('div', { style: 'flex:1;min-width:0' }, h('div', { style: 'font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis' }, c.name), h('div', { class: 'm muted', style: 'font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis' }, `$${c.ticker} · ${ago(c.genesis_time)} · ${short(c.creator)}`)), h('span', { class: cls }, st)),
        h('div', { class: 'col', style: 'gap:6px' }, CURVES.map((x) => h('div', { class: 'col', style: 'gap:4px' }, h('div', { class: 'between m', style: 'font-size:12px' }, h('span', { class: 'lab', style: `color:${Q[x].color}` }, Q[x].curve, h('span', { class: 'muted', style: 'font-weight:400;letter-spacing:0' }, ' ' + pct(c.curves[x].progress))), h('b', { 'data-point': x }, point(c, x) + ' per coin')), meter(c.curves[x].progress, x === 'qwen' ? 'w' : '', Q[x].curve)))),
        h('div', { style: 'display:flex;justify-content:space-between;gap:10px' }, h('span', { class: 'stat' }, '1 QWEN =', h('b', { 'data-implied': imp ? imp.kind : '' }, imp ? compact(imp.sats_per_qwen) + ' sats' : 'nothing yet'), imp ? h('span', null, KIND[imp.kind][0]) : null),
          h('span', { class: 'stat' }, 'paid to holders', h('b', { class: 'l' }, btc(c.curves.btc.paid.holder) + ' BTC'), h('b', { class: 'l' }, qwen(c.curves.qwen.paid.holder) + ' QWEN')), h('span', { class: 'stat', style: 'text-align:right' }, c.graduated ? 'merged' : 'last block', h('b', null, ago(c.last_block_time)))));
    });
    grid.replaceChildren(...(cards.length ? cards : [h('div', { class: 'panel pad col' }, h('span', { class: 'd', style: 'font-size:30px' }, 'Nothing here yet'), h('a', { href: '#/launch' }, 'Launch the first one'))]));
    live.forEach((c) => { last[c.ticker] = c.height; });
    const top = live.filter((c) => !c.graduated).sort((a, b) => b.progress - a.progress)[0];
    const lead = top ? CURVES.slice().sort((a, b) => top.curves[b].progress - top.curves[a].progress)[0] : null;
    spot.replaceChildren(top ? h('a', { class: 'card', style: 'border-color:#C7F23E;padding:22px', href: `#/c/${top.ticker}` }, h('div', { class: 'between lab l' }, 'Closest to graduation', h('span', null, h('span', { class: 'dot' }), ' ', ago(top.last_block_time))),
      h('div', { style: 'display:flex;align-items:center;gap:14px' }, tile(top.ticker, false, top.image || null), h('div', null, h('div', { style: 'font-size:20px;font-weight:700' }, top.name), h('div', { class: 'm muted', style: 'font-size:13px' }, `$${top.ticker} · by ${short(top.creator)}`))),
      h('div', { class: 'd l', style: 'font-size:clamp(64px,9vw,104px);line-height:.9' }, pct(top.progress)), meter(top.progress, 'l tall', Q[lead].curve),
      h('p', { class: 'soft' }, `${coins(top.curve_tokens - top.curves[lead].supply)} coins left on its ${Q[lead].curve}. The first curve to sell out graduates the coin; after that Bitcoin's own miners can secure it.`), h('span', { class: 'btn lime', style: 'box-shadow:none' }, 'Ape in')) : '');
    const pays = live.flatMap((c) => (c.recent || []).map((p) => ({ ...p, t: c.ticker }))).sort((a, b) => b.time - a.time).slice(0, 6);
    feed.replaceChildren(...(pays.length ? pays.map((p) => h('div', null, h('div', { class: 'm between' }, h('b', { class: 'l', style: 'font-size:16px' }, `+${owe(p.quote || 'btc', p.pay)}`), h('span', { class: 'muted', style: 'font-size:12px' }, ago(p.time))), h('span', { class: 'm muted', style: 'font-size:12px' }, `${short(p.pay_to)} on ${Q[p.quote || 'btc'].chain}, holding `, h('span', { style: 'color:#F2F0EC' }, '$' + p.t)))) : [h('div', { class: 'muted' }, 'No payouts yet.')]));
  };
  paintFilters(); paintPitch();
  const lively = h('section', { class: 'row', style: 'padding-bottom:40px;align-items:stretch' }, spot,
    h('div', { class: 'panel', style: 'flex:3 1 280px;min-width:0' }, h('div', { class: 'between lab', style: 'padding:14px 16px;border-bottom:1px solid #2C2C31' }, 'Paid to holders', h('span', { class: 'l' }, h('span', { class: 'dot' }), ' live')), feed, h('p', { class: 'muted', style: 'padding:12px 16px;font-size:13px' }, 'Each block on a curve owes sats or QWEN. One holder is drawn by bag size and paid on that chain, at the key that holds the coins.')));
  view.replaceChildren(
    pitch, lively, strip,
    h('section', { class: 'col', style: 'gap:20px;padding-bottom:64px' }, h('div', { class: 'between', style: 'align-items:center' }, h('h2', { class: 'd h2' }, 'The board'), fbar), grid),
    h('section', { id: 'how', class: 'col', style: 'gap:20px' }, h('h2', { class: 'd h2' }, 'How it works'), h('div', { class: 'grid', style: 'grid-template-columns:repeat(auto-fit,minmax(min(260px,100%),1fr))' },
      [['1', 'Launch', O, 'Name, ticker, target. A new proof-of-work chain starts at block zero. Nobody holds a coin until work is done.'], ['2', 'Buy is mint', O, 'Point hash at it, or have a block mined for you. Every coin has two curves, one owed in sats and one in QWEN: the more work done on a curve, the higher its price. Mint on whichever is cheaper.'], ['3', 'Hold is earn', L, 'Every curve block owes sats or QWEN. 80% goes to a holder drawn by bag size, 10% to the creator, 10% to hashfun. No staking, no opt in.'], ['4', 'Graduate', L, 'The first curve to sell out graduates the coin: the chain opens to merge-mining with Bitcoin. Coin, sats and QWEN all trade for each other by atomic swap, wallet to wallet.']]
        .map(([n, t, c, body]) => h('div', { class: 'panel pad col', style: 'gap:10px' }, h('span', { class: 'd', style: `font-size:44px;line-height:1;color:${c}` }, n), h('span', { class: 'd', style: 'font-size:24px' }, t), h('p', { class: 'soft' }, body))))));
  every(1500, async () => {
    [data, qw] = await Promise.all([api('/board'), api('/qwen').catch(() => qw)]);
    const has = data.some((c) => c.height != null), pk = JSON.stringify((qw && qw.pockets) || null);
    paint(); paintStrip();
    lively.hidden = !has; // of an empty board there is nothing to show but the pitch
    // The block is repainted when what it shows changed (the first answer, the first coin, the
    // count), not on every poll: a visitor reading it or about to click is left alone.
    if (firstPaint || pk !== pocketsWas || has !== hadCoins) { firstPaint = false; pocketsWas = pk; hadCoins = has; paintPitch(); }
  });
}

function coin(view, ticker, open) {
  let d = null, orders = [], tab = 'blocks', side = open === 'mine' ? 'mine' : 'buy', spend = 50000, sell = 0, q = null, qerr = '', me = null, seen = 0, wonAt = 0;
  const head = h('section'), blurb = h('div'), stats = h('div'), chart = h('div', { class: 'panel chart' }), prog = h('div', { class: 'panel pad col', style: 'gap:14px' }), tabsBox = h('div', { class: 'panel' }), trade = h('div', { class: 'trade' }), bag = h('div');
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
    const leg = d ? d.curves.btc.price : 0, share = q && q.price ? Math.min(1, leg / q.price) : 0;
    out.replaceChildren(
      h('span', { class: 'lab' }, 'You get about'),
      h('div', { style: 'display:flex;align-items:baseline;gap:10px' }, h('span', { class: 'd ' + (side === 'buy' ? 'o' : ''), id: 'q-get', style: 'font-size:52px;line-height:1' }, q ? (side === 'buy' ? coins(q.amount) : fmt(q.btc_amount)) : '…'), h('span', { class: 'm' }, side === 'buy' ? '$' + ticker : 'sats')),
      q ? h('div', null, h('div', { class: 'kv' }, h('span', null, 'Price'), h('span', { id: 'q-price' }, price(q.price) + ' sats per coin')), h('div', { class: 'kv' }, h('span', null, 'Speed'), side === 'buy' ? h('b', { class: q.instant ? 'l' : '' }, q.instant ? 'instant' : `${q.btc_confs} Bitcoin confirmation${q.btc_confs === 1 ? '' : 's'}`) : h('span', null, 'after 1 Bitcoin confirmation')),
        side === 'buy' ? h('div', { class: 'kv' }, h('span', null, 'Where the sats go'), h('span', { style: 'text-align:right' }, `${Math.round((1 - share) * 100)}% hash, ${Math.round(share * 80)}% holders, ${Math.round(share * 10)}% creator, ${Math.round(share * 10)}% hashfun`)) : null) : h('p', { class: qerr ? 'err' : 'muted', style: 'font-size:13px' }, qerr || 'asking the maker'),
      h('button', { class: 'btn wide' + (side === 'sell' ? ' white' : ''), id: 'go', type: 'button', disabled: !q || !(q.amount > 0), onclick: go }, side === 'buy' ? 'Buy with UniSat' : 'Sell to the maker'),
      h('p', { class: 'muted', style: 'font-size:13px' }, side === 'buy' ? 'Atomic swap, wallet to wallet. The coins land in your wallet, or your sats come back after the timelock.' : 'There is no reserve and no floor: you sell to a bid, by atomic swap. Coins you sell stop earning.'));
  };
  const paintTrade = () => {
    const sides = h('div', { class: 'sides' }, ['buy', 'sell', 'mine'].map((k) => h('button', { type: 'button', class: side === k ? 'on' : '', 'aria-pressed': String(side === k), onclick: () => { side = k; paintTrade(); if (k !== 'mine') quote(); } }, k)));
    let body;
    if (side === 'mine') {
      const desc = d ? 'data:application/json,' + encodeURIComponent(JSON.stringify(d.descriptor, null, 2)) : '#';
      if (d && d.pool) body = minePanel(ticker, d, () => { if (side === 'mine') paintTrade(); });
      else body = h('div', { class: 'pad col', style: 'gap:14px' }, h('p', { class: 'soft' }, 'The cheapest way in: no maker in between. Point SHA-256 hash at this coin and blocks pay you directly, on the curve you pick.'),
        h('a', { class: 'ghost', href: desc, download: `${ticker.toLowerCase()}.json` }, 'Download the descriptor'),
        h('pre', { class: 'code' }, `npm i -g hashfun\nhashfun node add ${ticker.toLowerCase()}.json --peer ${location.hostname}:${d && d.p2p_port ? d.p2p_port : '[PORT]'}\nhashfun node up ${ticker}\nhashfun mine ${ticker} --curve btc \\\n  --payout ${W.pub ? launchAddr(ticker) : '[YOUR ' + ticker + ' ADDRESS]'} \\\n  --btc-rpc [YOUR BITCOIN NODE]\n# or the QWEN curve: --curve qwen --qwen-rpc [YOUR QWENCOIN NODE]`),
        h('p', { class: 'muted', style: 'font-size:13px' }, 'Each block you mine owes sats (BTC curve) or QWEN (QWEN curve) to the drawn holder. The miner pays it from its own wallet on that chain, automatically, before the coins unlock.'));
    } else if (!cfg.maker) {
      body = h('div', { class: 'pad col' }, h('p', { class: 'soft' }, 'No instant maker on this site right now. Trade it peer to peer, for sats or for QWEN, or mine it.'), h('a', { class: 'btn wide', href: `#/swap/btc/${ticker}` }, 'Open the book'));
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
    const bal = me ? me.balance : 0, odds = me && me.earning_supply ? ((me.earning ?? bal) / me.earning_supply) * 0.8 : 0, won = Date.now() - wonAt < 6000;
    bag.replaceChildren(h('div', { class: 'bag pad col' + (won ? ' won' : '') }, h('div', { class: 'between lab' }, 'Your bag', h('span', null, short(launchAddr(ticker)))),
      won ? h('div', { class: 'd', style: 'font-size:48px;line-height:.95' }, 'You won') : h('div', null, h('div', { class: 'm muted', style: 'font-size:12px' }, d && d.graduated ? 'Payouts ended at graduation' : 'Your odds, every block'), h('div', { class: 'd l', id: 'odds', style: 'font-size:48px;line-height:.95' }, odds > 0 && !(d && d.graduated) ? '1 in ' + fmt(Math.max(1, Math.round(1 / odds))) : 'none yet')),
      h('div', { class: 'stat' }, 'holding', h('b', { id: 'bal' }, coins(bal) + ' $' + ticker)), h('span', { class: 'muted', style: 'font-size:13px' }, 'A block on the BTC curve pays your key on Bitcoin, a block on the QWEN curve pays the same key on Qwencoin. Nothing to claim, nothing to stake.')));
  };
  const paint = () => {
    const [st, cls] = status(d), cv = d.curves, imp = d.implied;
    head.replaceChildren(h('div', { class: 'between', style: 'align-items:center;padding-top:28px' }, h('div', { style: 'display:flex;align-items:center;gap:16px;min-width:0' }, tile(ticker, true, d.image || null), h('div', { class: 'col', style: 'gap:6px' }, h('h1', { class: 'd', style: 'font-size:clamp(36px,5vw,54px);line-height:.95' }, d.name), h('div', { class: 'm muted row', style: 'gap:6px 14px;font-size:13px' }, h('b', { style: 'color:#F2F0EC' }, '$' + ticker), [`by ${short(d.creator)}`, `launched ${since(d.genesis_time)}`, `id ${d.id.slice(0, 6)}…${d.id.slice(-4)}`, `block ${fmt(d.height)}`, hashrate(d.hashrate)].map((x) => h('span', null, x))))), h('span', { class: cls, style: 'padding:8px 12px;font-size:12px' }, st)));
    const links = Object.entries(d.links || {}).filter(([, u]) => /^https:\/\//.test(u));
    blurb.replaceChildren(...(d.description || links.length ? [h('div', { class: 'panel pad col', style: 'gap:10px' }, h('span', { class: 'lab' }, 'In its creator\'s words'), d.description ? h('p', { class: 'soft', id: 'blurb', style: 'white-space:pre-line;overflow-wrap:anywhere' }, d.description) : null,
      links.length ? h('div', { class: 'row', style: 'gap:8px' }, links.map(([k, u]) => h('a', { class: 'ghost', href: u, target: '_blank', rel: 'noopener noreferrer nofollow' }, k === 'x' ? 'X' : k))) : null)] : []));
    // The two price points, each in its own quote, and what the pair says QWEN is worth.
    const left = (x) => Math.max(0, cv[x].total * (d.graduated ? 0 : 1) - (d.graduated ? 0 : cv[x].paid.holder + cv[x].paid.creator + cv[x].paid.dev));
    const tileOf = (x) => h('div', { class: 'col', style: 'gap:4px;flex:1 1 200px', 'data-curve': x }, h('span', { class: 'lab', style: `color:${Q[x].color}` }, Q[x].curve),
      h('span', { style: 'display:flex;align-items:baseline;gap:10px;flex-wrap:wrap' }, h('span', { class: 'd', id: x === 'btc' ? 'price' : 'price-qwen', style: `font-size:clamp(44px,6vw,72px);line-height:.9;color:${Q[x].color}` }, price(cv[x].price)), h('span', { class: 'm muted' }, Q[x].per)),
      h('span', { class: 'm muted', style: 'font-size:12px' }, `owed on ${Q[x].chain} by whoever mines a coin here`));
    const [kn, kcls, kwhy] = imp ? KIND[imp.kind] : [];
    stats.replaceChildren(h('div', { class: 'row', style: 'gap:18px 28px;align-items:flex-start' }, tileOf('btc'), tileOf('qwen'),
      h('div', { class: 'col', style: 'gap:4px;flex:1 1 220px', id: 'implied' }, h('span', { class: 'lab l' }, 'Together they imply'),
        imp ? h('span', { style: 'display:flex;align-items:baseline;gap:10px;flex-wrap:wrap' }, h('span', { class: 'd l', id: 'implied-price', style: 'font-size:clamp(30px,4vw,44px);line-height:1' }, `1 QWEN = ${perQwen(imp.sats_per_qwen)}`), h('span', { class: 'm muted' }, 'sats'), h('span', { class: kcls, id: 'implied-kind' }, kn))
          : h('span', { class: 'm muted' }, 'nothing yet'),
        imp ? h('span', { class: 'm muted', style: 'font-size:12px' }, kwhy + ' The hash itself, the same on both curves, is left out.') : null)),
    h('div', { class: 'row', style: 'gap:10px 28px;margin-top:16px' }, h('span', { class: 'stat' }, 'paid to holders', h('b', { class: 'l', style: 'font-size:16px' }, paidHolders(d))), h('span', { class: 'stat' }, 'still to be won', h('b', { class: 'l', style: 'font-size:16px' }, `${btc(left('btc'))} BTC + ${qwen(left('qwen'))} QWEN`)), h('span', { class: 'stat' }, 'holders', h('b', { style: 'font-size:16px' }, fmt(d.holders))),
      h('span', { class: 'm muted', style: 'font-size:12px;flex:1 1 260px;align-self:center' }, 'QWEN sats: hundred-millionths of a QWEN, as sats are of a bitcoin.')));
    // One chart for both curves: each curve's price as a multiple of its own first coin. The two
    // curves have the same shape, so the same height is the same distance along the curve.
    const mult = (x) => (p) => p / (cv[x].price_at_start || 1), ser = Object.fromEntries(CURVES.map((x) => [x, d.series[x].map(([hgt, p]) => [hgt, mult(x)(p)])]));
    const grad = cv.btc.price_at_graduation / (cv.btc.price_at_start || 1), vals = CURVES.flatMap((x) => ser[x].map((p) => p[1])), hi = Math.max(...vals, 1), pad = Math.max((hi - 1) * 0.12, 0.02);
    const top = hi + pad, bot = 1, any = ser.btc, x0 = any.length ? any[0][0] : 0, x1 = any.length ? any[any.length - 1][0] : 1;
    const yOf = (p) => 280 - ((p - bot) / (top - bot)) * 260;
    const pts = (x) => ser[x].map(([hgt, p]) => `${(10 + ((hgt - x0) / Math.max(1, x1 - x0)) * 860).toFixed(1)},${yOf(p).toFixed(1)}`).join(' ');
    const gOn = grad <= top, gy = yOf(grad).toFixed(1), now = (x) => mult(x)(cv[x].price).toFixed(2) + 'x';
    chart.replaceChildren(h('div', { class: 'lab', style: 'padding:10px 12px;border-bottom:1px solid #2C2C31;display:flex;flex-wrap:wrap;gap:6px 18px' }, h('span', null, 'Price on each curve, times its first coin'), CURVES.map((x) => h('span', { style: `color:${Q[x].color}` }, `${Q[x].curve} ${now(x)}`)), h('span', { class: 'l' }, `graduation at ${grad.toFixed(1)}x`)),
      h('div', { style: 'position:relative' }, s('svg', { viewBox: '0 0 900 300', preserveAspectRatio: 'none', role: 'img', 'aria-label': `Price on each curve since launch as a multiple of its first coin: the BTC curve is at ${now('btc')}, the QWEN curve at ${now('qwen')}; a curve graduates the coin at ${grad.toFixed(1)}x` },
        [20, 85, 150, 215, 280].map((y) => s('line', { x1: 0, x2: 900, y1: y, y2: y, stroke: '#1F1F23', 'vector-effect': 'non-scaling-stroke' })),
        gOn ? s('line', { x1: 0, x2: 900, y1: gy, y2: gy, stroke: L, 'stroke-width': 2, 'stroke-dasharray': '8 8', 'vector-effect': 'non-scaling-stroke' }) : null,
        pts('btc') ? s('polygon', { points: `${pts('btc')} 870,280 10,280`, fill: O, opacity: 0.12 }) : null,
        CURVES.map((x) => (pts(x) ? s('polyline', { points: pts(x), fill: 'none', stroke: Q[x].color, 'stroke-width': 3, 'stroke-linejoin': 'round', 'vector-effect': 'non-scaling-stroke', 'data-line': x }) : null))),
      h('span', { class: 'm muted', style: 'position:absolute;left:10px;top:12px;font-size:11px' }, top.toFixed(2) + 'x'), h('span', { class: 'm muted', style: 'position:absolute;left:10px;top:264px;font-size:11px' }, '1x')),
      h('div', { class: 'm muted between', style: 'padding:8px 12px;border-top:1px solid #2C2C31;font-size:11px' }, h('span', null, 'block ' + fmt(x0)), h('span', null, 'a curve only moves when a block is mined on it'), h('span', null, 'block ' + fmt(x1))));
    prog.replaceChildren(...CURVES.map((x) => h('div', { class: 'col', style: 'gap:8px', 'data-progress': x }, h('div', { class: 'between' }, h('span', { style: 'display:flex;align-items:baseline;gap:10px' }, h('span', { class: 'd', style: `font-size:34px;line-height:1;color:${Q[x].color}` }, pct(cv[x].progress)), h('span', { class: 'lab' }, `of the ${Q[x].curve} mined`)),
      h('span', { class: 'm', style: 'font-size:13px' }, d.graduated ? (d.graduated_by === x ? `sold out: graduated the coin at block ${fmt(d.graduation_height)}` : `closed at graduation, ${coins(d.curve_tokens - cv[x].supply)} coins never minted`) : `${coins(d.curve_tokens - cv[x].supply)} coins left · ${fmt(cv[x].blocks)} block${cv[x].blocks === 1 ? '' : 's'}${cv[x].last_time ? ', last ' + since(cv[x].last_time) : ', none yet'}`)), meter(cv[x].progress, (x === 'qwen' ? 'w' : '') + ' tall', Q[x].curve))),
    h('p', { class: 'muted', style: 'font-size:13px' }, 'The first curve to sell out graduates the coin: the chain opens to merge-mining, so Bitcoin miners can secure it at no extra cost, the payouts to holders end, and what the other curve has not sold is never minted.'));
    const mine = W.pub ? launchAddr(ticker) : null, myOut = W.pub ? { btc: btcAddr(), qwen: cfg.qwen ? keyAddr('qwen') : btcAddr() } : {};
    let content;
    if (tab === 'blocks') {
      const cols = 'grid-template-columns:84px 50px 118px 62px minmax(0,1fr) minmax(0,1.7fr)';
      content = h('div', { class: 'table' }, h('div', null, h('div', { class: 'tr head', style: cols }, h('span', null, 'Block'), h('span', null, 'Age'), h('span', null, 'Miner'), h('span', null, 'Curve'), h('span', null, 'Minted'), h('span', null, 'Paid to')),
        d.blocks.map((b) => { const qt2 = b.quote || b.on || 'btc', you = b.pay_to && b.pay_to === myOut[qt2] && b.pay > 0; return h('div', { class: 'tr' + (you ? ' you' : '') + (b.height > seen && seen ? ' new' : ''), style: cols, 'data-on': b.on || '' }, h('b', null, fmt(b.height)), h('span', { class: 'muted' }, ago(b.time)), h('span', { class: 'muted' }, b.miner === mine ? 'you' : short(b.miner)),
          h('span', { style: b.on ? `color:${Q[b.on].color}` : '', class: b.on ? '' : 'muted' }, b.on ? Q[b.on].unit === 'sats' ? 'BTC' : 'QWEN' : b.auxpow ? 'merged' : 'tail'), h('span', { class: 'o' }, `+${coins(b.minted)}`),
          h('b', { class: b.settled && b.payee === 'holder' ? 'l' : b.settled ? '' : 'muted', style: 'white-space:nowrap;overflow:hidden;text-overflow:ellipsis' }, !b.curve || !b.owed ? (b.auxpow ? 'merge-mined' : 'nothing owed') : !b.draw_known ? `draw in ${Math.max(1, b.height + 6 - d.height)} blocks` : !b.pay ? 'no payout this block' : `${b.settled ? '+' : 'owes '}${owe(qt2, b.pay)} · ${you ? 'YOU' : b.payee === 'holder' ? 'holder ' + short(b.pay_to) : b.payee === 'dev' ? 'hashfun' : 'creator'}`)); })));
    } else if (tab === 'holders') {
      const cols = 'grid-template-columns:40px minmax(0,1.4fr) minmax(0,1fr) 90px 130px', max = d.top_holders.length ? d.top_holders[0].value : 1;
      content = h('div', { class: 'table' }, h('div', null, h('div', { class: 'tr head', style: cols }, h('span', null, '#'), h('span', null, 'Holder'), h('span', null, 'Bag'), h('span', null, 'Share'), h('span', null, 'Odds per block')),
        d.top_holders.map((x, i) => h('div', { class: 'tr' + (x.address === mine ? ' you' : ''), style: cols }, h('span', { class: 'muted' }, i + 1), h('b', null, x.address === mine ? 'you' : short(x.address) + (x.address === d.creator ? ' (creator)' : '')), h('span', { style: 'display:flex;align-items:center;gap:10px' }, h('i', { style: `display:block;height:10px;width:${Math.max(4, Math.round((x.value / max) * 120))}px;background:${O}` }), coins(x.value)), h('span', null, ((x.value / d.earning_supply) * 100).toFixed(2) + '%'), h('span', { class: 'l' }, d.graduated ? 'ended' : '1 in ' + fmt(Math.max(1, Math.round(d.earning_supply / x.value / 0.8))))))));
    } else if (tab === 'book') {
      content = bookTab(ticker, orders);
    } else {
      const de = d.descriptor;
      content = h('div', { class: 'pad', style: 'display:grid;grid-template-columns:repeat(auto-fit,minmax(min(280px,100%),1fr));gap:0 32px' }, [['Curves', 'two: BTC and QWEN, same shape'], ['Coins on each curve', coins(d.curve_tokens)], ['Minted on the curves so far', coins(d.curve_supply)], ['Most that can ever exist', coins(d.total_tokens + d.curve_tokens)], ['Premine', '0'], ['Creator fee', `${d.creator_fee_bps / 100}% of minted coins`],
        ['Owed over the BTC curve', btc(cv.btc.total) + ' BTC, on Bitcoin'], ['Owed over the QWEN curve', qwen(cv.qwen.total) + ' QWEN, on Qwencoin'], ['Split of what a block owes', '80 holders / 10 creator / 10 hashfun'], ['Block time', d.target_spacing + ' s'], ['Floor or reserve', 'none'],
        ['Creator on Bitcoin', short(cv.btc.creator)], ['Creator on Qwencoin', short(cv.qwen.creator)], ['Bitcoin anchor height', fmt(de.btc_anchor_height)], ['Qwencoin anchor height', fmt(de.qwen_anchor_height)], ['Confirmations before a payment counts', `${cv.btc.confs} on Bitcoin, ${cv.qwen.confs} on Qwencoin`],
        ['Launch id', d.id.slice(0, 10) + '…' + d.id.slice(-6)], ['Picture and description', d.meta ? `sha256 ${d.meta.slice(0, 10)}…, fixed by the genesis block` : 'none']].map(([k, v]) => h('div', { class: 'kv' }, h('span', null, k), h('span', { style: 'text-align:right' }, v))));
    }
    tabsBox.replaceChildren(h('div', { class: 'tabs' }, ['blocks', 'holders', 'book', 'about'].map((k) => h('button', { type: 'button', class: tab === k ? 'on' : '', id: 'tab-' + k, 'aria-pressed': String(tab === k), onclick: () => { tab = k; paint(); } }, k))), content);
    const mineWon = (b) => b.pay_to && b.pay_to === myOut[b.quote || 'btc'] && b.settled && b.pay > 0;
    if (W.pub && seen && d.blocks.some((b) => mineWon(b) && b.height > seen - 40 && !SS.getItem('won' + ticker + b.height))) { d.blocks.filter(mineWon).forEach((b) => SS.setItem('won' + ticker + b.height, '1')); wonAt = Date.now(); }
    seen = d.height;
    paintBag();
  };
  view.replaceChildren(h('p', { class: 'muted', style: 'padding-top:28px' }, 'Loading $' + ticker));
  let built = false, wasMine = '';
  every(1000, async () => {
    d = await api('/coin/' + ticker);
    if (d.height == null) { view.replaceChildren(h('p', { class: 'err', style: 'padding-top:28px' }, d.error || 'This launch is not running here.')); return; }
    if (W.pub) me = await api(`/coin/${ticker}/address/${launchAddr(ticker)}`).catch(() => me);
    orders = await book.list().catch(() => orders);
    if (!built) {
      built = true;
      // Under the name: what this is, in the pitch's words, and right after it the two price points.
      view.replaceChildren(head, h('p', { class: 'soft', id: 'coin-pitch', style: 'padding-top:14px;max-width:860px;font-size:16px' }, PITCH.coin.replaceAll('{TICKER}', '$' + ticker)),
        h('div', { class: 'row', style: 'align-items:flex-start;margin-top:22px' }, h('div', { class: 'col', style: 'flex:999 1 560px;gap:20px' }, stats, blurb, chart, prog, tabsBox), h('aside', { class: 'col side', style: 'flex:1 1 380px;gap:20px' }, trade, bag)));
      paintTrade();
      if (cfg.maker && side !== 'mine') quote();
    }
    // The mine panel shows each curve's price and queue: repaint it when those change, not on every poll.
    const sig = d.pool ? JSON.stringify([d.pool.queues || d.pool.queue, d.graduated, CURVES.map((x) => price(d.curves[x].price))]) : '';
    if (side === 'mine' && sig !== wasMine) paintTrade();
    wasMine = sig;
    paint();
  });
}

function launchForm(view) {
  // The CPU preset is for trying things out (a laptop can mine it; so can anyone else, cheaply).
  const grads = [['CPU test', 'minutes of one core', 5e7, 0x1f01ffff], ['Degen', '1 rig-day', 1.728e19], ['Standard', '100 rig-days', 1.728e21], ['Monster', '10,000 rig-days', 1.728e23]];
  const potsFor = (g) => (grads[g][3] ? [0.001, 0.01, 0.1, 1] : [0.1, 0.5, 1, 5]);
  // What the QWEN curve owes in all. A Qwencoin block mints 50 QWEN, and a payment on Qwencoin is
  // proven to the launch by that chain's headers: the larger the leg, the more confirmations.
  const qpotsFor = (g) => (grads[g][3] ? [0.1, 1, 10, 100] : [50, 500, 5000, 25000]);
  const st = { name: '', ticker: '', grad: cfg.btc.chain === 'regtest' ? 0 : 1, pot: 0, qpot: 0, qaddr: '', fee: 1, busy: false, err: '', pic: null, desc: '', x: '', telegram: '', website: '', terms: null, terr: '' };
  const pickPicture = async (file) => {
    if (!file) return;
    try { const p = await squarePicture(file); if (st.pic) URL.revokeObjectURL(st.pic.url); st.pic = { ...p, url: URL.createObjectURL(new Blob([p.image], { type: p.image_type })) }; st.err = ''; } catch (e) { st.err = e.message; }
    paint(); paintPrev();
  };
  st.pot = potsFor(st.grad)[1]; st.qpot = qpotsFor(st.grad)[1];
  const prev = h('div'), form = h('div', { class: 'col', style: 'flex:999 1 520px;gap:28px' });
  // The numbers the site would build the launch with (descriptor.make), asked before anything exists.
  const askTerms = async () => {
    const want = Math.round(st.qpot * COIN);
    try { st.terms = await api(`/launch/terms?qwen_total=${want}`); st.terr = ''; } catch (e) { st.terms = st.terms ? { ...st.terms, qwen_confs: null } : null; st.terr = e.message; }
    if (Math.round(st.qpot * COIN) === want) { paint(); paintPrev(); }
  };
  const hours = (sec) => (sec < 5400 ? `${Math.round(sec / 60)} minutes` : sec < 172800 ? `${(sec / 3600).toFixed(sec % 3600 ? 1 : 0)} hours` : `${(sec / 86400).toFixed(1)} days`);
  const qdest = () => st.qaddr.trim() || (W.pub && cfg.qwen ? keyAddr('qwen') : '');
  const paintPrev = () => {
    const t = st.terms || {}, g = t.curve_tokens || 0;
    prev.replaceChildren(h('span', { class: 'lab' }, 'On the board'), h('div', { class: 'card', style: 'border-color:#FF9A1F;margin-top:8px' }, h('div', { style: 'display:flex;align-items:center;gap:12px' }, tile(st.ticker || '??', false, st.pic ? st.pic.url : null), h('div', { style: 'flex:1;min-width:0' }, h('div', { style: 'font-weight:700' }, st.name || 'Your coin'), h('div', { class: 'm muted', style: 'font-size:12px' }, `$${st.ticker || 'TICKER'} · ${W.addr ? short(W.addr) : 'you'} · now`)), h('span', { class: 'pill w' }, 'new')),
      CURVES.map((x) => h('div', { class: 'col', style: 'gap:4px' }, h('div', { class: 'between m', style: 'font-size:12px' }, h('span', { class: 'lab', style: `color:${Q[x].color}` }, Q[x].curve), h('span', { class: 'muted' }, '0.0%')), meter(0, x === 'qwen' ? 'w' : '', Q[x].curve)))),
    h('div', { class: 'panel', style: 'margin-top:20px;padding:4px 16px' }, [['Curves', 'two: BTC and QWEN'], ['Coins on each curve', g ? coins(g) : '…'], ['Most that can ever exist', t.max_supply ? coins(t.max_supply) : '…'], ['Premine', '0'], ['Price, first coin to graduation', '14.7x on each curve'],
      ['Starting prices imply', st.qpot > 0 ? `1 QWEN = ${perQwen((st.pot / st.qpot) * COIN)} sats` : '…'], ['To holders, in BTC', (st.pot * 0.8).toFixed(3) + ' BTC'], ['To holders, in QWEN', qwen(st.qpot * 0.8 * COIN) + ' QWEN'], ['To you, in BTC and QWEN', `${(st.pot * 0.1).toFixed(3)} BTC + ${qwen(st.qpot * 0.1 * COIN)} QWEN`], ['To you, in coins', g ? `${fmt(Math.round((g / COIN) * st.fee / 100))} to ${fmt(Math.round((2 * g / COIN) * st.fee / 100))} ${st.ticker || 'coins'}` : '…']].map(([k, v]) => h('div', { class: 'kv' }, h('span', null, k), h('b', { style: 'text-align:right' }, v)))),
    h('p', { class: 'muted', style: 'margin-top:16px;font-size:13px' }, 'Those totals are what each curve owes if it sells out. The first curve to sell out graduates the coin and the other stops where it is, so only one of them is paid in full. No floor and no reserve: what blocks owe goes to holders as the curves are mined, not into a pool. After graduation the chain is merge-mined with Bitcoin and trades by atomic swap.'));
  };
  const submit = async () => {
    st.err = '';
    try {
      if (!/^[A-Z0-9]{2,10}$/.test(st.ticker)) throw new Error('Ticker: 2 to 10 letters or digits.');
      if (st.ticker === 'BTC' || st.ticker === 'QWEN') throw new Error(`${st.ticker} names a chain here, not a coin: pick another ticker.`);
      if (!st.name.trim()) throw new Error('Give it a name.');
      if (!cfg.qwen) throw new Error('This site has no Qwencoin node, and every launch is anchored on Qwencoin as well as on Bitcoin: it cannot create one.');
      await needWallet();
      try { B.addressToScript(qdest(), cfg.qwen); } catch (e) { throw new Error('Your QWEN address is not an address on this site\'s Qwencoin network.'); }
      if (st.terr) throw new Error(st.terr);
      st.busy = true; paint();
      const g = grads[st.grad];
      const meta = { description: st.desc.trim(), image_type: st.pic ? st.pic.image_type : '', image: st.pic ? st.pic.image : new Uint8Array(0), x: st.x.trim(), telegram: st.telegram.trim(), website: st.website.trim() };
      for (const k of ['x', 'telegram', 'website']) if (meta[k] && !/^https:\/\/[^\s"'<>]+$/.test(meta[k])) throw new Error(`The ${k === 'x' ? 'X' : k} link has to start with https://`);
      const hasMeta = Boolean(meta.description || st.pic || meta.x || meta.telegram || meta.website);
      const metadata = Object.fromEntries(Object.entries({ ...meta, image: st.pic ? B.b64(st.pic.image) : '' }).filter(([, v]) => v));
      const r = await api('/launch', { name: st.name.trim(), ticker: st.ticker, graduation_hashes: g[2], sats_total: Math.round(st.pot * COIN), qwen_total: Math.round(st.qpot * COIN), creator_fee_bps: Math.round(st.fee * 100), creator_script: B.hex(B.p2wpkh(W.pub)), creator_btc_address: W.addr, creator_qwen_address: qdest(), ...(g[3] ? { pow_limit_bits: g[3] } : {}), ...(hasMeta ? { metadata } : {}) });
      // The launch id must commit to exactly the picture and words given here, nothing swapped in.
      if (hasMeta && r.meta !== B.hex(B.metaHash(meta))) throw new Error('This site did not commit the launch to the picture and text you gave it. Do not promote this chain.');
      for (let i = 0; i < 60 && !cfg.launches[r.ticker]; i++) { await sleep(500); cfg = await api('/config').catch(() => cfg); }
      location.hash = '#/c/' + r.ticker;
    } catch (e) { st.busy = false; st.err = e.message; paint(); }
  };
  const paint = () => {
    const t = st.terms;
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
      h('div', { class: 'col' }, h('span', { class: 'd', style: 'font-size:26px' }, h('span', { class: 'o' }, '2 '), 'The curves'), h('span', { class: 'muted', style: 'font-size:13px' }, 'Every coin has two curves of the same shape: blocks mined on one owe sats, blocks mined on the other owe QWEN. Whoever mints picks the cheaper one, so the two totals below set where the coin starts pricing QWEN.'),
        h('span', { class: 'lab' }, 'Hash it takes to graduate (on either curve)'),
        h('div', { style: 'display:grid;grid-template-columns:repeat(auto-fit,minmax(min(150px,100%),1fr));gap:10px' }, grads.map((g, i) => h('button', { type: 'button', class: 'ghost' + (st.grad === i ? ' pick' : ''), style: 'flex-direction:column;align-items:flex-start;gap:4px;min-height:76px;padding:12px 14px;text-transform:none', 'aria-pressed': String(st.grad === i), onclick: () => { st.grad = i; if (!potsFor(i).includes(st.pot)) st.pot = potsFor(i)[1]; if (!qpotsFor(i).includes(st.qpot)) { st.qpot = qpotsFor(i)[1]; askTerms(); } paint(); paintPrev(); } }, h('span', { class: 'd', style: 'font-size:22px' }, g[0]), h('span', null, g[1])))),
        h('span', { class: 'muted', style: 'font-size:13px' }, 'One rig is a 200 TH/s ASIC. More hash to graduate means longer, pricier curves.'), h('span', { class: 'lab o' }, 'BTC curve: sats owed over the whole curve'),
        h('div', { style: 'display:grid;grid-template-columns:repeat(4,1fr);gap:10px' }, potsFor(st.grad).map((p) => h('button', { type: 'button', class: 'ghost' + (st.pot === p ? ' pick' : ''), style: 'min-height:56px;font-size:15px', 'aria-pressed': String(st.pot === p), 'data-pot': p, onclick: () => { st.pot = p; paint(); paintPrev(); } }, p + ' BTC'))),
        h('span', { class: 'lab', style: 'color:#F2F0EC' }, 'QWEN curve: QWEN owed over the whole curve'),
        h('div', { style: 'display:grid;grid-template-columns:repeat(4,1fr);gap:10px' }, qpotsFor(st.grad).map((p) => h('button', { type: 'button', class: 'ghost' + (st.qpot === p ? ' pick' : ''), style: 'min-height:56px;font-size:15px', 'aria-pressed': String(st.qpot === p), 'data-qpot': p, onclick: () => { st.qpot = p; paint(); paintPrev(); askTerms(); } }, fmt(p, p < 1 ? 1 : 0) + ' QWEN'))),
        st.terr ? h('p', { class: 'err', id: 'qterms', style: 'font-size:13px' }, st.terr)
          : h('div', { class: 'panel pad m', id: 'qterms', style: 'font-size:13px;display:flex;flex-direction:column;gap:6px' }, t && t.qwen_confs ? [h('span', null, h('b', null, `${t.qwen_confs} Qwencoin confirmations`), ` before a QWEN payment counts: about ${hours(t.qwen_seconds)} at ten minutes a block.`),
            h('span', { class: 'muted' }, 'Why: a QWEN payment proof is as hard to fake as that many Qwencoin blocks are to mine. A larger total needs more of them, so that paying is always cheaper than faking.'),
            h('span', { class: 'muted' }, `A miner has ${hours(t.settle_seconds)} after its block to pay and prove it (on either curve).`)] : 'asking the site what this total needs'),
        h('span', { class: 'muted', style: 'font-size:13px' }, 'Miners owe these in total while the curves are mined. Each block pays one address: a holder 80% of the time, you 10%, hashfun 10%.')),
      h('div', { class: 'col' }, h('span', { class: 'd', style: 'font-size:26px' }, h('span', { class: 'o' }, '3 '), 'Your cut'), h('div', { class: 'between' }, h('label', { class: 'lab', for: 'fee' }, 'Creator fee, in coins'), h('span', { class: 'd o', style: 'font-size:26px' }, st.fee + '%')),
        h('input', { id: 'fee', type: 'range', min: 0, max: 10, step: 0.5, value: st.fee, style: 'width:100%;min-height:44px;accent-color:#FF9A1F', oninput: (e) => { st.fee = parseFloat(e.target.value); e.target.parentNode.querySelector('.between .d').textContent = st.fee + '%'; paintPrev(); } }),
        h('span', { class: 'muted', style: 'font-size:13px' }, 'A slice of every block\'s freshly minted coins, paid as it is mined. Never up front. 10% is the hard cap.'),
        h('div', { class: 'panel pad m between', style: 'font-size:13px' }, h('span', { class: 'muted' }, 'Your sats land on Bitcoin at'), h('b', null, W.addr ? short(W.addr) + ' (UniSat)' : 'connect your wallet')),
        h('div', { class: 'col', style: 'gap:6px' }, h('label', { class: 'lab', for: 'qaddr' }, 'Your QWEN lands on Qwencoin at'),
          h('div', { class: 'field' }, h('input', { id: 'qaddr', class: 'm', style: 'font-size:13px', value: st.qaddr, placeholder: W.pub && cfg.qwen ? keyAddr('qwen') : 'connect your wallet, or paste a Qwencoin address', oninput: (e) => { st.qaddr = e.target.value; } })),
          h('span', { class: 'muted', style: 'font-size:13px' }, 'Left empty: your hashfun key on Qwencoin, which this page can spend from (Bags). A Qwencoin address has the same form as a Bitcoin one, and a key has the same address on both chains: what is paid here arrives on Qwencoin, at that key.'))),
      h('div', { class: 'col', style: 'gap:12px' }, h('button', { class: 'btn', id: 'launch-go', type: 'button', style: 'min-height:68px;font-size:28px', disabled: st.busy, onclick: submit }, st.busy ? 'Starting the chain…' : `Launch $${st.ticker || 'TICKER'}`), st.err ? h('p', { class: 'err' }, st.err) : null,
        cfg.allow_launch ? h('p', { class: 'muted', style: 'font-size:13px' }, 'The hash of this form, picture included, becomes the launch id, so anyone can check the chain against it. It starts at block zero and nobody holds a coin, you included.') : h('p', { class: 'err', style: 'font-size:13px' }, cfg.qwen ? 'This site does not create launches. Use the CLI: hashfun launch new' : 'This site has no Qwencoin node, so it does not create launches. Use the CLI: hashfun launch new')));
  };
  paint(); paintPrev(); askTerms();
  view.replaceChildren(h('div', { class: 'col', style: 'gap:12px;padding:40px 0 32px' }, h('h1', { class: 'd h1' }, 'Launch a ', h('span', { class: 'o' }, 'coin')), h('p', { class: 'soft', id: 'launch-pitch', style: 'max-width:680px;font-size:18px' }, PITCH.launch),
    h('p', { class: 'm l', id: 'launch-honest', style: 'font-size:13px' }, PITCH.honest)),
    h('div', { class: 'row', style: 'align-items:flex-start;gap:32px' }, form, h('aside', { style: 'flex:1 1 420px;min-width:0' }, prev)));
}

// The wallet's own address as it is written on an outside chain (the same script; the same string
// wherever the two networks share an address form, which Bitcoin and Qwencoin do).
const walletOn = (chain) => { try { return B.scriptToAddress(B.addressToScript(W.addr, cfg.btc), cfg[chain].hrp) || W.addr; } catch (e) { return W.addr; } };

function bags(view) {
  if (!W.pub) return view.replaceChildren(h('div', { class: 'col', style: 'padding:48px 0;align-items:flex-start' }, h('h1', { class: 'd h1' }, 'Your bags'), h('p', { class: 'soft' }, 'Connect to see what you hold and what it has paid you.'), h('button', { class: 'btn', type: 'button', onclick: () => connect(true).then(route).catch((e) => toast(e.message, true)) }, 'Connect UniSat')));
  const big = h('span', { class: 'd l', id: 'yield', style: 'font-size:clamp(72px,12vw,148px);line-height:.9' }, '…'), bigQ = h('span', { class: 'd', id: 'yield-qwen', style: 'font-size:clamp(40px,6vw,72px);line-height:.9' }, '…');
  const sweepBox = h('div', { class: 'col' }), table = h('div', { class: 'table panel' }), swapBox = h('div', { class: 'col' }), p2pBox = h('div', { class: 'col' });
  let y = null, yq = null, wq = null; // at the hashfun key on Bitcoin, at it on Qwencoin, at the wallet's address on Qwencoin
  const readQwen = async () => { if (!cfg.qwen) return; [yq, wq] = await Promise.all([api(`/chain/qwen/address/${keyAddr('qwen')}`), api(`/chain/qwen/address/${walletOn('qwen')}`).catch(() => null)]); paintYield(); };
  const sweep = async () => {
    try {
      const t = await api('/chain/btc/time'), us = y.utxos.filter((u) => u.confirmations > 0);
      const fee = t.feerate * (54 + 68 * us.length), total = us.reduce((a, u) => a + u.value, 0);
      if (total - fee < 600) throw new Error('not enough to cover the network fee yet');
      const tx = B.signP2wpkh(W.key, us, [{ value: total - fee, script: B.addressToScript(W.addr, cfg.btc) }]);
      const r = await api('/chain/btc/tx', { hex: B.txHex(tx) });
      toast(`Swept ${fmt(total - fee)} sats to ${short(W.addr)} on Bitcoin in ${short(r.txid)}`);
      y = { balance: 0, utxos: [] }; paintYield();
    } catch (e) { toast(e.message, true); }
  };
  // QWEN moves on Qwencoin only. From the hashfun key the page signs; from the wallet's own
  // address the wallet does (walletMoveQwen). Either way the destination is asked for by chain.
  const sendQwen = async (fromWallet) => {
    try {
      const to = (prompt(fromWallet ? 'Move the QWEN at your wallet address on Qwencoin to which Qwencoin address? Your hashfun key on Qwencoin is filled in: QWEN there can pay what your blocks owe and back your offers.' : 'Send the QWEN at your hashfun key on Qwencoin to which Qwencoin address? It has the same form as a Bitcoin address, and it has to be one you hold the key of on Qwencoin.', fromWallet ? keyAddr('qwen') : '') || '').trim();
      if (!to) return;
      try { B.addressToScript(to, cfg.qwen); } catch (e) { throw new Error('That is not an address on this site\'s Qwencoin network.'); }
      const r = await (fromWallet ? walletMoveQwen(to) : keyMoveQwen(to));
      toast(`Sent ${owe('qwen', r.value)} to ${short(to)} on Qwencoin in ${short(r.txid)}`);
      if (fromWallet) wq = { balance: 0, utxos: [] }; else yq = { balance: 0, utxos: [] };
      paintYield();
    } catch (e) { toast(e.message, true); }
  };
  const paintYield = () => {
    big.textContent = y ? fmt(y.balance) : '…';
    bigQ.textContent = !cfg.qwen ? 'none here' : yq ? qwen(yq.balance) : '…';
    const row = (id, amount, at, btn) => h('div', { class: 'col', style: 'gap:6px;padding:10px 0;border-top:1px solid #1F1F23', 'data-held': id }, h('div', { class: 'between', style: 'align-items:center' }, h('b', { class: 'm', style: 'font-size:16px' }, amount), btn), h('span', { class: 'm muted', style: 'font-size:12px;overflow-wrap:anywhere' }, at));
    sweepBox.replaceChildren(h('span', { class: 'lab' }, 'Waiting at your hashfun key: one key, two chains'),
      row('btc', y ? `${fmt(y.balance)} sats on Bitcoin` : '… on Bitcoin', where('btc'), h('button', { class: 'btn', id: 'sweep', type: 'button', style: 'min-height:44px;font-size:18px;padding:0 16px', disabled: !y || !y.utxos.some((u) => u.confirmations > 0), onclick: sweep }, 'Sweep to UniSat')),
      cfg.qwen ? row('qwen', yq ? `${qwen(yq.balance)} QWEN on Qwencoin` : '… on Qwencoin', where('qwen'), h('button', { class: 'btn white', id: 'send-qwen', type: 'button', style: 'min-height:44px;font-size:18px;padding:0 16px;box-shadow:none', disabled: !yq || !yq.utxos.some((u) => u.confirmations > 0), onclick: () => sendQwen(false) }, 'Send QWEN'))
        : h('span', { class: 'm muted', style: 'font-size:12px' }, 'This site has no Qwencoin node: it cannot see or move QWEN. What a QWEN-curve block paid your key is at the same key on Qwencoin.'),
      cfg.qwen && wq && wq.balance > 0 ? row('wallet-qwen', `${qwen(wq.balance)} QWEN on Qwencoin`, `${walletOn('qwen')} on Qwencoin: your wallet's own address, the same string it has on Bitcoin`, h('button', { class: 'ghost', id: 'move-qwen', type: 'button', onclick: () => sendQwen(true) }, 'Move with UniSat')) : null,
      h('span', { class: 'muted', style: 'font-size:13px' }, 'Payouts are ordinary transactions to the key that holds your coins: sats on Bitcoin, QWEN on Qwencoin. The address is the same on both; each balance is on its own chain. Nothing to claim; sweeping only moves them.'),
      h('button', { class: 'ghost', type: 'button', onclick: () => { if (confirm('Anyone who sees this key can take your coins and payouts. Show it?')) prompt('hashfun key (hex). Keep it offline.', B.hex(W.key)); } }, 'Back up this key'));
  };
  const paintSwaps = () => {
    const open = Object.values(swaps()).filter((r) => r.state !== 'done' && r.state !== 'refunded' && r.init_txid).sort((a, b) => b.created - a.created);
    swapBox.replaceChildren(...(open.length ? [h('h2', { class: 'd', style: 'font-size:32px' }, 'Open swaps'), ...open.map((r) => h('div', { class: 'panel pad between', style: 'align-items:center' }, h('span', { class: 'm' }, `${r.side} $${r.ticker} · ${fmt(r.q.btc_amount)} sats · ${r.state}`),
      h('span', { class: 'row', style: 'gap:8px' }, r.order_id ? h('button', { class: 'ghost', type: 'button', onclick: () => flow(`Resume $${r.ticker}`, (ui) => finishSwap(r, ui)) }, 'Resume') : null, h('button', { class: 'ghost', type: 'button', onclick: () => refundSwap(r).then((x) => { toast('Refunded in ' + short(x.refund_txid)); paintSwaps(); }).catch((e) => toast(e.message, true)) }, 'Refund'))))] : []));
  };
  paintYield(); paintSwaps();
  view.replaceChildren(h('section', { class: 'row', style: 'padding:40px 0 32px;align-items:stretch' }, h('div', { class: 'col', style: 'flex:3 1 480px;gap:10px' }, h('h1', { class: 'd', style: 'font-size:44px;line-height:1' }, 'Your bags'), h('span', { class: 'lab l' }, h('span', { class: 'dot' }), ' Won just by holding'),
    h('div', { style: 'display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 16px' }, big, h('span', { class: 'd l', style: 'font-size:44px' }, 'sats'), h('span', { class: 'm muted' }, 'on Bitcoin')),
    h('div', { style: 'display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 16px' }, bigQ, h('span', { class: 'd', style: 'font-size:32px' }, 'QWEN'), h('span', { class: 'm muted' }, 'on Qwencoin')),
    h('p', { class: 'soft' }, 'Every block on a curve of a coin you hold is another draw: BTC-curve blocks pay sats, QWEN-curve blocks pay QWEN.')),
    h('div', { class: 'panel pad', style: 'flex:2 1 340px;border:2px solid #F2F0EC' }, sweepBox)),
  h('section', { class: 'col', style: 'gap:14px' }, h('h2', { class: 'd', style: 'font-size:32px' }, 'Holdings'), table), h('section', { style: 'margin-top:32px' }, swapBox), h('section', { class: 'col', style: 'margin-top:32px;gap:14px' }, p2pBox));
  api(`/chain/btc/address/${btcAddr()}`).then((r) => { y = r; paintYield(); }).catch((e) => toast(e.message, true));
  readQwen().catch((e) => toast(e.message, true));
  let beat = 0;
  every(2500, async () => {
    cfg = await api('/config');
    if (++beat % 6 === 0) readQwen().catch(() => {}); // Qwencoin is small: its scan is quick, so this one follows along
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
// Holders trade with each other: any coin for sats or for QWEN, any coin for any other coin, and
// sats for QWEN. The page signs offers, answers takes and runs the swap (book.js); the site only
// passes signed messages along.
const told = new Set();
const book = createBook({ api, W, cfg: () => cfg, store: LS, unisat: () => (window.unisat ? { sendBitcoin: walletPay } : null), onChange: (r) => {
  if (r.role === 'maker' && r.state === 'done' && !told.has(r.id)) { told.add(r.id); toast(`Your offer filled: +${amt(r.get, r.got)}`); }
} });
// What the book trades: sats (Bitcoin), QWEN (Qwencoin) and every coin here. Sats are counted
// whole; QWEN and coins in hundred-millionths, shown as decimals.
const outside = (n) => n === 'btc' || n === 'qwen';
const amt = (n, v) => (n === 'btc' ? fmt(v) + ' sats' : n === 'qwen' ? qwen(v) + ' QWEN' : coins(v) + ' $' + n);
const unitOf = (n) => (n === 'btc' ? 'sats' : n === 'qwen' ? 'QWEN' : '$' + n);
const chainLabel = (n) => (n === 'btc' ? 'Bitcoin' : n === 'qwen' ? 'Qwencoin' : '$' + n);
const toUnits = (n, x) => Math.round(n === 'btc' ? x : x * COIN);
const fromUnits = (n, v) => (n === 'btc' ? v : v / COIN);
const dur = (sec) => (sec >= 7200 ? Math.round(sec / 3600) + ' hours' : Math.max(1, Math.round(sec / 60)) + ' minutes');
// The price in the units people quote: sats per QWEN between the two outside chains, sats or QWEN
// per coin when one of them is a side, coin for coin otherwise.
const rate = (pay, get, payAmt, getAmt) => {
  if (pay === 'btc' && get === 'qwen') return `${perQwen((payAmt / getAmt) * COIN)} sats per QWEN`;
  if (pay === 'qwen' && get === 'btc') return `${perQwen((getAmt / payAmt) * COIN)} sats per QWEN`;
  if (pay === 'btc') return `${price((payAmt / getAmt) * COIN)} sats per coin`;
  if (get === 'btc') return `${price((getAmt / payAmt) * COIN)} sats per coin`;
  if (pay === 'qwen') return `${price(payAmt / getAmt)} QWEN per coin`;
  if (get === 'qwen') return `${price(getAmt / payAmt)} QWEN per coin`;
  return `1 $${get} = ${price(payAmt / getAmt)} $${pay}`;
};
const assetTile = (n) => (n === 'btc' ? h('span', { class: 'tile', 'aria-hidden': 'true', style: 'background:#FF9A1F;color:#0A0A0B;border-color:#FF9A1F' }, 'B')
  : n === 'qwen' ? h('span', { class: 'tile', 'aria-hidden': 'true', style: 'background:#0A0A0B;color:#F2F0EC;border-color:#F2F0EC' }, 'Q') : tile(n));
const swapState = (r) => ({ requested: 'asking the maker', accepted: r.role === 'taker' ? 'about to lock' : 'waiting for the taker to lock', locking: 'locking',
  locked: r.role === 'taker' ? 'waiting for the maker to lock' : 'waiting for the taker to claim', done: 'done', failed: 'did not happen', released: 'nothing locked', refunded: 'refunded' }[r.state] || r.state);
// One line for a swap in a list: where it stands, in the state's words or in the engine's note
// (book.js), whichever says more, and never both saying the same thing.
const swapLine = (r) => {
  const st = swapState(r), n = (r.note || '').trim();
  if (FINAL.includes(r.state)) { // over: a note here was written with the outcome and is its reason
    if (r.state === 'done' || !n || n === st) return st;
    return r.state === 'refunded' ? n : `${st}: ${n}`;
  }
  // A maker's page counts confirmations on the taker's lock before it locks; once it has locked, that count is history.
  if (!n || n === st || (r.role === 'maker' && r.state !== 'accepted' && /confirmations on the taker's lock$/.test(n))) return st;
  // Progress on the other side's lock, or why this side now only waits for its timelock: the note is the whole story.
  if (/confirmations on the (maker|taker)'s lock$/.test(n) || /after its timelock$/.test(n) || /resumes by itself when it does$/.test(n) || n.startsWith("the maker's lock is not on the chain")) return n;
  return `${st} · ${n}`;
};

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

// The coin page's Book tab: who is selling this coin and who is buying it, best first, against
// sats and (when the site follows Qwencoin) against QWEN. Two prices for one coin, side by side.
function bookTab(ticker, orders) {
  const id = (cfg.launches[ticker] || {}).id, cols = 'grid-template-columns:minmax(0,1.3fr) minmax(0,1fr) minmax(0,1fr) 48px';
  const quotes = [['btc', cfg.btc_id], ...(cfg.qwen_id ? [['qwen', cfg.qwen_id]] : [])];
  const side = (title, list, pay, get, word, qn) => h('div', { style: 'flex:1 1 340px;min-width:0' }, h('div', { class: 'lab', style: 'padding:14px 16px 8px' }, title),
    h('div', { class: 'tr head', style: cols }, h('span', null, qn === 'btc' ? 'Sats per coin' : 'QWEN per coin'), h('span', null, 'Coins'), h('span', null, qn === 'btc' ? 'Sats' : 'QWEN'), h('span')),
    list.length ? list.map((o) => { const c = get === qn ? o.remaining_get : o.remaining, quo = get === qn ? o.remaining : o.remaining_get;
      return h('a', { class: 'tr', style: cols, href: `#/swap/${pay}/${get}/${o.id}`, 'data-order': o.id, 'data-quote': qn }, h('b', null, qn === 'btc' ? price((quo / c) * COIN) : price(quo / c)), h('span', null, coins(c)), h('span', { class: 'muted' }, qn === 'btc' ? fmt(quo) : qwen(quo)), h('span', { class: word === 'buy' ? 'o' : 'l' }, word)); })
      : h('div', { class: 'pad muted', style: 'font-size:13px' }, 'Nobody yet.'));
  const outsideIds = quotes.map((x) => x[1]);
  const others = orders.filter((o) => (o.give === id || o.get === id) && !outsideIds.includes(o.give) && !outsideIds.includes(o.get)).length;
  return h('div', { id: 'book' }, quotes.map(([qn, qid]) => h('div', { class: 'row', style: 'gap:0;border-bottom:1px solid #2C2C31', 'data-book': qn },
    side(`Selling $${ticker} for ${unitOf(qn)}`, orders.filter((o) => o.give === id && o.get === qid), qn, ticker, 'buy', qn), side(`Buying $${ticker} with ${unitOf(qn)}`, orders.filter((o) => o.get === id && o.give === qid), ticker, qn, 'sell', qn))),
    h('div', { class: 'pad between', style: 'align-items:center' }, h('span', { class: 'muted', style: 'font-size:13px;flex:1 1 280px' }, `Holders trading with each other by atomic swap: no custody, no listing.${cfg.qwen_id ? ' The same coin has a price in sats and a price in QWEN here; the gap between them is what QWEN costs in sats.' : ''}${others ? ` ${others} more offer${others === 1 ? '' : 's'} against other coins.` : ''}`),
      h('span', { class: 'row', style: 'gap:8px' }, h('a', { class: 'ghost', href: `#/swap/${ticker}/btc` }, `Sell $${ticker}`), h('a', { class: 'ghost', href: `#/swap/btc/${ticker}` }, `Bid in sats`), cfg.qwen_id ? h('a', { class: 'ghost', href: `#/swap/qwen/${ticker}` }, 'Bid in QWEN') : null, h('a', { class: 'ghost', href: `#/swap/${ticker}` }, 'Other coins'))));
}

// Offers of mine and swaps of mine, for Bags and the Swap page.
function p2pLists(myOrders) {
  const nm = (id) => book.nameOf(id) || '?', out = [];
  const rs = Object.values(book.recs()).filter((r) => r.taker).sort((a, b) => b.created - a.created).slice(0, 12);
  if (myOrders.length) out.push(h('h2', { class: 'd', style: 'font-size:32px' }, 'Your offers'), ...myOrders.map((o) => h('div', { class: 'panel pad between', 'data-offer': o.id, style: 'align-items:center' },
    h('span', { class: 'm' }, `give ${amt(nm(o.give), o.remaining)} for ${amt(nm(o.get), o.remaining_get)}`, h('span', { class: 'muted' }, o.remaining < o.give_amount ? ' · partly filled' : ''),
      // takers are shown an offer only once the board has seen what backs it at the maker's key
      o.backed === false ? h('span', { class: 'o', 'data-unlisted': '' }, ` · not listed yet: the board has not seen the ${nm(o.give) === 'btc' ? 'sats' : nm(o.give) === 'qwen' ? 'QWEN' : 'coins'} behind it`) : null),
    h('button', { class: 'ghost', type: 'button', onclick: () => book.cancel(o.id).then(() => { toast('Offer cancelled'); route(); }).catch((e) => toast(e.message, true)) }, 'Cancel'))));
  if (rs.length) out.push(h('h2', { class: 'd', style: 'font-size:32px' }, 'Peer-to-peer swaps'), ...rs.map((r) => {
    const pays = r.role === 'taker' ? [r.get, r.get_amount] : [r.give, r.give_amount], gets = r.role === 'taker' ? [r.give, r.give_amount] : [r.get, r.get_amount];
    return h('div', { class: 'panel pad between', 'data-p2p': r.state, 'data-role': r.role, style: 'align-items:center' }, h('span', { class: 'm' }, `${amt(...pays)} for ${amt(...gets)}`),
      h('span', { class: 'm ' + (r.state === 'done' ? 'l' : 'muted'), style: 'font-size:12px;text-align:right;flex:1 1 200px' }, swapLine(r)));
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
  const norm = (x) => (outside((x || '').toLowerCase()) ? x.toLowerCase() : (x || '').toUpperCase());
  const all = ['btc', ...(cfg.qwen ? ['qwen'] : []), ...Object.keys(cfg.launches).sort()];
  const pay = all.includes(norm(a)) ? norm(a) : 'btc';
  const get = all.includes(norm(b)) && norm(b) !== pay ? norm(b) : (pay === 'btc' ? all.find((n) => n !== 'btc') : 'btc');
  if (!get) return view.replaceChildren(h('div', { class: 'col', style: 'padding:48px 0;align-items:flex-start' }, h('h1', { class: 'd h1' }, 'Swap'), h('p', { class: 'soft' }, 'No coins here yet. Launch one first.'), h('a', { class: 'btn', href: '#/launch' }, 'Launch a coin')));
  const st = { sel: pick || null, payIn: '', giveIn: '', wantIn: '', perr: '', seen: '' };
  let offers = [], rivals = [], mine = [], bal = null, balOther = null;
  // The other outside chain: the hashfun key has the same address on Bitcoin and on Qwencoin, so
  // whenever one of its two balances is shown the other is shown beside it, each with its chain.
  const twin = pay === 'btc' ? (cfg.qwen ? 'qwen' : null) : pay === 'qwen' ? 'btc' : null;
  const picker = (cur, other, id, label, onpick) => h('div', { class: 'col', style: 'flex:1 1 260px;gap:6px' }, h('label', { class: 'lab', for: id }, label), h('div', { class: 'field' }, assetTile(cur),
    h('select', { id, onchange: (e) => onpick(e.target.value) }, all.filter((n) => n !== other).map((n) => h('option', { value: n, selected: n === cur }, n === 'btc' ? 'Bitcoin (sats)' : n === 'qwen' ? 'Qwencoin (QWEN)' : `${cfg.launches[n].name} ($${n})`)))));
  const offersBox = h('div', { class: 'panel', style: 'flex:3 1 420px;min-width:0' }), takeBox = h('div', { class: 'trade' }), postBox = h('div', { class: 'panel' }), mineBox = h('section', { class: 'col', style: 'gap:14px;margin-top:32px' });
  const balEl = h('span', { class: 'm muted', id: 'sw-bal', style: 'font-size:12px' }), rivalEl = h('span', { class: 'm muted', style: 'font-size:12px' });
  const kv = (k, v) => h('div', { class: 'kv' }, h('span', null, k), h('span', { style: 'text-align:right' }, v));

  const paintOffers = () => offersBox.replaceChildren(h('div', { class: 'between lab', style: 'padding:14px 16px;border-bottom:1px solid #2C2C31' }, `${chainLabel(get)} on offer for ${unitOf(pay)}`, h('span', { class: 'l' }, h('span', { class: 'dot' }), ` ${offers.length} live`)),
    ...(offers.length ? offers.map((o) => h('button', { type: 'button', class: 'offer' + (st.sel === o.id ? ' on' : ''), 'data-order': o.id, 'aria-pressed': String(st.sel === o.id), onclick: () => { st.sel = o.id; st.payIn = ''; st.seen = ''; paintOffers(); paintTake(); } },
      h('span', { class: 'd', style: 'font-size:26px;line-height:1' }, rate(pay, get, o.remaining_get, o.remaining)), h('span', { class: 'm', style: 'font-size:13px' }, `up to ${amt(get, o.remaining)} for ${amt(pay, o.remaining_get)}`),
      h('span', { class: 'm muted', style: 'font-size:12px' }, `from ${short(o.maker)}${W.pub && o.maker === B.hex(W.pub) ? ' (you)' : ''}, online now`)))
      : [h('div', { class: 'pad col' }, h('span', { class: 'd', style: 'font-size:26px' }, 'No offers this way yet'), h('p', { class: 'muted', style: 'font-size:13px' }, 'Leave your own: it is listed as soon as the board has seen the coins, sats or QWEN behind it.'))]));

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
      btn, h('p', { class: 'muted', style: 'font-size:13px' }, pay === 'btc' ? `Paid on Bitcoin from UniSat into a contract only the maker can claim, and only by handing you the ${get === 'qwen' ? 'QWEN' : 'coins'}.` : pay === 'qwen' ? 'Locked on Qwencoin from your hashfun key into a contract only the maker can claim, and only by paying you.' : 'Locked from your hashfun key into a contract only the maker can claim, and only by paying you.'),
      get === 'qwen' && W.pub ? h('p', { class: 'm muted', style: 'font-size:12px' }, `The QWEN arrives at your hashfun key on Qwencoin: ${keyAddr('qwen')}. Bags shows it and sends it on.`) : null));
    upd();
  };

  const paintPost = () => {
    const g = () => toUnits(pay, parseFloat(st.giveIn) || 0), w = () => toUnits(get, parseFloat(st.wantIn) || 0);
    const rateEl = h('span', { class: 'm', id: 'po-rate', style: 'font-size:13px' });
    const post = async () => {
      st.perr = '';
      try {
        await needWallet();
        const o = await book.post({ give: pay, get, give_amount: g(), get_amount: w() });
        st.giveIn = st.wantIn = '';
        toast(o && o.backed === false ? `Offer signed. It is listed once the board sees the ${pay === 'btc' ? 'sats' : pay === 'qwen' ? 'QWEN' : 'coins'} behind it.` : 'Your offer is live');
        await refresh();
      } catch (e) { st.perr = e.message; }
      paintPost();
    };
    const deposit = async () => {
      try { await needWallet(); const n = parseInt(prompt('Sats to move on Bitcoin from UniSat to your hashfun key (your offers are paid from there):', '100000') || '0', 10); if (n > 0) { await walletPay(btcAddr(), n); toast('On its way on Bitcoin. It counts after 1 confirmation.'); } } catch (e) { toast(e.message, true); }
    };
    const btn = h('button', { class: 'btn wide white', id: 'po-go', type: 'button', onclick: post }, 'Post offer');
    const upd = () => { const ok = g() > 0 && w() > 0; rateEl.textContent = ok ? rate(get, pay, w(), g()) : 'Set both sides: the price is what you make it.'; btn.disabled = !ok; };
    postBox.replaceChildren(h('div', { class: 'pad col' }, h('span', { class: 'lab' }, 'Or leave your own offer'),
      h('div', { class: 'field' }, h('input', { id: 'po-give', inputmode: 'decimal', 'aria-label': 'You give', placeholder: 'You give', value: st.giveIn, oninput: (e) => { st.giveIn = e.target.value.replace(/,/g, ''); upd(); } }), h('span', { class: 'm muted' }, unitOf(pay))),
      h('div', { class: 'field' }, h('input', { id: 'po-want', inputmode: 'decimal', 'aria-label': 'You want', placeholder: 'You want', value: st.wantIn, oninput: (e) => { st.wantIn = e.target.value.replace(/,/g, ''); upd(); } }), h('span', { class: 'm muted' }, unitOf(get))),
      rateEl, rivalEl, h('div', { class: 'between', style: 'align-items:center' }, balEl, pay === 'btc' ? h('button', { class: 'ghost', type: 'button', onclick: deposit }, 'Deposit from UniSat') : null),
      pay === 'qwen' && W.pub ? h('p', { class: 'm muted', id: 'qwen-deposit', style: 'font-size:12px;overflow-wrap:anywhere' }, `QWEN you offer is paid from your hashfun key on Qwencoin. To fund it, send QWEN on Qwencoin to ${keyAddr('qwen')}. It counts after 1 confirmation there. (The same key has this address on Bitcoin too; that balance is separate.)`) : null,
      btn, st.perr ? h('p', { class: 'err', id: 'po-err' }, st.perr) : null,
      h('p', { class: 'muted', style: 'font-size:13px' }, 'Signed by your hashfun key and live while this site is open in a tab (a background tab is fine): your page locks your side by itself when someone takes it, and claims the other side. Nothing leaves your key until someone takes it. Keep the tab open until a swap in progress is done.')));
    upd();
  };

  const refresh = async () => {
    const list = await book.list();
    offers = list.filter((o) => o.give === book.idOf(get) && o.get === book.idOf(pay));
    rivals = list.filter((o) => o.give === book.idOf(pay) && o.get === book.idOf(get));
    if (W.pub) { mine = await book.mine().catch(() => mine); bal = await book.balance(pay).catch(() => bal); if (twin) balOther = await book.balance(twin).catch(() => balOther); }
    if (!offers.some((o) => o.id === st.sel)) st.sel = offers.length ? offers[0].id : null;
    const o = offers.find((x) => x.id === st.sel), sig = o ? `${o.id}:${o.remaining}` : '';
    paintOffers();
    if (sig !== st.seen) { st.seen = sig; paintTake(); } // not on every poll: the amount box keeps its focus
    const on = (n, v) => `${v == null ? '…' : amt(n, v)} on ${chainLabel(n)}`;
    balEl.textContent = !W.pub ? 'Connect to post an offer' : outside(pay) ? `At your hashfun key: ${on(pay, bal)}${twin ? ' · ' + on(twin, balOther) : ''}` : `At your hashfun key: ${bal == null ? '…' : amt(pay, bal)}`;
    rivalEl.textContent = rivals.length ? `Best offer this way now: ${rate(get, pay, rivals[0].get_amount, rivals[0].give_amount)}` : 'Nobody else is offering this way.';
    mineBox.replaceChildren(...p2pLists(mine));
  };

  view.replaceChildren(h('div', { class: 'col', style: 'gap:12px;padding:40px 0 28px' }, h('h1', { class: 'd h1' }, 'Swap ', h('span', { class: 'o' }, 'anything')), h('p', { class: 'soft', style: 'max-width:680px;font-size:18px' }, 'Every coin here is its own Bitcoin-style chain, and so is Qwencoin: any of them swaps for any other, for sats or for QWEN, wallet to wallet. No pool, no bridge, no listing: one holder and another.')),
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
  if (name === 'coin') coin(view, parts[1].toUpperCase(), parts[2]); else if (name === 'launch') launchForm(view); else if (name === 'bags') bags(view); else if (name === 'swap') swap(view, parts[1], parts[2], parts[3]); else board(view);
  if (location.hash === '#how') setTimeout(() => { const e = $('how'); if (e) e.scrollIntoView(); }, 50);
}

(async () => {
  try { cfg = await api('/config'); } catch (e) { toast('The site API is not reachable: ' + e.message, true); }
  // A site without a Bitcoin node of its own says so once, in the footer: what it shows of Bitcoin comes from Electrum servers.
  if (cfg && cfg.btc_source === 'electrum') { const f = document.querySelector('footer.foot .wrap'); if (f) f.append(h('span', { id: 'btc-source', class: 'm', style: 'display:block;padding-top:6px;font-size:12px' }, 'This site reads Bitcoin through Electrum servers, not a node of its own.')); }
  $('wallet').addEventListener('click', () => (W.addr ? (location.hash = '#/bags') : connect(true).then(route).catch((e) => toast(e.message, true))));
  await connect(false).catch(() => false);
  paintWallet();
  // Another account or network in the wallet is another key and another set of records: start over.
  if (window.unisat && window.unisat.on) {
    window.unisat.on('accountsChanged', (a) => { if (W.addr && (!a || a[0] !== W.addr)) location.reload(); });
    for (const ev of ['networkChanged', 'chainChanged']) window.unisat.on(ev, () => { if (W.addr) location.reload(); });
  }
  book.start(); // answers takes on your offers and finishes or refunds your swaps while a tab is open
  // Mid-swap the page still has work to do (claim, or refund after the timelock): say so before it is closed.
  window.addEventListener('beforeunload', (e) => { if (book.pending()) { e.preventDefault(); e.returnValue = ''; } });
  window.addEventListener('hashchange', route);
  route();
})();
