// Test host for the peer-to-peer swap engine (hashfun/web/src/book.js): several traders in one
// node process, each with its own key and its own storage, all on one clock that the test moves.
// The engine is the browser's, byte for byte; what is replaced is the tab (explicit ticks), the
// wallet (a key) and the time. Driven by hashfun/tests/book_regtest.py over JSON lines:
//
//   {"op":"new","name":"M","priv":"<hex>","site":"http://127.0.0.1:1234"}
//   {"op":"clock","t":1800000000}                      seconds; every engine's clock
//   {"op":"post","name":"M","give":"TT","get":"btc","give_amount":..,"get_amount":..}
//   {"op":"take","name":"T","order":"<id>","amount":..,"tick":["M"]}   others are ticked while it waits
//   {"op":"tick","name":"M"}   {"op":"recs","name":"M"}   {"op":"balance","name":"M","chain":"btc"}
//   {"op":"mine","name":"M"}   {"op":"cancel","name":"M","order":"<id>"}   the trader's own offers
//   {"op":"note","name":"T","fill":"<id>","kind":"locked","body":{..}}   a hand-made signed message
//   {"op":"drop","name":"M"}                           the trader is gone (its storage stays)
import readline from 'node:readline';
import * as B from '../web/src/btc.js';
import { createBook, noteText } from '../web/src/book.js';

let clock = Date.now();
const traders = {};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function make({ name, priv, site }) {
  const api = async (p, body) => {
    const r = await fetch(site + '/api' + p, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined);
    const j = await r.json().catch(() => ({ error: 'bad response' }));
    if (!r.ok) throw new Error(j.error || 'request failed');
    return j;
  };
  const old = traders[name];
  const mem = old ? old.mem : {};
  const W = { key: B.unhex(priv), pub: null, addr: null };
  W.pub = B.pubkey(W.key);
  let cfg = await api('/config');
  const store = { getItem: (k) => (k in mem ? mem[k] : null), setItem: (k, v) => { mem[k] = v; } };
  const book = createBook({ api, W, cfg: () => cfg, store, unisat: () => null, now: () => clock });
  W.addr = book.addrOn('btc');
  traders[name] = { book, W, mem, api, refresh: async () => { cfg = await api('/config'); } };
  return { pub: B.hex(W.pub), btc: book.addrOn('btc'), coins: Object.fromEntries(Object.keys(cfg.launches).map((t) => [t, book.addrOn(t)])) };
}

const ops = {
  new: make,
  clock: async ({ t }) => { clock = t * 1000; return clock; },
  cfg: async ({ name }) => { await traders[name].refresh(); return true; },
  post: async ({ name, give, get, give_amount, get_amount }) => traders[name].book.post({ give, get, give_amount, get_amount }),
  list: async ({ name }) => traders[name].book.list(),
  mine: async ({ name }) => traders[name].book.mine(),
  cancel: async ({ name, order }) => { await traders[name].book.cancel(order); return true; },
  take: async ({ name, order, amount, tick = [] }) => {
    const t = traders[name];
    const o = (await t.book.list()).find((x) => x.id === order);
    if (!o) throw new Error('no such offer listed');
    let done = false, err = null, rec = null;
    t.book.take(o, amount || o.remaining_get).then((r) => { rec = r; }, (e) => { err = e; }).finally(() => { done = true; });
    while (!done) { for (const n of tick) if (traders[n]) await traders[n].book.tick(); await sleep(100); }
    if (err) throw err;
    return rec;
  },
  tick: async ({ name }) => { await traders[name].book.tick(); return Object.values(traders[name].book.recs()); },
  recs: async ({ name }) => Object.values(traders[name].book.recs()),
  balance: async ({ name, chain }) => traders[name].book.balance(chain),
  note: async ({ name, fill, kind, body }) => { const t = traders[name]; return t.api(`/book/fill/${fill}`, { from: B.hex(t.W.pub), kind, body, sig: B.signText(t.W.key, noteText(fill, kind, body)) }); },
  drop: async ({ name }) => { const t = traders[name]; delete traders[name]; traders['~' + name] = t; return true; },
  back: async ({ name }) => { traders[name] = traders['~' + name]; delete traders['~' + name]; return true; },
};

const rl = readline.createInterface({ input: process.stdin });
(async () => {
  for await (const line of rl) {
    if (!line.trim()) continue;
    let out;
    try { const m = JSON.parse(line); out = { ok: true, result: await ops[m.op](m) }; } catch (e) { out = { ok: false, error: e.message || String(e) }; }
    process.stdout.write(JSON.stringify(out === undefined ? { ok: true } : out) + '\n');
  }
})();
