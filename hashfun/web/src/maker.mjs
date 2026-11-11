// hashfun book: the page's peer-to-peer swap engine without the page.
//
// The same book.js that runs in a browser tab, hosted by node: a key in a file instead of a wallet
// extension, a JSON file instead of localStorage, and a loop instead of a tab that has to stay
// open. It talks to a hashfun site over HTTP exactly as the page does, so it needs no node of its
// own and works against anyone's site. Built into ../maker.cjs (npm run build); `hashfun book`
// runs that.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import readline from 'node:readline';
import * as B from './btc.js';
import { createBook, FINAL } from './book.js';

const HELP = `hashfun book: peer-to-peer offers and swaps without a browser tab

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
const COIN = 1e8;
const die = (msg) => { console.error('hashfun book: ' + msg); process.exit(1); };

// ---------------------------------------------------------------- arguments
const argv = process.argv.slice(process.argv[2] === 'book' ? 3 : 2);
const opts = {}, words = [];
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a.startsWith('--')) { const k = a.slice(2); if (['no-encrypt', 'help', 'once'].includes(k)) opts[k] = true; else opts[k] = argv[++i]; } else words.push(a);
}
const cmd = words[0];
const site = (opts.site || process.env.HASHFUN_SITE || 'http://127.0.0.1:8080').replace(/\/+$/, '');
const dir = opts.dir || process.env.HASHFUN_BOOK_DIR || path.join(os.homedir(), '.hashfun', 'book');
if (!cmd || opts.help || !['key', 'balances', 'post', 'offers', 'cancel', 'swaps', 'take', 'run'].includes(cmd)) {
  console.log(HELP);
  process.exit(cmd && !opts.help ? 1 : 0);
}

// ---------------------------------------------------------------- the key file
const ask = (q) => new Promise((res) => {
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr, terminal: true });
  rl.stdoutMuted = false;
  rl._writeToOutput = (s) => { if (!rl.stdoutMuted) rl.output.write(s); };
  rl.question(q, (a) => { rl.close(); process.stderr.write('\n'); res(a); });
  rl.stdoutMuted = true;
});
const password = async (confirm) => {
  if (process.env.HASHFUN_BOOK_PASSWORD !== undefined) return process.env.HASHFUN_BOOK_PASSWORD;
  if (!process.stdin.isTTY) die('the key file is encrypted: set HASHFUN_BOOK_PASSWORD');
  const p = await ask('password for the book key: ');
  if (confirm && p !== (await ask('again: '))) die('the two passwords differ');
  return p;
};
const KDF = { N: 32768, r: 8, p: 1, maxmem: 2 ** 27 };
const seal = (priv, pass) => {
  const salt = crypto.randomBytes(16), nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('chacha20-poly1305', crypto.scryptSync(pass, salt, 32, KDF), nonce, { authTagLength: 16 });
  const ct = Buffer.concat([c.update(Buffer.from(priv)), c.final()]);
  return { v: 1, kdf: 'scrypt', salt: salt.toString('hex'), nonce: nonce.toString('hex'), ct: ct.toString('hex'), tag: c.getAuthTag().toString('hex') };
};
const unseal = (j, pass) => {
  const d = crypto.createDecipheriv('chacha20-poly1305', crypto.scryptSync(pass, Buffer.from(j.salt, 'hex'), 32, KDF), Buffer.from(j.nonce, 'hex'), { authTagLength: 16 });
  d.setAuthTag(Buffer.from(j.tag, 'hex'));
  try { return new Uint8Array(Buffer.concat([d.update(Buffer.from(j.ct, 'hex')), d.final()])); } catch (e) { return die('wrong password for ' + path.join(dir, 'key.json')); }
};
async function loadKey() {
  const f = path.join(dir, 'key.json');
  if (fs.existsSync(f)) {
    const j = JSON.parse(fs.readFileSync(f, 'utf8'));
    return j.priv ? B.unhex(j.priv) : unseal(j, await password(false));
  }
  if (cmd !== 'key') die(`no key in ${dir} yet: run "hashfun book key" first`);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  let priv;
  for (;;) { priv = B.randomBytes(32); try { B.pubkey(priv); break; } catch (e) { /* not a valid scalar: draw again */ } }
  const body = opts['no-encrypt'] ? { v: 1, priv: B.hex(priv) } : seal(priv, await password(true));
  fs.writeFileSync(f, JSON.stringify(body), { mode: 0o600 });
  console.error(`new key written to ${f}${opts['no-encrypt'] ? ' (NOT encrypted)' : ''}. Back this file up: it is the only copy.`);
  return priv;
}

// ---------------------------------------------------------------- the host
const api = async (p, body) => {
  let r;
  try { r = await fetch(site + '/api' + p, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined); } catch (e) { throw new Error(`cannot reach ${site}: ${e.cause ? e.cause.code || e.cause.message : e.message}`); }
  const j = await r.json().catch(() => ({ error: 'bad response' }));
  if (!r.ok) throw new Error(j.error || 'request failed');
  return j;
};
// The store: one JSON file that every `hashfun book` command on this directory shares, also at the
// same time (a `post` while `run` is up). So a read goes to the file, and a write takes a lock,
// reads again, and changes only what this process itself changed since it last read that key:
// another command's new offer or record is never written over.
const stateFile = path.join(dir, 'state.json');
const readState = () => { try { return JSON.parse(fs.readFileSync(stateFile, 'utf8')); } catch (e) { return {}; } };
const seen = {}; // key -> the text this process last read or wrote: the base of its next change
const isMap = (x) => !!x && typeof x === 'object' && !Array.isArray(x);
const merge = (base, mine, theirs) => { // one level deep: my additions, changes and removals on top of theirs
  const out = { ...theirs };
  for (const k of new Set([...Object.keys(base), ...Object.keys(mine)])) {
    const was = JSON.stringify(base[k]), is = JSON.stringify(mine[k]);
    if (was === is) continue; // not mine to decide
    if (is === undefined) delete out[k]; else out[k] = mine[k];
  }
  return out;
};
const locked = (fn) => {
  const lock = stateFile + '.lock';
  for (let i = 0; ; i++) {
    try { fs.writeFileSync(lock, String(process.pid), { flag: 'wx' }); break; } catch (e) {
      // a lock that old was left by a process that died between two lines of a write
      try { if (Date.now() - fs.statSync(lock).mtimeMs > 10000) fs.rmSync(lock, { force: true }); } catch (e2) { /* gone meanwhile */ }
      if (i > 800) throw new Error(`cannot lock ${stateFile}`);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25); // 25 ms, without yielding to the engine
    }
  }
  try { return fn(); } finally { fs.rmSync(lock, { force: true }); }
};
const store = {
  getItem: (k) => { const v = readState()[k]; seen[k] = v; return v === undefined ? null : v; },
  setItem: (k, v) => locked(() => {
    const state = readState();
    let text = v;
    if (state[k] !== seen[k]) { // another command changed this key since this process read it
      let base, mine, theirs;
      try { base = JSON.parse(seen[k] || '{}'); mine = JSON.parse(v); theirs = JSON.parse(state[k] || '{}'); } catch (e) { base = null; }
      if (isMap(base) && isMap(mine) && isMap(theirs)) text = JSON.stringify(merge(base, mine, theirs));
    }
    state[k] = text; seen[k] = text;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmp = `${stateFile}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
    fs.renameSync(tmp, stateFile);
  }),
};
// One engine per key directory: two would lock coins for the same swap twice. `run` and `take`
// are the commands that drive swaps; `post`, `cancel` and the read-only ones may run beside them.
const engine = (what) => {
  const lock = path.join(dir, 'run.lock');
  try { fs.writeFileSync(lock, `${process.pid} ${what}`, { flag: 'wx' }); } catch (e) {
    const [pid, who] = fs.readFileSync(lock, 'utf8').split(' ');
    let alive = true; try { process.kill(Number(pid), 0); } catch (e2) { alive = false; }
    if (alive) die(`this key is busy: "hashfun book ${who || 'run'}" (pid ${pid}) is working its swaps. ${what === 'take' ? 'Take from another key (--dir), or stop it first' : 'One at a time per key directory'}`);
    fs.writeFileSync(lock, `${process.pid} ${what}`);
  }
  process.on('exit', () => { try { if (fs.readFileSync(lock, 'utf8').startsWith(`${process.pid} `)) fs.rmSync(lock, { force: true }); } catch (e) { /* already gone */ } });
};

const W = { key: null, pub: null, addr: null };
let cfg = null;
const names = () => ['btc', ...Object.keys(cfg.launches)];
const norm = (x) => (String(x || '').toLowerCase() === 'btc' ? 'btc' : String(x || '').toUpperCase());
const chain = (x, what) => { const n = norm(x); if (!names().includes(n)) die(`${what}: ${x || '(missing)'} is not on this site (${names().join(', ')})`); return n; };
const toUnits = (n, x) => { const v = Number(x); if (!(v > 0)) die(`amount ${x}: a positive number`); return Math.round(n === 'btc' ? v : v * COIN); };
const show = (n, v) => (n === 'btc' ? `${v} sats` : `${v / COIN} $${n}`);
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
const told = {};
const book = createBook({ api, W, cfg: () => cfg, store, unisat: () => null, onChange: (r) => {
  const line = `${r.role} ${r.id.slice(0, 8)} ${r.state}${r.note ? ': ' + r.note : ''}`;
  if (told[r.id] !== line) { told[r.id] = line; log(line + (r.state === 'done' ? ` (+${show(r.role === 'taker' ? r.give : r.get, r.got)})` : '')); }
} });
const describe = (o) => `${o.id}  give ${show(book.nameOf(o.give), o.remaining)} for ${show(book.nameOf(o.get), o.remaining_get)}${o.backed === false ? '  (not listed: the site has not seen the coins behind it yet)' : ''}`;

(async () => {
  W.key = await loadKey();
  W.pub = B.pubkey(W.key);
  cfg = await api('/config');
  W.addr = opts['btc-payout'] || book.addrOn('btc');
  try { B.addressToScript(W.addr, cfg.btc); } catch (e) { die(`--btc-payout ${W.addr}: not an address on this site's Bitcoin network`); }

  if (cmd === 'key') {
    console.log(JSON.stringify({ pubkey: B.hex(W.pub), site, send_sats_to: book.addrOn('btc'), send_coins_to: Object.fromEntries(Object.keys(cfg.launches).map((t) => [t, book.addrOn(t)])) }, null, 2));
  } else if (cmd === 'balances') {
    const out = {};
    for (const n of names()) out[n === 'btc' ? 'sats' : n] = n === 'btc' ? await book.balance(n) : (await book.balance(n)) / COIN;
    console.log(JSON.stringify(out, null, 2));
  } else if (cmd === 'post') {
    const give = chain(opts.give, '--give'), get = chain(opts.get, '--get');
    const r = await book.post({ give, get, give_amount: toUnits(give, opts['give-amount']), get_amount: toUnits(get, opts['get-amount']), ttl: opts.hours ? Math.round(Number(opts.hours) * 3600) : undefined }).catch((e) => die(e.message));
    console.log(describe(r));
    console.error('It is listed only while "hashfun book run" is running.');
  } else if (cmd === 'offers') {
    for (const o of await book.mine()) console.log(describe(o));
  } else if (cmd === 'cancel') {
    await book.cancel(words[1] || die('cancel ID')).catch((e) => die(e.message));
    console.log('cancelled');
  } else if (cmd === 'swaps') {
    for (const r of Object.values(book.recs()).sort((a, b) => a.created - b.created)) console.log(`${r.id.slice(0, 8)}  ${r.role}  ${r.state}${r.note ? '  ' + r.note : ''}`);
  } else if (cmd === 'take') {
    engine('take');
    const o = (await book.list()).find((x) => x.id === words[1] || x.id.startsWith(words[1] || '?')) || die('no such offer on the board right now');
    const pay = book.nameOf(o.get);
    const rec = await book.take(o, opts.pay ? Math.min(o.remaining_get, toUnits(pay, opts.pay)) : o.remaining_get).catch((e) => die(e.message));
    while (!FINAL.includes((book.recs()[rec.id] || {}).state)) { await book.tick(); await new Promise((r) => setTimeout(r, 2000)); }
    process.exit(book.recs()[rec.id].state === 'done' ? 0 : 2);
  } else if (cmd === 'run') {
    engine('run');
    let stop = false;
    const bye = () => { if (stop) process.exit(1); stop = true; if (book.pending()) console.error('a swap is in progress: finishing it first (Ctrl-C again to quit anyway; "run" resumes it later)'); };
    process.on('SIGINT', bye); process.on('SIGTERM', bye);
    log(`key ${B.hex(W.pub).slice(0, 16)}… on ${site}; ${(await book.mine().catch(() => [])).length} open offer(s)`);
    let last = 0;
    while (!(stop && !book.pending())) {
      if (Date.now() - last > 30000) { cfg = await api('/config').catch(() => cfg); last = Date.now(); }
      await book.tick();
      if (opts.once) break;
      await new Promise((r) => setTimeout(r, 2500));
    }
  }
  process.exit(0);
})().catch((e) => die(e.message || String(e)));
