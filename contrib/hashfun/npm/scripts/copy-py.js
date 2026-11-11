// Runs before `npm pack` (prepack): copies the Python package and the built site next to the
// wrapper, and checks the node binaries the package is about to ship.
const fs = require('fs');
const path = require('path');

const fail = (msg) => { console.error('hashfun pack: ' + msg); process.exit(1); };
const src = path.join(__dirname, '..', '..', '..', '..', 'hashfun');
const dst = path.join(__dirname, '..', 'py', 'hashfun');
fs.rmSync(path.join(__dirname, '..', 'py'), { recursive: true, force: true });
const copy = (from, to, keep) => {
  fs.mkdirSync(to, { recursive: true });
  for (const e of fs.readdirSync(from, { withFileTypes: true })) {
    if (e.isFile() && keep(e.name)) fs.copyFileSync(path.join(from, e.name), path.join(to, e.name));
  }
};
copy(src, dst, (n) => n.endsWith('.py') || n === 'bip39_english.txt' || n === 'board.html');
copy(path.join(src, 'web', 'static'), path.join(dst, 'web', 'static'), () => true);
copy(path.join(src, 'web'), path.join(dst, 'web'), (n) => n === 'maker.cjs'); // `hashfun book`: the swap engine under node
if (!fs.existsSync(path.join(dst, 'web', 'static', 'app.js')) || !fs.existsSync(path.join(dst, 'web', 'maker.cjs'))) fail('build the site first: cd hashfun/web && npm install && npm run build');
console.log('copied', fs.readdirSync(dst).length, 'entries to', dst);

// The node binaries: prebuilt/<system>-<processor>/hashfund, one per platform the package
// supports. The CLI picks its own at run time, so a package that lacks one is a package that
// does not work on that platform: refuse to pack it. HASHFUN_PACK_PARTIAL=1 packs what is here,
// for a machine of your own; never publish such a tarball.
const TARGETS = ['linux-x64', 'linux-arm64', 'darwin-arm64', 'darwin-x64'];
// What the file itself says it is. The CLI trusts the directory name, so a binary in the wrong
// directory (two CI artifacts swapped, a build for this machine's own system libraries) would
// reach users as "exec format error" or "not found": read the headers and refuse it here.
const kind = (f) => {
  const b = fs.readFileSync(f);
  if (b.readUInt32BE(0) === 0x7f454c46) { // ELF
    if (b[4] !== 2 || b[5] !== 1) return 'an ELF file that is not 64-bit little-endian';
    const cpu = { 62: 'x64', 183: 'arm64' }[b.readUInt16LE(18)] || `machine ${b.readUInt16LE(18)}`;
    const phoff = Number(b.readBigUInt64LE(32)), phentsize = b.readUInt16LE(54), phnum = b.readUInt16LE(56);
    let dynamic = false;
    for (let i = 0; i < phnum; i++) if (b.readUInt32LE(phoff + i * phentsize) === 3) dynamic = true; // PT_INTERP: needs the system's loader and libraries
    return `linux-${cpu}${dynamic ? ' (dynamically linked)' : ''}`;
  }
  if (b.readUInt32LE(0) === 0xfeedfacf) { // Mach-O, 64-bit
    const cpu = { 0x01000007: 'x64', 0x0100000c: 'arm64' }[b.readUInt32LE(4)] || `cputype ${b.readUInt32LE(4)}`;
    return `darwin-${cpu}`;
  }
  return 'not an ELF or 64-bit Mach-O executable';
};
const have = [], missing = [];
for (const t of TARGETS) {
  const f = path.join(__dirname, '..', 'prebuilt', t, 'hashfund');
  if (fs.existsSync(f) && fs.statSync(f).isFile()) {
    const is = kind(f);
    if (is !== t) {
      fail(`prebuilt/${t}/hashfund is ${is}, not a ${t} binary${is.endsWith('(dynamically linked)') ? ': the package ships static Linux binaries, which run on every distribution (bash contrib/hashfun/dist/build.sh ' + t + ', without TOOLCHAIN=native)' : ''}`);
    }
    fs.chmodSync(f, 0o755); // a CI artifact, a zip or a copy may have dropped the executable bit
    have.push(t);
  } else missing.push(t);
}
if (missing.length && process.env.HASHFUN_PACK_PARTIAL !== '1') {
  fail(`this package would ship without a node binary for ${missing.join(', ')}: build them (bash contrib/hashfun/dist/build.sh ${missing.join(' ')}) ` +
    'or let CI do it (.github/workflows/hashfun.yml builds and tests all four).\nFor a tarball that only has to work on your own machine: HASHFUN_PACK_PARTIAL=1 npm pack');
}
console.log(`node binaries in this package: ${have.join(', ') || 'none'}` +
  (missing.length ? `\nNOT in this package: ${missing.join(', ')} (HASHFUN_PACK_PARTIAL=1). It will not run a node there; do not publish it.` : ''));
