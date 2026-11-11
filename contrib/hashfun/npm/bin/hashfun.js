#!/usr/bin/env node
// The hashfun CLI is Python (standard library only). This wrapper finds a Python >= 3.10 and
// runs it on the copy shipped in this package. The node binary (hashfund) ships in this package
// too, one per platform under prebuilt/<system>-<processor>/: the Python CLI picks the one for
// this machine (`hashfun doctor` shows which, and tests it). HASHFUND=/path/to/hashfund overrides.
const { spawn, spawnSync } = require('child_process');
const path = require('path');

const py = path.join(__dirname, '..', 'py');
// `hashfun book` is the page's swap engine under node: no Python involved.
if (process.argv[2] === 'book') { require(path.join(py, 'hashfun', 'web', 'maker.cjs')); return; }
// macOS ships /usr/bin/python3 = 3.9 built against LibreSSL (no hashlib.scrypt, which the wallet
// file needs), so look past it: versioned names and Homebrew's usual places.
const candidates = [process.env.HASHFUN_PYTHON, 'python3', 'python3.14', 'python3.13', 'python3.12', 'python3.11', 'python3.10',
  '/opt/homebrew/bin/python3', '/usr/local/bin/python3', 'python'].filter(Boolean);
const probe = 'import sys, hashlib; sys.exit(0 if sys.version_info >= (3, 10) and hasattr(hashlib, "scrypt") else 1)';
let python = null;
for (const c of candidates) {
  const r = spawnSync(c, ['-c', probe]);
  if (r.status === 0) { python = c; break; }
}
if (!python) {
  console.error('hashfun needs Python 3.10 or newer, built with OpenSSL.\n' +
    (process.platform === 'darwin' ? 'The python3 that comes with macOS is 3.9 and too old: brew install python\n' : '') +
    'Or point at one: HASHFUN_PYTHON=/path/to/python hashfun ...');
  process.exit(1);
}
const env = { ...process.env, PYTHONPATH: py + (process.env.PYTHONPATH ? path.delimiter + process.env.PYTHONPATH : '') };
const child = spawn(python, ['-m', 'hashfun.cli', ...process.argv.slice(2)], { stdio: 'inherit', env });
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => child.kill(sig));
child.on('exit', (code, signal) => process.exit(signal ? 1 : code));
