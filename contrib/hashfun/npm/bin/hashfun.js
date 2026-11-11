#!/usr/bin/env node
// The hashfun CLI is Python (standard library only). This wrapper finds a Python >= 3.10 and
// runs it on the copy shipped in this package. The node binary (hashfund) is separate:
// set HASHFUND=/path/to/hashfund or put it on PATH.
const { spawn, spawnSync } = require('child_process');
const path = require('path');

const py = path.join(__dirname, '..', 'py');
const candidates = [process.env.HASHFUN_PYTHON, 'python3', 'python'].filter(Boolean);
let python = null;
for (const c of candidates) {
  const r = spawnSync(c, ['-c', 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)']);
  if (r.status === 0) { python = c; break; }
}
if (!python) {
  console.error('hashfun needs Python 3.10 or newer (python3 on PATH, or HASHFUN_PYTHON=/path/to/python).');
  process.exit(1);
}
const env = { ...process.env, PYTHONPATH: py + (process.env.PYTHONPATH ? path.delimiter + process.env.PYTHONPATH : '') };
const child = spawn(python, ['-m', 'hashfun.cli', ...process.argv.slice(2)], { stdio: 'inherit', env });
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => child.kill(sig));
child.on('exit', (code, signal) => process.exit(signal ? 1 : code));
