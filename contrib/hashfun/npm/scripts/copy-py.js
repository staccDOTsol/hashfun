// Copies the Python package (and the built site) next to the wrapper before `npm pack`.
const fs = require('fs');
const path = require('path');

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
if (!fs.existsSync(path.join(dst, 'web', 'static', 'app.js'))) throw new Error('build the site first: cd hashfun/web && npm install && npm run build');
console.log('copied', fs.readdirSync(dst).length, 'entries to', dst);
