// Runs the cases tests/test_web_js.py feeds on stdin through btc.js and prints the results.
import * as B from './btc.js';

let input = '';
process.stdin.on('data', (d) => { input += d; });
process.stdin.on('end', () => {
  const out = JSON.parse(input).map((c) => {
    try {
      if (c.op === 'addr') {
        const a = B.segwitEncode(c.hrp, c.ver, B.unhex(c.prog));
        return { addr: a, script: B.hex(B.addressToScript(a, { hrp: c.hrp })), back: B.scriptToAddress(B.addressToScript(a, { hrp: c.hrp }), c.hrp) };
      }
      if (c.op === 'legacy') return { script: B.hex(B.addressToScript(c.addr, { hrp: 'bc', p2pkh: c.p2pkh, p2sh: c.p2sh })) };
      const contract = c.contract && { secretHash: B.unhex(c.contract.h), recipientPub: B.unhex(c.contract.rpub), refundPub: B.unhex(c.contract.fpub), locktime: c.contract.locktime };
      if (c.op === 'contract') {
        const s = B.contractScript(contract), p = B.parseContract(s);
        return { script: B.hex(s), spk: B.hex(B.p2wsh(s)), locktime: p.locktime, rpub: B.hex(p.recipientPub), fpub: B.hex(p.refundPub), h: B.hex(p.secretHash) };
      }
      if (c.op === 'parse') { B.parseContract(B.unhex(c.script)); return { ok: true }; }
      const prev = { txid: c.txid, vout: c.vout };
      if (c.op === 'redeem') {
        const tx = B.redeemTx(contract, prev, c.amount, B.unhex(c.dest), c.fee, B.unhex(c.priv), B.unhex(c.secret));
        return { hex: B.txHex(tx), txid: B.txid(tx) };
      }
      if (c.op === 'refund') {
        const tx = B.refundTx(contract, prev, c.amount, B.unhex(c.dest), c.fee, B.unhex(c.priv));
        return { hex: B.txHex(tx), txid: B.txid(tx) };
      }
      if (c.op === 'p2wpkh') {
        const tx = B.signP2wpkh(B.unhex(c.priv), c.utxos, c.outputs.map((o) => ({ value: o.value, script: B.unhex(o.script) })));
        return { hex: B.txHex(tx), txid: B.txid(tx), pub: B.hex(B.pubkey(B.unhex(c.priv))) };
      }
      if (c.op === 'key') return { key: B.hex(B.keyFromSignature(c.sig)) };
      return { error: 'unknown op' };
    } catch (e) {
      return { error: String(e.message || e) };
    }
  });
  process.stdout.write(JSON.stringify(out));
});
