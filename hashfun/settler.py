"""Sats-leg automation for miners and pools.

Every curve coinbase is locked until its Bitcoin payment is proven on the launch chain. The
Settler does the whole loop for the blocks its owner mined:

  1. relay Bitcoin headers the launch has not seen (HFH1)
  2. once a block's draw is known and buried, pay the script the draw fixed on Bitcoin (tagged
     transaction: one tag list, tag i for output i)
  3. when that payment has enough confirmations, publish the SPV proof (HFP1)

All three ride in the coinbase of the owner's next block, so no spendable launch coins are
needed. State (which blocks are ours, which payments are out) is one JSON file.

Reorgs are the dangerous part, because Bitcoin that was paid stays paid:
  - a block is paid only once it is `pay_depth` deep, which also buries its draw block
    (the draw comes from the block DRAW_DELAY above it);
  - the signed payment is written to the state file before it is broadcast, so a crash
    between the two cannot pay twice;
  - a settlement is only forgotten once it is `pay_depth` deep; if the block carrying the proof
    is reorged out the proof is published again;
  - the draw fixes who is paid and nothing later changes it, except a reorg of the draw block
    itself. If that happens after payment, the old payment no longer counts: it is reported as
    lost and the block is paid again.

Two things it never does: pay for a block whose settlement deadline can no longer be met (the
Bitcoin would buy nothing: that coinbase is lost), and relay headers once the sats leg is over
(settle_deadline blocks after the last curve block the node no longer looks at them)."""
import json
import logging
import os
import threading
from typing import List, Optional

from . import yieldmodel as Y
from .crypto import sha256d
from .rpc import RPC, RPCError
from .ser import Tx, TxOut

log = logging.getLogger("hashfun.settler")

MAX_HEADERS_PER_BLOCK = 200
MAX_PROOFS_PER_BLOCK = 20
TAGS_PER_BTC_TX = 3  # 2 + 20n bytes of OP_RETURN data stays within the 80-byte relay standard
FORGET_DEPTH = 200   # keep watching a reorged-out block this long in case its branch comes back


def merkle_branch(txids: List[bytes], pos: int) -> List[bytes]:
    level, branch = list(txids), []
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        branch.append(level[pos ^ 1])
        level = [sha256d(level[j] + level[j + 1]) for j in range(0, len(level), 2)]
        pos >>= 1
    return branch


class NodeMismatch(RuntimeError):
    """The node does not answer getmintobligation the way this settler reads it."""


_ALWAYS = ("height", "hash", "curve", "owed", "draw_known", "settled", "deadline_height", "tag")


def checked_obligation(ob: dict) -> dict:
    """getmintobligation's answer, or NodeMismatch. Paying on a field read wrong costs real Bitcoin,
    so an answer in another shape stops the settler with one message instead of a guess."""
    if not isinstance(ob, dict):
        raise NodeMismatch("getmintobligation did not return an object: is this a hashfund node?")
    if "candidates" in ob or "candidate" in ob:
        raise NodeMismatch("the node answers getmintobligation with the earlier sats-leg rules (it lists 'candidates' to "
                           "pay in turn). Under the current rules the draw fixes one script to pay ('pay_script') and a "
                           "payment to anyone else settles nothing. Update hashfund to the version of this package; "
                           "nothing is paid until then")
    missing = [k for k in _ALWAYS if k not in ob]
    if not missing and ob["draw_known"]:
        missing = [k for k in ("pay", "payee") if k not in ob]
        if not missing and ob["pay"] > 0 and "pay_script" not in ob:
            missing = ["pay_script"]
    if missing:
        raise NodeMismatch(f"getmintobligation {ob.get('height', '?')} has no {', '.join(repr(k) for k in missing)}: this "
                           "hashfund and this package speak different versions of the sats leg. Update both; nothing "
                           "is paid until then")
    return ob


def payment_matches(ob: dict, p: dict) -> bool:
    """Does the payment recorded in p still satisfy the obligation as the chain sees it now?
    Mirrors consensus: the draw fixes the amount due and the one Bitcoin script it is due to
    (the drawn coin may be spent since: that changes nothing). Only another draw, after a reorg
    of the draw block, makes a payment stop counting."""
    return bool(ob.get("draw_known")) and 0 < ob.get("pay", 0) <= p["sats"] and ob.get("pay_script") == p["pay_script"]


class Settler:
    def __init__(self, launch: RPC, btc_wallet: RPC, state_path: str, max_pay_sats: Optional[int] = None,
                 pay_depth: int = 12):
        """launch: hashfund RPC. btc_wallet: funded Bitcoin Core wallet RPC that pays the sats.
        max_pay_sats: refuse any single obligation above this (None = no cap).
        pay_depth: blocks on top of a block before it is paid, and on top of a settlement before
        it is treated as final. 0 pays at the first chance (tests only)."""
        self.launch, self.btc, self.path, self.max_pay = launch, btc_wallet, state_path, max_pay_sats
        self.pay_depth = max(0, pay_depth)
        self.lock = threading.RLock()
        self.st = {"mine": [], "paid": {}, "done": [], "lost": []}
        if os.path.exists(state_path):
            with open(state_path) as f:
                self.st.update(json.load(f))
        self._confs = None

    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.st, f, indent=1)
        os.replace(tmp, self.path)

    # ------------------------------------------------------------ bookkeeping
    def add_block(self, height: int, block_hash: str):
        """Remember a block we mined (its coinbase is ours to settle)."""
        with self.lock:
            if not any(h == height and b == block_hash for h, b in self.st["mine"]):
                self.st["mine"].append([height, block_hash])
                self._save()

    def status(self) -> dict:
        with self.lock:
            return {"mined": len(self.st["mine"]), "awaiting_payment_or_proof": len(self.st["paid"]),
                    "settled_or_nothing_due": len(self.st["done"]), "lost_payments": len(self.st["lost"]),
                    "lost_sats": sum(x["sats"] for x in self.st["lost"])}

    def _finish(self, height: int, bhash: str):
        self.st["paid"].pop(f"{height}:{bhash}", None)
        if [height, bhash] in self.st["mine"]:
            self.st["mine"].remove([height, bhash])
        self.st["done"].append(height)
        del self.st["done"][:-2000]

    def _lose(self, key: str, why: str):
        p = self.st["paid"].pop(key)
        self.st["lost"].append({"block": key, "txid": p["txid"], "sats": p["sats"], "why": why})
        log.error("block %s: the %d sats paid in %s no longer count (%s)", key, p["sats"], p["txid"], why)

    def _obligation(self, height: int) -> dict:
        return checked_obligation(self.launch.getmintobligation(height))

    def sats_leg_over(self) -> bool:
        """settle_deadline blocks after the last curve block (the graduation block) nothing can be
        drawn or settled any more, and the node stops looking at headers and proofs. A reorg below
        that height reopens it, so this is asked again every round."""
        info = self.launch.getlaunchinfo()
        try:
            return bool(info["graduated"]) and info["height"] >= info["graduation_height"] + info["descriptor"]["settle_deadline"]
        except (KeyError, TypeError):
            return False  # a node that does not say: keep relaying

    # ------------------------------------------------------------ steps
    def relay_outputs(self) -> List[TxOut]:
        if self.sats_leg_over():
            return []
        have = self.launch.getbtcrelay()
        tip = self.btc.getblockcount()
        start = have["height"]
        same_chain = start <= tip and self.btc.getblockhash(start) == have["best"]
        if not same_chain:
            # Our Bitcoin node is on another branch (or behind): resend recent headers. The launch
            # ignores the ones it knows and connects the rest if the fork is within reach.
            start = max(have["anchor_height"], min(start, tip) - 12)
        heights = range(start + 1, min(tip, start + MAX_HEADERS_PER_BLOCK) + 1)
        hdrs = b"".join(bytes.fromhex(self.btc.getblockheader(self.btc.getblockhash(h), False)) for h in heights)
        return [TxOut(0, Y.op_return(b"HFH1" + hdrs))] if hdrs else []

    def _pay(self, group: List[dict]) -> bool:
        """One Bitcoin tx paying up to TAGS_PER_BTC_TX obligations: output i <-> tag i. The signed
        tx is saved before it is broadcast, so a crash in between cannot lead to a second payment."""
        outs = [TxOut(ob["pay"], bytes.fromhex(ob["pay_script"])) for ob in group]
        outs.append(TxOut(0, Y.payment_outputs_tag([bytes.fromhex(ob["tag"]) for ob in group])))
        raw = Tx(version=2, vin=[], vout=outs).serialize(witness=False).hex()
        funded = self.btc.fundrawtransaction(raw, {"changePosition": len(outs)}, False)
        signed = self.btc.signrawtransactionwithwallet(funded["hex"])
        if not signed.get("complete"):
            raise RuntimeError("bitcoin wallet could not sign the sats payment")
        txid = self.btc.decoderawtransaction(signed["hex"])["txid"]
        keys = []
        for vout, ob in enumerate(group):
            key = f"{ob['height']}:{ob['hash']}"
            keys.append(key)
            self.st["paid"][key] = {"txid": txid, "vout": vout, "sats": ob["pay"], "payee": ob["payee"],
                                    "pay_script": ob["pay_script"], "hex": signed["hex"]}
        self._save()
        try:
            self.btc.sendrawtransaction(signed["hex"])
        except RPCError:
            for key in keys:
                self.st["paid"].pop(key, None)
            self._save()
            raise
        for ob in group:
            log.info("block %d: paid %d sats to the drawn %s in %s", ob["height"], ob["pay"], ob["payee"], txid)
        return True

    def pay_due(self):
        """Pay every block of ours whose draw is known and buried and that is not paid or settled."""
        with self.lock:
            batch = []
            tip = self.launch.getblockcount()
            for height, bhash in list(self.st["mine"]):
                if f"{height}:{bhash}" in self.st["paid"]:
                    continue
                try:
                    ob = self._obligation(height)
                except RPCError:
                    continue  # above the tip right now (reorg in progress)
                if ob["hash"] != bhash:  # reorged out; nothing was paid for it
                    if tip - height >= FORGET_DEPTH:
                        self.st["mine"].remove([height, bhash])
                    continue
                if not ob["curve"] or ob["owed"] == 0:
                    self._finish(height, bhash)  # a property of the block itself: final
                    continue
                buried = tip - height >= self.pay_depth
                if not ob["draw_known"] or not buried:
                    continue
                if ob["pay"] == 0 or ob["settled"]:
                    self._finish(height, bhash)  # nothing due (the lottery, or nobody held yet), or already proven
                    continue
                if tip >= ob["deadline_height"]:
                    # The proof would have to be in a block at or below deadline_height, and the next
                    # block is already past it: a payment now would buy nothing. (A reorg could bring
                    # the chain back under the deadline, so the block is only given up once that
                    # height is buried, like everything else here.)
                    if tip - ob["deadline_height"] >= self.pay_depth:
                        log.error("block %d: its settlement deadline (height %d) passed unpaid; the coinbase is "
                                  "unspendable and nothing is paid for it", height, ob["deadline_height"])
                        self._finish(height, bhash)
                    continue
                if self.max_pay is not None and ob["pay"] > self.max_pay:
                    log.warning("block %d owes %d sats, above the configured cap; not paying", height, ob["pay"])
                    continue
                batch.append(ob)
            for i in range(0, len(batch), TAGS_PER_BTC_TX):
                try:
                    self._pay(batch[i:i + TAGS_PER_BTC_TX])
                except (RPCError, RuntimeError) as e:
                    log.warning("sats payment failed (will retry): %s", e)
                    break
            self._save()

    def proof_outputs(self) -> List[TxOut]:
        """HFP1 outputs for payments that are confirmed on Bitcoin and visible to the launch."""
        with self.lock:
            if self._confs is None:
                self._confs = self.launch.getbtcrelay()["confirmations_required"]
            relay_height = self.launch.getbtcrelay()["height"]
            btc_tip = self.btc.getblockcount()
            tip = self.launch.getblockcount()
            outs = []
            for key, p in list(self.st["paid"].items()):
                height, bhash = int(key.split(":")[0]), key.split(":")[1]
                try:
                    ob = self._obligation(height)
                except RPCError:
                    continue
                if ob["hash"] != bhash:
                    # Our block left the chain after we paid for it. Keep the record while its
                    # branch could still come back; after that the payment is written off.
                    if tip - height >= FORGET_DEPTH:
                        self._lose(key, "block reorged out")
                        if [height, bhash] in self.st["mine"]:
                            self.st["mine"].remove([height, bhash])
                    continue
                if ob["settled"]:
                    p.setdefault("seen", tip)
                    if tip - p["seen"] >= self.pay_depth:
                        self._finish(height, bhash)
                    continue
                p.pop("seen", None)  # not settled (any more): the proof has to go out (again)
                if tip >= ob["deadline_height"]:
                    self._lose(key, "settlement deadline missed; the coinbase is unspendable")
                    self._finish(height, bhash)
                    continue
                if not payment_matches(ob, p):
                    # The draw moved under us (a reorg of the draw block: nothing else can move it).
                    # Give the old branch pay_depth blocks to come back before paying again.
                    p.setdefault("bad", tip)
                    if tip - p["bad"] >= max(self.pay_depth, 1):
                        self._lose(key, "the draw changed after payment")
                    continue
                p.pop("bad", None)
                tx = self._payment_tx(key, p)
                if tx is None:
                    continue
                confs = tx.get("confirmations", 0)
                if confs < 0:
                    self._lose(key, "payment tx conflicted on Bitcoin")
                    continue
                if confs < self._confs or len(outs) >= MAX_PROOFS_PER_BLOCK:
                    continue
                blk = self.btc.getblock(tx["blockhash"], 1)
                # The proof only counts once the launch knows the block deep enough; headers relayed
                # in the same coinbase come first, so compare against what we are about to relay.
                if blk["height"] + self._confs - 1 > min(btc_tip, relay_height + MAX_HEADERS_PER_BLOCK):
                    continue
                txids = [bytes.fromhex(x)[::-1] for x in blk["tx"]]
                pos = blk["tx"].index(p["txid"])
                raw = Tx.parse(bytes.fromhex(tx["hex"])).serialize(witness=False)
                # (the proof's candidate byte is always 0: the payee is the one the draw fixed)
                proof = Y.PaymentProof(height, bytes.fromhex(tx["blockhash"])[::-1], pos, merkle_branch(txids, pos),
                                       p["vout"], 0, raw)
                outs.append(TxOut(0, Y.op_return(proof.payload())))
            self._save()
            return outs

    def _payment_tx(self, key: str, p: dict) -> Optional[dict]:
        """{confirmations, blockhash, hex} of the payment recorded at key; None: not now."""
        try:
            return self.btc.gettransaction(p["txid"])
        except RPCError:
            try:  # the wallet does not know it (crash before broadcast): send it now
                self.btc.sendrawtransaction(p["hex"])
            except RPCError as e:
                self._lose(key, f"payment tx not broadcastable: {e}")
            return None

    def coinbase_outputs(self) -> List[TxOut]:
        """Everything the next block's coinbase should carry: headers first, then proofs."""
        with self.lock:
            self.pay_due()
            return self.relay_outputs() + self.proof_outputs()


class WatchSettler(Settler):
    """Settles every block that anyone pays for, and pays nothing itself: no Bitcoin wallet.

    For a site whose users pay their own blocks' sats from their browser wallets. It keeps a list
    of the obligations that are due (drawn, pay > 0, unsettled, before their deadline), reads each
    new Bitcoin block for transactions whose first "HF" tag list names one of them with an output
    that pays the drawn script enough, and once such a payment is buried it publishes the proof,
    like the paying Settler. A payment made anywhere (this site, another wallet, by hand) counts.
    """

    LOOKBACK_BTC = 144  # Bitcoin blocks read back at the first start: a day of payments

    def __init__(self, launch: RPC, btc: RPC, state_path: str):
        super().__init__(launch, btc, state_path, max_pay_sats=None, pay_depth=0)
        self.st.setdefault("due", {})       # "height:hash" -> obligation (tag, pay, pay_script, deadline_height)
        self.st.setdefault("next", 0)       # the next launch height whose draw to look at
        self.st.setdefault("scanned", -1)   # the last Bitcoin height read for payments
        self.st.setdefault("scanned_hash", "")

    def status(self) -> dict:
        with self.lock:
            return {"due": len(self.st["due"]), "paid_awaiting_proof": len(self.st["paid"]),
                    "bitcoin_scanned_to": self.st["scanned"]}

    def due(self, script_hex: Optional[str] = None) -> List[dict]:
        """What is owed and unpaid now; with script_hex, only blocks whose coinbase pays it."""
        with self.lock:
            out = [dict(ob, key=k, paid=k in self.st["paid"]) for k, ob in self.st["due"].items()]
        if script_hex is not None:
            out = [o for o in out if script_hex in o.get("owners", [])]
        return sorted(out, key=lambda o: o["height"])

    def needs_blocks(self) -> bool:
        """Is something waiting for blocks: a payment for its proof, or a recent block that owes
        sats for its draw (DRAW_DELAY blocks on top of it)?"""
        with self.lock:
            if self.st["paid"]:
                return True
        tip = self.launch.getblockcount()
        for h in range(max(1, tip - Y.DRAW_DELAY + 1), tip + 1):
            ob = self._obligation(h)
            if ob["curve"] and ob["owed"] > 0 and not ob["draw_known"]:
                return True
        return False

    def _lose(self, key: str, why: str):
        # Nothing of ours was spent: the block is simply due again, if it still can be.
        p = self.st["paid"].pop(key)
        log.info("block %s: payment %s no longer counts (%s)", key, p["txid"], why)

    def _payment_tx(self, key: str, p: dict) -> Optional[dict]:
        try:
            hdr = self.btc.getblockheader(p["blockhash"])
        except RPCError:
            hdr = {"confirmations": -1}
        if hdr["confirmations"] < 0:  # its Bitcoin block left the best chain: read again from there
            self.st["scanned"] = min(self.st["scanned"], p["btc_height"] - 1)
            self.st["paid"].pop(key, None)
            return None
        return {"confirmations": hdr["confirmations"], "blockhash": p["blockhash"], "hex": p["hex"]}

    def _coinbase_owners(self, height: int) -> List[str]:
        blk = self.launch.getblock(self.launch.getblockhash(height), 2)
        return [o["scriptPubKey"]["hex"] for o in blk["tx"][0]["vout"] if o["value"] > 0]

    def _learn_draws(self):
        tip = self.launch.getblockcount()
        if self.st["next"] == 0:
            info = self.launch.getlaunchinfo()
            dl = (info.get("descriptor") or {}).get("settle_deadline", 17280)
            self.st["next"] = max(1, tip - dl)
        last = tip - Y.DRAW_DELAY
        h = self.st["next"]
        while h <= last and h < self.st["next"] + 2000:
            ob = self._obligation(h)
            if ob["curve"] and ob["draw_known"] and ob["pay"] > 0 and not ob["settled"] and tip < ob["deadline_height"]:
                self.st["due"][f"{h}:{ob['hash']}"] = {
                    "height": h, "hash": ob["hash"], "tag": ob["tag"], "pay": ob["pay"], "payee": ob["payee"],
                    "pay_script": ob["pay_script"], "deadline_height": ob["deadline_height"],
                    "owners": self._coinbase_owners(h)}
            h += 1
        self.st["next"] = h
        # Drop what is settled, past its deadline, or reorged out (a reorged height is looked at again).
        for k, ob in list(self.st["due"].items()):
            if k in self.st["paid"]:
                continue
            try:
                now = self._obligation(ob["height"]) if ob["height"] <= tip else None
            except RPCError:
                now = None
            if now is None or now["hash"] != ob["hash"] or not now["draw_known"]:
                del self.st["due"][k]
                self.st["next"] = min(self.st["next"], ob["height"])
            elif now["settled"] or tip >= now["deadline_height"]:
                del self.st["due"][k]

    def _scan_bitcoin(self):
        tip = self.btc.getblockcount()
        if self.st["scanned"] < 0:
            self.st["scanned"] = max(0, tip - self.LOOKBACK_BTC)
        elif self.st["scanned_hash"] and self.st["scanned"] <= tip and \
                self.btc.getblockhash(self.st["scanned"]) != self.st["scanned_hash"]:
            self.st["scanned"] = max(0, self.st["scanned"] - 12)  # a Bitcoin reorg: read the last blocks again
        by_tag = {ob["tag"]: k for k, ob in self.st["due"].items() if k not in self.st["paid"]}
        h = self.st["scanned"] + 1
        while h <= tip and h <= self.st["scanned"] + 24:
            bh = self.btc.getblockhash(h)
            if by_tag:
                for tx in self.btc.getblock(bh, 2)["tx"]:
                    self._match(tx, h, bh, by_tag)
            self.st["scanned"], self.st["scanned_hash"] = h, bh
            h += 1

    def _match(self, tx: dict, height: int, bhash: str, by_tag: dict):
        vouts = tx.get("vout", [])
        for o in vouts:
            data = Y.tagged_return(bytes.fromhex(o["scriptPubKey"]["hex"]), b"HF")
            if data is None:
                continue
            if (len(data) - 2) % 20:
                return  # the first tag list is malformed: the transaction binds nothing
            for i in range(0, (len(data) - 2) // 20):
                key = by_tag.get(data[2 + 20 * i:22 + 20 * i].hex())
                if key is None or i >= len(vouts):
                    continue
                ob, out = self.st["due"][key], vouts[i]
                sats = round(out["value"] * 1e8)
                if out["scriptPubKey"]["hex"] == ob["pay_script"] and sats >= ob["pay"]:
                    self.st["paid"][key] = {"txid": tx["txid"], "vout": i, "sats": sats, "payee": ob["payee"],
                                            "pay_script": ob["pay_script"], "hex": tx["hex"],
                                            "blockhash": bhash, "btc_height": height}
                    log.info("block %s: paid on Bitcoin in %s", key, tx["txid"])
            return  # only the first tag list counts

    def pay_due(self):
        with self.lock:
            self._learn_draws()
            self._scan_bitcoin()
            for k in list(self.st["paid"]):
                if k not in self.st["due"]:
                    ob = None
                    try:
                        h = int(k.split(":")[0])
                        ob = self._obligation(h)
                    except RPCError:
                        pass
                    if ob is None or ob["settled"] or ob["hash"] != k.split(":")[1]:
                        self.st["paid"].pop(k, None)
            self._save()
