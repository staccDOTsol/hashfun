"""Sats-leg automation for miners and pools.

A launch with a sats leg locks every curve coinbase until its Bitcoin payment is proven on the
launch chain. The Settler does the whole loop for the blocks its owner mined:

  1. relay Bitcoin headers the launch has not seen (HFH1)
  2. once a block's draw is known, pay the drawn payee on Bitcoin (tagged transaction)
  3. when that payment has enough confirmations, publish the SPV proof (HFP1)

All three ride in the coinbase of the owner's next block, so no spendable launch coins are
needed. State (which blocks are ours, which payments are out) is one JSON file."""
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


def merkle_branch(txids: List[bytes], pos: int) -> List[bytes]:
    level, branch = list(txids), []
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        branch.append(level[pos ^ 1])
        level = [sha256d(level[j] + level[j + 1]) for j in range(0, len(level), 2)]
        pos >>= 1
    return branch


class Settler:
    def __init__(self, launch: RPC, btc_wallet: RPC, state_path: str, max_pay_sats: Optional[int] = None):
        """launch: hashfund RPC. btc_wallet: funded Bitcoin Core wallet RPC that pays the sats.
        max_pay_sats: refuse any single obligation above this (None = no cap)."""
        self.launch, self.btc, self.path, self.max_pay = launch, btc_wallet, state_path, max_pay_sats
        self.lock = threading.RLock()
        self.st = {"mine": [], "paid": {}, "done": []}
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
                    "settled_or_nothing_due": len(self.st["done"])}

    # ------------------------------------------------------------ steps
    def relay_outputs(self) -> List[TxOut]:
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

    def _pay(self, obligations: List[dict]) -> Optional[str]:
        """One Bitcoin tx paying up to TAGS_PER_BTC_TX obligations: output i <-> tag i."""
        outs = [TxOut(ob["pay"], bytes.fromhex(ob["pay_script"])) for ob in obligations]
        outs.append(TxOut(0, Y.payment_outputs_tag([bytes.fromhex(ob["tag"]) for ob in obligations])))
        raw = Tx(version=2, vin=[], vout=outs).serialize(witness=False).hex()
        funded = self.btc.fundrawtransaction(raw, {"changePosition": len(outs)}, False)
        signed = self.btc.signrawtransactionwithwallet(funded["hex"])
        if not signed.get("complete"):
            raise RuntimeError("bitcoin wallet could not sign the sats payment")
        return self.btc.sendrawtransaction(signed["hex"])

    def pay_due(self):
        """Pay every block of ours whose draw is known and that is not paid or settled."""
        with self.lock:
            tip_hash = {}
            batch = []
            for height, bhash in list(self.st["mine"]):
                key = str(height)
                if key in self.st["paid"] or height in self.st["done"]:
                    continue
                try:
                    ob = self.launch.getmintobligation(height)
                except RPCError:
                    continue
                if ob["hash"] != bhash:  # our block was reorged out
                    self.st["mine"].remove([height, bhash])
                    continue
                if not ob["curve"] or ob["owed"] == 0 or ob["settled"] or (ob["draw_known"] and ob["pay"] == 0):
                    self.st["done"].append(height)
                    continue
                if not ob["draw_known"] or "pay_script" not in ob:
                    continue
                if self.max_pay is not None and ob["pay"] > self.max_pay:
                    log.warning("block %d owes %d sats, above the configured cap; not paying", height, ob["pay"])
                    continue
                tip_hash[height] = ob
                batch.append(ob)
            for i in range(0, len(batch), TAGS_PER_BTC_TX):
                group = batch[i:i + TAGS_PER_BTC_TX]
                try:
                    txid = self._pay(group)
                except (RPCError, RuntimeError) as e:
                    log.warning("sats payment failed (will retry): %s", e)
                    break
                for vout, ob in enumerate(group):
                    self.st["paid"][str(ob["height"])] = {"txid": txid, "vout": vout, "candidate": ob.get("candidate", 0),
                                                          "sats": ob["pay"], "payee": ob["payee"]}
                    log.info("block %d: paid %d sats to the drawn %s in %s", ob["height"], ob["pay"], ob["payee"], txid)
            self._save()

    def proof_outputs(self) -> List[TxOut]:
        """HFP1 outputs for payments that are confirmed on Bitcoin and visible to the launch."""
        with self.lock:
            if self._confs is None:
                self._confs = self.launch.getbtcrelay()["confirmations_required"]
            relay_height = self.launch.getbtcrelay()["height"]
            btc_tip = self.btc.getblockcount()
            launch_tip = self.launch.getblockcount()
            outs = []
            for key, p in list(self.st["paid"].items()):
                height = int(key)
                try:
                    ob = self.launch.getmintobligation(height)
                except RPCError:
                    continue
                if ob["settled"]:
                    del self.st["paid"][key]
                    self.st["done"].append(height)
                    continue
                if launch_tip >= ob["deadline_height"]:
                    log.error("block %d missed its settlement deadline; its coinbase is unspendable", height)
                    del self.st["paid"][key]
                    self.st["done"].append(height)
                    continue
                tx = self.btc.gettransaction(p["txid"])
                if tx.get("confirmations", 0) < self._confs or len(outs) >= MAX_PROOFS_PER_BLOCK:
                    continue
                blk = self.btc.getblock(tx["blockhash"], 1)
                # The proof only counts once the launch knows the block deep enough; headers relayed
                # in the same coinbase come first, so compare against what we are about to relay.
                if blk["height"] + self._confs - 1 > min(btc_tip, relay_height + MAX_HEADERS_PER_BLOCK):
                    continue
                txids = [bytes.fromhex(x)[::-1] for x in blk["tx"]]
                pos = blk["tx"].index(p["txid"])
                raw = Tx.parse(bytes.fromhex(tx["hex"])).serialize(witness=False)
                proof = Y.PaymentProof(height, bytes.fromhex(tx["blockhash"])[::-1], pos, merkle_branch(txids, pos),
                                       p["vout"], p["candidate"], raw)
                outs.append(TxOut(0, Y.op_return(proof.payload())))
            self._save()
            return outs

    def coinbase_outputs(self) -> List[TxOut]:
        """Everything the next block's coinbase should carry: headers first, then proofs."""
        with self.lock:
            self.pay_due()
            return self.relay_outputs() + self.proof_outputs()
