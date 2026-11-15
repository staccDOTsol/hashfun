"""Automation of the two legs (sats and qwen) for miners and pools.

Every curve coinbase is locked until what its block owes is paid on the block's own quote chain
(Bitcoin for a block on the BTC curve, Qwencoin for one on the QWEN curve) and proven on the launch
chain. The Settler does the whole loop for the blocks its owner mined:

  1. relay the headers the launch has not seen of every chain it has a node for (HFH1: Bitcoin,
     HFH2: Qwencoin, at most 8 new ones a block: the node evaluates no more)
  2. once a block's draw is known and buried, pay the script the draw fixed, on the block's quote
     chain, from that chain's wallet (tagged transaction: one tag list, tag i for output i)
  3. when that payment has enough confirmations, publish the SPV proof (HFP1 / HFP2)

All three ride in the coinbase of the owner's next block, so no spendable launch coins are
needed. (For Qwencoin headers that is also the only place they count: the node looks at an HFH2
output in a coinbase and nowhere else. The settler has never put headers anywhere else.) State
(which blocks are ours, which payments are out) is one JSON file.

A settler works with one wallet or with both. A block on a curve it has no wallet for is never
paid by it (it says so once): mine the curve you can pay. A chain it has a node of and no wallet
on (btc_node= / qwen_node=) still has its headers relayed: the proofs of everybody who pays on that
chain need them in the launch, and any block's coinbase may carry them.

Reorgs are the dangerous part, because coins that were paid stay paid:
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
payment would buy nothing: that coinbase is lost), and relay headers once the legs are over
(settle_deadline blocks after the last curve block the node no longer looks at them)."""
import json
import logging
import os
import threading
from typing import Dict, List, Optional

from . import yieldmodel as Y
from .btclight import LightError, is_light
from .crypto import sha256d
from .rpc import RPC, RPCError
from .ser import Tx, TxOut

log = logging.getLogger("hashfun.settler")

QUOTES = ("btc", "qwen")
CHAIN_NAME = {"btc": "Bitcoin", "qwen": "Qwencoin"}
UNIT = {"btc": "sats", "qwen": "qwen-sats"}
RELAY_RPC = {"btc": "getbtcrelay", "qwen": "getqwenrelay"}
# Headers of a chain one coinbase relays. Qwencoin: the node evaluates the work of at most 8 Qwencoin
# headers per launch block (each is a pass through 528 MB of weights) and skips the rest, so sending
# more new ones buys nothing; the oldest missing go first, so the tree always connects.
MAX_HEADERS_PER_BLOCK = 200
MAX_NEW_HEADERS = {"btc": MAX_HEADERS_PER_BLOCK, "qwen": Y.MAX_QWEN_PASSES}
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


def _where(node, txid: str, blockhash: str):
    """(height of the block, position in it, merkle branch) of a confirmed transaction. Bitcoin
    through Electrum servers (hashfun.btclight) has no block to read: the branch is asked for there
    and checked against the block's header before it is handed over."""
    if is_light(node):
        pr = node.txproof(txid, blockhash)
        return pr["height"], pr["pos"], pr["branch"]
    blk = node.getblock(blockhash, 1)
    pos = blk["tx"].index(txid)
    return blk["height"], pos, merkle_branch([bytes.fromhex(x)[::-1] for x in blk["tx"]], pos)


class NodeMismatch(RuntimeError):
    """The node does not answer getmintobligation the way this settler reads it."""


_ALWAYS = ("height", "hash", "curve", "quote", "owed", "draw_known", "settled", "deadline_height", "tag")


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
    if missing == ["quote"]:
        raise NodeMismatch("the node answers getmintobligation without a 'quote': it runs the earlier rule set (one curve, "
                           "quoted in BTC only). Under the current rules a block is on the BTC curve or on the QWEN curve "
                           "and is paid on that chain. Update hashfund to the version of this package; nothing is paid "
                           "until then")
    if not missing and ob["quote"] not in QUOTES:
        raise NodeMismatch(f"getmintobligation {ob['height']} names the quote {ob['quote']!r}, which this package does not "
                           "know. Update both; nothing is paid until then")
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
    Mirrors consensus: the draw fixes the amount due and the one script it is due to on the block's
    quote chain (the drawn coin may be spent since: that changes nothing). Only another draw, after
    a reorg of the draw block, makes a payment stop counting. (A block's quote is in its header, so
    a payment for the block with this hash is on the right chain or never was.)"""
    return (bool(ob.get("draw_known")) and 0 < ob.get("pay", 0) <= p["sats"] and ob.get("pay_script") == p["pay_script"]
            and ob.get("quote", "btc") == p.get("quote", "btc"))


class Settler:
    def __init__(self, launch: RPC, btc_wallet: Optional[RPC], state_path: str, max_pay_sats: Optional[int] = None,
                 pay_depth: int = 12, qwen_wallet: Optional[RPC] = None, max_pay_qwen: Optional[int] = None,
                 btc_node: Optional[RPC] = None, qwen_node: Optional[RPC] = None):
        """launch: hashfund RPC. btc_wallet: funded Bitcoin Core wallet RPC that pays what blocks on
        the BTC curve owe. qwen_wallet: funded Qwencoin wallet RPC (qwencoind speaks bitcoin-cli's
        RPC) that pays what blocks on the QWEN curve owe. Either may be None: nothing is then paid
        or proven on that chain.
        btc_node / qwen_node: an RPC of that chain's node to read its headers from, for a chain with
        no wallet here (a wallet RPC is a node RPC as well: where a wallet is given this is not
        needed). Nothing is ever paid through it. With neither a wallet nor a node of a chain, its
        headers are not relayed.
        max_pay_sats / max_pay_qwen: refuse any single obligation above this (None = no cap).
        pay_depth: blocks on top of a block before it is paid, and on top of a settlement before
        it is treated as final. 0 pays at the first chance (tests only)."""
        self.launch, self.path = launch, state_path
        # chains: the wallet that pays on each chain. nodes: where each chain's headers are read.
        self.chains: Dict[str, Optional[RPC]] = {"btc": btc_wallet, "qwen": qwen_wallet}
        self.nodes: Dict[str, Optional[RPC]] = {"btc": btc_node if btc_node is not None else btc_wallet,
                                                "qwen": qwen_node if qwen_node is not None else qwen_wallet}
        self.max_pay = {"btc": max_pay_sats, "qwen": max_pay_qwen}
        self.pay_depth = max(0, pay_depth)
        self.lock = threading.RLock()
        self.st = {"mine": [], "paid": {}, "done": [], "lost": []}
        if os.path.exists(state_path):
            with open(state_path) as f:
                self.st.update(json.load(f))
        self._confs: Dict[str, int] = {}
        self._said = set()   # things said once per run
        self._trouble = {}   # the last complaint about each chain's node, so that it is logged when it changes

    @property
    def btc(self) -> Optional[RPC]:
        """The Bitcoin wallet (as before there were two chains)."""
        return self.chains["btc"]

    @btc.setter
    def btc(self, rpc: Optional[RPC]):
        if self.nodes["btc"] is self.chains["btc"]:
            self.nodes["btc"] = rpc
        self.chains["btc"] = rpc

    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.st, f, indent=1)
        os.replace(tmp, self.path)

    def _once(self, key, message: str, *args):
        if key not in self._said:
            self._said.add(key)
            log.error(message, *args)

    # ------------------------------------------------------------ bookkeeping
    def add_block(self, height: int, block_hash: str):
        """Remember a block we mined (its coinbase is ours to settle)."""
        with self.lock:
            if not any(h == height and b == block_hash for h, b in self.st["mine"]):
                self.st["mine"].append([height, block_hash])
                self._save()

    def status(self) -> dict:
        with self.lock:
            lost = {q: sum(x["sats"] for x in self.st["lost"] if x.get("quote", "btc") == q) for q in QUOTES}
            return {"mined": len(self.st["mine"]), "awaiting_payment_or_proof": len(self.st["paid"]),
                    "settled_or_nothing_due": len(self.st["done"]), "lost_payments": len(self.st["lost"]),
                    "lost_sats": lost["btc"], "lost_qwen": lost["qwen"],
                    "wallets": [q for q in QUOTES if self.chains[q] is not None],
                    "relays": [q for q in QUOTES if self.nodes[q] is not None]}

    def _finish(self, height: int, bhash: str):
        self.st["paid"].pop(f"{height}:{bhash}", None)
        if [height, bhash] in self.st["mine"]:
            self.st["mine"].remove([height, bhash])
        self.st["done"].append(height)
        del self.st["done"][:-2000]

    def _lose(self, key: str, why: str):
        p = self.st["paid"].pop(key)
        quote = p.get("quote", "btc")
        self.st["lost"].append({"block": key, "txid": p["txid"], "sats": p["sats"], "quote": quote, "why": why})
        log.error("block %s: the %d %s paid in %s no longer count (%s)", key, p["sats"], UNIT[quote], p["txid"], why)

    def _obligation(self, height: int) -> dict:
        return checked_obligation(self.launch.getmintobligation(height))

    def sats_leg_over(self) -> bool:
        """settle_deadline blocks after the last curve block (the graduation block) nothing can be
        drawn or settled any more, on either leg, and the node stops looking at headers and proofs.
        A reorg below that height reopens it, so this is asked again every round."""
        info = self.launch.getlaunchinfo()
        try:
            return bool(info["graduated"]) and info["height"] >= info["graduation_height"] + info["descriptor"]["settle_deadline"]
        except (KeyError, TypeError):
            return False  # a node that does not say: keep relaying

    def _chain_trouble(self, quote: str, e: Optional[Exception]):
        """One chain's node not answering must not stop the other chain's work; say it when it changes."""
        text = None if e is None else str(e)
        if self._trouble.get(quote) != text:
            self._trouble[quote] = text
            if text is None:
                log.info("the %s node answers again", CHAIN_NAME[quote])
            else:
                log.warning("the %s node: %s (its headers, payments and proofs wait)", CHAIN_NAME[quote], text)

    # ------------------------------------------------------------ steps
    def relay_outputs(self) -> List[TxOut]:
        if self.sats_leg_over():
            return []
        outs = []
        for quote in QUOTES:
            node = self.nodes[quote]  # the wallet's node, or the node of a chain with no wallet here
            if node is None:
                continue
            try:
                outs += self._relay_chain(quote, node)
                self._chain_trouble(quote, None)
            except (RPCError, OSError, LightError) as e:
                self._chain_trouble(quote, e)
        return outs

    def _relay_chain(self, quote: str, node: RPC) -> List[TxOut]:
        """The headers of one chain the launch has not seen, oldest first, up to that chain's limit."""
        have = getattr(self.launch, RELAY_RPC[quote])()
        tip = node.getblockcount()
        start, limit = have["height"], MAX_NEW_HEADERS[quote]
        same_chain = start <= tip and node.getblockhash(start) == have["best"]
        if not same_chain:
            # Our node is on another branch (or behind): resend recent headers. The launch ignores
            # the ones it knows (they cost it nothing) and connects the rest if the fork is within reach.
            start = max(have["anchor_height"], min(start, tip) - 12)
            limit += 12
        heights = range(start + 1, min(tip, start + limit) + 1)
        hdrs = b"".join(bytes.fromhex(node.getblockheader(node.getblockhash(h), False)) for h in heights)
        return [TxOut(0, Y.op_return(Y.HEADER_TAG[quote] + hdrs))] if hdrs else []

    def _pay(self, group: List[dict], quote: str = "btc") -> bool:
        """One transaction on the quote's chain paying up to TAGS_PER_BTC_TX obligations of that quote:
        output i <-> tag i. The signed tx is saved before it is broadcast, so a crash in between
        cannot lead to a second payment."""
        wallet = self.chains[quote]
        outs = [TxOut(ob["pay"], bytes.fromhex(ob["pay_script"])) for ob in group]
        outs.append(TxOut(0, Y.payment_outputs_tag([bytes.fromhex(ob["tag"]) for ob in group])))
        raw = Tx(version=2, vin=[], vout=outs).serialize(witness=False).hex()
        funded = wallet.fundrawtransaction(raw, {"changePosition": len(outs)}, False)
        signed = wallet.signrawtransactionwithwallet(funded["hex"])
        if not signed.get("complete"):
            raise RuntimeError(f"the {CHAIN_NAME[quote]} wallet could not sign the payment")
        txid = wallet.decoderawtransaction(signed["hex"])["txid"]
        keys = []
        for vout, ob in enumerate(group):
            key = f"{ob['height']}:{ob['hash']}"
            keys.append(key)
            self.st["paid"][key] = {"txid": txid, "vout": vout, "sats": ob["pay"], "payee": ob["payee"],
                                    "pay_script": ob["pay_script"], "hex": signed["hex"], "quote": quote}
        self._save()
        try:
            wallet.sendrawtransaction(signed["hex"])
        except RPCError:
            for key in keys:
                self.st["paid"].pop(key, None)
            self._save()
            raise
        for ob in group:
            log.info("block %d: paid %d %s to the drawn %s on %s in %s", ob["height"], ob["pay"], UNIT[quote], ob["payee"],
                     CHAIN_NAME[quote], txid)
        return True

    def pay_due(self):
        """Pay every block of ours whose draw is known and buried and that is not paid or settled,
        each on its own quote chain."""
        with self.lock:
            batch = {q: [] for q in QUOTES}
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
                quote = ob["quote"]
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
                if self.chains[quote] is None:
                    # Mined on a curve this settler cannot pay. It stays on the list (a settler started
                    # with that wallet pays it) until its deadline passes.
                    self._once(("no wallet", quote),
                               "block %d is on the %s curve and owes %d %s, and this settler has no %s wallet: nothing is "
                               "paid for blocks on that curve, and their coinbases stay locked. Give it one, or mine the "
                               "other curve", height, quote.upper(), ob["pay"], UNIT[quote], CHAIN_NAME[quote])
                    continue
                if self.max_pay[quote] is not None and ob["pay"] > self.max_pay[quote]:
                    log.warning("block %d owes %d %s, above the configured cap; not paying", height, ob["pay"], UNIT[quote])
                    continue
                batch[quote].append(ob)
            for quote in QUOTES:
                for i in range(0, len(batch[quote]), TAGS_PER_BTC_TX):
                    try:
                        self._pay(batch[quote][i:i + TAGS_PER_BTC_TX], quote)
                    except (RPCError, RuntimeError, OSError) as e:
                        log.warning("%s payment failed (will retry): %s", CHAIN_NAME[quote], e)
                        break
            self._save()

    def proof_outputs(self) -> List[TxOut]:
        """HFP1 / HFP2 outputs for payments that are confirmed on their chain and visible to the launch."""
        with self.lock:
            tip = self.launch.getblockcount()
            seen = {}  # per quote, asked once a round: (confirmations required, relay height, the chain's tip)
            outs = []
            for key, p in list(self.st["paid"].items()):
                height, bhash = int(key.split(":")[0]), key.split(":")[1]
                quote = p.get("quote", "btc")
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
                node = self.chains[quote]
                if node is None:
                    self._once(("no node", quote),
                               "block %s was paid on %s (%s) and this settler has no %s node now: its proof cannot be "
                               "published until it has one, and the block's deadline is height %d",
                               key, CHAIN_NAME[quote], p["txid"], CHAIN_NAME[quote], ob["deadline_height"])
                    continue
                try:
                    if quote not in seen:
                        relay = getattr(self.launch, RELAY_RPC[quote])()
                        self._confs[quote] = relay["confirmations_required"]
                        seen[quote] = (relay["confirmations_required"], relay["height"], node.getblockcount())
                    confs_needed, relay_height, chain_tip = seen[quote]
                    tx = self._payment_tx(key, p)
                    if tx is None:
                        continue
                    confs = tx.get("confirmations", 0)
                    if confs < 0:
                        self._lose(key, f"payment tx conflicted on {CHAIN_NAME[quote]}")
                        continue
                    if confs < confs_needed or len(outs) >= MAX_PROOFS_PER_BLOCK:
                        continue
                    chain_height, pos, branch = _where(node, p["txid"], tx["blockhash"])
                    # The proof only counts once the launch knows the block deep enough; headers relayed
                    # in the same coinbase come first, so compare against what we are about to relay.
                    if chain_height + confs_needed - 1 > min(chain_tip, relay_height + MAX_NEW_HEADERS[quote]):
                        continue
                    raw = Tx.parse(bytes.fromhex(tx["hex"])).serialize(witness=False)
                    # (the proof's candidate byte is always 0: the payee is the one the draw fixed)
                    proof = Y.PaymentProof(height, bytes.fromhex(tx["blockhash"])[::-1], pos, branch, p["vout"], 0, raw)
                    outs.append(TxOut(0, Y.op_return(proof.payload(quote))))
                    self._chain_trouble(quote, None)
                except (RPCError, OSError, LightError) as e:
                    self._chain_trouble(quote, e)
            self._save()
            return outs

    def _payment_tx(self, key: str, p: dict) -> Optional[dict]:
        """{confirmations, blockhash, hex} of the payment recorded at key; None: not now."""
        wallet = self.chains[p.get("quote", "btc")]
        try:
            return wallet.gettransaction(p["txid"])
        except RPCError:
            try:  # the wallet does not know it (crash before broadcast): send it now
                wallet.sendrawtransaction(p["hex"])
            except RPCError as e:
                self._lose(key, f"payment tx not broadcastable: {e}")
            return None

    def coinbase_outputs(self) -> List[TxOut]:
        """Everything the next block's coinbase should carry: headers first, then proofs."""
        with self.lock:
            self.pay_due()
            return self.relay_outputs() + self.proof_outputs()


class WatchSettler(Settler):
    """Settles every block that anyone pays for, and pays nothing itself: no wallet on either chain.

    For a site whose users pay what their own blocks owe from their browser wallets. It keeps a list
    of the obligations that are due (drawn, pay > 0, unsettled, before their deadline), reads each
    new block of the two quote chains for transactions whose first "HF" tag list names one of them
    with an output that pays the drawn script enough, and once such a payment is buried it publishes
    the proof, like the paying Settler. A payment made anywhere (this site, another wallet, by hand)
    counts, on the chain of the block's quote: sats on Bitcoin for a block on the BTC curve, qwen on
    Qwencoin for one on the QWEN curve. Without a node of one of the chains (qwen=None: a site with
    no Qwencoin node) the dues of that quote are still listed, and nothing can be seen paid or proven
    for them here.
    """

    LOOKBACK = 144  # blocks of a quote chain read back at the first start: a day of Bitcoin, or of Qwencoin
    LOOKBACK_BTC = LOOKBACK

    def __init__(self, launch: RPC, btc: Optional[RPC], state_path: str, qwen: Optional[RPC] = None):
        super().__init__(launch, btc, state_path, max_pay_sats=None, pay_depth=0, qwen_wallet=qwen)
        self.st.setdefault("due", {})       # "height:hash" -> obligation (quote, tag, pay, pay_script, deadline_height)
        self.st.setdefault("next", 0)       # the next launch height whose draw to look at
        # the last height of each quote chain read for payments (a state file from before there were
        # two chains has Bitcoin's as "scanned" / "scanned_hash")
        scan = self.st.setdefault("scan", {})
        scan.setdefault("btc", {"height": self.st.pop("scanned", -1), "hash": self.st.pop("scanned_hash", "")})
        scan.setdefault("qwen", {"height": -1, "hash": ""})

    def status(self) -> dict:
        with self.lock:
            return {"due": len(self.st["due"]), "paid_awaiting_proof": len(self.st["paid"]),
                    "bitcoin_scanned_to": self.st["scan"]["btc"]["height"],
                    "qwencoin_scanned_to": self.st["scan"]["qwen"]["height"],
                    "chains": [q for q in QUOTES if self.chains[q] is not None]}

    def due(self, script_hex: Optional[str] = None) -> List[dict]:
        """What is owed and unpaid now, each with its `quote` ("btc": pay sats on Bitcoin, "qwen": pay
        qwen on Qwencoin; `pay` is in base units of that quote); with script_hex, only blocks whose
        coinbase pays it."""
        with self.lock:
            out = [dict(ob, key=k, paid=k in self.st["paid"]) for k, ob in self.st["due"].items()]
        if script_hex is not None:
            out = [o for o in out if script_hex in o.get("owners", [])]
        return sorted(out, key=lambda o: o["height"])

    def needs_blocks(self) -> bool:
        """Is something waiting for blocks: a payment for its proof, or a recent block that owes
        something for its draw (DRAW_DELAY blocks on top of it)?"""
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
        quote = p.get("quote", "btc")
        try:
            hdr = self.chains[quote].getblockheader(p["blockhash"])
        except RPCError:
            hdr = {"confirmations": -1}
        if hdr["confirmations"] < 0:  # its block left the best chain: read again from there
            scan = self.st["scan"][quote]
            scan["height"] = min(scan["height"], p.get("chain_height", p.get("btc_height", 0)) - 1)
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
                    "height": h, "hash": ob["hash"], "quote": ob["quote"], "tag": ob["tag"], "pay": ob["pay"],
                    "payee": ob["payee"], "pay_script": ob["pay_script"], "deadline_height": ob["deadline_height"],
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

    def _scan_chain(self, quote: str):
        """Read the next blocks of one quote chain for payments of dues of that quote."""
        node, scan = self.chains[quote], self.st["scan"][quote]
        if is_light(node):
            return self._scan_light(quote, node, scan)
        tip = node.getblockcount()
        if scan["height"] < 0:
            scan["height"] = max(0, tip - self.LOOKBACK)
        elif scan["hash"] and scan["height"] <= tip and node.getblockhash(scan["height"]) != scan["hash"]:
            scan["height"] = max(0, scan["height"] - 12)  # a reorg of that chain: read the last blocks again
        by_tag = {ob["tag"]: k for k, ob in self.st["due"].items()
                  if k not in self.st["paid"] and ob.get("quote", "btc") == quote}
        h = scan["height"] + 1
        while h <= tip and h <= scan["height"] + 24:
            bh = node.getblockhash(h)
            if by_tag:
                for tx in node.getblock(bh, 2)["tx"]:
                    self._match(tx, h, bh, by_tag, quote)
            scan["height"], scan["hash"] = h, bh
            h += 1

    def _scan_light(self, quote: str, node, scan: dict):
        """Bitcoin through Electrum servers (hashfun.btclight): there are no blocks to read. Each
        script that is owed is asked for the payments made to it in the last LOOKBACK blocks (each
        one fetched, hashed and proven in its block before it is listed), and those are matched like
        a block's transactions. Asked again when the chain's tip or the list of what is owed changes."""
        tip = node.getblockcount()
        tip_hash = node.getblockhash(tip)
        by_tag = {ob["tag"]: k for k, ob in self.st["due"].items()
                  if k not in self.st["paid"] and ob.get("quote", "btc") == quote}
        seen = [tip_hash, sorted(by_tag)]
        if by_tag and seen != scan.get("light"):
            for script in sorted({self.st["due"][k]["pay_script"] for k in by_tag.values()}):
                for tx in node.payments_to(script, max(0, tip - self.LOOKBACK)):
                    self._match(tx, tx["height"], tx["blockhash"], by_tag, quote)
        scan["height"], scan["hash"], scan["light"] = tip, tip_hash, seen if by_tag else None

    def _scan_bitcoin(self):
        self._scan_chain("btc")

    def _match(self, tx: dict, height: int, bhash: str, by_tag: dict, quote: str = "btc"):
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
                                            "pay_script": ob["pay_script"], "hex": tx["hex"], "quote": quote,
                                            "blockhash": bhash, "chain_height": height}
                    log.info("block %s: paid on %s in %s", key, CHAIN_NAME[quote], tx["txid"])
            return  # only the first tag list counts

    def pay_due(self):
        with self.lock:
            self._learn_draws()
            for quote in QUOTES:
                if self.chains[quote] is None:
                    continue
                try:
                    self._scan_chain(quote)
                    self._chain_trouble(quote, None)
                except (RPCError, OSError, LightError) as e:
                    self._chain_trouble(quote, e)
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
