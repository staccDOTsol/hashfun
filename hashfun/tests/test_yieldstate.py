"""The sats leg's state machine (hashfun/yieldstate.py) against scenarios worked out by hand, one per
rule, and against itself: the state after any sequence of connects and disconnects must equal the
state of the same chain replayed from nothing.

The model is the reference the node is compared with (hashfun/tests/yield_regtest.py), so these
tests are about the rules, not about an implementation: where they compute an expected payee they do
it from the list of live coins written out in the test."""
import bisect
import itertools
import os
import random
import unittest

from hashfun import descriptor as D
from hashfun import yieldmodel as Y
from hashfun import yieldstate as S
from hashfun.auxpow import AuxTree, serialize_auxpow
from hashfun.crypto import sha256, sha256d
from hashfun.ser import (Tx, TxIn, TxOut, address_to_script, bits_to_target, header_bytes, merkle_branch, merkle_root,
                         push_int, varint, work_from_bits)


def H(*parts) -> bytes:
    return sha256(b"|".join(p if isinstance(p, bytes) else str(p).encode() for p in parts))


def person(n: int) -> bytes:
    """An earning script (P2WPKH), one per person."""
    return b"\x00\x14" + bytes([n]) * 20


LID = H("launch")
CREATOR_BTC = person(0xCC)
A, B, C, E, M, M2 = (person(n) for n in (1, 2, 3, 5, 9, 10))
PARAMS = S.Params(LID, min_payment=10_000, settle_deadline=20, btc_confs=1, creator_btc_script=CREATOR_BTC)


def draw_of(work_hash: bytes, owed: int, params=PARAMS):
    seed = Y.draw_seed(params.launch_id, work_hash)
    pay, payee = Y.compute_draw(owed, params.min_payment, seed)
    return seed, pay, payee


def work_hash_for(owed: int, want, tag="", params=PARAMS) -> bytes:
    """A seed block hash whose draw satisfies want(seed, pay, payee)."""
    for k in range(200_000):
        wh = H("work", tag, k)
        if want(*draw_of(wh, owed, params)):
            return wh
    raise AssertionError("no such draw")


def holder_point_in(total: int, lo: int, hi: int, pay_positive=None):
    def want(seed, pay, payee):
        if payee != Y.HOLDER or not lo <= Y.candidate_point(seed, 0, total) < hi:
            return False
        return pay_positive is None or (pay > 0) == pay_positive
    return want


class Chain:
    """Blocks made by hand, connected to a State as they are made."""

    def __init__(self, params=PARAMS):
        self.p, self.btc, self.blocks, self.k = params, {}, [], 0
        self.state = S.State(params, self.relay())

    def relay(self):
        return S.StubRelay(self.btc)

    def tx(self, spends=(), outs=()) -> S.StateTx:
        self.k += 1
        return S.StateTx(H("tx", self.k), False, list(spends), list(outs))

    def add(self, *txs, curve=False, owed=0, miner=None, reward=50, work_hash=None, cb_outs=None) -> S.Block:
        h = len(self.blocks)
        self.k += 1
        outs = list(cb_outs) if cb_outs is not None else ([(reward, miner)] if miner else [])
        cb = S.StateTx(H("coinbase", self.k), True, [], outs)
        hash_ = H("block", h, self.k)
        b = S.Block(h, hash_, work_hash or hash_, curve and h >= 1, owed, [cb, *txs])
        self.state.connect(b)
        self.blocks.append(b)
        return b

    def pop(self) -> S.Block:
        self.state.disconnect()
        return self.blocks.pop()

    def replayed(self) -> S.State:
        return S.State.replay(self.p, self.relay, self.blocks)

    # ---- Bitcoin payments, as the stub relay sees them
    def payment(self, pays, lists=None, confirmations=1):
        """A Bitcoin transaction with outputs pays = [(script, sats, tag)], then its tag lists
        (default: one list, tag i for output i), alone in a block. Returns (block hash, raw tx)."""
        outs = [TxOut(sats, script) for script, sats, _ in pays]
        for tags in ([[t for _, _, t in pays]] if lists is None else lists):
            outs.append(TxOut(0, Y.payment_outputs_tag(tags)))
        self.k += 1
        raw = Tx(version=2, vin=[TxIn(H("funding", self.k), 0)], vout=outs).serialize(witness=False)
        block = H("btc block", self.k)
        self.btc[block] = (confirmations, sha256d(raw))
        return block, raw

    def tag(self, height: int) -> bytes:
        return Y.pay_tag(self.p.launch_id, self.blocks[height].hash)

    @staticmethod
    def proof(mint_height, btc_block, raw, vout=0, candidate=0):
        return (0, Y.op_return(Y.PaymentProof(mint_height, btc_block, 0, [], vout, candidate, raw).payload()))


def outpoint(block: S.Block, vout=0, tx=0):
    return (block.txs[tx].txid, vout)


class HolderDraw(unittest.TestCase):
    def setUp(self):
        # 0 genesis; 1..3 not on the curve, so their coinbases are live at once: A 100, B 300, C 600;
        # 4 on the curve, owing 20,000 sats (its coinbase to M is held); 5 moves B's coin to E.
        c = self.c = Chain()
        c.add()
        self.a, self.b, self.cc = c.add(miner=A, reward=100), c.add(miner=B, reward=300), c.add(miner=C, reward=600)
        self.m = c.add(curve=True, owed=20_000, miner=M, reward=50)
        self.move = c.add(c.tx(spends=[outpoint(self.b)], outs=[(300, E)]))
        for _ in range(4):
            c.add()
        # live now, in list order: A 100, C 600, E 300. B's coin is dead, M's is held. Block 10 draws for block 4.
        self.live = [(A, outpoint(self.a), 100), (C, outpoint(self.cc), 600), (E, outpoint(self.move, 0, 1), 300)]

    def expected(self, x):
        acc = 0
        for script, (txid, vout), value in self.live:
            acc += value
            if acc > x:
                return script, {"txid": txid[::-1].hex(), "vout": vout, "value": value}
        raise AssertionError

    def test_a_coin_spent_before_the_draw_is_never_drawn_and_the_draw_is_by_live_value(self):
        c, seen = self.c, {}
        self.assertEqual(c.state.earning(), 1000)
        for trial in range(400):
            wh = H("trial", trial)
            seed, pay, payee = draw_of(wh, 20_000)
            c.add(work_hash=wh)
            ob = c.state.obligation(4)
            self.assertEqual((ob["draw_known"], ob["pay"], ob["earning"], ob["payee"]), (True, 20_000, 1000, S.PAYEE_NAMES[payee]))
            if payee == Y.HOLDER:
                script, coin = self.expected(Y.candidate_point(seed, 0, 1000))
                self.assertEqual((ob["pay_script"], ob["coin"]), (script.hex(), coin))
                seen[script] = seen.get(script, 0) + 1
            else:
                self.assertEqual(ob["pay_script"], (CREATOR_BTC if payee == Y.CREATOR else Y.DEV_BTC_SCRIPT).hex())
                self.assertNotIn("coin", ob)
            self.assertNotIn(ob["pay_script"], (B.hex(), M.hex()))  # the spent coin; the miner's own held coinbase
            c.pop()
            self.assertFalse(c.state.obligation(4)["draw_known"])
        self.assertEqual(set(seen), {A, C, E})
        holders = sum(seen.values())
        self.assertAlmostEqual(seen[C] / holders, 0.6, delta=0.09)   # by value: 600 of 1000
        self.assertAlmostEqual(seen[A] / holders, 0.1, delta=0.06)

    def test_the_payee_is_fixed_at_the_draw_even_if_the_coin_moves_in_the_next_block(self):
        c = self.c
        c.add(work_hash=work_hash_for(20_000, holder_point_in(1000, 100, 700)))  # the point falls on C's coin
        before = c.state.obligation(4)
        self.assertEqual((before["pay_script"], before["coin"]["value"]), (C.hex(), 600))
        c.add(c.tx(spends=[outpoint(self.cc)], outs=[(600, E)]))                 # 11: C sells everything
        self.assertEqual(c.state.obligation(4), before)
        self.assertEqual(c.state.earning(), 1000)
        # a payment to the script that C held with at the draw settles, long after the coin is gone
        btc, raw = c.payment([(C, 20_000, c.tag(4))])
        c.add(cb_outs=[c.proof(4, btc, raw)])
        ob = c.state.obligation(4)
        self.assertTrue(ob["settled"] and ob["spendable"])
        self.assertEqual({k: v for k, v in ob.items() if k not in ("settled", "spendable")},
                         {k: v for k, v in before.items() if k not in ("settled", "spendable")})
        # and a payment to where the coin went does not
        c.pop()
        btc, raw = c.payment([(E, 20_000, c.tag(4))])
        c.add(cb_outs=[c.proof(4, btc, raw)])
        self.assertFalse(c.state.obligation(4)["settled"])

    def test_a_coin_made_in_the_draw_block_is_not_in_that_draw_and_one_spent_in_it_still_is(self):
        c = self.c
        wh = work_hash_for(20_000, holder_point_in(1000, 0, 100))                # the point falls on A's coin
        c.add(c.tx(spends=[outpoint(self.a)], outs=[(10**9, E)]), work_hash=wh)  # A's coin is spent in the draw block itself
        ob = c.state.obligation(4)
        self.assertEqual((ob["earning"], ob["pay_script"], ob["coin"]["value"]), (1000, A.hex(), 100))
        self.assertEqual(c.state.earning(), 1000 - 100 + 10**9)

    def test_churn_does_not_buy_weight(self):
        """The review's C3: under the old rule every self-transfer registered its value again."""
        c = self.c
        seeds = [H("churn", k) for k in range(1500)]

        def share_of_e():
            hits = holders = 0
            for wh in seeds:
                seed, _pay, payee = draw_of(wh, 20_000)
                if payee != Y.HOLDER:
                    continue
                c.add(work_hash=wh)
                holders += 1
                hits += c.state.obligation(4)["pay_script"] == E.hex()
                c.pop()
            return hits / holders

        before = share_of_e()
        self.assertAlmostEqual(before, 0.3, delta=0.05)  # 300 of 1000
        c.pop()  # make room: the churn goes into block 9
        spend = outpoint(self.move, 0, 1)
        txs = []
        for _ in range(1000):  # E sends its 300 to itself a thousand times
            t = c.tx(spends=[spend], outs=[(300, E)])
            txs.append(t)
            spend = (t.txid, 0)
        c.add(*txs)
        self.assertEqual(c.state.earning(), 1000)
        self.assertEqual(sum(1 for x in c.state.coins if x.live), 3)
        self.assertEqual(len(c.state.coins), 4 + 1000)
        self.assertEqual(share_of_e(), before)  # the same points fall on the same people: only the order of the list moved


class HeldCoinbase(unittest.TestCase):
    def chain(self, owed):
        c = Chain()
        c.add()
        c.add(miner=A, reward=1000)                               # 1: live at once
        m = c.add(curve=True, owed=owed, miner=M, reward=50)      # 2: held
        for _ in range(5):
            c.add()                                               # 3..7
        return c, m

    def test_released_at_a_draw_that_says_nothing_is_due(self):
        c, m = self.chain(owed=4000)                              # under the minimum: a lottery
        self.assertEqual((c.state.earning(), c.state.spendable(2)), (1000, False))
        wh = work_hash_for(4000, lambda seed, pay, payee: pay == 0)
        c.add(c.tx(outs=[(7, E)]), miner=B, reward=5, work_hash=wh)   # 8: the draw; this block has coins of its own
        ob = c.state.obligation(2)
        self.assertEqual((ob["pay"], ob["earning"], ob["settled"], ob["spendable"]), (0, 1000, False, True))
        self.assertIn(ob["payee"], S.PAYEE_NAMES)            # the class is reported; who would have been paid is not
        self.assertTrue("pay_script" not in ob and "coin" not in ob)
        self.assertEqual(c.state.earning(), 1000 + 50 + 5 + 7)
        # appended at the draw, before anything block 8 itself makes
        self.assertEqual([(x.script, x.value) for x in c.state.coins], [(A, 1000), (M, 50), (B, 5), (E, 7)])
        c.pop()
        self.assertEqual((c.state.earning(), [x.script for x in c.state.coins]), (1000, [A]))
        self.assertEqual(c.state.snapshot(), c.replayed().snapshot())

    def test_released_when_the_block_settles_and_never_otherwise(self):
        c, m = self.chain(owed=20_000)
        c.add(work_hash=work_hash_for(20_000, holder_point_in(1000, 0, 1000)))   # 8: the draw, payee A
        self.assertEqual((c.state.obligation(2)["pay_script"], c.state.earning(), c.state.spendable(2)), (A.hex(), 1000, False))
        for _ in range(3):
            c.add()                                               # 9..11: nothing changes while it is unpaid
            self.assertEqual(c.state.earning(), 1000)
        btc, raw = c.payment([(A, 20_000, c.tag(2))])
        c.add(miner=B, reward=5, cb_outs=[c.proof(2, btc, raw), (5, B)])  # 12: the proof rides in the coinbase
        self.assertTrue(c.state.obligation(2)["settled"])
        self.assertEqual([(x.script, x.value) for x in c.state.coins], [(A, 1000), (M, 50), (B, 5)])  # released, then 12's own
        self.assertEqual(c.state.earning(), 1055)
        c.pop()
        self.assertEqual((c.state.earning(), c.state.obligation(2)["settled"], c.state.spendable(2)), (1000, False, False))
        # never paid: never live, never spendable, whatever happens after the deadline
        for _ in range(PARAMS.settle_deadline + 5):
            c.add()
            self.assertEqual((c.state.live_value(), c.state.spendable(2)), (1000, False))
        self.assertEqual(c.state.snapshot(), c.replayed().snapshot())

    def test_with_nobody_holding_the_holders_share_is_owed_to_no_one(self):
        def first_draw(payee):
            c = Chain()
            c.add()
            c.add(curve=True, owed=20_000, miner=M, reward=50)    # 1: the only value anywhere, and it is held
            for _ in range(5):
                c.add()
            self.assertEqual((c.state.earning(), c.state.spendable(1)), (0, False))
            c.add(work_hash=work_hash_for(20_000, lambda seed, pay, p: p == payee))  # 7: the draw of block 1
            return c
        c = first_draw(Y.HOLDER)
        ob = c.state.obligation(1)
        self.assertEqual((ob["payee"], ob["pay"], ob["earning"], ob["settled"], ob["spendable"]), ("holder", 0, 0, False, True))
        self.assertTrue("pay_script" not in ob and "coin" not in ob)
        self.assertEqual([(x.script, x.value) for x in c.state.coins], [(M, 50)])  # free: released at its draw
        btc, raw = c.payment([(CREATOR_BTC, 20_000, c.tag(1))])                    # and there is nothing to settle
        c.add(cb_outs=[c.proof(1, btc, raw)])
        self.assertFalse(c.state.obligation(1)["settled"])
        c.pop()
        c.pop()
        self.assertEqual((c.state.coins, c.state.spendable(1), c.state.obligation(1)["draw_known"]), ([], False, False))
        # the creator's and the dev's shares are theirs whether anybody holds or not
        for payee, script in ((Y.CREATOR, CREATOR_BTC), (Y.DEV, Y.DEV_BTC_SCRIPT)):
            c = first_draw(payee)
            ob = c.state.obligation(1)
            self.assertEqual((ob["payee"], ob["pay"], ob["pay_script"], ob["earning"], ob["spendable"]),
                             (S.PAYEE_NAMES[payee], 20_000, script.hex(), 0, False))
            self.assertEqual((c.state.coins, "coin" in ob), ([], False))
            btc, raw = c.payment([(script, 20_000, c.tag(1))])
            c.add(cb_outs=[c.proof(1, btc, raw)])
            self.assertEqual((c.state.obligation(1)["settled"], c.state.earning()), (True, 50))

    def test_a_miner_cannot_draw_its_own_held_coinbase(self):
        c = Chain()
        c.add()
        c.add(miner=A, reward=1)                                  # 1: one unit, live
        c.add(curve=True, owed=20_000, miner=M, reward=10**12)    # 2: a fortune, held
        for _ in range(5):
            c.add()
        for k in range(200):                                      # 8: the draw of block 2, two hundred ways
            wh = H("own", k)
            c.add(work_hash=wh)
            ob = c.state.obligation(2)
            self.assertEqual(ob["earning"], 1)
            if draw_of(wh, 20_000)[2] == Y.HOLDER:
                self.assertEqual((ob["pay_script"], ob["coin"]["value"]), (A.hex(), 1))
            self.assertNotEqual(ob["pay_script"], M.hex())
            c.pop()

    def test_a_curve_block_that_owes_nothing_is_not_held(self):
        c = Chain()
        c.add()
        c.add(curve=True, owed=0, miner=M, reward=50)
        self.assertEqual((c.state.earning(), c.state.spendable(1)), (50, True))
        for _ in range(6):
            c.add()
        ob = c.state.obligation(1)                                # it still has a draw: a draw for nothing
        self.assertEqual((ob["draw_known"], ob["pay"], ob["spendable"], ob["settled"]), (True, 0, True, False))
        self.assertEqual(c.state.earning(), 50)

    def test_creator_and_dev_draws(self):
        for payee, script in ((Y.CREATOR, CREATOR_BTC), (Y.DEV, Y.DEV_BTC_SCRIPT)):
            c, _ = self.chain(owed=20_000)
            c.add(work_hash=work_hash_for(20_000, lambda seed, pay, p, payee=payee: p == payee))
            ob = c.state.obligation(2)
            self.assertEqual((ob["payee"], ob["pay"], ob["pay_script"], ob["earning"]),
                             (S.PAYEE_NAMES[payee], 20_000, script.hex(), 1000))
            self.assertNotIn("coin", ob)
            # under the minimum the amount is a lottery: the minimum to the same payee, or nothing to nobody
            c, _ = self.chain(owed=4000)
            c.add(work_hash=work_hash_for(4000, lambda seed, pay, p, payee=payee: p == payee and pay > 0))
            ob = c.state.obligation(2)
            self.assertEqual((ob["payee"], ob["pay"], ob["pay_script"], ob["spendable"]),
                             (S.PAYEE_NAMES[payee], 10_000, script.hex(), False))
            c.pop()
            c.add(work_hash=work_hash_for(4000, lambda seed, pay, p, payee=payee: p == payee and pay == 0))
            ob = c.state.obligation(2)
            self.assertEqual((ob["payee"], ob["pay"], ob["spendable"], "pay_script" in ob, "coin" in ob),
                             (S.PAYEE_NAMES[payee], 0, True, False, False))

    def test_no_draw_before_six_blocks_and_none_for_blocks_off_the_curve(self):
        c, _ = self.chain(owed=20_000)                            # tip is 7; block 2's draw comes with block 8
        ob = c.state.obligation(2)
        self.assertEqual((ob["draw_known"], ob["draw_height"], ob["deadline_height"]), (False, 8, 2 + PARAMS.settle_deadline))
        self.assertEqual(set(ob), {"height", "hash", "curve", "owed", "draw_known", "draw_height", "settled", "spendable",
                                   "deadline_height", "tag"})
        self.assertEqual((ob["hash"], ob["tag"]), (c.blocks[2].hash[::-1].hex(), Y.pay_tag(LID, c.blocks[2].hash).hex()))
        c.add(work_hash=work_hash_for(20_000, lambda seed, pay, payee: payee == Y.HOLDER))
        self.assertEqual(set(c.state.obligation(2)) - set(ob), {"pay", "payee", "earning", "pay_script", "coin"})
        c.pop()
        c.add(work_hash=work_hash_for(20_000, lambda seed, pay, payee: payee == Y.DEV))
        self.assertEqual(set(c.state.obligation(2)) - set(ob), {"pay", "payee", "earning", "pay_script"})
        for _ in range(2):
            c.add()
        self.assertFalse(c.state.obligation(1)["draw_known"])     # block 1 is not on the curve: it never has a draw
        self.assertEqual((c.state.obligation(1)["curve"], c.state.obligation(1)["owed"], c.state.spendable(1)), (False, 0, True))
        self.assertTrue(c.state.spendable(99))                    # a height that is not there holds nothing back


class FirstBlocks(unittest.TestCase):
    """A launch from its first block: every block is on the curve and owes sats, so every coinbase is
    held and at the first draws nobody holds anything."""

    def miner(self, h):
        return person(100 + h)

    def start(self, first_class):
        c = Chain()
        c.add()                                                   # genesis: no coins
        for h in range(1, 7):
            c.add(curve=True, owed=20_000, miner=self.miner(h), reward=50)
        self.assertEqual((c.state.earning(), [c.state.spendable(h) for h in range(1, 7)]), (0, [False] * 6))
        c.add(curve=True, owed=20_000, miner=self.miner(7), reward=50,
              work_hash=work_hash_for(20_000, lambda seed, pay, payee: payee == first_class))
        return c

    def holder_block(self, c, total, lo, hi):
        h = len(c.blocks)
        return c.add(curve=True, owed=20_000, miner=self.miner(h), reward=50,
                     work_hash=work_hash_for(20_000, holder_point_in(total, lo, hi), tag=h))

    def test_the_first_holder_draw_is_free_and_then_that_coin_is_drawn_until_others_settle(self):
        c = self.start(Y.HOLDER)                                  # block 7: the draw of block 1
        ob = c.state.obligation(1)
        self.assertEqual((ob["payee"], ob["pay"], ob["earning"], ob["spendable"], "pay_script" in ob), ("holder", 0, 0, True, False))
        self.assertEqual([(x.script, x.value) for x in c.state.coins], [(self.miner(1), 50)])
        first = {"txid": c.blocks[1].txs[0].txid[::-1].hex(), "vout": 0, "value": 50}
        for h in (8, 9, 10):                                      # holder draws of blocks 2, 3, 4: one coin to fall on
            self.holder_block(c, 50, 0, 50)
            ob = c.state.obligation(h - 6)
            self.assertEqual((ob["pay"], ob["payee"], ob["pay_script"], ob["coin"], ob["earning"], ob["spendable"]),
                             (20_000, "holder", self.miner(1).hex(), first, 50, False))
        self.assertEqual(c.state.earning(), 50)
        # block 2's miner pays block 1's: its coinbase is live from the block that carries the proof
        btc, raw = c.payment([(self.miner(1), 20_000, c.tag(2))])
        wh = work_hash_for(20_000, holder_point_in(50, 0, 50), tag="eleven")
        c.add(curve=True, owed=20_000, miner=self.miner(11), reward=50, work_hash=wh, cb_outs=[c.proof(2, btc, raw), (50, self.miner(11))])
        self.assertEqual((c.state.obligation(5)["earning"], c.state.obligation(5)["coin"]), (50, first))  # drawn before the proof
        self.assertEqual(([(x.script, x.value) for x in c.state.coins], c.state.earning()),
                         ([(self.miner(1), 50), (self.miner(2), 50)], 100))
        # from here the two share the draws by value: a point under 50 is the first coin, the rest the second
        self.holder_block(c, 100, 0, 50)                          # 12: the draw of block 6
        self.assertEqual((c.state.obligation(6)["pay_script"], c.state.obligation(6)["earning"]), (self.miner(1).hex(), 100))
        c.pop()
        self.holder_block(c, 100, 50, 100)
        second = {"txid": c.blocks[2].txs[0].txid[::-1].hex(), "vout": 0, "value": 50}
        self.assertEqual((c.state.obligation(6)["pay_script"], c.state.obligation(6)["coin"]), (self.miner(2).hex(), second))
        self.assertEqual(c.state.snapshot(), c.replayed().snapshot())

    def test_creator_and_dev_draws_are_due_from_the_first_block_and_the_first_holder_draw_after_them_is_free(self):
        for first_class, script in ((Y.CREATOR, CREATOR_BTC), (Y.DEV, Y.DEV_BTC_SCRIPT)):
            c = self.start(first_class)
            ob = c.state.obligation(1)
            self.assertEqual((ob["pay"], ob["pay_script"], ob["earning"], ob["spendable"]), (20_000, script.hex(), 0, False))
            self.assertEqual(c.state.coins, [])
            c.add(curve=True, owed=20_000, miner=self.miner(8), reward=50,
                  work_hash=work_hash_for(20_000, lambda seed, pay, payee: payee == Y.HOLDER))  # the draw of block 2
            ob = c.state.obligation(2)
            self.assertEqual((ob["payee"], ob["pay"], ob["earning"], ob["spendable"]), ("holder", 0, 0, True))
            self.assertEqual([(x.script, x.value) for x in c.state.coins], [(self.miner(2), 50)])
            self.assertFalse(c.state.spendable(1))                # block 1 still owes its creator or dev


class Settling(unittest.TestCase):
    def setUp(self, btc_confs=1):
        self.p = S.Params(LID, 10_000, 20, btc_confs, CREATOR_BTC)
        c = self.c = Chain(self.p)
        c.add()
        c.add(miner=A, reward=1000)
        c.add(curve=True, owed=20_000, miner=M, reward=50)        # 2
        c.add(curve=True, owed=20_000, miner=M2, reward=60)       # 3
        for _ in range(4):
            c.add()                                               # 4..7
        want_a = holder_point_in(1000, 0, 1000)
        c.add(work_hash=work_hash_for(20_000, want_a, "two"))     # 8: draw of 2, payee A
        c.add(work_hash=work_hash_for(20_000, want_a, "three"))   # 9: draw of 3, payee A
        self.assertEqual([c.state.obligation(h)["pay_script"] for h in (2, 3)], [A.hex(), A.hex()])

    def settled(self):
        return [self.c.state.obligation(h)["settled"] for h in (2, 3)]

    def test_the_first_tag_list_is_the_only_one(self):
        """The review's C2: one output, two tag lists, two blocks settled by one payment."""
        c = self.c
        btc, raw = c.payment([(A, 20_000, c.tag(2))], lists=[[c.tag(2)], [c.tag(3)]])
        c.add(cb_outs=[c.proof(2, btc, raw), c.proof(3, btc, raw)])
        self.assertEqual(self.settled(), [True, False])
        c.pop()
        # the other way round: block 3 is the one the first list names
        btc, raw = c.payment([(A, 20_000, c.tag(3))], lists=[[c.tag(3)], [c.tag(2)]])
        c.add(cb_outs=[c.proof(2, btc, raw), c.proof(3, btc, raw)])
        self.assertEqual(self.settled(), [False, True])
        c.pop()
        # a first list of a broken length does not make way for the second
        outs = [TxOut(20_000, A), TxOut(0, Y.op_return(b"HF" + c.tag(2)[:19])), TxOut(0, Y.payment_outputs_tag([c.tag(2)]))]
        raw = Tx(version=2, vin=[TxIn(H("f"), 0)], vout=outs).serialize(witness=False)
        c.btc[H("odd")] = (1, sha256d(raw))
        c.add(cb_outs=[c.proof(2, H("odd"), raw)])
        self.assertEqual(self.settled(), [False, False])

    def test_one_transaction_may_still_pay_several_blocks_one_output_each(self):
        c = self.c
        btc, raw = c.payment([(A, 20_000, c.tag(2)), (A, 20_000, c.tag(3))])
        c.add(cb_outs=[c.proof(2, btc, raw, vout=0), c.proof(3, btc, raw, vout=1)])
        self.assertEqual(self.settled(), [True, True])
        c.pop()
        c.add(cb_outs=[c.proof(2, btc, raw, vout=1), c.proof(3, btc, raw, vout=0)])  # each proof naming the other's output
        self.assertEqual(self.settled(), [False, False])

    def test_what_does_not_settle(self):
        c, tag = self.c, self.c.tag(2)
        cases = {
            "another script": c.payment([(E, 20_000, tag)]),
            "one sat short": c.payment([(A, 19_999, tag)]),
            "another block's tag": c.payment([(A, 20_000, c.tag(4))]),
            "no tag list": c.payment([(A, 20_000, tag)], lists=[]),
            "not confirmed": c.payment([(A, 20_000, tag)], confirmations=0),
        }
        for name, (btc, raw) in cases.items():
            c.add(cb_outs=[c.proof(2, btc, raw)])
            self.assertEqual(self.settled(), [False, False], name)
            c.pop()
        btc, raw = c.payment([(A, 20_000, tag)])
        for name, out in {"candidate 1": c.proof(2, btc, raw, candidate=1), "another output": c.proof(2, btc, raw, vout=1),
                          "a Bitcoin block nobody relayed": c.proof(2, H("unknown"), raw),
                          "a block that is not on the curve": c.proof(1, btc, raw),
                          "a block that does not exist yet": c.proof(10, btc, raw),
                          "height 0": c.proof(0, btc, raw)}.items():
            c.add(cb_outs=[out])
            self.assertEqual(self.settled(), [False, False], name)
            c.pop()
        # the same payment with the right proof does settle; twice is once; an overpayment is fine
        c.add(cb_outs=[c.proof(2, btc, raw), c.proof(2, btc, raw)])
        self.assertEqual((self.settled(), c.state.info[-1].settled_here), ([True, False], [2]))
        c.pop()
        btc, raw = c.payment([(A, 20_001, tag)])
        c.add(cb_outs=[c.proof(2, btc, raw)])
        self.assertEqual(self.settled(), [True, False])

    def test_a_proof_in_a_transaction_that_is_not_the_coinbase_counts_too_and_in_output_order(self):
        c = self.c
        btc, raw = c.payment([(A, 20_000, c.tag(2))])
        c.add(c.tx(outs=[(9, E), c.proof(2, btc, raw), (11, B)]), miner=C, reward=3)
        self.assertTrue(self.settled()[0])
        # 10's coinbase coin first, then (released by the proof inside the transaction) block 2's, then the transaction's own
        self.assertEqual([(x.script, x.value) for x in c.state.coins], [(A, 1000), (C, 3), (M, 50), (E, 9), (B, 11)])

    def test_the_deadline_is_inclusive_and_the_draw_block_itself_is_too_early(self):
        c = self.c                                                # tip 9; block 3's deadline is height 23
        btc, raw = c.payment([(A, 20_000, c.tag(3))])
        while c.state.height() < 3 + self.p.settle_deadline - 1:
            c.add()
        c.add(cb_outs=[c.proof(3, btc, raw)])                     # at height 23: the last block that may carry it
        self.assertEqual((c.state.height(), self.settled()[1]), (23, True))
        c.pop()
        c.add()
        c.add(cb_outs=[c.proof(3, btc, raw)])                     # at height 24: too late, for good
        self.assertEqual((c.state.height(), self.settled()[1], c.state.spendable(3)), (24, False, False))
        # too early: a proof inside the very block that makes the draw
        c2 = Chain(self.p)
        c2.add()
        c2.add(miner=A, reward=1000)
        c2.add(curve=True, owed=20_000, miner=M, reward=50)
        for _ in range(5):
            c2.add()
        wh = work_hash_for(20_000, holder_point_in(1000, 0, 1000))
        btc, raw = c2.payment([(A, 20_000, c2.tag(2))])
        c2.add(cb_outs=[c2.proof(2, btc, raw)], work_hash=wh)     # block 8 draws for block 2 and carries its proof
        self.assertEqual((c2.state.obligation(2)["pay_script"], c2.state.obligation(2)["settled"]), (A.hex(), False))
        c2.add(cb_outs=[c2.proof(2, btc, raw)])
        self.assertTrue(c2.state.obligation(2)["settled"])

    def test_confirmations(self):
        self.setUp(btc_confs=3)
        c = self.c
        btc, raw = c.payment([(A, 20_000, c.tag(2))], confirmations=2)
        c.add(cb_outs=[c.proof(2, btc, raw)])
        self.assertEqual(self.settled(), [False, False])
        c.btc[btc] = (3, c.btc[btc][1])
        c.add(cb_outs=[c.proof(2, btc, raw)])
        self.assertEqual(self.settled(), [True, False])

    def test_a_block_with_nothing_due_cannot_be_settled(self):
        c = Chain()
        c.add()
        c.add(miner=A, reward=1000)
        c.add(curve=True, owed=4000, miner=M, reward=50)
        for _ in range(5):
            c.add()
        c.add(work_hash=work_hash_for(4000, lambda seed, pay, payee: pay == 0 and payee == Y.HOLDER))
        btc, raw = c.payment([(A, 10_000, c.tag(2))])
        c.add(cb_outs=[c.proof(2, btc, raw)])
        self.assertEqual((c.state.obligation(2)["settled"], c.state.obligation(2)["spendable"]), (False, True))

    def test_relayed_headers_are_counted_and_undone(self):
        c = self.c
        headers = [bytes([k]) * 80 for k in range(3)]
        c.add(cb_outs=[(0, Y.op_return(b"HFH1" + headers[0] + headers[1])), (0, Y.op_return(b"HFH1" + headers[1] + headers[2])),
                       (0, Y.op_return(b"HFH1" + headers[0][:79]))])
        self.assertEqual((c.state.relay.headers, c.state.info[-1].relayed), ([sha256d(x) for x in headers],) * 2)
        c.pop()
        self.assertEqual(c.state.relay.headers, [])


class Undo(unittest.TestCase):
    def test_disconnect_is_the_inverse_of_connect_for_everything_a_block_can_do(self):
        c = Chain()
        c.add()
        a = c.add(miner=A, reward=1000)
        c.add(curve=True, owed=20_000, miner=M, reward=50)        # 2: to be settled by the block under test
        c.add(curve=True, owed=4000, miner=M2, reward=60)         # 3: to be released by its draw in the block under test
        for _ in range(4):
            c.add()
        c.add(work_hash=work_hash_for(20_000, holder_point_in(1000, 0, 1000)))  # 8: draw of 2
        before = c.state.snapshot()
        btc, raw = c.payment([(A, 20_000, c.tag(2))])
        wh = work_hash_for(4000, lambda seed, pay, payee: pay == 0)
        # block 9: draws for 3 (released), settles 2 (released), relays a header, kills A's coin, makes new coins
        c.add(c.tx(spends=[outpoint(a)], outs=[(400, B), (600, C)]), miner=E, reward=5, work_hash=wh,
              cb_outs=[(0, Y.op_return(b"HFH1" + bytes(80))), c.proof(2, btc, raw), (5, E)])
        i = c.state.info[-1]
        self.assertEqual((i.drew, i.released_here, i.settled_here, i.killed, len(i.relayed)), (3, [3, 2], [2], [0], 1))
        self.assertEqual([(x.script, x.value, x.live) for x in c.state.coins],
                         [(A, 1000, False), (M2, 60, True), (M, 50, True), (E, 5, True), (B, 400, True), (C, 600, True)])
        self.assertEqual(c.state.snapshot(), c.replayed().snapshot())
        c.pop()
        self.assertEqual(c.state.snapshot(), before)
        self.assertEqual(c.state.snapshot(), c.replayed().snapshot())

    def test_a_different_branch_after_a_disconnect_equals_that_chain_replayed(self):
        c = Chain()
        c.add()
        coins = [c.add(miner=person(20 + k), reward=100 * (k + 1)) for k in range(4)]
        c.add(curve=True, owed=20_000, miner=M, reward=50)        # 5
        for _ in range(5):
            c.add()
        first = [c.add(c.tx(spends=[outpoint(coins[k])], outs=[(100 * (k + 1), E)]), work_hash=H("branch one", k))
                 for k in range(3)]                               # 11 draws for 5
        one = c.state.obligation(5)
        for _ in first:
            c.pop()
            self.assertEqual(c.state.snapshot(), c.replayed().snapshot())
        for k in range(4):
            c.add(c.tx(spends=[outpoint(coins[3 - k])], outs=[(1, B)]), work_hash=H("branch two", k))
            self.assertEqual(c.state.snapshot(), c.replayed().snapshot())
        self.assertEqual(c.state.obligation(5)["earning"], one["earning"])  # both branches drew over the same live coins
        self.assertEqual(c.state.info[5].seed, Y.draw_seed(LID, H("branch two", 0)))  # ... each with its own block's seed


class BtcSim:
    """A regtest Bitcoin for the random scenario: headers with real proof of work at the regtest limit."""

    def __init__(self):
        self.time = 1_600_000_000
        self.anchor = self._header(bytes(32), H("anchor"))
        self.chain = [self.anchor]   # headers, best chain
        self.roots = {}

    def _header(self, prev: bytes, root: bytes) -> bytes:
        self.time += 600
        for nonce in itertools.count():
            h = header_bytes(1, prev, root, self.time, 0x207FFFFF, nonce)
            if int.from_bytes(sha256d(h), "little") <= bits_to_target(0x207FFFFF):
                return h

    def mine(self, txids):
        """A block holding these transactions (after a made-up coinbase). Returns its hash."""
        txids = [H("btc coinbase", len(self.chain))] + list(txids)
        hdr = self._header(sha256d(self.chain[-1]), merkle_root(txids))
        self.chain.append(hdr)
        self.roots[sha256d(hdr)] = txids
        return sha256d(hdr)


class RandomChains(unittest.TestCase):
    """Random blocks, spends, payments (right and wrong), header relays and reorgs, with the real
    header relay. After every step: the state equals the same chain replayed from nothing, and
    every draw equals a payee worked out a second way."""

    def run_one(self, seed: int, steps: int):
        rng = random.Random(seed)
        btc = BtcSim()
        params = S.Params(LID, 10_000, 30, rng.choice([1, 2]), CREATOR_BTC)
        factory = lambda: S.HeaderRelay(btc.anchor, 0, 0, True)  # noqa: E731
        state, blocks, counter = S.State(params, factory()), [], itertools.count()
        people = [person(40 + k) for k in range(5)]
        proofs = []        # every proof output ever made (also the wrong ones): they may ride again after a reorg
        stats = {"kills": 0, "settled": 0, "released_at_draw": 0, "reorgs": 0, "wrong": 0, "holder_draws": 0, "nobody_holds": 0,
                 "past_the_end": 0, "reopened": 0}
        curve_until, walked_back = steps // 2, False  # the sats leg ends at curve_until - 1 + 30, well inside the run

        def make_block():
            h = len(blocks)
            hash_ = H("rc", seed, next(counter))
            curve = 1 <= h < curve_until
            owed = rng.choice([0, 4000, 4000, 20_000, 20_000, 35_000]) if curve else 0
            cb_outs = [(rng.choice([0, 1, 50, 500]), rng.choice(people)), (rng.choice([0, 3]), CREATOR_BTC)]
            if h == 0:
                cb_outs = []  # as in a real launch: the genesis block makes no coin,
            elif h <= 8:
                owed = max(owed, 4000)  # and the first blocks all owe, so the first draws find nobody holding
            if rng.random() < 0.15:
                cb_outs.append((0, Y.yield_tag_script(rng.choice([person(77), b"\x51", b""]))))  # a redirect, or a broken one
            # relay: the Bitcoin headers the launch has not seen, sometimes
            known = set(state.relay.chain.nodes)
            missing = [x for x in btc.chain[1:] if sha256d(x) not in known]
            if missing and rng.random() < 0.8:
                cb_outs.append((0, Y.op_return(b"HFH1" + b"".join(missing[:rng.randrange(1, 6)]))))
            for p in rng.sample(proofs, min(len(proofs), rng.randrange(0, 4))):
                cb_outs.append(p)
            txs = []
            live = [(c.txid, c.vout) for c in state.coins if c.live]
            for _ in range(rng.randrange(0, 4) if h > 8 else 0):  # (the transactions here make coins from nothing)
                spends = rng.sample(live, min(len(live), rng.randrange(0, 3)))
                live = [x for x in live if x not in spends]
                if rng.random() < 0.1:
                    spends.append((H("nothing", next(counter)), 0))  # an outpoint that is no coin: kills nothing
                outs = [(rng.choice([0, 1, 10, 100, 1000]), rng.choice(people + [b"\x51", b"\x6a\x01\x00"]))
                        for _ in range(rng.randrange(1, 4))]
                txs.append(S.StateTx(H("rtx", seed, next(counter)), False, spends, outs))
            return S.Block(h, hash_, hash_ if rng.random() < 0.8 else H("parent of", hash_), curve, owed,
                           [S.StateTx(H("rcb", seed, next(counter)), True, [], cb_outs)] + txs)

        def pay_someone():
            due = [h for h, i in enumerate(state.info) if i.draw_known and i.pay > 0 and not i.settled]
            if not due:
                return
            pick = rng.sample(due, min(len(due), rng.randrange(1, 4)))
            wrong = rng.choice([None, None, None, "script", "short", "tag", "candidate", "two lists"])
            pays = [(state.info[h].pay_script, state.info[h].pay, Y.pay_tag(LID, state.info[h].hash)) for h in pick]
            lists, candidate = None, 0
            if wrong == "script":
                pays[0] = (person(99), pays[0][1], pays[0][2])
            elif wrong == "short":
                pays[0] = (pays[0][0], pays[0][1] - 1, pays[0][2])
            elif wrong == "tag":
                pays[0] = (pays[0][0], pays[0][1], H("other")[:20])
            elif wrong == "candidate":
                candidate = 1
            elif wrong == "two lists":  # the real tags only in a second list
                lists = [[H("decoy", k)[:20] for k in range(len(pays))], [t for _, _, t in pays]]
            outs = [TxOut(s, script) for script, s, _ in pays]
            for tags in ([[t for _, _, t in pays]] if lists is None else lists):
                outs.append(TxOut(0, Y.payment_outputs_tag(tags)))
            raw = Tx(version=2, vin=[TxIn(H("fund", next(counter)), 0)], vout=outs).serialize(witness=False)
            block = btc.mine([sha256d(raw)])
            txids = btc.roots[block]
            for vout, h in enumerate(pick):
                proofs.append((0, Y.op_return(Y.PaymentProof(h, block, 1, merkle_branch(txids, 1), vout, candidate, raw).payload())))
            stats["wrong"] += wrong is not None

        def second_opinion(b: S.Block):
            """The draw this block will make, from the live coins as they stand before it."""
            m = b.height - S.DRAW_DELAY
            if m < 1 or not state.info[m].curve:
                return None
            seed_, pay, payee = draw_of(b.work_hash, state.info[m].owed, params)
            live = [c for c in state.coins if c.live]
            total = sum(c.value for c in live)
            if pay == 0 or (payee == Y.HOLDER and not total):
                return 0, b"", total
            if payee == Y.DEV:
                return pay, Y.DEV_BTC_SCRIPT, total
            if payee == Y.CREATOR:
                return pay, CREATOR_BTC, total
            sums = list(itertools.accumulate(c.value for c in live))
            return pay, live[bisect.bisect_right(sums, Y.candidate_point(seed_, 0, total))].script, total

        for step in range(steps):
            depth = rng.randrange(1, 5) if blocks and rng.random() < 0.12 else 0
            if len(state.above) >= 2 and not walked_back:  # once per run: from past the end back to before it
                depth, walked_back = len(state.above) + rng.randrange(1, 4), True
            if depth:
                was_closed = state.closed()
                for _ in range(min(len(blocks) - 1, depth)):
                    state.disconnect()
                    blocks.pop()
                stats["reorgs"] += 1
                stats["reopened"] += was_closed and not state.closed()
                self.assertEqual(state.snapshot(), S.State.replay(params, factory, blocks).snapshot(), (seed, step, "undo"))
            if rng.random() < 0.5:
                pay_someone()
            if rng.random() < 0.3:
                btc.mine([])
            b = make_block()
            before = state.snapshot() if state.closed() else None
            expect = None if state.closed() else second_opinion(b)
            if not state.connect(b):  # past the end: the block is not looked at
                blocks.append(b)
                stats["past_the_end"] += 1
                self.assertEqual((state.height(), state.tracked(), state.earning()), (b.height, curve_until - 1 + 30, 0))
                self.assertEqual((state.snapshot()[:2], state.snapshot()[3], state.above[:-1]), (before[:2], before[3], list(before[2])))
                self.assertEqual(state.snapshot(), S.State.replay(params, factory, blocks).snapshot(), (seed, step))
                self.assertEqual(state.obligation(b.height)["hash"], b.hash[::-1].hex())
                continue
            blocks.append(b)
            i = state.info[-1]
            if expect is not None:
                d = state.info[i.drew]
                self.assertEqual((d.pay, d.pay_script, d.earning), expect, (seed, step))
                self.assertEqual(d.coin is not None, d.pay > 0 and d.payee == Y.HOLDER)
                stats["holder_draws"] += d.coin is not None
                stats["nobody_holds"] += d.payee == Y.HOLDER and d.earning == 0
                stats["released_at_draw"] += i.drew in i.released_here
            stats["kills"] += len(i.killed)
            stats["settled"] += len(i.settled_here)
            self.assertEqual(state.snapshot(), S.State.replay(params, factory, blocks).snapshot(), (seed, step))
            self.assertEqual(state.live_value(), sum(c.value for c in state.coins if c.live))
            self.assertEqual(state.earning(), 0 if state.closed() else state.live_value())
            self.assertEqual(state.closed(), not b.curve and b.height >= curve_until - 1 + 30)
            for h, inf in enumerate(state.info):  # held coins are in the list exactly when they were released
                if inf.held:
                    self.assertEqual(any((c.txid, c.vout) == inf.held[0][:2] for c in state.coins), inf.released, (seed, step, h))
                    self.assertEqual(inf.released, inf.draw_known and (inf.pay == 0 or inf.settled))
        return stats

    def test_random_chains(self):
        total = {}
        for seed in range(int(os.environ.get("HFYIELD_SEEDS", "6"))):
            for k, v in self.run_one(seed, 140).items():
                total[k] = total.get(k, 0) + v
        for k, v in total.items():  # the scenario has to have reached every path it is there for
            self.assertGreater(v, 0 if k == "nobody_holds" else 5, (k, total))
        self.assertGreaterEqual(total["reopened"], 6)  # every run walked back over the end of the sats leg


class PureFunctions(unittest.TestCase):
    """yieldmodel's side of the two rules this round changed (test_diff_cpp compares them with the C++)."""

    def test_only_the_first_tag_list_binds(self):
        tag, other = H("t")[:20], H("o")[:20]

        def verify(outs, vout=0, pay=5000, to=A):
            raw = Tx(version=2, vin=[TxIn(H("in"), 0)], vout=outs).serialize(witness=False)
            return Y.verify_btc_payment(Y.PaymentProof(1, bytes(32), 0, [], vout, 0, raw), sha256d(raw), tag, to, pay)[0]
        lst = Y.payment_outputs_tag
        self.assertTrue(verify([TxOut(5000, A), TxOut(0, lst([tag]))]))
        self.assertTrue(verify([TxOut(5000, A), TxOut(0, lst([tag])), TxOut(0, lst([other]))]))   # a later list changes nothing
        self.assertFalse(verify([TxOut(5000, A), TxOut(0, lst([other])), TxOut(0, lst([tag]))]))  # the tag only in a second list
        self.assertFalse(verify([TxOut(5000, A), TxOut(0, Y.op_return(b"HF" + tag + b"\x00")), TxOut(0, lst([tag]))]))
        self.assertFalse(verify([TxOut(5000, A), TxOut(0, Y.op_return(b"HF")), TxOut(0, lst([tag]))]))  # an empty first list
        self.assertTrue(verify([TxOut(0, lst([other, tag])), TxOut(5000, A)], vout=1))            # the list may come first
        self.assertFalse(verify([TxOut(0, lst([tag, other])), TxOut(5000, A)], vout=1))
        self.assertFalse(verify([TxOut(5000, A), TxOut(0, lst([tag]))], pay=5001))
        self.assertFalse(verify([TxOut(5000, A), TxOut(0, lst([tag]))], to=B))
        self.assertFalse(verify([TxOut(5000, A)]))

    def test_only_a_coinbase_redirects_and_only_its_output_0_to_a_script_that_earns(self):
        cb_in, tx_in = [TxIn(bytes(32), 0xFFFFFFFF, b"\x01\x01")], [TxIn(H("prev"), 0)]
        tag = Y.yield_tag_script

        def coins(vin, outs):
            tx = Tx(vin=vin, vout=outs)
            return Y.registered_outputs(tx, Y.is_coinbase(tx))
        self.assertTrue(Y.is_coinbase(Tx(vin=cb_in, vout=[])) and not Y.is_coinbase(Tx(vin=tx_in, vout=[])))
        self.assertEqual(coins(cb_in, [TxOut(50, A), TxOut(5, B), TxOut(0, tag(E))]), [(0, 50, E), (1, 5, B)])
        self.assertEqual(coins(tx_in, [TxOut(50, A), TxOut(5, B), TxOut(0, tag(E))]), [(0, 50, A), (1, 5, B)])  # not a coinbase
        for bad in (b"", b"\x51", b"\x99" * 30, E + b"\x00", bytes(80)):                                           # not an earning script
            self.assertEqual(coins(cb_in, [TxOut(50, A), TxOut(0, tag(bad)), TxOut(0, tag(E))]), [(0, 50, A)], bad)
        self.assertEqual(coins(cb_in, [TxOut(50, A), TxOut(0, tag(E)), TxOut(0, tag(B))]), [(0, 50, E)])       # the first one counts
        self.assertEqual(coins(cb_in, [TxOut(0, tag(E)), TxOut(50, A)]), [(1, 50, A)])                         # output 0 is no coin
        self.assertEqual(coins(cb_in, [TxOut(0, A), TxOut(50, B), TxOut(0, tag(E))]), [(1, 50, B)])            # nor is a zero one
        for script in (b"\x76\xa9\x14" + bytes(20) + b"\x88\xac", b"\xa9\x14" + bytes(20) + b"\x87", b"\x51\x20" + bytes(32)):
            self.assertEqual(coins(cb_in, [TxOut(50, A), TxOut(0, tag(script))]), [(0, 50, script)])           # P2PKH, P2SH, P2TR
        self.assertEqual(coins(tx_in, [TxOut(0, A), TxOut(1, b"\x51"), TxOut(1, b"\x6a")]), [])

    def test_header_payloads(self):
        self.assertIsNone(Y.parse_btc_headers(b"HFH1"))
        self.assertIsNone(Y.parse_btc_headers(b"HFH1" + bytes(79)))
        self.assertIsNone(Y.parse_btc_headers(b"HFH1" + bytes(161)))
        self.assertEqual(Y.parse_btc_headers(b"HFH1" + b"\x01" * 80 + b"\x02" * 80), [b"\x01" * 80, b"\x02" * 80])

    def test_the_dev_script_is_the_address_and_the_node_has_the_same_one(self):
        self.assertEqual(Y.DEV_BTC_SCRIPT, address_to_script("bc1pctxxt9z57ypwrvdws45hgpgkx922e39gj3hkqe0hsgv3863f4ffsu7p7x3", "bc"))
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src", "kernel", "chainparams.cpp")
        if os.path.exists(src):  # a source checkout: the node's copy of the same constant
            with open(src) as f:
                self.assertIn(f'HASHFUN_DEV_BTC_SCRIPT{{ParseHex("{Y.DEV_BTC_SCRIPT.hex()}")}}', f.read())


def launch():
    """A test launch at the regtest limit (2 hashes a block) that leaves the curve after a few blocks."""
    d = D.make("yield model test", "YMT", person(0xEE), 8, test=True, pow_limit_bits=0x207FFFFF,
               target_spacing=10, lwma_window=10, genesis_time=1_700_000_000)
    d.sats_num, d.sats_shift = 2000, 0
    d.grind_genesis()
    return d


class FakeNode:
    """Serves blocks the way hashfund does: getblockcount, getblockhash, getblock HASH 0|2."""

    def __init__(self):
        self.chain = []  # (raw block, json)

    def getblockcount(self):
        return len(self.chain) - 1

    def getblockhash(self, height):
        return self.chain[height][1]["hash"]

    def getblock(self, hash_hex, verbosity):
        raw, js = next(x for x in self.chain if x[1]["hash"] == hash_hex)
        return raw.hex() if verbosity == 0 else js

    def push(self, height, txs, merge_mined=False, salt=0):
        prev = bytes.fromhex(self.chain[-1][1]["hash"])[::-1] if self.chain else bytes(32)
        version = 0x20000000 | (0x100 if merge_mined else 0)
        header = header_bytes(version, prev, merkle_root([t.txid() for t in txs]), 1_700_000_000 + 10 * height + salt, 0x207FFFFF, 0)
        aux, js_aux = b"", None
        if merge_mined:
            tree = AuxTree({7: sha256d(header)})
            pcb = Tx(version=1, vin=[TxIn(bytes(32), 0xFFFFFFFF, push_int(1) + tree.commitment_push())], vout=[TxOut(0, b"\x6a")])
            parent = header_bytes(1, H("parent prev"), pcb.txid(), 1_700_000_000, 0x207FFFFF, height)
            aux = serialize_auxpow(pcb, [], [], 0, parent)
            js_aux = {"parentblock": parent.hex() if height % 2 else {"hash": sha256d(parent)[::-1].hex()}}
        raw = header + aux + varint(len(txs)) + b"".join(t.serialize() for t in txs)
        js = {"hash": sha256d(header)[::-1].hex(), "height": height, "bits": "207fffff", "tx": [{
            "txid": t.txid()[::-1].hex(),
            "vin": [{"coinbase": "00"}] if Y.is_coinbase(t) else [{"txid": i.prev_txid[::-1].hex(), "vout": i.prev_vout} for i in t.vin],
            "vout": [{"value": o.value / 100_000_000, "n": n, "scriptPubKey": {"hex": o.script_pubkey.hex()}} for n, o in enumerate(t.vout)],
        } for t in txs]}
        if js_aux:
            js["auxpow"] = js_aux
        self.chain.append((raw, js))
        return header


class FromANode(unittest.TestCase):
    def coinbase(self, height, outs):
        return Tx(version=2, vin=[TxIn(bytes(32), 0xFFFFFFFF, push_int(height) + b"\x01\x00")], vout=outs)

    def test_blocks_read_from_a_node_and_followed_through_a_reorg(self):
        d, node = launch(), FakeNode()
        # A block is on the curve while the work above genesis at its parent is below the graduation
        # work. Every block here is 2 hashes, so that is the first ceil(graduation_work / 2) blocks.
        on_curve = (d.graduation_work + 1) // 2
        self.assertTrue(2 <= on_curve <= 5, d.graduation_work)
        node.push(0, [self.coinbase(0, [TxOut(0, b"\x6a")])])
        cbs = {}
        for h in range(1, 8):
            cbs[h] = self.coinbase(h, [TxOut(1_234_567_890_123, A if h % 2 else B), TxOut(21, person(0xEE))])
            spend = [Tx(version=2, vin=[TxIn(cbs[h - 1].txid(), 0, b"", 0xFFFFFFFD, [b"\x01" * 72, b"\x02" * 33])],
                        vout=[TxOut(1_234_567_890_000, C)])] if h in (3, 6) else []
            node.push(h, [cbs[h]] + spend, merge_mined=h >= 6)
        f = S.Follower(d, node)
        self.assertEqual(f.sync(), (0, 8))
        self.assertEqual(f.work, [0, 2, 4, 6, 8, 10, 12, 14])
        self.assertEqual([(b.curve, b.owed) for b in f.blocks],
                         [(False, 0)] + [(True, Y.owed(work_from_bits(0x207FFFFF), 2000, 0))] * on_curve + [(False, 0)] * (7 - on_curve))
        self.assertEqual(f.blocks[1].owed, 4000)
        self.assertTrue(all(b.work_hash == b.hash for b in f.blocks[:6]))
        for b in f.blocks[6:]:                                    # merge-mined: the parent's hash carried the work
            self.assertNotEqual(b.work_hash, b.hash)
        raw6 = node.chain[6][0]
        self.assertEqual(f.blocks[6].work_hash, sha256d(raw6[raw6.index(H("parent prev")) - 4:][:80]))
        self.assertEqual(f.blocks[3].txs[1].inputs, [(cbs[2].txid(), 0)])
        self.assertEqual(f.blocks[1].txs[0].outputs[0], (1_234_567_890_123, A))   # exact, through the JSON's decimals too
        self.assertEqual(f.state.snapshot(), f.rebuilt().snapshot())
        self.assertEqual(f.state.height(), 7)
        # the node reorganizes: blocks 5..7 are replaced by 5'..8'
        del node.chain[5:]
        for h in range(5, 9):
            node.push(h, [self.coinbase(h, [TxOut(77, C)])], salt=1)
        self.assertEqual(f.sync(), (3, 4))
        self.assertEqual((f.state.height(), f.blocks[-1].hash[::-1].hex()), (8, node.getblockhash(8)))
        self.assertEqual(f.state.snapshot(), f.rebuilt().snapshot())
        self.assertEqual(f.sync(), (0, 0))
        # a shorter chain is followed too
        del node.chain[7:]
        self.assertEqual(f.sync(), (2, 0))
        self.assertEqual(f.state.snapshot(), f.rebuilt().snapshot())

    def test_the_two_ways_of_reading_a_block_are_checked_against_each_other(self):
        d, node = launch(), FakeNode()
        node.push(0, [self.coinbase(0, [TxOut(5, A)])])
        node.chain[0][1]["tx"][0]["vout"][0]["value"] = 0.00000006   # the JSON now says something else
        with self.assertRaises(AssertionError):
            S.Follower(d, node).sync()
        S.Follower(d, node, check_json=False).sync()

    def test_differences(self):
        model = {"height": 3, "pay": 5, "coin": {"txid": "aa", "vout": 0, "value": 9}}
        self.assertEqual(S.differences(dict(model), model), [])
        self.assertEqual(S.differences({"height": 3, "pay": 5, "coin": None}, {"height": 3, "pay": 5}), [])
        self.assertEqual(len(S.differences({"height": 3, "pay": 6, "candidates": []}, model)), 3)


if __name__ == "__main__":
    unittest.main()
