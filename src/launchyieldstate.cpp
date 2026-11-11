// Copyright (c) 2026 The hashfun developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <launchyieldstate.h>

#include <arith_uint256.h>
#include <auxpow.h>
#include <chain.h>
#include <launchcurve.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <streams.h>
#include <util/log.h>

#include <cassert>

using launchyield::DRAW_DELAY;
using launchyield::Payee;

LaunchYieldState& GetLaunchYieldState()
{
    static LaunchYieldState state;
    return state;
}

const LaunchYieldState::Info* LaunchYieldState::At(int height) const
{
    return height >= 0 && height < static_cast<int>(m_info.size()) ? &m_info[height] : nullptr;
}

bool LaunchYieldState::Spendable(int height) const
{
    const Info* i = At(height);
    if (!i || !i->curve || i->owed == 0) return true;
    if (!i->draw_known) return false;
    return i->pay == 0 || i->settled;
}

// ---- the coin list -----------------------------------------------------------------------------
// Coins sit in the order they were appended and never move; a dead coin keeps its place with
// weight 0. A Fenwick tree over the live values answers "how much is live" and "which coin holds
// point x" in O(log n). Appending and cutting the tail keep the tree valid: node i only sums
// positions (i - lowbit(i), i].

static inline size_t LowBit(size_t i) { return i & (~i + 1); }

void LaunchYieldState::TreeAdd(uint32_t index, uint64_t delta)
{
    // delta may be the two's complement of a value: the sums stay exact modulo 2^64 and never go below zero.
    for (size_t i = size_t{index} + 1; i <= m_tree.size(); i += LowBit(i)) m_tree[i - 1] += delta;
}

uint32_t LaunchYieldState::TreeFind(uint64_t x) const
{
    // The first coin whose cumulative live value exceeds x. Needs x < m_total.
    size_t pos = 0, step = 1;
    while (step * 2 <= m_tree.size()) step *= 2;
    for (; step > 0; step /= 2) {
        const size_t next = pos + step;
        if (next <= m_tree.size() && m_tree[next - 1] <= x) {
            pos = next;
            x -= m_tree[next - 1];
        }
    }
    return static_cast<uint32_t>(pos);
}

void LaunchYieldState::Append(Coin coin)
{
    assert(coin.value > 0 && m_coins.size() < UINT32_MAX);
    const size_t i = m_tree.size() + 1; // 1-based position of the new coin
    uint64_t sum = static_cast<uint64_t>(coin.value);
    for (size_t j = i - 1; j > i - LowBit(i); j -= LowBit(j)) sum += m_tree[j - 1];
    m_tree.push_back(sum);
    m_total += static_cast<uint64_t>(coin.value);
    m_index[coin.out] = static_cast<uint32_t>(m_coins.size());
    coin.live = true;
    m_coins.push_back(std::move(coin));
}

void LaunchYieldState::Release(int mint_height, Info& cur)
{
    Info& m = m_info[mint_height];
    if (m.released || m.held.empty()) return;
    for (const Coin& c : m.held) Append(c);
    m.released = true;
    cur.released_here.push_back(mint_height);
}

// ---- settling ----------------------------------------------------------------------------------

bool LaunchYieldState::TrySettle(const launchyield::PaymentProof& proof, int height, const Consensus::Params& params)
{
    const int64_t m = proof.mint_height;
    if (m < 1 || m + DRAW_DELAY >= height || m >= static_cast<int64_t>(m_info.size())) return false;
    Info& info = m_info[m];
    if (!info.curve || !info.draw_known || info.settled || info.pay == 0) return false;
    if (height > m + params.launch_settle_deadline) return false;
    if (proof.candidate != 0) return false; // the payee is fixed by the draw: there is nothing to choose
    const auto* btc = m_btc.Find(proof.btc_block);
    if (!btc || m_btc.Confirmations(proof.btc_block) < params.launch_btc_confs) return false;
    std::string err;
    if (!launchyield::VerifyBtcPayment(proof, btc->merkle_root, launchyield::PayTag(params.launch_id, info.hash), info.pay_script, info.pay, err)) {
        LogDebug(BCLog::VALIDATION, "hashfun: payment proof for block %d ignored: %s\n", m, err);
        return false;
    }
    info.settled = true;
    return true;
}

// ---- connecting and disconnecting a block ------------------------------------------------------

void LaunchYieldState::Connect(const CBlock& block, const CBlockIndex* pindex, const Consensus::Params& params)
{
    const int height = pindex->nHeight;
    if (height != static_cast<int>(m_info.size())) return;
    if (Closed(params)) return; // nothing after this block can change what any coinbase may do
    if (height == 0) {
        CPureBlockHeader anchor;
        DataStream ss{params.launch_btc_anchor_header};
        ss >> anchor;
        m_btc.Init(anchor, params.launch_btc_anchor_height, params.launch_btc_anchor_period_time, params.launch_btc_regtest);
    }
    {
        Info info;
        info.hash = pindex->GetBlockHash();
        info.curve = height >= 1 && !LaunchGraduatedAt(pindex->pprev, params);
        info.owed = info.curve ? launchyield::Owed(GetBlockProof(*pindex), params.launch_sats_num, params.launch_sats_shift) : 0;
        info.coins_before = static_cast<uint32_t>(m_coins.size());
        if (info.curve) m_last_curve = height;
        m_info.push_back(std::move(info));
    }
    Info& cur = m_info.back(); // m_info does not grow again in this call

    // 1. The draw of the block DRAW_DELAY below, over the coins that are live now: at the end of the
    //    previous block, before anything in this one. The seed is the hash that carried this block's
    //    work: for a merge-mined block that is the parent chain's block hash (its own hash can be
    //    re-rolled for free).
    const int drawn = height - DRAW_DELAY;
    if (drawn >= 1 && m_info[drawn].curve) {
        Info& d = m_info[drawn];
        const uint256 work_hash = block.auxpow ? block.auxpow->getParentBlockHash() : cur.hash;
        d.seed = launchyield::DrawSeed(params.launch_id, work_hash);
        const launchyield::Draw draw = launchyield::ComputeDraw(d.owed, params.launch_sats_min_payment, d.seed);
        d.pay = draw.pay;
        d.payee = draw.payee;
        d.earning = static_cast<CAmount>(m_total);
        if (draw.payee == Payee::HOLDER && m_total == 0) {
            // The holders' share with nobody holding yet (the first blocks of a launch): it is
            // owed to no one. Not to the creator: that would make the creator the holder of
            // everything until the first payment confirms on Bitcoin.
            d.pay = 0;
        }
        if (d.pay > 0) {
            if (draw.payee == Payee::DEV) {
                d.pay_script = params.launch_dev_btc_script;
            } else if (draw.payee == Payee::CREATOR) {
                d.pay_script = params.launch_creator_btc_script;
            } else {
                const uint64_t x = launchyield::CandidatePoint(d.seed, 0, arith_uint256{m_total}).GetLow64();
                const Coin& c = m_coins[TreeFind(x)];
                assert(c.live);
                d.pay_script = c.script;
                d.has_coin = true;
                d.coin = c.out;
                d.coin_value = c.value;
            }
        }
        d.draw_known = true;
        cur.drew = drawn;
        if (d.pay == 0) Release(drawn, cur); // nothing is due: its coinbase is free, and earns from here on
    }

    // 2. The transactions, in order: inputs kill coins, tagged outputs relay Bitcoin headers and
    //    settle blocks, then the transaction's own earning outputs become coins.
    const bool hold_coinbase = cur.curve && cur.owed > 0;
    for (const CTransactionRef& tx : block.vtx) {
        const bool coinbase = tx->IsCoinBase();
        if (!coinbase) {
            for (const CTxIn& in : tx->vin) {
                const auto it = m_index.find(in.prevout);
                if (it == m_index.end()) continue;
                const uint32_t idx = it->second;
                Coin& c = m_coins[idx];
                c.live = false;
                TreeAdd(idx, ~static_cast<uint64_t>(c.value) + 1);
                m_total -= static_cast<uint64_t>(c.value);
                cur.killed.push_back(idx);
                m_index.erase(it);
            }
        }
        for (const CTxOut& out : tx->vout) {
            if (const auto data = launchyield::TaggedReturn(out.scriptPubKey, "HFH1")) {
                if (const auto headers = launchyield::ParseBtcHeaders(*data)) {
                    for (const CPureBlockHeader& h : *headers) {
                        std::string err;
                        if (m_btc.Accept(h, err)) cur.btc_added.push_back(h.GetHash());
                    }
                }
            } else if (const auto data = launchyield::TaggedReturn(out.scriptPubKey, "HFP1")) {
                if (const auto proof = launchyield::ParsePaymentProof(*data)) {
                    if (TrySettle(*proof, height, params)) {
                        const int m = static_cast<int>(proof->mint_height);
                        cur.settled_here.push_back(m);
                        Release(m, cur); // paid: its coinbase earns from here on
                    }
                }
            }
        }
        const Txid txid = tx->GetHash();
        for (const launchyield::RegOut& r : launchyield::RegisteredOutputs(*tx)) {
            Coin c{COutPoint{txid, r.vout}, r.value, r.btc_script, true};
            if (coinbase && hold_coinbase) {
                cur.held.push_back(std::move(c));
            } else {
                Append(std::move(c));
            }
        }
    }
}

void LaunchYieldState::Pop()
{
    Info& cur = m_info.back();
    // Everything this block appended is the tail of the coin list.
    for (size_t i = m_coins.size(); i-- > cur.coins_before;) {
        const Coin& c = m_coins[i];
        if (!c.live) continue;
        m_total -= static_cast<uint64_t>(c.value);
        m_index.erase(c.out);
    }
    m_coins.resize(cur.coins_before);
    m_tree.resize(cur.coins_before);
    // The coins it killed are live again (one created and spent inside this block went with the tail).
    for (auto it = cur.killed.rbegin(); it != cur.killed.rend(); ++it) {
        if (*it >= cur.coins_before) continue;
        Coin& c = m_coins[*it];
        c.live = true;
        TreeAdd(*it, static_cast<uint64_t>(c.value));
        m_total += static_cast<uint64_t>(c.value);
        m_index[c.out] = *it;
    }
    for (int m : cur.released_here) m_info[m].released = false;
    for (int m : cur.settled_here) m_info[m].settled = false;
    for (auto it = cur.btc_added.rbegin(); it != cur.btc_added.rend(); ++it) m_btc.Remove(*it);
    if (cur.drew >= 0) {
        Info& d = m_info[cur.drew];
        d.draw_known = false;
        d.pay = 0;
        d.payee = Payee::HOLDER;
        d.seed = uint256{};
        d.pay_script.clear();
        d.has_coin = false;
        d.coin = COutPoint{};
        d.coin_value = 0;
        d.earning = 0;
    }
    if (cur.curve) m_last_curve = Height() - 1; // curve blocks are 1..m_last_curve, with no gaps
    m_info.pop_back();
}

void LaunchYieldState::Disconnect(const CBlockIndex* pindex)
{
    if (!m_info.empty() && Height() == pindex->nHeight && m_info.back().hash == pindex->GetBlockHash()) Pop();
}

bool LaunchYieldState::Sync(const CBlockIndex* tip, const Consensus::Params& params, const node::BlockManager& blockman)
{
    if (!tip) return true;
    while (!m_info.empty() && (Height() > tip->nHeight || m_info.back().hash != tip->GetAncestor(Height())->GetBlockHash())) Pop();
    while (Height() < tip->nHeight && !Closed(params)) {
        const CBlockIndex* next = tip->GetAncestor(Height() + 1);
        CBlock block;
        if (!blockman.ReadBlock(block, *next)) {
            // Without this block the state says nothing about later ones, and a node that guessed
            // would follow blocks its peers reject. The caller stops.
            LogError("hashfun: cannot read block %d to rebuild the sats-leg state\n", next->nHeight);
            return false;
        }
        Connect(block, next, params);
    }
    return true;
}
