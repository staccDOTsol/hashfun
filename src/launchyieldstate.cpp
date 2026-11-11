// Copyright (c) 2026 The hashfun developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <launchyieldstate.h>

#include <chain.h>
#include <coins.h>
#include <launchcurve.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <streams.h>
#include <util/log.h>

using launchyield::DRAW_DELAY;
using launchyield::MAX_CANDIDATES;
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

std::optional<LaunchYieldState::Reg> LaunchYieldState::Candidate(int mint_height, int i) const
{
    const Info* m = At(mint_height);
    if (!m || !m->draw_known || mint_height < 1) return std::nullopt;
    // Value registered strictly before the mint block: a miner never draws its own coinbase.
    const arith_uint256& total = m_info[mint_height - 1].cum_reg;
    if (total == 0) return std::nullopt;
    const arith_uint256 x = launchyield::CandidatePoint(m->seed, i, total);
    int lo = 0, hi = mint_height - 1; // first height whose cumulative value exceeds x
    while (lo < hi) {
        const int mid = lo + (hi - lo) / 2;
        if (m_info[mid].cum_reg > x) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    arith_uint256 acc = lo > 0 ? m_info[lo - 1].cum_reg : arith_uint256{0};
    for (const Reg& r : m_info[lo].reg) {
        acc += arith_uint256{static_cast<uint64_t>(r.value)};
        if (acc > x) return r;
    }
    return std::nullopt;
}

bool LaunchYieldState::Recipient(int mint_height, int candidate, const CCoinsViewCache* view, const Consensus::Params& params,
                                 std::vector<unsigned char>& script) const
{
    const Info* m = At(mint_height);
    if (!m || !m->draw_known) return false;
    if (m->payee == Payee::DEV) {
        script = params.launch_dev_btc_script;
        return true;
    }
    if (m->payee == Payee::CREATOR || mint_height < 1 || m_info[mint_height - 1].cum_reg == 0) {
        script = params.launch_creator_btc_script;
        return true;
    }
    if (candidate < 0 || candidate > MAX_CANDIDATES) return false;
    // The payee is the first candidate still unspent; every earlier one must be spent.
    for (int j = 0; j < candidate; ++j) {
        const auto c = Candidate(mint_height, j);
        if (!c) return false;
        if (view && view->HaveCoin(c->out)) return false;
    }
    if (candidate == MAX_CANDIDATES) {
        script = params.launch_creator_btc_script;
        return true;
    }
    const auto c = Candidate(mint_height, candidate);
    if (!c) return false;
    script = c->script;
    return true;
}

bool LaunchYieldState::TrySettle(const launchyield::PaymentProof& proof, int height, const Consensus::Params& params, const CCoinsViewCache* view)
{
    const int64_t m = proof.mint_height;
    if (m < 1 || m + DRAW_DELAY >= height || m >= static_cast<int64_t>(m_info.size())) return false;
    Info& info = m_info[m];
    if (!info.curve || !info.draw_known || info.settled || info.pay == 0) return false;
    if (height > m + params.launch_settle_deadline) return false;
    const auto* btc = m_btc.Find(proof.btc_block);
    if (!btc || m_btc.Confirmations(proof.btc_block) < params.launch_btc_confs) return false;
    std::vector<unsigned char> recipient;
    if (!Recipient(m, proof.candidate, view, params, recipient)) return false;
    std::string err;
    if (!launchyield::VerifyBtcPayment(proof, btc->merkle_root, launchyield::PayTag(params.launch_id, info.hash), recipient, info.pay, err)) {
        LogDebug(BCLog::VALIDATION, "hashfun: payment proof for block %d ignored: %s\n", m, err);
        return false;
    }
    info.settled = true;
    return true;
}

void LaunchYieldState::Connect(const CBlock& block, const CBlockIndex* pindex, const Consensus::Params& params, const CCoinsViewCache* view)
{
    const int height = pindex->nHeight;
    if (height != static_cast<int>(m_info.size())) return;
    if (height == 0) {
        CPureBlockHeader anchor;
        DataStream ss{params.launch_btc_anchor_header};
        ss >> anchor;
        m_btc.Init(anchor, params.launch_btc_anchor_height, params.launch_btc_anchor_period_time, params.launch_btc_regtest);
    }
    Info info;
    info.hash = pindex->GetBlockHash();
    info.curve = height >= 1 && !LaunchGraduatedAt(pindex->pprev, params);
    info.owed = info.curve ? launchyield::Owed(GetBlockProof(*pindex), params.launch_sats_num, params.launch_sats_shift) : 0;
    info.cum_reg = height > 0 ? m_info.back().cum_reg : arith_uint256{0};

    // This block's hash seeds the draw of the block DRAW_DELAY below it.
    const int drawn = height - DRAW_DELAY;
    if (drawn >= 1 && m_info[drawn].curve) {
        Info& d = m_info[drawn];
        d.seed = launchyield::DrawSeed(params.launch_id, info.hash);
        const launchyield::Draw draw = launchyield::ComputeDraw(d.owed, params.launch_sats_min_payment, d.seed);
        d.pay = draw.pay;
        d.payee = draw.payee;
        d.draw_known = true;
        info.drew = drawn;
    }
    m_info.push_back(std::move(info));
    Info& cur = m_info.back();

    for (const CTransactionRef& tx : block.vtx) {
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
                    if (TrySettle(*proof, height, params, view)) cur.settled_here.push_back(proof->mint_height);
                }
            }
        }
        const Txid txid = tx->GetHash();
        for (const launchyield::RegOut& r : launchyield::RegisteredOutputs(*tx)) {
            cur.reg.push_back({COutPoint{txid, r.vout}, r.value, r.btc_script});
            cur.cum_reg += arith_uint256{static_cast<uint64_t>(r.value)};
        }
    }
}

void LaunchYieldState::Pop()
{
    Info& cur = m_info.back();
    for (int m : cur.settled_here) m_info[m].settled = false;
    for (auto it = cur.btc_added.rbegin(); it != cur.btc_added.rend(); ++it) m_btc.Remove(*it);
    if (cur.drew >= 0) {
        Info& d = m_info[cur.drew];
        d.draw_known = false;
        d.pay = 0;
        d.seed = uint256{};
    }
    m_info.pop_back();
}

void LaunchYieldState::Disconnect(const CBlockIndex* pindex)
{
    if (!m_info.empty() && Height() == pindex->nHeight && m_info.back().hash == pindex->GetBlockHash()) Pop();
}

void LaunchYieldState::Sync(const CBlockIndex* tip, const Consensus::Params& params, const node::BlockManager& blockman)
{
    if (!tip) return;
    while (!m_info.empty() && (Height() > tip->nHeight || m_info.back().hash != tip->GetAncestor(Height())->GetBlockHash())) Pop();
    while (Height() < tip->nHeight) {
        const CBlockIndex* next = tip->GetAncestor(Height() + 1);
        CBlock block;
        if (!blockman.ReadBlock(block, *next)) {
            LogError("hashfun: cannot read block %d to rebuild the sats-leg state\n", next->nHeight);
            return;
        }
        Connect(block, next, params, /*view=*/nullptr);
    }
}
