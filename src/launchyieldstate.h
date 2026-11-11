// Copyright (c) 2026 The hashfun developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LAUNCHYIELDSTATE_H
#define BITCOIN_LAUNCHYIELDSTATE_H

#include <arith_uint256.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <launchyield.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <optional>
#include <vector>

class CBlock;
class CBlockIndex;
class CCoinsViewCache;
namespace node {
class BlockManager;
}

/**
 * Chain state of the sats leg, derived purely from the active chain's blocks:
 * the relayed Bitcoin header tree, the yield-registered outputs per block, and
 * each curve block's obligation (owed, draw, settled). Kept in memory, one
 * entry per height; Sync() rebuilds or rewinds it from disk whenever it does
 * not represent the block being built on. Guarded by cs_main.
 */
class LaunchYieldState
{
public:
    struct Reg {
        COutPoint out;
        CAmount value{0};
        std::vector<unsigned char> script;
    };
    struct Info {
        uint256 hash;
        bool curve{false};
        CAmount owed{0};
        bool draw_known{false};
        CAmount pay{0};
        launchyield::Payee payee{launchyield::Payee::HOLDER};
        uint256 seed;
        bool settled{false};
        std::vector<Reg> reg;
        arith_uint256 cum_reg; //!< registered value created up to and including this block
        // undo
        std::vector<uint256> btc_added;
        std::vector<int> settled_here;
        int drew{-1};
    };

    static bool Enabled(const Consensus::Params& p) { return p.launch_enabled && p.launch_sats_num > 0; }

    /** Make the state represent `tip` (pop and/or replay from disk as needed). */
    void Sync(const CBlockIndex* tip, const Consensus::Params& params, const node::BlockManager& blockman);
    /** Apply a block on top of the represented tip. view == nullptr: replay (candidate spentness is not re-checked). */
    void Connect(const CBlock& block, const CBlockIndex* pindex, const Consensus::Params& params, const CCoinsViewCache* view);
    /** Undo Connect if `pindex` is the represented tip. */
    void Disconnect(const CBlockIndex* pindex);

    int Height() const { return static_cast<int>(m_info.size()) - 1; }
    const Info* At(int height) const;
    /** May the coinbase of the block at `height` be spent? */
    bool Spendable(int height) const;
    std::optional<Reg> Candidate(int mint_height, int i) const;
    /** Script a payment for `mint_height` must pay if the payer names holder candidate `candidate`
     *  (MAX_CANDIDATES = "all spent, pay the creator"). false if that choice is not allowed. */
    bool Recipient(int mint_height, int candidate, const CCoinsViewCache* view, const Consensus::Params& params,
                   std::vector<unsigned char>& script) const;
    const launchyield::BtcChain& Btc() const { return m_btc; }

private:
    void Pop();
    bool TrySettle(const launchyield::PaymentProof& proof, int height, const Consensus::Params& params, const CCoinsViewCache* view);

    std::vector<Info> m_info;
    launchyield::BtcChain m_btc;
};

LaunchYieldState& GetLaunchYieldState();

#endif // BITCOIN_LAUNCHYIELDSTATE_H
