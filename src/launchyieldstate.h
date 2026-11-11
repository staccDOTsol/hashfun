// Copyright (c) 2026 The hashfun developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LAUNCHYIELDSTATE_H
#define BITCOIN_LAUNCHYIELDSTATE_H

#include <consensus/amount.h>
#include <consensus/params.h>
#include <launchyield.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <util/hasher.h>

#include <cstdint>
#include <unordered_map>
#include <vector>

class CBlock;
class CBlockIndex;
namespace node {
class BlockManager;
}

/**
 * Chain state of the sats leg: the relayed Bitcoin header tree, the coins that
 * earn (and which of them are live), and each curve block's obligation (owed,
 * draw, settled).
 *
 * It is a pure function of the active chain's blocks, genesis to tip. Nothing
 * in it reads the UTXO set, the clock, or whether a block arrived live or is
 * being replayed at start: Connect() takes the block and nothing else. That is
 * a consensus requirement, not a tidiness: a proof that is not accepted is
 * ignored rather than invalid, so "was it accepted" must come out the same on
 * every node, whenever it computes it.
 *
 * Kept in memory, one entry per height; Sync() rebuilds or rewinds it from disk
 * whenever it does not represent the block being built on. Guarded by cs_main.
 */
class LaunchYieldState
{
public:
    /** An output that earns: paid, when drawn, at `script` on Bitcoin. */
    struct Coin {
        COutPoint out;
        CAmount value{0};
        std::vector<unsigned char> script;
        bool live{true};
    };
    struct Info {
        uint256 hash;
        bool curve{false};
        CAmount owed{0};
        // The draw, made when the block DRAW_DELAY above this one is connected, and fixed from then on.
        bool draw_known{false};
        CAmount pay{0};
        launchyield::Payee payee{launchyield::Payee::HOLDER};
        uint256 seed;
        std::vector<unsigned char> pay_script; //!< the Bitcoin script a payment for this block must pay
        bool has_coin{false};                  //!< a holder was drawn: the coin that won
        COutPoint coin;
        CAmount coin_value{0};
        CAmount earning{0};                    //!< value of all live coins at the draw
        bool settled{false};
        // This block's own coinbase coins, when it owes sats: not live until it settles (or its draw says nothing is due).
        std::vector<Coin> held;
        bool released{false};
        // undo: what connecting this block did
        uint32_t coins_before{0};          //!< length of the coin list before this block
        std::vector<uint32_t> killed;      //!< coins its inputs spent, in order
        std::vector<int> released_here;    //!< heights whose held coins it appended
        std::vector<uint256> btc_added;
        std::vector<int> settled_here;
        int drew{-1};
    };

    static bool Enabled(const Consensus::Params& p) { return p.launch_enabled && p.launch_sats_num > 0; }

    /** Make the state represent `tip` (pop and/or replay from disk as needed). false: a block could not be read. */
    [[nodiscard]] bool Sync(const CBlockIndex* tip, const Consensus::Params& params, const node::BlockManager& blockman);
    /** Apply a block on top of the represented tip. */
    void Connect(const CBlock& block, const CBlockIndex* pindex, const Consensus::Params& params);
    /** Undo Connect if `pindex` is the represented tip. */
    void Disconnect(const CBlockIndex* pindex);

    int Height() const { return static_cast<int>(m_info.size()) - 1; }
    const Info* At(int height) const;
    /** May the coinbase of the block at `height` be spent? */
    bool Spendable(int height) const;
    /**
     * The sats leg is over: the represented tip is settle_deadline blocks past the last curve
     * block, so nothing can be drawn or settled any more. From here the state stops growing
     * (later blocks are not tracked, and a node starting up replays the chain only this far).
     */
    bool Closed(const Consensus::Params& params) const
    {
        return !m_info.empty() && !m_info.back().curve && Height() >= m_last_curve + params.launch_settle_deadline;
    }
    /** Value of all live coins: what the next draw is taken over. 0 once the sats leg is over. */
    CAmount Earning(const Consensus::Params& params) const { return Closed(params) ? 0 : static_cast<CAmount>(m_total); }
    size_t Coins() const { return m_coins.size(); }
    const launchyield::BtcChain& Btc() const { return m_btc; }

private:
    void Pop();
    bool TrySettle(const launchyield::PaymentProof& proof, int height, const Consensus::Params& params);
    void Append(Coin coin);
    void Release(int mint_height, Info& cur);
    // Live value per coin in a Fenwick tree: sums and "which coin holds point x" in O(log n).
    void TreeAdd(uint32_t index, uint64_t delta);
    uint32_t TreeFind(uint64_t x) const;

    std::vector<Info> m_info;
    std::vector<Coin> m_coins;                                               //!< in the order they were appended
    std::vector<uint64_t> m_tree;                                            //!< m_tree[i-1] = live value of coins (i - lowbit(i), i]
    std::unordered_map<COutPoint, uint32_t, SaltedOutpointHasher> m_index;   //!< live coins only; never iterated
    uint64_t m_total{0};
    int m_last_curve{0}; //!< height of the last block on the curve (they are 1..m_last_curve); 0: none
    launchyield::BtcChain m_btc;
};

LaunchYieldState& GetLaunchYieldState();

#endif // BITCOIN_LAUNCHYIELDSTATE_H
