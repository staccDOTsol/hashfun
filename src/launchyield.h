// Copyright (c) 2026 The hashfun developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LAUNCHYIELD_H
#define BITCOIN_LAUNCHYIELD_H

#include <arith_uint256.h>
#include <consensus/amount.h>
#include <primitives/pureheader.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

/**
 * hashfun sats leg: pure consensus functions (no chain state, no I/O).
 *
 * A curve block owes real BTC on top of its hash: owed = (work * num) >> shift.
 * Six launch blocks later that block's hash seeds a draw:
 *   - payment size: owed if owed >= min, else min with probability owed/min
 *     (so every Bitcoin output is worth sending; expectation is preserved);
 *   - recipient class: 80% a holder, 10% the creator, 10% the dev;
 *   - holder: up to 16 candidate points into the value of all yield-registered
 *     outputs created up to the minting block; the payee is the first
 *     candidate whose output is still unspent, i.e. coin-weighted over holders
 *     who have not moved. All 16 spent -> creator.
 * The miner pays on Bitcoin and proves it here (SPV against the in-chain
 * Bitcoin header relay) before the settlement deadline; until then the
 * coinbase cannot be spent, and after it the coins are gone.
 */
namespace launchyield {

static constexpr int DRAW_DELAY = 6;          //!< seed block = mint block + DRAW_DELAY
static constexpr int MAX_CANDIDATES = 16;
static constexpr int HOLDER_BPS = 8000;
static constexpr int CREATOR_BPS = 1000;      //!< remainder (1000) is the dev's

enum class Payee { HOLDER = 0, CREATOR = 1, DEV = 2 };

struct Draw {
    CAmount pay{0}; //!< 0: nothing due, the block settles itself
    Payee payee{Payee::HOLDER};
};

/** (work * num) >> shift, capped at MAX_MONEY. */
CAmount Owed(const arith_uint256& work, uint64_t num, uint32_t shift);
uint256 DrawSeed(const uint256& launch_id, const uint256& seed_block_hash);
Draw ComputeDraw(CAmount owed, CAmount min_payment, const uint256& seed);
/** i-th candidate point in [0, registered_total); registered_total must be > 0. */
arith_uint256 CandidatePoint(const uint256& seed, int i, const arith_uint256& registered_total);
/** 20-byte tag a Bitcoin payment must carry for (launch, mint block). */
std::array<unsigned char, 20> PayTag(const uint256& launch_id, const uint256& mint_block_hash);

/** Data of an output that is OP_RETURN <one push starting with the 4-byte tag>. */
std::optional<std::vector<unsigned char>> TaggedReturn(const CScript& script, std::string_view tag);

struct RegOut {
    uint32_t vout{0};
    CAmount value{0};
    std::vector<unsigned char> btc_script;
};
/**
 * Outputs of tx that earn yield: the tx carries OP_RETURN "HFY1"<btc scriptPubKey>
 * (1..80 bytes). Every other positive, non-OP_RETURN output registers to that
 * script; in a coinbase only vout 0 does.
 */
std::vector<RegOut> RegisteredOutputs(const CTransaction& tx);

/** OP_RETURN "HFP1" payload: proof that a mint block's sats were paid on Bitcoin. */
struct PaymentProof {
    uint32_t mint_height{0};
    uint256 btc_block;
    uint32_t tx_index{0};
    std::vector<uint256> branch;
    uint32_t pay_vout{0};
    uint8_t candidate{0}; //!< which holder candidate was paid (ignored for creator/dev)
    std::vector<unsigned char> raw_tx; //!< Bitcoin tx, serialized without witness
};
std::optional<PaymentProof> ParsePaymentProof(std::span<const unsigned char> payload);
/**
 * The Bitcoin tx is in the block with this merkle root, output pay_vout pays
 * at least `pay` to recipient_script, and the tx's "HF" tag list binds that
 * same output index to `tag` (so one output cannot settle two blocks).
 */
bool VerifyBtcPayment(const PaymentProof& proof, const uint256& merkle_root, const std::array<unsigned char, 20>& tag,
                      const std::vector<unsigned char>& recipient_script, CAmount pay, std::string& error);

/** OP_RETURN "HFH1" payload: n * 80-byte Bitcoin headers. */
std::optional<std::vector<CPureBlockHeader>> ParseBtcHeaders(std::span<const unsigned char> payload);

/**
 * Bitcoin header tree rooted at the descriptor's anchor, fed by headers relayed
 * inside launch blocks. Fully validating (PoW, difficulty schedule, median
 * time), so the launch chain's view of Bitcoin is a pure function of its own
 * blocks. Best tip = most work, ties to the numerically lowest hash.
 */
class BtcChain
{
public:
    struct Node {
        uint256 prev;
        uint256 merkle_root;
        uint32_t time{0};
        uint32_t bits{0};
        int height{0};
        arith_uint256 work;
    };

    void Init(const CPureBlockHeader& anchor, int anchor_height, uint32_t anchor_period_time, bool regtest);
    bool Initialized() const { return !m_nodes.empty(); }
    /** Add a header. false + error if invalid, unconnected or already known. */
    bool Accept(const CPureBlockHeader& header, std::string& error);
    /** Undo an Accept (the header must have no children). */
    void Remove(const uint256& hash);
    const Node* Find(const uint256& hash) const;
    /** 1 for the best tip, 0 if unknown or off the best chain. */
    int Confirmations(const uint256& hash) const;
    const uint256& Best() const { return m_best; }
    int BestHeight() const;
    size_t Size() const { return m_nodes.size(); }

private:
    uint32_t ExpectedBits(const Node& prev) const;
    void PickBest();

    std::map<uint256, Node> m_nodes;
    std::map<uint256, int> m_children;
    uint256 m_anchor;
    uint256 m_best;
    uint32_t m_anchor_period_time{0};
    bool m_regtest{false};
};

} // namespace launchyield

#endif // BITCOIN_LAUNCHYIELD_H
