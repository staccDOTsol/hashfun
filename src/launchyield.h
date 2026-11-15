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
#include <set>
#include <span>
#include <string>
#include <vector>

/**
 * hashfun sats leg and QWEN leg: pure consensus functions (no chain state, no I/O).
 *
 * A launch has two curves (launchcurve.h). A block on the BTC curve owes real BTC on top of its
 * hash, a block on the QWEN curve owes qwen on Qwencoin: owed = (work * num) >> shift with the
 * curve's own num and shift, in base units of its asset. Everything below is the same for both;
 * "Bitcoin" reads "the chain of the block's curve". The two chains run the same script engine
 * and the same transaction and merkle formats, and a Qwencoin main-network address is the same
 * string as the Bitcoin address of the same key, so a payee's script means the same on both.
 *
 * Six launch blocks later that block's hash seeds a draw:
 *   - payment size: owed if owed >= min, else min with probability owed/min
 *     (so every Bitcoin output is worth sending; expectation is preserved);
 *   - recipient class: 80% a holder, 10% the creator, 10% the dev;
 *   - holder: one point into the value of the coins that are live (unspent) at
 *     that moment; the coin holding the point is the payee, fixed from then on.
 *     Coin-weighted over current holders. No opt-in: a coin is paid at its own
 *     script on Bitcoin. Nobody holds a coin yet -> the creator.
 * The miner pays on Bitcoin and proves it here (SPV against the in-chain
 * Bitcoin header relay) before the settlement deadline; until then the
 * coinbase cannot be spent, and after it the coins are gone.
 */
namespace launchyield {

static constexpr int DRAW_DELAY = 6;          //!< seed block = mint block + DRAW_DELAY
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
/** Point i derived from the seed, in [0, total); total must be > 0. The holder draw uses point 0 over the live value. */
arith_uint256 CandidatePoint(const uint256& seed, int i, const arith_uint256& total);
/** 20-byte tag a Bitcoin payment must carry for (launch, mint block). */
std::array<unsigned char, 20> PayTag(const uint256& launch_id, const uint256& mint_block_hash);

/** Data of an output that is OP_RETURN <one push starting with the 4-byte tag>. */
std::optional<std::vector<unsigned char>> TaggedReturn(const CScript& script, std::string_view tag);

struct RegOut {
    uint32_t vout{0};
    CAmount value{0};
    std::vector<unsigned char> btc_script;
};
/** P2PKH, P2SH or a witness program: a script that means the same thing on Bitcoin. */
bool EarnsYield(const CScript& script);
/**
 * Outputs of tx that earn yield, with the Bitcoin script their yield is paid to.
 * Holding is enough: every positive P2PKH / P2SH / witness-program output earns,
 * and is paid at its own scriptPubKey on Bitcoin (a launch is a Bitcoin fork, so
 * the same key controls both). A coinbase may redirect its output 0 (the miner's
 * own) with OP_RETURN "HFY1"<btc scriptPubKey>: the first such output counts, and
 * only if that script is itself one that earns. No other transaction can redirect.
 */
std::vector<RegOut> RegisteredOutputs(const CTransaction& tx);

/** OP_RETURN "HFP1" payload: proof that a mint block's sats were paid on Bitcoin. */
struct PaymentProof {
    uint32_t mint_height{0};
    uint256 btc_block;
    uint32_t tx_index{0};
    std::vector<uint256> branch;
    uint32_t pay_vout{0};
    uint8_t candidate{0}; //!< must be 0 (the payee is fixed by the draw; the byte is from an earlier format)
    std::vector<unsigned char> raw_tx; //!< Bitcoin tx, serialized without witness
};
std::optional<PaymentProof> ParsePaymentProof(std::span<const unsigned char> payload);
/**
 * The Bitcoin tx is in the block with this merkle root, output pay_vout pays
 * at least `pay` to recipient_script, and the tx's "HF" tag list (its first
 * OP_RETURN "HF" output, and no other) binds that same output index to `tag`,
 * so one output cannot settle two blocks.
 */
bool VerifyBtcPayment(const PaymentProof& proof, const uint256& merkle_root, const std::array<unsigned char, 20>& tag,
                      const std::vector<unsigned char>& recipient_script, CAmount pay, std::string& error);

/** OP_RETURN "HFH1" (Bitcoin) or "HFH2" (Qwencoin) payload: n * 80-byte headers. */
std::optional<std::vector<CPureBlockHeader>> ParseBtcHeaders(std::span<const unsigned char> payload);

/**
 * Qwencoin's proof of work (https://github.com/staccDOTsol/qwencoin, src/pow.h there). A header's
 * work value is not its hash:
 *
 *     value = SHA256( fold(net(seed, nNonce)) XOR seed ),   seed = SHA256d(header with nNonce = 0)
 *
 * where net is a pass through the gate, up and down projections of all 24 layers of Qwen3.5-0.8B
 * at 16-bit fixed point with sign activations (crypto/qwork.h, Qwencoin's own kernel). The value
 * is compared with the target exactly as Bitcoin compares a block hash; the header's identity
 * stays its SHA256d hash. The pass runs over a table of the model's weights (qwork.bin, 528 MB),
 * mapped once per process.
 */
inline constexpr uint64_t QWORK_CHECKSUM = 0x33a548a33925d201ULL; //!< qwork_fnv64 of the table; its sha256 is 8f53884f7727e80b86f3ddf288d3c3f0f998f1c63b8cd4f0bdad182ddd3f2c03
inline constexpr int QWORK_LAYERS = 24, QWORK_N = 1024, QWORK_M = 3584;
/** Map the table and check that it is the chain's. Returns an empty string, or what is wrong. */
std::string LoadQworkTable(const std::string& path);
void UnloadQworkTable();
bool QworkLoaded();
/**
 * Keep work values in this file from now on: read the ones it has, append each new one. Every
 * start replays the launch's blocks, and without the file every relayed Qwencoin header costs its
 * pass again. Returns an empty string, or why the file cannot be written (the node then goes on
 * with what it keeps in memory). A record is believed only with its check, so a damaged file
 * costs passes, never a wrong value.
 */
std::string KeepQworkValues(const std::string& path);
/** The work value of a Qwencoin header. The table must be loaded. */
uint256 QwenWorkValue(const CPureBlockHeader& header);
/** How many passes through the weights this process has made (a value that was kept costs none). */
uint64_t QwenPasses();
/**
 * For tests only: a stand-in for the pass through the weights (nullptr: none again). With one
 * set, a Qwencoin main-network header's work value is what the function returns and no table is
 * needed, so the tree's own rules (the limit, the retarget, the timestamp rules at the edges of a
 * period) can be tested on chains made for the purpose. The node never calls this.
 */
void SetQwenWorkForTests(uint256 (*fn)(const CPureBlockHeader&));
/** Whether a Qwencoin main-network header meets the target its own bits name (bits no easier than Qwencoin's limit). */
bool CheckQwenWork(const CPureBlockHeader& header);

/** How many Qwencoin headers one launch block may have its nodes check the work of (see HeaderChain::Accept). */
inline constexpr int QWEN_PASSES_PER_BLOCK = 8;

/**
 * Header tree of another chain (Bitcoin, Qwencoin), rooted at the descriptor's anchor and fed by
 * headers relayed inside launch blocks. Fully validating (PoW, difficulty schedule, median
 * time), so the launch chain's view of that chain is a pure function of its own blocks. Best
 * tip = most work, ties to the numerically lowest hash.
 *
 * Rules, by chain:
 *   Bitcoin    work = the header's hash; limit 0x1d00ffff; retarget every 2016 blocks
 *   Qwencoin   work = QwenWorkValue(header); limit 0x2000ffff; the same retarget
 *              and its two timestamp rules at the edges of a period: the first block of a
 *              period not more than 600 s before its parent, the last not before the first
 *   regtest    (either chain) bits 0x207fffff, work = the header's hash, no retarget:
 *              Bitcoin's regtest rules, which qwencoind -regtest keeps
 * The retarget is Bitcoin's, target * timespan / two weeks with the timespan clamped to a factor
 * of four, computed as q * num + (r * num) / den with target = q * den + r: the same number, and
 * near Qwencoin's limit the product itself would not fit in 256 bits (Qwencoin's MulDiv).
 */
class HeaderChain
{
public:
    enum class Rules { BITCOIN, QWENCOIN };
    struct Node {
        uint256 prev;
        uint256 merkle_root;
        uint32_t time{0};
        uint32_t bits{0};
        int height{0};
        arith_uint256 work;
        uint32_t period_time{0}; //!< time of the first block of this block's difficulty period
    };

    void Init(const CPureBlockHeader& anchor, int anchor_height, uint32_t anchor_period_time, Rules rules, bool regtest);
    bool Initialized() const { return !m_nodes.empty(); }
    /**
     * Add a header. false + error if invalid, unconnected or already known. The checks run in
     * this order: already known, does not connect, wrong bits, work, median time, and on
     * Qwencoin's main network the two timestamp rules at the edges of a difficulty period.
     *
     * `budget`, when given, is how many more headers may have their work checked. A Qwencoin
     * pass costs a node a twentieth of a second where a Bitcoin hash costs nothing, and a header
     * that fails costs whoever relays it nothing at all, so a launch block may make its nodes
     * check only QWEN_PASSES_PER_BLOCK of them: a header that gets as far as the work check
     * takes one from the budget, and with none left it is refused unchecked, as if it were not
     * there. What counts is how far a header gets, never whether its value was already known,
     * so the answer is the same on every node.
     */
    bool Accept(const CPureBlockHeader& header, std::string& error, int* budget = nullptr);
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
    void UpdateMain();

    /** Most work first, ties to the numerically lowest hash: begin() is the best tip. */
    struct ByWork {
        bool operator()(const std::pair<arith_uint256, uint256>& a, const std::pair<arith_uint256, uint256>& b) const
        {
            return a.first > b.first || (a.first == b.first && UintToArith256(a.second) < UintToArith256(b.second));
        }
    };

    std::map<uint256, Node> m_nodes;
    std::map<uint256, int> m_children;
    std::set<std::pair<arith_uint256, uint256>, ByWork> m_order; //!< every header, best first
    std::vector<uint256> m_main;                                 //!< the best chain: m_main[i] is at height anchor + i
    uint256 m_anchor;
    uint256 m_best;
    int m_anchor_height{0};
    Rules m_rules{Rules::BITCOIN};
    bool m_regtest{false};
};

/** The Bitcoin header tree, by the name it had while a launch followed one chain. */
using BtcChain = HeaderChain;

} // namespace launchyield

#endif // BITCOIN_LAUNCHYIELD_H
