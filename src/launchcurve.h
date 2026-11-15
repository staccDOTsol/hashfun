// Copyright (c) 2026 The hashfun developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LAUNCHCURVE_H
#define BITCOIN_LAUNCHCURVE_H

#include <arith_uint256.h>
#include <consensus/amount.h>
#include <consensus/params.h>

#include <cstdint>
#include <optional>
#include <vector>

class CBlockIndex;

/**
 * hashfun consensus curves.
 *
 * A launch has two curves of the same shape over the same coin: the BTC curve and the QWEN curve
 * (contrib/hashfun/TWIN.md). A block mined before graduation is on exactly one of them: it mints
 * from that curve and owes that curve's asset (launchyield.h). For one curve, with W the work of
 * the blocks on it (expected hashes):
 *
 *   S(W)     = floor(T0 * W / (V0 + W))         constant product, x*y=k
 *   S'(W)    = T0*V0 / (V0+W)^2                  coins per hash
 *   price    = (V0+W)^2 / (T0*V0)                hashes per satoshi
 *
 * A block's curve subsidy is S(W_after) - S(W_before) on its own curve, so issuance is a pure
 * function of the work put into that curve: path independent, timestamp independent, and sniping
 * a cheap block buys exactly the curve price. Nothing ties the two curves together: whoever mints
 * picks one, and each price is moved only by what is bought through it.
 *
 * Graduation: the first curve with S(W) >= G  <=>  W >= W_g = ceil(G*V0/(T0-G)). The crossing
 * block mints only up to G, and what the other curve has not sold is never minted. After
 * graduation each block gets the tail reward (halving by absolute height) and AuxPoW becomes
 * valid.
 */

/**
 * Bit of a block header's nVersion that puts the block on the QWEN curve; clear: the BTC curve.
 * It is not part of the base version (the low 8 bits), the auxpow flag (bit 8) or the auxpow
 * chain id (bits 16 and up).
 */
inline constexpr int32_t LAUNCH_VERSION_QWEN = 0x200;

enum class LaunchCurve { BTC = 0, QWEN = 1 };
inline LaunchCurve LaunchCurveOf(int32_t nVersion) { return (nVersion & LAUNCH_VERSION_QWEN) ? LaunchCurve::QWEN : LaunchCurve::BTC; }
inline const char* LaunchCurveName(LaunchCurve curve) { return curve == LaunchCurve::QWEN ? "qwen" : "btc"; }

/** Chainwork above genesis for pindex (pindex may be the genesis): both curves and the tail together. */
arith_uint256 LaunchRelWork(const CBlockIndex* pindex, const Consensus::Params& params);
/**
 * Work of the blocks of pindex's chain that are on a curve, per curve. A block is on the QWEN
 * curve when its version has LAUNCH_VERSION_QWEN and its parent has not graduated (the header
 * rule refuses the bit on any other block, so on a valid chain that is every block with the bit);
 * the BTC curve has the rest of the chain's work above genesis. After graduation the QWEN sum
 * stands still and the BTC one keeps growing with the tail's blocks: nothing reads it then.
 */
arith_uint256 LaunchCurveWork(const CBlockIndex* pindex, LaunchCurve curve, const Consensus::Params& params);
/** Exact supply of one curve at curve work w, clamped to G. */
CAmount LaunchCurveSupply(const arith_uint256& w, const Consensus::Params& params);
/** Whether a curve with work w has sold out. */
bool LaunchCurveComplete(const arith_uint256& w, const Consensus::Params& params);
/** Whether the chain has graduated as of pindex: one of its curves has sold out. */
bool LaunchGraduatedAt(const CBlockIndex* pindex, const Consensus::Params& params);
/** Tail reward at an absolute height. */
CAmount LaunchTailReward(int nHeight, const Consensus::Params& params);
/** Subsidy of the block at nHeight with difficulty nBits and version nVersion on top of pindexPrev. */
CAmount LaunchSubsidy(const CBlockIndex* pindexPrev, uint32_t nBits, int32_t nVersion, int nHeight, const Consensus::Params& params);
/**
 * The header rule `bad-curve-version`: only a block that mints from a curve can be on the QWEN
 * one, so LAUNCH_VERSION_QWEN may be set only on a block whose parent has not graduated.
 */
bool LaunchCurveVersionOk(int32_t nVersion, const CBlockIndex* pindexPrev, const Consensus::Params& params);
/** Mandatory creator output amount for a given subsidy. */
CAmount LaunchCreatorFee(CAmount subsidy, const Consensus::Params& params);
/** First height whose block crossed graduation, or -1. O(log n). */
int LaunchGraduationHeight(const CBlockIndex* tip, const Consensus::Params& params);
/** The curve whose last block graduated the chain, if it has graduated as of tip. */
std::optional<LaunchCurve> LaunchGraduatedBy(const CBlockIndex* tip, const Consensus::Params& params);
/**
 * What one curve has minted as of pindex. Once the chain has graduated this is the curve's supply
 * at the graduation block and no longer moves.
 */
CAmount LaunchCurveMinted(const CBlockIndex* pindex, LaunchCurve curve, const Consensus::Params& params);
/** What both curves have minted as of pindex. */
CAmount LaunchCurveMinted(const CBlockIndex* pindex, const Consensus::Params& params);
/** Total tail subsidy minted in heights [from, to]. */
CAmount LaunchTailMinted(int from_height, int to_height, const Consensus::Params& params);
/**
 * What every coinbase of a launch pushes in its scriptSig right after the block height: the first
 * 16 bytes of the launch id. No transaction can then exist on two launches (a coinbase names its
 * launch, and everything else descends from coinbases), so nothing spent on one launch can be
 * replayed on another, however alike the two are.
 */
std::vector<unsigned char> LaunchCoinbaseTag(const Consensus::Params& params);
/** Hashes per whole coin on a curve with work w (double, for display). */
double LaunchHashesPerCoin(const arith_uint256& w, const Consensus::Params& params);
/**
 * Forget the per-curve work sums remembered so far. They are keyed by block hash and are a pure
 * function of the header chain, so the node never needs this; a test that builds unrelated chains
 * out of made-up block hashes does.
 */
void LaunchCurveCacheClear();

#endif // BITCOIN_LAUNCHCURVE_H
