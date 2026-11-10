// Copyright (c) 2026 The hashfun developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LAUNCHCURVE_H
#define BITCOIN_LAUNCHCURVE_H

#include <arith_uint256.h>
#include <consensus/amount.h>
#include <consensus/params.h>

#include <cstdint>

class CBlockIndex;

/**
 * hashfun consensus curve.
 *
 *   W        = chainwork relative to genesis (expected hashes)
 *   S(W)     = floor(T0 * W / (V0 + W))         constant product, x*y=k
 *   S'(W)    = T0*V0 / (V0+W)^2                  coins per hash
 *   price    = (V0+W)^2 / (T0*V0)                hashes per satoshi
 *
 * A block's curve subsidy is S(W_after) - S(W_before), so issuance is a
 * pure function of cumulative work: path independent, timestamp independent,
 * and sniping a cheap block buys exactly the curve price.
 *
 * Graduation: S(W) >= G  <=>  W >= W_g = ceil(G*V0/(T0-G)). The crossing
 * block mints only up to G. After graduation each block gets the tail
 * reward (halving by absolute height) and AuxPoW becomes valid.
 */

/** Chainwork above genesis for pindex (pindex may be the genesis). */
arith_uint256 LaunchRelWork(const CBlockIndex* pindex, const Consensus::Params& params);
/** Exact curve supply at relative work w, clamped to G. */
CAmount LaunchCurveSupply(const arith_uint256& w, const Consensus::Params& params);
/** Whether the chain with relative work w has graduated. */
bool LaunchGraduated(const arith_uint256& w, const Consensus::Params& params);
bool LaunchGraduatedAt(const CBlockIndex* pindex, const Consensus::Params& params);
/** Tail reward at an absolute height. */
CAmount LaunchTailReward(int nHeight, const Consensus::Params& params);
/** Subsidy of the block at nHeight with difficulty nBits on top of pindexPrev. */
CAmount LaunchSubsidy(const CBlockIndex* pindexPrev, uint32_t nBits, int nHeight, const Consensus::Params& params);
/** Mandatory creator output amount for a given subsidy. */
CAmount LaunchCreatorFee(CAmount subsidy, const Consensus::Params& params);
/** First height whose block crossed graduation, or -1. O(log n). */
int LaunchGraduationHeight(const CBlockIndex* tip, const Consensus::Params& params);
/** Total tail subsidy minted in heights [from, to]. */
CAmount LaunchTailMinted(int from_height, int to_height, const Consensus::Params& params);
/** Hashes per whole coin at relative work w (double, for display). */
double LaunchHashesPerCoin(const arith_uint256& w, const Consensus::Params& params);
/** Parse a decimal or 0x-hex string into a uint256 (big-endian bytes). */
bool ParseUint256Decimal(const std::string& s, arith_uint256& out);

#endif // BITCOIN_LAUNCHCURVE_H
