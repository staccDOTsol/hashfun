// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/check.h>

#include <algorithm>

/**
 * LWMA-1 (Zawy) per-block difficulty for hashfun launch chains.
 *
 * Linearly weighted moving average of the last N solvetimes; recent blocks
 * weigh more. Timestamps are forced monotonic in a way that cannot be gamed
 * (out-of-order stamps count as +1s, never negative), and each solvetime is
 * capped at 6T so a single late stamp cannot crash difficulty. Before N blocks
 * exist the window is the whole chain. The result never exceeds powLimit and
 * the multiplication is guarded against 256-bit overflow (relevant for
 * test launches whose powLimit is near 2^255).
 *
 * This base target depends only on ancestors. LaunchStallRelief below then
 * eases it by the candidate block's own timestamp.
 */
static unsigned int LwmaNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    const arith_uint256 pow_limit = UintToArith256(params.powLimit);
    const int64_t T = params.nPowTargetSpacing;
    const int64_t height = pindexLast->nHeight;
    const int64_t N = std::min<int64_t>(params.lwma_window, height);
    if (N < 1 || T < 1) return pow_limit.GetCompact();

    const int64_t k = N * (N + 1) * T / 2;
    arith_uint256 avg_target{0};
    int64_t sum_weighted_solvetimes = 0;
    int64_t previous_timestamp = pindexLast->GetAncestor(height - N)->GetBlockTime();
    int64_t j = 0;
    for (int64_t i = height - N + 1; i <= height; ++i) {
        const CBlockIndex* block = pindexLast->GetAncestor(i);
        const int64_t this_timestamp = block->GetBlockTime() > previous_timestamp ? block->GetBlockTime() : previous_timestamp + 1;
        const int64_t solvetime = std::min<int64_t>(6 * T, this_timestamp - previous_timestamp);
        previous_timestamp = this_timestamp;
        ++j;
        sum_weighted_solvetimes += solvetime * j;
        arith_uint256 target;
        target.SetCompact(block->nBits);
        avg_target += target / static_cast<uint64_t>(N) / static_cast<uint64_t>(k);
    }
    if (sum_weighted_solvetimes < 1) sum_weighted_solvetimes = 1;
    const arith_uint256 sw{static_cast<uint64_t>(sum_weighted_solvetimes)};
    if (avg_target > pow_limit / sw) return pow_limit.GetCompact();
    arith_uint256 next_target = avg_target * sw;
    if (next_target > pow_limit) next_target = pow_limit;
    if (next_target == 0) next_target = 1;
    return next_target.GetCompact();
}

/**
 * Real-time stall relief for launch chains: the target doubles for every full
 * 6T the candidate block's timestamp sits past its parent's, up to powLimit.
 *
 * A launch only attracts hash while minting is profitable, and LWMA alone
 * adjusts per block, so a chain left at high difficulty would never produce
 * the block that lowers it. With relief, difficulty decays in wall-clock time
 * until anyone can extend the chain. This is safe to make aggressive because
 * issuance is priced by work: an easier block mints proportionally fewer
 * coins, so stamping a block late (bounded by the FTL) buys nothing.
 *
 * nBits is therefore a function of (ancestors, own nTime): a template is only
 * valid for the 6T bucket it was built in, and miners must not roll nTime.
 */
static unsigned int LaunchStallRelief(unsigned int base_bits, const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    if (pblock == nullptr) return base_bits;
    const int64_t elapsed = pblock->GetBlockTime() - pindexLast->GetBlockTime();
    const int64_t step = 6 * params.nPowTargetSpacing;
    if (step < 1 || elapsed < step) return base_bits;
    const arith_uint256 pow_limit = UintToArith256(params.powLimit);
    arith_uint256 target;
    target.SetCompact(base_bits);
    for (int64_t n = elapsed / step; n > 0; --n) {
        if (target > (pow_limit >> 1)) return pow_limit.GetCompact();
        target <<= 1;
    }
    return target.GetCompact();
}

bool LaunchTemplateStale(const CBlockIndex* pindexPrev, const CBlockHeader& header, int64_t now, const Consensus::Params& params)
{
    if (pindexPrev == nullptr || params.lwma_window <= 0) return false;
    CBlockHeader probe{header};
    if (now > probe.GetBlockTime()) probe.nTime = static_cast<uint32_t>(now);
    return LaunchStallRelief(LwmaNextWorkRequired(pindexPrev, params), pindexPrev, &probe, params) != header.nBits;
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    if (params.lwma_window > 0) return LaunchStallRelief(LwmaNextWorkRequired(pindexLast, params), pindexLast, pblock, params);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then it MUST be a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;

    // Special difficulty rule for Testnet4
    if (params.enforce_BIP94) {
        // Here we use the first block of the difficulty period. This way
        // the real difficulty is always preserved in the first block as
        // it is not allowed to use the min-difficulty exception.
        int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
        const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
        bnNew.SetCompact(pindexFirst->nBits);
    } else {
        bnNew.SetCompact(pindexLast->nBits);
    }

    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;
    // LWMA retargets every block; there is no fixed transition window to check.
    if (params.lwma_window > 0) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

// Bypasses the actual proof of work check during fuzz testing with a simplified validation checking whether
// the most significant bit of the last byte of the hash is set.
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    if (EnableFuzzDeterminism()) return (hash.data()[31] & 0x80) == 0;
    return CheckProofOfWorkImpl(hash, nBits, params);
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    auto bnTarget{DeriveTarget(nBits, params.powLimit)};
    if (!bnTarget) return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
