// Copyright (c) 2026 The hashfun developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <launchcurve.h>

#include <chain.h>

#include <algorithm>

namespace {

arith_uint256 WorkFromBits(uint32_t nBits)
{
    arith_uint256 target;
    bool neg, ovf;
    target.SetCompact(nBits, &neg, &ovf);
    if (neg || ovf || target == 0) return 0;
    // Same as GetBlockProof: 2**256 / (target+1), computed without overflow.
    return (~target / (target + 1)) + 1;
}

} // namespace

arith_uint256 LaunchRelWork(const CBlockIndex* pindex, const Consensus::Params& params)
{
    if (pindex == nullptr) return 0;
    const arith_uint256 g = UintToArith256(params.launch_genesis_work);
    return pindex->nChainWork > g ? pindex->nChainWork - g : arith_uint256{0};
}

bool LaunchGraduated(const arith_uint256& w, const Consensus::Params& params)
{
    return params.launch_enabled && w >= UintToArith256(params.launch_graduation_work);
}

bool LaunchGraduatedAt(const CBlockIndex* pindex, const Consensus::Params& params)
{
    return LaunchGraduated(LaunchRelWork(pindex, params), params);
}

CAmount LaunchCurveSupply(const arith_uint256& w, const Consensus::Params& params)
{
    if (!params.launch_enabled) return 0;
    if (LaunchGraduated(w, params)) return params.launch_graduation_tokens;
    // w < W_g <= 1000*V0 <= 2^170 and T0 < 2^51, so T0*w < 2^221: no overflow.
    const arith_uint256 v0 = UintToArith256(params.launch_virtual_work);
    const arith_uint256 num = arith_uint256{static_cast<uint64_t>(params.launch_virtual_tokens)} * w;
    const arith_uint256 den = v0 + w;
    const CAmount s = static_cast<CAmount>((num / den).GetLow64());
    return std::min(s, params.launch_graduation_tokens);
}

CAmount LaunchTailReward(int nHeight, const Consensus::Params& params)
{
    if (params.launch_tail_reward <= 0 || params.launch_tail_halving_interval <= 0) return 0;
    const int halvings = nHeight / params.launch_tail_halving_interval;
    if (halvings >= 63) return 0;
    return params.launch_tail_reward >> halvings;
}

CAmount LaunchSubsidy(const CBlockIndex* pindexPrev, uint32_t nBits, int nHeight, const Consensus::Params& params)
{
    const arith_uint256 w_prev = LaunchRelWork(pindexPrev, params);
    if (LaunchGraduated(w_prev, params)) return LaunchTailReward(nHeight, params);
    const arith_uint256 w_after = w_prev + WorkFromBits(nBits);
    return LaunchCurveSupply(w_after, params) - LaunchCurveSupply(w_prev, params);
}

CAmount LaunchCreatorFee(CAmount subsidy, const Consensus::Params& params)
{
    if (!params.launch_enabled || params.launch_creator_fee_bps <= 0 || subsidy <= 0) return 0;
    return subsidy * params.launch_creator_fee_bps / 10000;
}

int LaunchGraduationHeight(const CBlockIndex* tip, const Consensus::Params& params)
{
    if (tip == nullptr || !LaunchGraduatedAt(tip, params)) return -1;
    int lo = 1, hi = tip->nHeight; // invariant: graduated at hi
    while (lo < hi) {
        const int mid = lo + (hi - lo) / 2;
        if (LaunchGraduatedAt(tip->GetAncestor(mid), params)) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return hi;
}

CAmount LaunchTailMinted(int from_height, int to_height, const Consensus::Params& params)
{
    if (from_height > to_height || params.launch_tail_reward <= 0 || params.launch_tail_halving_interval <= 0) return 0;
    const int64_t H = params.launch_tail_halving_interval;
    CAmount total = 0;
    for (int64_t k = from_height / H; k < 63; ++k) {
        const int64_t seg_lo = std::max<int64_t>(k * H, from_height);
        const int64_t seg_hi = std::min<int64_t>((k + 1) * H - 1, to_height);
        if (seg_lo > to_height) break;
        const CAmount r = params.launch_tail_reward >> k;
        if (r == 0) break;
        if (seg_hi >= seg_lo) total += r * (seg_hi - seg_lo + 1);
    }
    return total;
}

double LaunchHashesPerCoin(const arith_uint256& w, const Consensus::Params& params)
{
    if (!params.launch_enabled) return 0;
    const arith_uint256 wg = UintToArith256(params.launch_graduation_work);
    const double v0 = UintToArith256(params.launch_virtual_work).getdouble();
    const double wd = (w < wg ? w : wg).getdouble();
    const double t0 = static_cast<double>(params.launch_virtual_tokens);
    return (v0 + wd) * (v0 + wd) / (t0 * v0) * static_cast<double>(COIN);
}
