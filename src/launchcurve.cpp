// Copyright (c) 2026 The hashfun developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <launchcurve.h>

#include <chain.h>
#include <crypto/common.h>
#include <uint256.h>

#include <algorithm>
#include <mutex>
#include <unordered_map>

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

arith_uint256 RelWork(const CBlockIndex* pindex, const Consensus::Params& params)
{
    const arith_uint256 g = UintToArith256(params.launch_genesis_work);
    return pindex->nChainWork > g ? pindex->nChainWork - g : arith_uint256{0};
}

/** Graduated, given the chain's work above genesis and the part of it that is on the QWEN curve. */
bool Graduated(const arith_uint256& rel, const arith_uint256& qwen, const Consensus::Params& params)
{
    const arith_uint256 wg = UintToArith256(params.launch_graduation_work);
    return qwen >= wg || (rel > qwen ? rel - qwen : arith_uint256{0}) >= wg;
}

/**
 * The QWEN curve's work as of a block is not in the block index (the index stores what Bitcoin
 * stores). It is a pure function of the header chain, so it is remembered here by block hash:
 *  - below graduation, one sum every STEP blocks: a lookup walks down to the nearest one;
 *  - the first graduated block of every chain seen: nothing above it is on a curve, so the sum of
 *    any descendant is that block's, found with one ancestor lookup and no memory per block (a
 *    graduated launch lives on for years of tail blocks).
 * A block hash commits to the block's version and to everything below it, so an entry can never
 * be wrong for the block index of this process, across reorganisations, a reindex or an unload.
 */
struct QwenWorkCache {
    static constexpr int STEP = 64;
    static constexpr size_t MAX_GRADUATIONS = 16; //!< one per chain that forks below its graduation block: a handful at most
    struct HashKey {
        size_t operator()(const uint256& h) const { return ReadLE64(h.begin()); }
    };
    struct Graduation {
        uint256 hash;
        int height;
        arith_uint256 qwen;
    };
    std::mutex mutex;
    std::unordered_map<uint256, arith_uint256, HashKey> sums;
    std::vector<Graduation> graduations;
};

QwenWorkCache& Cache()
{
    static QwenWorkCache cache;
    return cache;
}

arith_uint256 QwenWork(const CBlockIndex* pindex, const Consensus::Params& params)
{
    if (pindex == nullptr || pindex->pprev == nullptr || !params.launch_enabled) return 0;
    QwenWorkCache& cache = Cache();
    std::lock_guard lock{cache.mutex};
    for (size_t i = 0; i < cache.graduations.size(); ++i) {
        const auto& g = cache.graduations[i];
        if (pindex->nHeight < g.height) continue;
        const CBlockIndex* at = pindex->GetAncestor(g.height);
        if (at != nullptr && at->GetBlockHash() == g.hash) {
            const arith_uint256 qwen = g.qwen;
            // The entry just used goes to the back: when the list is full the one dropped is the
            // one not asked about for longest, never the chain the node is on.
            std::rotate(cache.graduations.begin() + i, cache.graduations.begin() + i + 1, cache.graduations.end());
            return qwen;
        }
    }
    // Down to the nearest block whose sum is known (the genesis block's is zero) ...
    std::vector<const CBlockIndex*> path;
    arith_uint256 sum{0};
    const CBlockIndex* base = pindex;
    for (; base->pprev != nullptr; base = base->pprev) {
        if (base->nHeight % QwenWorkCache::STEP == 0) {
            if (const auto it = cache.sums.find(base->GetBlockHash()); it != cache.sums.end()) {
                sum = it->second;
                break;
            }
        }
        path.push_back(base);
    }
    // ... and back up, block by block. Only blocks below graduation are ever remembered every STEP,
    // so `base` has not graduated unless the list of graduation blocks above lost its entry; then
    // the walk went down to the last block below graduation and finds the same block again.
    bool graduated = Graduated(RelWork(base, params), sum, params);
    for (auto it = path.rbegin(); it != path.rend() && !graduated; ++it) {
        const CBlockIndex* b = *it;
        if (b->nVersion & LAUNCH_VERSION_QWEN) sum += GetBlockProof(*b);
        graduated = Graduated(RelWork(b, params), sum, params);
        if (graduated) {
            if (cache.graduations.size() >= QwenWorkCache::MAX_GRADUATIONS) cache.graduations.erase(cache.graduations.begin());
            cache.graduations.push_back({b->GetBlockHash(), b->nHeight, sum});
        } else if (b->nHeight % QwenWorkCache::STEP == 0) {
            cache.sums.emplace(b->GetBlockHash(), sum);
        }
    }
    return sum;
}

} // namespace

void LaunchCurveCacheClear()
{
    QwenWorkCache& cache = Cache();
    std::lock_guard lock{cache.mutex};
    cache.sums.clear();
    cache.graduations.clear();
}

arith_uint256 LaunchRelWork(const CBlockIndex* pindex, const Consensus::Params& params)
{
    if (pindex == nullptr) return 0;
    return RelWork(pindex, params);
}

arith_uint256 LaunchCurveWork(const CBlockIndex* pindex, LaunchCurve curve, const Consensus::Params& params)
{
    if (pindex == nullptr) return 0;
    const arith_uint256 qwen = QwenWork(pindex, params);
    if (curve == LaunchCurve::QWEN) return qwen;
    const arith_uint256 rel = RelWork(pindex, params);
    return rel > qwen ? rel - qwen : arith_uint256{0};
}

bool LaunchCurveComplete(const arith_uint256& w, const Consensus::Params& params)
{
    return params.launch_enabled && w >= UintToArith256(params.launch_graduation_work);
}

bool LaunchGraduatedAt(const CBlockIndex* pindex, const Consensus::Params& params)
{
    if (pindex == nullptr || !params.launch_enabled) return false;
    return Graduated(RelWork(pindex, params), QwenWork(pindex, params), params);
}

CAmount LaunchCurveSupply(const arith_uint256& w, const Consensus::Params& params)
{
    if (!params.launch_enabled) return 0;
    if (LaunchCurveComplete(w, params)) return params.launch_graduation_tokens;
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

CAmount LaunchSubsidy(const CBlockIndex* pindexPrev, uint32_t nBits, int32_t nVersion, int nHeight, const Consensus::Params& params)
{
    if (LaunchGraduatedAt(pindexPrev, params)) return LaunchTailReward(nHeight, params);
    // The block mints from its own curve: the other curve's work does not move its price.
    const arith_uint256 w_prev = LaunchCurveWork(pindexPrev, LaunchCurveOf(nVersion), params);
    const arith_uint256 w_after = w_prev + WorkFromBits(nBits);
    return LaunchCurveSupply(w_after, params) - LaunchCurveSupply(w_prev, params);
}

bool LaunchCurveVersionOk(int32_t nVersion, const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    return !(nVersion & LAUNCH_VERSION_QWEN) || !LaunchGraduatedAt(pindexPrev, params);
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

std::optional<LaunchCurve> LaunchGraduatedBy(const CBlockIndex* tip, const Consensus::Params& params)
{
    const int height = LaunchGraduationHeight(tip, params);
    if (height < 0) return std::nullopt;
    // Below the graduation block neither curve had sold out, and that block's work went to one of
    // them: its own.
    return LaunchCurveOf(tip->GetAncestor(height)->nVersion);
}

CAmount LaunchCurveMinted(const CBlockIndex* pindex, LaunchCurve curve, const Consensus::Params& params)
{
    if (pindex == nullptr || !params.launch_enabled) return 0;
    const int height = LaunchGraduationHeight(pindex, params);
    const CBlockIndex* at = height < 0 ? pindex : pindex->GetAncestor(height);
    return LaunchCurveSupply(LaunchCurveWork(at, curve, params), params);
}

CAmount LaunchCurveMinted(const CBlockIndex* pindex, const Consensus::Params& params)
{
    if (pindex == nullptr || !params.launch_enabled) return 0;
    const int height = LaunchGraduationHeight(pindex, params);
    const CBlockIndex* at = height < 0 ? pindex : pindex->GetAncestor(height);
    return LaunchCurveSupply(LaunchCurveWork(at, LaunchCurve::BTC, params), params) +
           LaunchCurveSupply(LaunchCurveWork(at, LaunchCurve::QWEN, params), params);
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

std::vector<unsigned char> LaunchCoinbaseTag(const Consensus::Params& params)
{
    return {params.launch_id.begin(), params.launch_id.begin() + 16};
}
