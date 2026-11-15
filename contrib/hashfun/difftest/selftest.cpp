// hashfun rule set 3 (two curves, the QWEN leg): the node's own consensus code checked against
// expectations written out here, without the rest of the node. Run by `hfdiff --selftest` and by
// the "selftest" op of the driver (hashfun/tests/test_diff_cpp.py).
//
// What is checked:
//   curves     per-curve work, subsidy on a block's own curve, graduation by either curve, the
//              crossing block, the version rule, minted supply standing still after graduation,
//              the work cache against a recomputation from the genesis block, forks
//   relay      the header tree under Bitcoin's and Qwencoin's regtest rules, the limit of work
//              checks per launch block, the errors by chain
//   state      a launch with both curves in use: what each block owes and to which script by its
//              curve, payments proven on the block's own chain and refused on the other one,
//              confirmations per chain, the pass limit across a block's outputs, counters, undo
//   table      (with QWORK_TABLE) Qwencoin's work function on its real table: the genesis value
//   vectors    (with QWORK_TABLE and QWEN_VECTORS) real Qwencoin headers across every retarget the
//              chain has made: each one's hash and work value, the tree accepting them from an
//              anchor below each retarget, each refused with its nonce changed

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <crypto/hex_base.h>
#include <hash.h>
#include <kernel/chainparams.h>
#include <kernel/launch.h>
#include <launchcurve.h>
#include <launchyield.h>
#include <launchyieldstate.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace {

using launchyield::HeaderChain;

const char* const REGTEST_GENESIS =
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f"
    "617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000";
const uint32_t REGTEST_BITS = 0x207fffff;

struct Report {
    UniValue checks{UniValue::VARR};
    void Add(const std::string& name, bool ok, const std::string& detail = "", bool skipped = false)
    {
        UniValue c(UniValue::VOBJ);
        c.pushKV("name", name);
        c.pushKV("ok", ok);
        c.pushKV("skipped", skipped);
        c.pushKV("detail", detail);
        checks.push_back(std::move(c));
    }
};

/** One named check made of many expectations: it passes when none failed, and says which did. */
struct Case {
    Report& report;
    std::string name;
    int expectations{0};
    std::string note; //!< numbers worth reading in the report
    std::vector<std::string> failed;
    Case(Report& r, std::string n) : report{r}, name{std::move(n)} {}
    void Expect(bool cond, const std::string& what)
    {
        ++expectations;
        if (!cond && failed.size() < 6) failed.push_back(what);
        else if (!cond) failed.back() = "... and more";
    }
    template <typename A, typename B>
    void Equal(const A& a, const B& b, const std::string& what)
    {
        std::ostringstream ss;
        ss << what << ": " << a << " != " << b;
        Expect(a == b, ss.str());
    }
    ~Case()
    {
        std::string detail = strprintf("%d expectations", expectations);
        if (!note.empty()) detail += " (" + note + ")";
        for (const auto& f : failed) detail += "; " + f;
        report.Add(name, failed.empty(), detail);
    }
};

struct LaunchSpec {
    std::string virtual_work{"40"};
    int64_t virtual_tokens{100000000000000};   // 1,000,000 coins
    int64_t graduation_tokens{70000000000000}; //   700,000 coins: W_g = ceil(0.7 * 40 / 0.3) = 94 hashes
    int64_t sats_num{5000}, qwen_num{7000};
    int64_t sats_min{10000}, qwen_min{10000};
    int btc_confs{1}, qwen_confs{2};
    int settle_deadline{720};
};

std::unique_ptr<const CChainParams> MakeLaunch(const LaunchSpec& spec)
{
    for (uint32_t nonce = 0; nonce < 1000; ++nonce) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("version", 3);
        o.pushKV("name", "Self Test");
        o.pushKV("ticker", "SELF");
        o.pushKV("hrp", "self");
        o.pushKV("genesis_time", 1794000000);
        o.pushKV("genesis_nonce", static_cast<int64_t>(nonce));
        o.pushKV("pow_limit_bits", "0x207fffff");
        o.pushKV("target_spacing", 5);
        o.pushKV("lwma_window", 90);
        o.pushKV("virtual_work", spec.virtual_work);
        o.pushKV("virtual_tokens", spec.virtual_tokens);
        o.pushKV("graduation_tokens", spec.graduation_tokens);
        o.pushKV("tail_reward", 5000);
        o.pushKV("tail_halving_interval", 1000000);
        o.pushKV("creator_script", "00141111111111111111111111111111111111111111");
        o.pushKV("creator_fee_bps", 100);
        o.pushKV("test", true);
        o.pushKV("btc_anchor_height", 0);
        o.pushKV("btc_anchor_header", REGTEST_GENESIS);
        o.pushKV("btc_anchor_period_time", 0);
        o.pushKV("sats_num", spec.sats_num);
        o.pushKV("sats_shift", 0);
        o.pushKV("sats_min_payment", spec.sats_min);
        o.pushKV("settle_deadline", spec.settle_deadline);
        o.pushKV("btc_confs", spec.btc_confs);
        o.pushKV("creator_btc_script", "0014c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1");
        o.pushKV("btc_regtest", true);
        o.pushKV("qwen_anchor_height", 0);
        o.pushKV("qwen_anchor_header", REGTEST_GENESIS);
        o.pushKV("qwen_anchor_period_time", 0);
        o.pushKV("qwen_num", spec.qwen_num);
        o.pushKV("qwen_shift", 0);
        o.pushKV("qwen_min_payment", spec.qwen_min);
        o.pushKV("qwen_confs", spec.qwen_confs);
        o.pushKV("creator_qwen_script", "0014c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2");
        o.pushKV("qwen_regtest", true);
        std::string error;
        const auto d = ParseLaunchDescriptor(o.write(), error);
        if (!d) throw std::runtime_error("selftest descriptor: " + error);
        try {
            return CChainParams::Launch(CChainParams::LaunchOptions{.desc = *d});
        } catch (const std::exception&) {
            // this nonce's genesis hash is over the limit: the next one
        }
    }
    throw std::runtime_error("selftest descriptor: no genesis nonce found");
}

arith_uint256 WorkOf(uint32_t bits)
{
    arith_uint256 target;
    target.SetCompact(bits);
    return (~target / (target + 1)) + 1;
}

// ---- a chain of index entries, and the curves recomputed the slow way -------------------------

struct Chain {
    const Consensus::Params& c;
    std::vector<std::unique_ptr<CBlockIndex>> idx;
    std::vector<std::unique_ptr<uint256>> hashes;
    explicit Chain(const CChainParams& p) : c{p.GetConsensus()}
    {
        idx.push_back(std::make_unique<CBlockIndex>(p.GenesisBlock()));
        hashes.push_back(std::make_unique<uint256>(p.GenesisBlock().GetHash()));
        idx.back()->phashBlock = hashes.back().get();
        idx.back()->nHeight = 0;
        idx.back()->nChainWork = GetBlockProof(*idx.back());
        idx.back()->BuildSkip();
    }
    /** An entry on top of `prev` (default: the last one added). Its hash commits to parent, version, bits and salt. */
    CBlockIndex* Add(bool qwen, uint32_t bits, CBlockIndex* prev = nullptr, uint32_t salt = 0)
    {
        if (!prev) prev = idx.back().get();
        auto b = std::make_unique<CBlockIndex>();
        b->pprev = prev;
        b->nHeight = prev->nHeight + 1;
        b->nBits = bits;
        b->nVersion = 4 | (c.nAuxpowChainId << 16) | (qwen ? LAUNCH_VERSION_QWEN : 0);
        b->nTime = prev->nTime + 5;
        b->nChainWork = prev->nChainWork + GetBlockProof(*b);
        HashWriter hw;
        hw << prev->GetBlockHash() << b->nVersion << b->nBits << salt;
        hashes.push_back(std::make_unique<uint256>(hw.GetHash()));
        b->phashBlock = hashes.back().get();
        b->BuildSkip();
        idx.push_back(std::move(b));
        return idx.back().get();
    }
};

/** The rules of TWIN.md section 3 with nothing remembered: walks the chain from the genesis block. */
struct Slow {
    arith_uint256 wb{0}, wq{0};
    bool graduated{false};
    int graduation_height{-1};
    bool by_qwen{false};
    arith_uint256 grad_wb{0}, grad_wq{0};
};
Slow SlowWalk(const CBlockIndex* tip, const Consensus::Params& c)
{
    std::vector<const CBlockIndex*> path;
    for (const CBlockIndex* p = tip; p && p->pprev; p = p->pprev) path.push_back(p);
    const arith_uint256 wg = UintToArith256(c.launch_graduation_work);
    Slow s;
    for (auto it = path.rbegin(); it != path.rend(); ++it) {
        const CBlockIndex* b = *it;
        const bool qwen = (b->nVersion & LAUNCH_VERSION_QWEN) && !s.graduated;
        (qwen ? s.wq : s.wb) += WorkOf(b->nBits);
        if (!s.graduated && (s.wb >= wg || s.wq >= wg)) {
            s.graduated = true;
            s.graduation_height = b->nHeight;
            s.by_qwen = qwen;
            s.grad_wb = s.wb;
            s.grad_wq = s.wq;
        }
    }
    return s;
}
CAmount SlowSupply(const arith_uint256& w, const Consensus::Params& c)
{
    const arith_uint256 v0 = UintToArith256(c.launch_virtual_work);
    const arith_uint256 s = arith_uint256{static_cast<uint64_t>(c.launch_virtual_tokens)} * w / (v0 + w);
    const arith_uint256 g{static_cast<uint64_t>(c.launch_graduation_tokens)};
    return static_cast<CAmount>((s < g ? s : g).GetLow64());
}

void CheckTip(Case& t, const CBlockIndex* tip, const Consensus::Params& c, const std::string& where)
{
    const Slow s = SlowWalk(tip, c);
    t.Expect(LaunchCurveWork(tip, LaunchCurve::QWEN, c) == s.wq, where + ": QWEN curve work");
    t.Expect(LaunchCurveWork(tip, LaunchCurve::BTC, c) == s.wb, where + ": BTC curve work");
    t.Equal(LaunchGraduatedAt(tip, c), s.graduated, where + ": graduated");
    t.Equal(LaunchGraduationHeight(tip, c), s.graduation_height, where + ": graduation height");
    const auto by = LaunchGraduatedBy(tip, c);
    t.Expect(by.has_value() == s.graduated && (!by || (*by == LaunchCurve::QWEN) == s.by_qwen), where + ": graduated by");
    const CAmount mb = SlowSupply(s.graduated ? s.grad_wb : s.wb, c), mq = SlowSupply(s.graduated ? s.grad_wq : s.wq, c);
    t.Equal(LaunchCurveMinted(tip, LaunchCurve::BTC, c), mb, where + ": BTC curve minted");
    t.Equal(LaunchCurveMinted(tip, LaunchCurve::QWEN, c), mq, where + ": QWEN curve minted");
    t.Equal(LaunchCurveMinted(tip, c), mb + mq, where + ": both curves minted");
}

/** Expected subsidy of a block with these bits and this curve bit on top of prev, the slow way. */
CAmount SlowSubsidy(const CBlockIndex* prev, uint32_t bits, bool qwen, int height, const Consensus::Params& c)
{
    const Slow s = SlowWalk(prev, c);
    if (s.graduated) return LaunchTailReward(height, c);
    const arith_uint256 w = qwen ? s.wq : s.wb;
    return SlowSupply(w + WorkOf(bits), c) - SlowSupply(w, c);
}

void TestCurves(Report& report)
{
    const auto params = MakeLaunch(LaunchSpec{});
    const Consensus::Params& c = params->GetConsensus();
    const arith_uint256 wg = UintToArith256(c.launch_graduation_work);
    const CAmount G = c.launch_graduation_tokens;
    const uint32_t bits_cycle[] = {0x207fffff, 0x203fffff, 0x207fffff, 0x201fffff}; // work 2, 4, 2, 8

    {
        Case t{report, "curves: W_g and the shape"};
        t.Expect(wg == arith_uint256{94}, "W_g = ceil(G * V0 / (T0 - G)) = 94 for V0 40, T0 1,000,000, G 700,000");
        t.Equal(SlowSupply(arith_uint256{94}, c), G, "S(W_g) is G");
        t.Expect(SlowSupply(arith_uint256{93}, c) < G, "S(W_g - 1) is below G");
        t.Equal(LaunchCurveSupply(arith_uint256{10}, c), CAmount{20000000000000}, "S(10) = T0 * 10 / 50");
    }
    for (const bool qwen_wins : {false, true}) {
        // Blocks alternate between the curves in an uneven pattern; the winning curve gets two of every three.
        LaunchCurveCacheClear();
        Chain chain{*params};
        Case t{report, strprintf("curves: interleaved blocks, graduation by the %s curve", qwen_wins ? "QWEN" : "BTC")};
        int n = 0, crossing = -1;
        CAmount crossing_subsidy = 0, crossing_left = 0;
        while (chain.idx.size() < 400 && !LaunchGraduatedAt(chain.idx.back().get(), c)) {
            const bool qwen = (n % 3 != 0) == qwen_wins;
            const uint32_t bits = bits_cycle[n % 4];
            const CBlockIndex* prev = chain.idx.back().get();
            const Slow before = SlowWalk(prev, c);
            const CAmount subsidy = LaunchSubsidy(prev, bits, qwen ? LAUNCH_VERSION_QWEN : 0, prev->nHeight + 1, c);
            t.Equal(subsidy, SlowSubsidy(prev, bits, qwen, prev->nHeight + 1, c), strprintf("block %d subsidy on its own curve", prev->nHeight + 1));
            // The same block on the other curve mints that curve's price, which is another number as soon as the curves differ.
            const CAmount other = LaunchSubsidy(prev, bits, qwen ? 0 : LAUNCH_VERSION_QWEN, prev->nHeight + 1, c);
            t.Equal(other, SlowSubsidy(prev, bits, !qwen, prev->nHeight + 1, c), strprintf("block %d subsidy had it been on the other curve", prev->nHeight + 1));
            t.Expect(LaunchCurveVersionOk(LAUNCH_VERSION_QWEN, prev, c), strprintf("block %d may be on the QWEN curve: its parent has not graduated", prev->nHeight + 1));
            const CBlockIndex* b = chain.Add(qwen, bits);
            const Slow after = SlowWalk(b, c);
            t.Expect((qwen ? after.wb : after.wq) == (qwen ? before.wb : before.wq), strprintf("block %d leaves the other curve's work alone", b->nHeight));
            if (after.graduated) {
                crossing = b->nHeight;
                crossing_subsidy = subsidy;
                crossing_left = G - SlowSupply(qwen ? before.wq : before.wb, c);
                t.Equal(qwen, qwen_wins, "the curve the crossing block is on");
            }
            CheckTip(t, b, c, strprintf("height %d", b->nHeight));
            ++n;
        }
        t.Expect(crossing > 0, "the chain graduated");
        t.Equal(crossing_subsidy, crossing_left, "the crossing block mints exactly what its curve had left");
        const CBlockIndex* grad = chain.idx.back().get();
        const CAmount minted_at_graduation = LaunchCurveMinted(grad, c);
        const CAmount winner = LaunchCurveMinted(grad, qwen_wins ? LaunchCurve::QWEN : LaunchCurve::BTC, c);
        const CAmount loser = LaunchCurveMinted(grad, qwen_wins ? LaunchCurve::BTC : LaunchCurve::QWEN, c);
        t.Equal(winner, G, "the curve that graduated the launch minted G");
        t.Expect(loser > 0 && loser < G, "the other curve minted part of its G, and the rest never");
        // After graduation: the tail, the bit refused, the curves standing still however much work follows.
        t.Expect(!LaunchCurveVersionOk(LAUNCH_VERSION_QWEN, grad, c), "the bit is refused on the block after graduation");
        t.Expect(LaunchCurveVersionOk(0, grad, c), "a block without the bit is fine after graduation");
        t.Expect(LaunchCurveVersionOk(0x100, grad, c), "the auxpow flag is not the curve bit");
        for (int i = 0; i < 200; ++i) {
            const CBlockIndex* prev = chain.idx.back().get();
            t.Equal(LaunchSubsidy(prev, 0x1f00ffff, 0, prev->nHeight + 1, c), LaunchTailReward(prev->nHeight + 1, c), "tail reward after graduation");
            // A header chain that breaks the rule (the bit after graduation) still mints the tail and moves no curve.
            t.Equal(LaunchSubsidy(prev, 0x1f00ffff, LAUNCH_VERSION_QWEN, prev->nHeight + 1, c), LaunchTailReward(prev->nHeight + 1, c), "tail reward whatever the bit says");
            const CBlockIndex* b = chain.Add(i % 5 == 0, 0x1f00ffff); // 65536 hashes a block: far more work than both curves took
            t.Expect(!LaunchCurveVersionOk(LAUNCH_VERSION_QWEN, b, c), "the bit stays refused");
            if (i % 20 == 0 || i == 199) CheckTip(t, b, c, strprintf("tail height %d", b->nHeight));
        }
        t.Equal(LaunchCurveMinted(chain.idx.back().get(), c), minted_at_graduation, "minted supply stands still after graduation");
        t.Equal(LaunchGraduationHeight(chain.idx.back().get(), c), crossing, "the graduation height is the crossing block's");
        // The same answers with nothing remembered, asked from the top down and for ancestors in any order.
        LaunchCurveCacheClear();
        CheckTip(t, chain.idx.back().get(), c, "the tip after forgetting everything");
        for (size_t i = chain.idx.size(); i-- > 1;) {
            if (i % 7 == 0) CheckTip(t, chain.idx[i].get(), c, strprintf("ancestor %d after forgetting everything", int(i)));
        }
    }
    {
        // A presale long enough for many remembered sums (one every 64 blocks), and two branches that
        // differ only in which curve their blocks are on.
        LaunchSpec spec;
        spec.virtual_work = "100000";
        const auto big = MakeLaunch(spec);
        const Consensus::Params& bc = big->GetConsensus();
        LaunchCurveCacheClear();
        Chain chain{*big};
        Case t{report, "curves: a long presale, and two branches from one block"};
        for (int i = 0; i < 700; ++i) chain.Add(i % 2 == 1, bits_cycle[i % 4]);
        CBlockIndex* fork = chain.idx[500].get();
        CheckTip(t, chain.idx.back().get(), bc, "the long chain's tip");
        CheckTip(t, fork, bc, "the block the branches leave from");
        CBlockIndex* a = fork;
        CBlockIndex* b = fork;
        for (int i = 0; i < 150; ++i) {
            a = chain.Add(true, 0x207fffff, a, 1);
            b = chain.Add(false, 0x207fffff, b, 2);
        }
        CheckTip(t, a, bc, "the branch on the QWEN curve");
        CheckTip(t, b, bc, "the branch on the BTC curve");
        t.Expect(LaunchCurveWork(a, LaunchCurve::QWEN, bc) == LaunchCurveWork(fork, LaunchCurve::QWEN, bc) + arith_uint256{300}, "150 QWEN blocks of 2 hashes add 300 to the QWEN curve");
        t.Expect(LaunchCurveWork(b, LaunchCurve::QWEN, bc) == LaunchCurveWork(fork, LaunchCurve::QWEN, bc), "150 BTC blocks add nothing to the QWEN curve");
        t.Expect(LaunchRelWork(a, bc) == LaunchRelWork(b, bc), "the two branches have the same total work");
        t.Expect(LaunchSubsidy(a, 0x207fffff, 0, a->nHeight + 1, bc) != LaunchSubsidy(b, 0x207fffff, 0, b->nHeight + 1, bc), "and different prices on the BTC curve");
        for (int i = 1; i <= 700; i += 37) CheckTip(t, chain.idx[i].get(), bc, strprintf("height %d", i));
    }
}

// ---- the header tree ---------------------------------------------------------------------------

CPureBlockHeader ParseHeader(const std::string& hex)
{
    CPureBlockHeader h;
    DataStream ss{ParseHex(hex)};
    ss >> h;
    return h;
}

/** A regtest chain of another network: headers mined on demand on top of the regtest genesis block. */
struct Regtest {
    std::vector<CPureBlockHeader> headers; //!< headers[0] is the anchor
    uint32_t salt;
    explicit Regtest(uint32_t s) : salt{s} { headers.push_back(ParseHeader(REGTEST_GENESIS)); }
    static CPureBlockHeader Mine(const uint256& prev, const uint256& merkle_root, uint32_t time)
    {
        CPureBlockHeader h;
        h.nVersion = 0x20000000;
        h.hashPrevBlock = prev;
        h.hashMerkleRoot = merkle_root;
        h.nTime = time;
        h.nBits = REGTEST_BITS;
        h.nNonce = 0;
        arith_uint256 target;
        target.SetCompact(REGTEST_BITS);
        while (UintToArith256(h.GetHash()) > target) ++h.nNonce;
        return h;
    }
    /** The next block, holding the transaction with this txid alone (or nothing in particular). */
    const CPureBlockHeader& Next(const uint256& merkle_root = uint256{})
    {
        uint256 root = merkle_root;
        if (root.IsNull()) {
            HashWriter hw;
            hw << salt << static_cast<uint32_t>(headers.size());
            root = hw.GetHash();
        }
        headers.push_back(Mine(headers.back().GetHash(), root, headers.back().nTime + 600));
        return headers.back();
    }
};

void TestRelay(Report& report)
{
    for (const bool qwen : {false, true}) {
        const char* who = qwen ? "qwen" : "btc";
        Case t{report, strprintf("relay: %s regtest rules", qwen ? "Qwencoin's" : "Bitcoin's")};
        HeaderChain tree;
        Regtest net{qwen ? 7u : 3u};
        tree.Init(net.headers[0], 0, 0, qwen ? HeaderChain::Rules::QWENCOIN : HeaderChain::Rules::BITCOIN, /*regtest=*/true);
        std::string err;
        for (int i = 0; i < 15; ++i) t.Expect(tree.Accept(net.Next(), err), strprintf("header %d accepted (%s)", i + 1, err));
        t.Equal(tree.BestHeight(), 15, "best height");
        t.Equal(tree.Confirmations(net.headers[1].GetHash()), 15, "confirmations of the first header");
        t.Expect(!tree.Accept(net.headers[5], err) && err == strprintf("%s header already known", who), "a known header: " + err);
        CPureBlockHeader stray = Regtest::Mine(uint256::ONE, uint256{}, net.headers.back().nTime + 600);
        t.Expect(!tree.Accept(stray, err) && err == strprintf("%s header does not connect", who), "an unconnected header: " + err);
        CPureBlockHeader hard = Regtest::Mine(net.headers.back().GetHash(), uint256{}, net.headers.back().nTime + 600);
        hard.nBits = 0x1d00ffff;
        t.Expect(!tree.Accept(hard, err) && err == strprintf("%s header has wrong difficulty", who), "other bits than regtest's: " + err);
        CPureBlockHeader weak = Regtest::Mine(net.headers.back().GetHash(), uint256::ONE, net.headers.back().nTime + 600);
        arith_uint256 target;
        target.SetCompact(REGTEST_BITS);
        while (UintToArith256(weak.GetHash()) <= target) ++weak.nNonce;
        t.Expect(!tree.Accept(weak, err) && err == strprintf("%s header lacks proof of work", who), "a hash over the target: " + err);
        CPureBlockHeader old = Regtest::Mine(net.headers.back().GetHash(), uint256::ONE, net.headers[net.headers.size() - 6].nTime);
        t.Expect(!tree.Accept(old, err) && err == strprintf("%s header time is not past the median", who), "a time at the median of the last eleven: " + err);
        // A branch with more work takes over; removing it gives the first chain back.
        const uint256 was_best = tree.Best();
        std::vector<CPureBlockHeader> branch;
        uint256 prev = net.headers[13].GetHash();
        for (int i = 0; i < 3; ++i) {
            branch.push_back(Regtest::Mine(prev, uint256{static_cast<uint8_t>(40 + i)}, net.headers.back().nTime + 900 + 600 * i));
            prev = branch.back().GetHash();
            t.Expect(tree.Accept(branch.back(), err), "branch header accepted: " + err);
        }
        t.Expect(tree.Best() == branch.back().GetHash() && tree.BestHeight() == 16, "the longer branch is the best chain");
        t.Equal(tree.Confirmations(net.headers[15].GetHash()), 0, "a header off the best chain has no confirmations");
        for (auto it = branch.rbegin(); it != branch.rend(); ++it) tree.Remove(it->GetHash());
        t.Expect(tree.Best() == was_best && tree.BestHeight() == 15, "removing the branch restores the first chain");
    }
    {
        Case t{report, "relay: the limit of work checks per launch block"};
        HeaderChain tree;
        Regtest net{11};
        tree.Init(net.headers[0], 0, 0, HeaderChain::Rules::QWENCOIN, /*regtest=*/true);
        std::string err;
        t.Expect(tree.Accept(net.Next(), err), "a first header, outside any limit");
        int budget = launchyield::QWEN_PASSES_PER_BLOCK;
        t.Equal(budget, 8, "the limit");
        // What does not get as far as the work check costs nothing.
        t.Expect(!tree.Accept(net.headers[1], err, &budget) && budget == 8, "a known header takes nothing from the budget");
        CPureBlockHeader stray = Regtest::Mine(uint256::ONE, uint256{}, 1);
        t.Expect(!tree.Accept(stray, err, &budget) && budget == 8, "an unconnected header takes nothing");
        CPureBlockHeader hard = Regtest::Mine(net.headers.back().GetHash(), uint256{}, net.headers.back().nTime + 600);
        hard.nBits = 0x1d00ffff;
        t.Expect(!tree.Accept(hard, err, &budget) && budget == 8, "a header with wrong bits takes nothing");
        // What does, costs one, accepted or not.
        CPureBlockHeader weak = Regtest::Mine(net.headers.back().GetHash(), uint256::ONE, net.headers.back().nTime + 600);
        arith_uint256 target;
        target.SetCompact(REGTEST_BITS);
        while (UintToArith256(weak.GetHash()) <= target) ++weak.nNonce;
        t.Expect(!tree.Accept(weak, err, &budget) && budget == 7, "a header that fails its work check takes one");
        int accepted = 0;
        std::vector<CPureBlockHeader> ten;
        for (int i = 0; i < 10; ++i) ten.push_back(net.Next());
        std::vector<std::string> errors;
        for (const auto& h : ten) {
            accepted += tree.Accept(h, err, &budget);
            errors.push_back(err);
        }
        t.Equal(accepted, 7, "seven more accepted: eight work checks in all");
        t.Equal(budget, 0, "nothing left");
        t.Expect(errors[7] == "qwen header not looked at: this block has had its share of work checks", "the ninth is not looked at: " + errors[7]);
        t.Expect(errors[8] == "qwen header does not connect", "what follows it has nothing to connect to: " + errors[8]);
        t.Equal(tree.BestHeight(), 8, "best height after the limited block");
        budget = 8; // the next launch block
        accepted = 0;
        for (const auto& h : ten) accepted += tree.Accept(h, err, &budget);
        t.Equal(accepted, 3, "the next block takes the rest");
        t.Equal(budget, 5, "at one check each (the seven already known cost nothing)");
        t.Equal(tree.BestHeight(), 11, "best height");
    }
}

// ---- the state ---------------------------------------------------------------------------------

std::vector<unsigned char> Bytes(const DataStream& ss)
{
    std::vector<unsigned char> out(ss.size());
    if (!out.empty()) std::memcpy(out.data(), ss.data(), ss.size());
    return out;
}

CScript Data(const std::vector<unsigned char>& payload) { return CScript() << OP_RETURN << payload; }

std::vector<unsigned char> HeadersPayload(const char* tag, const std::vector<CPureBlockHeader>& headers)
{
    DataStream ss;
    for (const auto& h : headers) ss << h;
    std::vector<unsigned char> out(tag, tag + 4);
    const auto body = Bytes(ss);
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

/** A payment on a quote chain: output 0 pays, and the tag list binds output 0 to one mint block. */
struct Payment {
    std::vector<unsigned char> raw;
    uint256 txid;
};
Payment Pay(const std::vector<unsigned char>& script, CAmount amount, const std::array<unsigned char, 20>& tag, uint32_t salt)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256{static_cast<uint8_t>(salt + 1)}), salt};
    tx.vout.emplace_back(amount, CScript(script.begin(), script.end()));
    std::vector<unsigned char> tags{'H', 'F'};
    tags.insert(tags.end(), tag.begin(), tag.end());
    tx.vout.emplace_back(0, Data(tags));
    DataStream ss;
    ss << TX_NO_WITNESS(tx);
    Payment p;
    p.raw = Bytes(ss);
    p.txid = Hash(p.raw);
    return p;
}

std::vector<unsigned char> ProofPayload(const char* tag, uint32_t mint_height, const uint256& block, const Payment& payment, uint8_t candidate = 0)
{
    std::vector<unsigned char> out(tag, tag + 4);
    const auto le32 = [&](uint32_t x) { for (int i = 0; i < 4; ++i) out.push_back((x >> (8 * i)) & 0xff); };
    le32(mint_height);
    out.insert(out.end(), block.begin(), block.end());
    le32(0);          // the transaction's index in its block
    out.push_back(0); // no branch: the block holds this transaction alone
    le32(0);          // the paying output
    out.push_back(candidate);
    out.insert(out.end(), payment.raw.begin(), payment.raw.end());
    return out;
}

/** A launch chain as the state sees one: blocks, their index entries and the state itself. */
struct Sim {
    std::unique_ptr<const CChainParams> params;
    const Consensus::Params& c;
    LaunchYieldState ys;
    std::vector<std::unique_ptr<CBlockIndex>> idx;
    std::vector<std::unique_ptr<uint256>> hashes;
    std::vector<CBlock> blocks;

    explicit Sim(const LaunchSpec& spec) : params{MakeLaunch(spec)}, c{params->GetConsensus()}
    {
        LaunchCurveCacheClear();
        Push(params->GenesisBlock());
    }
    void Push(const CBlock& block)
    {
        auto b = std::make_unique<CBlockIndex>(block);
        hashes.push_back(std::make_unique<uint256>(block.GetHash()));
        b->phashBlock = hashes.back().get();
        b->pprev = idx.empty() ? nullptr : idx.back().get();
        b->nHeight = b->pprev ? b->pprev->nHeight + 1 : 0;
        b->nChainWork = (b->pprev ? b->pprev->nChainWork : arith_uint256{0}) + GetBlockProof(*b);
        b->BuildSkip();
        idx.push_back(std::move(b));
        blocks.push_back(block);
        ys.Connect(block, idx.back().get(), c);
    }
    void Pop()
    {
        ys.Disconnect(idx.back().get());
        idx.pop_back();
        hashes.pop_back();
        blocks.pop_back();
    }
    int Height() const { return idx.back()->nHeight; }
    static std::vector<unsigned char> MinerScript(int height)
    {
        std::vector<unsigned char> s{0x00, 0x14};
        s.insert(s.end(), 20, static_cast<unsigned char>(height));
        return s;
    }
    /** The block at the next height: on a curve, with these extra coinbase outputs, not yet connected. */
    CBlock Build(bool qwen, const std::vector<CScript>& extra = {}) const
    {
        const int height = Height() + 1;
        CMutableTransaction cb;
        cb.vin.resize(1);
        cb.vin[0].prevout.SetNull();
        cb.vin[0].scriptSig = CScript() << height << LaunchCoinbaseTag(c);
        const auto miner = MinerScript(height);
        cb.vout.emplace_back(50 * COIN + height, CScript(miner.begin(), miner.end()));
        for (const CScript& s : extra) cb.vout.emplace_back(0, s);
        CBlock block;
        block.nVersion = 4 | (c.nAuxpowChainId << 16) | (qwen ? LAUNCH_VERSION_QWEN : 0);
        block.hashPrevBlock = idx.back()->GetBlockHash();
        block.nTime = idx.back()->nTime + 5;
        block.nBits = REGTEST_BITS; // 2 hashes of work
        block.nNonce = 0;
        block.vtx.push_back(MakeTransactionRef(std::move(cb)));
        block.hashMerkleRoot = block.vtx[0]->GetHash().ToUint256();
        return block;
    }
    /**
     * Connect the next block, with its nonce chosen so that the draw it makes (of the block six
     * below) names this payee class and, when asked, pays something. Nothing checks a block's own
     * work here, so any nonce is a block.
     */
    void Mine(bool qwen, const std::vector<CScript>& extra = {}, std::optional<launchyield::Payee> want = std::nullopt, bool want_pay = true)
    {
        CBlock block = Build(qwen, extra);
        const int drawn = Height() + 1 - launchyield::DRAW_DELAY;
        if (want && drawn >= 1) {
            const LaunchYieldState::Info* d = ys.At(drawn);
            const CAmount min = d->quote == LaunchCurve::QWEN ? c.launch_qwen_min_payment : c.launch_sats_min_payment;
            for (;; ++block.nNonce) {
                const launchyield::Draw draw = launchyield::ComputeDraw(d->owed, min, launchyield::DrawSeed(c.launch_id, block.GetHash()));
                if (draw.payee == *want && (draw.pay > 0) == want_pay) break;
            }
        }
        Push(block);
    }
    /** Everything the state says, as text: two states are the same state when this is. */
    std::string Print() const
    {
        std::string out = strprintf("height %d earning %d coins %d closed %d btc %s/%d/%d qwen %s/%d/%d count %d,%d %d,%d\n", ys.Height(), ys.Earning(c),
                                    int(ys.Coins()), ys.Closed(c), ys.Btc().Best().GetHex(), ys.Btc().BestHeight(), int(ys.Btc().Size()),
                                    ys.Qwen().Best().GetHex(), ys.Qwen().BestHeight(), int(ys.Qwen().Size()), ys.Count(LaunchCurve::BTC).blocks,
                                    ys.Count(LaunchCurve::BTC).last_height, ys.Count(LaunchCurve::QWEN).blocks, ys.Count(LaunchCurve::QWEN).last_height);
        for (int h = 0; h <= ys.Height(); ++h) {
            const LaunchYieldState::Info& i = *ys.At(h);
            out += strprintf("%d %s curve %d quote %d owed %d draw %d pay %d payee %d seed %s script %s coin %d %s:%d %d earning %d settled %d released %d spendable %d\n",
                             h, i.hash.GetHex(), i.curve, int(i.quote), i.owed, i.draw_known, i.pay, int(i.payee), i.seed.GetHex(), HexStr(i.pay_script),
                             i.has_coin, i.coin.hash.GetHex(), i.coin.n, i.coin_value, i.earning, i.settled, i.released, ys.Spendable(h));
        }
        return out;
    }
};

/** A header on top of `prev` whose own hash meets `bits`: what counts as work under the stand-in below. */
CPureBlockHeader MineBits(const uint256& prev, uint32_t time, uint32_t bits, uint32_t salt = 0)
{
    CPureBlockHeader h;
    h.nVersion = 0x20000000;
    h.hashPrevBlock = prev;
    HashWriter hw;
    hw << salt << time << bits;
    h.hashMerkleRoot = hw.GetHash();
    h.nTime = time;
    h.nBits = bits;
    h.nNonce = 0;
    arith_uint256 target;
    target.SetCompact(bits);
    while (UintToArith256(h.GetHash()) > target) ++h.nNonce;
    return h;
}

/**
 * Qwencoin's main-network rules on chains made for the purpose. The pass through the weights is
 * replaced by the header's own hash (launchyield::SetQwenWorkForTests), so every other rule of the
 * tree is exercised here with no table: the limit, the retarget (expected values computed
 * independently, with unbounded integers), and the two timestamp rules at the edges of a period.
 */
void TestQwenRules(Report& report)
{
    launchyield::SetQwenWorkForTests(+[](const CPureBlockHeader& h) { return h.GetHash(); });
    const int64_t T = 14 * 24 * 3600;
    {
        Case t{report, "relay: Qwencoin's retarget on made-up chains"};
        struct Retarget {
            uint32_t bits;
            int64_t span;
            uint32_t next;
        };
        // (bits of the closing period, its length in seconds) -> bits of the next period, as
        // min(limit, target * clamp(span, T/4, 4T) // T) says in arbitrary-precision arithmetic.
        const Retarget cases[] = {
            {0x2000ffff, 100000, 0x1f3fffc0},  // a fast first period: the clamp to a quarter (the real chain's first retarget)
            {0x1f3fffc0, 1000000, 0x1f34e8c4}, // an ordinary one; target * span does not fit in 256 bits here
            {0x1f3fffc0, 5 * T, 0x2000ffff},   // a slow one: times four, which is the limit exactly
            {0x2000ffff, 5 * T, 0x2000ffff},   // at the limit already: capped
            {0x1f0ffff0, 777777, 0x1f0a49b3},
            {0x1f03fffc, T + 12345, 0x1f040a6f},
        };
        int n = 0;
        for (const Retarget& r : cases) {
            ++n;
            const uint32_t opened = 1800000000;                          // when the period opened
            const uint32_t closes = opened + static_cast<uint32_t>(r.span); // the time of its last block
            HeaderChain tree;
            const CPureBlockHeader anchor = MineBits(uint256{}, closes - 600, r.bits, n);
            tree.Init(anchor, 2014, opened, HeaderChain::Rules::QWENCOIN, /*regtest=*/false);
            std::string err;
            const CPureBlockHeader last = MineBits(anchor.GetHash(), closes, r.bits, n);
            t.Expect(tree.Accept(last, err), strprintf("case %d: the last block of the period (%s)", n, err));
            if (r.next != r.bits) {
                const CPureBlockHeader stale = MineBits(last.GetHash(), closes + 600, r.bits, n);
                t.Expect(!tree.Accept(stale, err) && err == "qwen header has wrong difficulty", strprintf("case %d: the old bits after the retarget: %s", n, err));
            }
            const CPureBlockHeader first = MineBits(last.GetHash(), closes + 600, r.next, n);
            t.Expect(tree.Accept(first, err), strprintf("case %d: bits %08x open the next period (%s)", n, r.next, err));
            const CPureBlockHeader second = MineBits(first.GetHash(), closes + 1200, r.next, n);
            t.Expect(tree.Accept(second, err), strprintf("case %d: and stay (%s)", n, err));
            t.Equal(tree.BestHeight(), 2017, strprintf("case %d: best height", n));
        }
        // Easier than the limit is never a Qwencoin header, whatever a retarget would say.
        HeaderChain tree;
        const CPureBlockHeader anchor = MineBits(uint256{}, 1800000000, 0x2000ffff, 99);
        tree.Init(anchor, 10, 1800000000 - 6000, HeaderChain::Rules::QWENCOIN, /*regtest=*/false);
        std::string err;
        t.Expect(!tree.Accept(MineBits(anchor.GetHash(), 1800000600, 0x207fffff, 99), err) && err == "qwen header has wrong difficulty", "regtest bits on the main network: " + err);
        CPureBlockHeader weak = MineBits(anchor.GetHash(), 1800000600, 0x2000ffff, 99);
        arith_uint256 target;
        target.SetCompact(0x2000ffff);
        while (UintToArith256(weak.GetHash()) <= target) ++weak.nNonce;
        t.Expect(!tree.Accept(weak, err) && err == "qwen header lacks proof of work", "a value over the target: " + err);
    }
    {
        Case t{report, "relay: Qwencoin's two timestamp rules at the edges of a period"};
        const uint32_t opened = 1800000000, bits = 0x2000ffff, next_bits = 0x1f3fffc0;
        const uint32_t closes = opened + 100000;
        HeaderChain tree;
        const CPureBlockHeader anchor = MineBits(uint256{}, closes - 600, bits, 7);
        tree.Init(anchor, 2014, opened, HeaderChain::Rules::QWENCOIN, /*regtest=*/false);
        std::string err;
        // The last block of a period is not stamped before the period's first.
        t.Expect(!tree.Accept(MineBits(anchor.GetHash(), opened - 1, bits, 7), err) && err == "qwen header closes a difficulty period before the time the period opened",
                 "the last block one second before the period opened: " + err);
        t.Expect(tree.Accept(MineBits(anchor.GetHash(), opened, bits, 8), err), "the last block at the very second the period opened is taken (" + err + ")");
        const CPureBlockHeader last = MineBits(anchor.GetHash(), closes, bits, 7);
        t.Expect(tree.Accept(last, err), "the last block (" + err + ")");
        // The first block of a period is not stamped more than ten minutes before its parent.
        t.Expect(!tree.Accept(MineBits(last.GetHash(), closes - 601, next_bits, 7), err) && err == "qwen header opens a difficulty period too long before its parent's time",
                 "the first block 601 s before its parent: " + err);
        t.Expect(tree.Accept(MineBits(last.GetHash(), closes - 600, next_bits, 7), err), "600 s before its parent is taken (" + err + ")");
        // Inside a period neither rule speaks: a block may be stamped well before its parent (the
        // median rule has too few timestamps to speak here).
        const CPureBlockHeader first = MineBits(last.GetHash(), closes + 600, next_bits, 9);
        t.Expect(tree.Accept(first, err), "the first block (" + err + ")");
        t.Expect(tree.Accept(MineBits(first.GetHash(), closes - 5000, next_bits, 9), err), "a block inside the period stamped before its parent is taken (" + err + ")");
        // A regtest Qwencoin is not followed this closely, and Bitcoin has neither rule.
        HeaderChain reg;
        Regtest net{31};
        reg.Init(net.headers[0], 2014, net.headers[0].nTime + 100000, HeaderChain::Rules::QWENCOIN, /*regtest=*/true);
        t.Expect(reg.Accept(net.Next(), err), "regtest: a period's last block stamped before the period's start is taken (" + err + ")");
        t.Expect(reg.Accept(Regtest::Mine(net.headers.back().GetHash(), uint256::ONE, net.headers.back().nTime - 5000), err),
                 "regtest: a period's first block stamped long before its parent is taken (" + err + ")");
    }
    launchyield::SetQwenWorkForTests(nullptr);
}

void TestState(Report& report)
{
    using launchyield::Payee;
    Sim sim{LaunchSpec{}};
    const Consensus::Params& c = sim.c;
    const std::vector<unsigned char> dev = c.launch_dev_btc_script;
    Regtest btc{21}, qwen{22}; // two different regtest networks on the same genesis block
    std::vector<std::string> undo_failures;
    int undo_checks = 0;
    // Every block from here on is also taken off again and put back: the state must come back, and return, to the letter.
    const auto mine = [&](bool on_qwen, const std::vector<CScript>& extra = {}, std::optional<Payee> want = std::nullopt, bool want_pay = true) {
        const std::string before = sim.Print();
        sim.Mine(on_qwen, extra, want, want_pay);
        const std::string after = sim.Print();
        const CBlock block = sim.blocks.back();
        sim.Pop();
        ++undo_checks;
        if (sim.Print() != before) undo_failures.push_back(strprintf("disconnecting block %d does not restore the state", sim.Height() + 1));
        sim.Push(block);
        if (sim.Print() != after) undo_failures.push_back(strprintf("connecting block %d again gives another state", sim.Height()));
    };

    {
        Case t{report, "state: what a block owes, by its curve"};
        for (int h = 1; h <= 6; ++h) mine(h % 2 == 0); // odd heights on the BTC curve, even ones on the QWEN curve
        for (int h = 1; h <= 6; ++h) {
            const LaunchYieldState::Info& i = *sim.ys.At(h);
            const bool q = h % 2 == 0;
            t.Expect(i.curve, strprintf("block %d is a curve block", h));
            t.Expect((i.quote == LaunchCurve::QWEN) == q, strprintf("block %d quote", h));
            t.Equal(i.owed, CAmount{q ? 14000 : 10000}, strprintf("block %d owes 2 hashes at its curve's rate (5000 sats or 7000 qwen a hash)", h));
            t.Expect(!sim.ys.Spendable(h), strprintf("block %d's coinbase is held", h));
        }
        t.Equal(sim.ys.Count(LaunchCurve::BTC).blocks, 3, "blocks on the BTC curve");
        t.Equal(sim.ys.Count(LaunchCurve::QWEN).blocks, 3, "blocks on the QWEN curve");
        t.Equal(sim.ys.Count(LaunchCurve::BTC).last_height, 5, "latest block on the BTC curve");
        t.Equal(sim.ys.Count(LaunchCurve::QWEN).last_height, 6, "latest block on the QWEN curve");
        t.Equal(sim.ys.Earning(c), CAmount{0}, "nothing earns while every coinbase is held");
    }
    {
        Case t{report, "state: the payee's script, by the block's curve"};
        mine(false, {}, Payee::CREATOR); // 7 draws 1 (BTC)
        mine(true, {}, Payee::CREATOR);  // 8 draws 2 (QWEN)
        mine(false, {}, Payee::DEV);     // 9 draws 3 (BTC)
        mine(true, {}, Payee::DEV);      // 10 draws 4 (QWEN)
        mine(false, {}, Payee::HOLDER, /*want_pay=*/true); // 11 draws 5 (BTC): a holder, and nobody holds yet
        t.Expect(sim.ys.At(1)->pay_script == c.launch_creator_btc_script && sim.ys.At(1)->pay == 10000, "block 1 (BTC curve): 10000 sats to the creator's Bitcoin script");
        t.Expect(sim.ys.At(2)->pay_script == c.launch_creator_qwen_script && sim.ys.At(2)->pay == 14000, "block 2 (QWEN curve): 14000 qwen to the creator's Qwencoin script");
        t.Expect(sim.ys.At(3)->pay_script == dev && sim.ys.At(3)->pay == 10000, "block 3 (BTC curve): the dev's script");
        t.Expect(sim.ys.At(4)->pay_script == dev && sim.ys.At(4)->pay == 14000, "block 4 (QWEN curve): the same dev script");
        t.Expect(sim.ys.At(5)->draw_known && sim.ys.At(5)->pay == 0 && sim.ys.Spendable(5), "block 5: a holder's share with nobody holding is owed to no one, and its coinbase is free");
        t.Equal(sim.ys.Earning(c), CAmount{50 * COIN + 5}, "block 5's coinbase earns from here on");
        mine(true, {}, Payee::HOLDER); // 12 draws 6 (QWEN): the only live coin is block 5's coinbase
        const LaunchYieldState::Info& six = *sim.ys.At(6);
        t.Expect(six.has_coin && six.pay == 14000 && six.pay_script == Sim::MinerScript(5), "block 6 (QWEN curve): 14000 qwen to the holder's own script, the same script it has on the launch");
        t.Expect(six.coin == COutPoint{sim.blocks[5].vtx[0]->GetHash(), 0}, "the coin that won is block 5's coinbase output");
    }
    const auto tag = [&](int h) { return launchyield::PayTag(c.launch_id, sim.idx[h]->GetBlockHash()); };
    {
        Case t{report, "state: a block is settled on its own chain and on no other"};
        // The four payments, each made on both chains: in its own block of the Bitcoin regtest network and of the Qwencoin one.
        const Payment pay1 = Pay(c.launch_creator_btc_script, 10000, tag(1), 1);  // block 1 owes sats
        const Payment pay2 = Pay(c.launch_creator_qwen_script, 14000, tag(2), 2); // block 2 owes qwen
        const CPureBlockHeader b_pay1 = btc.Next(pay1.txid), b_pay2 = btc.Next(pay2.txid);
        const CPureBlockHeader q_pay2 = qwen.Next(pay2.txid), q_pay1 = qwen.Next(pay1.txid);
        // Block 13 relays the Bitcoin headers, and the first Qwencoin one only: one confirmation, where qwen_confs is 2.
        mine(false, {Data(HeadersPayload("HFH1", {b_pay1, b_pay2})), Data(HeadersPayload("HFH2", {q_pay2}))});
        t.Equal(sim.ys.Btc().BestHeight(), 2, "Bitcoin relay height");
        t.Equal(sim.ys.Qwen().BestHeight(), 1, "Qwencoin relay height");
        t.Equal(sim.ys.Qwen().Confirmations(q_pay2.GetHash()), 1, "the Qwencoin payment has one confirmation");
        // Block 14: a right proof with too few confirmations, and the wrong-chain proofs.
        mine(true, {Data(ProofPayload("HFP2", 2, q_pay2.GetHash(), pay2)),    // right chain, one confirmation short
                    Data(ProofPayload("HFP1", 2, q_pay2.GetHash(), pay2)),    // a Bitcoin proof naming a Qwencoin block
                    Data(ProofPayload("HFP1", 2, b_pay2.GetHash(), pay2)),    // the qwen debt "paid" on Bitcoin: a real, confirmed, tagged payment there
                    Data(ProofPayload("HFP2", 1, b_pay1.GetHash(), pay1))});  // a Qwencoin proof naming a Bitcoin block
        t.Expect(!sim.ys.At(2)->settled, "block 2 (owes qwen) is not settled by one confirmation, by a Bitcoin proof, or by the same payment made on Bitcoin");
        t.Expect(!sim.ys.At(1)->settled, "block 1 (owes sats) is not settled by a Qwencoin proof naming a Bitcoin block");
        // Block 15 relays the rest of the Qwencoin chain: the payment of block 2 gets its confirmations, and
        // the sats debt of block 1, "paid" on Qwencoin, gets the two a Qwencoin proof needs as well.
        const CPureBlockHeader q_more = qwen.Next();
        mine(false, {Data(HeadersPayload("HFH2", {q_pay1, q_more}))});
        t.Equal(sim.ys.Qwen().Confirmations(q_pay2.GetHash()), 3, "three confirmations now");
        t.Equal(sim.ys.Qwen().Confirmations(q_pay1.GetHash()), 2, "and two on the sats payment made on Qwencoin");
        mine(true, {Data(ProofPayload("HFP2", 1, q_pay1.GetHash(), pay1))}); // 16: the sats debt "paid" on Qwencoin, confirmed there
        t.Expect(!sim.ys.At(1)->settled, "block 1 (owes sats) is not settled by the same payment made on Qwencoin");
        t.Expect(!sim.ys.Spendable(1) && !sim.ys.Spendable(2), "both coinbases are still held");
        const CAmount earning_before = sim.ys.Earning(c);
        // Block 17: each proof on its own chain.
        mine(false, {Data(ProofPayload("HFP1", 1, b_pay1.GetHash(), pay1)), Data(ProofPayload("HFP2", 2, q_pay2.GetHash(), pay2))});
        t.Expect(sim.ys.At(1)->settled && sim.ys.Spendable(1), "block 1 is settled by the Bitcoin proof of the sats payment");
        t.Expect(sim.ys.At(2)->settled && sim.ys.Spendable(2), "block 2 is settled by the Qwencoin proof of the qwen payment");
        t.Equal(sim.ys.Earning(c), earning_before + (50 * COIN + 1) + (50 * COIN + 2), "the two settled coinbases earn from here on");
    }
    {
        Case t{report, "state: the pass limit across one block's outputs"};
        const int before = sim.ys.Qwen().BestHeight();
        std::vector<CPureBlockHeader> ten;
        for (int i = 0; i < 10; ++i) ten.push_back(qwen.Next());
        const CPureBlockHeader stray = Regtest::Mine(uint256::ONE, uint256{}, 5);
        // Two outputs, with a known header and an unconnected one first: neither costs a check.
        mine(true, {Data(HeadersPayload("HFH2", {qwen.headers[1], stray, ten[0], ten[1], ten[2], ten[3], ten[4], ten[5]})),
                    Data(HeadersPayload("HFH2", {ten[6], ten[7], ten[8], ten[9]}))});
        t.Equal(sim.ys.Qwen().BestHeight(), before + 8, "eight Qwencoin headers of ten are taken from one block");
        mine(false, {Data(HeadersPayload("HFH2", ten))});
        t.Equal(sim.ys.Qwen().BestHeight(), before + 10, "the next block takes the other two");
        // The Bitcoin relay has no such limit: its work check is a hash.
        std::vector<CPureBlockHeader> twenty;
        for (int i = 0; i < 20; ++i) twenty.push_back(btc.Next());
        const int btc_before = sim.ys.Btc().BestHeight();
        mine(true, {Data(HeadersPayload("HFH1", twenty))});
        t.Equal(sim.ys.Btc().BestHeight(), btc_before + 20, "twenty Bitcoin headers in one block");
    }
    {
        Case t{report, "state: every block taken off and put back"};
        t.note = strprintf("%d blocks disconnected and connected again one by one, then all %d at once", undo_checks, sim.Height());
        t.Expect(undo_checks > 15, strprintf("%d blocks disconnected and connected again", undo_checks));
        for (const auto& f : undo_failures) t.Expect(false, f);
        // And all of them at once: down to the genesis block and back up.
        const std::string top = sim.Print();
        std::vector<CBlock> blocks(sim.blocks.begin() + 1, sim.blocks.end());
        while (sim.Height() > 0) sim.Pop();
        t.Equal(sim.ys.Earning(c), CAmount{0}, "nothing earns at the genesis block");
        t.Equal(sim.ys.Count(LaunchCurve::BTC).blocks + sim.ys.Count(LaunchCurve::QWEN).blocks, 0, "no curve blocks at the genesis block");
        t.Expect(sim.ys.Qwen().Size() == 1 && sim.ys.Btc().Size() == 1, "both relays are back at their anchors");
        for (const CBlock& b : blocks) sim.Push(b);
        t.Expect(sim.Print() == top, "replaying the chain from the genesis block gives the same state");
    }
    {
        // The minimum payment is the curve's own: a debt under it is drawn up to it or down to nothing.
        LaunchSpec spec;
        spec.virtual_work = "4000"; // W_g = 9334 hashes: no graduation in the 126 blocks below
        spec.sats_min = 50000;      // a BTC-curve block owes 10000 sats
        spec.qwen_min = 28000;      // a QWEN-curve block owes 14000 qwen
        Sim lot{spec};
        Case t{report, "state: the minimum payment, by the block's curve"};
        for (int h = 1; h <= 126; ++h) lot.Mine(h % 2 == 0);
        int paid[2] = {0, 0}, nothing[2] = {0, 0};
        for (int h = 1; h <= 120; ++h) {
            const LaunchYieldState::Info& i = *lot.ys.At(h);
            const bool q = h % 2 == 0;
            const CAmount min = q ? 28000 : 50000;
            const launchyield::Draw draw = launchyield::ComputeDraw(i.owed, min, i.seed);
            t.Expect(i.draw_known, strprintf("block %d has its draw", h));
            // A holder's share with nobody holding is owed to no one; otherwise the draw's own amount.
            t.Expect(i.pay == draw.pay || (i.pay == 0 && draw.payee == Payee::HOLDER && i.earning == 0), strprintf("block %d pays what a draw with its own curve's minimum says", h));
            t.Expect(draw.pay == 0 || draw.pay == min, strprintf("block %d: the minimum of its curve or nothing", h));
            ++(draw.pay > 0 ? paid : nothing)[q];
        }
        t.Expect(paid[0] > 0 && nothing[0] > paid[0], strprintf("BTC curve: %d of 60 draws pay 50000 sats (one in five expected)", paid[0]));
        t.Expect(paid[1] > 10 && nothing[1] > 10, strprintf("QWEN curve: %d of 60 draws pay 28000 qwen (one in two expected)", paid[1]));
    }
    {
        Case t{report, "state: Qwencoin headers count in the coinbase only"};
        const int q_before = sim.ys.Qwen().BestHeight(), b_before = sim.ys.Btc().BestHeight();
        const CPureBlockHeader q = qwen.Next(), b = btc.Next();
        CBlock block = sim.Build(true);
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
        tx.vout.emplace_back(0, Data(HeadersPayload("HFH2", {q})));
        tx.vout.emplace_back(0, Data(HeadersPayload("HFH1", {b})));
        block.vtx.push_back(MakeTransactionRef(std::move(tx)));
        block.hashMerkleRoot = BlockMerkleRoot(block);
        const std::string before = sim.Print();
        sim.Push(block);
        t.Equal(sim.ys.Qwen().BestHeight(), q_before, "a Qwencoin header in a transaction that is not the coinbase is not looked at");
        t.Equal(sim.ys.Btc().BestHeight(), b_before + 1, "a Bitcoin header in the same transaction is taken");
        sim.Pop();
        t.Expect(sim.Print() == before, "taking that block off restores the state");
        sim.Push(block);
        mine(false, {Data(HeadersPayload("HFH2", {q}))});
        t.Equal(sim.ys.Qwen().BestHeight(), q_before + 1, "the same header in the next block's coinbase is taken");
    }
    {
        // Graduation by the QWEN curve: 47 blocks of 2 hashes on it reach W_g = 94 while the BTC curve has a few.
        Sim grad{LaunchSpec{}};
        Case t{report, "state: after graduation nothing is on a curve"};
        int h = 0;
        while (!LaunchGraduatedAt(grad.idx.back().get(), grad.c)) {
            ++h;
            grad.Mine(h % 4 != 0);
        }
        const int g = grad.Height();
        t.Expect(grad.ys.At(g)->curve && grad.ys.At(g)->quote == LaunchCurve::QWEN, "the crossing block is a curve block on the QWEN curve");
        t.Expect(LaunchGraduatedBy(grad.idx.back().get(), grad.c) == LaunchCurve::QWEN, "graduated by the QWEN curve");
        for (int i = 0; i < 5; ++i) grad.Mine(false);
        t.Expect(!grad.ys.At(g + 1)->curve && grad.ys.At(g + 1)->owed == 0 && grad.ys.Spendable(g + 1), "the block after it owes nothing and its coinbase is free");
        t.Equal(grad.ys.Count(LaunchCurve::QWEN).last_height, g, "the QWEN curve's latest block is the crossing block");
        t.Equal(grad.ys.Count(LaunchCurve::QWEN).blocks + grad.ys.Count(LaunchCurve::BTC).blocks, g, "every block up to graduation was on one of the curves");
        t.Equal(grad.ys.Count(LaunchCurve::BTC).blocks, g / 4, "one block in four was on the BTC curve");
    }
}

// ---- Qwencoin's real work function -------------------------------------------------------------

struct Vector {
    int height;
    CPureBlockHeader header;
    std::string hash, work;
};

void TestTable(Report& report, const std::string& table, const std::string& vectors_path)
{
    if (table.empty()) {
        report.Add("table: Qwencoin's work function on its real table", true, "QWORK_TABLE is not set", /*skipped=*/true);
        report.Add("vectors: real Qwencoin headers", true, "QWORK_TABLE is not set", /*skipped=*/true);
        return;
    }
    {
        Case t{report, "table: what is not the table is refused"};
        const std::string missing = launchyield::LoadQworkTable(table + ".absent");
        t.Expect(missing.find("cannot be opened") != std::string::npos, "a missing file: " + missing);
        const std::string junk_path = table + ".selftest-junk";
        {
            std::ofstream f(junk_path, std::ios::binary);
            f << "QWRK1 this is not a table of weights, only its first word";
        }
        const std::string junk = launchyield::LoadQworkTable(junk_path);
        t.Expect(junk.find("is not a work table") != std::string::npos, "a file that is not one: " + junk);
        {
            // A well-formed table of another shape: 1 layer of 64 x 64.
            std::ofstream f(junk_path, std::ios::binary | std::ios::trunc);
            const unsigned char head[24] = {'Q', 'W', 'R', 'K', '1', 0, 0, 0, 1, 0, 0, 0, 64, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0};
            f.write(reinterpret_cast<const char*>(head), 24);
            const std::vector<char> body(3 * 64 * 64 * 2, 1);
            f.write(body.data(), body.size());
        }
        const std::string small = launchyield::LoadQworkTable(junk_path);
        t.Expect(small.find("holds 1 layers of 64 x 64") != std::string::npos, "a table of another shape: " + small);
        std::remove(junk_path.c_str());
        t.Expect(!launchyield::QworkLoaded(), "nothing is loaded after three refusals");
    }
    const std::string problem = launchyield::LoadQworkTable(table);
    {
        Case t{report, "table: Qwencoin's work function on its real table"};
        t.Expect(problem.empty(), "the table loads: " + problem);
        if (!problem.empty()) return;
        // Qwencoin's genesis block (its chainparams): the hash is only a name, the work value is what meets the target.
        CPureBlockHeader genesis;
        genesis.nVersion = 1;
        genesis.hashMerkleRoot = *uint256::FromHex("23dc9bf99c1982b80a89976c64e8e38dc5e429db3600dbaba1431fbe70e080a8");
        genesis.nTime = 1794460000;
        genesis.nBits = 0x2000ffff;
        genesis.nNonce = 6;
        t.Equal(genesis.GetHash().GetHex(), std::string{"51ebb1f392844e411a0c52ba535773b0cb4a04cac6aede0d822249d5c6ce3cf5"}, "the genesis hash");
        t.Equal(launchyield::QwenWorkValue(genesis).GetHex(), std::string{"0083bfd7a2ae5796c139f180b33630684eb71751e4b2b3153ffe288da7739d1d"}, "the genesis work value");
        t.Expect(launchyield::CheckQwenWork(genesis), "it meets its target");
        CPureBlockHeader other = genesis;
        other.nNonce = 5;
        t.Expect(launchyield::QwenWorkValue(other) != launchyield::QwenWorkValue(genesis), "another nonce is another value");
        other = genesis;
        other.nBits = 0x207fffff;
        t.Expect(!launchyield::CheckQwenWork(other), "bits easier than Qwencoin's limit never pass");
        t.note = "genesis work value " + launchyield::QwenWorkValue(genesis).GetHex();
    }
    {
        Case t{report, "table: work values are kept across a restart"};
        CPureBlockHeader h;
        h.nVersion = 1;
        h.hashMerkleRoot = uint256{"23dc9bf99c1982b80a89976c64e8e38dc5e429db3600dbaba1431fbe70e080a8"};
        h.nTime = 1794460000;
        h.nBits = 0x2000ffff;
        h.nNonce = 41; // not the genesis block: a header nothing above has evaluated
        const std::string keep = table + ".selftest-values";
        std::remove(keep.c_str());
        t.Expect(launchyield::LoadQworkTable(table).empty(), "the table loads");
        t.Expect(launchyield::KeepQworkValues(keep).empty(), "the values file opens");
        uint64_t passes = launchyield::QwenPasses();
        const uint256 value = launchyield::QwenWorkValue(h);
        t.Equal(launchyield::QwenPasses(), passes + 1, "a header never seen costs one pass");
        launchyield::QwenWorkValue(h);
        t.Equal(launchyield::QwenPasses(), passes + 1, "and none the second time");
        // A restart: the table is mapped again and the values come from the file.
        t.Expect(launchyield::LoadQworkTable(table).empty() && launchyield::KeepQworkValues(keep).empty(), "table and values file again");
        passes = launchyield::QwenPasses();
        t.Expect(launchyield::QwenWorkValue(h) == value, "the kept value is the value");
        t.Equal(launchyield::QwenPasses(), passes, "and costs no pass after the restart");
        // A damaged record is not believed: the pass is made again and gives the same value.
        launchyield::UnloadQworkTable();
        {
            std::fstream f(keep, std::ios::binary | std::ios::in | std::ios::out);
            f.seekg(40);
            const char was = static_cast<char>(f.get());
            f.seekp(40);
            f.put(static_cast<char>(was ^ 0x5a));
        }
        t.Expect(launchyield::LoadQworkTable(table).empty() && launchyield::KeepQworkValues(keep).empty(), "table and the damaged file");
        passes = launchyield::QwenPasses();
        t.Expect(launchyield::QwenWorkValue(h) == value, "the value of a header whose record was damaged");
        t.Equal(launchyield::QwenPasses(), passes + 1, "it cost a pass: the damaged record was not believed");
        // A file cut in the middle of a record: the tail is dropped, the whole records are kept.
        launchyield::UnloadQworkTable();
        {
            std::ofstream f(keep, std::ios::binary | std::ios::app);
            f << "half a record";
        }
        t.Expect(launchyield::LoadQworkTable(table).empty() && launchyield::KeepQworkValues(keep).empty(), "table and the cut file");
        passes = launchyield::QwenPasses();
        t.Expect(launchyield::QwenWorkValue(h) == value, "the value again");
        t.Equal(launchyield::QwenPasses(), passes, "the record appended after the damage was read back");
        launchyield::UnloadQworkTable();
        std::remove(keep.c_str());
        t.Expect(launchyield::LoadQworkTable(table).empty(), "the table loads again for what follows");
    }
    if (vectors_path.empty()) {
        report.Add("vectors: real Qwencoin headers", true, "QWEN_VECTORS is not set", /*skipped=*/true);
        return;
    }
    std::vector<Vector> vectors;
    std::map<int, uint32_t> period_starts{{0, 1794460000}, {2016, 1794557679}, {4032, 1794596667}, {6048, 1794679485}};
    {
        std::ifstream f(vectors_path);
        std::stringstream ss;
        ss << f.rdbuf();
        UniValue doc;
        if (!f.good() && ss.str().empty()) {
            report.Add("vectors: real Qwencoin headers", false, "cannot read " + vectors_path);
            return;
        }
        if (!doc.read(ss.str()) || !doc.isObject() || !doc["headers"].isArray()) {
            report.Add("vectors: real Qwencoin headers", false, vectors_path + " is not {\"headers\": [...]}");
            return;
        }
        if (doc.exists("period_starts")) {
            for (const std::string& k : doc["period_starts"].getKeys()) period_starts[std::stoi(k)] = doc["period_starts"][k].getInt<uint32_t>();
        }
        for (const UniValue& v : doc["headers"].getValues()) {
            vectors.push_back({v["height"].getInt<int>(), ParseHeader(v["header"].get_str()), v["hash"].get_str(), v["work"].get_str()});
        }
    }
    {
        Case t{report, strprintf("vectors: the hash and the work value of %d real Qwencoin headers", int(vectors.size()))};
        for (const Vector& v : vectors) {
            t.Equal(v.header.GetHash().GetHex(), v.hash, strprintf("hash of block %d", v.height));
            t.Equal(launchyield::QwenWorkValue(v.header).GetHex(), v.work, strprintf("work value of block %d", v.height));
            t.Expect(launchyield::CheckQwenWork(v.header), strprintf("block %d meets its target", v.height));
        }
    }
    // Runs of consecutive heights: the first header of each is an anchor, the tree takes the rest.
    std::vector<std::pair<size_t, size_t>> runs;
    for (size_t i = 0; i < vectors.size();) {
        size_t j = i;
        while (j + 1 < vectors.size() && vectors[j + 1].height == vectors[j].height + 1) ++j;
        runs.emplace_back(i, j);
        i = j + 1;
    }
    {
        Case t{report, "vectors: the Qwencoin tree takes real headers across every retarget"};
        int accepted = 0, retargets = 0, refused = 0, lucky = 0;
        for (const auto& [first, last] : runs) {
            const Vector& anchor = vectors[first];
            const int period = anchor.height - anchor.height % 2016;
            t.Expect(period_starts.count(period) > 0, strprintf("the start of the period of block %d is known", anchor.height));
            HeaderChain tree;
            tree.Init(anchor.header, anchor.height, period_starts[period], HeaderChain::Rules::QWENCOIN, /*regtest=*/false);
            std::string err;
            for (size_t i = first + 1; i <= last; ++i) {
                const Vector& v = vectors[i];
                // First the same header with another nonce, on top of the same parent: its work value is another
                // number, and (but for a value that happens to be under the target too) it must be refused.
                CPureBlockHeader changed = v.header;
                ++changed.nNonce;
                const bool took = tree.Accept(changed, err);
                if (took) {
                    t.Expect(launchyield::CheckQwenWork(changed), strprintf("block %d with its nonce changed was accepted without meeting the target", v.height));
                    tree.Remove(changed.GetHash());
                    ++lucky;
                } else {
                    t.Expect(err == "qwen header lacks proof of work", strprintf("block %d with its nonce changed: %s", v.height, err));
                    ++refused;
                }
                if (v.height % 2016 == 0) {
                    // At a retarget the parent's bits are no longer the right ones.
                    CPureBlockHeader stale = v.header;
                    stale.nBits = vectors[i - 1].header.nBits;
                    t.Expect(!tree.Accept(stale, err) && err == "qwen header has wrong difficulty", strprintf("block %d with the bits of the period before: %s", v.height, err));
                    t.Expect(v.header.nBits != vectors[i - 1].header.nBits, strprintf("block %d retargets", v.height));
                    ++retargets;
                }
                const bool ok = tree.Accept(v.header, err);
                t.Expect(ok, strprintf("block %d accepted (%s)", v.height, err));
                accepted += ok;
            }
            t.Equal(tree.BestHeight(), vectors[last].height, strprintf("best height of the run from %d", anchor.height));
            t.Equal(tree.Confirmations(vectors[first + 1].header.GetHash()), int(last - first), strprintf("confirmations of block %d", vectors[first + 1].height));
            // The pass limit under the real rules: a second tree given the whole run within one budget takes eight.
            HeaderChain limited;
            limited.Init(anchor.header, anchor.height, period_starts[period], HeaderChain::Rules::QWENCOIN, /*regtest=*/false);
            int budget = launchyield::QWEN_PASSES_PER_BLOCK, taken = 0;
            for (size_t i = first + 1; i <= last; ++i) taken += limited.Accept(vectors[i].header, err, &budget);
            t.Equal(taken, std::min<int>(8, int(last - first)), strprintf("headers taken within one block's limit, run from %d", anchor.height));
        }
        t.note = strprintf("%d headers accepted in %d runs, %d retargets crossed, %d changed nonces refused, %d met the target by themselves", accepted,
                           int(runs.size()), retargets, refused, lucky);
        t.Expect(retargets >= 3, strprintf("%d retargets crossed", retargets));
        t.Expect(refused >= accepted - 3, strprintf("%d of %d changed nonces refused (%d met the target by themselves)", refused, accepted, lucky));
        t.Expect(accepted == int(vectors.size() - runs.size()), strprintf("%d headers accepted in %d runs", accepted, int(runs.size())));
    }
}

} // namespace

UniValue RunSelfTest(const std::string& table, const std::string& vectors)
{
    Report report;
    const auto guarded = [&](const char* group, auto fn) {
        try {
            fn();
        } catch (const std::exception& e) {
            report.Add(std::string{group} + ": stopped by an exception", false, e.what());
        }
    };
    guarded("curves", [&] { TestCurves(report); });
    guarded("relay", [&] { TestRelay(report); });
    guarded("qwen rules", [&] { TestQwenRules(report); });
    guarded("state", [&] { TestState(report); });
    guarded("table", [&] { TestTable(report, table, vectors); });
    launchyield::UnloadQworkTable();
    LaunchCurveCacheClear();
    bool ok = true;
    for (const UniValue& c : report.checks.getValues()) ok = ok && c["ok"].get_bool();
    UniValue out(UniValue::VOBJ);
    out.pushKV("ok", ok);
    out.pushKV("checks", std::move(report.checks));
    return out;
}
