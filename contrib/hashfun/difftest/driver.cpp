// hashfun differential driver: the node's own consensus code (descriptor
// parsing, launch identity, chain params, curve, LWMA) compiled without the
// rest of the node, driven over JSON lines so hashfun/tests/test_diff_cpp.py
// can compare every value against the independent Python model.
//
// stdin, one request per line:
//   {"op":"desc","json":"<descriptor text>"}
//   {"op":"chain","json":"<descriptor text>","headers":[[time,bits],...]}
//   {"op":"tail","json":"<descriptor text>","ranges":[[from,to],...]}
// stdout: one JSON object per request.

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/params.h>
#include <crypto/hex_base.h>
#include <kernel/chainparams.h>
#include <kernel/launch.h>
#include <launchcurve.h>
#include <pow.h>
#include <primitives/block.h>
#include <tinyformat.h>
#include <univalue.h>

#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

std::string Hex256(const arith_uint256& x) { return ArithToUint256(x).GetHex(); }

std::optional<LaunchDescriptor> Parse(const UniValue& req, UniValue& out)
{
    std::string err;
    auto d = ParseLaunchDescriptor(req["json"].get_str(), err);
    if (!d) {
        out.pushKV("ok", false);
        out.pushKV("error", err);
    }
    return d;
}

UniValue Desc(const UniValue& req)
{
    UniValue r(UniValue::VOBJ);
    auto d = Parse(req, r);
    if (!d) return r;
    r.pushKV("ok", true);
    r.pushKV("canon", HexStr(LaunchCanonicalBytes(*d)));
    r.pushKV("id", LaunchIdHex(*d));
    r.pushKV("magic", HexStr(LaunchMessageStart(*d)));
    r.pushKV("chain_id", LaunchChainId(*d));
    r.pushKV("p2p", LaunchP2PPort(*d));
    r.pushKV("rpc", LaunchRPCPort(*d));
    r.pushKV("datadir", LaunchDataDirName(*d));
    try {
        const auto p = CChainParams::Launch(CChainParams::LaunchOptions{.desc = *d});
        const auto& c = p->GetConsensus();
        r.pushKV("genesis", c.hashGenesisBlock.GetHex());
        r.pushKV("graduation_work", c.launch_graduation_work.GetHex());
        r.pushKV("genesis_work", c.launch_genesis_work.GetHex());
        r.pushKV("pow_limit_bits", strprintf("%08x", UintToArith256(c.powLimit).GetCompact()));
        r.pushKV("params_chain_id", c.nAuxpowChainId);
        r.pushKV("params_magic", HexStr(p->MessageStart()));
        r.pushKV("params_port", p->GetDefaultPort());
        r.pushKV("hrp", p->Bech32HRP());
    } catch (const std::exception& e) {
        r.pushKV("params_error", e.what());
    }
    return r;
}

UniValue Chain(const UniValue& req)
{
    UniValue r(UniValue::VOBJ);
    auto d = Parse(req, r);
    if (!d) return r;
    const auto p = CChainParams::Launch(CChainParams::LaunchOptions{.desc = *d});
    const Consensus::Params& c = p->GetConsensus();
    std::vector<std::unique_ptr<CBlockIndex>> idx;
    idx.push_back(std::make_unique<CBlockIndex>(p->GenesisBlock()));
    idx.back()->nHeight = 0;
    idx.back()->nChainWork = GetBlockProof(*idx.back());
    idx.back()->BuildSkip();

    UniValue next(UniValue::VARR), relw(UniValue::VARR), supply(UniValue::VARR), grad(UniValue::VARR),
        grad_h(UniValue::VARR), subsidy(UniValue::VARR), fee(UniValue::VARR), permitted(UniValue::VARR);
    const CBlockHeader dummy;
    auto record = [&](const CBlockIndex* tip) {
        next.push_back(strprintf("%08x", GetNextWorkRequired(tip, &dummy, c)));
        relw.push_back(Hex256(LaunchRelWork(tip, c)));
        supply.push_back(LaunchCurveSupply(LaunchRelWork(tip, c), c));
        grad.push_back(LaunchGraduatedAt(tip, c));
        grad_h.push_back(LaunchGraduationHeight(tip, c));
    };
    record(idx.back().get());
    const UniValue& headers = req["headers"];
    for (size_t i = 0; i < headers.size(); ++i) {
        auto b = std::make_unique<CBlockIndex>();
        b->pprev = idx.back().get();
        b->nHeight = b->pprev->nHeight + 1;
        b->nTime = static_cast<uint32_t>(headers[i][0].getInt<int64_t>());
        b->nBits = static_cast<uint32_t>(headers[i][1].getInt<int64_t>());
        b->nChainWork = b->pprev->nChainWork + GetBlockProof(*b);
        b->BuildSkip();
        const CAmount s = LaunchSubsidy(b->pprev, b->nBits, b->nHeight, c);
        subsidy.push_back(s);
        fee.push_back(LaunchCreatorFee(s, c));
        permitted.push_back(PermittedDifficultyTransition(c, b->nHeight, b->pprev->nBits, b->nBits));
        idx.push_back(std::move(b));
        record(idx.back().get());
    }
    r.pushKV("ok", true);
    r.pushKV("next_bits", std::move(next));
    r.pushKV("rel_work", std::move(relw));
    r.pushKV("curve_supply", std::move(supply));
    r.pushKV("graduated", std::move(grad));
    r.pushKV("graduation_height", std::move(grad_h));
    r.pushKV("subsidy", std::move(subsidy));
    r.pushKV("creator_fee", std::move(fee));
    r.pushKV("permitted", std::move(permitted));
    return r;
}

UniValue Tail(const UniValue& req)
{
    UniValue r(UniValue::VOBJ);
    auto d = Parse(req, r);
    if (!d) return r;
    const auto p = CChainParams::Launch(CChainParams::LaunchOptions{.desc = *d});
    UniValue minted(UniValue::VARR), reward(UniValue::VARR);
    const UniValue& ranges = req["ranges"];
    for (size_t i = 0; i < ranges.size(); ++i) {
        const int from = ranges[i][0].getInt<int>(), to = ranges[i][1].getInt<int>();
        minted.push_back(LaunchTailMinted(from, to, p->GetConsensus()));
        reward.push_back(LaunchTailReward(to, p->GetConsensus()));
    }
    r.pushKV("ok", true);
    r.pushKV("tail_minted", std::move(minted));
    r.pushKV("tail_reward", std::move(reward));
    return r;
}

} // namespace

int main()
{
    std::string line;
    while (std::getline(std::cin, line)) {
        UniValue req, out;
        try {
            if (!req.read(line)) throw std::runtime_error("bad request json");
            const std::string& op = req["op"].get_str();
            out = op == "desc" ? Desc(req) : op == "chain" ? Chain(req) : op == "tail" ? Tail(req) : UniValue{};
            if (out.isNull()) throw std::runtime_error("unknown op " + op);
        } catch (const std::exception& e) {
            out = UniValue(UniValue::VOBJ);
            out.pushKV("ok", false);
            out.pushKV("exception", e.what());
        }
        std::cout << out.write() << "\n" << std::flush;
    }
}
