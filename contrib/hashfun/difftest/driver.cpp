// hashfun differential driver: the node's own consensus code (descriptor
// parsing, launch identity, chain params, curve, LWMA) compiled without the
// rest of the node, driven over JSON lines so hashfun/tests/test_diff_cpp.py
// can compare every value against the independent Python model.
//
// stdin, one request per line:
//   {"op":"desc","json":"<descriptor text>"}      (every op: "json_hex":"<the text's bytes in hex>" instead of "json")
//   {"op":"chain","json":"<descriptor text>","headers":[[time,bits],...]}
//   {"op":"tail","json":"<descriptor text>","ranges":[[from,to],...]}
//   {"op":"auxpow","json":"<descriptor text>","header":"<hex: 80-byte header + CAuxPow>"}
// stdout: one JSON object per request.

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/params.h>
#include <crypto/hex_base.h>
#include <kernel/chainparams.h>
#include <kernel/launch.h>
#include <launchcurve.h>
#include <launchyield.h>
#include <pow.h>
#include <auxpow.h>
#include <primitives/block.h>
#include <streams.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>

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
    // "json_hex" in place of "json": the file's bytes in hex, for bytes a JSON string cannot carry
    // (a launch file that is not valid UTF-8).
    std::string text;
    if (req.exists("json_hex")) {
        const auto bytes = ParseHex(req["json_hex"].get_str());
        text.assign(bytes.begin(), bytes.end());
    } else {
        text = req["json"].get_str();
    }
    auto d = ParseLaunchDescriptor(text, err);
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
        grad_h(UniValue::VARR), subsidy(UniValue::VARR), fee(UniValue::VARR), permitted(UniValue::VARR), timed(UniValue::VARR);
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
        {
            // Consensus nBits for a block with this timestamp (LWMA base + stall relief).
            CBlockHeader hdr;
            hdr.nTime = b->nTime;
            timed.push_back(strprintf("%08x", GetNextWorkRequired(b->pprev, &hdr, c)));
        }
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
    r.pushKV("bits_for_time", std::move(timed));
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

/**
 * Deserialize a merge-mined header exactly as the node does and run the
 * header-level PoW check. The check below mirrors validation.cpp's
 * CheckProofOfWork(const CBlockHeader&, params) (validation.cpp itself is not
 * linkable here); CAuxPow::check, the parent PoW check and all serialization
 * are the node's own code.
 */
UniValue AuxPow(const UniValue& req)
{
    UniValue r(UniValue::VOBJ);
    auto d = Parse(req, r);
    if (!d) return r;
    const auto p = CChainParams::Launch(CChainParams::LaunchOptions{.desc = *d});
    const Consensus::Params& c = p->GetConsensus();
    r.pushKV("ok", true);
    const auto bytes = TryParseHex<uint8_t>(req["header"].get_str());
    if (!bytes) throw std::runtime_error("bad header hex");
    DataStream ss{*bytes};
    CBlockHeader h;
    std::string stage = "ok";
    try {
        ss >> h;
        if (!ss.empty()) stage = "trailing-bytes";
    } catch (const std::exception& e) {
        stage = "deserialize";
    }
    if (stage == "ok") {
        if (!h.IsLegacy() && c.fStrictChainId && h.GetChainId() != c.nAuxpowChainId) {
            stage = "chain-id";
        } else if (!h.auxpow) {
            if (h.IsAuxpow()) {
                stage = "no-auxpow";
            } else if (!CheckProofOfWork(h.GetHash(), h.nBits, c)) {
                stage = "pow";
            }
        } else if (!h.IsAuxpow()) {
            stage = "auxpow-flag";
        } else if (!CheckProofOfWork(h.auxpow->getParentBlockHash(), h.nBits, c)) {
            stage = "parent-pow";
        } else if (!h.auxpow->check(h.GetHash(), h.GetChainId(), c)) {
            stage = "auxpow-check";
        }
        r.pushKV("hash", h.GetHash().GetHex());
    }
    r.pushKV("valid", stage == "ok");
    r.pushKV("stage", stage);
    return r;
}

uint256 RawHash(const UniValue& v)
{
    const auto b = ParseHex(v.get_str());
    if (b.size() != 32) throw std::runtime_error("expected 32 bytes");
    uint256 h;
    std::copy(b.begin(), b.end(), h.begin());
    return h;
}

std::string RawHex(const uint256& h) { return HexStr(std::span<const unsigned char>{h.begin(), 32}); }

/** {"op":"yield","work":hex,"num":n,"shift":n,"min":n,"id":raw32,"seed_block":raw32,"mint_block":raw32,"total":hex} */
UniValue Yield(const UniValue& req)
{
    using namespace launchyield;
    UniValue r(UniValue::VOBJ);
    const arith_uint256 work = UintToArith256(*uint256::FromHex(req["work"].get_str()));
    const CAmount owed = Owed(work, req["num"].getInt<uint64_t>(), req["shift"].getInt<uint32_t>());
    const uint256 id = RawHash(req["id"]);
    const uint256 seed = DrawSeed(id, RawHash(req["seed_block"]));
    const Draw d = ComputeDraw(owed, req["min"].getInt<int64_t>(), seed);
    r.pushKV("owed", owed);
    r.pushKV("seed", RawHex(seed));
    r.pushKV("pay", d.pay);
    r.pushKV("payee", static_cast<int>(d.payee));
    r.pushKV("tag", HexStr(PayTag(id, RawHash(req["mint_block"]))));
    const arith_uint256 total = UintToArith256(*uint256::FromHex(req["total"].get_str()));
    UniValue pts(UniValue::VARR);
    if (total != 0) {
        for (int i = 0; i < 64; ++i) pts.push_back(Hex256(CandidatePoint(seed, i, total))); // the draw uses point 0; the rest check the function
    }
    r.pushKV("points", std::move(pts));
    return r;
}

/** {"op":"regouts","tx":hex} */
UniValue RegOuts(const UniValue& req)
{
    UniValue r(UniValue::VOBJ), outs(UniValue::VARR);
    CMutableTransaction mtx;
    DataStream ss{ParseHex(req["tx"].get_str())};
    ss >> TX_WITH_WITNESS(mtx);
    for (const auto& o : launchyield::RegisteredOutputs(CTransaction{mtx})) {
        UniValue e(UniValue::VARR);
        e.push_back(static_cast<int64_t>(o.vout));
        e.push_back(o.value);
        e.push_back(HexStr(o.btc_script));
        outs.push_back(std::move(e));
    }
    r.pushKV("outs", std::move(outs));
    return r;
}

/** {"op":"proof","payload":hex,"root":raw32,"tag":hex20,"recipient":hex,"pay":n} */
UniValue Proof(const UniValue& req)
{
    UniValue r(UniValue::VOBJ);
    const auto payload = ParseHex(req["payload"].get_str());
    const auto proof = launchyield::ParsePaymentProof(payload);
    r.pushKV("parsed", proof.has_value());
    if (!proof) return r;
    std::array<unsigned char, 20> tag;
    const auto tb = ParseHex(req["tag"].get_str());
    std::copy(tb.begin(), tb.begin() + 20, tag.begin());
    std::string err;
    const bool ok = launchyield::VerifyBtcPayment(*proof, RawHash(req["root"]), tag, ParseHex(req["recipient"].get_str()),
                                                  req["pay"].getInt<int64_t>(), err);
    r.pushKV("valid", ok);
    r.pushKV("error", err);
    r.pushKV("mint_height", static_cast<int64_t>(proof->mint_height));
    r.pushKV("btc_block", RawHex(proof->btc_block));
    r.pushKV("candidate", proof->candidate);
    return r;
}

/** {"op":"btc","anchor":hex80,"height":n,"period_time":n,"regtest":bool,"ops":[["add",hex80]|["del",raw32]|["conf",raw32]]} */
UniValue Btc(const UniValue& req)
{
    launchyield::BtcChain chain;
    CPureBlockHeader anchor;
    {
        DataStream ss{ParseHex(req["anchor"].get_str())};
        ss >> anchor;
    }
    chain.Init(anchor, req["height"].getInt<int>(), req["period_time"].getInt<uint32_t>(), req["regtest"].get_bool());
    UniValue res(UniValue::VARR);
    for (const UniValue& op : req["ops"].getValues()) {
        const std::string& kind = op[0].get_str();
        if (kind == "add") {
            CPureBlockHeader h;
            DataStream ss{ParseHex(op[1].get_str())};
            ss >> h;
            std::string err;
            chain.Accept(h, err);
            res.push_back(err);
        } else if (kind == "del") {
            chain.Remove(RawHash(op[1]));
            res.push_back("");
        } else {
            res.push_back(chain.Confirmations(RawHash(op[1])));
        }
    }
    UniValue r(UniValue::VOBJ);
    r.pushKV("results", std::move(res));
    r.pushKV("best", RawHex(chain.Best()));
    r.pushKV("best_height", chain.BestHeight());
    r.pushKV("size", static_cast<int64_t>(chain.Size()));
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
            out = op == "desc" ? Desc(req) : op == "chain" ? Chain(req) : op == "tail" ? Tail(req) :
                  op == "auxpow" ? AuxPow(req) : op == "yield" ? Yield(req) : op == "regouts" ? RegOuts(req) :
                  op == "proof" ? Proof(req) : op == "btc" ? Btc(req) : UniValue{};
            if (out.isNull()) throw std::runtime_error("unknown op " + op);
        } catch (const std::exception& e) {
            out = UniValue(UniValue::VOBJ);
            out.pushKV("ok", false);
            out.pushKV("exception", e.what());
        }
        std::cout << out.write() << "\n" << std::flush;
    }
}
