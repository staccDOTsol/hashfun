// hashfun differential driver: the node's own consensus code (descriptor
// parsing, launch identity, chain params, curve, LWMA) compiled without the
// rest of the node, driven over JSON lines so hashfun/tests/test_diff_cpp.py
// can compare every value against the independent Python model.
//
// stdin, one request per line:
//   {"op":"desc","json":"<descriptor text>"}      (every op: "json_hex":"<the text's bytes in hex>" instead of "json")
//   {"op":"chain","json":"<descriptor text>","headers":[[time,bits],[time,bits,version],...]}
//   {"op":"tail","json":"<descriptor text>","ranges":[[from,to],...]}
//   {"op":"auxpow","json":"<descriptor text>","header":"<hex: 80-byte header + CAuxPow>"}
//   {"op":"yield",...} {"op":"regouts",...} {"op":"proof",...}
//   {"op":"btc","anchor":hex80,"height":n,"period_time":n,"regtest":bool,"rules":"btc"|"qwen","table":path,"ops":[...]}
//   {"op":"qwork","table":path,"headers":[hex80,...]}
//   {"op":"state","json":"<descriptor text>","table":path,"steps":[["connect",blockhex],["disconnect"],["dump"],["dump",from]]}
//   {"op":"selftest","table":path,"vectors":path}
//   any request may carry "work":"hash": for that request a Qwencoin main-network header's work
//   value is its own SHA256d hash (a stand-in for the pass through the weights; no table needed)
// stdout: one JSON object per request.
//
//   hfdiff --selftest      the node's own checks of rule set 3 (selftest.cpp), one line per check;
//                          QWORK_TABLE and QWEN_VECTORS in the environment add the real Qwencoin data.

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/params.h>
#include <crypto/hex_base.h>
#include <crypto/sha256.h>
#include <kernel/chainparams.h>
#include <kernel/launch.h>
#include <launchcurve.h>
#include <launchyield.h>
#include <launchyieldstate.h>
#include <pow.h>
#include <auxpow.h>
#include <primitives/block.h>
#include <streams.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
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

/** A block hash for an index entry that stands for no real header: unique in this process. */
uint256 MadeUpHash()
{
    static uint64_t counter{0};
    ++counter;
    uint256 h;
    CSHA256().Write(reinterpret_cast<const unsigned char*>("hfdiff-index"), 12).Write(reinterpret_cast<const unsigned char*>(&counter), 8).Finalize(h.begin());
    return h;
}

/**
 * "headers": [time, bits] or [time, bits, version]: the version is the header's nVersion (only bit
 * 0x200, the QWEN curve, matters here; left out it is 0, the BTC curve).
 * Per index entry (the genesis block first): next_bits, rel_work, work_btc, work_qwen, minted_btc,
 * minted_qwen, curve_supply (both curves, as of the graduation block once graduated), graduated,
 * graduation_height, graduated_by ("" | "btc" | "qwen").
 * Per header: subsidy (on the header's own curve), creator_fee, permitted, bits_for_time,
 * version_ok (the rule bad-curve-version).
 */
UniValue Chain(const UniValue& req)
{
    UniValue r(UniValue::VOBJ);
    auto d = Parse(req, r);
    if (!d) return r;
    const auto p = CChainParams::Launch(CChainParams::LaunchOptions{.desc = *d});
    const Consensus::Params& c = p->GetConsensus();
    LaunchCurveCacheClear(); // the hashes below are made up: nothing remembered from another request may match them
    std::vector<std::unique_ptr<CBlockIndex>> idx;
    std::vector<std::unique_ptr<uint256>> hashes;
    idx.push_back(std::make_unique<CBlockIndex>(p->GenesisBlock()));
    hashes.push_back(std::make_unique<uint256>(MadeUpHash()));
    idx.back()->phashBlock = hashes.back().get();
    idx.back()->nHeight = 0;
    idx.back()->nChainWork = GetBlockProof(*idx.back());
    idx.back()->BuildSkip();

    UniValue next(UniValue::VARR), relw(UniValue::VARR), supply(UniValue::VARR), grad(UniValue::VARR),
        grad_h(UniValue::VARR), subsidy(UniValue::VARR), fee(UniValue::VARR), permitted(UniValue::VARR), timed(UniValue::VARR),
        work_btc(UniValue::VARR), work_qwen(UniValue::VARR), minted_btc(UniValue::VARR), minted_qwen(UniValue::VARR),
        grad_by(UniValue::VARR), version_ok(UniValue::VARR);
    const CBlockHeader dummy;
    auto record = [&](const CBlockIndex* tip) {
        next.push_back(strprintf("%08x", GetNextWorkRequired(tip, &dummy, c)));
        relw.push_back(Hex256(LaunchRelWork(tip, c)));
        work_btc.push_back(Hex256(LaunchCurveWork(tip, LaunchCurve::BTC, c)));
        work_qwen.push_back(Hex256(LaunchCurveWork(tip, LaunchCurve::QWEN, c)));
        minted_btc.push_back(LaunchCurveMinted(tip, LaunchCurve::BTC, c));
        minted_qwen.push_back(LaunchCurveMinted(tip, LaunchCurve::QWEN, c));
        supply.push_back(LaunchCurveMinted(tip, c));
        grad.push_back(LaunchGraduatedAt(tip, c));
        grad_h.push_back(LaunchGraduationHeight(tip, c));
        const auto by = LaunchGraduatedBy(tip, c);
        grad_by.push_back(by ? LaunchCurveName(*by) : "");
    };
    record(idx.back().get());
    const UniValue& headers = req["headers"];
    for (size_t i = 0; i < headers.size(); ++i) {
        auto b = std::make_unique<CBlockIndex>();
        hashes.push_back(std::make_unique<uint256>(MadeUpHash()));
        b->phashBlock = hashes.back().get();
        b->pprev = idx.back().get();
        b->nHeight = b->pprev->nHeight + 1;
        b->nTime = static_cast<uint32_t>(headers[i][0].getInt<int64_t>());
        b->nBits = static_cast<uint32_t>(headers[i][1].getInt<int64_t>());
        b->nVersion = headers[i].size() > 2 ? static_cast<int32_t>(headers[i][2].getInt<int64_t>()) : 0;
        {
            // Consensus nBits for a block with this timestamp (LWMA base + stall relief).
            CBlockHeader hdr;
            hdr.nTime = b->nTime;
            timed.push_back(strprintf("%08x", GetNextWorkRequired(b->pprev, &hdr, c)));
        }
        b->nChainWork = b->pprev->nChainWork + GetBlockProof(*b);
        b->BuildSkip();
        const CAmount s = LaunchSubsidy(b->pprev, b->nBits, b->nVersion, b->nHeight, c);
        subsidy.push_back(s);
        fee.push_back(LaunchCreatorFee(s, c));
        permitted.push_back(PermittedDifficultyTransition(c, b->nHeight, b->pprev->nBits, b->nBits));
        version_ok.push_back(LaunchCurveVersionOk(b->nVersion, b->pprev, c));
        idx.push_back(std::move(b));
        record(idx.back().get());
    }
    r.pushKV("ok", true);
    r.pushKV("next_bits", std::move(next));
    r.pushKV("rel_work", std::move(relw));
    r.pushKV("work_btc", std::move(work_btc));
    r.pushKV("work_qwen", std::move(work_qwen));
    r.pushKV("minted_btc", std::move(minted_btc));
    r.pushKV("minted_qwen", std::move(minted_qwen));
    r.pushKV("curve_supply", std::move(supply));
    r.pushKV("graduated", std::move(grad));
    r.pushKV("graduation_height", std::move(grad_h));
    r.pushKV("graduated_by", std::move(grad_by));
    r.pushKV("subsidy", std::move(subsidy));
    r.pushKV("creator_fee", std::move(fee));
    r.pushKV("permitted", std::move(permitted));
    r.pushKV("bits_for_time", std::move(timed));
    r.pushKV("version_ok", std::move(version_ok));
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

/** Load Qwencoin's work table for this process, once per path. Returns "" or what is wrong. */
std::string UseTable(const std::string& path)
{
    static std::string loaded;
    if (path == loaded && launchyield::QworkLoaded()) return {};
    const std::string problem = launchyield::LoadQworkTable(path);
    loaded = problem.empty() ? path : std::string{};
    return problem;
}

/**
 * {"op":"btc","anchor":hex80,"height":n,"period_time":n,"regtest":bool,
 *  "rules":"btc"|"qwen" (default "btc"), "table":path (Qwencoin's work table: needed for rules qwen without regtest),
 *  "ops":[["add",hex80]|["del",raw32]|["conf",raw32]|["budget",n]]}
 * "budget": how many more headers may have their work checked from here on (the per-block limit of
 * the Qwencoin relay); n < 0 lifts the limit. Results: add -> the error ("" when accepted), del -> "",
 * conf -> confirmations, budget -> "". "budget" in the answer: what is left, -1 without a limit.
 */
UniValue Btc(const UniValue& req)
{
    using launchyield::HeaderChain;
    HeaderChain chain;
    CPureBlockHeader anchor;
    {
        DataStream ss{ParseHex(req["anchor"].get_str())};
        ss >> anchor;
    }
    const bool qwen = req.exists("rules") && req["rules"].get_str() == "qwen";
    if (req.exists("table")) {
        if (const std::string problem = UseTable(req["table"].get_str()); !problem.empty()) {
            UniValue r(UniValue::VOBJ);
            r.pushKV("ok", false);
            r.pushKV("error", problem);
            return r;
        }
    }
    chain.Init(anchor, req["height"].getInt<int>(), req["period_time"].getInt<uint32_t>(),
               qwen ? HeaderChain::Rules::QWENCOIN : HeaderChain::Rules::BITCOIN, req["regtest"].get_bool());
    int budget = -1;
    UniValue res(UniValue::VARR);
    for (const UniValue& op : req["ops"].getValues()) {
        const std::string& kind = op[0].get_str();
        if (kind == "add") {
            CPureBlockHeader h;
            DataStream ss{ParseHex(op[1].get_str())};
            ss >> h;
            std::string err;
            chain.Accept(h, err, budget < 0 ? nullptr : &budget);
            res.push_back(err);
        } else if (kind == "del") {
            chain.Remove(RawHash(op[1]));
            res.push_back("");
        } else if (kind == "budget") {
            budget = op[1].getInt<int>();
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
    r.pushKV("budget", budget);
    return r;
}

/**
 * {"op":"qwork","table":path,"headers":[hex80,...]}: the work value of each header on Qwencoin's
 * main network (a uint256 as the node prints one) and whether it meets the header's own bits.
 */
UniValue Qwork(const UniValue& req)
{
    UniValue r(UniValue::VOBJ);
    if (const std::string problem = UseTable(req["table"].get_str()); !problem.empty()) {
        r.pushKV("ok", false);
        r.pushKV("error", problem);
        return r;
    }
    UniValue values(UniValue::VARR), meets(UniValue::VARR), hashes(UniValue::VARR);
    for (const UniValue& hex : req["headers"].getValues()) {
        CPureBlockHeader h;
        DataStream ss{ParseHex(hex.get_str())};
        ss >> h;
        hashes.push_back(h.GetHash().GetHex());
        values.push_back(launchyield::QwenWorkValue(h).GetHex());
        meets.push_back(launchyield::CheckQwenWork(h));
    }
    r.pushKV("ok", true);
    r.pushKV("hashes", std::move(hashes));
    r.pushKV("values", std::move(values));
    r.pushKV("meets", std::move(meets));
    return r;
}

/** What getmintobligation says about one height, from the state alone (plus the draw's seed). */
UniValue ObligationOf(const LaunchYieldState& ys, const CBlockIndex* index, const Consensus::Params& c)
{
    static const LaunchYieldState::Info untracked;
    const int height = index->nHeight;
    const LaunchYieldState::Info* info = ys.At(height);
    if (!info) info = &untracked;
    UniValue r(UniValue::VOBJ);
    r.pushKV("height", height);
    r.pushKV("hash", index->GetBlockHash().GetHex());
    r.pushKV("curve", info->curve);
    r.pushKV("quote", LaunchCurveName(LaunchCurveOf(index->nVersion)));
    r.pushKV("owed", info->owed);
    r.pushKV("draw_known", info->draw_known);
    r.pushKV("draw_height", height + launchyield::DRAW_DELAY);
    r.pushKV("settled", info->settled);
    r.pushKV("spendable", ys.Spendable(height));
    r.pushKV("deadline_height", height + c.launch_settle_deadline);
    r.pushKV("tag", HexStr(launchyield::PayTag(c.launch_id, index->GetBlockHash())));
    if (info->draw_known) {
        r.pushKV("pay", info->pay);
        r.pushKV("payee", info->payee == launchyield::Payee::HOLDER ? "holder" : info->payee == launchyield::Payee::CREATOR ? "creator" : "dev");
        if (info->pay > 0) r.pushKV("pay_script", HexStr(info->pay_script));
        r.pushKV("earning", info->earning);
        r.pushKV("seed", RawHex(info->seed));
        if (info->has_coin) {
            UniValue coin(UniValue::VOBJ);
            coin.pushKV("txid", info->coin.hash.GetHex());
            coin.pushKV("vout", static_cast<int64_t>(info->coin.n));
            coin.pushKV("value", info->coin_value);
            r.pushKV("coin", std::move(coin));
        }
    }
    return r;
}

UniValue RelayOf(const launchyield::HeaderChain& chain)
{
    UniValue r(UniValue::VOBJ);
    r.pushKV("best", chain.Best().GetHex());
    r.pushKV("height", chain.BestHeight());
    r.pushKV("headers", static_cast<int64_t>(chain.Size()));
    return r;
}

/**
 * {"op":"state","json":"<descriptor text>","table":path (only for a launch without qwen_regtest),
 *  "steps":[["connect",blockhex] | ["disconnect"] | ["dump"] | ["dump",from_height]]}
 *
 * The node's sats-leg / QWEN-leg state (src/launchyieldstate.cpp) driven block by block, with
 * nothing else of the node around it. It starts with the launch's genesis block connected.
 * "connect": a whole block as the node serializes it (header, auxpow if the version says so,
 * transactions with witnesses), put on top of the current tip: its hash is the header's, its work
 * what its bits say; nothing about it is validated, exactly as the state itself validates nothing.
 * "disconnect": the tip is taken off again (the undo path). "dump": everything the state says:
 *   {"height", "closed", "earning", "coins", "btc": R, "qwen": R, "count": {"btc": [blocks, last_height], "qwen": [...]},
 *    "graduated", "obligations": [what getmintobligation gives for each height from from_height (default 1), plus "seed"]}
 * with R = {"best", "height", "headers"} as getbtcrelay / getqwenrelay name them.
 * Answer: {"ok":true,"dumps":[one per dump step]}.
 */
UniValue State(const UniValue& req)
{
    UniValue r(UniValue::VOBJ);
    auto d = Parse(req, r);
    if (!d) return r;
    if (req.exists("table")) {
        if (const std::string problem = UseTable(req["table"].get_str()); !problem.empty()) {
            r.pushKV("ok", false);
            r.pushKV("error", problem);
            return r;
        }
    }
    const auto p = CChainParams::Launch(CChainParams::LaunchOptions{.desc = *d});
    const Consensus::Params& c = p->GetConsensus();
    LaunchCurveCacheClear();
    std::vector<std::unique_ptr<CBlockIndex>> idx;
    std::vector<std::unique_ptr<uint256>> hashes;
    LaunchYieldState ys;
    auto push = [&](const CBlock& block) {
        auto b = std::make_unique<CBlockIndex>(block);
        hashes.push_back(std::make_unique<uint256>(block.GetHash()));
        b->phashBlock = hashes.back().get();
        b->pprev = idx.empty() ? nullptr : idx.back().get();
        b->nHeight = b->pprev ? b->pprev->nHeight + 1 : 0;
        b->nChainWork = (b->pprev ? b->pprev->nChainWork : arith_uint256{0}) + GetBlockProof(*b);
        b->BuildSkip();
        idx.push_back(std::move(b));
        ys.Connect(block, idx.back().get(), c);
    };
    push(p->GenesisBlock());
    UniValue dumps(UniValue::VARR);
    for (const UniValue& step : req["steps"].getValues()) {
        const std::string& kind = step[0].get_str();
        if (kind == "connect") {
            CBlock block;
            DataStream ss{ParseHex(step[1].get_str())};
            ss >> TX_WITH_WITNESS(block);
            if (!ss.empty()) throw std::runtime_error("trailing bytes after the block");
            push(block);
        } else if (kind == "disconnect") {
            if (idx.size() < 2) throw std::runtime_error("nothing to disconnect");
            ys.Disconnect(idx.back().get());
            idx.pop_back();
            hashes.pop_back();
        } else if (kind == "dump") {
            const CBlockIndex* tip = idx.back().get();
            UniValue o(UniValue::VOBJ);
            o.pushKV("height", tip->nHeight);
            o.pushKV("closed", ys.Closed(c));
            o.pushKV("earning", ys.Earning(c));
            o.pushKV("coins", static_cast<int64_t>(ys.Coins()));
            o.pushKV("btc", RelayOf(ys.Btc()));
            o.pushKV("qwen", RelayOf(ys.Qwen()));
            UniValue count(UniValue::VOBJ);
            for (const LaunchCurve curve : {LaunchCurve::BTC, LaunchCurve::QWEN}) {
                UniValue pair(UniValue::VARR);
                pair.push_back(ys.Count(curve).blocks);
                pair.push_back(ys.Count(curve).last_height);
                count.pushKV(LaunchCurveName(curve), std::move(pair));
            }
            o.pushKV("count", std::move(count));
            o.pushKV("graduated", LaunchGraduatedAt(tip, c));
            UniValue obligations(UniValue::VARR);
            const int from = step.size() > 1 ? step[1].getInt<int>() : 1;
            for (int h = std::max(from, 0); h <= tip->nHeight; ++h) obligations.push_back(ObligationOf(ys, idx[h].get(), c));
            o.pushKV("obligations", std::move(obligations));
            dumps.push_back(std::move(o));
        } else {
            throw std::runtime_error("unknown step " + kind);
        }
    }
    r.pushKV("ok", true);
    r.pushKV("dumps", std::move(dumps));
    return r;
}

} // namespace

UniValue RunSelfTest(const std::string& table, const std::string& vectors);

namespace {
UniValue SelfTest(const UniValue& req)
{
    return RunSelfTest(req.exists("table") ? req["table"].get_str() : std::string{}, req.exists("vectors") ? req["vectors"].get_str() : std::string{});
}
} // namespace

int main(int argc, char** argv)
{
    if (argc > 1 && std::strcmp(argv[1], "--selftest") == 0) {
        const char* table = std::getenv("QWORK_TABLE");
        const char* vectors = std::getenv("QWEN_VECTORS");
        const UniValue out = RunSelfTest(table ? table : "", vectors ? vectors : "");
        int failed{0}, skipped{0};
        for (const UniValue& check : out["checks"].getValues()) {
            const bool ok = check["ok"].get_bool(), skip = check["skipped"].get_bool();
            failed += !ok;
            skipped += skip;
            std::cout << (skip ? "skip " : ok ? "ok   " : "FAIL ") << check["name"].get_str();
            if (!check["detail"].get_str().empty()) std::cout << ": " << check["detail"].get_str();
            std::cout << "\n";
        }
        std::cout << out["checks"].size() << " checks, " << failed << " failed, " << skipped << " skipped\n";
        return failed ? 1 : 0;
    }
    std::string line;
    while (std::getline(std::cin, line)) {
        UniValue req, out;
        try {
            if (!req.read(line)) throw std::runtime_error("bad request json");
            const std::string& op = req["op"].get_str();
            // "work":"hash" on any request: for its duration a Qwencoin main-network header's work
            // value is its own SHA256d hash instead of a pass through the weights, so the tree's
            // other rules (the limit, the retarget, the period-edge timestamps, the budget) can be
            // compared on made-up chains with no table.
            struct StandIn {
                explicit StandIn(bool on) { if (on) launchyield::SetQwenWorkForTests(+[](const CPureBlockHeader& h) { return h.GetHash(); }); }
                ~StandIn() { launchyield::SetQwenWorkForTests(nullptr); }
            } stand_in{req.exists("work") && req["work"].get_str() == "hash"};
            out = op == "desc" ? Desc(req) : op == "chain" ? Chain(req) : op == "tail" ? Tail(req) :
                  op == "auxpow" ? AuxPow(req) : op == "yield" ? Yield(req) : op == "regouts" ? RegOuts(req) :
                  op == "proof" ? Proof(req) : op == "btc" ? Btc(req) : op == "qwork" ? Qwork(req) :
                  op == "state" ? State(req) : op == "selftest" ? SelfTest(req) : UniValue{};
            if (out.isNull()) throw std::runtime_error("unknown op " + op);
        } catch (const std::exception& e) {
            out = UniValue(UniValue::VOBJ);
            out.pushKV("ok", false);
            out.pushKV("exception", e.what());
        }
        std::cout << out.write() << "\n" << std::flush;
    }
}
