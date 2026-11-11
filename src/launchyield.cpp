// Copyright (c) 2026 The hashfun developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <launchyield.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <script/script.h>
#include <streams.h>

#include <algorithm>
#include <cstring>

namespace launchyield {
namespace {

uint256 Sha256Of(std::initializer_list<std::span<const unsigned char>> parts, bool twice)
{
    uint256 out;
    CSHA256 h;
    for (const auto& p : parts) h.Write(p.data(), p.size());
    h.Finalize(out.begin());
    if (twice) CSHA256().Write(out.begin(), 32).Finalize(out.begin());
    return out;
}

std::span<const unsigned char> Tag(const char* s)
{
    return {reinterpret_cast<const unsigned char*>(s), strlen(s)};
}

arith_uint256 TargetFromBits(uint32_t bits, bool& ok)
{
    arith_uint256 target;
    bool neg, ovf;
    target.SetCompact(bits, &neg, &ovf);
    ok = !neg && !ovf && target != 0;
    return target;
}

const uint32_t BTC_POW_LIMIT_BITS = 0x1d00ffff;
const uint32_t BTC_REGTEST_BITS = 0x207fffff;
const int64_t BTC_TIMESPAN = 14 * 24 * 60 * 60;
const int BTC_INTERVAL = 2016;

} // namespace

CAmount Owed(const arith_uint256& work, uint64_t num, uint32_t shift)
{
    if (num == 0 || work == 0) return 0;
    if (shift >= 256) return 0;
    // work * num must not wrap: num < 2^63.
    if (work > (~arith_uint256{0} >> 63)) return MAX_MONEY;
    const arith_uint256 v = (work * arith_uint256{num}) >> shift;
    if (v > arith_uint256{static_cast<uint64_t>(MAX_MONEY)}) return MAX_MONEY;
    return static_cast<CAmount>(v.GetLow64());
}

uint256 DrawSeed(const uint256& launch_id, const uint256& seed_block_hash)
{
    return Sha256Of({Tag("hashfun-draw"), {launch_id.begin(), 32}, {seed_block_hash.begin(), 32}}, /*twice=*/true);
}

Draw ComputeDraw(CAmount owed, CAmount min_payment, const uint256& seed)
{
    Draw d;
    if (owed <= 0) {
        d.pay = 0;
    } else if (owed >= min_payment) {
        d.pay = owed;
    } else if (ReadLE64(seed.begin()) % static_cast<uint64_t>(min_payment) < static_cast<uint64_t>(owed)) {
        d.pay = min_payment;
    }
    const uint64_t r = ReadLE64(seed.begin() + 8) % 10000;
    d.payee = r < HOLDER_BPS ? Payee::HOLDER : r < HOLDER_BPS + CREATOR_BPS ? Payee::CREATOR : Payee::DEV;
    return d;
}

arith_uint256 CandidatePoint(const uint256& seed, int i, const arith_uint256& registered_total)
{
    unsigned char idx[5] = {'c'};
    WriteLE32(idx + 1, static_cast<uint32_t>(i));
    const arith_uint256 x = UintToArith256(Sha256Of({{seed.begin(), 32}, {idx, 5}}, /*twice=*/false));
    return x - (x / registered_total) * registered_total;
}

std::array<unsigned char, 20> PayTag(const uint256& launch_id, const uint256& mint_block_hash)
{
    const uint256 h = Sha256Of({Tag("hashfun-pay"), {launch_id.begin(), 32}, {mint_block_hash.begin(), 32}}, /*twice=*/false);
    std::array<unsigned char, 20> out;
    std::copy(h.begin(), h.begin() + 20, out.begin());
    return out;
}

std::optional<std::vector<unsigned char>> TaggedReturn(const CScript& script, std::string_view tag)
{
    if (script.empty() || script[0] != OP_RETURN) return std::nullopt;
    CScript::const_iterator pc = script.begin() + 1;
    opcodetype op;
    std::vector<unsigned char> data;
    if (!script.GetOp(pc, op, data) || op > OP_PUSHDATA4 || pc != script.end()) return std::nullopt;
    if (data.size() < tag.size() || !std::equal(tag.begin(), tag.end(), data.begin())) return std::nullopt;
    return data;
}

bool EarnsYield(const CScript& s)
{
    const size_t n = s.size();
    if (n == 25 && s[0] == OP_DUP && s[1] == OP_HASH160 && s[2] == 20 && s[23] == OP_EQUALVERIFY && s[24] == OP_CHECKSIG) return true;
    if (n == 23 && s[0] == OP_HASH160 && s[1] == 20 && s[22] == OP_EQUAL) return true;
    return n >= 4 && n <= 42 && (s[0] == OP_0 || (s[0] >= OP_1 && s[0] <= OP_16)) && s[1] == n - 2;
}

std::vector<RegOut> RegisteredOutputs(const CTransaction& tx)
{
    std::vector<RegOut> out;
    // Only a coinbase may redirect, and only its output 0: the miner made that output and owns it.
    // Anywhere else the transaction's author is not the owner of every output, and a redirect
    // would let a payer keep the yield of coins he pays to someone else. The first HFY1 output
    // decides, and only if what it names is itself a script that earns: every miner whose block
    // draws this coin has to be able to relay a Bitcoin payment to it.
    std::vector<unsigned char> redirect;
    if (tx.IsCoinBase()) {
        for (const CTxOut& o : tx.vout) {
            if (auto data = TaggedReturn(o.scriptPubKey, "HFY1")) {
                if (EarnsYield(CScript(data->begin() + 4, data->end()))) redirect.assign(data->begin() + 4, data->end());
                break;
            }
        }
    }
    for (uint32_t i = 0; i < tx.vout.size(); ++i) {
        const CTxOut& o = tx.vout[i];
        if (o.nValue <= 0 || !EarnsYield(o.scriptPubKey)) continue;
        const bool redirected = !redirect.empty() && i == 0;
        out.push_back({i, o.nValue, redirected ? redirect : std::vector<unsigned char>(o.scriptPubKey.begin(), o.scriptPubKey.end())});
    }
    return out;
}

std::optional<PaymentProof> ParsePaymentProof(std::span<const unsigned char> p)
{
    // "HFP1" | u32 mint_height | 32 btc_block | u32 tx_index | u8 n | n*32 branch | u32 pay_vout | u8 candidate | raw tx
    if (p.size() < 4 + 4 + 32 + 4 + 1) return std::nullopt;
    PaymentProof r;
    size_t off = 4;
    r.mint_height = ReadLE32(p.data() + off); off += 4;
    std::copy(p.begin() + off, p.begin() + off + 32, r.btc_block.begin()); off += 32;
    r.tx_index = ReadLE32(p.data() + off); off += 4;
    const size_t n = p[off++];
    if (n > 32 || p.size() < off + 32 * n + 4 + 1) return std::nullopt;
    for (size_t i = 0; i < n; ++i) {
        uint256 h;
        std::copy(p.begin() + off, p.begin() + off + 32, h.begin());
        r.branch.push_back(h);
        off += 32;
    }
    r.pay_vout = ReadLE32(p.data() + off); off += 4;
    r.candidate = p[off++];
    r.raw_tx.assign(p.begin() + off, p.end());
    return r;
}

bool VerifyBtcPayment(const PaymentProof& proof, const uint256& merkle_root, const std::array<unsigned char, 20>& tag,
                      const std::vector<unsigned char>& recipient_script, CAmount pay, std::string& error)
{
    // A 64-byte "transaction" is indistinguishable from an inner merkle node.
    if (proof.raw_tx.size() < 60 || proof.raw_tx.size() == 64 || proof.raw_tx.size() > 100000) {
        error = "btc tx size";
        return false;
    }
    CMutableTransaction tx;
    try {
        DataStream ss{proof.raw_tx};
        ss >> TX_NO_WITNESS(tx);
        if (!ss.empty()) throw std::ios_base::failure("trailing bytes");
    } catch (const std::exception&) {
        error = "btc tx does not parse (must be serialized without witness)";
        return false;
    }
    if (tx.vin.empty() || tx.vout.empty()) {
        error = "btc tx has no inputs or outputs";
        return false;
    }
    if (proof.branch.size() < 32 && (proof.tx_index >> proof.branch.size()) != 0) {
        error = "btc tx index outside the merkle tree";
        return false;
    }
    uint256 h = Hash(proof.raw_tx);
    uint32_t idx = proof.tx_index;
    for (const uint256& sib : proof.branch) {
        h = (idx & 1) ? Hash(sib, h) : Hash(h, sib);
        idx >>= 1;
    }
    if (h != merkle_root) {
        error = "btc merkle proof does not match the block";
        return false;
    }
    if (proof.pay_vout >= tx.vout.size()) {
        error = "btc pay output missing";
        return false;
    }
    const CTxOut& out = tx.vout[proof.pay_vout];
    if (out.nValue < pay || !std::equal(out.scriptPubKey.begin(), out.scriptPubKey.end(), recipient_script.begin(), recipient_script.end())) {
        error = "btc output does not pay the drawn recipient enough";
        return false;
    }
    // One tag list per transaction: the first OP_RETURN "HF" output, and no other. Position i of
    // that list binds output i to one mint block. If later lists counted too, one output could
    // carry a tag from each of them and settle that many blocks with a single payment.
    for (const CTxOut& o : tx.vout) {
        const auto data = TaggedReturn(o.scriptPubKey, "HF");
        if (!data) continue;
        const size_t pos = 2 + size_t{20} * proof.pay_vout;
        if ((data->size() - 2) % 20 == 0 && data->size() >= pos + 20 && std::equal(tag.begin(), tag.end(), data->begin() + pos)) return true;
        break;
    }
    error = "btc tx does not bind this output to the mint block";
    return false;
}

std::optional<std::vector<CPureBlockHeader>> ParseBtcHeaders(std::span<const unsigned char> p)
{
    if (p.size() < 4 + 80 || (p.size() - 4) % 80 != 0) return std::nullopt;
    std::vector<CPureBlockHeader> out;
    DataStream ss{p.subspan(4)};
    while (!ss.empty()) {
        CPureBlockHeader h;
        ss >> h;
        out.push_back(h);
    }
    return out;
}

void BtcChain::Init(const CPureBlockHeader& anchor, int anchor_height, uint32_t anchor_period_time, bool regtest)
{
    m_nodes.clear();
    m_children.clear();
    m_order.clear();
    m_regtest = regtest;
    m_anchor_height = anchor_height;
    m_anchor = anchor.GetHash();
    Node n;
    n.prev = anchor.hashPrevBlock;
    n.merkle_root = anchor.hashMerkleRoot;
    n.time = anchor.nTime;
    n.bits = anchor.nBits;
    n.height = anchor_height;
    n.work = 0; // work is counted from the anchor
    // An anchor that opens a difficulty period is its own period start; otherwise the first
    // block of its period is below it and the descriptor supplies that block's time.
    n.period_time = anchor_height % BTC_INTERVAL == 0 ? anchor.nTime : anchor_period_time;
    m_nodes.emplace(m_anchor, n);
    m_order.emplace(n.work, m_anchor);
    m_best = m_anchor;
    m_main.assign(1, m_anchor);
}

const BtcChain::Node* BtcChain::Find(const uint256& hash) const
{
    const auto it = m_nodes.find(hash);
    return it == m_nodes.end() ? nullptr : &it->second;
}

int BtcChain::BestHeight() const
{
    const Node* n = Find(m_best);
    return n ? n->height : -1;
}

uint32_t BtcChain::ExpectedBits(const Node& prev) const
{
    if (m_regtest) return BTC_REGTEST_BITS;
    const int height = prev.height + 1;
    if (height % BTC_INTERVAL != 0) return prev.bits;
    // prev closes its period; every header carries the time of its period's first block, so
    // this costs the same at a retarget as anywhere else (no walk down the chain).
    const int64_t first_time = prev.period_time;
    int64_t timespan = int64_t{prev.time} - first_time;
    timespan = std::clamp<int64_t>(timespan, BTC_TIMESPAN / 4, BTC_TIMESPAN * 4);
    bool ok;
    const arith_uint256 limit = TargetFromBits(BTC_POW_LIMIT_BITS, ok);
    arith_uint256 target = TargetFromBits(prev.bits, ok);
    target *= static_cast<uint32_t>(timespan);
    target /= static_cast<uint32_t>(BTC_TIMESPAN);
    if (target > limit) target = limit;
    return target.GetCompact();
}

void BtcChain::UpdateMain()
{
    // Walk down from the best tip until the old best chain is met, and rewrite only what is above.
    std::vector<uint256> path;
    uint256 cur = m_best;
    const Node* n = &m_nodes.at(cur);
    for (;;) {
        const size_t i = static_cast<size_t>(n->height - m_anchor_height);
        if (i < m_main.size() && m_main[i] == cur) break;
        path.push_back(cur);
        if (cur == m_anchor) break;
        cur = n->prev;
        n = &m_nodes.at(cur);
    }
    m_main.resize(static_cast<size_t>(m_nodes.at(m_best).height - m_anchor_height) + 1 - path.size());
    m_main.insert(m_main.end(), path.rbegin(), path.rend());
}

bool BtcChain::Accept(const CPureBlockHeader& header, std::string& error)
{
    const uint256 hash = header.GetHash();
    if (m_nodes.count(hash)) {
        error = "btc header already known";
        return false;
    }
    const Node* prev = Find(header.hashPrevBlock);
    if (!prev) {
        error = "btc header does not connect";
        return false;
    }
    if (header.nBits != ExpectedBits(*prev)) {
        error = "btc header has wrong difficulty";
        return false;
    }
    bool ok;
    const arith_uint256 target = TargetFromBits(header.nBits, ok);
    if (!ok || UintToArith256(hash) > target) {
        error = "btc header lacks proof of work";
        return false;
    }
    // Median of the last 11 timestamps. Within 11 blocks of the anchor the true median is
    // unknowable (it needs headers below the anchor), and Bitcoin timestamps are not monotonic,
    // so the rule is only enforced once all 11 are in the tree.
    std::vector<uint32_t> times;
    for (const Node* n = prev; n && times.size() < 11; n = Find(n->prev)) times.push_back(n->time);
    std::sort(times.begin(), times.end());
    if (times.size() == 11 && header.nTime <= times[5]) {
        error = "btc header time is not past the median";
        return false;
    }
    Node n;
    n.prev = header.hashPrevBlock;
    n.merkle_root = header.hashMerkleRoot;
    n.time = header.nTime;
    n.bits = header.nBits;
    n.height = prev->height + 1;
    n.work = prev->work + (~target / (target + 1)) + 1;
    n.period_time = n.height % BTC_INTERVAL == 0 ? header.nTime : prev->period_time;
    m_nodes.emplace(hash, n);
    m_order.emplace(n.work, hash);
    ++m_children[header.hashPrevBlock];
    if (m_order.begin()->second != m_best) {
        m_best = m_order.begin()->second;
        UpdateMain();
    }
    return true;
}

void BtcChain::Remove(const uint256& hash)
{
    const auto it = m_nodes.find(hash);
    if (it == m_nodes.end() || hash == m_anchor || m_children.count(hash)) return;
    const uint256 prev = it->second.prev;
    m_order.erase({it->second.work, hash});
    m_nodes.erase(it);
    if (--m_children[prev] == 0) m_children.erase(prev);
    if (hash == m_best) {
        m_best = m_order.begin()->second;
        UpdateMain();
    }
}

int BtcChain::Confirmations(const uint256& hash) const
{
    const Node* n = Find(hash);
    if (!n) return 0;
    const size_t i = static_cast<size_t>(n->height - m_anchor_height);
    if (i >= m_main.size() || m_main[i] != hash) return 0;
    return static_cast<int>(m_main.size() - i);
}

} // namespace launchyield
