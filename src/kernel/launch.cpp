// Copyright (c) 2026 The hashfun developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/launch.h>

#include <arith_uint256.h>
#include <consensus/amount.h>
#include <crypto/hex_base.h>
#include <crypto/sha256.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <cstring>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>

namespace {

void PutU8(std::vector<unsigned char>& v, uint8_t x) { v.push_back(x); }
void PutU16(std::vector<unsigned char>& v, uint16_t x)
{
    v.push_back(x & 0xff);
    v.push_back(x >> 8);
}
void PutU32(std::vector<unsigned char>& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i) v.push_back((x >> (8 * i)) & 0xff);
}
void PutI64(std::vector<unsigned char>& v, int64_t x)
{
    const uint64_t u = static_cast<uint64_t>(x);
    for (int i = 0; i < 8; ++i) v.push_back((u >> (8 * i)) & 0xff);
}
void PutCompact(std::vector<unsigned char>& v, uint64_t n)
{
    if (n < 253) {
        PutU8(v, n);
    } else if (n <= 0xffff) {
        PutU8(v, 253);
        PutU16(v, n);
    } else if (n <= 0xffffffff) {
        PutU8(v, 254);
        PutU32(v, n);
    } else {
        PutU8(v, 255);
        PutI64(v, static_cast<int64_t>(n));
    }
}
void PutBytes(std::vector<unsigned char>& v, const unsigned char* p, size_t n)
{
    PutCompact(v, n);
    v.insert(v.end(), p, p + n);
}
void PutStr(std::vector<unsigned char>& v, const std::string& s)
{
    PutBytes(v, reinterpret_cast<const unsigned char*>(s.data()), s.size());
}

std::array<unsigned char, 32> Sha256(const std::vector<unsigned char>& data)
{
    std::array<unsigned char, 32> out;
    CSHA256().Write(data.data(), data.size()).Finalize(out.data());
    return out;
}

std::array<unsigned char, 32> TaggedDerive(const char* tag, const std::array<unsigned char, 32>& id)
{
    std::vector<unsigned char> v(tag, tag + strlen(tag));
    v.insert(v.end(), id.begin(), id.end());
    return Sha256(v);
}

std::optional<LaunchDescriptor> g_launch;

bool IsUpperAlnum(const std::string& s)
{
    for (char c : s) {
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) return false;
    }
    return true;
}
bool IsLowerAlnum(const std::string& s)
{
    for (char c : s) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) return false;
    }
    return true;
}

template <typename T>
bool GetUInt(const UniValue& o, const std::string& key, T& out, std::string& error, uint64_t maxv)
{
    const UniValue& v = o.find_value(key);
    if (v.isNull()) return true; // keep default
    int64_t x;
    if (v.isNum()) {
        // Fractions, exponents and values beyond int64 make getInt throw.
        try {
            x = v.getInt<int64_t>();
        } catch (const std::exception&) {
            error = strprintf("%s: expected integer", key);
            return false;
        }
    } else if (v.isStr()) {
        const std::string& s = v.get_str();
        auto parsed = (s.starts_with("0x") ? std::optional<int64_t>{} : ToIntegral<int64_t>(s));
        if (!parsed && s.starts_with("0x")) {
            if (s.size() == 2) {
                error = strprintf("%s: invalid hex", key);
                return false;
            }
            uint64_t acc = 0;
            for (size_t i = 2; i < s.size(); ++i) {
                const int d = HexDigit(s[i]);
                if (d < 0 || acc > (std::numeric_limits<uint64_t>::max() >> 4)) {
                    error = strprintf("%s: invalid hex", key);
                    return false;
                }
                acc = (acc << 4) | d;
            }
            if (acc > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
                error = strprintf("%s: out of range", key);
                return false;
            }
            parsed = static_cast<int64_t>(acc);
        }
        if (!parsed) {
            error = strprintf("%s: not an integer", key);
            return false;
        }
        x = *parsed;
    } else {
        error = strprintf("%s: expected integer", key);
        return false;
    }
    if (x < 0 || static_cast<uint64_t>(x) > maxv) {
        error = strprintf("%s: out of range", key);
        return false;
    }
    out = static_cast<T>(x);
    return true;
}

/** Strict hex bytes: absent/null keeps the default; otherwise a string of min_len..max_len bytes, hex digits only. */
bool GetHexBytes(const UniValue& o, const std::string& key, std::vector<unsigned char>& out, std::string& error, size_t min_len, size_t max_len)
{
    const UniValue& v = o.find_value(key);
    if (v.isNull()) return true;
    const std::string s = v.isStr() ? v.get_str() : std::string{"?"};
    if (s.size() % 2 != 0 || s.size() < 2 * min_len || s.size() > 2 * max_len || (!s.empty() && !IsHex(s))) {
        error = strprintf("%s: expected %d..%d bytes of hex", key, min_len, max_len);
        return false;
    }
    out = ParseHex(s);
    return true;
}

bool GetStr(const UniValue& o, const std::string& key, std::string& out, std::string& error, bool required)
{
    const UniValue& v = o.find_value(key);
    if (v.isNull()) {
        if (required) error = strprintf("%s: required", key);
        return !required;
    }
    if (!v.isStr()) {
        error = strprintf("%s: expected string", key);
        return false;
    }
    out = v.get_str();
    return true;
}

bool ParseUint256Decimal(const std::string& s, arith_uint256& out)
{
    out = 0;
    if (s.empty()) return false;
    if (s.size() > 2 && (s.starts_with("0x") || s.starts_with("0X"))) {
        if (s.size() - 2 > 64) return false;
        for (size_t i = 2; i < s.size(); ++i) {
            const int d = HexDigit(s[i]);
            if (d < 0) return false;
            out <<= 4;
            out += arith_uint256{static_cast<uint64_t>(d)};
        }
        return true;
    }
    const arith_uint256 maxv = ~arith_uint256{0};
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        const uint64_t d = c - '0';
        if (out > (maxv - arith_uint256{d}) / 10) return false;
        out *= 10;
        out += arith_uint256{d};
    }
    return true;
}

} // namespace

std::vector<unsigned char> LaunchCanonicalBytes(const LaunchDescriptor& d)
{
    std::vector<unsigned char> v;
    static const char tag[] = "hashfun-launch";
    v.insert(v.end(), tag, tag + sizeof(tag) - 1);
    PutU32(v, d.version);
    PutStr(v, d.name);
    PutStr(v, d.ticker);
    PutStr(v, d.hrp);
    PutU8(v, d.pubkey_prefix);
    PutU8(v, d.script_prefix);
    PutU8(v, d.secret_prefix);
    PutU32(v, d.genesis_time);
    PutU32(v, d.pow_limit_bits);
    PutU32(v, d.target_spacing);
    PutU32(v, d.lwma_window);
    PutU32(v, d.ftl);
    v.insert(v.end(), d.virtual_work_be.begin(), d.virtual_work_be.end());
    PutI64(v, d.virtual_tokens);
    PutI64(v, d.graduation_tokens);
    PutI64(v, d.tail_reward);
    PutU32(v, d.tail_halving_interval);
    PutBytes(v, d.creator_script.data(), d.creator_script.size());
    PutU16(v, d.creator_fee_bps);
    PutU8(v, d.test ? 1 : 0);
    PutU32(v, d.btc_anchor_height);
    v.insert(v.end(), d.btc_anchor_header.begin(), d.btc_anchor_header.end());
    PutU32(v, d.btc_anchor_period_time);
    PutI64(v, static_cast<int64_t>(d.sats_num));
    PutU32(v, d.sats_shift);
    PutI64(v, d.sats_min_payment);
    PutU32(v, d.settle_deadline);
    PutU32(v, d.btc_confs);
    PutBytes(v, d.creator_btc_script.data(), d.creator_btc_script.size());
    PutU8(v, d.btc_regtest ? 1 : 0);
    return v;
}

std::array<unsigned char, 32> ComputeLaunchId(const LaunchDescriptor& d)
{
    const auto first = Sha256(LaunchCanonicalBytes(d));
    return Sha256(std::vector<unsigned char>(first.begin(), first.end()));
}

std::string LaunchIdHex(const LaunchDescriptor& d)
{
    return HexStr(d.id);
}

std::optional<LaunchDescriptor> ParseLaunchDescriptor(const std::string& json, std::string& error)
{
    UniValue o;
    if (!o.read(json) || !o.isObject()) {
        error = "descriptor is not a JSON object";
        return std::nullopt;
    }
    LaunchDescriptor d;
    if (!GetUInt(o, "version", d.version, error, 0xffffffff)) return std::nullopt;
    if (d.version != 1) {
        error = "unsupported descriptor version";
        return std::nullopt;
    }
    if (!GetStr(o, "name", d.name, error, true)) return std::nullopt;
    if (!GetStr(o, "ticker", d.ticker, error, true)) return std::nullopt;
    d.hrp = ToLower(d.ticker);
    if (!GetStr(o, "hrp", d.hrp, error, false)) return std::nullopt;
    if (!GetUInt(o, "pubkey_prefix", d.pubkey_prefix, error, 255)) return std::nullopt;
    if (!GetUInt(o, "script_prefix", d.script_prefix, error, 255)) return std::nullopt;
    if (!GetUInt(o, "secret_prefix", d.secret_prefix, error, 255)) return std::nullopt;
    if (o.find_value("genesis_time").isNull()) {
        error = "genesis_time: required";
        return std::nullopt;
    }
    if (!GetUInt(o, "genesis_time", d.genesis_time, error, 0xffffffff)) return std::nullopt;
    if (!GetUInt(o, "genesis_nonce", d.genesis_nonce, error, 0xffffffff)) return std::nullopt;
    if (!GetUInt(o, "pow_limit_bits", d.pow_limit_bits, error, 0xffffffff)) return std::nullopt;
    if (!GetUInt(o, "target_spacing", d.target_spacing, error, 3600)) return std::nullopt;
    if (!GetUInt(o, "lwma_window", d.lwma_window, error, 1000)) return std::nullopt;
    if (!GetUInt(o, "ftl", d.ftl, error, 7200)) return std::nullopt;

    std::string vw;
    if (!GetStr(o, "virtual_work", vw, error, true)) return std::nullopt;
    arith_uint256 v0;
    if (!ParseUint256Decimal(vw, v0)) {
        error = "virtual_work: expected decimal or 0x-hex integer string";
        return std::nullopt;
    }
    for (int i = 0; i < 32; ++i) {
        d.virtual_work_be[31 - i] = static_cast<unsigned char>((v0 >> (8 * i)).GetLow64() & 0xff);
    }
    if (!GetUInt(o, "virtual_tokens", d.virtual_tokens, error, MAX_MONEY)) return std::nullopt;
    if (!GetUInt(o, "graduation_tokens", d.graduation_tokens, error, MAX_MONEY)) return std::nullopt;
    if (!GetUInt(o, "tail_reward", d.tail_reward, error, MAX_MONEY)) return std::nullopt;
    if (!GetUInt(o, "tail_halving_interval", d.tail_halving_interval, error, 0xffffffff)) return std::nullopt;
    std::string cs;
    if (!GetStr(o, "creator_script", cs, error, false)) return std::nullopt;
    auto csb = TryParseHex<unsigned char>(cs);
    if (!csb) {
        error = "creator_script: invalid hex";
        return std::nullopt;
    }
    d.creator_script = *csb;
    if (!GetUInt(o, "creator_fee_bps", d.creator_fee_bps, error, 1000)) return std::nullopt;
    {
        const UniValue& t = o.find_value("test");
        if (!t.isNull()) {
            if (!t.isBool()) {
                error = "test: expected bool";
                return std::nullopt;
            }
            d.test = t.get_bool();
        }
    }
    if (!GetUInt(o, "p2p_port", d.p2p_port, error, 65535)) return std::nullopt;
    if (!GetUInt(o, "rpc_port", d.rpc_port, error, 65535)) return std::nullopt;
    if (!GetUInt(o, "btc_anchor_height", d.btc_anchor_height, error, 0xffffffff)) return std::nullopt;
    {
        std::vector<unsigned char> hdr;
        if (!GetHexBytes(o, "btc_anchor_header", hdr, error, 80, 80)) return std::nullopt;
        if (!hdr.empty()) std::copy(hdr.begin(), hdr.end(), d.btc_anchor_header.begin());
    }
    if (!GetUInt(o, "btc_anchor_period_time", d.btc_anchor_period_time, error, 0xffffffff)) return std::nullopt;
    if (!GetUInt(o, "sats_num", d.sats_num, error, uint64_t{1} << 62)) return std::nullopt;
    if (!GetUInt(o, "sats_shift", d.sats_shift, error, 128)) return std::nullopt;
    if (!GetUInt(o, "sats_min_payment", d.sats_min_payment, error, MAX_MONEY)) return std::nullopt;
    if (!GetUInt(o, "settle_deadline", d.settle_deadline, error, 1000000)) return std::nullopt;
    if (!GetUInt(o, "btc_confs", d.btc_confs, error, 100)) return std::nullopt;
    if (!GetHexBytes(o, "creator_btc_script", d.creator_btc_script, error, 1, 80)) return std::nullopt;
    {
        const UniValue& t = o.find_value("btc_regtest");
        if (!t.isNull()) {
            if (!t.isBool()) {
                error = "btc_regtest: expected bool";
                return std::nullopt;
            }
            d.btc_regtest = t.get_bool();
        }
    }
    {
        const bool has_anchor = std::any_of(d.btc_anchor_header.begin(), d.btc_anchor_header.end(), [](unsigned char c) { return c != 0; });
        if ((d.btc_anchor_height != 0 || d.btc_anchor_period_time != 0) && !has_anchor) {
            error = "btc_anchor_header: required with btc_anchor_height / btc_anchor_period_time";
            return std::nullopt;
        }
        // Every launch has a sats leg: one kind of coin.
        if (d.sats_num == 0) {
            error = "sats_num: required (every launch has a sats leg)";
            return std::nullopt;
        }
        {
            if (!has_anchor) {
                error = "btc_anchor_header: required";
                return std::nullopt;
            }
            if (d.creator_btc_script.empty()) {
                error = "creator_btc_script: required";
                return std::nullopt;
            }
            if (d.sats_min_payment < 546) {
                error = "sats_min_payment: at least 546";
                return std::nullopt;
            }
            if (d.settle_deadline < 110) {
                error = "settle_deadline: at least 110 blocks";
                return std::nullopt;
            }
            if (d.btc_confs < 1) {
                error = "btc_confs: at least 1";
                return std::nullopt;
            }
        }
    }
    {
        const UniValue& s = o.find_value("seeds");
        if (!s.isNull()) {
            if (!s.isArray()) {
                error = "seeds: expected array of strings";
                return std::nullopt;
            }
            for (const auto& e : s.getValues()) {
                if (!e.isStr()) {
                    error = "seeds: expected array of strings";
                    return std::nullopt;
                }
                d.seeds.push_back(e.get_str());
            }
        }
    }

    // ---- validation ----
    if (d.name.empty() || d.name.size() > 64) {
        error = "name: 1..64 chars";
        return std::nullopt;
    }
    if (d.ticker.size() < 2 || d.ticker.size() > 10 || !IsUpperAlnum(d.ticker)) {
        error = "ticker: 2..10 chars [A-Z0-9]";
        return std::nullopt;
    }
    static const std::set<std::string> reserved_hrps{"bc", "tb", "bcrt", "ltc", "tltc", "rltc", "nc", "tn", "ncrt"};
    if (d.hrp.empty() || d.hrp.size() > 20 || !IsLowerAlnum(d.hrp) || reserved_hrps.contains(d.hrp)) {
        error = "hrp: 1..20 chars [a-z0-9], not a Bitcoin/Litecoin/Namecoin hrp";
        return std::nullopt;
    }
    static const std::set<int> btc_prefixes{0, 5, 111, 196};
    if (d.pubkey_prefix == d.script_prefix || btc_prefixes.contains(d.pubkey_prefix) || btc_prefixes.contains(d.script_prefix)) {
        error = "pubkey_prefix/script_prefix: must differ from each other and from Bitcoin's";
        return std::nullopt;
    }
    {
        arith_uint256 lim;
        bool neg, ovf;
        lim.SetCompact(d.pow_limit_bits, &neg, &ovf);
        if (neg || ovf || lim == 0) {
            error = "pow_limit_bits: invalid compact target";
            return std::nullopt;
        }
    }
    // Block times are whole seconds and LWMA counts every solvetime as at least 1 s, so with
    // T = 1 no window can ever look faster than the target and difficulty could never rise.
    if (d.target_spacing < 2) {
        error = "target_spacing: 2..3600";
        return std::nullopt;
    }
    if (d.lwma_window < 3) {
        error = "lwma_window: 3..1000";
        return std::nullopt;
    }
    if (d.ftl < 1) {
        error = "ftl: 1..7200";
        return std::nullopt;
    }
    if (v0 == 0 || v0 > (arith_uint256{1} << 160)) {
        error = "virtual_work: must be in (0, 2^160]";
        return std::nullopt;
    }
    if (d.virtual_tokens <= 0 || d.graduation_tokens <= 0 || d.graduation_tokens >= d.virtual_tokens) {
        error = "need 0 < graduation_tokens < virtual_tokens";
        return std::nullopt;
    }
    if (d.virtual_tokens - d.graduation_tokens < d.virtual_tokens / 1000) {
        error = "graduation_tokens may be at most 99.9% of virtual_tokens";
        return std::nullopt;
    }
    if (d.tail_reward > 0 && d.tail_halving_interval == 0) {
        error = "tail_halving_interval: required when tail_reward > 0";
        return std::nullopt;
    }
    {
        // Max total = G + tail_reward * interval * 2 (geometric halvings). 256-bit, no overflow, portable (no __int128 on MSVC).
        const arith_uint256 tail_total = arith_uint256{static_cast<uint64_t>(d.tail_reward)} * arith_uint256{d.tail_halving_interval} * 2;
        if (arith_uint256{static_cast<uint64_t>(d.graduation_tokens)} + tail_total > arith_uint256{static_cast<uint64_t>(MAX_MONEY)}) {
            error = "graduation_tokens + total tail emission exceeds MAX_MONEY";
            return std::nullopt;
        }
    }
    if (d.creator_script.size() > 100) {
        error = "creator_script: at most 100 bytes";
        return std::nullopt;
    }
    if (d.creator_fee_bps > 0 && d.creator_script.empty()) {
        error = "creator_script: required when creator_fee_bps > 0";
        return std::nullopt;
    }
    d.id = ComputeLaunchId(d);
    return d;
}

LaunchDescriptor ReadLaunchDescriptorFile(const std::string& path)
{
    std::ifstream f(path);
    if (!f.good()) {
        throw std::runtime_error(strprintf("cannot read launch descriptor %s", path));
    }
    std::stringstream ss;
    ss << f.rdbuf();
    std::string error;
    auto d = ParseLaunchDescriptor(ss.str(), error);
    if (!d) {
        throw std::runtime_error(strprintf("invalid launch descriptor %s: %s", path, error));
    }
    return *d;
}

std::string LaunchDescriptorToJSON(const LaunchDescriptor& d)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("version", static_cast<int64_t>(d.version));
    o.pushKV("name", d.name);
    o.pushKV("ticker", d.ticker);
    o.pushKV("hrp", d.hrp);
    o.pushKV("pubkey_prefix", d.pubkey_prefix);
    o.pushKV("script_prefix", d.script_prefix);
    o.pushKV("secret_prefix", d.secret_prefix);
    o.pushKV("genesis_time", static_cast<int64_t>(d.genesis_time));
    o.pushKV("genesis_nonce", static_cast<int64_t>(d.genesis_nonce));
    o.pushKV("pow_limit_bits", strprintf("0x%08x", d.pow_limit_bits));
    o.pushKV("target_spacing", static_cast<int64_t>(d.target_spacing));
    o.pushKV("lwma_window", static_cast<int64_t>(d.lwma_window));
    o.pushKV("ftl", static_cast<int64_t>(d.ftl));
    o.pushKV("virtual_work", "0x" + HexStr(d.virtual_work_be));
    o.pushKV("virtual_tokens", d.virtual_tokens);
    o.pushKV("graduation_tokens", d.graduation_tokens);
    o.pushKV("tail_reward", d.tail_reward);
    o.pushKV("tail_halving_interval", static_cast<int64_t>(d.tail_halving_interval));
    o.pushKV("creator_script", HexStr(d.creator_script));
    o.pushKV("creator_fee_bps", static_cast<int64_t>(d.creator_fee_bps));
    o.pushKV("test", d.test);
    o.pushKV("btc_anchor_height", static_cast<int64_t>(d.btc_anchor_height));
    o.pushKV("btc_anchor_header", HexStr(d.btc_anchor_header));
    o.pushKV("btc_anchor_period_time", static_cast<int64_t>(d.btc_anchor_period_time));
    o.pushKV("sats_num", static_cast<int64_t>(d.sats_num));
    o.pushKV("sats_shift", static_cast<int64_t>(d.sats_shift));
    o.pushKV("sats_min_payment", d.sats_min_payment);
    o.pushKV("settle_deadline", static_cast<int64_t>(d.settle_deadline));
    o.pushKV("btc_confs", static_cast<int64_t>(d.btc_confs));
    if (!d.creator_btc_script.empty()) o.pushKV("creator_btc_script", HexStr(d.creator_btc_script));
    o.pushKV("btc_regtest", d.btc_regtest);
    o.pushKV("p2p_port", static_cast<int64_t>(LaunchP2PPort(d)));
    o.pushKV("rpc_port", static_cast<int64_t>(LaunchRPCPort(d)));
    UniValue seeds(UniValue::VARR);
    for (const auto& s : d.seeds) seeds.push_back(s);
    o.pushKV("seeds", std::move(seeds));
    o.pushKV("launch_id", HexStr(d.id));
    return o.write(2);
}

std::array<unsigned char, 4> LaunchMessageStart(const LaunchDescriptor& d)
{
    const auto h = TaggedDerive("hashfun-magic", d.id);
    return {static_cast<unsigned char>(h[0] | 0x80), static_cast<unsigned char>(h[1] | 0x80),
            static_cast<unsigned char>(h[2] | 0x80), static_cast<unsigned char>(h[3] | 0x80)};
}

int32_t LaunchChainId(const LaunchDescriptor& d)
{
    const auto h = TaggedDerive("hashfun-chainid", d.id);
    const uint32_t v = h[0] | (static_cast<uint32_t>(h[1]) << 8);
    int32_t cid = static_cast<int32_t>(v % 0x1FFE) + 1; // 1..0x1FFE: below any BIP9-style parent version
    // Avoid chain IDs already used by live merge-mined chains (Namecoin, Dogecoin, Syscoin).
    if (cid == 1 || cid == 98 || cid == 4096) ++cid;
    return cid;
}

uint16_t LaunchP2PPort(const LaunchDescriptor& d)
{
    if (d.p2p_port) return d.p2p_port;
    const auto h = TaggedDerive("hashfun-port", d.id);
    const uint32_t v = h[0] | (static_cast<uint32_t>(h[1]) << 8);
    return static_cast<uint16_t>(20000 + (v % 10000) * 2);
}

uint16_t LaunchRPCPort(const LaunchDescriptor& d)
{
    if (d.rpc_port) return d.rpc_port;
    return LaunchP2PPort(d) + 1;
}

std::string LaunchDataDirName(const LaunchDescriptor& d)
{
    return "launch_" + ToLower(d.ticker) + "_" + HexStr(d.id).substr(0, 8);
}

const std::optional<LaunchDescriptor>& GetGlobalLaunch() { return g_launch; }
void SetGlobalLaunch(const LaunchDescriptor& d) { g_launch = d; }
