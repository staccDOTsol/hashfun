// Copyright (c) 2026 The hashfun developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_LAUNCH_H
#define BITCOIN_KERNEL_LAUNCH_H

#include <uint256.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

//! The descriptor format this node reads. It is hashed into the launch id and names the rule
//! set the launch runs under, so a file made for one rule set is never read under another:
//! 1 = the pre-release rules: the first sats leg, whose holder draw has been replaced, read by
//!     a parser that took anchors, payout scripts and time limits it should have refused;
//! 2 = the sats leg drawn over live coins, and the stricter parser below.
inline constexpr uint32_t LAUNCH_DESCRIPTOR_VERSION = 2;

//! The future-time limit (ftl: how far past a node's clock a block may be stamped) of a launch
//! that is not a test launch must be at least LAUNCH_MIN_FTL seconds and less than
//! 6 * target_spacing. The upper side is the difficulty rule's own unit: src/pow.cpp doubles the
//! target for every full 6T a block's stamp sits past its parent's and caps every solvetime at
//! 6T, so a stamp that may run 6T ahead buys a relief step (or a capped solvetime) with no
//! time passing. The lower side is ordinary clock disagreement between honest machines: a few
//! seconds must never make one of them refuse the other's block. 10 is also the largest round
//! floor that leaves every legal spacing a choice (target_spacing >= 2 gives 6T - 1 >= 11).
inline constexpr uint32_t LAUNCH_MIN_FTL = 10;
inline constexpr uint32_t LAUNCH_MAX_FTL = 7200;
/** The ftl of a descriptor that names none: min(6T - 1, 7200, max(10, N * T / 20)). In range for
 *  every legal (target_spacing, lwma_window). hashfun/descriptor.py default_ftl is the same. */
uint32_t LaunchDefaultFtl(uint32_t target_spacing, uint32_t lwma_window);

/**
 * A launch descriptor fully defines a hashfun chain. One universal node
 * binary boots any launch from its descriptor (-launch=<file.json>).
 *
 * The launch id is SHA256d over a canonical binary serialization of every
 * consensus-relevant field (everything except genesis_nonce, ports and
 * seeds). The id is committed in the genesis coinbase, so the genesis hash
 * identifies both the descriptor and the mined genesis.
 */
struct LaunchDescriptor {
    uint32_t version{LAUNCH_DESCRIPTOR_VERSION};
    std::string name;
    std::string ticker;
    std::string hrp;
    uint8_t pubkey_prefix{40};
    uint8_t script_prefix{100};
    uint8_t secret_prefix{168};
    uint32_t genesis_time{0};
    uint32_t genesis_nonce{0};
    uint32_t pow_limit_bits{0x1d00ffff};
    uint32_t target_spacing{5};
    uint32_t lwma_window{90};
    uint32_t ftl{22}; //!< LaunchDefaultFtl(5, 90); the parser computes it from the two above when the file names none
    std::array<unsigned char, 32> virtual_work_be{}; //!< V0, big-endian
    int64_t virtual_tokens{0};                        //!< T0, satoshis
    int64_t graduation_tokens{0};                     //!< G, satoshis
    int64_t tail_reward{0};                           //!< satoshis/block after graduation
    uint32_t tail_halving_interval{0};                //!< blocks, < 2^31 (it becomes an int in the chain parameters)
    std::vector<unsigned char> creator_script;
    uint16_t creator_fee_bps{0};
    bool test{false};
    //! The anchor: a Bitcoin block header that existed when the descriptor was made. It is
    //! hashed into the launch id, so no block of this chain can predate that Bitcoin block, and
    //! it is the checkpoint the in-chain Bitcoin header relay starts from. period_time is the
    //! timestamp of the first block of the anchor's 2016-block difficulty period. Mandatory.
    //! Unless btc_regtest, the parser requires what it can check without a Bitcoin chain: the
    //! header meets its own difficulty, that difficulty is no easier than Bitcoin's minimum, the
    //! period start is set, is not later than the anchor allows, and is the anchor's own time
    //! when the anchor opens a period. Whether the header really is the block at that height is
    //! for a Bitcoin node to say (hashfun/descriptor.py check_anchor). height < 2^31.
    uint32_t btc_anchor_height{0};
    std::array<unsigned char, 80> btc_anchor_header{};
    uint32_t btc_anchor_period_time{0};
    //! Sats leg: a curve block owes (work * sats_num) >> sats_shift satoshis of
    //! real BTC, paid on Bitcoin to a drawn recipient (80% holders, 10% creator,
    //! 10% dev) and proven here before settle_deadline blocks. Mandatory (> 0).
    uint64_t sats_num{0};
    uint32_t sats_shift{0};
    int64_t sats_min_payment{10000};
    uint32_t settle_deadline{720};
    uint32_t btc_confs{1};
    //! Where the creator's share is paid on Bitcoin. Must be a script form that earns
    //! (launchyield::EarnsYield: P2PKH, P2SH or a witness program): every miner whose block
    //! draws the creator has to get a Bitcoin payment to it relayed, or loses the block.
    std::vector<unsigned char> creator_btc_script;
    //! Which Bitcoin the sats leg follows: mainnet rules (false) or regtest (true, for
    //! test fleets). Independent of `test`, which only relaxes mining RPC checks.
    bool btc_regtest{false};
    //! SHA256 of the launch's metadata (image, description, links; see hashfun/meta.py). The
    //! bytes themselves ride in the launch file under "metadata" and are not read by the node.
    //! All zero = none. Appended to the canonical bytes only when set, so a launch without
    //! metadata hashes exactly as it did before this field existed.
    std::array<unsigned char, 32> meta{};

    // Not part of the launch id.
    uint16_t p2p_port{0};
    uint16_t rpc_port{0};
    std::vector<std::string> seeds;

    //! Computed: SHA256d(canonical bytes), raw hash byte order.
    std::array<unsigned char, 32> id{};
};

/** Canonical serialization hashed into the launch id. */
std::vector<unsigned char> LaunchCanonicalBytes(const LaunchDescriptor& d);
std::array<unsigned char, 32> ComputeLaunchId(const LaunchDescriptor& d);
std::string LaunchIdHex(const LaunchDescriptor& d);

/** Parse + validate a descriptor from JSON text. Computes id. */
std::optional<LaunchDescriptor> ParseLaunchDescriptor(const std::string& json, std::string& error);
/** Read + parse a descriptor file. Throws std::runtime_error on failure. */
LaunchDescriptor ReadLaunchDescriptorFile(const std::string& path);
/** Serialize back to JSON text (all fields, incl. computed id). */
std::string LaunchDescriptorToJSON(const LaunchDescriptor& d);

std::array<unsigned char, 4> LaunchMessageStart(const LaunchDescriptor& d);
int32_t LaunchChainId(const LaunchDescriptor& d);
uint16_t LaunchP2PPort(const LaunchDescriptor& d);
uint16_t LaunchRPCPort(const LaunchDescriptor& d);
std::string LaunchDataDirName(const LaunchDescriptor& d);

/** Process-wide descriptor, set once by -launch handling. */
const std::optional<LaunchDescriptor>& GetGlobalLaunch();
void SetGlobalLaunch(const LaunchDescriptor& d);

#endif // BITCOIN_KERNEL_LAUNCH_H
