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
    uint32_t version{1};
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
    uint32_t ftl{60};
    std::array<unsigned char, 32> virtual_work_be{}; //!< V0, big-endian
    int64_t virtual_tokens{0};                        //!< T0, satoshis
    int64_t graduation_tokens{0};                     //!< G, satoshis
    int64_t tail_reward{0};                           //!< satoshis/block after graduation
    uint32_t tail_halving_interval{0};
    std::vector<unsigned char> creator_script;
    uint16_t creator_fee_bps{0};
    bool test{false};
    //! Optional anchor: a Bitcoin block header that existed when the descriptor
    //! was made. It is hashed into the launch id, so no block of this chain can
    //! predate that Bitcoin block, and it is the checkpoint the in-chain
    //! Bitcoin header relay starts from. period_time is the timestamp of the
    //! first block of the anchor's 2016-block difficulty period. Mandatory.
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
    std::vector<unsigned char> creator_btc_script;

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
