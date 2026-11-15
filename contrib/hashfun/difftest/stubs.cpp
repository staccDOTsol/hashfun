// Link stubs for symbols the consensus subset references but never calls here.
#include <node/blockstorage.h>
#include <util/check.h>
#include <util/hasher.h>
#include <util/log.h>

#include <cstdio>
#include <cstdlib>
#include <string>

bool node::BlockManager::ReadBlockHeader(CBlockHeader&, const CBlockIndex&) const { std::abort(); }
// The sats-leg state reads blocks back only in Sync(), which the driver never calls: it connects the blocks it is given.
bool node::BlockManager::ReadBlock(CBlock&, const CBlockIndex&) const { std::abort(); }
// The state's index of live coins is never iterated, so a fixed salt changes no answer (the node draws a random one).
SaltedOutpointHasher::SaltedOutpointHasher() : m_hasher{0x6866646966660001ULL, 0x6866646966660002ULL} {}
void util::log::Log(util::log::Entry) {}
bool util::log::ShouldDebugLog(util::log::Category) { return false; }
std::string StrFormatFailedCheck(std::string_view assertion) { return std::string{assertion}; }
void internal_abort_helper(const std::source_location& loc, std::string_view msg)
{
    std::fprintf(stderr, "%s:%u: %.*s\n", loc.file_name(), unsigned(loc.line()), int(msg.size()), msg.data());
    std::abort();
}
