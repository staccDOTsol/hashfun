// Link stubs for symbols the consensus subset references but never calls here.
#include <node/blockstorage.h>
#include <util/check.h>
#include <util/log.h>

#include <cstdio>
#include <cstdlib>
#include <string>

bool node::BlockManager::ReadBlockHeader(CBlockHeader&, const CBlockIndex&) const { std::abort(); }
void util::log::Log(util::log::Entry) {}
std::string StrFormatFailedCheck(std::string_view assertion) { return std::string{assertion}; }
void internal_abort_helper(const std::source_location& loc, std::string_view msg)
{
    std::fprintf(stderr, "%s:%u: %.*s\n", loc.file_name(), unsigned(loc.line()), int(msg.size()), msg.data());
    std::abort();
}
