#include "mempool_writer.h"
#include "txmempool.h"
#include "validation.h"
#include "logging.h"

void WriteMemPoolBeforeBlock()
{
    auto mempool_vec = mempool.infoAll();
    LogPrintf("mempool size=%u\n", mempool_vec.size());
}
