#include "mempool_writer.h"
#include "txmempool.h"
#include "validation.h"
#include "logging.h"

void WriteMemPoolBeforeBlock()
{
    LogPrintf("Writing mempool contents");
    LogPrintf("txid total_fee virtual_size ancestor [ancestor... etc]\n");
    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    for (; mi != mempool.mapTx.get<ancestor_score>().end(); ++mi) {
        const CTxMemPoolEntry &entry = *mi;
        LogPrintf("%s %ld %ld", entry.GetTx().GetHash().ToString(), entry.GetModifiedFee(), entry.GetTxWeight());
        CTxMemPool::setEntries setAncestors;
        uint64_t noLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        mempool.CalculateMemPoolAncestors(entry, setAncestors, noLimit, noLimit, noLimit, noLimit, dummy, false);
        for (CTxMemPool::txiter ancestorIt : setAncestors) {
            LogPrintf(" %s", ancestorIt->GetTx().GetHash().ToString());
        }
        LogPrintf("\n");
    }
}
