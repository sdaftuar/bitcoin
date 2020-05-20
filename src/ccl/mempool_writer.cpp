#include "mempool_writer.h"
#include "txmempool.h"
#include "validation.h"
#include "primitives/block.h"
#include "amount.h"
#include "consensus/validation.h"
#include "miner.h"
#include "chainparams.h"

void WriteMemPoolBeforeBlock(const CBlock &block)
{
    std::string filename = block.GetHash().ToString() + ".mempool";
    FILE *fp = fopen(filename.c_str(), "a");
    fprintf(fp, "# txid total_fee weight ancestor [ancestor... etc]\n");
    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    for (; mi != mempool.mapTx.get<ancestor_score>().end(); ++mi) {
        const CTxMemPoolEntry &entry = *mi;
        fprintf(fp, "%s %ld %ld", entry.GetTx().GetHash().ToString().c_str(), entry.GetModifiedFee(), entry.GetTxWeight());
        CTxMemPool::setEntries setAncestors;
        uint64_t noLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        mempool.CalculateMemPoolAncestors(entry, setAncestors, noLimit, noLimit, noLimit, noLimit, dummy, false);
        for (CTxMemPool::txiter ancestorIt : setAncestors) {
            fprintf(fp, " %s", ancestorIt->GetTx().GetHash().ToString().c_str());
        }
        fprintf(fp, "\n");
    }
    fclose(fp);
}

void WriteGBTBeforeBlock(const CBlock &block)
{
    std::string filename = block.GetHash().ToString() + ".gbt";
    FILE *fp = fopen(filename.c_str(), "a");

    std::unique_ptr<CBlockTemplate> pblocktemplate;
    CScript scriptDummy = CScript() << OP_TRUE;
    pblocktemplate = BlockAssembler(Params()).CreateNewBlock(scriptDummy);
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience
    fprintf(fp, "CreateNewBlock(): fees %ld weight %ld\n", -pblocktemplate->vTxFees[0], GetBlockWeight(*pblock));
    for (const auto& it : pblock->vtx) {
        const CTransaction& tx = *it;
        fprintf(fp, "%s\n", tx.GetHash().ToString().c_str());
    }
    fclose(fp);
}

void WriteBlockStatsAndTransactions(const CBlock &block, CAmount nFees, int64_t block_weight)
{
    std::string filename = block.GetHash().ToString() + ".block";
    FILE *fp = fopen(filename.c_str(), "a");
    fprintf(fp, "Block %s fees %ld weight %ld\n", block.GetHash().ToString().c_str(), nFees, block_weight);
    for (size_t i=0; i<block.vtx.size(); ++i) {
        fprintf(fp, "%s\n", block.vtx[i]->GetHash().ToString().c_str());
    }
    fclose(fp);
}
