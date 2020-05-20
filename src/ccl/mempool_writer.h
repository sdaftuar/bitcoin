#ifndef MEMPOOL_WRITER_H
#define MEMPOOL_WRITER_H

#include "amount.h"

class CBlock;

void WriteMemPoolBeforeBlock(const CBlock &block);
void WriteGBTBeforeBlock(const CBlock &block);
void WriteBlockStatsAndTransactions(const CBlock &block, CAmount nFees, int64_t block_weight);

#endif // MEMPOOL_WRITER_H
