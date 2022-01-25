#include "streams.h"
#include "util/time.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "simulation.h"
#include "clientversion.h"

#include <filesystem>
#include <vector>

using namespace std;

void print(TxEvent &);
void print(BlockEvent &);
void print(HeadersEvent &);
void print(CompactBlockEvent &);
void print(BlockTransactionsEvent &);

void printTime(int64_t timeMicros);

enum DataType { TX, BLOCK, HEADERS, CMPCTBLOCK, BLOCKTXN, INVALID };

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <data file> [<data type (one of BLOCK, TX, HEADERS, CMPCTBLOCK, BLOCKTXN)>]\n", argv[0]);
        exit(1);
    }

    AutoFile filein(fopen(argv[1], "rb"));

    std::filesystem::path ifName = argv[1];

    DataType dataType = INVALID;
    // Try to figure out the data type from the name of the file...
    if (ifName.stem().compare("block") == 0) dataType = BLOCK;
    else if (ifName.stem().compare("tx") == 0) dataType = TX;
    else if (ifName.stem().compare("headers") == 0) dataType = HEADERS;
    else if (ifName.stem().compare("cmpctblock") == 0) dataType = CMPCTBLOCK;
    else if (ifName.stem().compare("blocktxn") == 0) dataType = BLOCKTXN;

    if (argc >= 3) {
        if (strcmp(argv[2], "BLOCK") == 0) dataType = BLOCK;
        else if (strcmp(argv[2], "TX") == 0) dataType = TX;
        else if (strcmp(argv[2], "HEADERS") == 0) dataType = HEADERS;
        else if (strcmp(argv[2], "CMPCTBLOCK") == 0) dataType = CMPCTBLOCK;
        else if (strcmp(argv[2], "BLOCKTXN") == 0) dataType = BLOCKTXN;
        else {
            printf("Invalid data type (%s) given\n", argv[2]);
            exit(2);
        }
    }

    if (dataType == INVALID) {
        printf("Unable to determine data type, please specify\n");
        exit(3);
    }

    bool eof=false;
    while (!eof) {
        TxEvent txEvent;
        BlockEvent blockEvent;
        HeadersEvent headersEvent;
        CompactBlockEvent compactBlockEvent;
        BlockTransactionsEvent blockTransactionsEvent;

        switch(dataType) {
            case BLOCK:
                {
                    if (Simulation::ReadEvent(filein, &blockEvent))
                        print(blockEvent);
                    else eof=true;
                    break;
                }
            case TX:
                {
                    if (Simulation::ReadEvent(filein, &txEvent))
                        print(txEvent);
                    else eof=true;
                    break;
                }
            case HEADERS:
                {
                    if (Simulation::ReadEvent(filein, &headersEvent))
                        print(headersEvent);
                    else eof=true;
                    break;
                }
            case CMPCTBLOCK:
                {
                    if (Simulation::ReadEvent(filein, &compactBlockEvent))
                        print(compactBlockEvent);
                    else eof=true;
                    break;
                }
            case BLOCKTXN:
                {
                    if (Simulation::ReadEvent(filein, &blockTransactionsEvent))
                        print(blockTransactionsEvent);
                    else eof=true;
                    break;
                }
            case INVALID:
                break;
        }
    }
}

void printTime(int64_t timestamp)
{
    int64_t ts = timestamp / 1000000;
    int micros = timestamp % 1000000;

    printf("%s.%d ", FormatISO8601DateTime(ts).c_str(), micros);
}

void print(TxEvent &txEvent)
{
    printTime(txEvent.timeMicros);
    printf("%s", txEvent.obj->ToString().c_str());
}

void print(BlockEvent &blockEvent)
{
    printTime(blockEvent.timeMicros);

    CBlock &block = *blockEvent.obj;
    printf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%lu)\n",
            block.GetHash().ToString().c_str(),
            block.nVersion,
            block.hashPrevBlock.ToString().c_str(),
            block.hashMerkleRoot.ToString().c_str(),
            block.nTime, block.nBits, block.nNonce,
            block.vtx.size());
    for (unsigned int i = 0; i < block.vtx.size(); i++)
        printf("[%d] %s\n", i, block.vtx[i]->ToString().c_str());
    printf("\n");
}

void print(HeadersEvent &headersEvent)
{
    printTime(headersEvent.timeMicros);
    printf("\n");
    for (size_t i=0;i <headersEvent.obj->size(); ++i) {
        CBlockHeader &block = (*headersEvent.obj)[i];
        printf("[%lu] CBlockHeader(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u)\n",
                i, block.GetHash().ToString().c_str(),
                block.nVersion,
                block.hashPrevBlock.ToString().c_str(),
                block.hashMerkleRoot.ToString().c_str(),
                block.nTime, block.nBits, block.nNonce);
    }
}

void print(CompactBlockEvent &compactBlockEvent)
{
    printTime(compactBlockEvent.timeMicros);

    CBlockHeaderAndShortTxIDs &compactBlock = *compactBlockEvent.obj;
    printf("CBlockHeaderAndShortTxIDs(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u)\n",
            compactBlock.header.GetHash().ToString().c_str(),
            compactBlock.header.nVersion,
            compactBlock.header.hashPrevBlock.ToString().c_str(),
            compactBlock.header.hashMerkleRoot.ToString().c_str(),
            compactBlock.header.nTime, compactBlock.header.nBits, compactBlock.header.nNonce);
}

void print(BlockTransactionsEvent &blockTransactionsEvent)
{
    printTime(blockTransactionsEvent.timeMicros);

    BlockTransactions &blockTransactions = *blockTransactionsEvent.obj;
    printf("BlockTransactions(hash=%s, txn=%lu)\n",
            blockTransactions.blockhash.ToString().c_str(),
            blockTransactions.txn.size());
    for (unsigned int i = 0; i < blockTransactions.txn.size(); i++)
        printf("[%d] %s\n", i, blockTransactions.txn[i]->ToString().c_str());
    printf("\n");
}
