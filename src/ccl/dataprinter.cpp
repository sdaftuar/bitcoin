#include "streams.h"
#include "util.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "simulation.h"
#include "txmempool.h"
#include "clientversion.h"

#include "boost/filesystem.hpp"
#include <vector>

using namespace std;

void print(BlockEvent &);
void print(CTxMemPoolEntry &);
void print(TxEvent &);
void print(HeadersEvent &);

void printTime(int64_t timeMicros);

enum DataType { BLOCK, MEMPOOL, TX, HEADERS, INVALID };

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <data file> [<data type (one of BLOCK, MEMPOOL, TX, HEADERS)>]\n", argv[0]);
        exit(1);
    }

    CAutoFile filein(fopen(argv[1], "rb"), SER_DISK, CLIENT_VERSION);

    boost::filesystem::path ifName = argv[1];

    DataType dataType = INVALID;
    // Try to figure out the data type from the name of the file...
    if (ifName.stem().compare("block") == 0) dataType = BLOCK;
    else if (ifName.stem().compare("tx") == 0) dataType = TX;
    else if (ifName.stem().compare("mempool") == 0) dataType = MEMPOOL;
    else if (ifName.stem().compare("headers") == 0) dataType = HEADERS;

    if (argc >= 3) {
        if (strcmp(argv[2], "BLOCK") == 0) dataType = BLOCK;
        else if (strcmp(argv[2], "TX") == 0) dataType = TX;
        else if (strcmp(argv[2], "MEMPOOL") == 0) dataType = MEMPOOL;
        else if (strcmp(argv[2], "HEADERS") == 0) dataType = HEADERS;
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
            case MEMPOOL:
                {
                    CTransaction tx;
                    int64_t nFee;
                    int64_t nTime;
                    double dPriority;
                    unsigned int nHeight;

                    try {
                        filein >> tx;
                        filein >> nFee;
                        filein >> nTime;
                        filein >> dPriority;
                        filein >> nHeight;
                        CTxMemPoolEntry e(tx, nFee, nTime, dPriority, nHeight);
                        print(e);
                    } catch (std::ios_base::failure) {
                        eof = true;
                    }
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

    printf("%s.%d ", DateTimeStrFormat("%Y%m%d %H:%M:%S", ts).c_str(), micros);
}

void print(BlockEvent &blockEvent)
{
    printTime(blockEvent.timeMicros);

    CBlock &block = blockEvent.obj;
    printf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%lu)\n",
            block.GetHash().ToString().c_str(),
            block.nVersion,
            block.hashPrevBlock.ToString().c_str(),
            block.hashMerkleRoot.ToString().c_str(),
            block.nTime, block.nBits, block.nNonce,
            block.vtx.size());
    for (unsigned int i = 0; i < block.vtx.size(); i++)
        printf("[%d] %s\n", i, block.vtx[i].ToString().c_str());
    printf("\n");
}

void print(TxEvent &txEvent)
{
    printTime(txEvent.timeMicros);
    printf("%s", txEvent.obj.ToString().c_str());
}

void print(HeadersEvent &headersEvent)
{
    printTime(headersEvent.timeMicros);
    printf("\n");
    for (size_t i=0;i <headersEvent.obj.size(); ++i) {
        CBlockHeader &block = headersEvent.obj[i];
        printf("[%lu] CBlockHeader(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u)\n",
                i, block.GetHash().ToString().c_str(),
                block.nVersion,
                block.hashPrevBlock.ToString().c_str(),
                block.hashMerkleRoot.ToString().c_str(),
                block.nTime, block.nBits, block.nNonce);
    }
}

void print(CTxMemPoolEntry &entry)
{
    printf("%s\n", entry.GetTx().ToString().c_str());
    printf("nFee= %lu nTxSize= %lu nTime= %ld dPriority= %g nHeight= %d\n", 
            entry.GetFee(), entry.GetTxSize(), entry.GetTime(),
            entry.GetPriority(entry.GetHeight()), entry.GetHeight());
}
