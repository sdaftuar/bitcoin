#include "streams.h"
#include "util.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "simulation.h"
#include "clientversion.h"

#include "boost/filesystem.hpp"
#include <vector>

using namespace std;

void print(HeadersEvent &);

void printTime(int64_t timeMicros);

enum DataType { BLOCK, MEMPOOL, TX, HEADERS, INVALID };

int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: %s <data file> <outputdir>\n", argv[0]);
        exit(1);
    }

    CAutoFile filein(fopen(argv[1], "rb"), SER_DISK, CLIENT_VERSION);

    boost::filesystem::path ifName = argv[1];
    boost::filesystem::path ofName = argv[2];
    ofName /= ifName.filename();

    CAutoFile fileout(fopen(ofName.string().c_str(), "ab"), SER_DISK, CLIENT_VERSION);

    bool eof=false;
    int counter=0;
    while (!eof) {
        HeadersEvent headersEvent;

        if (Simulation::ReadEvent(filein, &headersEvent)) {
            fileout << headersEvent.timeMicros;
            fileout << headersEvent.obj;
            ++counter;
        } else {
            eof=true;
        }
    }
    printf("Wrote out %d headers events\n", counter);
}

#if 0
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

void print(MyCTxMemPoolEntry &entry)
{
    printf("%s\n", entry.tx->ToString().c_str());
    printf("nFee= %lu nTime= %ld dPriority= %g nHeight= %d\n",
            entry.nFee, entry.nTime, entry.dPriority, entry.nHeight);
}
#endif
