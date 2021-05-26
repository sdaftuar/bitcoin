#include "streams.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include <ccl/simulation.h>
#include "clientversion.h"
#include "util/system.h"

#include "boost/filesystem.hpp"
#include <vector>

#include <util/translation.h>

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
    if (argc < 4) {
        printf("Usage: %s <data type (BLOCK, TX, HEADERS, CMPCTBLOCK, BLOCKTXN)> <data filename 1> <data filename 2> ...]\n", argv[0]);
        exit(1);
    }


    DataType dataType = INVALID;

    if (true) {
        if (strcmp(argv[1], "BLOCK") == 0) dataType = BLOCK;
        else if (strcmp(argv[1], "TX") == 0) dataType = TX;
        else if (strcmp(argv[1], "HEADERS") == 0) dataType = HEADERS;
        else if (strcmp(argv[1], "CMPCTBLOCK") == 0) dataType = CMPCTBLOCK;
        else if (strcmp(argv[1], "BLOCKTXN") == 0) dataType = BLOCKTXN;
        else {
            printf("Invalid data type (%s) given\n", argv[2]);
            exit(2);
        }
    }

    printf("Outputting to combinedata.outputfile\n");
    CAutoFile fileout(fopen("combinedata.outputfile", "ab"), SER_DISK, CLIENT_VERSION);

    for (int j=2; j<argc; ++j) {
        printf("Processing %s\n", argv[j]);
        CAutoFile filein(fopen(argv[j], "rb"), SER_DISK, CLIENT_VERSION);

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
                        if (Simulation::ReadEvent(filein, &blockEvent)) {
                            fileout << blockEvent.timeMicros;
                            fileout << *blockEvent.obj;
                        }
                        else eof=true;
                        break;
                    }
                case TX:
                    {
                        if (Simulation::ReadEvent(filein, &txEvent)) {
                            fileout << txEvent.timeMicros;
                            fileout << *txEvent.obj;
                        }
                        else eof=true;
                        break;
                    }
                case HEADERS:
                    {
                        if (Simulation::ReadEvent(filein, &headersEvent)) {
                            fileout << headersEvent.timeMicros;
                            fileout << *headersEvent.obj;
                        }
                        else eof=true;
                        break;
                    }
                case CMPCTBLOCK:
                    {
                        if (Simulation::ReadEvent(filein, &compactBlockEvent)) {
                            fileout << compactBlockEvent.timeMicros;
                            fileout << *compactBlockEvent.obj;
                        }
                        else eof=true;
                        break;
                    }
                case BLOCKTXN:
                    {
                        if (Simulation::ReadEvent(filein, &blockTransactionsEvent)) {
                            fileout << blockTransactionsEvent.timeMicros;
                            fileout << *blockTransactionsEvent.obj;
                        }
                        else eof=true;
                        break;
                    }
                case INVALID:
                    break;
            }
        }
    }
}
