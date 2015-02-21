#include "simulation.h"
#include "ccl/cclglobals.h"

#include "init.h"
#include "main.h"
#include "primitives/transaction.h"
#include "primitives/block.h"
#include "util.h"

#include <string>
#include <boost/interprocess/sync/file_lock.hpp>

using namespace boost;
using namespace std;

Simulation::Simulation(date sdate, date edate, string datadir, bool loadMempool)
 : logdir(datadir),
   begindate(sdate), enddate(edate),
   loadMempoolAtStartup(loadMempool)
{
    LoadFiles(begindate);
    if (blkfile->IsNull()) {
        LogPrintf("Simulation: can't open block file, continuing without\n");
    }
    if (txfile->IsNull()) {
        LogPrintf("Simulation: can't open tx file, continuing without\n");
    }
    if (headersfile->IsNull()) {
        LogPrintf("Simulation: can't open headers file, continuing without\n");
    }

    // Actually, this should error if the right date can't be found...
    if (loadMempoolAtStartup) {
        InitAutoFile(mempoolfile, "mempool.", begindate);
        if (mempoolfile->IsNull()) {
            LogPrintf("Simulation: can't open mempool file, continuing without\n");
        }
    }
}

void Simulation::LoadFiles(date d)
{
    InitAutoFile(txfile, "tx.", d);
    InitAutoFile(blkfile, "block.", d);
    InitAutoFile(headersfile, "headers.", d);
}

void Simulation::InitAutoFile(auto_ptr<CAutoFile> &which, std::string fileprefix, date d)
{
    for (date s=d; s<= enddate; s += days(1)) {
        string filename = fileprefix + boost::gregorian::to_iso_string(s);
        boost::filesystem::path fullpath = logdir / filename; 
        which.reset(new CAutoFile(fopen(fullpath.string().c_str(), "rb"),
                    SER_DISK, CLIENT_VERSION));
        if (!which->IsNull()) {
            LogPrintf("Simulation: InitAutoFile opened %s\n", fullpath.string().c_str());
            break;
        }
    }
}


void Simulation::operator()()
{
    LogPrintf("Simulation starting\n");
    
    date curdate = begindate;
    if (loadMempoolAtStartup) {
        // Start up with beginning mempool
        cclGlobals->InitMemPool(*mempoolfile);
    } else {
        LogPrintf("Simulation: not loading mempool\n");
    }
    while (curdate <= enddate) {
        bool txEOF = false;
        bool blkEOF = false;
        bool hdrEOF = false;

        BlockEvent blockEvent;
        TxEvent txEvent;
        HeadersEvent headersEvent;

        while (!txEOF || !blkEOF || !hdrEOF) {
            if (!txEOF && !txEvent.valid) {
                txEOF = !ReadEvent(*txfile, &txEvent);
            }
            // TODO: look at LoadExternalBlockFile (in main.cpp) and try
            // to understand why there's so much more code there.  Might
            // need to beef this up...
            if (!blkEOF && !blockEvent.valid) {
                blkEOF = !ReadEvent(*blkfile, &blockEvent);
            }
            if (!hdrEOF && !headersEvent.valid) {
                hdrEOF = !ReadEvent(*headersfile, &headersEvent);
            }
            
            vector<CCLEvent *> validEvents;
            if (txEvent.valid) validEvents.push_back(&txEvent);
            if (blockEvent.valid) validEvents.push_back(&blockEvent);
            if (headersEvent.valid) validEvents.push_back(&headersEvent);
            if (validEvents.empty()) break;

            CCLEvent *nextEvent = validEvents[0];
            for (size_t i=1; i<validEvents.size(); ++i) {
                if (*validEvents[i] < *nextEvent) nextEvent = validEvents[i];
            }
            timeInMicros = nextEvent->timeMicros;
            SetMockTime(nextEvent->timeMicros / 1000000);

            if (nextEvent == &txEvent) {
                ProcessTransaction(txEvent.obj);
                txEvent.reset();
            } else if (nextEvent == &blockEvent) {
                CValidationState state;
                ProcessNewBlock(state, NULL, &blockEvent.obj);
                blockEvent.reset();
            } else if (nextEvent == &headersEvent) {
                CValidationState state;
                for (size_t i=0; i<headersEvent.obj.size(); ++i) {
                    // The 3rd argument to AcceptBlockHeader is only
                    // used for catching misbehaving nodes.  This could
                    // cause a sim-live discrepancy where 
                    if (!AcceptBlockHeader(headersEvent.obj[i], state, NULL)) {
                        int nDoS;
                        if (state.IsInvalid(nDoS)) break;
                    }
                }
                headersEvent.reset();
            }
        }
        curdate += days(1);
        LoadFiles(curdate);
    }
    LogPrintf("Simulation exiting, mempool size: %lu\n", cclGlobals->mempool->size());
    StartShutdown();
}
