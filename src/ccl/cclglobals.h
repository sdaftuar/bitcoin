#ifndef CCL_GLOBALS_H
#define CCL_GLOBALS_H

#include "ccl/datalogger.h"
#include "ccl/simulation.h"

#include "streams.h"
#include "txmempool.h"
#include "leveldb/util/random.h"

#include "clientversion.h"

#include <boost/thread/thread.hpp>
#include <string>
#include <memory>

class uint256;
using namespace std;

/**
 * A container object for (unmerged CCL) global data structures.
 *
 * Usage: Create a CCLGlobals at startup.
 *           * Call UpdateUsage for bitcoind options unique to ccl
 *           * Call Init to instantiate ccl datastructures with cmd line options
 *           * Call Run (for sim mode -- returns false if no sim started)
 *           * Call Shutdown to cleanup at process shutdown
 *
 * Also includes helper functions for ccl datastructures to share.
 */

class CCLGlobals {
public:
    CCLGlobals();
    ~CCLGlobals();

    // Global stuff -- for using the class at all
    void UpdateUsage(string &strUsage);
    bool Init(CTxMemPool *pool);
    bool Run(boost::thread_group &threadGroup);
    void Shutdown();

    // Helper functions (for CCL classes to call)
    void InitMemPool(CAutoFile &mempoolLog);
    void WriteMempool(CAutoFile &logfile);
    uint256 GetDetRandHash(); // deterministic randomness

    auto_ptr<DataLogger> dlog;
    auto_ptr<Simulation> simulation;

    // Try to reduce reliance on global namespace
    CTxMemPool * mempool;

private:
    bool writeMempoolAtShutdown;
    std::string outputFileName;
    leveldb::Random rnd;
};

extern CCLGlobals * cclGlobals;

#endif
