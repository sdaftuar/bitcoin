#ifndef CCL_GLOBALS_H
#define CCL_GLOBALS_H

#include "ccl/datalogger.h"
#include "ccl/simulation.h"

#include "streams.h"
#include "txmempool.h"
#include "validation.h"
#include "leveldb/util/random.h"
#include "util/system.h"
#include <util/thread.h>

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
    void SetupArgs(ArgsManager &gArgs);
    bool Init(ChainstateManager *chainman, CTxMemPool *mempool);
    bool IsSim(); // true if running in historical sim mode
    bool Run();
    void Shutdown();

    // Use the leveldb random number generator -- not a crypto secure
    // random function, but we just need this to be deterministic so
    // low expectations...
    size_t GetDetRandomNumber(size_t max_val) { return rnd.Uniform(max_val); }

    unique_ptr<DataLogger> dlog;
    unique_ptr<Simulation> simulation;
    std::thread m_thread;

public:
    ChainstateManager *m_chainman{nullptr};
    CTxMemPool *m_mempool{nullptr};

private:
    std::string outputFileName;
    leveldb::Random rnd;
};

extern CCLGlobals * cclGlobals;

#endif
