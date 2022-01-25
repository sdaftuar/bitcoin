#ifndef CCL_GLOBALS_H
#define CCL_GLOBALS_H

#include "ccl/datalogger.h"
#include "ccl/simulation.h"

#include "streams.h"
#include "txmempool.h"
#include "leveldb/util/random.h"

#include "clientversion.h"
#include <interfaces/node.h>

#include <boost/thread/thread.hpp>
#include <string>
#include <memory>

class uint256;
using namespace std;
using node::NodeContext;

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
    CCLGlobals(NodeContext& _node);
    ~CCLGlobals();

    // Global stuff -- for using the class at all
    static void SetupArgs();
    bool Init();
    bool IsSim(); // true if running in historical sim mode
    bool Run();
    void StopThreads();
    void Shutdown();

    // Use the leveldb random number generator -- not a crypto secure
    // random function, but we just need this to be deterministic so
    // low expectations...
    size_t GetDetRandomNumber(size_t max_val) { return rnd.Uniform(max_val); }

    unique_ptr<DataLogger> dlog;
    unique_ptr<Simulation> simulation;

private:
    std::string outputFileName;
    leveldb::Random rnd;
    std::thread simthread;
    NodeContext &node;
};

extern CCLGlobals * cclGlobals;

#endif

