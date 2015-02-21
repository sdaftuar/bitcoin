#ifndef BITCOIN_SIMULATION_H
#define BITCOIN_SIMULATION_H

#include "streams.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "txmempool.h"
#include "boost/date_time/gregorian/gregorian.hpp" //include all types plus i/o
#include "boost/filesystem.hpp"

#include <string>
#include <serialize.h>

#include <memory>

using namespace boost::gregorian;
using namespace std;

/**
 * CCLEvent and derived classes BlockEvent/TxEvent allow for
 * code deduplication; @see ReadEvent below.  BlockEvent and TxEvent
 * are wrappers around the Block and Transaction objects.
 */

struct CCLEvent {
    CCLEvent() { reset(); }
    virtual void reset() { timeMicros = INT64_MAX; valid = false; }
    int64_t timeMicros;
    bool valid;

    virtual bool operator<(CCLEvent &b) { return timeMicros < b.timeMicros; }
};

struct BlockEvent : public CCLEvent {
    BlockEvent() : CCLEvent() { }
    CBlock obj;
};

struct TxEvent : public CCLEvent {
    TxEvent() : CCLEvent() {}
    CTransaction obj;
};

struct HeadersEvent : public CCLEvent {
    HeadersEvent() : CCLEvent() {}
    vector<CBlockHeader> obj;
};

/**
 * Simulation: plays historical data (@see DataLogger) back through bitcoind.
 *
 * Usage: Construct with dates to run the simulation, along with path to directory
 *        where data is stored, and whether to start with an empty or pre-
 *        populated mempool.
 * 
 * Currently only delivers events to bitcoind's main.cpp functions 
 * (ProcessNewBlock and a new ProcessTransaction that mirrors the code that
 * handles transactions coming in from the network).
 *
 * Should probably not use this code with the code that connects to peers
 * over the network; preventing that is handled by init.cpp.
 *
 * This only works if you have a bitcoin datadir that is setup with the 
 * blockindex and chainstate as of midnight on startdate.
 */

class Simulation {
public:
    Simulation(date startdate, date enddate, std::string datadir, bool loadMempool);
    ~Simulation() {}

    void operator()();
    // Query the simulation for the current time (micros since epoch)
    int64_t Clock() { return timeInMicros; }

    template<class T> static bool ReadEvent(CAutoFile &input, T *event);

private:
    void LoadFiles(date d);
    void InitAutoFile(auto_ptr<CAutoFile> &which, std::string fileprefix, date d);

    auto_ptr<CAutoFile> blkfile;
    auto_ptr<CAutoFile> txfile;
    auto_ptr<CAutoFile> mempoolfile;
    auto_ptr<CAutoFile> headersfile;

    boost::filesystem::path logdir;

    date begindate, enddate;
    bool loadMempoolAtStartup;

    int64_t timeInMicros; // microseconds since epoch
};

template<class T>
bool Simulation::ReadEvent(CAutoFile &input, T *event)
{
    try {
        input >> event->timeMicros;
        input >> event->obj;
        event->valid = true;
    } catch (std::ios_base::failure) {
        event->reset();
        return false;
    }
    return true;
}

template<>
inline bool Simulation::ReadEvent<HeadersEvent>(CAutoFile &input, HeadersEvent *event)
{
    try {
        input >> event->timeMicros;
        size_t numHeaders;
        input >> numHeaders;
        event->obj.resize(numHeaders);
        for (size_t i=0; i<numHeaders; ++i) {
            input >> event->obj[i];
        }
    } catch (std::ios_base::failure) {
        event->reset();
        return false;
    }
    return true;
}

#endif
