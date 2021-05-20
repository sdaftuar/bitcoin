#ifndef BITCOIN_SIMULATION_H
#define BITCOIN_SIMULATION_H

#include "streams.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "blockencodings.h"
#include "boost/date_time/gregorian/gregorian.hpp"
#include "boost/filesystem.hpp"
#include "txorphanage.h"
#include "bloom.h"
#include "validation.h"

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
    std::shared_ptr<CBlock> obj;
    void reset_shared_ptr() { obj.reset(new CBlock); }
};

struct TxEvent : public CCLEvent {
    TxEvent() : CCLEvent() {}
    std::shared_ptr<CTransaction> obj;
    void reset_shared_ptr() { obj.reset(new CTransaction(CMutableTransaction())); }
};

struct HeadersEvent : public CCLEvent {
    HeadersEvent() : CCLEvent() {}
    std::shared_ptr<vector<CBlockHeader>> obj;
    void reset_shared_ptr() { obj.reset(new vector<CBlockHeader>); }
};

struct CompactBlockEvent : public CCLEvent {
    CompactBlockEvent() : CCLEvent() {}
    std::shared_ptr<CBlockHeaderAndShortTxIDs> obj;
    void reset_shared_ptr() { obj.reset(new CBlockHeaderAndShortTxIDs); }
};

struct BlockTransactionsEvent : public CCLEvent {
    BlockTransactionsEvent() : CCLEvent() {}
    std::shared_ptr<BlockTransactions> obj;
    void reset_shared_ptr() { obj.reset(new BlockTransactions); }
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
    Simulation(date startdate, date enddate, std::string datadir);
    ~Simulation() {}

    void Run();
    // Query the simulation for the current time (micros since epoch)
    int64_t Clock() { return timeInMicros; }

    template<class T> static bool ReadEvent(CAutoFile &input, T *event);

private:
    // transaction processing -- the net_processing versions are now tightly
    // coupled with the net_processing state, making them difficult to reuse,
    // so we reimplement here.
    void ProcessTransaction(const CTransactionRef& ptx);
    bool AlreadyHaveTx(const GenTxid& gtxid);
    void ProcessOrphanTx(std::set<uint256>& orphan_work_set) EXCLUSIVE_LOCKS_REQUIRED(cs_main, g_cs_orphans);
    TxOrphanage m_orphanage;
    CRollingBloomFilter recentRejects{120000, 0.000001};
    uint256 hashRecentRejectsChainTip{};

private:
    void LoadFiles(date d);
    void InitAutoFile(unique_ptr<CAutoFile> &which, std::string fileprefix, date d);

    unique_ptr<CAutoFile> blkfile;
    unique_ptr<CAutoFile> txfile;
    unique_ptr<CAutoFile> headersfile;
    unique_ptr<CAutoFile> cmpctblockfile;
    unique_ptr<CAutoFile> blocktxnfile;

    boost::filesystem::path logdir;

    date begindate, enddate;

    int64_t timeInMicros; // microseconds since epoch
};

template<class T>
bool Simulation::ReadEvent(CAutoFile &input, T *event)
{
    try {
        input >> event->timeMicros;
        event->reset_shared_ptr();
        input >> *(event->obj);
        event->valid = true;
    } catch (std::ios_base::failure) {
        event->reset();
        return false;
    }
    return true;
}

template<>
inline bool Simulation::ReadEvent<TxEvent>(CAutoFile &input, TxEvent *event)
{
    try {
        input >> event->timeMicros;
        event->obj.reset(new CTransaction(deserialize, input));
        event->valid = true;
    } catch (std::ios_base::failure) {
        event->reset();
        return false;
    }
    return true;
}

#endif
