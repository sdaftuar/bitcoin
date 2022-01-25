#ifndef BITCOIN_SIMULATION_H
#define BITCOIN_SIMULATION_H

#include "streams.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "blockencodings.h"
#include "boost/date_time/gregorian/gregorian.hpp"
#include <interfaces/node.h>
#include <node/context.h>
#include <txorphanage.h>

#include <filesystem>
#include <string>
#include <serialize.h>

#include <memory>

using namespace boost::gregorian;
using namespace std;
using node::NodeContext;

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

    void RunSim(NodeContext &node);
    // Query the simulation for the current time (micros since epoch)
    int64_t Clock() { return timeInMicros; }

    template<class T> static bool ReadEvent(AutoFile &input, T *event);

private:
    void LoadFiles(date d);
    void InitAutoFile(unique_ptr<AutoFile> &which, std::string fileprefix, date d);
    void ProcessTransaction(const CTransactionRef& ptx, ChainstateManager &m_chainman, CTxMemPool& m_mempool);
    bool ProcessOrphanTx(ChainstateManager& m_chainman);

    TxOrphanage m_orphanage;

    unique_ptr<AutoFile> blkfile;
    unique_ptr<AutoFile> txfile;
    unique_ptr<AutoFile> headersfile;
    unique_ptr<AutoFile> cmpctblockfile;
    unique_ptr<AutoFile> blocktxnfile;

    std::filesystem::path logdir;

    date begindate, enddate;

    int64_t timeInMicros; // microseconds since epoch
};

template<class T>
bool Simulation::ReadEvent(AutoFile &input, T *event)
{
    try {
        input >> event->timeMicros;
        event->reset_shared_ptr();
        input >> TX_WITH_WITNESS(*(event->obj));
        event->valid = true;
    } catch (std::ios_base::failure &) {
        event->reset();
        return false;
    }
    return true;
}

template<>
inline bool Simulation::ReadEvent<TxEvent>(AutoFile &input, TxEvent *event)
{
    try {
        input >> event->timeMicros;
        event->obj.reset(new CTransaction(deserialize, TX_WITH_WITNESS, input));
        event->valid = true;
    } catch (std::ios_base::failure &) {
        event->reset();
        return false;
    }
    return true;
}

#endif
