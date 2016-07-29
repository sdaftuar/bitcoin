#include "datalogger.h"
#include "cclutil.h"
#include "cclglobals.h"

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "boost/date_time/gregorian/gregorian.hpp" //include all types plus i/o

using namespace boost::gregorian;
using namespace boost::posix_time;

DataLogger::DataLogger(string pathPrefix)
{
    if (pathPrefix == "") {
        logdir = GetDataDir();
    } else {
        logdir = pathPrefix;
    }

    LoadOldMempool();
    RollDate();

    if (transactionLog->IsNull()) {
        LogPrintf("DataLogger: Unable to create transaction log file, will proceed with no tx log\n");
    }
    if (blockLog->IsNull()) {
        LogPrintf("DataLogger: Unable to create block log file, will proceed with no block log\n");
    }
    if (mempoolLog->IsNull()) {
        LogPrintf("DataLogger: Unable to create mempool log file, will proceed with no mempool log\n");
    }
    if (headersLog->IsNull()) {
        LogPrintf("DataLogger: Unable to create headers log file, will proceed with no headers log\n");
    }
    if (cmpctblockLog->IsNull()) {
        LogPrintf("DataLogger: Unable to create compact block log file, will proceed without\n");
    }
    if (blocktxnLog->IsNull()) {
        LogPrintf("DataLogger: Unable to create block transactions log file, will proceed without\n");
    }
}

DataLogger::~DataLogger() {}

void DataLogger::LoadOldMempool()
{
    date today(day_clock::local_day());

    std::string fullname = "mempool." + to_iso_string(today);
    boost::filesystem::path thispath = logdir / fullname;

    if (!boost::filesystem::exists(thispath)) {
        fullname = "mempool." + to_iso_string(today-days(1));
        thispath = logdir / fullname;
    }

    CAutoFile oldMempool(fopen(thispath.string().c_str(), "rb"), SER_DISK, CLIENT_VERSION);

    if (!oldMempool.IsNull()) {
        cclGlobals->InitMemPool(oldMempool);
    } else {
        LogPrintf("DataLogger: unable to load previous mempool, continuing without\n");
    }
}

void DataLogger::RollDate()
{
    LogPrintf("DataLogger: log files rolling to new date\n");
    date today(day_clock::local_day());

    // Convention is to name these files based on the p2p strings used
    // to specify the event type.
    InitAutoFile(transactionLog, "tx.", to_iso_string(today));
    InitAutoFile(blockLog, "block.", to_iso_string(today));
    InitAutoFile(mempoolLog, "mempool.", to_iso_string(today));
    InitAutoFile(headersLog, "headers.", to_iso_string(today));
    InitAutoFile(cmpctblockLog, "cmpctblock.", to_iso_string(today));
    InitAutoFile(blocktxnLog, "blocktxn.", to_iso_string(today));

    cclGlobals->WriteMempool(*mempoolLog);

    logRotateDate = today + days(1);
}

void DataLogger::InitAutoFile(unique_ptr<CAutoFile> &which, std::string prefix, std::string curdate)
{
    std::string fullname = prefix + curdate;
    boost::filesystem::path thispath = logdir / fullname;

    if (!RotateFile(logdir, fullname)) {
        LogPrintf("DataLogger::InitAutoFile: Unable to rotate %s, check filesystem permissions\n",
            fullname);
    }

    // Note that the CAutoFile destructor calls fclose()
    which.reset(new CAutoFile(fopen(thispath.string().c_str(), "ab"), SER_DISK, CLIENT_VERSION));
}

void DataLogger::Shutdown()
{
    cclGlobals->WriteMempool(*mempoolLog);
}

void DataLogger::OnNewTransaction(CTransaction &tx)
{
    if (!transactionLog->IsNull()) {
        if (day_clock::local_day() >= logRotateDate) {
            RollDate();
        }
        *transactionLog << GetTimeMicros();
        *transactionLog << tx;
    }
}

void DataLogger::OnNewBlock(CBlock &block)
{
    if (!blockLog->IsNull()) {
        if (day_clock::local_day() >= logRotateDate) {
            RollDate();
        }
        *blockLog << GetTimeMicros();
        *blockLog << block;
    }
}

void DataLogger::OnNewHeaders(vector<CBlockHeader> &headers)
{
    if (!headersLog->IsNull()) {
        if (day_clock::local_day() >= logRotateDate) {
            RollDate();
        }
        *headersLog << GetTimeMicros();
        *headersLog << headers.size();
        for (size_t i=0; i<headers.size(); ++i) {
            *headersLog << headers[i];
        }
    }
}

void DataLogger::OnNewCompactBlock(CBlockHeaderAndShortTxIDs &cmpctblock)
{
    if (!cmpctblockLog->IsNull()) {
        if (day_clock::local_day() >= logRotateDate) {
            RollDate();
        }
        *cmpctblockLog << GetTimeMicros();
        *cmpctblockLog << cmpctblock;
    }
}

void DataLogger::OnNewBlockTransactions(BlockTransactions &blocktxn)
{
    if (!blocktxnLog->IsNull()) {
        if (day_clock::local_day() >= logRotateDate) {
            RollDate();
        }
        *blocktxnLog << GetTimeMicros();
        *blocktxnLog << blocktxn;
    }
}
