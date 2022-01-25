#include "datalogger.h"
#include "cclutil.h"
#include "cclglobals.h"

#include "primitives/block.h"
#include "primitives/transaction.h"

using namespace boost::gregorian;
using namespace boost::posix_time;

DataLogger::DataLogger(string pathPrefix, ArgsManager& args)
{
    if (pathPrefix == "") {
        logdir = args.GetDataDirNet();
    } else {
        logdir = pathPrefix;
    }

    RollDate();

    if (transactionLog->IsNull()) {
        LogPrintf("DataLogger: Unable to create transaction log file, will proceed with no tx log\n");
    }
    if (blockLog->IsNull()) {
        LogPrintf("DataLogger: Unable to create block log file, will proceed with no block log\n");
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

void DataLogger::RollDate()
{
    LogPrintf("DataLogger: log files rolling to new date\n");
    date today(day_clock::local_day());

    // Convention is to name these files based on the p2p strings used
    // to specify the event type.
    InitAutoFile(transactionLog, "tx.", to_iso_string(today));
    InitAutoFile(blockLog, "block.", to_iso_string(today));
    InitAutoFile(headersLog, "headers.", to_iso_string(today));
    InitAutoFile(cmpctblockLog, "cmpctblock.", to_iso_string(today));
    InitAutoFile(blocktxnLog, "blocktxn.", to_iso_string(today));

    logRotateDate = today + days(1);
}

void DataLogger::InitAutoFile(unique_ptr<AutoFile> &which, std::string prefix, std::string curdate)
{
    std::string fullname = prefix + curdate;
    std::filesystem::path thispath = logdir / fullname;

    if (!RotateFile(logdir, fullname)) {
        LogPrintf("DataLogger::InitAutoFile: Unable to rotate %s, check filesystem permissions\n",
            fullname);
    }

    // Note that the AutoFile destructor calls fclose()
    which.reset(new AutoFile(fopen(thispath.string().c_str(), "ab")));
}

void DataLogger::Shutdown()
{ }

void DataLogger::OnNewTransaction(const CTransaction &tx)
{
    if (!transactionLog->IsNull()) {
        if (day_clock::local_day() >= logRotateDate) {
            RollDate();
        }
        *transactionLog << GetTimeMicros();
        *transactionLog << TX_WITH_WITNESS(tx);
    }
}

void DataLogger::OnNewBlock(CBlock &block)
{
    if (!blockLog->IsNull()) {
        if (day_clock::local_day() >= logRotateDate) {
            RollDate();
        }
        *blockLog << GetTimeMicros();
        *blockLog << TX_WITH_WITNESS(block);
    }
}

void DataLogger::OnNewHeaders(vector<CBlockHeader> &headers)
{
    if (!headersLog->IsNull()) {
        if (day_clock::local_day() >= logRotateDate) {
            RollDate();
        }
        *headersLog << GetTimeMicros();
        *headersLog << headers;
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

void DataLogger::OnNewBlockTransactions(const BlockTransactions &blocktxn)
{
    if (!blocktxnLog->IsNull()) {
        if (day_clock::local_day() >= logRotateDate) {
            RollDate();
        }
        *blocktxnLog << GetTimeMicros();
        *blocktxnLog << blocktxn;
    }
}
