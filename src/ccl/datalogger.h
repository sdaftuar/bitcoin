#ifndef DATA_LOGGER_H
#define DATA_LOGGER_H

#include "blockencodings.h"
#include "streams.h"
#include <string>
#include <memory>
#include <filesystem>
#include "boost/date_time/gregorian/gregorian.hpp"
#include <common/args.h>
#include "logging.h"

using namespace std;

class CTransaction;
class CBlock;
class CBlockHeader;

/**
 * DataLogger: log block and tx data as it arrives.
 *
 * Usage: Pass in directory name to hold the log files in to the constructor.
 *        Will create block.<date> and tx.<date> files that store blocks
 *        received and transactions received on that date.
 *
 *        Requires bitcoind to call OnNewTransaction and OnNewBlock methods.
 */

class DataLogger {
private:
    unique_ptr<AutoFile> transactionLog;
    unique_ptr<AutoFile> blockLog;
    unique_ptr<AutoFile> headersLog;
    unique_ptr<AutoFile> cmpctblockLog;
    unique_ptr<AutoFile> blocktxnLog;

    // Store the path where we're putting
    // all the data files, for log rotation
    // purposes
    std::filesystem::path logdir;

    boost::gregorian::date logRotateDate;

    void InitAutoFile(unique_ptr<AutoFile> &which, std::string prefix, std::string curdate);
    void RollDate();

public:
    void Shutdown();

public:
    DataLogger(string pathPrefix, ArgsManager& args);
    ~DataLogger();

    void OnNewTransaction(const CTransaction &tx);
    void OnNewBlock(CBlock &block);
    void OnNewHeaders(vector<CBlockHeader> &headers);
    void OnNewCompactBlock(CBlockHeaderAndShortTxIDs &cmpctblock);
    void OnNewBlockTransactions(const BlockTransactions &blocktxn);
};

#endif
