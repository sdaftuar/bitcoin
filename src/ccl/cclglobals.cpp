#include "cclglobals.h"
#include "init.h"
#include "ui_interface.h" // Defines the _() function!
#include "uint256.h"
#include "util.h"

#include <string>

CCLGlobals *cclGlobals = new CCLGlobals;

CCLGlobals::CCLGlobals() 
    : mempool(NULL), writeMempoolAtShutdown(false), rnd(301)
{
}

CCLGlobals::~CCLGlobals() 
{
    LogPrintf("CCLGlobals: destructor\n");
}

void CCLGlobals::UpdateUsage(std::string &strUsage)
{
    strUsage += "\n" + _("CCL Options:") + "\n";

    // CCL options:
    strUsage += "  -writemempool=<file>            " + _("Write out mempool at end of run to DATADIR/file; specifying file is optional (default: 'mempool')") + "\n";

    // DataLogger options
    strUsage += "  -dlogdir=<dirname>      " + _("Turn on data logging to specified output directory") + "\n";    

    // Simulation options
    strUsage += "  -simulation            " + _("Sim mode! Don't call add networking threads to threadgroup") + "\n";
    strUsage += "      -simdatadir=<dir>  " + _("For simulations: specify data directory (default: /chaincode/data/)") + "\n";
    strUsage += "      -start=<YYYYMMDD>  " + _("For simulations: start date") + "\n";
    strUsage += "      -end=<YYYYMMDD>    " + _("For simulations: end date (defaults to start date)") + "\n";
    strUsage += "      -loadmempool=[1/0] " + _("Turn on/off loading initial mempool (default: 1)") + "\n";

}

bool CCLGlobals::Init(CTxMemPool *pool)
{
    mempool = pool;

    // CCL initialization
    if (mapArgs.count("-writemempool")) {
        writeMempoolAtShutdown = true;
        if (mapArgs["-writemempool"].empty())
            outputFileName = "mempool";
        else
            outputFileName = mapArgs["-writemempool"];
    }

    // DataLogger initialization
    if (mapArgs.count("-dlogdir")) {
	    this->dlog.reset(new DataLogger(mapArgs["-dlogdir"]));
    }

    // Simulation initialization
    std::string startdate, enddate, simdatadir="/chaincode/data";
    if (mapArgs.count("-simulation")) {
        if (mapArgs.count("-start")) {
            startdate = mapArgs["-start"];
        } else {
            LogPrintf("CCLGlobals::Init: Must specify -start (date) for simulation\n");
            return false;
        }
        if (mapArgs.count("-end")) {
            enddate = mapArgs["-end"];
        } else {
            enddate = startdate;
        }
        if (mapArgs.count("-simdatadir")) {
            simdatadir = mapArgs["-simdatadir"];
        }
        bool loadMempool = GetBoolArg("-loadmempool", true);
        simulation.reset(new 
            Simulation(boost::gregorian::from_undelimited_string(startdate),
                boost::gregorian::from_undelimited_string(enddate),
                simdatadir, loadMempool)
        );
    }
    return true;
}

bool CCLGlobals::Run(boost::thread_group &threadGroup)
{
    if (simulation.get() != NULL) {
        threadGroup.create_thread(boost::ref(*simulation.get()));
        return true;  // means don't use network
    } else {
        return false;
    }
}

void CCLGlobals::Shutdown()
{
    if (dlog.get()) dlog->Shutdown();
    if (writeMempoolAtShutdown) {
        boost::filesystem::path output = GetDataDir() /
            outputFileName;
        CAutoFile mplog(fopen(output.string().c_str(), "wb"),
                SER_DISK, CLIENT_VERSION);
        WriteMempool(mplog);
    }
}

void CCLGlobals::InitMemPool(CAutoFile &filein)
{
    int counter=0;
    LOCK(mempool->cs);

    try {
        while (1) {
            CTransaction tx;
            int64_t nFee;
            int64_t nTime;
            double dPriority;
            unsigned int nHeight;

            filein >> tx;
            filein >> nFee;
            filein >> nTime;
            filein >> dPriority;
            filein >> nHeight;

            CTxMemPoolEntry e(tx, nFee, nTime, dPriority, nHeight);
            mempool->addUnchecked(tx.GetHash(), e);
            ++counter;
        }
    } catch (std::ios_base::failure e) {

    }
    LogPrintf("CCLGlobals: added %d entries to mempool\n", counter);
}

void CCLGlobals::WriteMempool(CAutoFile &logfile)
{
    if (!logfile.IsNull()) {
        LOCK(mempool->cs);
        std::map<uint256, CTxMemPoolEntry>::iterator it;
        for (it=cclGlobals->mempool->mapTx.begin(); 
            it != cclGlobals->mempool->mapTx.end(); ++it) {
            // can't get this to work:
            // mempoolLog << it->second;
            CTxMemPoolEntry &e = it->second;
            logfile << e.GetTx();
            logfile << e.GetFee();
            logfile << e.GetTime();
            logfile << e.GetPriority(e.GetHeight());
            logfile << e.GetHeight();
        }
    }
}

// Use the leveldb random number generator -- not a crypto secure
// random function, but we just need this to be deterministic so
// low expectations...
uint256 CCLGlobals::GetDetRandHash()
{
    uint256 ret;
    for (unsigned i=0; i<16; ++i) {
        uint256 val = rnd.Uniform(1<<16);
        ret |= (val << i*16);
    }
    LogPrintf("random hash requested: %s\n", ret.GetHex());
    return ret;
}
