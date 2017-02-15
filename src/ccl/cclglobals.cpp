#include "cclglobals.h"
#include "consensus/validation.h"
#include "init.h"
#include "ui_interface.h" // Defines the _() function!
#include "arith_uint256.h"
#include "uint256.h"
#include "util.h"
#include "validation.h"
#include "net_processing.h"

#include <string>
#include <boost/date_time/posix_time/conversion.hpp>

CCLGlobals *cclGlobals = new CCLGlobals;

CCLGlobals::CCLGlobals()
    : rnd(301)
{
}

CCLGlobals::~CCLGlobals()
{
    LogPrintf("CCLGlobals: destructor\n");
}

void CCLGlobals::UpdateUsage(std::string &strUsage)
{
    strUsage += "\n" + _("CCL Options:") + "\n";

    // DataLogger options
    strUsage += "  -dlogdir=<dirname>      " + _("Turn on data logging to specified output directory") + "\n";

    // Simulation options
    strUsage += "  -simulation            " + _("Sim mode! Don't call add networking threads to threadgroup") + "\n";
    strUsage += "      -simdatadir=<dir>  " + _("For simulations: specify data directory (default: /chaincode/data/)") + "\n";
    strUsage += "      -start=<YYYYMMDD>  " + _("For simulations: start date") + "\n";
    strUsage += "      -end=<YYYYMMDD>    " + _("For simulations: end date (defaults to start date)") + "\n";
    strUsage += "      -loadmempool=[1/0] " + _("Turn on/off loading initial mempool (default: 0)") + "\n";

}

bool CCLGlobals::Init()
{
    // DataLogger initialization
    if (IsArgSet("-dlogdir")) {
	    this->dlog.reset(new DataLogger(GetArg("-dlogdir", "")));
    }

    // Simulation initialization
    std::string startdate, enddate, simdatadir="/chaincode/data";
    if (IsArgSet("-simulation")) {
        if (IsArgSet("-start")) {
            startdate = GetArg("-start", "");
        } else {
            LogPrintf("CCLGlobals::Init: Must specify -start (date) for simulation\n");
            return false;
        }
        if (IsArgSet("-end")) {
            enddate = GetArg("-end", "");
        } else {
            enddate = startdate;
        }
        if (IsArgSet("-simdatadir")) {
            simdatadir = GetArg("-simdatadir", "");
        }
        simulation.reset(new
            Simulation(boost::gregorian::from_undelimited_string(startdate),
                boost::gregorian::from_undelimited_string(enddate),
                simdatadir)
        );

        // If we're in simulation, normal mempool loading won't take place,
        // because we disable the import thread.
        // Load the mempool directly if asked to do so.
        if (GetBoolArg("-loadmempool", false)) {
            // LoadMempool will proactively expire old transactions,
            // so set the mocktime to be from where the simulation would start.
            boost::gregorian::date sdate = boost::gregorian::from_undelimited_string(startdate);
            boost::posix_time::ptime simStart(sdate);
            boost::posix_time::time_duration dur = simStart - boost::posix_time::ptime(boost::gregorian::date(1970,1,1));
            SetMockTime(std::time_t(dur.total_seconds()));
            LoadMempool();
        }
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

bool CCLGlobals::IsSim()
{
    return (simulation.get() != NULL);
}

void CCLGlobals::Shutdown()
{
    if (dlog.get()) dlog->Shutdown();
}

// Use the leveldb random number generator -- not a crypto secure
// random function, but we just need this to be deterministic so
// low expectations...
uint256 CCLGlobals::GetDetRandHash()
{
    arith_uint256 ret;
    for (unsigned i=0; i<16; ++i) {
        arith_uint256 val = rnd.Uniform(1<<16);
        ret |= (val << i*16);
    }
    return ArithToUint256(ret);
}
