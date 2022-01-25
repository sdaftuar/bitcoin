#include "simulation.h"
#include "ccl/cclglobals.h"

#include "chainparams.h"
#include "init.h"
#include "validation.h"
#include "net_processing.h"
#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "primitives/block.h"
#include "shutdown.h"
#include <interfaces/node.h>
#include <node/context.h>

#include <string>
#include <boost/interprocess/sync/file_lock.hpp>

using namespace boost;
using namespace std;

Simulation::Simulation(date sdate, date edate, string datadir)
 : logdir(datadir),
   begindate(sdate), enddate(edate)
{
    LoadFiles(begindate);
    if (blkfile->IsNull()) {
        LogPrintf("Simulation: can't open block file, continuing without\n");
    }
    if (txfile->IsNull()) {
        LogPrintf("Simulation: can't open tx file, continuing without\n");
    }
    if (headersfile->IsNull()) {
        LogPrintf("Simulation: can't open headers file, continuing without\n");
    }
    if (cmpctblockfile->IsNull()) {
        LogPrintf("Simulation: can't open cmpctblock file, continuing without\n");
    }
    if (blocktxnfile->IsNull()) {
        LogPrintf("Simulation: can't open blocktxn file, continuing without\n");
    }
}

void Simulation::LoadFiles(date d)
{
    if (!gArgs.GetBoolArg("-blocksonly", DEFAULT_BLOCKSONLY)) {
        InitAutoFile(txfile, "tx.", d);
    } else {
        txfile.reset(new AutoFile(NULL));
    }
    InitAutoFile(blkfile, "block.", d);
    InitAutoFile(headersfile, "headers.", d);
    InitAutoFile(cmpctblockfile, "cmpctblock.", d);
    InitAutoFile(blocktxnfile, "blocktxn.", d);
}

void Simulation::InitAutoFile(unique_ptr<AutoFile> &which, std::string fileprefix, date d)
{
    for (date s=d; s<= enddate; s += days(1)) {
        string filename = fileprefix + boost::gregorian::to_iso_string(s);
        std::filesystem::path fullpath = logdir / filename;
        which.reset(new AutoFile(fopen(fullpath.string().c_str(), "rb")));
        if (!which->IsNull()) {
            LogPrintf("Simulation: InitAutoFile opened %s\n", fullpath.string().c_str());
            break;
        }
    }
}


void Simulation::RunSim(NodeContext& node)
{
    LogPrintf("Simulation starting\n");

    date curdate = begindate;
    while (curdate <= enddate) {
        bool txEOF = false;
        bool blkEOF = false;
        bool hdrEOF = false;
        bool cbEOF = false;
        bool btEOF = false;

        BlockEvent blockEvent;
        TxEvent txEvent;
        HeadersEvent headersEvent;
        CompactBlockEvent cmpctblockEvent;
        BlockTransactionsEvent blocktxnEvent;

        while (!txEOF || !blkEOF || !hdrEOF || !cbEOF || !btEOF) {
            if (!txEOF && !txEvent.valid && !txfile->IsNull()) {
                txEOF = !ReadEvent(*txfile, &txEvent);
            }
            if (!blkEOF && !blockEvent.valid) {
                blkEOF = !ReadEvent(*blkfile, &blockEvent);
            }
            if (!hdrEOF && !headersEvent.valid) {
                hdrEOF = !ReadEvent(*headersfile, &headersEvent);
            }
            if (!cbEOF && !cmpctblockEvent.valid) {
                cbEOF = !ReadEvent(*cmpctblockfile, &cmpctblockEvent);
            }
            if (!btEOF && !blocktxnEvent.valid) {
                btEOF = !ReadEvent(*blocktxnfile, &blocktxnEvent);
            }

            vector<CCLEvent *> validEvents;
            if (txEvent.valid) validEvents.push_back(&txEvent);
            if (blockEvent.valid) validEvents.push_back(&blockEvent);
            if (headersEvent.valid) validEvents.push_back(&headersEvent);
            if (cmpctblockEvent.valid) validEvents.push_back(&cmpctblockEvent);
            if (blocktxnEvent.valid) validEvents.push_back(&blocktxnEvent);
            if (validEvents.empty()) break;

            CCLEvent *nextEvent = validEvents[0];
            for (size_t i=1; i<validEvents.size(); ++i) {
                if (*validEvents[i] < *nextEvent) nextEvent = validEvents[i];
            }
            timeInMicros = nextEvent->timeMicros;
            SetMockTime(nextEvent->timeMicros / 1000000);

            if (nextEvent == &txEvent) {
                ProcessTransaction(txEvent.obj, *node.chainman, *node.mempool);
                txEvent.reset();
            } else if (nextEvent == &blockEvent) {
                node.chainman->ProcessNewBlock(blockEvent.obj, true, true, NULL);
                blockEvent.reset();
            } else if (nextEvent == &headersEvent) {
                BlockValidationState dummy;
                node.chainman->ProcessNewBlockHeaders(*(headersEvent.obj), true, dummy, NULL);
                headersEvent.reset();
            } else if (nextEvent == &cmpctblockEvent) {
                // Process cmpctblockEvent as a header message
                BlockValidationState dummy;
                node.chainman->ProcessNewBlockHeaders({cmpctblockEvent.obj->header}, true, dummy, NULL);
                cmpctblockEvent.reset();
            } else if (nextEvent == &blocktxnEvent) {
                // TODO: add a blocktxn handler
                blocktxnEvent.reset();
            }
        }
        curdate += days(1);
        LoadFiles(curdate);
    }
    LogPrintf("Simulation exiting\n");
    StartShutdown();
}

// Reimplementation of PeerManagerImpl::ProcessOrphanTx, but with peer=0
// assumed throughout
bool Simulation::ProcessOrphanTx(ChainstateManager &m_chainman)
{
    CTransactionRef porphanTx = nullptr;

    while (CTransactionRef porphanTx = m_orphanage.GetTxToReconsider(0)) {
        const MempoolAcceptResult result = m_chainman.ProcessTransaction(porphanTx);
        const TxValidationState& state = result.m_state;
        const uint256& orphanHash = porphanTx->GetHash();

        if (result.m_result_type == MempoolAcceptResult::ResultType::VALID) {
            LogPrint(BCLog::MEMPOOL, "   accepted orphan tx %s\n", orphanHash.ToString());
            m_orphanage.AddChildrenToWorkSet(*porphanTx);
            m_orphanage.EraseTx(Txid::FromUint256(orphanHash));
            return true;
        } else if (state.GetResult() != TxValidationResult::TX_MISSING_INPUTS) {
            // Has inputs but not accepted to mempool
            // Probably non-standard or insufficient fee
            LogPrint(BCLog::MEMPOOL, "   removed orphan tx %s\n", orphanHash.ToString());
            m_orphanage.EraseTx(Txid::FromUint256(orphanHash));
            return true;
        }
    }

    return false;
}

void Simulation::ProcessTransaction(const CTransactionRef& ptx, ChainstateManager &m_chainman, CTxMemPool &m_mempool)
{
    const CTransaction& tx = *ptx;

    const MempoolAcceptResult result = m_chainman.ProcessTransaction(ptx);
    const TxValidationState& state = result.m_state;

    static FastRandomContext rng{true};

    if (result.m_result_type == MempoolAcceptResult::ResultType::VALID) {
        LogPrint(BCLog::MEMPOOL, "AcceptToMemoryPool: accepted %s (poolsz %u txn, %u kB)\n",
                tx.GetHash().ToString(),
                m_mempool.size(), m_mempool.DynamicMemoryUsage() / 1000);
        std::set<uint256> orphan_work_set;
        m_orphanage.AddChildrenToWorkSet(tx);
        ProcessOrphanTx(m_chainman);
    } else if (state.GetResult() == TxValidationResult::TX_MISSING_INPUTS) {
        m_orphanage.AddTx(ptx, 0);
        unsigned int nMaxOrphanTx = (unsigned int)std::max((int64_t)0, gArgs.GetIntArg("-maxorphantx", DEFAULT_MAX_ORPHAN_TRANSACTIONS));
        m_orphanage.LimitOrphans(nMaxOrphanTx, rng);
    }
    if (state.IsInvalid()) {
        LogPrint(BCLog::MEMPOOLREJ, "%s was not accepted: %s\n", tx.GetHash().ToString(),
                state.ToString());
    }
    return;
}
