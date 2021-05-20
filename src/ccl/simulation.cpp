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
        txfile.reset(new CAutoFile(NULL, SER_DISK, CLIENT_VERSION));
    }
    InitAutoFile(blkfile, "block.", d);
    InitAutoFile(headersfile, "headers.", d);
    InitAutoFile(cmpctblockfile, "cmpctblock.", d);
    InitAutoFile(blocktxnfile, "blocktxn.", d);
}

void Simulation::InitAutoFile(unique_ptr<CAutoFile> &which, std::string fileprefix, date d)
{
    for (date s=d; s<= enddate; s += days(1)) {
        string filename = fileprefix + boost::gregorian::to_iso_string(s);
        boost::filesystem::path fullpath = logdir / filename;
        which.reset(new CAutoFile(fopen(fullpath.string().c_str(), "rb"),
                    SER_DISK, CLIENT_VERSION));
        if (!which->IsNull()) {
            LogPrintf("Simulation: InitAutoFile opened %s\n", fullpath.string().c_str());
            break;
        }
    }
}


void Simulation::Run()
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
                ProcessTransaction(txEvent.obj);
                txEvent.reset();
            } else if (nextEvent == &blockEvent) {
                cclGlobals->m_chainman->ProcessNewBlock(Params(), blockEvent.obj, true, NULL);
                blockEvent.reset();
            } else if (nextEvent == &headersEvent) {
                BlockValidationState dummy;
                cclGlobals->m_chainman->ProcessNewBlockHeaders(*(headersEvent.obj), dummy, Params(), NULL);
                headersEvent.reset();
            } else if (nextEvent == &cmpctblockEvent) {
                // Process cmpctblockEvent as a header message
                BlockValidationState dummy;
                cclGlobals->m_chainman->ProcessNewBlockHeaders({cmpctblockEvent.obj->header}, dummy, Params(), NULL);
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

// For simulations -- replicate the transaction processing done
// in the message processing off the network.
// When updating master, must revisit against current transaction processing
// logic
void Simulation::ProcessTransaction(const CTransactionRef& ptx)
{
    const CTransaction& tx = *ptx;
    CTxMemPool& mempool = *cclGlobals->m_mempool;
    CChainState& active_chainstate = cclGlobals->m_chainman->ActiveChainstate();

    CInv inv(MSG_TX, tx.GetHash());

    LOCK2(cs_main, g_cs_orphans);

    bool fMissingInputs = false;

    std::set<uint256> orphan_work_set;

    const GenTxid gtxid = ToGenTxid(inv);
    if (AlreadyHaveTx(gtxid)) return;

    const MempoolAcceptResult result = AcceptToMemoryPool(active_chainstate, mempool, ptx, false /* bypass_limits */);
    const TxValidationState& state = result.m_state;
    if (result.m_result_type == MempoolAcceptResult::ResultType::VALID) {
        mempool.check(active_chainstate);
        m_orphanage.AddChildrenToWorkSet(tx, orphan_work_set);

        LogPrint(BCLog::MEMPOOL, "AcceptToMemoryPool: accepted %s (poolsz %u txn, %u kB)\n",
                tx.GetHash().ToString(),
                mempool.size(), mempool.DynamicMemoryUsage() / 1000);

        // Recursively process any orphan transactions that depended on this one
        while (!orphan_work_set.empty()) {
            ProcessOrphanTx(orphan_work_set);
        }
    }
    else if (fMissingInputs)
    {
        bool fRejectedParents = false; // It may be the case that the orphans parents have all been rejected
        // Deduplicate parent txids, so that we don't have to loop over
        // the same parent txid more than once down below.
        std::vector<uint256> unique_parents;
        unique_parents.reserve(tx.vin.size());
        for (const CTxIn& txin : tx.vin) {
            // We start with all parents, and then remove duplicates below.
            unique_parents.push_back(txin.prevout.hash);
        }
        std::sort(unique_parents.begin(), unique_parents.end());
        unique_parents.erase(std::unique(unique_parents.begin(), unique_parents.end()), unique_parents.end());
        for (const uint256& parent_txid : unique_parents) {
            if (recentRejects.contains(parent_txid)) {
                fRejectedParents = true;
                break;
            }
        }
        if (!fRejectedParents) {
            m_orphanage.AddTx(ptx, 1234321); // hopefully a random unique value for the simulator to use
            // (note: there shouldn't be any CNode's in use in sim)

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded (see CVE-2012-3789)
            unsigned int nMaxOrphanTx = (unsigned int)std::max((int64_t)0, gArgs.GetArg("-maxorphantx", DEFAULT_MAX_ORPHAN_TRANSACTIONS));
            unsigned int nEvicted = m_orphanage.LimitOrphans(nMaxOrphanTx);
            if (nEvicted > 0) {
                LogPrint(BCLog::MEMPOOL, "mapOrphan overflow, removed %u tx\n", nEvicted);
            }
        } else {
            LogPrint(BCLog::MEMPOOL, "not keeping orphan with rejected parents %s\n",tx.GetHash().ToString());
            // We will continue to reject this tx since it has rejected
            // parents so avoid re-requesting it from other peers.
            recentRejects.insert(tx.GetHash());
        }
    } else {
        if ((!tx.HasWitness() && state.GetResult() != TxValidationResult::TX_WITNESS_MUTATED) ||
                state.GetResult() == TxValidationResult::TX_INPUTS_NOT_STANDARD) {
            // Do not use rejection cache for witness transactions or
            // witness-stripped transactions, as they can have been malleated.
            // See https://github.com/bitcoin/bitcoin/issues/8279 for details.
            // However, if the transaction failed for TX_INPUTS_NOT_STANDARD,
            // then we know that the witness was irrelevant to the policy
            // failure, since this check depends only on the txid
            // (the scriptPubKey being spent is covered by the txid).
            recentRejects.insert(tx.GetHash());
        } 
    }

    // If a tx has been detected by recentRejects, we will have reached
    // this point and the tx will have been ignored. Because we haven't run
    // the tx through AcceptToMemoryPool, we won't have computed a DoS
    // score for it or determined exactly why we consider it invalid.
    //
    // This means we won't penalize any peer subsequently relaying a DoSy
    // tx (even if we penalized the first peer who gave it to us) because
    // we have to account for recentRejects showing false positives. In
    // other words, we shouldn't penalize a peer if we aren't *sure* they
    // submitted a DoSy tx.
    //
    // Note that recentRejects doesn't just record DoSy or invalid
    // transactions, but any tx not accepted by the mempool, which may be
    // due to node policy (vs. consensus). So we can't blanket penalize a
    // peer simply for relaying a tx that our recentRejects has caught,
    // regardless of false positives.

    if (state.IsInvalid())
    {
        LogPrint(BCLog::MEMPOOLREJ, "%s was not accepted: %s\n", tx.GetHash().ToString(),
                state.ToString());
    }
}

void Simulation::ProcessOrphanTx(std::set<uint256>& orphan_work_set)
{
    CTxMemPool& m_mempool = *cclGlobals->m_mempool;
    CChainState& active_chainstate = cclGlobals->m_chainman->ActiveChainstate();

    AssertLockHeld(cs_main);
    AssertLockHeld(g_cs_orphans);

    while (!orphan_work_set.empty()) {
        const uint256 orphanHash = *orphan_work_set.begin();
        orphan_work_set.erase(orphan_work_set.begin());

        const auto [porphanTx, from_peer] = m_orphanage.GetTx(orphanHash);
        if (porphanTx == nullptr) continue;

        const MempoolAcceptResult result = AcceptToMemoryPool(active_chainstate, m_mempool, porphanTx, false /* bypass_limits */);
        const TxValidationState& state = result.m_state;

        if (result.m_result_type == MempoolAcceptResult::ResultType::VALID) {
            LogPrint(BCLog::MEMPOOL, "   accepted orphan tx %s\n", orphanHash.ToString());
            m_orphanage.AddChildrenToWorkSet(*porphanTx, orphan_work_set);
            m_orphanage.EraseTx(orphanHash);
            break;
        } else if (state.GetResult() != TxValidationResult::TX_MISSING_INPUTS) {
            if (state.IsInvalid()) {
                LogPrint(BCLog::MEMPOOL, "   invalid orphan tx %s from peer=%d. %s\n",
                    orphanHash.ToString(),
                    from_peer,
                    state.ToString());
            }
            // Has inputs but not accepted to mempool
            // Probably non-standard or insufficient fee
            LogPrint(BCLog::MEMPOOL, "   removed orphan tx %s\n", orphanHash.ToString());
            if (state.GetResult() != TxValidationResult::TX_WITNESS_STRIPPED) {
                // We can add the wtxid of this transaction to our reject filter.
                // Do not add txids of witness transactions or witness-stripped
                // transactions to the filter, as they can have been malleated;
                // adding such txids to the reject filter would potentially
                // interfere with relay of valid transactions from peers that
                // do not support wtxid-based relay. See
                // https://github.com/bitcoin/bitcoin/issues/8279 for details.
                // We can remove this restriction (and always add wtxids to
                // the filter even for witness stripped transactions) once
                // wtxid-based relay is broadly deployed.
                // See also comments in https://github.com/bitcoin/bitcoin/pull/18044#discussion_r443419034
                // for concerns around weakening security of unupgraded nodes
                // if we start doing this too early.
                recentRejects.insert(porphanTx->GetWitnessHash());
                // If the transaction failed for TX_INPUTS_NOT_STANDARD,
                // then we know that the witness was irrelevant to the policy
                // failure, since this check depends only on the txid
                // (the scriptPubKey being spent is covered by the txid).
                // Add the txid to the reject filter to prevent repeated
                // processing of this transaction in the event that child
                // transactions are later received (resulting in
                // parent-fetching by txid via the orphan-handling logic).
                if (state.GetResult() == TxValidationResult::TX_INPUTS_NOT_STANDARD && porphanTx->GetWitnessHash() != porphanTx->GetHash()) {
                    // We only add the txid if it differs from the wtxid, to
                    // avoid wasting entries in the rolling bloom filter.
                    recentRejects.insert(porphanTx->GetHash());
                }
            }
            m_orphanage.EraseTx(orphanHash);
            break;
        }
    }
    m_mempool.check(active_chainstate);
}

bool Simulation::AlreadyHaveTx(const GenTxid& gtxid)
{
    CChain& active_chain = cclGlobals->m_chainman->ActiveChain();
    if (active_chain.Tip()->GetBlockHash() != hashRecentRejectsChainTip) {
        // If the chain tip has changed previously rejected transactions
        // might be now valid, e.g. due to a nLockTime'd tx becoming valid,
        // or a double-spend. Reset the rejects filter and give those
        // txs a second chance.
        hashRecentRejectsChainTip = active_chain.Tip()->GetBlockHash();
        recentRejects.reset();
    }

    const uint256& hash = gtxid.GetHash();

    if (m_orphanage.HaveTx(gtxid)) return true;
    return recentRejects.contains(hash) || cclGlobals->m_mempool->exists(gtxid);
}
