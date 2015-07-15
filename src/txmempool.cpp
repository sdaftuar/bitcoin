// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txmempool.h"

#include "clientversion.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "main.h"
#include "policy/fees.h"
#include "streams.h"
#include "util.h"
#include "utilmoneystr.h"
#include "version.h"

using namespace std;

CTxMemPoolEntry::CTxMemPoolEntry():
    nFee(0), nTxSize(0), nModSize(0), nUsageSize(0), nTime(0), dPriority(0.0), hadNoDependencies(false),
    nCountWithDescendants(0), nSizeWithDescendants(0), nFeesWithDescendants(0)
{
    nHeight = MEMPOOL_HEIGHT;
}

CTxMemPoolEntry::CTxMemPoolEntry(const CTransaction& _tx, const CAmount& _nFee,
                                 int64_t _nTime, double _dPriority,
                                 unsigned int _nHeight, bool poolHasNoInputsOf):
    tx(_tx), nFee(_nFee), nTime(_nTime), dPriority(_dPriority), nHeight(_nHeight),
    hadNoDependencies(poolHasNoInputsOf)
{
    nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
    nModSize = tx.CalculateModifiedSize(nTxSize);
    nUsageSize = RecursiveDynamicUsage(tx);

    nCountWithDescendants = 1;
    nSizeWithDescendants = nTxSize;
    nFeesWithDescendants = nFee;
}

CTxMemPoolEntry::CTxMemPoolEntry(const CTxMemPoolEntry& other)
{
    *this = other;
}

double
CTxMemPoolEntry::GetPriority(unsigned int currentHeight) const
{
    CAmount nValueIn = tx.GetValueOut()+nFee;
    double deltaPriority = ((double)(currentHeight-nHeight)*nValueIn)/nModSize;
    double dResult = dPriority + deltaPriority;
    return dResult;
}

// Update the given tx for any in-mempool descendants.
// Assumes that setMemPoolChildren is correct for the given tx and all
// descendants.
bool CTxMemPool::UpdateForDescendants(indexed_transaction_set::iterator it, int maxDescendantsToVisit, std::map<uint256, std::set<uint256> > &cachedDescendants, const std::set<uint256> &setExclude)
{
    // Track the number of entries (outside setExclude) that we'd need to visit
    // (will bail out if it exceeds maxDescendantsToVisit)
    int nChildrenToVisit = 0; 

    std::set<uint256> stageHashes, setAllDescendants;
    stageHashes = it->GetMemPoolChildren();

    while (!stageHashes.empty()) {
        setAllDescendants.insert(stageHashes.begin(), stageHashes.end());

        std::set<uint256> hashesToAdd;
        BOOST_FOREACH(const uint256 &childhash, stageHashes) {
            indexed_transaction_set::iterator cit = mapTx.find(childhash);
            if (cit->IsDirty()) {
                // Don't consider any more children if any descendant is dirty
                return false;
            }
            const std::set<uint256> &setChildren = cit->GetMemPoolChildren();
            BOOST_FOREACH(const uint256 &nextHash, setChildren) {
                std::map<uint256, std::set<uint256> >::iterator cacheIt = cachedDescendants.find(nextHash);
                if (cacheIt != cachedDescendants.end()) {
                    // We've already calculated this one, just add the entries for this set
                    // but don't traverse again.
                    BOOST_FOREACH(const uint256 &cacheHash, cacheIt->second) {
                        // update visit count only for new child transactions
                        // (outside of setExclude and hashesToAdd)
                        if (setAllDescendants.insert(cacheHash).second &&
                                !setExclude.count(cacheHash) &&
                                !hashesToAdd.count(cacheHash)) {
                            nChildrenToVisit++;
                        }
                    }
                } else if (!setAllDescendants.count(nextHash)) {
                    // Try adding to hashesToAdd, and update our visit count
                    if (hashesToAdd.insert(nextHash).second && !setExclude.count(nextHash)) {
                        nChildrenToVisit++;
                    }
                }
                if (nChildrenToVisit > maxDescendantsToVisit) {
                    return false;
                }
            }
        }
        stageHashes = hashesToAdd;
    }
    // setAllDescendants now contains all in-mempool descendants of hash.
    // Update and add to cached descendant map
    int64_t modifySize = 0;
    CAmount modifyFee = 0;
    int64_t modifyCount = 0;
    BOOST_FOREACH(const uint256 &chash, setAllDescendants) {
        if (!setExclude.count(chash)) {
            indexed_transaction_set::iterator cit = mapTx.find(chash);
            modifySize += cit->GetTxSize();
            modifyFee += cit->GetFee();
            modifyCount++;
            cachedDescendants[it->GetTx().GetHash()].insert(chash);
        }
    }
    mapTx.modify(it, update_descendant_state(modifySize, modifyFee, modifyCount));
    return true;
}

// vHashesToUpdate is the set of transaction hashes from a disconnected block
// which has been re-added to the mempool.
// for each entry, look for descendants that are outside hashesToUpdate, and
// add fee/size information for such descendants to the parent.
void CTxMemPool::UpdateTransactionsFromBlock(const std::vector<uint256> &vHashesToUpdate)
{
    // For each entry in vHashesToUpdate, store the set of in-mempool, but not
    // in-vHashesToUpdate transactions, so that we don't have to recalculate
    // descendants when we come across a previously seen entry.
    std::map<uint256, std::set<uint256> > mapMemPoolDescendantsToUpdate;

    // Use a set for lookups into vHashesToUpdate (these entries are already
    // accounted for in the state of their ancestors)
    std::set<uint256> setAlreadyIncluded(vHashesToUpdate.begin(), vHashesToUpdate.end());

    // Iterate in reverse, so that whenever we are looking at at a transaction
    // we are sure that all in-mempool descendants have already been processed.
    // This maximizes the benefit of the descendant cache and guarantees that
    // setMemPoolChildren will be updated, an assumption made in
    // UpdateForDescendants.
    BOOST_REVERSE_FOREACH(const uint256 &hash, vHashesToUpdate) {
        std::set<uint256> stageHashes;
        // calculate children from mapNextTx
        indexed_transaction_set::iterator it = mapTx.find(hash);
        if (it == mapTx.end()) {
            continue;
        }
        std::map<COutPoint, CInPoint>::iterator iter = mapNextTx.lower_bound(COutPoint(hash, 0));
        // First calculate the children, and update setMemPoolChildren to
        // include them, and update their setMemPoolParents to include this tx.
        for (; iter != mapNextTx.end() && iter->first.hash == hash; ++iter) {
            const uint256 &childHash = iter->second.ptx->GetHash();
            // We can skip updating entries we've encountered before or that
            // are in the block (which are already accounted for).
            if (stageHashes.insert(childHash).second && !setAlreadyIncluded.count(childHash)) {
                mapTx.modify(it, update_children(*this, true, childHash));
                mapTx.modify(mapTx.find(childHash), update_parent(*this, true, hash));
            }
        }
        if (!UpdateForDescendants(it, 100, mapMemPoolDescendantsToUpdate, setAlreadyIncluded)) {
            // Mark as dirty if we can't do the calculation.
            mapTx.modify(it, set_dirty());
        }
    }
}

bool CTxMemPool::CalculateMemPoolAncestors(const CTxMemPoolEntry &entry, std::set<uint256> &setAncestors, uint64_t limitAncestorCount, uint64_t limitAncestorSize, uint64_t limitDescendantCount, uint64_t limitDescendantSize, CValidationState &state)
{
    std::set<uint256> parentHashes;
    const CTransaction &tx = entry.GetTx();

    // Get parents of this transaction that are in the mempool
    // entry may or may not already be in the mempool, so we iterate mapTx
    // to find parents, rather than try entry.GetMemPoolParents()
    // TODO: optimize this so that we only check limits and walk
    // tx.vin when called on entries not already in the mempool.
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        if (mapTx.find(tx.vin[i].prevout.hash) != mapTx.end()) {
            parentHashes.insert(tx.vin[i].prevout.hash);
            if (parentHashes.size() + 1 > limitAncestorCount) {
                return state.DoS(0, false, REJECT_LONGCHAIN, strprintf("too many unconfirmed parents [limit: %u]", limitAncestorCount));
            }
        }
    }

    size_t totalSizeWithAncestors = entry.GetTxSize();

    while (!parentHashes.empty()) {
        setAncestors.insert(parentHashes.begin(), parentHashes.end());
        std::set<uint256> stageParentSet; 
        BOOST_FOREACH(const uint256 &stageHash, parentHashes) {
            indexed_transaction_set::iterator stageit = mapTx.find(stageHash);
            assert(stageit != mapTx.end());

            totalSizeWithAncestors += stageit->GetTxSize();
            if (stageit->GetSizeWithDescendants() + entry.GetTxSize() > limitDescendantSize) {
                return state.DoS(0, false, REJECT_LONGCHAIN, strprintf("exceeds descendant size limit for tx %s [limit: %u]", stageHash.ToString().substr(0,10), limitDescendantSize));
            } else if (uint64_t(stageit->GetCountWithDescendants() + 1) > limitDescendantCount) {
                return state.DoS(0, false, REJECT_LONGCHAIN, strprintf("too many descendants for tx %s [limit: %u]", stageHash.ToString().substr(0,10), limitDescendantCount));
            } else if (totalSizeWithAncestors > limitAncestorSize) {
                return state.DoS(0, false, REJECT_LONGCHAIN, strprintf("exceeds ancestor size limit [limit: %u]", limitAncestorSize));
            }

            const std::set<uint256> & setMemPoolParents = stageit->GetMemPoolParents();
            BOOST_FOREACH(const uint256 &phash, setMemPoolParents) {
                // If this is a new ancestor, add it.
                if (setAncestors.count(phash) == 0) {
                    stageParentSet.insert(phash);
                }
                if (stageParentSet.size() + setAncestors.size() + 1 > limitAncestorCount) {
                    return state.DoS(0, false, REJECT_LONGCHAIN, strprintf("too-many-ancestors [limit: %u]", limitAncestorCount));
                }
            }    
        }
        parentHashes = stageParentSet;
    }

    return true;
}

void CTxMemPool::UpdateAncestorsOf(bool add, const uint256 &hash, const std::set<uint256> &setAncestors)
{
    indexed_transaction_set::iterator it = mapTx.find(hash);
    const std::set<uint256> &parentHashes = it->GetMemPoolParents();
    BOOST_FOREACH(const uint256 &phash, parentHashes) {
        // add or remove hash as a child of phash
        indexed_transaction_set::iterator pit = mapTx.find(phash);
        assert (pit != mapTx.end());
        mapTx.modify(pit, update_children(*this, add, hash));
    }
    int64_t updateCount = (add ? 1 : -1);
    int64_t updateSize = updateCount * it->GetTxSize();
    CAmount updateFee = updateCount * it->GetFee();
    BOOST_FOREACH(const uint256 &ancestorHash, setAncestors) {
        indexed_transaction_set::iterator updateIt = mapTx.find(ancestorHash);
        assert (updateIt != mapTx.end());
        mapTx.modify(updateIt, update_descendant_state(updateSize, updateFee, updateCount));
    }
}

void CTxMemPool::UpdateChildrenForRemoval(const uint256 &hash)
{
    const std::set<uint256> &setMemPoolChildren = mapTx.find(hash)->GetMemPoolChildren();
    BOOST_FOREACH(const uint256 &childHash, setMemPoolChildren) {
        indexed_transaction_set::iterator updateIt = mapTx.find(childHash);
        assert(updateIt != mapTx.end());
        mapTx.modify(updateIt, update_parent(*this, false, hash));
    }
}

void CTxMemPool::UpdateForRemoveFromMempool(const std::set<uint256> &hashesToRemove)
{
    // For each entry, walk back all ancestors and decrement size associated with this
    // transaction
    uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
    BOOST_FOREACH(const uint256& removeHash, hashesToRemove) {
        std::set<uint256> setAncestors;
        CValidationState dummy;
        const CTxMemPoolEntry &entry = *mapTx.find(removeHash);
        CalculateMemPoolAncestors(entry, setAncestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy);
        // Note that UpdateAncestorsOf severs the child links that point to
        // removeHash in the entries for the parents of removeHash.  This is
        // fine since we don't need to use the mempool children of any entries
        // to walk back over our ancestors (but we do need the mempool
        // parents!)
        UpdateAncestorsOf(false, removeHash, setAncestors);
    }
    // After updating all the ancestor sizes, we can now sever the link between each
    // transaction being removed and any mempool children (ie, update setMemPoolParents
    // for each direct child of a transaction being removed).
    BOOST_FOREACH(const uint256& removeHash, hashesToRemove) {
        UpdateChildrenForRemoval(removeHash);
    }
}

void CTxMemPoolEntry::SetDirty()
{
    nCountWithDescendants=0;
    nSizeWithDescendants=nTxSize;
    nFeesWithDescendants=nFee;
}

size_t CTxMemPoolEntry::UpdateParent(bool add, uint256 hash)
{
    size_t ret=0;
    if (add && setMemPoolParents.insert(hash).second) {
        ret = memusage::IncrementalDynamicUsage(setMemPoolParents);
        nUsageSize += ret;
    } else if (!add && setMemPoolParents.erase(hash)) {
        ret = memusage::IncrementalDynamicUsage(setMemPoolParents);
        nUsageSize -= ret;
    }
    return ret;
}

size_t CTxMemPoolEntry::UpdateChildren(bool add, uint256 hash)
{
    size_t ret=0;
    if (add && setMemPoolChildren.insert(hash).second) {
        ret = memusage::IncrementalDynamicUsage(setMemPoolChildren);
        nUsageSize += ret;
    } else if (!add && setMemPoolChildren.erase(hash)) { 
        ret = memusage::IncrementalDynamicUsage(setMemPoolChildren);
        nUsageSize -= ret;
    }
    return ret;
}

void CTxMemPoolEntry::UpdateState(int64_t modifySize, CAmount modifyFee, int64_t modifyCount)
{
    if (!IsDirty()) {
        nSizeWithDescendants += modifySize;
        nFeesWithDescendants += modifyFee;
        nCountWithDescendants += modifyCount;
    }
}

CTxMemPool::CTxMemPool(const CFeeRate& _minRelayFee) :
    nTransactionsUpdated(0)
{
    // Sanity checks off by default for performance, because otherwise
    // accepting transactions becomes O(N^2) where N is the number
    // of transactions in the pool
    fSanityCheck = false;

    minerPolicyEstimator = new CBlockPolicyEstimator(_minRelayFee);
}

CTxMemPool::~CTxMemPool()
{
    delete minerPolicyEstimator;
}

void CTxMemPool::pruneSpent(const uint256 &hashTx, CCoins &coins)
{
    LOCK(cs);

    std::map<COutPoint, CInPoint>::iterator it = mapNextTx.lower_bound(COutPoint(hashTx, 0));

    // iterate over all COutPoints in mapNextTx whose hash equals the provided hashTx
    while (it != mapNextTx.end() && it->first.hash == hashTx) {
        coins.Spend(it->first.n); // and remove those outputs from coins
        it++;
    }
}

unsigned int CTxMemPool::GetTransactionsUpdated() const
{
    LOCK(cs);
    return nTransactionsUpdated;
}

void CTxMemPool::AddTransactionsUpdated(unsigned int n)
{
    LOCK(cs);
    nTransactionsUpdated += n;
}


bool CTxMemPool::addUnchecked(const uint256& hash, const CTxMemPoolEntry &entry, const std::set<uint256> &setAncestors, bool fCurrentEstimate)
{
    // Add to memory pool without checking anything.
    // Used by main.cpp AcceptToMemoryPool(), which DOES do
    // all the appropriate checks.
    LOCK(cs);
    indexed_transaction_set::iterator newit = mapTx.insert(entry).first;
    // Update cachedInnerUsage before we add parents, which will update
    // it further.
    cachedInnerUsage += entry.DynamicMemoryUsage();

    const CTransaction& tx = newit->GetTx();
    std::set<uint256> setParentTransactions;
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        mapNextTx[tx.vin[i].prevout] = CInPoint(&tx, i);
        setParentTransactions.insert(tx.vin[i].prevout.hash);
    }
    // Don't bother worrying about child transactions of this one.
    // Normal case of a new transaction arriving is that there can't be any
    // children, because such children would be orphans.
    // An exception to that is if a transaction enters that used to be in a block.
    // In that case, our disconnect block logic will call UpdateTransactionsFromBlock
    // to clean up the mess we're leaving here.

    // Update ancestors with information about this tx
    std::set<uint256> updatedParentEntries;
    BOOST_FOREACH (const uint256 &phash, setParentTransactions) {
        if (mapTx.count(phash)) {
            mapTx.modify(newit, update_parent(*this, true, phash));
        }
    }
    UpdateAncestorsOf(true, hash, setAncestors);

    nTransactionsUpdated++;
    totalTxSize += entry.GetTxSize();
    minerPolicyEstimator->processTransaction(entry, fCurrentEstimate);

    return true;
}


// Calculates descendants of hash that are not already in setDescendants, and adds to 
// setDescendants. Assumes hash is already a tx in the mempool and setMemPoolChildren
// is correct for tx and all descendants.
// Also assumes that if an entry is in setDescendants already, then all
// in-mempool descendants of it are already in setDescendants as well, so that we
// can save time by not iterating over those entries.
void CTxMemPool::CalculateDescendants(const uint256 &hash, std::set<uint256> &setDescendants)
{
    std::set<uint256> stage;
    if (setDescendants.count(hash) == 0) {
        stage.insert(hash);
    }
    // Traverse down the children of each hash, only adding children that are not
    // accounted for in setDescendants already (because those children have either
    // already been walked, or will be walked in this iteration).
    while (!stage.empty()) {
        setDescendants.insert(stage.begin(), stage.end());
        std::set<uint256> setNext;
        BOOST_FOREACH(const uint256 &stagehash, stage) {
            indexed_transaction_set::iterator it = mapTx.find(stagehash);
            const std::set<uint256> &setChildren = it->GetMemPoolChildren();
            BOOST_FOREACH(const uint256 &childhash, setChildren) {
                if (!setDescendants.count(childhash)) {
                    setNext.insert(childhash);
                }
            }
        }
        stage = setNext;
    }
}

void CTxMemPool::remove(const CTransaction &origTx, std::list<CTransaction>& removed, bool fRecursive)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        std::set<uint256> txToRemove;
        if (mapTx.count(origTx.GetHash())) {
            txToRemove.insert(origTx.GetHash());
        } else if (fRecursive) {
            // If recursively removing but origTx isn't in the mempool
            // be sure to remove any children that are in the pool. This can
            // happen during chain re-orgs if origTx isn't re-accepted into
            // the mempool for any reason.
            for (unsigned int i = 0; i < origTx.vout.size(); i++) {
                std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(COutPoint(origTx.GetHash(), i));
                if (it == mapNextTx.end())
                    continue;
                txToRemove.insert(it->second.ptx->GetHash());
            }
        }
        std::set<uint256> setAllRemoves;
        if (fRecursive) {
            BOOST_FOREACH(const uint256 &hash, txToRemove) {
                CalculateDescendants(hash, setAllRemoves);
            }
        } else {
            setAllRemoves = txToRemove;
        }
        BOOST_FOREACH(const uint256& hash, setAllRemoves) {
            removed.push_back(mapTx.find(hash)->GetTx());
        }
        RemoveStaged(setAllRemoves);
    }
}

void CTxMemPool::removeCoinbaseSpends(const CCoinsViewCache *pcoins, unsigned int nMemPoolHeight)
{
    // Remove transactions spending a coinbase which are now immature
    LOCK(cs);
    list<CTransaction> transactionsToRemove;
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        const CTransaction& tx = it->GetTx();
        BOOST_FOREACH(const CTxIn& txin, tx.vin) {
            indexed_transaction_set::const_iterator it2 = mapTx.find(txin.prevout.hash);
            if (it2 != mapTx.end())
                continue;
            const CCoins *coins = pcoins->AccessCoins(txin.prevout.hash);
            if (fSanityCheck) assert(coins);
            if (!coins || (coins->IsCoinBase() && ((signed long)nMemPoolHeight) - coins->nHeight < COINBASE_MATURITY)) {
                transactionsToRemove.push_back(tx);
                break;
            }
        }
    }
    BOOST_FOREACH(const CTransaction& tx, transactionsToRemove) {
        list<CTransaction> removed;
        remove(tx, removed, true);
    }
}

void CTxMemPool::removeConflicts(const CTransaction &tx, std::list<CTransaction>& removed)
{
    // Remove transactions which depend on inputs of tx, recursively
    list<CTransaction> result;
    LOCK(cs);
    BOOST_FOREACH(const CTxIn &txin, tx.vin) {
        std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end()) {
            const CTransaction &txConflict = *it->second.ptx;
            if (txConflict != tx)
            {
                remove(txConflict, removed, true);
            }
        }
    }
}

/**
 * Called when a block is connected. Removes from mempool and updates the miner fee estimator.
 */
void CTxMemPool::removeForBlock(const std::vector<CTransaction>& vtx, unsigned int nBlockHeight,
                                std::list<CTransaction>& conflicts, bool fCurrentEstimate)
{
    LOCK(cs);
    std::vector<CTxMemPoolEntry> entries;
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        uint256 hash = tx.GetHash();

        indexed_transaction_set::iterator i = mapTx.find(hash);
        if (i != mapTx.end())
            entries.push_back(*i);
    }
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        std::list<CTransaction> dummy;
        remove(tx, dummy, false);
        removeConflicts(tx, conflicts);
        ClearPrioritisation(tx.GetHash());
    }
    // After the txs in the new block have been removed from the mempool, update policy estimates
    minerPolicyEstimator->processBlock(nBlockHeight, entries, fCurrentEstimate);
}

void CTxMemPool::clear()
{
    LOCK(cs);
    mapTx.clear();
    mapNextTx.clear();
    totalTxSize = 0;
    cachedInnerUsage = 0;
    ++nTransactionsUpdated;
}

void CTxMemPool::check(const CCoinsViewCache *pcoins) const
{
    if (!fSanityCheck)
        return;

    LogPrint("mempool", "Checking mempool with %u transactions and %u inputs\n", (unsigned int)mapTx.size(), (unsigned int)mapNextTx.size());

    uint64_t checkTotal = 0;
    uint64_t innerUsage = 0;

    CCoinsViewCache mempoolDuplicate(const_cast<CCoinsViewCache*>(pcoins));

    LOCK(cs);
    list<const CTxMemPoolEntry*> waitingOnDependants;
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        unsigned int i = 0;
        checkTotal += it->GetTxSize();
        innerUsage += it->DynamicMemoryUsage();
        const CTransaction& tx = it->GetTx();
        bool fDependsWait = false;
        std::set<uint256> setParentCheck;
        BOOST_FOREACH(const CTxIn &txin, tx.vin) {
            // Check that every mempool transaction's inputs refer to available coins, or other mempool tx's.
            indexed_transaction_set::const_iterator it2 = mapTx.find(txin.prevout.hash);
            if (it2 != mapTx.end()) {
                const CTransaction& tx2 = it2->GetTx();
                assert(tx2.vout.size() > txin.prevout.n && !tx2.vout[txin.prevout.n].IsNull());
                fDependsWait = true;
                setParentCheck.insert(it2->GetTx().GetHash());
            } else {
                const CCoins* coins = pcoins->AccessCoins(txin.prevout.hash);
                assert(coins && coins->IsAvailable(txin.prevout.n));
            }
            // Check whether its inputs are marked in mapNextTx.
            std::map<COutPoint, CInPoint>::const_iterator it3 = mapNextTx.find(txin.prevout);
            assert(it3 != mapNextTx.end());
            assert(it3->second.ptx == &tx);
            assert(it3->second.n == i);
            i++;
        }
        assert(setParentCheck == it->GetMemPoolParents());
        // Check children against mapNextTx
        std::set<uint256> setChildrenCheck;
        std::map<COutPoint, CInPoint>::const_iterator iter = mapNextTx.lower_bound(COutPoint(it->GetTx().GetHash(), 0));
        int64_t childSizes = 0;
        CAmount childFees = 0;
        for (; iter != mapNextTx.end() && iter->first.hash == it->GetTx().GetHash(); ++iter) {
            if (setChildrenCheck.insert(iter->second.ptx->GetHash()).second) {
                indexed_transaction_set::const_iterator childit = mapTx.find(iter->second.ptx->GetHash());
                childSizes += childit->GetTxSize();
                childFees += childit->GetFee();
            }
        }
        assert(setChildrenCheck == it->GetMemPoolChildren());
        // Also check to make sure size/fees is greater than sum with immediate children.
        // just a sanity check, not definitive that this calc is correct...
        // also check that the size is less than the size of the entire mempool.
        if (!it->IsDirty()) {
            assert(it->GetSizeWithDescendants() >= childSizes + int64_t(it->GetTxSize()));
            assert(it->GetFeesWithDescendants() >= childFees + it->GetFee());
        } else {
            assert(it->GetSizeWithDescendants() == int64_t(it->GetTxSize()));
            assert(it->GetFeesWithDescendants() == it->GetFee());
        }
        assert(it->GetFeesWithDescendants() >= 0);

        if (fDependsWait)
            waitingOnDependants.push_back(&(*it));
        else {
            CValidationState state;
            assert(CheckInputs(tx, state, mempoolDuplicate, false, 0, false, NULL));
            UpdateCoins(tx, state, mempoolDuplicate, 1000000);
        }
    }
    unsigned int stepsSinceLastRemove = 0;
    while (!waitingOnDependants.empty()) {
        const CTxMemPoolEntry* entry = waitingOnDependants.front();
        waitingOnDependants.pop_front();
        CValidationState state;
        if (!mempoolDuplicate.HaveInputs(entry->GetTx())) {
            waitingOnDependants.push_back(entry);
            stepsSinceLastRemove++;
            assert(stepsSinceLastRemove < waitingOnDependants.size());
        } else {
            assert(CheckInputs(entry->GetTx(), state, mempoolDuplicate, false, 0, false, NULL));
            UpdateCoins(entry->GetTx(), state, mempoolDuplicate, 1000000);
            stepsSinceLastRemove = 0;
        }
    }
    for (std::map<COutPoint, CInPoint>::const_iterator it = mapNextTx.begin(); it != mapNextTx.end(); it++) {
        uint256 hash = it->second.ptx->GetHash();
        indexed_transaction_set::const_iterator it2 = mapTx.find(hash);
        const CTransaction& tx = it2->GetTx();
        assert(it2 != mapTx.end());
        assert(&tx == it->second.ptx);
        assert(tx.vin.size() > it->second.n);
        assert(it->first == it->second.ptx->vin[it->second.n].prevout);
    }

    assert(totalTxSize == checkTotal);
    assert(innerUsage == cachedInnerUsage);
}

void CTxMemPool::queryHashes(vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (indexed_transaction_set::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back(mi->GetTx().GetHash());
}

bool CTxMemPool::lookup(uint256 hash, CTransaction& result) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end()) return false;
    result = i->GetTx();
    return true;
}

CFeeRate CTxMemPool::estimateFee(int nBlocks) const
{
    LOCK(cs);
    return minerPolicyEstimator->estimateFee(nBlocks);
}
double CTxMemPool::estimatePriority(int nBlocks) const
{
    LOCK(cs);
    return minerPolicyEstimator->estimatePriority(nBlocks);
}

bool
CTxMemPool::WriteFeeEstimates(CAutoFile& fileout) const
{
    try {
        LOCK(cs);
        fileout << 109900; // version required to read: 0.10.99 or later
        fileout << CLIENT_VERSION; // version that wrote the file
        minerPolicyEstimator->Write(fileout);
    }
    catch (const std::exception&) {
        LogPrintf("CTxMemPool::WriteFeeEstimates(): unable to write policy estimator data (non-fatal)\n");
        return false;
    }
    return true;
}

bool
CTxMemPool::ReadFeeEstimates(CAutoFile& filein)
{
    try {
        int nVersionRequired, nVersionThatWrote;
        filein >> nVersionRequired >> nVersionThatWrote;
        if (nVersionRequired > CLIENT_VERSION)
            return error("CTxMemPool::ReadFeeEstimates(): up-version (%d) fee estimate file", nVersionRequired);

        LOCK(cs);
        minerPolicyEstimator->Read(filein);
    }
    catch (const std::exception&) {
        LogPrintf("CTxMemPool::ReadFeeEstimates(): unable to read policy estimator data (non-fatal)\n");
        return false;
    }
    return true;
}

void CTxMemPool::PrioritiseTransaction(const uint256 hash, const string strHash, double dPriorityDelta, const CAmount& nFeeDelta)
{
    {
        LOCK(cs);
        std::pair<double, CAmount> &deltas = mapDeltas[hash];
        deltas.first += dPriorityDelta;
        deltas.second += nFeeDelta;
    }
    LogPrintf("PrioritiseTransaction: %s priority += %f, fee += %d\n", strHash, dPriorityDelta, FormatMoney(nFeeDelta));
}

void CTxMemPool::ApplyDeltas(const uint256 hash, double &dPriorityDelta, CAmount &nFeeDelta)
{
    LOCK(cs);
    std::map<uint256, std::pair<double, CAmount> >::iterator pos = mapDeltas.find(hash);
    if (pos == mapDeltas.end())
        return;
    const std::pair<double, CAmount> &deltas = pos->second;
    dPriorityDelta += deltas.first;
    nFeeDelta += deltas.second;
}

void CTxMemPool::ClearPrioritisation(const uint256 hash)
{
    LOCK(cs);
    mapDeltas.erase(hash);
}

bool CTxMemPool::HasNoInputsOf(const CTransaction &tx) const
{
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        if (exists(tx.vin[i].prevout.hash))
            return false;
    return true;
}

CCoinsViewMemPool::CCoinsViewMemPool(CCoinsView *baseIn, CTxMemPool &mempoolIn) : CCoinsViewBacked(baseIn), mempool(mempoolIn) { }

bool CCoinsViewMemPool::GetCoins(const uint256 &txid, CCoins &coins) const {
    // If an entry in the mempool exists, always return that one, as it's guaranteed to never
    // conflict with the underlying cache, and it cannot have pruned entries (as it contains full)
    // transactions. First checking the underlying cache risks returning a pruned entry instead.
    CTransaction tx;
    if (mempool.lookup(txid, tx)) {
        coins = CCoins(tx, MEMPOOL_HEIGHT);
        return true;
    }
    return (base->GetCoins(txid, coins) && !coins.IsPruned());
}

bool CCoinsViewMemPool::HaveCoins(const uint256 &txid) const {
    return mempool.exists(txid) || base->HaveCoins(txid);
}

size_t CTxMemPool::DynamicMemoryUsage() const {
    LOCK(cs);
    // Estimate the overhead of mapTx to be 9 pointers + an allocation, as no exact formula for boost::multi_index_contained is implemented.
    return memusage::MallocUsage(sizeof(CTxMemPoolEntry) + 9 * sizeof(void*)) * mapTx.size() + memusage::DynamicUsage(mapNextTx) + memusage::DynamicUsage(mapDeltas) + cachedInnerUsage;
}

void CTxMemPool::RemoveStaged(std::set<uint256>& stage) {
    UpdateForRemoveFromMempool(stage);
    BOOST_FOREACH(const uint256& hash, stage) {
        removeUnchecked(hash);
    }
}

bool CTxMemPool::addUnchecked(const uint256&hash, const CTxMemPoolEntry &entry, bool fCurrentEstimate)
{
    std::set<uint256> setAncestors;
    uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
    CValidationState dummy;
    CalculateMemPoolAncestors(entry, setAncestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy);
    return addUnchecked(hash, entry, setAncestors, fCurrentEstimate);
}

// TODO: replace this hash with an iterator?
void CTxMemPool::removeUnchecked(const uint256& hash)
{
    indexed_transaction_set::iterator it = mapTx.find(hash);

    BOOST_FOREACH(const CTxIn& txin, it->GetTx().vin)
        mapNextTx.erase(txin.prevout);

    totalTxSize -= it->GetTxSize();
    cachedInnerUsage -= it->DynamicMemoryUsage();
    mapTx.erase(it);
    nTransactionsUpdated++;
    minerPolicyEstimator->removeTx(hash);
}

void update_parent::operator() (CTxMemPoolEntry &e)
{
    int64_t updateSize = e.UpdateParent(add, hash);
    if (!add)
        updateSize *= -1;
    pool.UpdateInnerUsage(updateSize);
}

void update_children::operator() (CTxMemPoolEntry &e)
{
    int64_t updateSize = e.UpdateChildren(add, hash);
    if (!add)
        updateSize *= -1;
    pool.UpdateInnerUsage(updateSize);
}

void CTxMemPool::UpdateInnerUsage(int64_t sizeAdjustment)
{
    cachedInnerUsage += sizeAdjustment;
}
