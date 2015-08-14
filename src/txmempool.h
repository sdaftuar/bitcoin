// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXMEMPOOL_H
#define BITCOIN_TXMEMPOOL_H

#include <list>
#include <set>

#include "amount.h"
#include "coins.h"
#include "primitives/transaction.h"
#include "sync.h"

#undef foreach
#include "boost/multi_index_container.hpp"
#include "boost/multi_index/ordered_index.hpp"

class CAutoFile;
class CValidationState;

inline double AllowFreeThreshold()
{
    return COIN * 144 / 250;
}

inline bool AllowFree(double dPriority)
{
    // Large (in bytes) low-priority (new, small-coin) transactions
    // need a fee.
    return dPriority > AllowFreeThreshold();
}

/** Fake height value used in CCoins to signify they are only in the memory pool (since 0.8) */
static const unsigned int MEMPOOL_HEIGHT = 0x7FFFFFFF;

class CTxMemPool;

/** \class CTxMemPoolEntry
 *
 * CTxMemPoolEntry stores data about the correponding transaction, as well
 * as data about all in-mempool transactions that depend on the transaction
 * ("descendant" transactions).  We track state for descendant transactions
 * in order to make limiting the size of the mempool work better (see below).
 *
 * When a new entry is added to the mempool, we update setMemPoolParents to
 * contain all the unconfirmed (ie, in-mempool) parents of the transaction.
 * This is used when walking back to look at ancestors of a transactions.
 * We also update setMemPoolChildren for the direct parents of a transaction,
 * and we update the descendant state (nCountWithDescendants,
 * nSizeWithDescendants, and nFeesWithDescendants) for all ancestors of the
 * newly added transaction.
 *
 * If updating the descendant state is skipped, we can mark the entry as
 * "dirty", and set nSizeWithDescendants/nFeesWithDescendants to equal nTxSize/
 * nTxFee. (This can potentially happen during a reorg, where we limit the
 * amount of work we're willing to do to avoid consuming too much CPU.)
 *
 * Generally, setMemPoolChildren and setMemPoolParents should match the exact
 * set of in-mempool children/parents (this is enforced by CTxMemPool).  But
 * this will temporarily not be the case when transactions are added back to
 * the mempool after a block is disconnected.  See discussion below.
 */

class CTxMemPoolEntry
{
private:
    CTransaction tx;
    CAmount nFee; //! Cached to avoid expensive parent-transaction lookups
    size_t nTxSize; //! ... and avoid recomputing tx size
    size_t nModSize; //! ... and modified size for priority
    size_t nUsageSize; //! ... and total memory usage
    int64_t nTime; //! Local time when entering the mempool
    double dPriority; //! Priority when entering the mempool
    unsigned int nHeight; //! Chain height when entering the mempool
    bool hadNoDependencies; //! Not dependent on any other txs when it entered the mempool

    std::set<uint256> setMemPoolParents;  //! Track in-mempool parents 
    std::set<uint256> setMemPoolChildren; //! ... and in-mempool children

    // Information about descendants of this transaction that are in the
    // mempool; if we remove this transaction we must remove all of these
    // descendants as well.  if nCountWithDescendants is 0, treat this entry as
    // dirty, and nSizeWithDescendants and nFeesWithDescendants will not be
    // correct.
    int64_t nCountWithDescendants; //! number of descendant transactions
    int64_t nSizeWithDescendants;  //! ... and size
    CAmount nFeesWithDescendants;  //! ... and total fees (all including us)

public:
    CTxMemPoolEntry(const CTransaction& _tx, const CAmount& _nFee,
                    int64_t _nTime, double _dPriority, unsigned int _nHeight, bool poolHasNoInputsOf = false);
    CTxMemPoolEntry();
    CTxMemPoolEntry(const CTxMemPoolEntry& other);

    const CTransaction& GetTx() const { return this->tx; }
    double GetPriority(unsigned int currentHeight) const;
    const CAmount& GetFee() const { return nFee; }
    size_t GetTxSize() const { return nTxSize; }
    int64_t GetTime() const { return nTime; }
    unsigned int GetHeight() const { return nHeight; }
    bool WasClearAtEntry() const { return hadNoDependencies; }
    size_t DynamicMemoryUsage() const { return nUsageSize; }

    // Adjusts the descendant state, if this entry is not dirty.
    void UpdateState(int64_t modifySize, CAmount modifyFee, int64_t modifyCount);

    // Returns estimated memory allocated/released
    size_t UpdateParent(bool add, uint256 hash);
    size_t UpdateChildren(bool add, uint256 hash);

    /** We can set the entry to be dirty if doing the full calculation of in-
     *  mempool descendants will be too expensive, which can potentially happen
     *  when re-adding transactions from a block back to the mempool.
     */
    void SetDirty();
    bool IsDirty() const { return nCountWithDescendants == 0; }

    const std::set<uint256> & GetMemPoolParents() const { return setMemPoolParents; }
    const std::set<uint256> & GetMemPoolChildren() const { return setMemPoolChildren; }

    int64_t GetCountWithDescendants() const { return nCountWithDescendants; }
    int64_t GetSizeWithDescendants() const { return nSizeWithDescendants; }
    CAmount GetFeesWithDescendants() const { return nFeesWithDescendants; }
};

// Helpers for modifying CTxMemPool::mapTx, which is a boost multi_index.
struct update_parent
{
    update_parent(CTxMemPool &_pool, bool _add, uint256 _hash): pool(_pool), add(_add), hash(_hash) 
    {}

    void operator() (CTxMemPoolEntry &e);

    private:
        CTxMemPool &pool;
        bool add;
        uint256 hash;
};

struct update_children
{
    update_children(CTxMemPool &_pool, bool _add, uint256 _hash): pool(_pool), add(_add), hash(_hash) 
    {}

    void operator() (CTxMemPoolEntry &e);

    private:
        CTxMemPool &pool;
        bool add;
        uint256 hash;
};

struct update_descendant_state
{
    update_descendant_state(int64_t _modifySize, CAmount _modifyFee, int64_t _modifyCount) :
        modifySize(_modifySize), modifyFee(_modifyFee), modifyCount(_modifyCount)
    {}

    void operator() (CTxMemPoolEntry &e)
        { e.UpdateState(modifySize, modifyFee, modifyCount); }

    private:
        int64_t modifySize;
        CAmount modifyFee;
        int64_t modifyCount;
};

struct set_dirty
{
    void operator() (CTxMemPoolEntry &e)
        { e.SetDirty(); }
};

// extracts a TxMemPoolEntry's transaction hash
struct mempoolentry_txid
{
    typedef uint256 result_type;
    result_type operator() (const CTxMemPoolEntry &entry) const
    {
        return entry.GetTx().GetHash();
    }
};

/** \class CompareTxMemPoolEntryByFeeRate
 *
 *  Sort an entry by max(feerate of entry's tx, feerate with all descendants).
 */
class CompareTxMemPoolEntryByFeeRate
{
public:
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b)
    {
        bool fUseADescendants = UseDescendantFeeRate(a);
        bool fUseBDescendants = UseDescendantFeeRate(b);

        double aFees = fUseADescendants ? a.GetFeesWithDescendants() : a.GetFee();
        double aSize = fUseADescendants ? a.GetSizeWithDescendants() : a.GetTxSize();

        double bFees = fUseBDescendants ? b.GetFeesWithDescendants() : b.GetFee();
        double bSize = fUseBDescendants ? b.GetSizeWithDescendants() : b.GetTxSize();

        // Avoid division by rewriting (a/b > c/d) as (a*d > c*b).
        double f1 = aFees * bSize;
        double f2 = aSize * bFees;

        if (f1 == f2) {
            return a.GetTime() < b.GetTime();
        }
        return f1 > f2;
    }

    // Calculate which feerate to use for an entry (avoiding division).
    bool UseDescendantFeeRate(const CTxMemPoolEntry &a)
    {
        double f1 = (double)a.GetFee() * a.GetSizeWithDescendants();
        double f2 = (double)a.GetFeesWithDescendants() * a.GetTxSize();
        return f2 > f1;
    }
};

class CompareTxMemPoolEntryByEntryTime
{
public:
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b)
    {
        return a.GetTime() < b.GetTime();
    }
};

class CBlockPolicyEstimator;

/** An inpoint - a combination of a transaction and an index n into its vin */
class CInPoint
{
public:
    const CTransaction* ptx;
    uint32_t n;

    CInPoint() { SetNull(); }
    CInPoint(const CTransaction* ptxIn, uint32_t nIn) { ptx = ptxIn; n = nIn; }
    void SetNull() { ptx = NULL; n = (uint32_t) -1; }
    bool IsNull() const { return (ptx == NULL && n == (uint32_t) -1); }
    size_t DynamicMemoryUsage() const { return 0; }
};

/**
 * CTxMemPool stores valid-according-to-the-current-best-chain
 * transactions that may be included in the next block.
 *
 * Transactions are added when they are seen on the network
 * (or created by the local node), but not all transactions seen
 * are added to the pool: if a new transaction double-spends
 * an input of a transaction in the pool, it is dropped,
 * as are non-standard transactions.
 *
 * Mempool limiting:
 *
 * The mempool's max memory usage can be specified with -maxmempool.
 * This value is the "hardcap", a threshold we try to never exceed.
 * We set the "softcap" equal to 70% of this value.  As long as we're
 * below the softcap, new transactions are accepted as long as they are valid
 * and meet the base relay requirements.
 *
 * Once the mempool usage is above the softcap, new transactions can try to
 * enter the mempool by evicting existing transactions. In order for
 * transaction A to evict a transaction B, it must also evict all of the
 * in-mempool descendants of B.
 * Let S be the set containing B and those descendant transactions; then we
 * require:
 * - feerate(A) > feerate(S).
 *   We try to keep the highest fee rate transactions.
 * - fees(A) > fees(S)
 *   We can't allow total fees in the mempool to decrease without risking a DoS
 *   vulnerability.  We use the minrelayfee to ensure that using relay
 *   bandwidth incurs a cost, and allowing the fees in the mempool to decrease
 *   could allow an attacker to relay transactions for free.
 * - (fees(A) - fees(S)) > feerequired(A)
 *   Any transaction must pay for its own relay, after accounting for the fees
 *   of transactions being removed.
 *
 * This eviction code is run when calling StageTrimToSize.
 *
 * If a new transaction arrives when usage is above the softcap but is unable
 * to enter by evicting existing transactions, then it has another chance to enter
 * the mempool if its feerate is sufficiently high.  We take the usage between the
 * softcap and the hardcap, and divide it up into 10 bands (1,...,10).  Within
 * a band, we accept transactions without evicting existing transactions if the
 * feerate is above minrelayfee * 2^(n), where n is the band number.
 *
 * Once we're above the softcap, we can use the existince of higher fee rate
 * transactions in the aggregate to try to evict transactions as well.  The idea
 * is that the eviction algorithm described above generally makes it difficult
 * for small transactions, even with a high fee rate, to evict long low-fee
 * rate chains, because the total fee is hard to exceed. Using the knowledge
 * that we have known high-fee-rate transactions in the reserve space, we can
 * use them in the aggregate to try to evict large packages of transactions.
 * This eviction strategy is run when calling SurplusTrim.
 *
 * Finally, there is also functionality for removing old transactions from
 * the mempool, via the Expire() function.
 *
 * CTxMemPool::mapTx, and CTxMemPoolEntry bookkeeping:
 *
 * mapTx is a boost::multi_index that sorts the mempool on 3 criteria:
 * - transaction hash
 * - feerate [we use max(feerate of tx, feerate of tx with all descendants)]
 * - time in mempool
 *
 * In order for the feerate sort to remain correct, we must update transactions
 * in the mempool when new descendants arrive.  To facilitate this, we track
 * in each transaction's CTxMemPoolEntry the set of in-mempool direct parents
 * and direct children, along with the size and fees of all descendants.
 *
 * Usually when a new transaction is added to the mempool, it has no in-mempool
 * children (because any such children would be an orphan).  So in addUnchecked,
 * we:
 * - update a new entry's setMemPoolParents to include all in-mempool parents
 * - update the new entry's direct parents to include the new tx as a child
 * - update all ancestors of the transaction to include the new tx's size/fee
 *
 * When a transaction is removed from the mempool, we must:
 * - update all in-mempool parents to not track the tx in setMemPoolChildren
 * - update all ancestors to not include the tx's size/fees in descendant state
 * - update all in-mempool children to not include it as a parent
 *
 * These happen in UpdateForRemoveFromMempool.  (Note that when removing a
 * transaction along with its descendants, we must calculate that set of
 * transactions to be removed before doing the removal, or else the mempool can
 * be in an inconsistent state where it's impossible to walk the ancestors of
 * a transaction.)
 *
 * In the event of a reorg, the assumption that a newly added tx has no
 * in-mempool children is false.  In particular, the mempool is in an
 * inconsistent state while new transactions are being added, because there may
 * be descendant transactions of a tx coming from a disconnected block that are
 * unreachable from just looking at transactions in the mempool (the linking
 * transactions may also be in the disconnected block, waiting to be added).
 * Because of this, there's not much benefit in trying to search for in-mempool
 * children in addUnchecked.  Instead, in the special case of transactions
 * being added from a disconnected block, we require the caller to clean up the
 * state, to account for in-mempool, out-of-block descendants for all the
 * in-block transactions by calling UpdateTransactionsFromBlock.  Note that
 * until this is called, the mempool state is not consistent, and in particular
 * setMemPoolChildren and setMemPoolParents may not be correct (and therefore
 * functions like CalculateMemPoolAncestors and CalculateDescendants that rely
 * on them to walk the mempool are not generally safe to use).
 *
 * Computational limits:
 *
 * Updating all in-mempool ancestors of a newly added transaction can be slow,
 * if no bound exists on how many in-mempool ancestors there may be.
 * CalculateMemPoolAncestors() takes configurable limits that are designed to
 * prevent these calculations from being too CPU intensive, and for ensuring
 * that transaction packages can't be too large for the eviction code to be
 * able to properly function.  See comments below.
 *
 * Adding transactions from a disconnected block can be very time consuming,
 * because we don't have a way to limit the number of in-mempool descendants.
 * To bound CPU processing, we limit the amount of work we're willing to do
 * to properly update the descendant information for a tx being added from
 * a disconnected block.  If we would exceed the limit, then we instead mark
 * the entry as "dirty", and set the feerate for sorting purposes to be equal
 * the feerate of the transaction without any descendants.
 *
 */
class CTxMemPool
{
private:
    bool fSanityCheck; //! Normally false, true if -checkmempool or -regtest
    unsigned int nTransactionsUpdated;
    CBlockPolicyEstimator* minerPolicyEstimator;

    uint64_t totalTxSize; //! sum of all mempool tx' byte sizes
    uint64_t cachedInnerUsage; //! sum of dynamic memory usage of all the map elements (NOT the maps themselves)

public:
    typedef boost::multi_index_container<
        CTxMemPoolEntry,
        boost::multi_index::indexed_by<
            // sorted by txid
            boost::multi_index::ordered_unique<mempoolentry_txid>,
            // sorted by fee rate
            boost::multi_index::ordered_non_unique<
                boost::multi_index::identity<CTxMemPoolEntry>,
                CompareTxMemPoolEntryByFeeRate
            >,
            // sorted by entry time
            boost::multi_index::ordered_non_unique<
                boost::multi_index::identity<CTxMemPoolEntry>,
                CompareTxMemPoolEntryByEntryTime
            >
        >
    > indexed_transaction_set;

    mutable CCriticalSection cs;
    indexed_transaction_set mapTx;
    std::map<COutPoint, CInPoint> mapNextTx;
    std::map<uint256, std::pair<double, CAmount> > mapDeltas;
    size_t bypassedSize;

    CTxMemPool(const CFeeRate& _minRelayFee);
    ~CTxMemPool();

    /**
     * If sanity-checking is turned on, check makes sure the pool is
     * consistent (does not contain two transactions that spend the same inputs,
     * all inputs are in the mapNextTx array). If sanity-checking is turned off,
     * check does nothing.
     */
    void check(const CCoinsViewCache *pcoins) const;
    void setSanityCheck(bool _fSanityCheck) { fSanityCheck = _fSanityCheck; }

    // addUnchecked must updated state for all ancestors of a given transaction,
    // to track size/count of descendant transactions.  First version of
    // addUnchecked can be used to have it call CalculateMemPoolAncestors, and
    // then invoke the second version.
    bool addUnchecked(const uint256& hash, const CTxMemPoolEntry &entry, bool fCurrentEstimate = true);
    bool addUnchecked(const uint256& hash, const CTxMemPoolEntry &entry, const std::set<uint256> &setAncestors, bool fCurrentEstimate = true);

    // When mempool entries gain/lose mempool children/parents, update the
    // cached inner usage as well.
    void UpdateInnerUsage(int64_t sizeAdjustment);

    void remove(const CTransaction &tx, std::list<CTransaction>& removed, bool fRecursive = false);
    void removeCoinbaseSpends(const CCoinsViewCache *pcoins, unsigned int nMemPoolHeight);
    void removeConflicts(const CTransaction &tx, std::list<CTransaction>& removed);
    void removeForBlock(const std::vector<CTransaction>& vtx, unsigned int nBlockHeight,
                        std::list<CTransaction>& conflicts, bool fCurrentEstimate = true);
    void clear();
    void queryHashes(std::vector<uint256>& vtxid);
    void pruneSpent(const uint256& hash, CCoins &coins);
    unsigned int GetTransactionsUpdated() const;
    void AddTransactionsUpdated(unsigned int n);
    /**
     * Check that none of this transactions inputs are in the mempool, and thus
     * the tx is not dependent on other mempool transactions to be included in a block.
     */
    bool HasNoInputsOf(const CTransaction& tx) const;

    /** Affect CreateNewBlock prioritisation of transactions */
    void PrioritiseTransaction(const uint256 hash, const std::string strHash, double dPriorityDelta, const CAmount& nFeeDelta);
    void ApplyDeltas(const uint256 hash, double &dPriorityDelta, CAmount &nFeeDelta);
    void ClearPrioritisation(const uint256 hash);

    // StageTrimToSize will call TrimMempool for any mempool usage over the size limit up to the size of toadd.
    bool StageTrimToSize(size_t sizelimit, const CTxMemPoolEntry& toadd, CAmount nFeesReserved, std::set<uint256>& stage, CAmount& nFeesRemoved);
    // SurplusTrim will call TrimMempool for usageToTrim with synthetic fees and size based on multiplier*minRelayRate.
    void SurplusTrim(int mutliplier, CFeeRate minRelayRate, size_t usageToTrim);
private:
    /** TrimMempool will build a list of transactions (hashes) to remove until it reaches sizeToTrim:
     *  - No txs in protect are removed.
     *  - The total fees removed are not more than the feeToUse (minus any nFeesReserved).
     *  - The feerate of what is removed is not better than the feerate of feeToUse/sizeToUse.
     *  - if mustTrimAllSize return false unless sizeToTrim is met
     *  - iterextra helps provide a bound on how many txs will be iterated over.
     *  - The list returned in stage is consistent (if a parent is included, all its descendants are included as well).
     *  - Total fees removed are returned in nfeesRemoved
     */
    bool TrimMempool(size_t sizeToTrim, std::set<uint256> &protect, CAmount nFeesReserved, size_t sizeToUse, CAmount feeToUse,
		     bool mustTrimAllSize, int iterextra, std::set<uint256>& stage, CAmount &nfeesRemoved);
public:
    void RemoveStaged(std::set<uint256>& stage);

    /** When adding transactions from a disconnected block back to the mempool,
     *  new mempool entries may have children in the mempool (which is generally
     *  not the case when otherwise adding transactions).
     *  UpdateTransactionsFromBlock will find child transactions and update the
     *  descendant state for each transaction in hashesToUpdate (excluding any
     *  child transactions present in hashesToUpdate, which are already accounted
     *  for).
     */
    void UpdateTransactionsFromBlock(const std::vector<uint256> &hashesToUpdate);

    /** Try to calculate all in-mempool ancestors of entry.
     *  (these are all calculated including the tx itself)
     *  limitAncestorCount = max number of ancestors
     *  limitAncestorSize = max size of ancestors
     *  limitDescendantCount = max number of descendants any ancestor can have
     *  limitDescendantSize = max size of descendants any ancestor can have
     */
    bool CalculateMemPoolAncestors(const CTxMemPoolEntry &entry, std::set<uint256> &setAncestors, uint64_t limitAncestorCount, uint64_t limitAncestorSize, uint64_t limitDescendantCount, uint64_t limitDescendantSize, CValidationState &state);

    /** Expire all transaction (and their dependencies) in the mempool older than time. Return the number of removed transactions. */
    int Expire(int64_t time);

    unsigned long size()
    {
        LOCK(cs);
        return mapTx.size();
    }

    uint64_t GetTotalTxSize()
    {
        LOCK(cs);
        return totalTxSize;
    }

    bool exists(uint256 hash) const
    {
        LOCK(cs);
        return (mapTx.count(hash) != 0);
    }

    bool lookup(uint256 hash, CTransaction& result) const;

    /** Estimate fee rate needed to get into the next nBlocks */
    CFeeRate estimateFee(int nBlocks) const;

    /** Estimate priority needed to get into the next nBlocks */
    double estimatePriority(int nBlocks) const;
    
    /** Write/Read estimates to disk */
    bool WriteFeeEstimates(CAutoFile& fileout) const;
    bool ReadFeeEstimates(CAutoFile& filein);

    size_t DynamicMemoryUsage() const;
    size_t GuessDynamicMemoryUsage(const CTxMemPoolEntry& entry) const;

private:
    /** UpdateForDescendants is used by UpdateTransactionsFromBlock to update
     *  the descendants for a single transaction that has been added to the
     *  mempool but may have child transactions in the mempool, eg during a
     *  chain reorg.  setExclude is the set of descendant transactions in the
     *  mempool that must not be accounted for (because any descendants in
     *  setExclude were added to the mempool after the transaction being
     *  updated and hence their state is already reflected in the parent
     *  state).
     *
     *  If updating an entry requires looking at more than maxDescendantsToVisit
     *  transactions, outside of the ones in setExclude, then give up.
     *
     *  cachedDescendants will be updated with the descendants of the transaction
     *  being updated, so that future invocations don't need to walk the
     *  same transaction again, if encountered in another transaction chain.
     */
    bool UpdateForDescendants(indexed_transaction_set::iterator it,
            int maxDescendantsToVisit,
            std::map<uint256, std::set<uint256> > &cachedDescendants,
            const std::set<uint256> &setExclude);
    /** Update ancestors of hash to add/remove it as a descendant transaction. */
    void UpdateAncestorsOf(bool add, const uint256 &hash, const std::set<uint256> &setAncestors);
    /** For each transaction being removed, update ancestors and any direct children. */
    void UpdateForRemoveFromMempool(const std::set<uint256> &hashesToRemove);
    /** Sever link between specified transaction and direct children. */
    void UpdateChildrenForRemoval(const uint256 &hash);
    /** Populate setDescendants with all in-mempool descendants of hash.
     *  Assumes that setDescendants includes all in-mempool descendants of anything
     *  already in it.  */
    void CalculateDescendants(const uint256 &hash, std::set<uint256> &setDescendants);

    /** Before calling removeUnchecked for a given transaction,
     *  UpdateForRemoveFromMempool must be called on the entire (dependent) set
     *  of transactions being removed at the same time.  We use each
     *  CTxMemPoolEntry's setMemPoolParents in order to walk ancestors of a
     *  given transaction that is removed, so we can't remove intermediate
     *  transactions in a chain before we've updated all the state for the
     *  removal.
     */
    void removeUnchecked(const uint256& hash);
};

/** 
 * CCoinsView that brings transactions from a memorypool into view.
 * It does not check for spendings by memory pool transactions.
 */
class CCoinsViewMemPool : public CCoinsViewBacked
{
protected:
    CTxMemPool &mempool;

public:
    CCoinsViewMemPool(CCoinsView *baseIn, CTxMemPool &mempoolIn);
    bool GetCoins(const uint256 &txid, CCoins &coins) const;
    bool HaveCoins(const uint256 &txid) const;
};

#endif // BITCOIN_TXMEMPOOL_H
