// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXMEMPOOL_H
#define BITCOIN_TXMEMPOOL_H

#include <coins.h>
#include <consensus/amount.h>
#include <indirectmap.h>
#include <kernel/cs_main.h>
#include <kernel/mempool_entry.h>          // IWYU pragma: export
#include <kernel/mempool_limits.h>         // IWYU pragma: export
#include <kernel/mempool_options.h>        // IWYU pragma: export
#include <kernel/mempool_removal_reason.h> // IWYU pragma: export
#include <logging.h>
#include <policy/feerate.h>
#include <policy/packages.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <util/epochguard.h>
#include <util/hasher.h>
#include <util/result.h>
#include <util/strencodings.h>

#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/indexed_by.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/tag.hpp>
#include <boost/multi_index_container.hpp>

#include <atomic>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

class CChain;
class CTxMemPoolEntry;

/** Fake height value used in Coin to signify they are only in the memory pool (since 0.8) */
static const uint32_t MEMPOOL_HEIGHT = 0x7FFFFFFF;

/**
 * Test whether the LockPoints height and time are still valid on the current chain
 */
bool TestLockPointValidity(CChain& active_chain, const LockPoints& lp) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Data structure for managing clusters of transactions in the mempool.
 *
 * We can consider the graph of mempool transactions where edges connect
 * transactions that have a parent/child relationship. Then two transactions
 * are in a "cluster" if they are connected in this graph.
 *
 * Clusters are sorted for transaction selection/eviction purposes
 * independently of each other.
 */

class CTxMemPool;

class Cluster {
public:
    Cluster(int64_t id, CTxMemPool* mempool) : m_id(id), m_mempool(mempool) {}

    void Clear() {
        m_chunks.clear();
        m_tx_count = 0;
    }

    // Add a transaction and update the sort.
    void AddTransaction(const CTxMemPoolEntry& entry, bool sort);
    void RemoveTransaction(const CTxMemPoolEntry& entry);

    // Sort the cluster and partition into chunks.
    void Sort(bool reassign_locations = true);

    // Just rechunk the cluster using its existing linearization.
    void Rechunk();

    // Helper function
    void RechunkFromLinearization(std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef>& txs, bool reassign_locations);

    void Merge(std::vector<Cluster *>::iterator first, std::vector<Cluster*>::iterator last, bool this_cluster_first);

    uint64_t GetMemoryUsage() const {
        return memusage::DynamicUsage(m_chunks) + m_tx_count * sizeof(void*) * 3;
    }

    CTxMemPoolEntry::CTxMemPoolEntryRef GetLastTransaction();

    // The chunks of transactions which will be added to blocks or
    // evicted from the mempool.
    struct Chunk {
        Chunk(CAmount _fee, int64_t _size) : fee(_fee), size(_size) {}
        Chunk(Chunk&& other) = default;
        Chunk& operator=(Cluster::Chunk&& other) = default;
        Chunk& operator=(const Cluster::Chunk& other) = delete;

        CAmount fee{0};
        int64_t size{0};
        std::list<CTxMemPoolEntry::CTxMemPoolEntryRef> txs;
    };

    typedef std::vector<Chunk>::iterator ChunkIter;
    typedef std::pair<ChunkIter, Cluster*> HeapEntry;

    std::vector<Chunk> m_chunks;
    int64_t m_tx_count{0};
    int64_t m_tx_size{0};

    const int64_t m_id;
    CTxMemPool* m_mempool;
    mutable Epoch::Marker m_epoch_marker; //!< epoch when last touched
};

// extracts a transaction hash from CTxMemPoolEntry or CTransactionRef
struct mempoolentry_txid
{
    typedef uint256 result_type;
    result_type operator() (const CTxMemPoolEntry &entry) const
    {
        return entry.GetTx().GetHash();
    }

    result_type operator() (const CTransactionRef& tx) const
    {
        return tx->GetHash();
    }
};

// extracts a transaction witness-hash from CTxMemPoolEntry or CTransactionRef
struct mempoolentry_wtxid
{
    typedef uint256 result_type;
    result_type operator() (const CTxMemPoolEntry &entry) const
    {
        return entry.GetTx().GetWitnessHash();
    }

    result_type operator() (const CTransactionRef& tx) const
    {
        return tx->GetWitnessHash();
    }
};

/** \class CompareTxMemPoolEntryByScore
 *
 *  Sort by feerate of entry (fee/size) in descending order
 *  This is only used for transaction relay, so we use GetFee()
 *  instead of GetModifiedFee() to avoid leaking prioritization
 *  information via the sort order.
 */
class CompareTxMemPoolEntryByScore
{
public:
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) const
    {
        double f1 = (double)a.GetFee() * b.GetTxSize();
        double f2 = (double)b.GetFee() * a.GetTxSize();
        if (f1 == f2) {
            return b.GetTx().GetHash() < a.GetTx().GetHash();
        }
        return f1 > f2;
    }
};

class CompareTxMemPoolEntryByEntryTime
{
public:
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) const
    {
        return a.GetTime() < b.GetTime();
    }
};

// Multi_index tag names
struct entry_time {};
struct index_by_wtxid {};

class CBlockPolicyEstimator;

/**
 * Information about a mempool transaction.
 */
struct TxMempoolInfo
{
    /** The transaction itself */
    CTransactionRef tx;

    /** Time the transaction entered the mempool. */
    std::chrono::seconds m_time;

    /** Fee of the transaction. */
    CAmount fee;

    /** Virtual size of the transaction. */
    int32_t vsize;

    /** The fee delta. */
    int64_t nFeeDelta;
};

/**
 * CTxMemPool stores valid-according-to-the-current-best-chain transactions
 * that may be included in the next block.
 *
 * Transactions are added when they are seen on the network (or created by the
 * local node), but not all transactions seen are added to the pool. For
 * example, the following new transactions will not be added to the mempool:
 * - a transaction which doesn't meet the minimum fee requirements.
 * - a new transaction that double-spends an input of a transaction already in
 * the pool where the new transaction does not meet the Replace-By-Fee
 * requirements as defined in doc/policy/mempool-replacements.md.
 * - a non-standard transaction.
 *
 * CTxMemPool::mapTx, CTxMemPoolEntry, and CTxMemPool::m_cluster_map
 * bookkeeping:
 *
 * mapTx is a boost::multi_index that sorts the mempool on 3 criteria:
 * - transaction hash (txid)
 * - witness-transaction hash (wtxid)
 * - time in mempool
 *
 * We additionally partition the mempool transactions into clusters, in which
 * any two transactions that have a parent/child relationship are assigned to
 * the same cluster. Clusters are stored in m_cluster_map. Every
 * CTxMemPoolEntry has a reference to the cluster to which it belongs, along
 * with a location within the cluster. Clusters themselves are sorted
 * ("linearized") as optimally as we are able to maximize mining income, using
 * algorithms implemented in cluster_linearize.h.
 *
 * To facilitate graph traversal algorithms, we cache within each
 * CTxMemPoolEntry the set of in-mempool direct parents and children.
 *
 * Usually when a new transaction is added to the mempool, it has no in-mempool
 * children (because any such children would be an orphan).  So in
 * addUnchecked(), we:
 * - update a new entry's setMemPoolParents to include all in-mempool parents
 * - update the new entry's direct parents to include the new tx as a child
 *
 * When a transaction is removed from the mempool, we must:
 * - update all in-mempool parents to not track the tx in setMemPoolChildren
 * - update all in-mempool children to not include it as a parent
 *
 * These happen in UpdateForRemoveFromMempool().
 *
 * In the event of a reorg, the assumption that a newly added tx has no
 * in-mempool children is false.  In particular, the mempool is in an
 * inconsistent state while new transactions are being added, because there may
 * be child transactions of a tx coming from a disconnected block that are
 * unreachable from just looking at transactions in the mempool (the linking
 * transactions may also be in the disconnected block, waiting to be added).
 * Because of this, there's not much benefit in trying to search for in-mempool
 * children in addUnchecked().  Instead, in the special case of transactions
 * being added from a disconnected block, we require the caller to clean up the
 * state, to account for in-mempool, out-of-block children for all the
 * in-block transactions by calling UpdateTransactionsFromBlock().  Note that
 * until this is called, the mempool state is not consistent, and in particular
 * the cached parents/children stored in CTxMemPoolEntry are not correct (so
 * CalculateMemPoolAncestors() and CalculateDescendants() that rely
 * on them to walk the mempool are not generally safe to use).
 *
 * Computational limits:
 *
 * Optimizing a cluster for mining revenue can be CPU intensive, so the mempool
 * should operate in a context where the maximum number of transactions in a
 * cluster is bounded.
 *
 */
class CTxMemPool
{
protected:
    const int m_check_ratio; //!< Value n means that 1 times in n we check.
    std::atomic<unsigned int> nTransactionsUpdated{0}; //!< Used by getblocktemplate to trigger CreateNewBlock() invocation
    CBlockPolicyEstimator* const minerPolicyEstimator;

    uint64_t totalTxSize GUARDED_BY(cs){0};      //!< sum of all mempool tx's virtual sizes. Differs from serialized tx size since witness data is discounted. Defined in BIP 141.
    CAmount m_total_fee GUARDED_BY(cs){0};       //!< sum of all mempool tx's fees (NOT modified fee)
    uint64_t cachedInnerUsage GUARDED_BY(cs){0}; //!< sum of dynamic memory usage of all the map elements (NOT the maps themselves)

    mutable int64_t lastRollingFeeUpdate GUARDED_BY(cs){GetTime()};
    mutable bool blockSinceLastRollingFeeBump GUARDED_BY(cs){false};
    mutable double rollingMinimumFeeRate GUARDED_BY(cs){0}; //!< minimum fee to get into the pool, decreases exponentially
    mutable Epoch m_epoch GUARDED_BY(cs){};

    // In-memory counter for external mempool tracking purposes.
    // This number is incremented once every time a transaction
    // is added or removed from the mempool for any reason.
    mutable uint64_t m_sequence_number GUARDED_BY(cs){1};

    void trackPackageRemoved(const CFeeRate& rate) EXCLUSIVE_LOCKS_REQUIRED(cs);

    bool m_load_tried GUARDED_BY(cs){false};

    CFeeRate GetMinFee(size_t sizelimit) const;

public:

    static const int ROLLING_FEE_HALFLIFE = 60 * 60 * 12; // public only for testing

    typedef boost::multi_index_container<
        CTxMemPoolEntry,
        boost::multi_index::indexed_by<
            // sorted by txid
            boost::multi_index::hashed_unique<mempoolentry_txid, SaltedTxidHasher>,
            // sorted by wtxid
            boost::multi_index::hashed_unique<
                boost::multi_index::tag<index_by_wtxid>,
                mempoolentry_wtxid,
                SaltedTxidHasher
            >,
            // sorted by entry time
            boost::multi_index::ordered_non_unique<
                boost::multi_index::tag<entry_time>,
                boost::multi_index::identity<CTxMemPoolEntry>,
                CompareTxMemPoolEntryByEntryTime
            >
        >
    > indexed_transaction_set;

    /**
     * This mutex needs to be locked when accessing `mapTx` or other members
     * that are guarded by it.
     *
     * @par Consistency guarantees
     *
     * By design, it is guaranteed that:
     *
     * 1. Locking both `cs_main` and `mempool.cs` will give a view of mempool
     *    that is consistent with current chain tip (`ActiveChain()` and
     *    `CoinsTip()`) and is fully populated. Fully populated means that if the
     *    current active chain is missing transactions that were present in a
     *    previously active chain, all the missing transactions will have been
     *    re-added to the mempool and should be present if they meet size and
     *    consistency constraints.
     *
     * 2. Locking `mempool.cs` without `cs_main` will give a view of a mempool
     *    consistent with some chain that was active since `cs_main` was last
     *    locked, and that is fully populated as described above. It is ok for
     *    code that only needs to query or remove transactions from the mempool
     *    to lock just `mempool.cs` without `cs_main`.
     *
     * To provide these guarantees, it is necessary to lock both `cs_main` and
     * `mempool.cs` whenever adding transactions to the mempool and whenever
     * changing the chain tip. It's necessary to keep both mutexes locked until
     * the mempool is consistent with the new chain tip and fully populated.
     */
    mutable RecursiveMutex cs;
    indexed_transaction_set mapTx GUARDED_BY(cs);

    // Clusters
    std::unordered_map<int64_t, std::unique_ptr<Cluster>> m_cluster_map GUARDED_BY(cs);
    int64_t m_next_cluster_id GUARDED_BY(cs){0};

    using txiter = indexed_transaction_set::nth_index<0>::type::const_iterator;
    std::vector<std::pair<uint256, txiter>> vTxHashes GUARDED_BY(cs); //!< All tx witness hashes/entries in mapTx, in random order

    typedef std::set<txiter, CompareIteratorByHash> setEntries;
    typedef std::vector<txiter> Entries;

    using Limits = kernel::MemPoolLimits;

    bool CompareMiningScore(txiter a, txiter b) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    void TopoSort(std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef>& to_be_sorted) const;
    void CalculateAncestorData(const CTxMemPoolEntry& entry, size_t& ancestor_count, size_t& ancestor_size, CAmount& ancestor_fees) const EXCLUSIVE_LOCKS_REQUIRED(cs);
    void CalculateDescendantData(const CTxMemPoolEntry& entry, size_t& descendant_count, size_t& descendant_size, CAmount& descendant_fees) const EXCLUSIVE_LOCKS_REQUIRED(cs);

private:
    void UpdateParent(txiter entry, txiter parent, bool add) EXCLUSIVE_LOCKS_REQUIRED(cs);
    void UpdateChild(txiter entry, txiter child, bool add) EXCLUSIVE_LOCKS_REQUIRED(cs);

    std::vector<indexed_transaction_set::const_iterator> GetSortedScoreWithTopology() const EXCLUSIVE_LOCKS_REQUIRED(cs);

    /**
     * Track locally submitted transactions to periodically retry initial broadcast.
     */
    std::set<uint256> m_unbroadcast_txids GUARDED_BY(cs);


    /**
     * Helper function to calculate all in-mempool ancestors of staged_ancestors
     *
     * @param[in]   staged_ancestors    Should contain entries in the mempool.
     *
     * @return all in-mempool ancestors
     */
    setEntries CalculateAncestors(CTxMemPoolEntry::Parents &staged_ancestors)
            const EXCLUSIVE_LOCKS_REQUIRED(cs);

    // Helper to remove all transactions that conflict with a given
    // transaction (used for transactions appearing in a block).
    void removeConflicts(const CTransaction& tx) EXCLUSIVE_LOCKS_REQUIRED(cs);

public:
    indirectmap<COutPoint, const CTransaction*> mapNextTx GUARDED_BY(cs);
    std::map<uint256, CAmount> mapDeltas GUARDED_BY(cs);

    using Options = kernel::MemPoolOptions;

    const int64_t m_max_size_bytes;
    const std::chrono::seconds m_expiry;
    const CFeeRate m_incremental_relay_feerate;
    const CFeeRate m_min_relay_feerate;
    const CFeeRate m_dust_relay_feerate;
    const bool m_permit_bare_multisig;
    const std::optional<unsigned> m_max_datacarrier_bytes;
    const bool m_require_standard;
    const bool m_full_rbf;

    const Limits m_limits;

    /** Create a new CTxMemPool.
     * Sanity checks will be off by default for performance, because otherwise
     * accepting transactions becomes O(N^2) where N is the number of transactions
     * in the pool.
     */
    explicit CTxMemPool(const Options& opts);

    /**
     * If sanity-checking is turned on, check makes sure the pool is
     * consistent (does not contain two transactions that spend the same inputs,
     * all inputs are in the mapNextTx array). If sanity-checking is turned off,
     * check does nothing.
     */
    void check(const CCoinsViewCache& active_coins_tip, int64_t spendheight) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    // Note that addUnchecked is ONLY called from ATMP outside of tests
    // and any other callers may break wallet's in-mempool tracking (due to
    // lack of CValidationInterface::TransactionAddedToMempool callbacks).
    void addUnchecked(const CTxMemPoolEntry& entry, bool validFeeEstimate = true) EXCLUSIVE_LOCKS_REQUIRED(cs, cs_main);

    void removeRecursive(const CTransaction& tx, MemPoolRemovalReason reason) EXCLUSIVE_LOCKS_REQUIRED(cs);
    /** After reorg, filter the entries that would no longer be valid in the next block, and update
     * the entries' cached LockPoints if needed.  The mempool does not have any knowledge of
     * consensus rules. It just appplies the callable function and removes the ones for which it
     * returns true.
     * @param[in]   filter_final_and_mature   Predicate that checks the relevant validation rules
     *                                        and updates an entry's LockPoints.
     * */
    void removeForReorg(CChain& chain, std::function<bool(txiter)> filter_final_and_mature) EXCLUSIVE_LOCKS_REQUIRED(cs, cs_main);
    void removeForBlock(const std::vector<CTransactionRef>& vtx, unsigned int nBlockHeight) EXCLUSIVE_LOCKS_REQUIRED(cs);

    bool CompareMiningScoreWithTopology(const uint256& hasha, const uint256& hashb, bool wtxid=false);
    void queryHashes(std::vector<uint256>& vtxid) const;
    bool isSpent(const COutPoint& outpoint) const;
    unsigned int GetTransactionsUpdated() const;
    void AddTransactionsUpdated(unsigned int n);
    /**
     * Check that none of this transactions inputs are in the mempool, and thus
     * the tx is not dependent on other mempool transactions to be included in a block.
     */
    bool HasNoInputsOf(const CTransaction& tx) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    /** Affect CreateNewBlock prioritisation of transactions */
    void PrioritiseTransaction(const uint256& hash, const CAmount& nFeeDelta);
    void ApplyDelta(const uint256& hash, CAmount &nFeeDelta) const EXCLUSIVE_LOCKS_REQUIRED(cs);
    void ClearPrioritisation(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs);

    struct delta_info {
        /** Whether this transaction is in the mempool. */
        const bool in_mempool;
        /** The fee delta added using PrioritiseTransaction(). */
        const CAmount delta;
        /** The modified fee (base fee + delta) of this entry. Only present if in_mempool=true. */
        std::optional<CAmount> modified_fee;
        /** The prioritised transaction's txid. */
        const uint256 txid;
    };
    /** Return a vector of all entries in mapDeltas with their corresponding delta_info. */
    std::vector<delta_info> GetPrioritisedTransactions() const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    /** Get the transaction in the pool that spends the same prevout */
    const CTransaction* GetConflictTx(const COutPoint& prevout) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    /** Returns an iterator to the given hash, if found */
    std::optional<txiter> GetIter(const uint256& txid) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    /** Translate a set of hashes into a set of pool iterators to avoid repeated lookups.
     * Does not require that all of the hashes correspond to actual transactions in the mempool,
     * only returns the ones that exist. */
    setEntries GetIterSet(const std::set<uint256>& hashes) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    /** Translate a list of hashes into a list of mempool iterators to avoid repeated lookups.
     * The nth element in txids becomes the nth element in the returned vector. If any of the txids
     * don't actually exist in the mempool, returns an empty vector. */
    std::vector<txiter> GetIterVec(const std::vector<uint256>& txids) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    /** Remove a set of transactions from the mempool.
     *  If a transaction is in this set, then all in-mempool descendants must
     *  also be in the set, unless this transaction is being removed for being
     *  in a block.
     */
    void RemoveStaged(setEntries& stage, bool updateDescendants, MemPoolRemovalReason reason) EXCLUSIVE_LOCKS_REQUIRED(cs);
    void RemoveSingleTxForBlock(txiter it) EXCLUSIVE_LOCKS_REQUIRED(cs);

    // Remove the given chunk (guaranteed to be last in the cluster)
    // Leave the resulting cluster otherwise unchanged (ie don't repartition/re-sort).
    void RemoveChunkForEviction(Cluster *cluster, std::list<CTxMemPoolEntry::CTxMemPoolEntryRef>& entries) EXCLUSIVE_LOCKS_REQUIRED(cs);

    /** UpdateTransactionsFromBlock is called when adding transactions from a
     * disconnected block back to the mempool, new mempool entries may have
     * children in the mempool (which is generally not the case when otherwise
     * adding transactions).
     *  @post parent/children state in all CTxMemPoolEntry is updated, and
     *        clusters are recomputed and re-sorted. Too-large clusters are
     *        trimmed.
     *
     * @param[in] vHashesToUpdate          The set of txids from the
     *     disconnected block that have been accepted back into the mempool.
     */
    void UpdateTransactionsFromBlock(const std::vector<uint256>& vHashesToUpdate) EXCLUSIVE_LOCKS_REQUIRED(cs, cs_main) LOCKS_EXCLUDED(m_epoch);

    /**
     * Calculate whether cluster size limits would be exceeded if a new tx were
     * added to the mempool (assuming no conflicts).
     *
     * @param[in] entry_size         vbytes of the new transaction(s)
     * @param[in] entry_count        number of new transactions to be added
     * @param[in] limits             Contains maximum cluster size/count
     * @param[in] all_parents        All parents of entry/entries in the mempool
     *
     * @return true if cluster limits are respected, or an error if limits were
     *         exceeded
     */
    util::Result<bool> CheckClusterSizeLimit(int64_t entry_size, size_t entry_count,
            const Limits& limits, const CTxMemPoolEntry::Parents& all_parents) const
        EXCLUSIVE_LOCKS_REQUIRED(cs);

    /**
     * Calculate all in-mempool ancestors of entry.
     * (these are all calculated including the tx itself)
     *
     * @param[in]   entry               CTxMemPoolEntry of which all in-mempool ancestors are calculated
     * @param[in]   fSearchForParents   Whether to search a tx's vin for in-mempool parents, or look
                                       up parents from mapLinks. Must be true for entries not in
     *                                  the mempool
     *
     * @return all in-mempool ancestors
     */
    setEntries CalculateMemPoolAncestors(const CTxMemPoolEntry& entry,
                                   bool fSearchForParents = true) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    void CalculateParents(CTxMemPoolEntry &entry) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    /**
     * Temporarily construct the cluster that would correspond to a
     * hypothetical new mempool transaction ("entry"). Take into account the
     * removal of all transactions in "all_conflicts" for the purposes of
     * determining which transactions would be in the hypothetical cluster.
     * Sort the cluster as well so that the mining score of the transaction can
     * be determined by the caller.
     */
    bool BuildClusterForTransaction(CTxMemPoolEntry& entry, const setEntries& all_conflicts, const Limits& limits, Cluster& temp_cluster) EXCLUSIVE_LOCKS_REQUIRED(cs);

    util::Result<CFeeRate> CalculateMiningScoreOfReplacementTx(CTxMemPoolEntry& entry, CAmount modified_fee,
                                                 const setEntries& all_conflicts, const Limits& limits) EXCLUSIVE_LOCKS_REQUIRED(cs);

    /** Collect the entire cluster of connected transactions for each transaction in txids.
     * All txids must correspond to transaction entries in the mempool, otherwise this returns an
     * empty vector. This call will also exit early and return an empty vector if it collects 500 or
     * more transactions as a DoS protection. */
    std::vector<txiter> GatherClusters(const std::vector<uint256>& txids) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    /** Calculate all in-mempool ancestors of a set of transactions not already in the mempool and
     * check cluster limits.
     * @param[in]       package                 Transaction package being evaluated for acceptance
     *                                          to mempool. The transactions need not be direct
     *                                          ancestors/descendants of each other.
     * @param[in]       limits                  Maximum number and size of cluster
     * @param[out]      errString               Populated with error reason if a limit is hit.
     */
    bool CheckPackageLimits(const Package& package,
                            const Limits& limits,
                            std::string &errString) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    /** Populate setDescendants with all in-mempool descendants of hash.
     *  Assumes that setDescendants includes all in-mempool descendants of anything
     *  already in it.  */
    void CalculateDescendants(txiter it, setEntries& setDescendants) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    std::vector<txiter> CalculateDescendants(std::vector<txiter> txs) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    /** The minimum fee to get into the mempool, which may itself not be enough
     *  for larger-sized transactions.
     *  The m_incremental_relay_feerate policy variable is used to bound the time it
     *  takes the fee rate to go back down all the way to 0. When the feerate
     *  would otherwise be half of this, it is set to 0 instead.
     */
    CFeeRate GetMinFee() const {
        return GetMinFee(m_max_size_bytes);
    }

    /** Remove transactions from the mempool until its dynamic size is <= sizelimit.
      *  pvNoSpendsRemaining, if set, will be populated with the list of outpoints
      *  which are not in mempool which no longer have any spends in this mempool.
      */
    void TrimToSize(size_t sizelimit, std::vector<COutPoint>* pvNoSpendsRemaining = nullptr) EXCLUSIVE_LOCKS_REQUIRED(cs);

    /** Expire all transaction (and their dependencies) in the mempool older than time. Return the number of removed transactions. */
    int Expire(std::chrono::seconds time) EXCLUSIVE_LOCKS_REQUIRED(cs);

    /**
     * Calculate the ancestor and cluster count for the given transaction.
     * The counts include the transaction itself.
     * When ancestors is non-zero (ie, the transaction itself is in the mempool),
     * ancestorsize and ancestorfees will also be set to the appropriate values.
     */
    void GetTransactionAncestry(const uint256& txid, size_t& ancestors, size_t& clustersize, size_t* ancestorsize = nullptr, CAmount* ancestorfees = nullptr) const;

    /**
     * @returns true if an initial attempt to load the persisted mempool was made, regardless of
     *          whether the attempt was successful or not
     */
    bool GetLoadTried() const;

    /**
     * Set whether or not an initial attempt to load the persisted mempool was made (regardless
     * of whether the attempt was successful or not)
     */
    void SetLoadTried(bool load_tried);

    unsigned long size() const
    {
        LOCK(cs);
        return mapTx.size();
    }

    uint64_t GetTotalTxSize() const EXCLUSIVE_LOCKS_REQUIRED(cs)
    {
        AssertLockHeld(cs);
        return totalTxSize;
    }

    CAmount GetTotalFee() const EXCLUSIVE_LOCKS_REQUIRED(cs)
    {
        AssertLockHeld(cs);
        return m_total_fee;
    }

    bool exists(const GenTxid& gtxid) const
    {
        LOCK(cs);
        if (gtxid.IsWtxid()) {
            return (mapTx.get<index_by_wtxid>().count(gtxid.GetHash()) != 0);
        }
        return (mapTx.count(gtxid.GetHash()) != 0);
    }

    CTransactionRef get(const uint256& hash) const;
    txiter get_iter_from_wtxid(const uint256& wtxid) const EXCLUSIVE_LOCKS_REQUIRED(cs)
    {
        AssertLockHeld(cs);
        return mapTx.project<0>(mapTx.get<index_by_wtxid>().find(wtxid));
    }
    TxMempoolInfo info(const GenTxid& gtxid) const;

    /** Returns info for a transaction if its entry_sequence < last_sequence */
    TxMempoolInfo info_for_relay(const GenTxid& gtxid, uint64_t last_sequence) const;

    std::vector<TxMempoolInfo> infoAll() const;

    size_t DynamicMemoryUsage() const;

    /** Adds a transaction to the unbroadcast set */
    void AddUnbroadcastTx(const uint256& txid)
    {
        LOCK(cs);
        // Sanity check the transaction is in the mempool & insert into
        // unbroadcast set.
        if (exists(GenTxid::Txid(txid))) m_unbroadcast_txids.insert(txid);
    };

    /** Removes a transaction from the unbroadcast set */
    void RemoveUnbroadcastTx(const uint256& txid, const bool unchecked = false);

    /** Returns transactions in unbroadcast set */
    std::set<uint256> GetUnbroadcastTxs() const
    {
        LOCK(cs);
        return m_unbroadcast_txids;
    }

    /** Returns whether a txid is in the unbroadcast set */
    bool IsUnbroadcastTx(const uint256& txid) const EXCLUSIVE_LOCKS_REQUIRED(cs)
    {
        AssertLockHeld(cs);
        return m_unbroadcast_txids.count(txid) != 0;
    }

    /** Guards this internal counter for external reporting */
    uint64_t GetAndIncrementSequence() const EXCLUSIVE_LOCKS_REQUIRED(cs) {
        return m_sequence_number++;
    }

    uint64_t GetSequence() const EXCLUSIVE_LOCKS_REQUIRED(cs) {
        return m_sequence_number;
    }

private:
    // During reorg we add transactions back to mempool, must reconnect
    // clusters with in-mempool descendants.
    void UpdateClusterForDescendants(txiter updateIt) EXCLUSIVE_LOCKS_REQUIRED(cs);
    /** Update parents of hash to add/remove it as a child transaction. */
    void UpdateParentsOf(bool add, txiter hash) EXCLUSIVE_LOCKS_REQUIRED(cs);
    /** For each transaction being removed, update parents and any children. */
    void UpdateForRemoveFromMempool(const setEntries &entriesToRemove) EXCLUSIVE_LOCKS_REQUIRED(cs);
    /** Sever link between specified transaction and direct children. */
    void UpdateChildrenForRemoval(txiter entry) EXCLUSIVE_LOCKS_REQUIRED(cs);

    /** Before calling removeUnchecked for a given transaction,
     *  UpdateForRemoveFromMempool must be called on the entire (dependent) set
     *  of transactions being removed at the same time.  We use each
     *  CTxMemPoolEntry's setMemPoolParents in order to walk ancestors of a
     *  given transaction that is removed, so we can't remove intermediate
     *  transactions in a chain before we've updated all the state for the
     *  removal.
     */
    void removeUnchecked(txiter entry, MemPoolRemovalReason reason) EXCLUSIVE_LOCKS_REQUIRED(cs);

    // Create a new (empty) cluster in the cluster map, and return a pointer to it.
    Cluster* AssignCluster() EXCLUSIVE_LOCKS_REQUIRED(cs);
    // Potentially split a cluster into smaller clusters (eg after transactions are removed)
    void RecalculateClusterAndMaybeSort(Cluster *cluster, bool sort) EXCLUSIVE_LOCKS_REQUIRED(cs);
public:
    /** visited marks a CTxMemPoolEntry as having been traversed
     * during the lifetime of the most recently created Epoch::Guard
     * and returns false if we are the first visitor, true otherwise.
     *
     * An Epoch::Guard must be held when visited is called or an assert will be
     * triggered.
     *
     */
    bool visited(const CTxMemPoolEntry& entry) const EXCLUSIVE_LOCKS_REQUIRED(cs, m_epoch)
    {
        return m_epoch.visited(entry.m_epoch_marker);
    }
    bool visited(const txiter it) const EXCLUSIVE_LOCKS_REQUIRED(cs, m_epoch)
    {
        return m_epoch.visited(it->m_epoch_marker);
    }

    bool visited(std::optional<txiter> it) const EXCLUSIVE_LOCKS_REQUIRED(cs, m_epoch)
    {
        assert(m_epoch.guarded()); // verify guard even when it==nullopt
        return !it || visited(*it);
    }

    bool visited(Cluster *cluster) const EXCLUSIVE_LOCKS_REQUIRED(cs, m_epoch)
    {
        return m_epoch.visited(cluster->m_epoch_marker);
    }

    friend class Cluster;
};

/**
 * CCoinsView that brings transactions from a mempool into view.
 * It does not check for spendings by memory pool transactions.
 * Instead, it provides access to all Coins which are either unspent in the
 * base CCoinsView, are outputs from any mempool transaction, or are
 * tracked temporarily to allow transaction dependencies in package validation.
 * This allows transaction replacement to work as expected, as you want to
 * have all inputs "available" to check signatures, and any cycles in the
 * dependency graph are checked directly in AcceptToMemoryPool.
 * It also allows you to sign a double-spend directly in
 * signrawtransactionwithkey and signrawtransactionwithwallet,
 * as long as the conflicting transaction is not yet confirmed.
 */
class CCoinsViewMemPool : public CCoinsViewBacked
{
    /**
    * Coins made available by transactions being validated. Tracking these allows for package
    * validation, since we can access transaction outputs without submitting them to mempool.
    */
    std::unordered_map<COutPoint, Coin, SaltedOutpointHasher> m_temp_added;

    /**
     * Set of all coins that have been fetched from mempool or created using PackageAddTransaction
     * (not base). Used to track the origin of a coin, see GetNonBaseCoins().
     */
    mutable std::unordered_set<COutPoint, SaltedOutpointHasher> m_non_base_coins;
protected:
    const CTxMemPool& mempool;

public:
    CCoinsViewMemPool(CCoinsView* baseIn, const CTxMemPool& mempoolIn);
    /** GetCoin, returning whether it exists and is not spent. Also updates m_non_base_coins if the
     * coin is not fetched from base. */
    bool GetCoin(const COutPoint &outpoint, Coin &coin) const override;
    /** Add the coins created by this transaction. These coins are only temporarily stored in
     * m_temp_added and cannot be flushed to the back end. Only used for package validation. */
    void PackageAddTransaction(const CTransactionRef& tx);
    /** Get all coins in m_non_base_coins. */
    std::unordered_set<COutPoint, SaltedOutpointHasher> GetNonBaseCoins() const { return m_non_base_coins; }
    /** Clear m_temp_added and m_non_base_coins. */
    void Reset();
};

/**
 * DisconnectedBlockTransactions

 * During the reorg, it's desirable to re-add previously confirmed transactions
 * to the mempool, so that anything not re-confirmed in the new chain is
 * available to be mined. However, it's more efficient to wait until the reorg
 * is complete and process all still-unconfirmed transactions at that time,
 * since we expect most confirmed transactions to (typically) still be
 * confirmed in the new chain, and re-accepting to the memory pool is expensive
 * (and therefore better to not do in the middle of reorg-processing).
 * Instead, store the disconnected transactions (in order!) as we go, remove any
 * that are included in blocks in the new chain, and then process the remaining
 * still-unconfirmed transactions at the end.
 */

// multi_index tag names
struct txid_index {};
struct insertion_order {};

struct DisconnectedBlockTransactions {
    typedef boost::multi_index_container<
        CTransactionRef,
        boost::multi_index::indexed_by<
            // sorted by txid
            boost::multi_index::hashed_unique<
                boost::multi_index::tag<txid_index>,
                mempoolentry_txid,
                SaltedTxidHasher
            >,
            // sorted by order in the blockchain
            boost::multi_index::sequenced<
                boost::multi_index::tag<insertion_order>
            >
        >
    > indexed_disconnected_transactions;

    // It's almost certainly a logic bug if we don't clear out queuedTx before
    // destruction, as we add to it while disconnecting blocks, and then we
    // need to re-process remaining transactions to ensure mempool consistency.
    // For now, assert() that we've emptied out this object on destruction.
    // This assert() can always be removed if the reorg-processing code were
    // to be refactored such that this assumption is no longer true (for
    // instance if there was some other way we cleaned up the mempool after a
    // reorg, besides draining this object).
    ~DisconnectedBlockTransactions() { assert(queuedTx.empty()); }

    indexed_disconnected_transactions queuedTx;
    uint64_t cachedInnerUsage = 0;

    // Estimate the overhead of queuedTx to be 6 pointers + an allocation, as
    // no exact formula for boost::multi_index_contained is implemented.
    size_t DynamicMemoryUsage() const {
        return memusage::MallocUsage(sizeof(CTransactionRef) + 6 * sizeof(void*)) * queuedTx.size() + cachedInnerUsage;
    }

    void addTransaction(const CTransactionRef& tx)
    {
        queuedTx.insert(tx);
        cachedInnerUsage += RecursiveDynamicUsage(tx);
    }

    // Remove entries based on txid_index, and update memory usage.
    void removeForBlock(const std::vector<CTransactionRef>& vtx)
    {
        // Short-circuit in the common case of a block being added to the tip
        if (queuedTx.empty()) {
            return;
        }
        for (auto const &tx : vtx) {
            auto it = queuedTx.find(tx->GetHash());
            if (it != queuedTx.end()) {
                cachedInnerUsage -= RecursiveDynamicUsage(*it);
                queuedTx.erase(it);
            }
        }
    }

    // Remove an entry by insertion_order index, and update memory usage.
    void removeEntry(indexed_disconnected_transactions::index<insertion_order>::type::iterator entry)
    {
        cachedInnerUsage -= RecursiveDynamicUsage(*entry);
        queuedTx.get<insertion_order>().erase(entry);
    }

    void clear()
    {
        cachedInnerUsage = 0;
        queuedTx.clear();
    }
};

#endif // BITCOIN_TXMEMPOOL_H
