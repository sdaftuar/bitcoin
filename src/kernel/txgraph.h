#ifndef TX_GRAPH_H
#define TX_GRAPH_H

#include <util/feefrac.h>
#include <consensus/amount.h>
#include <policy/fees.h>
#include <util/epochguard.h>
#include <memusage.h>
#include <sync.h>

#include <atomic>
#include <functional>
#include <list>
#include <set>
#include <utility>

using namespace std;

class TxGraphCluster;
class TxGraph;

static std::atomic<int64_t> unique_id_counter{0};

class TxEntry {
public:
    typedef std::reference_wrapper<const TxEntry> TxEntryRef;
    typedef std::pair<size_t, std::list<TxEntryRef>::iterator> Location;

    struct CompareById {
        bool operator()(const TxEntryRef& a, const TxEntryRef& b) const {
            return a.get().unique_id < b.get().unique_id;
        }
    };

    typedef std::set<TxEntryRef, CompareById> TxEntryParents;
    typedef std::set<TxEntryRef, CompareById> TxEntryChildren;

    TxEntry(int32_t vsize, CAmount modified_fee)
        : m_virtual_size(vsize), m_modified_fee(modified_fee) {}
    int64_t unique_id{++unique_id_counter};
    int32_t m_virtual_size;
    CAmount m_modified_fee;              //!< Tx fee (including prioritisetransaction effects)
    int32_t GetTxSize() const { return m_virtual_size; }
    CAmount GetModifiedFee() const { return m_modified_fee; }
    mutable TxEntryParents parents;
    mutable TxEntryChildren children;
    mutable Location m_loc;              //!< Location within a cluster
    mutable TxGraphCluster *m_cluster{nullptr}; //! The cluster this entry belongs to
    mutable Epoch::Marker m_epoch_marker; //!< epoch when last touched
};

class TxGraphCluster {
public:
    TxGraphCluster(int64_t id, TxGraph *tx_graph) : m_id(id), m_tx_graph(tx_graph) {}

    void Clear() {
        m_chunks.clear();
        m_tx_count = 0;
    }

    // Add a transaction and update the sort.
    void AddTransaction(const TxEntry& entry, bool sort);
    void RemoveTransaction(const TxEntry& entry);

    // Sort the cluster and partition into chunks.
    void Sort(bool reassign_locations = true);

    // Just rechunk the cluster using its existing linearization.
    void Rechunk();

    // Sanity checks -- verify metadata matches and clusters are topo-sorted.
    bool Check();

private:
    // Helper function
    void RechunkFromLinearization(std::vector<TxEntry::TxEntryRef>& txs, bool reassign_locations);

public:
    void Merge(std::vector<TxGraphCluster *>::iterator first, std::vector<TxGraphCluster*>::iterator last, bool this_cluster_first);

    uint64_t GetMemoryUsage() const {
        return memusage::DynamicUsage(m_chunks) + m_tx_count * sizeof(void*) * 3;
    }

    TxEntry::TxEntryRef GetLastTransaction();

    // The chunks of transactions which will be added to blocks or
    // evicted from the mempool.
    struct Chunk {
        Chunk(CAmount _fee, int64_t _size) : fee(_fee), size(_size) {}
        Chunk(Chunk&& other) = default;
        Chunk& operator=(TxGraphCluster::Chunk&& other) = default;
        Chunk& operator=(const TxGraphCluster::Chunk& other) = delete;

        CAmount fee{0};
        int64_t size{0};
        std::list<TxEntry::TxEntryRef> txs;
    };

    typedef std::vector<Chunk>::iterator ChunkIter;
    typedef std::pair<ChunkIter, TxGraphCluster*> HeapEntry;

    std::vector<Chunk> m_chunks;
    int64_t m_tx_count{0};
    int64_t m_tx_size{0};

    const int64_t m_id;
    mutable Epoch::Marker m_epoch_marker; //!< epoch when last touched

    TxGraph *m_tx_graph{nullptr};  
};

class Trimmer {
public:
    Trimmer(TxGraph *tx_graph);
    ~Trimmer();
    CFeeRate RemoveWorstChunk(std::vector<TxEntry::TxEntryRef>& txs_to_remove);

private:
    static bool ChunkCompare(const TxGraphCluster::HeapEntry& a, const TxGraphCluster::HeapEntry& b) {
        return FeeFrac(a.first->fee, a.first->size) > FeeFrac(b.first->fee, b.first->size);
    }
    std::vector<TxGraphCluster::HeapEntry> heap_chunks;
    std::set<TxGraphCluster*> clusters_with_evictions;

    TxGraph *m_tx_graph{nullptr};
};

class TxSelector {
public:
    TxSelector(TxGraph *tx_graph);
    ~TxSelector();
    // Return the next chunk in the mempool that is at most max_vsize in size.
    void SelectNextChunk(std::vector<TxEntry::TxEntryRef>& txs);
    // If the transactions were successfully used, then notify the TxSelector
    // to keep selecting transactions from the same cluster.
    void Success();

private:
    static bool ChunkCompare(const TxGraphCluster::HeapEntry& a, const TxGraphCluster::HeapEntry& b) {
        return FeeFrac(a.first->fee, a.first->size) < FeeFrac(b.first->fee, b.first->size);
    }
    std::vector<TxGraphCluster::HeapEntry> heap_chunks;

    TxGraph *m_tx_graph{nullptr};
    TxGraphCluster::HeapEntry m_last_entry_selected{TxGraphCluster::ChunkIter(), nullptr};
};

struct GraphLimits {
    int64_t cluster_count{100};
    int64_t cluster_size_vbytes{101000};
};

class TxGraph {
public:
    TxGraph() {}

    // (lazily?) add a transaction to the graph (assume no in-mempool children?)
    void AddTx(TxEntry *new_tx, int32_t vsize, CAmount modified_fee, const std::vector<TxEntry::TxEntryRef>& parents);

    // Lazily remove a transaction from the graph
    void RemoveTx(TxEntry::TxEntryRef remove_tx) EXCLUSIVE_LOCKS_REQUIRED(cs);

    void RemoveBatch(std::vector<TxEntry::TxEntryRef> &txs_removed);

    // add a group of parent transactions, but limit resulting cluster sizes.
    void AddParentTxs(std::vector<TxEntry::TxEntryRef> parent_txs, GraphLimits limits, std::function<std::vector<TxEntry::TxEntryRef>(TxEntry::TxEntryRef)> func, std::vector<TxEntry::TxEntryRef> &txs_removed);

    // Evict the last chunk from the given cluster.
    // We need to do this iteratively, so lazy updating of state would be better.
    void RemoveChunkForEviction(TxGraphCluster *cluster) EXCLUSIVE_LOCKS_REQUIRED(cs);

    std::vector<TxEntry::TxEntryRef> GetAncestors(const TxEntry& tx);

    std::vector<TxEntry::TxEntryRef> GetDescendants(const TxEntry& tx);

    bool Check(); // sanity checks

private:
    // Create a new (empty) cluster in the cluster map, and return a pointer to it.
    TxGraphCluster* AssignTxGraphCluster() EXCLUSIVE_LOCKS_REQUIRED(cs);

    bool visited(const TxEntry& entry) const EXCLUSIVE_LOCKS_REQUIRED(cs, m_epoch)
    {
        return m_epoch.visited(entry.m_epoch_marker);
    }

    bool visited(TxGraphCluster *cluster) const EXCLUSIVE_LOCKS_REQUIRED(cs, m_epoch)
    {
        return m_epoch.visited(cluster->m_epoch_marker);
    }

    void RecalculateTxGraphClusterAndMaybeSort(TxGraphCluster *cluster, bool sort) EXCLUSIVE_LOCKS_REQUIRED(cs);

    void TopoSort(std::vector<TxEntry::TxEntryRef>& to_be_sorted) const;

    void UpdateParent(TxEntry::TxEntryRef entry, TxEntry::TxEntryRef parent, bool add) EXCLUSIVE_LOCKS_REQUIRED(cs);
    void UpdateChild(TxEntry::TxEntryRef entry, TxEntry::TxEntryRef child, bool add) EXCLUSIVE_LOCKS_REQUIRED(cs);

    void UpdateTxGraphClusterForDescendants(const TxEntry& tx) EXCLUSIVE_LOCKS_REQUIRED(cs);

private:
    mutable RecursiveMutex cs;

    // TxGraphClusters
    std::unordered_map<int64_t, std::unique_ptr<TxGraphCluster>> m_cluster_map GUARDED_BY(cs);
    int64_t m_next_cluster_id GUARDED_BY(cs){0};

    mutable Epoch m_epoch GUARDED_BY(cs){};
    uint64_t cachedInnerUsage GUARDED_BY(cs){0};

    friend class Trimmer;
    friend class TxGraphCluster;
    friend class TxSelector;
};

#endif // TXGRAPH_H
