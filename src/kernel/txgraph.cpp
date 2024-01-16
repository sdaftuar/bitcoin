#include <kernel/txgraph.h>
#include <cluster_linearize.h>
#include <util/time.h>
#include <logging.h>
#include <reverse_iterator.h>
#include <util/strencodings.h>

void TxGraphCluster::AddTransaction(const TxEntry& entry, bool sort)
{
    m_chunks.emplace_back(entry.GetModifiedFee(), entry.GetTxSize());
    m_chunks.back().txs.emplace_back(entry);
    entry.m_cluster = this;
    ++m_tx_count;
    m_tx_size += entry.GetTxSize();
    if (sort) Sort();
    return;
}

void TxGraphCluster::RemoveTransaction(const TxEntry& entry)
{
    m_chunks[entry.m_loc.first].txs.erase(entry.m_loc.second);

    // Chunk (or cluster) may now be empty, but this will get cleaned up
    // when the cluster is re-sorted (or when the cluster is deleted) Note:
    // if we cleaned up empty chunks here, then this would break the
    // locations of other entries in the cluster. Since we would like to be
    // able to do multiple removals in a row and then clean up the sort, we
    // can't clean up empty chunks here.
    --m_tx_count;
    m_tx_size -= entry.m_virtual_size;
    return;
}

void TxGraphCluster::RechunkFromLinearization(std::vector<TxEntry::TxEntryRef>& txs, bool reassign_locations)
{
    m_chunks.clear();
    m_tx_size = 0;

    for (auto txentry : txs) {
        m_chunks.emplace_back(txentry.get().GetModifiedFee(), txentry.get().GetTxSize());
        m_chunks.back().txs.emplace_back(txentry);
        while (m_chunks.size() >= 2) {
            auto cur_iter = std::prev(m_chunks.end());
            auto prev_iter = std::prev(cur_iter);
            // We only combine chunks if the feerate would go up; if two
            // chunks have equal feerate, we prefer to keep the smaller
            // chunksize (which is generally better for both mining and
            // eviction).
            if (FeeFrac(prev_iter->fee, prev_iter->size) < FeeFrac(cur_iter->fee, cur_iter->size)) {
                prev_iter->fee += cur_iter->fee;
                prev_iter->size += cur_iter->size;
                prev_iter->txs.splice(prev_iter->txs.end(), cur_iter->txs, cur_iter->txs.begin(), cur_iter->txs.end());
                m_chunks.erase(cur_iter);
            } else {
                break;
            }
        }
        m_tx_size += txentry.get().GetTxSize();
    }

    if (reassign_locations) {
        // Update locations of all transactions
        for (size_t i=0; i<m_chunks.size(); ++i) {
            for (auto it = m_chunks[i].txs.begin(); it != m_chunks[i].txs.end(); ++it) {
                it->get().m_loc = {i, it};
            }
        }
    }
}

TxEntry::TxEntryRef TxGraphCluster::GetLastTransaction()
{
    assert(m_tx_count > 0);
    for (auto chunkit = m_chunks.rbegin(); chunkit != m_chunks.rend(); ++chunkit) {
        if (!chunkit->txs.empty()) return chunkit->txs.back();
    }
    // Unreachable
    assert(false);
}

bool TxGraphCluster::Check()
{
    // First check that the metadata is correct.
    int64_t tx_count = 0;
    int64_t tx_size = 0;
    for (auto &chunk : m_chunks) { 
        for (auto &tx : chunk.txs) {
            ++tx_count;
            tx_size += tx.get().GetTxSize();
        }
    }
    if (tx_count != m_tx_count) return false;
    if (tx_size != m_tx_size) return false;

    // Check topology.
    std::set<TxEntry::TxEntryRef, TxEntry::CompareById> seen_elements;
    for (auto &chunk : m_chunks) {
        for (auto tx : chunk.txs) {
            for (auto parent : tx.get().parents) {
                if (seen_elements.count(parent) == 0) return false;
            }
            seen_elements.insert(tx);
            if (tx.get().m_cluster != this) return false;
            if (&m_chunks[tx.get().m_loc.first] != &chunk) return false;
            if (tx.get().m_loc.second->get().unique_id != tx.get().unique_id) return false;
        }
    }
    return true;
}

namespace {

template <typename SetType>
std::vector<TxEntry::TxEntryRef> InvokeSort(size_t tx_count, const std::vector<TxGraphCluster::Chunk>& chunks)
{
    std::vector<TxEntry::TxEntryRef> txs;
    cluster_linearize::Cluster<SetType> cluster;
    const auto time_1{SteadyClock::now()};

    std::vector<TxEntry::TxEntryRef> orig_txs;
    std::vector<std::pair<const TxEntry*, unsigned>> entry_to_index;
    cluster_linearize::LinearizationResult result;

    cluster.reserve(tx_count);
    entry_to_index.reserve(tx_count);
    cluster.clear();
    for (auto &chunk : chunks) {
        for (auto tx : chunk.txs) {
            orig_txs.emplace_back(tx);
            cluster.emplace_back(FeeFrac(uint64_t(tx.get().GetModifiedFee()+1000000*int64_t(tx.get().GetTxSize())), tx.get().GetTxSize()), SetType{});
            entry_to_index.emplace_back(&(tx.get()), cluster.size() - 1);
        }
    }
    std::sort(entry_to_index.begin(), entry_to_index.end());
    for (size_t i=0; i<orig_txs.size(); ++i) {
        for (auto& parent : orig_txs[i].get().parents) {
            auto it = std::lower_bound(entry_to_index.begin(), entry_to_index.end(), &(parent.get()),
                    [&](const auto& a, const auto& b) { return std::less<const TxEntry*>()(a.first, b); });
            assert(it != entry_to_index.end());
            assert(it->first == &(parent.get()));
            cluster[i].second.Set(it->second);
        }
    }
    result = cluster_linearize::LinearizeCluster(cluster, 0, 0);
    txs.clear();
    for (auto index : result.linearization) {
        txs.push_back(orig_txs[index]);
    }

    const auto time_2{SteadyClock::now()};
    if (tx_count >= 10) {
        double time_millis = Ticks<MillisecondsDouble>(time_2-time_1);

        LogPrint(BCLog::BENCH, "InvokeSort linearize cluster: %zu txs, %.4fms, %u iter, %.1fns/iter, %u comps, %.1fns/comp, encoding: %s\n",
                tx_count,
                time_millis,
                result.iterations,
                time_millis * 1000000.0 / (result.iterations > 0 ? result.iterations : result.iterations+1),
                result.comparisons,
                time_millis * 1000000.0 / (result.comparisons > 0 ? result.comparisons : result.comparisons+1),
                HexStr(cluster_linearize::DumpCluster(cluster)));
    }
    return txs;
}

} // namespace

void TxGraphCluster::Sort(bool reassign_locations)
{
    std::vector<TxEntry::TxEntryRef> txs;
    if (m_tx_count <= 32) {
        txs = InvokeSort<BitSet<32>>(m_tx_count, m_chunks);
    } else if (m_tx_count <= 64) {
        txs = InvokeSort<BitSet<64>>(m_tx_count, m_chunks);
    } else if (m_tx_count <= 128) {
        txs = InvokeSort<BitSet<128>>(m_tx_count, m_chunks);
    } else if (m_tx_count <= 192) {
        txs = InvokeSort<BitSet<192>>(m_tx_count, m_chunks);
    } else if (m_tx_count <= 256) {
        txs = InvokeSort<BitSet<256>>(m_tx_count, m_chunks);
    } else if (m_tx_count <= 320) {
        txs = InvokeSort<BitSet<320>>(m_tx_count, m_chunks);
    } else if (m_tx_count <= 384) {
        txs = InvokeSort<BitSet<384>>(m_tx_count, m_chunks);
    } else if (m_tx_count <= 1280) {
        txs = InvokeSort<BitSet<1280>>(m_tx_count, m_chunks);
    } else {
        // Only do the topological sort for big clusters
        for (auto &chunk : m_chunks) {
            for (auto chunk_tx : chunk.txs) {
                txs.emplace_back(chunk_tx.get());
            }
        }
        m_tx_graph->TopoSort(txs);
    }
    RechunkFromLinearization(txs, reassign_locations);
}

void TxGraphCluster::Rechunk()
{
    std::vector<TxEntry::TxEntryRef> txs;

    // Insert all transactions from the cluster into txs
    for (auto &chunk : m_chunks) {
        for (auto chunk_tx : chunk.txs) {
            txs.push_back(chunk_tx);
        }
    }

    RechunkFromLinearization(txs, true);
}

// Merge the clusters from [first, last) into this cluster.
void TxGraphCluster::Merge(std::vector<TxGraphCluster*>::iterator first, std::vector<TxGraphCluster*>::iterator last, bool this_cluster_first)
{
    // Check to see if we have anything to do.
    if (first == last) return;

    std::vector<Chunk> new_chunks;
    std::vector<TxGraphCluster::HeapEntry> heap_chunks;

    int64_t total_txs = m_tx_count;

    // Make a heap of all the best chunks.
    for (auto it = first; it != last; ++it) {
        if ((*it)->m_chunks.size() > 0) {
            heap_chunks.emplace_back((*it)->m_chunks.begin(), *it);
        }
        total_txs += (*it)->m_tx_count;
    }

    // During a reorg, we want to merge clusters corresponding to descendants
    // so that they appear after the cluster with their parent. This allows us
    // to trim megaclusters down to our cluster size limit in a way that
    // respects topology but still preferences higher feerate chunks over lower
    // feerate chunks.
    if (this_cluster_first) {
        new_chunks = std::move(m_chunks);
        m_chunks.clear();
    } else {
        heap_chunks.emplace_back(m_chunks.begin(), this);
    }
    // Define comparison operator on our heap entries (using feerate of chunks).
    auto cmp = [](const TxGraphCluster::HeapEntry& a, const TxGraphCluster::HeapEntry& b) {
        // TODO: branch on size of fee to do this as 32-bit calculation
        // instead? etc
        return FeeFrac(a.first->fee, a.first->size) < FeeFrac(b.first->fee, b.first->size);
        return a.first->fee*b.first->size < b.first->fee*a.first->size;
    };

    std::make_heap(heap_chunks.begin(), heap_chunks.end(), cmp);

    while (!heap_chunks.empty()) {
        // Take the best chunk from the heap.
        auto best_chunk = heap_chunks.front();
        new_chunks.emplace_back(std::move(*(best_chunk.first)));
        // Remove the best chunk from the heap.
        std::pop_heap(heap_chunks.begin(), heap_chunks.end(), cmp);
        heap_chunks.pop_back();
        // If the cluster has more chunks, add the next best chunk to the heap.
        ++best_chunk.first;
        if (best_chunk.first != best_chunk.second->m_chunks.end()) {
            heap_chunks.emplace_back(best_chunk.first, best_chunk.second);
            std::push_heap(heap_chunks.begin(), heap_chunks.end(), cmp);
        }
    }

    // At this point we've merged the clusters into new_chunks.
    m_chunks = std::move(new_chunks);

    m_tx_count=0;

    // Update the cluster and location information for each transaction.
    for (size_t i=0; i<m_chunks.size(); ++i) {
        for (auto it = m_chunks[i].txs.begin(); it != m_chunks[i].txs.end(); ++it) {
            it->get().m_cluster = this;
            it->get().m_loc = {i, it};
            ++m_tx_count;
        }
    }

    assert(m_tx_count == total_txs);
}

void TxGraph::AddTx(TxEntry *new_tx, int32_t vsize, CAmount modified_fee, const std::vector<TxEntry::TxEntryRef>& parents)
{
    LOCK(cs);
    new_tx->m_virtual_size = vsize;
    new_tx->m_modified_fee = modified_fee;
    // Figure out which cluster this transaction belongs to.
    std::vector<TxGraphCluster*> clusters_to_merge;
    {
        WITH_FRESH_EPOCH(m_epoch);
        for (auto p : parents) {
            UpdateParent(*new_tx, p, true);
            UpdateChild(p, *new_tx, true);
            if (!visited(p.get().m_cluster)) {
                clusters_to_merge.push_back(p.get().m_cluster);
            }
        }
    }

    // Merge all the clusters together.
    if (clusters_to_merge.size() == 0) {
        // No parents, make a new cluster.
        new_tx->m_cluster = AssignTxGraphCluster();
        new_tx->m_cluster->AddTransaction(*new_tx, true);
        cachedInnerUsage += new_tx->m_cluster->GetMemoryUsage();
    } else if (clusters_to_merge.size() == 1) {
        cachedInnerUsage -= clusters_to_merge[0]->GetMemoryUsage();
        // Only one parent cluster: add to it.
        clusters_to_merge[0]->AddTransaction(*new_tx, true);
        cachedInnerUsage += clusters_to_merge[0]->GetMemoryUsage();
    } else {
        cachedInnerUsage -= clusters_to_merge[0]->GetMemoryUsage();
        clusters_to_merge[0]->Merge(clusters_to_merge.begin()+1, clusters_to_merge.end(), false);
        // Add this transaction to the cluster.
        clusters_to_merge[0]->AddTransaction(*new_tx, true);
        // Need to delete the other clusters.
        for (auto it=clusters_to_merge.begin()+1; it != clusters_to_merge.end(); ++it) {
            cachedInnerUsage -= (*it)->GetMemoryUsage();
            m_cluster_map.erase((*it)->m_id);
        }
        cachedInnerUsage += clusters_to_merge[0]->GetMemoryUsage();
    }
}

void TxGraph::RemoveTx(TxEntry::TxEntryRef remove_tx)
{
    cachedInnerUsage -= memusage::DynamicUsage(remove_tx.get().parents) + memusage::DynamicUsage(remove_tx.get().children);
    // Update the parent/child state
    for (const TxEntry::TxEntryRef& parent: remove_tx.get().parents) {
        parent.get().children.erase(remove_tx);
    }
    for (const TxEntry::TxEntryRef& child: remove_tx.get().children) {
        child.get().parents.erase(remove_tx);
    }
    // Update the cluster
    remove_tx.get().m_cluster->RemoveTransaction(remove_tx.get());
}


std::vector<TxEntry::TxEntryRef> TxGraph::GetDescendants(const TxEntry& tx)
{
    std::vector<TxEntry::TxEntryRef> result{}, work_queue{};

    LOCK(cs);

    WITH_FRESH_EPOCH(m_epoch);
    visited(tx);
    work_queue.push_back(tx);

    while (!work_queue.empty()) {
        auto it = work_queue.back();
        work_queue.pop_back();
        result.push_back(it);
        for (auto& child: it.get().children) {
            if (!visited(child.get())) {
                work_queue.push_back(child);
            }
        }
    }
    return result;
}

std::vector<TxEntry::TxEntryRef> TxGraph::GetAncestors(const TxEntry& tx)
{
    std::vector<TxEntry::TxEntryRef> result{}, work_queue{};

    LOCK(cs);

    WITH_FRESH_EPOCH(m_epoch);
    visited(tx);
    work_queue.push_back(tx);

    while (!work_queue.empty()) {
        auto it = work_queue.back();
        work_queue.pop_back();
        result.push_back(it);
        for (auto& parent: it.get().parents) {
            if (!visited(parent.get())) {
                work_queue.push_back(parent);
            }
        }
    }
    return result;
}

TxGraphCluster* TxGraph::AssignTxGraphCluster()
{
    auto new_cluster = std::make_unique<TxGraphCluster>(m_next_cluster_id++, this);
    TxGraphCluster* ret = new_cluster.get(); // XXX No one is going to like this.
    m_cluster_map[new_cluster->m_id] = std::move(new_cluster);
    return ret;
}

// When transactions are removed from a cluster, the cluster might get split
// into smaller clusters.
void TxGraph::RecalculateTxGraphClusterAndMaybeSort(TxGraphCluster *cluster, bool sort)
{
    // TODO: if the common case involves no cluster splitting, can we short
    // circuit the work here somehow?

    // Wipe cluster assignments.
    std::vector<TxEntry::TxEntryRef> txs;
    for (auto& chunk : cluster->m_chunks) {
        for (auto& txentry: chunk.txs) {
            txentry.get().m_cluster = nullptr;
            txs.push_back(txentry);
        }
    }
    cluster->Clear();

    // The first transaction gets to stay in the existing cluster.
    bool first = true;
    for (auto& txentry : txs) {
        if (txentry.get().m_cluster == nullptr) {
            if (first) {
                txentry.get().m_cluster = cluster;
                first = false;
            } else {
                txentry.get().m_cluster = AssignTxGraphCluster();
            }
            txentry.get().m_cluster->AddTransaction(txentry.get(), false);
            // We need to label all transactions connected to this one as
            // being in the same cluster.
            {
                WITH_FRESH_EPOCH(m_epoch);
                std::vector<TxEntry::TxEntryRef> work_queue;
                for (auto entry : txentry.get().children) {
                    work_queue.push_back(entry);
                    visited(entry.get());
                }

                while (!work_queue.empty()) {
                    auto next_entry = work_queue.back();
                    work_queue.pop_back();
                    next_entry.get().m_cluster = txentry.get().m_cluster;

                    for (auto& descendant : next_entry.get().children) {
                        if (!visited(descendant.get())) {
                            work_queue.push_back(descendant);
                        }
                    }
                    for (auto& ancestor : next_entry.get().parents) {
                        if (!visited(ancestor.get())) {
                            work_queue.push_back(ancestor);
                        }
                    }
                }
            }
        } else {
            // If we already have a cluster assignment, we need to just add
            // ourselves to the cluster. Doing the addition here preserves
            // the topology and sort order from the original cluster.
            txentry.get().m_cluster->AddTransaction(txentry.get(), false);
        }
    }

    // After all assignments are made, either re-sort or re-chunk each cluster.
    std::vector<TxGraphCluster *> clusters_to_fix;
    {
        WITH_FRESH_EPOCH(m_epoch);
        for (auto it : txs) {
            if (!visited(it.get().m_cluster)) {
                clusters_to_fix.push_back(it.get().m_cluster);
            }
        }
    }
    for (auto cluster : clusters_to_fix) {
        if (sort) {
            cluster->Sort();
        } else {
            cluster->Rechunk();
        }
        cachedInnerUsage += cluster->GetMemoryUsage();
    }

    // Sanity check that all transactions are where they should be.
    for (auto it : txs) {
        assert(it.get().unique_id == it.get().m_loc.second->get().unique_id);
    }
}

void TxGraph::RemoveBatch(std::vector<TxEntry::TxEntryRef> &txs_removed)
{
    LOCK(cs);
    static std::vector<TxGraphCluster *> cluster_clean_up;
    cluster_clean_up.clear();
    {
        WITH_FRESH_EPOCH(m_epoch);
        for (auto t : txs_removed) {
            bool delete_now{false};
            TxGraphCluster *cluster = t.get().m_cluster;

            // Single transaction clusters can be deleted immediately without
            // any additional work.  TxGraphClusters with more than one transaction
            // need to be cleaned up later, even if they are ultimately fully
            // cleared, since we've left the pointer to the cluster
            // in the cluster_clean_up structure (so don't want to delete it and
            // invalidate the pointer).
            if (!visited(cluster)) {
                if (cluster->m_tx_count > 1) {
                    cluster_clean_up.push_back(cluster);
                } else {
                    delete_now = true;
                }
                cachedInnerUsage -= cluster->GetMemoryUsage();
            }
            RemoveTx(t);
            if (delete_now) {
                m_cluster_map.erase(cluster->m_id);
            }
        }
    }
    // After all transactions have been removed, delete the empty clusters and
    // repartition/re-sort the remaining clusters (which could have split).
    for (auto c : cluster_clean_up) {
        if (c->m_tx_count == 0) {
            m_cluster_map.erase(c->m_id);
        } else {
            RecalculateTxGraphClusterAndMaybeSort(c, true);
        }
    }
}

// Remove the last chunk from the cluster.
void TxGraph::RemoveChunkForEviction(TxGraphCluster *cluster)
{
    AssertLockHeld(cs);

    cachedInnerUsage -= cluster->GetMemoryUsage();

    std::vector<TxEntry::TxEntryRef> txs;
    for (auto& tx : cluster->m_chunks.back().txs) {
        txs.emplace_back(tx);
    }

    for (auto& tx : txs) {
        RemoveTx(tx);
    }

    cluster->m_chunks.pop_back();

    cachedInnerUsage += cluster->GetMemoryUsage();
    // Note: at this point the clusters will still be sorted, but they may need
    // to be split.
}

void TxGraph::TopoSort(std::vector<TxEntry::TxEntryRef>& to_be_sorted) const
{
    LOCK(cs);
    std::vector<TxEntry::TxEntryRef> sorted;
    sorted.reserve(to_be_sorted.size());
    std::vector<bool> already_added(to_be_sorted.size(), false);

    WITH_FRESH_EPOCH(m_epoch);
    for (size_t i=0; i<to_be_sorted.size(); ++i) {
        auto tx = to_be_sorted[i];
        // Check to see if this is already in the list.
        if (m_epoch.is_visited(tx.get().m_epoch_marker)) continue;

        // Gather the children for traversal.
        std::vector<TxEntry::TxEntryRef> work_queue;
        for (auto child : tx.get().children) {
            if (!m_epoch.is_visited(child.get().m_epoch_marker)) {
                work_queue.push_back(child);

                while (!work_queue.empty()) {
                    auto next_entry = work_queue.back();
                    // Check to see if this entry is already added.
                    if (m_epoch.is_visited(next_entry.get().m_epoch_marker)) {
                        work_queue.pop_back();
                        continue;
                    }
                    // Otherwise, check to see if all children have been walked.
                    bool children_visited_already = true;
                    for (auto child : next_entry.get().children) {
                        if (!m_epoch.is_visited(child.get().m_epoch_marker)) {
                            children_visited_already = false;
                            work_queue.push_back(child);
                        }
                    }
                    // If children have all been walked, we can remove this entry and
                    // add it to the list
                    if (children_visited_already) {
                        work_queue.pop_back();
                        sorted.push_back(next_entry);
                        visited(next_entry);
                    }
                }
            }
        }
        // Now that the descendants are added, we can add this entry.
        sorted.push_back(tx);
        visited(tx);
    }
    std::reverse(sorted.begin(), sorted.end());
    to_be_sorted.swap(sorted);
}

void TxGraph::UpdateChild(TxEntry::TxEntryRef entry, TxEntry::TxEntryRef child, bool add)
{
    AssertLockHeld(cs);
    TxEntry::TxEntryChildren s;
    if (add && entry.get().children.insert(child).second) {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
    } else if (!add && entry.get().children.erase(child)) {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
    }
}

void TxGraph::UpdateParent(TxEntry::TxEntryRef entry, TxEntry::TxEntryRef parent, bool add)
{
    AssertLockHeld(cs);
    TxEntry::TxEntryParents s;
    if (add && entry.get().parents.insert(parent).second) {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
    } else if (!add && entry.get().parents.erase(parent)) {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
    }
}

void TxGraph::AddParentTxs(std::vector<TxEntry::TxEntryRef> parent_txs, GraphLimits limits, 
        std::function<std::vector<TxEntry::TxEntryRef>(TxEntry::TxEntryRef)> func,
        std::vector<TxEntry::TxEntryRef> &txs_removed)
{
    LOCK(cs);
    for (auto tx : parent_txs) {
        auto children = func(tx);
        for (auto child : children) {
            UpdateChild(tx, child, true);
            UpdateParent(child, tx, true);
        }
    }
    // Now that all the parent transactions have been added, we can merge
    // clusters and remove transactions that exceed the limits.

    // Start by merging, then re-sort after merges are complete.
    for (const auto& tx : reverse_iterate(parent_txs)) {
        UpdateTxGraphClusterForDescendants(tx);
    }
    std::vector<TxGraphCluster *> unique_clusters_from_block;
    {
        WITH_FRESH_EPOCH(m_epoch);
        for (const auto& tx : reverse_iterate(parent_txs)) {
            if (!visited(tx.get().m_cluster)) {
                unique_clusters_from_block.push_back(tx.get().m_cluster);
            }
        }
    }
    for (TxGraphCluster *cluster : unique_clusters_from_block) {
        // If the cluster is too big, then we need to limit it by
        // evicting transactions and then re-calculate the cluster (it
        // may have split).  Otherwise, just sort.
        if (cluster->m_tx_count > limits.cluster_count || cluster->m_tx_size > limits.cluster_size_vbytes) {
            // Remove the last transaction in the cluster.
            cachedInnerUsage -= cluster->GetMemoryUsage();
            while (cluster->m_tx_count > limits.cluster_count ||
                    cluster->m_tx_size > limits.cluster_size_vbytes) {
                TxEntry::TxEntryRef last_tx = cluster->GetLastTransaction();
                RemoveTx(last_tx);
                txs_removed.emplace_back(last_tx);
            }
            RecalculateTxGraphClusterAndMaybeSort(cluster, true);
        } else {
            // Sort() can change the memory usage of the cluster
            cachedInnerUsage -= cluster->GetMemoryUsage();
            cluster->Sort();
            cachedInnerUsage += cluster->GetMemoryUsage();
        }
    }
}

void TxGraph::UpdateTxGraphClusterForDescendants(const TxEntry& tx)
{
    AssertLockHeld(cs);
    TxEntry::TxEntryChildren children = tx.children;
    std::vector<TxGraphCluster *> clusters_to_merge{tx.m_cluster};
    {
        WITH_FRESH_EPOCH(m_epoch);
        visited(tx.m_cluster);
        cachedInnerUsage -= tx.m_cluster->GetMemoryUsage();
        for (auto child : children) {
            if (!visited(child.get().m_cluster)) {
                clusters_to_merge.push_back(child.get().m_cluster);
                cachedInnerUsage -= child.get().m_cluster->GetMemoryUsage();
            }
        }
    }
    if (clusters_to_merge.size() > 1) {
        // Merge the other clusters into this one, but keep this cluster as
        // first so that it's topologically sound.
        clusters_to_merge[0]->Merge(clusters_to_merge.begin()+1, clusters_to_merge.end(), true);
        // Need to delete the other clusters.
        for (auto it=clusters_to_merge.begin()+1; it!= clusters_to_merge.end(); ++it) {
            m_cluster_map.erase((*it)->m_id);
        }
        // Note: we cannot re-sort the cluster here, because (a) we are not yet
        // finished merging connected clusters together, so some parents may be
        // missing, and (b) the cluster may be too large. Sorting should happen
        // only after all clustering is complete, and the clusters have been
        // trimmed down to our cluster count limit.
        clusters_to_merge[0]->Rechunk();
        // Add some assertion that topology is still valid?
    }
    cachedInnerUsage += clusters_to_merge[0]->GetMemoryUsage();
    return;
}

bool TxGraph::Check()
{
    // TODO: add checks on cachedInnerUsage

    LOCK(cs);
    // Run sanity checks on each cluster.
    for (const auto & [id, cluster] : m_cluster_map) {
        if (!cluster->Check()) {
            return false;
        }
    }
    return true;
}

Trimmer::Trimmer(TxGraph* tx_graph)
    : m_tx_graph(tx_graph)
{
    // TODO: we don't need the chunk in the heap, just the cluster.
    for (const auto & [id, cluster] : tx_graph->m_cluster_map) {
        if (!cluster->m_chunks.empty()) {
            heap_chunks.emplace_back(cluster->m_chunks.end()-1, cluster.get());
        }
    }

    std::make_heap(heap_chunks.begin(), heap_chunks.end(), ChunkCompare);
}

CFeeRate Trimmer::RemoveWorstChunk(std::vector<TxEntry::TxEntryRef>& txs_to_remove)
{
    LOCK(m_tx_graph->cs);
    // Remove the top element (lowest feerate) and evict.
    auto worst_chunk = heap_chunks.front();
    std::pop_heap(heap_chunks.begin(), heap_chunks.end(), Trimmer::ChunkCompare);
    heap_chunks.pop_back();

    // Save the txs being removed.
    for (auto& tx : worst_chunk.second->m_chunks.back().txs) {
        txs_to_remove.emplace_back(tx);
    }

    // Remove the worst chunk from the cluster.
    m_tx_graph->RemoveChunkForEviction(worst_chunk.second);

    // Check to see if there are more eviction candidates in this cluster.
    if (worst_chunk.second->m_tx_count > 0) {
        heap_chunks.emplace_back(worst_chunk.second->m_chunks.end()-1, worst_chunk.second);
        std::push_heap(heap_chunks.begin(), heap_chunks.end(), Trimmer::ChunkCompare);
    }

    clusters_with_evictions.insert(worst_chunk.second);

    CFeeRate removed(worst_chunk.first->fee, worst_chunk.first->size);
    return removed;
}

Trimmer::~Trimmer()
{
    // Before we can return, we have to clean up the clusters that saw
    // evictions, because they will have stray chunks and may need to be
    // re-partitioned.
    // However, these clusters do not need to be re-sorted, because evicted
    // chunks at the end can never change the relative ordering of transactions
    // that come before them.
    for (TxGraphCluster* cluster : clusters_with_evictions) {
        m_tx_graph->cachedInnerUsage -= cluster->GetMemoryUsage();
        if (cluster->m_tx_count == 0) {
            m_tx_graph->m_cluster_map.erase(cluster->m_id);
        } else {
            m_tx_graph->RecalculateTxGraphClusterAndMaybeSort(cluster, false);
        }
    }
}
