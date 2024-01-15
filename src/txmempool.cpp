// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txmempool.h>

#include <chain.h>
#include <cluster_linearize.h>
#include <coins.h>
#include <common/system.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <logging.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <random.h>
#include <reverse_iterator.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/overflow.h>
#include <util/result.h>
#include <util/time.h>
#include <util/trace.h>
#include <util/translation.h>
#include <validationinterface.h>

#include <cmath>
#include <numeric>
#include <optional>
#include <string_view>
#include <utility>

bool TestLockPointValidity(CChain& active_chain, const LockPoints& lp)
{
    AssertLockHeld(cs_main);
    // If there are relative lock times then the maxInputBlock will be set
    // If there are no relative lock times, the LockPoints don't depend on the chain
    if (lp.maxInputBlock) {
        // Check whether active_chain is an extension of the block at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        if (!active_chain.Contains(lp.maxInputBlock)) {
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

void CTxMemPool::UpdateTransactionsFromBlock(const std::vector<uint256>& vHashesToUpdate)
{
    AssertLockHeld(cs);

    std::vector<TxEntry::TxEntryRef> parent_txs;

    // Iterate in reverse, so that whenever we are looking at a transaction
    // we are sure that all in-mempool descendants have already been processed.
    for (const uint256 &hash : reverse_iterate(vHashesToUpdate)) {
        txiter it = mapTx.find(hash);
        if (it != mapTx.end()) {
            parent_txs.push_back(*it);
        }
    }

    std::vector<TxEntry::TxEntryRef> txs_to_remove;

    tx_graph.AddParentTxs(parent_txs, m_limits, 
            [this](const TxEntry::TxEntryRef& tx) {
                std::vector<TxEntry::TxEntryRef> children;
                const uint256& hash = dynamic_cast<CTxMemPoolEntry&>(tx.get()).GetTx().GetHash();

                auto iter = this->mapNextTx.lower_bound(COutPoint(Txid::FromUint256(hash), 0));
                // First calculate the children, and update CTxMemPoolEntry::m_children to
                // include them, and update their CTxMemPoolEntry::m_parents to include this tx.
                // we cache the in-mempool children to avoid duplicate updates
                {
                    WITH_FRESH_EPOCH(m_epoch);
                    for (; iter != this->mapNextTx.end() && iter->first->hash == hash; ++iter) {
                        const uint256 &childHash = iter->second->GetHash();
                        txiter childIter = this->mapTx.find(childHash);
                        assert(childIter != this->mapTx.end());
                        // We can skip updating entries we've encountered before or that
                        // are in the block (which are already accounted for).
                        if (!this->visited(childIter)) {
                            children.emplace_back(*childIter);
                        }
                    }
                }
                return children;
            },
            txs_to_remove);
    for (auto& tx : txs_to_remove) {
        removeUnchecked(mapTx.iterator_to(dynamic_cast<CTxMemPoolEntry&>(tx.get())), MemPoolRemovalReason::SIZELIMIT);
    }
}

CTxMemPool::Entries CTxMemPool::CalculateAncestors(const Entries& parents) const
{
    Entries ancestors{}, work_queue{};

    WITH_FRESH_EPOCH(m_epoch);
    for (auto p : parents) {
        if (!visited(p)) {
            work_queue.push_back(p);
        }
    }

    while (!work_queue.empty()) {
        auto it = work_queue.back();
        work_queue.pop_back();
        ancestors.push_back(it);

        for (auto parent : it->GetMemPoolParentsConst()) {
            auto parent_it = mapTx.iterator_to(parent);
            if (!visited(parent_it)) {
                work_queue.push_back(parent_it);
            }
        }
    }

    return ancestors;
}

bool CTxMemPool::CheckPackageLimits(const Package& package,
                                    const int64_t total_vsize,
                                    std::string &errString) const
{
    CTxMemPoolEntry::Parents staged_ancestors;
    for (const auto& tx : package) {
        for (const auto& input : tx->vin) {
            std::optional<txiter> piter = GetIter(input.prevout.hash);
            if (piter) {
                staged_ancestors.insert(**piter);
            }
        }
    }
    auto cluster_result{CheckClusterSizeLimit(total_vsize, package.size(), m_limits, staged_ancestors)};
    if (!cluster_result) {
        errString = util::ErrorString(cluster_result).original;
        return false;
    }
    return true;
}

CTxMemPool::Entries CTxMemPool::CalculateParents(const CTxMemPoolEntry &entry) const
{
    Entries ret;
    {
        WITH_FRESH_EPOCH(m_epoch);
        for (const CTxIn &txin : entry.GetTx().vin) {
            std::optional<txiter> piter = GetIter(txin.prevout.hash);
            if (piter && !visited(*piter)) {
                ret.push_back(*piter);
            }
        }
    }
    return ret;
}

bool CTxMemPool::BuildClusterForTransaction(CTxMemPoolEntry& entry, const setEntries& all_conflicts, const Limits& limits, Cluster& temp_cluster)
{
    // Start by calculating all parents, which much be in the same cluster as entry.
    // Then, we repeat by walking all children of those parents, and add those to the cluster.
    // For each child, walk its parents, and repeat until we have nothing left to walk, or until we exceed some limit.
    // Return the built cluster.
    temp_cluster.Clear();
    temp_cluster.m_chunks.emplace_back(0, 0);
    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> work_queue;

    // Start by calculating the parents of this transaction, and adding them to the work queue.
    {
        Entries parents = CalculateParents(entry);
        // The parents need to be in the CTxMemPoolEntry for the Sort() below
        // to work.
        for (auto it : parents) {
            entry.GetMemPoolParents().insert(*it);
        }

        WITH_FRESH_EPOCH(m_epoch);

        for (auto parent_iter : entry.GetMemPoolParentsConst()) {
            work_queue.push_back(parent_iter);
            visited(parent_iter.get());
        }
        while (!work_queue.empty()) {
            auto next_entry = work_queue.back();
            work_queue.pop_back();
            if (all_conflicts.count(mapTx.iterator_to(next_entry))) {
                // Skip entries that are in the conflicts list
                continue;
            }
            temp_cluster.m_chunks[0].txs.push_back(next_entry);
            temp_cluster.m_tx_count++;
            temp_cluster.m_tx_size += next_entry.get().GetTxSize();
            if (temp_cluster.m_tx_count > limits.cluster_count || temp_cluster.m_tx_size > limits.cluster_size_vbytes) {
                return false;
            }
            auto next_children = next_entry.get().GetMemPoolChildrenConst();
            for (auto descendant : next_children) {
                if (!visited(descendant.get())) {
                    work_queue.push_back(descendant);
                }
            }
            auto next_parents = next_entry.get().GetMemPoolParentsConst();
            for (auto parent : next_parents) {
                if (!visited(parent.get())) {
                    work_queue.push_back(parent);
                }
            }
        }
    }
    temp_cluster.m_chunks[0].txs.emplace_back(entry);
    temp_cluster.m_tx_count++;
    temp_cluster.m_tx_size += entry.GetTxSize();

    if (temp_cluster.m_tx_count > limits.cluster_count || temp_cluster.m_tx_size > limits.cluster_size_vbytes) {
        return false;
    }

    temp_cluster.Sort(false);

    // Undo the changes we made to the entry.
    entry.GetMemPoolParents().clear();

    return true;
}

util::Result<bool> CTxMemPool::CheckClusterSizeLimit(int64_t entry_size, size_t entry_count,
        const Limits& limits, const CTxMemPoolEntry::Parents& all_parents) const
{
    int64_t total_cluster_count = entry_count;
    int64_t total_cluster_vbytes = entry_size;

    {
        WITH_FRESH_EPOCH(m_epoch);
        for (auto ancestor_iter : all_parents) {
            if (!visited(ancestor_iter.get().m_cluster)) {
                total_cluster_count += ancestor_iter.get().m_cluster->m_tx_count;
                total_cluster_vbytes += ancestor_iter.get().m_cluster->m_tx_size;
                // Short-circuit the calculation if we're definitely going to exceed the cluster limits.
                if (total_cluster_count > limits.cluster_count || total_cluster_vbytes > limits.cluster_size_vbytes) {
                    break;
                }
            }
        }
    }
    if (total_cluster_count > limits.cluster_count) {
        return util::Error{Untranslated(strprintf("too many unconfirmed transactions in the cluster [limit: %ld]", limits.cluster_count))};
    }
    if (total_cluster_vbytes > limits.cluster_size_vbytes) {
        return util::Error{Untranslated(strprintf("exceeds cluster size limit [limit: %d]", limits.cluster_size_vbytes))};
    }
    return true;
}

CTxMemPool::Entries CTxMemPool::CalculateMemPoolAncestors(const CTxMemPoolEntry& entry, bool fSearchForParents) const
{
    Entries parents;
    if (fSearchForParents) {
        parents = CalculateParents(entry);
    } else {
        for (auto p : entry.GetMemPoolParentsConst()) {
            parents.push_back(mapTx.iterator_to(p.get()));
        }
    }

    return CalculateAncestors(parents);
}

CTxMemPool::setEntries CTxMemPool::CalculateMemPoolAncestorsSlow(
    const CTxMemPoolEntry &entry,
    bool fSearchForParents /* = true */) const
{
    auto ancestors = CalculateMemPoolAncestors(entry, fSearchForParents);

    setEntries ret;
    ret.insert(ancestors.begin(), ancestors.end());
    return ret;
}

bool CTxMemPool::CalculateFeerateDiagramsForRBF(CTxMemPoolEntry& entry, CAmount modified_fee, const setEntries& direct_conflicts, const setEntries& all_conflicts, std::vector<FeeSizePoint>& old_diagram, std::vector<FeeSizePoint>& new_diagram)
{
    // Gather the old clusters, which consists of the cluster(s) that the new
    // transaction might merge, along with the clusters of all conflicting
    // transactions.
    Entries parents = CalculateParents(entry);

    std::vector<Cluster *> old_clusters;
    {
        WITH_FRESH_EPOCH(m_epoch);
        for (auto iter : direct_conflicts) {
            if (!visited(iter->m_cluster)) {
                old_clusters.emplace_back(iter->m_cluster);
            }
        }
        for (auto p : parents) {
            if (!visited(p->m_cluster)) {
                old_clusters.emplace_back(p->m_cluster);
            }
        }
    }

    GetFeerateDiagram(old_clusters, old_diagram);

    std::vector<Cluster *> new_clusters;
    if (!CalculateClustersForTransactions(entry, modified_fee, all_conflicts, old_clusters, new_clusters)) {
        return false;
    }

    GetFeerateDiagram(new_clusters, new_diagram);

    // Delete all the new clusters
    for (Cluster * cluster : new_clusters) {
        delete cluster;
    }

    return true;
}

bool CTxMemPool::CalculateClustersForTransactions(CTxMemPoolEntry& entry, CAmount modified_fee, const setEntries& all_conflicts, const std::vector<Cluster*>& old_clusters, std::vector<Cluster*>& new_clusters)
{
    new_clusters.clear();

    entry.UpdateModifiedFee(modified_fee - entry.GetFee());

    std::map<uint256, Cluster*> tx_to_new_cluster;

    // First cluster is special
    Cluster *first_cluster = new Cluster(0, this);
    new_clusters.emplace_back(first_cluster);

    // Start by figuring out which transactions would be clustered with the new
    // transaction, breaking early if limits are hit.
    if (!BuildClusterForTransaction(entry, all_conflicts, m_limits, *first_cluster)) {
        entry.UpdateModifiedFee(-modified_fee + entry.GetFee());
        delete first_cluster;
        return false;
    }
    entry.UpdateModifiedFee(-modified_fee + entry.GetFee());

    // If we succeeded, then label all these transactions.
    for (auto &chunk: first_cluster->m_chunks) {
        for (auto &tx: chunk.txs) {
            tx_to_new_cluster[tx.get().GetTx().GetHash()] = first_cluster;
        }
    }

    // Now go through all transactions and figure out what cluster they belong to.
    for (auto& cluster : old_clusters) {
        for (auto& chunk : cluster->m_chunks) {
            for (auto tx : chunk.txs) {
                if (all_conflicts.count(mapTx.iterator_to(tx.get()))) {
                    continue;
                }
                if (!tx_to_new_cluster.count(tx.get().GetTx().GetHash())) {
                    new_clusters.emplace_back(new Cluster(0, this));
                    tx_to_new_cluster[tx.get().GetTx().GetHash()] = new_clusters.back();
                } else if (tx_to_new_cluster[tx.get().GetTx().GetHash()] == first_cluster) {
                    // If the transaction is already in the first cluster, then
                    // we don't need to do anything, that cluster is done.
                    continue;
                }
                // Add the transaction to the end of the existing cluster.
                // We can't call Cluster::AddTransaction because that would change the existing pointer, which would break everything.
                Cluster *c = tx_to_new_cluster[tx.get().GetTx().GetHash()];
                c->m_chunks.emplace_back(tx.get().GetModifiedFee(), tx.get().GetTxSize());
                c->m_chunks.back().txs.emplace_back(tx);
                c->m_tx_count++;
                c->m_tx_size += tx.get().GetTxSize();

                // Now we have to mark all the connected transactions as being
                // in the same cluster.
                {
                    WITH_FRESH_EPOCH(m_epoch);
                    auto children = tx.get().GetMemPoolChildrenConst();
                    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> work_queue;
                    for (auto& entry : children) {
                        visited(entry.get());
                        if (all_conflicts.count(mapTx.iterator_to(entry.get()))) {
                            continue;
                        }
                        work_queue.push_back(entry);
                    }

                    while (!work_queue.empty()) {
                        auto next_entry = work_queue.back();
                        work_queue.pop_back();
                        tx_to_new_cluster[next_entry.get().GetTx().GetHash()] = c;

                        auto next_children = next_entry.get().GetMemPoolChildrenConst();
                        for (auto& descendant : next_children) {
                            if (!visited(descendant.get())) {
                                if (all_conflicts.count(mapTx.iterator_to(descendant.get()))) {
                                    continue;
                                }
                                work_queue.push_back(descendant);
                            }
                        }
                        auto next_parents = next_entry.get().GetMemPoolParentsConst();
                        for (auto& ancestor : next_parents) {
                            if (!visited(ancestor.get())) {
                                if (all_conflicts.count(mapTx.iterator_to(ancestor.get()))) {
                                    continue;
                                }
                                work_queue.push_back(ancestor);
                            }
                        }
                    }
                }
            }
        }
    }

    // Now sort all the clusters, other than the first which is done.
    for (size_t i=1; i<new_clusters.size(); i++) {
        new_clusters[i]->Sort(false);
    }

    return true;
}

void CTxMemPool::GetFeerateDiagram(std::vector<Cluster *> clusters, std::vector<FeeSizePoint>& diagram) const
{
    diagram.clear();
    diagram.emplace_back(FeeSizePoint{0, 0});

    std::vector<Cluster::HeapEntry> heap_chunks;

    // TODO: refactor so that we're not just copying this from the miner or the rpc code.
    // Initialize the heap with the best entry from each cluster
    for (auto& cluster : clusters) {
        if (!cluster->m_chunks.empty()) {
            heap_chunks.emplace_back(cluster->m_chunks.begin(), cluster);
        }
    }
    // Define comparison operator on our heap entries (using feerate of chunks).
    auto cmp = [](const Cluster::HeapEntry& a, const Cluster::HeapEntry& b) {
        return FeeSizePoint{a.first->size, a.first->fee} < FeeSizePoint{b.first->size, b.first->fee};
        return a.first->fee*b.first->size < b.first->fee*a.first->size;
    };
    std::make_heap(heap_chunks.begin(), heap_chunks.end(), cmp);

    CAmount accum_fee{0};
    int64_t accum_size{0};
    while (!heap_chunks.empty()) {
        auto best_chunk = heap_chunks.front();
        std::pop_heap(heap_chunks.begin(), heap_chunks.end(), cmp);
        heap_chunks.pop_back();

        accum_size += best_chunk.first->size;
        accum_fee += best_chunk.first->fee;

        diagram.emplace_back(FeeSizePoint{accum_size, accum_fee});

        ++best_chunk.first;
        if (best_chunk.first != best_chunk.second->m_chunks.end()) {
            heap_chunks.emplace_back(best_chunk);
            std::push_heap(heap_chunks.begin(), heap_chunks.end(), cmp);
        }
    }

    return;
}

CTxMemPool::CTxMemPool(const Options& opts)
    : m_check_ratio{opts.check_ratio},
      m_max_size_bytes{opts.max_size_bytes},
      m_expiry{opts.expiry},
      m_incremental_relay_feerate{opts.incremental_relay_feerate},
      m_min_relay_feerate{opts.min_relay_feerate},
      m_dust_relay_feerate{opts.dust_relay_feerate},
      m_permit_bare_multisig{opts.permit_bare_multisig},
      m_max_datacarrier_bytes{opts.max_datacarrier_bytes},
      m_require_standard{opts.require_standard},
      m_full_rbf{opts.full_rbf},
      m_persist_v1_dat{opts.persist_v1_dat},
      m_limits{opts.limits},
      txgraph(this)
{
}

bool CTxMemPool::isSpent(const COutPoint& outpoint) const
{
    LOCK(cs);
    return mapNextTx.count(outpoint);
}

unsigned int CTxMemPool::GetTransactionsUpdated() const
{
    return nTransactionsUpdated;
}

void CTxMemPool::AddTransactionsUpdated(unsigned int n)
{
    nTransactionsUpdated += n;
}

void CTxMemPool::addUnchecked(const CTxMemPoolEntry &entry)
{
    // Add to memory pool without checking anything.
    // Used by AcceptToMemoryPool(), which DOES do
    // all the appropriate checks.
    indexed_transaction_set::iterator newit = mapTx.emplace(CTxMemPoolEntry::ExplicitCopy, entry).first;

    // Update transaction for any feeDelta created by PrioritiseTransaction
    CAmount delta{0};
    ApplyDelta(entry.GetTx().GetHash(), delta);
    // The following call to UpdateModifiedFee assumes no previous fee modifications
    Assume(entry.GetFee() == entry.GetModifiedFee());
    if (delta) {
        mapTx.modify(newit, [&delta](CTxMemPoolEntry& e) { e.UpdateModifiedFee(delta); });
    }

    // Update cachedInnerUsage to include contained transaction's usage.
    // (When we update the entry for in-mempool parents, memory usage will be
    // further updated.)
    cachedInnerUsage += entry.DynamicMemoryUsage();

    const CTransaction& tx = newit->GetTx();
    std::set<uint256> setParentTransactions;
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        mapNextTx.insert(std::make_pair(&tx.vin[i].prevout, &tx));
        setParentTransactions.insert(tx.vin[i].prevout.hash);
    }
    // Don't bother worrying about child transactions of this one.
    // Normal case of a new transaction arriving is that there can't be any
    // children, because such children would be orphans.
    // An exception to that is if a transaction enters that used to be in a block.
    // In that case, our disconnect block logic will call UpdateTransactionsFromBlock
    // to clean up the mess we're leaving here.

    std::vector<TxEntryRef> parents;
    for (const auto& pit : GetIterSet(setParentTransactions)) {
        parents.emplace_back(*pit);
    }

    nTransactionsUpdated++;
    totalTxSize += entry.GetTxSize();
    m_total_fee += entry.GetFee();

    txns_randomized.emplace_back(newit->GetSharedTx());
    newit->idx_randomized = txns_randomized.size() - 1;

    txgraph.AddTx(*newit, newit->GetTxSize(), newit->GetModifiedFee(), parents);

    TRACE3(mempool, added,
        entry.GetTx().GetHash().data(),
        entry.GetTxSize(),
        entry.GetFee()
    );
}

void CTxMemPool::removeUnchecked(txiter it, MemPoolRemovalReason reason)
{
    // We increment mempool sequence value no matter removal reason
    // even if not directly reported below.
    uint64_t mempool_sequence = GetAndIncrementSequence();

    if (reason != MemPoolRemovalReason::BLOCK) {
        // Notify clients that a transaction has been removed from the mempool
        // for any reason except being included in a block. Clients interested
        // in transactions included in blocks can subscribe to the BlockConnected
        // notification.
        GetMainSignals().TransactionRemovedFromMempool(it->GetSharedTx(), reason, mempool_sequence);
    }
    TRACE5(mempool, removed,
        it->GetTx().GetHash().data(),
        RemovalReasonToString(reason).c_str(),
        it->GetTxSize(),
        it->GetFee(),
        std::chrono::duration_cast<std::chrono::duration<std::uint64_t>>(it->GetTime()).count()
    );

    for (const CTxIn& txin : it->GetTx().vin)
        mapNextTx.erase(txin.prevout);

    RemoveUnbroadcastTx(it->GetTx().GetHash(), true /* add logging because unchecked */);

    if (txns_randomized.size() > 1) {
        // Update idx_randomized of the to-be-moved entry.
        Assert(GetEntry(txns_randomized.back()->GetHash()))->idx_randomized = it->idx_randomized;
        // Remove entry from txns_randomized by replacing it with the back and deleting the back.
        txns_randomized[it->idx_randomized] = std::move(txns_randomized.back());
        txns_randomized.pop_back();
        if (txns_randomized.size() * 2 < txns_randomized.capacity())
            txns_randomized.shrink_to_fit();
    } else
        txns_randomized.clear();

    totalTxSize -= it->GetTxSize();
    m_total_fee -= it->GetFee();
    cachedInnerUsage -= it->DynamicMemoryUsage();
    mapTx.erase(it);
    nTransactionsUpdated++;
}

// Calculates descendants of given entry and adds to setDescendants.
void CTxMemPool::CalculateDescendantsSlow(txiter entryit, setEntries& setDescendants) const
{
    auto descendants = GetDescendants({*entryit});
    for (auto d : descendants) {
        setDescendants.insert(mapTx.iterator_to(dynamic_cast<CTxMemPoolEntry&>(d)));
    }
}

void CTxMemPool::removeRecursive(const CTransaction &origTx, MemPoolRemovalReason reason)
{
    // Remove transaction from memory pool
    AssertLockHeld(cs);
    std::vector<TxEntryRef> txToRemove;
    txiter origit = mapTx.find(origTx.GetHash());

    {
        WITH_FRESH_EPOCH(m_epoch);
        if (origit != mapTx.end()) {
            visited(origit);
            txToRemove.push_back(*origit);
        } else {
            // When recursively removing but origTx isn't in the mempool
            // be sure to remove any children that are in the pool. This can
            // happen during chain re-orgs if origTx isn't re-accepted into
            // the mempool for any reason.
            for (unsigned int i = 0; i < origTx.vout.size(); i++) {
                auto it = mapNextTx.find(COutPoint(origTx.GetHash(), i));
                if (it == mapNextTx.end())
                    continue;
                txiter nextit = mapTx.find(it->second->GetHash());
                assert(nextit != mapTx.end());
                if (!visited(nextit)) {
                    txToRemove.push_back(*nextit);
                }
            }
        }
    }
    setEntries setAllRemoves;
    auto all_removes = tx_graph.CalculateDescendants(txToRemove);

    for (auto d : all_removes) {
        setAllRemoves.insert(mapTx.iterator_to(dynamic_cast<CTxMemPoolEntry&>(d)));
    }
    RemoveStaged(setAllRemoves, false, reason);
}

void CTxMemPool::removeForReorg(CChain& chain, std::function<bool(txiter)> check_final_and_mature)
{
    // Remove transactions spending a coinbase which are now immature and no-longer-final transactions
    AssertLockHeld(cs);
    AssertLockHeld(::cs_main);

    std::vector<TxEntryRef> txToRemove;
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        if (check_final_and_mature(it)) txToRemove.push_back(*it);
    }
    auto descendants = tx_graph.CalculateDescendants(txToRemove);

    setEntries setAllRemoves;
    for (auto d : descendants) {
        setAllRemoves.insert(mapTx.iterator_to(dynamic_cast<CTxMemPoolEntry&>(d)));
    }

    RemoveStaged(setAllRemoves, false, MemPoolRemovalReason::REORG);
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        assert(TestLockPointValidity(chain, it->GetLockPoints()));
    }
}

void CTxMemPool::removeConflicts(const CTransaction &tx)
{
    // Remove transactions which depend on inputs of tx, recursively
    AssertLockHeld(cs);
    for (const CTxIn &txin : tx.vin) {
        auto it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end()) {
            const CTransaction &txConflict = *it->second;
            if (txConflict != tx)
            {
                ClearPrioritisation(txConflict.GetHash());
                removeRecursive(txConflict, MemPoolRemovalReason::CONFLICT);
            }
        }
    }
}

/**
 * Called when a block is connected. Removes from mempool.
 */
void CTxMemPool::removeForBlock(const std::vector<CTransactionRef>& vtx, unsigned int nBlockHeight)
{
    AssertLockHeld(cs);
    std::vector<RemovedMempoolTransactionInfo> txs_removed_for_block;
    txs_removed_for_block.reserve(vtx.size());
    std::vector<TxEntry::TxEntryRef> txs_to_remove;

    // Look up all iterators, and grab the transaction data that we'll need for
    // the callback later.
    for (const auto& tx : vtx)
    {
        txiter it = mapTx.find(tx->GetHash());
        if (it != mapTx.end()) {
            txs_to_remove.emplace_back(*it);
            txs_removed_for_block.emplace_back(*it);
        }
    }

    // Remove these transactions from the tx graph
    tx_graph.RemoveBatch(vtx);

    // Remove the transactions from the mempool
    for (auto tx : txs_to_remove) 
        removeUnchecked(mapTx.iterator_to(dynamic_cast<CTxMemPoolEntry&>(*tx)), MemPoolRemovalReason::BLOCK);
    }

    for (const auto& tx : vtx) {
        removeConflicts(*tx);
        ClearPrioritisation(tx->GetHash());
    }
    GetMainSignals().MempoolTransactionsRemovedForBlock(txs_removed_for_block, nBlockHeight);
    lastRollingFeeUpdate = GetTime();
    blockSinceLastRollingFeeBump = true;
}

void CTxMemPool::check(const CCoinsViewCache& active_coins_tip, int64_t spendheight) const
{
    if (m_check_ratio == 0) return;

    if (GetRand(m_check_ratio) >= 1) return;

    AssertLockHeld(::cs_main);
    LOCK(cs);
    LogPrint(BCLog::MEMPOOL, "Checking mempool with %u transactions and %u inputs\n", (unsigned int)mapTx.size(), (unsigned int)mapNextTx.size());

    uint64_t checkTotal = 0;
    CAmount check_total_fee{0};
    uint64_t innerUsage = 0;

    CCoinsViewCache mempoolDuplicate(const_cast<CCoinsViewCache*>(&active_coins_tip));

    for (const auto& it : GetSortedScoreWithTopology()) {
        checkTotal += it->GetTxSize();
        check_total_fee += it->GetFee();
        innerUsage += it->DynamicMemoryUsage();

        // Check that a transaction's location in cluster is correct.
        assert(it->GetTx().GetHash() == it->m_loc.second->get().GetTx().GetHash());
        const CTransaction& tx = it->GetTx();
        innerUsage += memusage::DynamicUsage(it->GetMemPoolParentsConst()) + memusage::DynamicUsage(it->GetMemPoolChildrenConst());
        CTxMemPoolEntry::Parents setParentCheck;
        for (const CTxIn &txin : tx.vin) {
            // Check that every mempool transaction's inputs refer to available coins, or other mempool tx's.
            indexed_transaction_set::const_iterator it2 = mapTx.find(txin.prevout.hash);
            if (it2 != mapTx.end()) {
                const CTransaction& tx2 = it2->GetTx();
                assert(tx2.vout.size() > txin.prevout.n && !tx2.vout[txin.prevout.n].IsNull());
                setParentCheck.insert(*it2);

                // Check that every parent is in the same cluster.
                assert(it2->m_cluster == it->m_cluster);
            }
            // We are iterating through the mempool entries sorted topologically and by score.
            // All parents must have been checked before their children and their coins added to
            // the mempoolDuplicate coins cache.
            assert(mempoolDuplicate.HaveCoin(txin.prevout));
            // Check whether its inputs are marked in mapNextTx.
            auto it3 = mapNextTx.find(txin.prevout);
            assert(it3 != mapNextTx.end());
            assert(it3->first == &txin.prevout);
            assert(it3->second == &tx);
        }
        auto comp = [](const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) -> bool {
            return a.GetTx().GetHash() == b.GetTx().GetHash();
        };
        assert(setParentCheck.size() == it->GetMemPoolParentsConst().size());
        assert(std::equal(setParentCheck.begin(), setParentCheck.end(), it->GetMemPoolParentsConst().begin(), comp));

        // Check children against mapNextTx
        CTxMemPoolEntry::Children setChildrenCheck;
        auto iter = mapNextTx.lower_bound(COutPoint(it->GetTx().GetHash(), 0));
        for (; iter != mapNextTx.end() && iter->first->hash == it->GetTx().GetHash(); ++iter) {
            txiter childit = mapTx.find(iter->second->GetHash());
            assert(childit != mapTx.end()); // mapNextTx points to in-mempool transactions
            // Children should be in the same cluster.
            assert(childit->m_cluster == it->m_cluster);
            setChildrenCheck.insert(*childit);
        }
        assert(setChildrenCheck.size() == it->GetMemPoolChildrenConst().size());
        assert(std::equal(setChildrenCheck.begin(), setChildrenCheck.end(), it->GetMemPoolChildrenConst().begin(), comp));

        TxValidationState dummy_state; // Not used. CheckTxInputs() should always pass
        CAmount txfee = 0;
        assert(!tx.IsCoinBase());
        assert(Consensus::CheckTxInputs(tx, dummy_state, mempoolDuplicate, spendheight, txfee));
        for (const auto& input: tx.vin) mempoolDuplicate.SpendCoin(input.prevout);
        AddCoins(mempoolDuplicate, tx, std::numeric_limits<int>::max());
    }
    for (auto it = mapNextTx.cbegin(); it != mapNextTx.cend(); it++) {
        uint256 hash = it->second->GetHash();
        indexed_transaction_set::const_iterator it2 = mapTx.find(hash);
        const CTransaction& tx = it2->GetTx();
        assert(it2 != mapTx.end());
        assert(&tx == it->second);
    }

    // Check that clusters are sorted topologically and that the chunk metadata
    // matches the txs in the chunk.
    for (const auto & [id, cluster] : m_cluster_map) {
        assert(cluster->m_tx_count > 0); // no empty clusters
        CTxMemPoolEntry::Parents txs_so_far;
        for (size_t i=0; i<cluster->m_chunks.size(); ++i) {
            int64_t fee{0};
            int64_t size{0};
            assert(!cluster->m_chunks[i].txs.empty()); // no empty chunks
            for (auto it=cluster->m_chunks[i].txs.begin(); it != cluster->m_chunks[i].txs.end(); ++it) {
                fee += it->get().GetModifiedFee();
                size += it->get().GetTxSize();
                // Check that all parents are in txs_so_far
                for (const auto& parent : it->get().GetMemPoolParentsConst()) {
                    assert(txs_so_far.count(parent));
                }
                txs_so_far.insert(*it);
            }
            assert(fee == cluster->m_chunks[i].fee);
            assert(size == cluster->m_chunks[i].size);
        }
        innerUsage += cluster->GetMemoryUsage();
    }

    // Check that each cluster is connected.
    for (const auto & [id, cluster] : m_cluster_map) {
        // Since we've checked the parents and children already, we'll use
        // those values here.
        // We'll check that if we walk to every transaction reachable from the
        // first one, that we get every tx in the cluster.
        auto first_tx = cluster->m_chunks.front().txs.front();
        std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> work_queue;
        int reachable_txs = 1; // we'll count the transactions we reach.

        WITH_FRESH_EPOCH(m_epoch);
        visited(first_tx.get());
        assert(first_tx.get().GetMemPoolParentsConst().size() == 0); // first tx can never have parents.
        for (auto child : first_tx.get().GetMemPoolChildrenConst()) {
            work_queue.push_back(child);
            visited(child.get());
            ++reachable_txs;
        }
        while (work_queue.size() > 0) {
            auto next_tx = work_queue.back();
            work_queue.pop_back();
            for (auto parent : next_tx.get().GetMemPoolParentsConst()) {
                if (!visited(parent.get())) {
                    ++reachable_txs;
                    work_queue.push_back(parent);
                }
            }
            for (auto child : next_tx.get().GetMemPoolChildrenConst()) {
                if (!visited(child.get())) {
                    ++reachable_txs;
                    work_queue.push_back(child);
                }
            }
        }
        assert(reachable_txs == cluster->m_tx_count);
    }

    assert(totalTxSize == checkTotal);
    assert(m_total_fee == check_total_fee);
    assert(innerUsage == cachedInnerUsage);
}

// Return true if a comes before b in mempool sort order
bool CTxMemPool::CompareMiningScore(txiter a, txiter b) const
{
    if (a == b) return false; // An element cannot be less than itself.

    CAmount a_fee = a->m_cluster->m_chunks[a->m_loc.first].fee;
    int64_t a_size = a->m_cluster->m_chunks[a->m_loc.first].size;
    CAmount b_fee = b->m_cluster->m_chunks[b->m_loc.first].fee;
    int64_t b_size = b->m_cluster->m_chunks[b->m_loc.first].size;

    FeeSizePoint a_frac{a_size, a_fee};
    FeeSizePoint b_frac{b_size, b_fee};
    if (a_frac != b_frac) {
        return a_frac > b_frac;
    } else if (a->m_cluster != b->m_cluster) {
        // Equal scores in different clusters; sort by cluster id.
        return a->m_cluster->m_id < b->m_cluster->m_id;
        //return a->GetTx().GetHash() < b->GetTx().GetHash();
    } else if (a->m_loc.first != b->m_loc.first) {
        // Equal scores in same cluster; sort by chunk index.
        return a->m_loc.first < b->m_loc.first;
    } else {
        // Equal scores in same cluster and chunk; sort by position in chunk.
        for (auto it = a->m_cluster->m_chunks[a->m_loc.first].txs.begin();
                it != a->m_cluster->m_chunks[a->m_loc.first].txs.end(); ++it) {
            if (&(it->get()) == &(*a)) return true;
            if (&(it->get()) == &(*b)) return false;
        }
    }
    Assume(false); // this should not be reachable.
    return true;
}

bool CTxMemPool::CompareMiningScoreWithTopology(const uint256& hasha, const uint256& hashb, bool wtxid)
{
    /* Return `true` if hasha should be considered sooner than hashb. Namely when:
     *   a is not in the mempool, but b is
     *   both are in the mempool and a has a higher mining score than b
     *   both are in the mempool and a appears before b in the same cluster
     */
    LOCK(cs);
    indexed_transaction_set::const_iterator j = wtxid ? get_iter_from_wtxid(hashb) : mapTx.find(hashb);
    if (j == mapTx.end()) return false;
    indexed_transaction_set::const_iterator i = wtxid ? get_iter_from_wtxid(hasha) : mapTx.find(hasha);
    if (i == mapTx.end()) return true;

    return CompareMiningScore(i, j);
}

std::vector<CTxMemPool::indexed_transaction_set::const_iterator> CTxMemPool::GetSortedScoreWithTopology() const
{
    std::vector<indexed_transaction_set::const_iterator> iters;
    AssertLockHeld(cs);

    iters.reserve(mapTx.size());

    for (indexed_transaction_set::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi) {
        iters.push_back(mi);
    }
    std::sort(iters.begin(), iters.end(), [this](const CTxMemPool::indexed_transaction_set::const_iterator& a, const CTxMemPool::indexed_transaction_set::const_iterator& b) {
        LOCK(this->cs); // TODO: this is unnecessary, to quiet a compiler warning
        return this->CompareMiningScore(a, b);
    });
    return iters;
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid) const
{
    LOCK(cs);
    auto iters = GetSortedScoreWithTopology();

    vtxid.clear();
    vtxid.reserve(mapTx.size());

    for (auto it : iters) {
        vtxid.push_back(it->GetTx().GetHash());
    }
}

static TxMempoolInfo GetInfo(CTxMemPool::indexed_transaction_set::const_iterator it) {
    return TxMempoolInfo{it->GetSharedTx(), it->GetTime(), it->GetFee(), it->GetTxSize(), it->GetModifiedFee() - it->GetFee()};
}

std::vector<CTxMemPoolEntryRef> CTxMemPool::entryAll() const
{
    AssertLockHeld(cs);

    std::vector<CTxMemPoolEntryRef> ret;
    ret.reserve(mapTx.size());
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        ret.emplace_back(*it);
    }
    return ret;
}

std::vector<TxMempoolInfo> CTxMemPool::infoAll() const
{
    LOCK(cs);
    auto iters = GetSortedScoreWithTopology();

    std::vector<TxMempoolInfo> ret;
    ret.reserve(mapTx.size());
    for (auto it : iters) {
        ret.push_back(GetInfo(it));
    }

    return ret;
}

const CTxMemPoolEntry* CTxMemPool::GetEntry(const Txid& txid) const
{
    AssertLockHeld(cs);
    const auto i = mapTx.find(txid);
    return i == mapTx.end() ? nullptr : &(*i);
}

CTransactionRef CTxMemPool::get(const uint256& hash) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
        return nullptr;
    return i->GetSharedTx();
}

TxMempoolInfo CTxMemPool::info(const GenTxid& gtxid) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = (gtxid.IsWtxid() ? get_iter_from_wtxid(gtxid.GetHash()) : mapTx.find(gtxid.GetHash()));
    if (i == mapTx.end())
        return TxMempoolInfo();
    return GetInfo(i);
}

TxMempoolInfo CTxMemPool::info_for_relay(const GenTxid& gtxid, uint64_t last_sequence) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = (gtxid.IsWtxid() ? get_iter_from_wtxid(gtxid.GetHash()) : mapTx.find(gtxid.GetHash()));
    if (i != mapTx.end() && i->GetSequence() < last_sequence) {
        return GetInfo(i);
    } else {
        return TxMempoolInfo();
    }
}

void CTxMemPool::PrioritiseTransaction(const uint256& hash, const CAmount& nFeeDelta)
{
    {
        LOCK(cs);
        CAmount &delta = mapDeltas[hash];
        delta = SaturatingAdd(delta, nFeeDelta);
        txiter it = mapTx.find(hash);
        if (it != mapTx.end()) {
            mapTx.modify(it, [&nFeeDelta](CTxMemPoolEntry& e) { e.UpdateModifiedFee(nFeeDelta); });

            ++nTransactionsUpdated;

            cachedInnerUsage -= it->m_cluster->GetMemoryUsage();

            // Re-sort the cluster this came from.
            it->m_cluster->Sort();

            cachedInnerUsage += it->m_cluster->GetMemoryUsage();
        }
        if (delta == 0) {
            mapDeltas.erase(hash);
            LogPrintf("PrioritiseTransaction: %s (%sin mempool) delta cleared\n", hash.ToString(), it == mapTx.end() ? "not " : "");
        } else {
            LogPrintf("PrioritiseTransaction: %s (%sin mempool) fee += %s, new delta=%s\n",
                      hash.ToString(),
                      it == mapTx.end() ? "not " : "",
                      FormatMoney(nFeeDelta),
                      FormatMoney(delta));
        }
    }
}

void CTxMemPool::ApplyDelta(const uint256& hash, CAmount &nFeeDelta) const
{
    AssertLockHeld(cs);
    std::map<uint256, CAmount>::const_iterator pos = mapDeltas.find(hash);
    if (pos == mapDeltas.end())
        return;
    const CAmount &delta = pos->second;
    nFeeDelta += delta;
}

void CTxMemPool::ClearPrioritisation(const uint256& hash)
{
    AssertLockHeld(cs);
    mapDeltas.erase(hash);
}

std::vector<CTxMemPool::delta_info> CTxMemPool::GetPrioritisedTransactions() const
{
    AssertLockNotHeld(cs);
    LOCK(cs);
    std::vector<delta_info> result;
    result.reserve(mapDeltas.size());
    for (const auto& [txid, delta] : mapDeltas) {
        const auto iter{mapTx.find(txid)};
        const bool in_mempool{iter != mapTx.end()};
        std::optional<CAmount> modified_fee;
        if (in_mempool) modified_fee = iter->GetModifiedFee();
        result.emplace_back(delta_info{in_mempool, delta, modified_fee, txid});
    }
    return result;
}

const CTransaction* CTxMemPool::GetConflictTx(const COutPoint& prevout) const
{
    const auto it = mapNextTx.find(prevout);
    return it == mapNextTx.end() ? nullptr : it->second;
}

std::optional<CTxMemPool::txiter> CTxMemPool::GetIter(const uint256& txid) const
{
    auto it = mapTx.find(txid);
    if (it != mapTx.end()) return it;
    return std::nullopt;
}

CTxMemPool::setEntries CTxMemPool::GetIterSet(const std::set<uint256>& hashes) const
{
    CTxMemPool::setEntries ret;
    for (const auto& h : hashes) {
        const auto mi = GetIter(h);
        if (mi) ret.insert(*mi);
    }
    return ret;
}

std::vector<CTxMemPool::txiter> CTxMemPool::GetIterVec(const std::vector<uint256>& txids) const
{
    AssertLockHeld(cs);
    std::vector<txiter> ret;
    ret.reserve(txids.size());
    for (const auto& txid : txids) {
        const auto it{GetIter(txid)};
        if (!it) return {};
        ret.push_back(*it);
    }
    return ret;
}

bool CTxMemPool::HasNoInputsOf(const CTransaction &tx) const
{
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        if (exists(GenTxid::Txid(tx.vin[i].prevout.hash)))
            return false;
    return true;
}

CCoinsViewMemPool::CCoinsViewMemPool(CCoinsView* baseIn, const CTxMemPool& mempoolIn) : CCoinsViewBacked(baseIn), mempool(mempoolIn) { }

bool CCoinsViewMemPool::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    // Check to see if the inputs are made available by another tx in the package.
    // These Coins would not be available in the underlying CoinsView.
    if (auto it = m_temp_added.find(outpoint); it != m_temp_added.end()) {
        coin = it->second;
        return true;
    }

    // If an entry in the mempool exists, always return that one, as it's guaranteed to never
    // conflict with the underlying cache, and it cannot have pruned entries (as it contains full)
    // transactions. First checking the underlying cache risks returning a pruned entry instead.
    CTransactionRef ptx = mempool.get(outpoint.hash);
    if (ptx) {
        if (outpoint.n < ptx->vout.size()) {
            coin = Coin(ptx->vout[outpoint.n], MEMPOOL_HEIGHT, false);
            m_non_base_coins.emplace(outpoint);
            return true;
        } else {
            return false;
        }
    }
    return base->GetCoin(outpoint, coin);
}

void CCoinsViewMemPool::PackageAddTransaction(const CTransactionRef& tx)
{
    for (unsigned int n = 0; n < tx->vout.size(); ++n) {
        m_temp_added.emplace(COutPoint(tx->GetHash(), n), Coin(tx->vout[n], MEMPOOL_HEIGHT, false));
        m_non_base_coins.emplace(tx->GetHash(), n);
    }
}
void CCoinsViewMemPool::Reset()
{
    m_temp_added.clear();
    m_non_base_coins.clear();
}

size_t CTxMemPool::DynamicMemoryUsage() const {
    LOCK(cs);
    // Estimate the overhead of mapTx to be 9 pointers + an allocation, as no exact formula for boost::multi_index_contained is implemented.
    return memusage::MallocUsage(sizeof(CTxMemPoolEntry) + 9 * sizeof(void*)) * mapTx.size() + memusage::DynamicUsage(mapNextTx) + memusage::DynamicUsage(mapDeltas) + memusage::DynamicUsage(txns_randomized) + memusage::DynamicUsage(m_cluster_map) + cachedInnerUsage;
}

void CTxMemPool::RemoveUnbroadcastTx(const uint256& txid, const bool unchecked) {
    LOCK(cs);

    if (m_unbroadcast_txids.erase(txid))
    {
        LogPrint(BCLog::MEMPOOL, "Removed %i from set of unbroadcast txns%s\n", txid.GetHex(), (unchecked ? " before confirmation that txn was sent out" : ""));
    }
}

void CTxMemPool::RemoveStaged(setEntries &stage, bool updateDescendants, MemPoolRemovalReason reason) {
    AssertLockHeld(cs);

    // TODO: avoid going back and forth between maps and vectors
    std::vector<TxEntry::TxEntryRef> txs_to_remove;
    for (auto iter : stage) {
        txs_to_remove.push_back(*iter);
    }

    // Remove this group of transactions from the tx graph
    tx_graph.RemoveBatch(txs_to_remove);

    // Now remove them from the mempool
    for (txiter it : stage) {
        removeUnchecked(it, reason);
    }
}

int CTxMemPool::Expire(std::chrono::seconds time)
{
    AssertLockHeld(cs);
    indexed_transaction_set::index<entry_time>::type::iterator it = mapTx.get<entry_time>().begin();
    Entries toremove;
    while (it != mapTx.get<entry_time>().end() && it->GetTime() < time) {
        toremove.push_back(mapTx.project<0>(it));
        it++;
    }
    auto descendants = CalculateDescendants(toremove);

    setEntries stage;
    stage.insert(descendants.begin(), descendants.end());

    RemoveStaged(stage, false, MemPoolRemovalReason::EXPIRY);
    return stage.size();
}

void CTxMemPool::UpdateChild(txiter entry, txiter child, bool add)
{
    AssertLockHeld(cs);
    CTxMemPoolEntry::Children s;
    if (add && entry->GetMemPoolChildren().insert(*child).second) {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
    } else if (!add && entry->GetMemPoolChildren().erase(*child)) {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
    }
}

void CTxMemPool::UpdateParent(txiter entry, txiter parent, bool add)
{
    AssertLockHeld(cs);
    CTxMemPoolEntry::Parents s;
    if (add && entry->GetMemPoolParents().insert(*parent).second) {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
    } else if (!add && entry->GetMemPoolParents().erase(*parent)) {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
    }
}

CFeeRate CTxMemPool::GetMinFee(size_t sizelimit) const {
    LOCK(cs);
    if (!blockSinceLastRollingFeeBump || rollingMinimumFeeRate == 0)
        return CFeeRate(llround(rollingMinimumFeeRate));

    int64_t time = GetTime();
    if (time > lastRollingFeeUpdate + 10) {
        double halflife = ROLLING_FEE_HALFLIFE;
        if (DynamicMemoryUsage() < sizelimit / 4)
            halflife /= 4;
        else if (DynamicMemoryUsage() < sizelimit / 2)
            halflife /= 2;

        rollingMinimumFeeRate = rollingMinimumFeeRate / pow(2.0, (time - lastRollingFeeUpdate) / halflife);
        lastRollingFeeUpdate = time;

        if (rollingMinimumFeeRate < (double)m_incremental_relay_feerate.GetFeePerK() / 2) {
            rollingMinimumFeeRate = 0;
            return CFeeRate(0);
        }
    }
    return std::max(CFeeRate(llround(rollingMinimumFeeRate)), m_incremental_relay_feerate);
}

void CTxMemPool::trackPackageRemoved(const CFeeRate& rate) {
    AssertLockHeld(cs);
    if (rate.GetFeePerK() > rollingMinimumFeeRate) {
        rollingMinimumFeeRate = rate.GetFeePerK();
        blockSinceLastRollingFeeBump = false;
    }
}

void CTxMemPool::TrimToSize(size_t sizelimit, std::vector<COutPoint>* pvNoSpendsRemaining) {
    AssertLockHeld(cs);

    unsigned nTxnRemoved = 0;
    CFeeRate maxFeeRateRemoved(0);

    if (DynamicMemoryUsage() <= sizelimit) return;

    Trimmer tx_graph_trimmer(&tx_graph);

    while (!mapTx.empty() && DynamicMemoryUsage() > sizelimit) {
        std::vector<TxEntry::TxEntryRef> txs_to_remove;

        CFeeRate removed = tx_graph_trimmer.RemoveWorstChunk(txs_to_remove);

        // We set the new mempool min fee to the feerate of the removed set, plus the
        // "minimum reasonable fee rate" (ie some value under which we consider txn
        // to have 0 fee). This way, we don't allow txn to enter mempool with feerate
        // equal to txn which were removed with no block in between.
        removed += m_incremental_relay_feerate;
        trackPackageRemoved(removed);
        maxFeeRateRemoved = std::max(maxFeeRateRemoved, removed);

        nTxnRemoved += txs_to_remove.size();

        std::vector<CTransaction> txn;
        if (pvNoSpendsRemaining) {
            txn.reserve(worst_chunk.first->txs.size());
            for (auto tx_entry_ref : txs_to_remove)
                txn.push_back(tx_entry_ref.get().GetTx());
        }

        // Remove these transactions from the mempool.
        for (auto tx: txs_to_remove) {
            removeUnchecked(mapTx.iterator_to(dynamic_cast<CTxMemPoolEntry&>(tx.get()), MemPoolRemovalReason::SIZELIMIT);
        }

        if (pvNoSpendsRemaining) {
            for (const CTransaction& tx : txn) {
                for (const CTxIn& txin : tx.vin) {
                    if (exists(GenTxid::Txid(txin.prevout.hash))) continue;
                    pvNoSpendsRemaining->push_back(txin.prevout);
                }
            }
        }
    }

    if (maxFeeRateRemoved > CFeeRate(0)) {
        LogPrint(BCLog::MEMPOOL, "Removed %u txn, rolling minimum fee bumped to %s\n", nTxnRemoved, maxFeeRateRemoved.ToString());
    }
}

void CTxMemPool::CalculateAncestorData(const CTxMemPoolEntry& entry, size_t& ancestor_count, size_t& ancestor_size, CAmount& ancestor_fees) const
{
    ancestor_count = 1;
    ancestor_size = entry.GetTxSize();
    ancestor_fees = entry.GetModifiedFee();
    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> work_queue;

    WITH_FRESH_EPOCH(m_epoch);
    for (auto tx : entry.GetMemPoolParentsConst()) {
        work_queue.push_back(tx);
        visited(tx);
    }
    while (!work_queue.empty()) {
        auto next_entry = work_queue.back();
        work_queue.pop_back();
        ancestor_size += next_entry.get().GetTxSize();
        ++ancestor_count;
        ancestor_fees += next_entry.get().GetModifiedFee();
        for (auto tx : next_entry.get().GetMemPoolParentsConst()) {
            if (!visited(tx)) work_queue.push_back(tx);
        }
    }
}

void CTxMemPool::CalculateDescendantData(const CTxMemPoolEntry& entry, size_t& descendant_count, size_t& descendant_size, CAmount& descendant_fees) const
{
    descendant_count = 1;
    descendant_size = entry.GetTxSize();
    descendant_fees = entry.GetModifiedFee();
    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> work_queue;

    WITH_FRESH_EPOCH(m_epoch);
    for (auto tx : entry.GetMemPoolChildrenConst()) {
        work_queue.push_back(tx);
        visited(tx);
    }
    while (!work_queue.empty()) {
        auto next_entry = work_queue.back();
        work_queue.pop_back();
        descendant_size += next_entry.get().GetTxSize();
        ++descendant_count;
        descendant_fees += next_entry.get().GetModifiedFee();
        for (auto tx : next_entry.get().GetMemPoolChildrenConst()) {
            if (!visited(tx)) work_queue.push_back(tx);
        }
    }
}

void CTxMemPool::GetTransactionAncestry(const uint256& txid, size_t& ancestors, size_t& clustersize, size_t* const ancestorsize, CAmount* const ancestorfees) const {
    LOCK(cs);
    auto it = mapTx.find(txid);
    ancestors = clustersize = 0;
    if (it != mapTx.end()) {
        size_t dummysize{0};
        CAmount dummyfees{0};
        CalculateAncestorData(*it, ancestors, ancestorsize ? *ancestorsize :
                dummysize, ancestorfees ? *ancestorfees : dummyfees);
        clustersize = it->m_cluster->m_tx_count;
    }
}

bool CTxMemPool::GetLoadTried() const
{
    LOCK(cs);
    return m_load_tried;
}

void CTxMemPool::SetLoadTried(bool load_tried)
{
    LOCK(cs);
    m_load_tried = load_tried;
}

std::vector<CTxMemPool::txiter> CTxMemPool::GatherClusters(const std::vector<uint256>& txids) const
{
    AssertLockHeld(cs);
    std::vector<txiter> clustered_txs{GetIterVec(txids)};
    // Use epoch: visiting an entry means we have added it to the clustered_txs vector. It does not
    // necessarily mean the entry has been processed.
    WITH_FRESH_EPOCH(m_epoch);
    for (const auto& it : clustered_txs) {
        visited(it);
    }
    // i = index of where the list of entries to process starts
    for (size_t i{0}; i < clustered_txs.size(); ++i) {
        // DoS protection: if there are 500 or more entries to process, just quit.
        if (clustered_txs.size() > 500) return {};
        const txiter& tx_iter = clustered_txs.at(i);
        for (const auto& entries : {tx_iter->GetMemPoolParentsConst(), tx_iter->GetMemPoolChildrenConst()}) {
            for (const CTxMemPoolEntry& entry : entries) {
                const auto entry_it = mapTx.iterator_to(entry);
                if (!visited(entry_it)) {
                    clustered_txs.push_back(entry_it);
                }
            }
        }
    }
    return clustered_txs;
}
