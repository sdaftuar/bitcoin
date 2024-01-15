#ifndef TXGRAPH_H
#define TXGRAPH_H

class TxGraph;

class TxEntry {
public:
    // Some handle to the tx itself?
    TxGraph* graph;
    TxGraph::Location location_in_graph;
};

class CTxMemPoolEntry : public TxEntry {
    const CTransactionRef tx;
    Parents parents;
    Children children;
    CAmount fee; // unmodified fee
    uint64_t entry_sequence;
    int64_t nTime;
    bool spends_coinbase;
    int64_t sigOpCost;
    LockPoints lockPoints;
    size_t nUsageSize;
};

class ChangeSet {
public:
    ChangeSet(TxGraph*);
    // Register a transaction that would be removed from the graph as part of
    // this change.
    void RemoveTx(TxEntry *remove_tx);
    // Register a transaction that would be newly added to the graph as part of
    // this change.
    void AddTx(TxEntry *add_tx);

    // Check that the changeset is within the given cluster size limits.
    bool CheckLimits(Limits);

    // Construct feerate diagrams with and without this changeset being applied.
    std::vector<FeeFrac> GetOldFeerateDiagram();
    std::vector<FeeFrac> GetNewFeerateDiagram();

    friend class TxGraph;
};

class TxGraph {
public:
    TxGraph();

    // (lazily?) add a transaction to the graph (assume no in-mempool children?)
    void AddTx(TxEntry *new_tx, int32_t vsize, CAmount modified_fee, Parents parents);

    // Lazily remove a transaction from the graph
    void RemoveTx(TxEntry *remove_tx);

    // Remove a group of transactions from the graph (eg ConnectBlock)
    // Probably don't need this:
    // RemoveBatchTx(txs);

    // add a group of parent transactions, but limit resulting cluster sizes.
    void AddParentTxs(std::vector<TxEntry *> parent_txs, Limits limits, Fn children_finder, std::vector<TxEntry *> &txs_removed);

    // Evict the worst chunk from the mempool.
    // We need to do this iteratively, so lazy updating of state would be better.
    void RemoveWorstChunk(std::vector<TxEntry *> txs_removed, FeeFrac chunk_feerate_removed);

    // Get the memory in use by TxGraph
    size_t MemoryUsage();

    // Some methods for getting the chunks in decreasing-feerate-order
    GetChunkIterator(); // ?? not sure what this should be
    
    std::vector<TxEntry *> GetAncestors(TxEntry *tx);

    std::vector<TxEntry *> GetDescendants(TxEntry *tx);

    // Check cluster size limits for a given number of new transactions, with a
    // given total vsize, and a given set of parents whose clusters would all
    // be merged.
    bool CheckLimits(Parents parents, int32_t vsize, int32_t tx_count, Limits limits);
    // Probably don't need a separate function for packages?
    // CheckPackageLimits(potential_new_package, limits);

    // For RBF calculations.
    ChangeSet GetChangeSet();
    void ApplyChangeSet(ChangeSet& change_set);

    // Return true if a comes before b in mempool sort order
    bool CompareMiningScore(tx_a, tx_b);
};

#endif // TXGRAPH_H
