// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mini_miner.h>

#include <boost/multi_index/detail/hash_index_iterator.hpp>
#include <boost/operators.hpp>
#include <consensus/amount.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>

#include <algorithm>
#include <numeric>
#include <utility>

namespace node {
namespace FeeBumpCalculator {

// Return the set of transactions in the mempool that spend the given
// outpoints, along with their unconfirmed ancestors.
CTxMemPool::setEntries GetMempoolTxsForOutpoints(CTxMemPool& mempool, const std::vector<COutPoint>& outpoints, CTxMemPool::setEntries exclude)
{
    LOCK(mempool.cs);
    std::set<Txid> hashes;
    for (const auto& outpoint : outpoints) {
        hashes.insert(Txid::FromUint256(outpoint.hash));
    }
    CTxMemPool::setEntries txs_without_ancestors = mempool.GetIterSet(hashes);
    // We also need to include all ancestors of these transactions, as we'll be
    // interested in whether or not they get mined as well.
    CTxMemPool::setEntries ret = txs_without_ancestors;
    for (auto it : txs_without_ancestors) {
        if (!exclude.count(it)) {
            CTxMemPool::setEntries ancestors = mempool.CalculateMemPoolAncestors(*it, false);
            ret.insert(ancestors.begin(), ancestors.end());
        } else {
            ret.erase(it);
        }
    }
    return ret;
}

// Return the set of transactions in the mempool that spend the given outpoints.
CTxMemPool::setEntries CalculateToBeReplacedTransactions(CTxMemPool& pool, const std::vector<COutPoint>& outpoints)
{
    LOCK(pool.cs);
    CTxMemPool::setEntries ret;
    for (const auto& outpoint : outpoints) {
        if (const auto ptx{pool.GetConflictTx(outpoint)}) {
            // This outpoint is already being spent by another transaction in the mempool. We
            // assume that the caller wants to replace this transaction and its descendants. It
            // would be unusual for the transaction to have descendants as the wallet won’t normally
            // attempt to replace transactions with descendants. If the outpoint is from a mempool
            // transaction, we still need to calculate its ancestors bump fees (added to
            // m_requested_outpoints_by_txid below), but after removing the to-be-replaced entries.
            //
            // Note that the descendants of a transaction include the transaction itself. Also note,
            // that this is only calculating bump fees. RBF fee rules should be handled separately.
            CTxMemPool::Entries descendants = pool.CalculateDescendants({pool.GetIter(ptx->GetHash()).value()});
            ret.insert(descendants.begin(), descendants.end());
        }
    }
    return ret;
}

// Given a set of transactions of interest, return the subset whose mining
// score (based on the full mempool contents, excluding transactions that would
// be replaced) is at least as high as the target feerate.
CTxMemPool::setEntries WouldBeMined(CTxMemPool& pool, const CFeeRate& target, CTxMemPool::setEntries txs, CTxMemPool::setEntries to_be_replaced) EXCLUSIVE_LOCKS_REQUIRED(pool.cs)
{
    AssertLockHeld(pool.cs);
    CTxMemPool::setEntries mined;
    auto mining_scores = pool.GetMiningScores(txs, to_be_replaced);
    for (auto& it : txs) {
        FeeFrac feerate(mining_scores[it->GetTx().GetHash()]);
        if (feerate.fee >= target.GetFee(feerate.size)) {
            mined.insert(it);
        }
    }
    return mined;
}

// Given a set of outpoints of interest, calculate the fee bump that would be
// required to bring the transaction corresponding to that outpoint to the
// target feerate, including any unconfirmed ancestors whose mining score
// (exclusive of transactions that would be replaced) is at or above the target
// feerate already. Return the result in a map from outpoints->fee bump.
std::map<COutPoint, CAmount> CalculateBumpFees(CTxMemPool& mempool, const std::vector<COutPoint>& outpoints, const CFeeRate& target_feerate)
{
    LOCK(mempool.cs);
    auto to_be_replaced = CalculateToBeReplacedTransactions(mempool, outpoints);
    auto all_transactions = GetMempoolTxsForOutpoints(mempool, outpoints, to_be_replaced);
    auto would_be_mined = WouldBeMined(mempool, target_feerate, all_transactions, to_be_replaced);

    std::map<Txid, CAmount> txid_bump_fees;

    for (auto it : all_transactions) {
        if (would_be_mined.count(it)) {
            txid_bump_fees.insert({it->GetTx().GetHash(), 0});
        } else {
            // Calculate the in-mempool ancestors of this transaction.
            CTxMemPool::setEntries ancestors = mempool.CalculateMemPoolAncestors(*it, false);
            ancestors.insert(it);
            FeeFrac ancestor_feerate;
            for (auto anc : ancestors) {
                if (!would_be_mined.count(anc)) {
                    ancestor_feerate += FeeFrac(anc->GetModifiedFee(), anc->GetTxSize());
                }
            }
            CAmount fee1 = target_feerate.GetFee(ancestor_feerate.size) - ancestor_feerate.fee;
            CAmount fee2 = target_feerate.GetFee(it->GetTxSize()) - it->GetModifiedFee();
            txid_bump_fees.insert({it->GetTx().GetHash(), std::max(fee1, fee2)});
        }
    }

    std::map<COutPoint, CAmount> ret;
    // Now we need to map the bump fees to the requested outpoints.
    for (const auto& outpoint : outpoints) {
        auto txid = Txid::FromUint256(outpoint.hash);
        if (auto it = txid_bump_fees.find(txid); it != txid_bump_fees.end()) {
            ret.insert({outpoint, it->second});
        } else {
            ret.insert({outpoint, 0});
        }
    }
    return ret;
}

// Calculate the total fee bump required to bring all transactions
// corresponding to the given outpoints up to the target feerate, including the
// full (possibly shared) ancestry, but excluding ancestors which already have
// mining scores at or above the target feerate.
CAmount CalculateTotalBumpFees(CTxMemPool& mempool, const std::vector<COutPoint>& outpoints, const CFeeRate& target_feerate)
{
    LOCK(mempool.cs);
    auto to_be_replaced = CalculateToBeReplacedTransactions(mempool, outpoints);
    auto all_transactions = GetMempoolTxsForOutpoints(mempool, outpoints, to_be_replaced);
    auto would_be_mined = WouldBeMined(mempool, target_feerate, all_transactions, to_be_replaced);
    CTxMemPool::setEntries all_ancestors;
    for (auto it : all_transactions) {
        CTxMemPool::setEntries ancestors = mempool.CalculateMemPoolAncestors(*it, false);
        ancestors.insert(it);
        for (auto& a: ancestors) {
            if (!would_be_mined.count(a)) {
                all_ancestors.insert(a);
            }
        }
    }
    FeeFrac ancestor_feerate;
    for (auto &ancestor : all_ancestors) {
        ancestor_feerate += FeeFrac(ancestor->GetModifiedFee(), ancestor->GetTxSize());
    }
    return target_feerate.GetFee(ancestor_feerate.size) - ancestor_feerate.fee;
}
} // namespace FeeBumpCalculator
} // namespace node
