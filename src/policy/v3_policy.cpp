// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/v3_policy.h>

#include <coins.h>
#include <consensus/amount.h>
#include <logging.h>
#include <tinyformat.h>
#include <util/check.h>

#include <algorithm>
#include <numeric>
#include <vector>

void FindInPackageParents(const PackageWithAncestorCounts& package_with_ancestors, const CTransactionRef& ptx, std::vector<int>& in_package_parents)
{
    std::set<Txid> possible_parents;
    for (auto &input : ptx->vin) {
        possible_parents.insert(input.prevout.hash);
    }

    for (size_t i=0; i<package_with_ancestors.package.size(); ++i) {
        const auto& tx = package_with_ancestors.package[i];
        // We assume the package is sorted, so that we don't need to continue
        // looking past the transaction itself.
        if (&(*tx) == &(*ptx)) break;
        if (possible_parents.count(tx->GetHash())) {
            in_package_parents.push_back(i);
        }
    }
}

bool PackageV3Checks(const CTransactionRef& ptx, int64_t vsize,
        const PackageWithAncestorCounts& package_with_ancestors,
        const CTxMemPool::setEntries& mempool_ancestors,
        CTxMemPool& pool)
{
    std::vector<int> in_package_parents;

    FindInPackageParents(package_with_ancestors, ptx, in_package_parents);

    // Now we have all ancestors, so we can start checking v3 rules.
    if (ptx->nVersion == 3) {
        // v3 transactions can have at most 1 unconfirmed parent
        if (mempool_ancestors.size() + in_package_parents.size() > 1) return false;

        bool has_parent = (mempool_ancestors.size() + in_package_parents.size() > 0);

        if (has_parent) {
            // Find the parent and extract the information we need for v3
            // checks.
            int parent_version = 0;
            Txid parent_hash = Txid::FromUint256(uint256(0));
            int other_descendants=0;

            if (mempool_ancestors.size() > 0) {
                // There's a parent in the mempool.
                auto &parent = *mempool_ancestors.begin();
                parent_version = parent->GetTx().nVersion;
                other_descendants = parent->GetCountWithDescendants()-1;
                parent_hash = parent->GetTx().GetHash();
            } else { // it must be in the package
                auto &parent_index = in_package_parents[0];
                // If the in-package parent has mempool ancestors, then this is
                // a v3 violation.
                if (package_with_ancestors.ancestor_counts[parent_index] > 0) return false;

                auto &parent = package_with_ancestors.package[parent_index];
                parent_version = parent->nVersion;
                other_descendants=0;
                parent_hash = parent->GetHash();
            }

            // If there's a parent, it must have the right version.
            if (parent_version != 3) return false;

            // If there's a parent, it cannot have any other in-mempool children.
            if (other_descendants > 0) return false;

            // If there's a parent, then neither the parent nor this tx can
            // have an in-package child.
            for (const auto& tx : package_with_ancestors.package) {
                if (&(*tx) == &(*ptx)) continue;
                for (auto& input : tx->vin) {
                    if (input.prevout.hash == parent_hash) return false;
                    if (input.prevout.hash == ptx->GetHash()) return false;
                }
            }

            // If there's a parent, this transaction cannot be too large.
            if (vsize > V3_CHILD_MAX_VSIZE) {
                return false;
            }
        }
    } else {
        // Non-v3 transactions cannot have v3 parents.
        for (auto it : mempool_ancestors) {
            if (it->GetTx().nVersion == 3) return false;
        }
        for (const auto& index: in_package_parents) {
            if (package_with_ancestors.package[index]->nVersion == 3) return false;
        }
    }
    return true;
}

#if 0
util::Result<std::map<Txid, std::set<Txid>>> PackageV3Checks(const Package& package)
{
    // Map from txid of a v3 transaction to its ancestor set, including itself.
    // Since we enforce v3 inheritance rules as we build this set, sets should consist exclusively
    // of v3 transactions.
    std::map<Txid, std::set<Txid>> v3_ancestor_sets;
    // Map from txid of a v3 transaction to its descendant set, including itself.
    std::map<Txid, std::set<Txid>> v3_descendant_sets;

    // This should only be called for v3 packages.
    if (!Assume(std::any_of(package.cbegin(), package.cend(), [](const auto& tx){ return tx->nVersion == 3; }))) {
        return v3_ancestor_sets;
    }

    // Build a map from txid to wtxid for quick lookup; we'll use the wtxid for error strings.
    // Map from txid to wtxid for v3 txns in the package.
    std::unordered_map<Txid, Wtxid, SaltedTxidHasher> v3_txid_to_wtxid;
    // Map from txid to wtxid for non-v3 txns in the package.
    std::unordered_map<Txid, Wtxid, SaltedTxidHasher> non_v3_txid_to_wtxid;
    // Populate these maps.
    for (const auto& tx : package) {
        if (tx->nVersion == 3) {
            // Transactions should have unique txids. If duplicate txids exist, this function
            // will still detect violations, but it will return the earlier transaction's wtxid.
            Assume(v3_txid_to_wtxid.emplace(tx->GetHash(), tx->GetWitnessHash()).second);
            // Ancestor and descendant sets are inclusive of oneself.
            std::set<Txid> txid_self{tx->GetHash()};
            Assume(v3_ancestor_sets.emplace(tx->GetHash(), txid_self).second);
            Assume(v3_descendant_sets.emplace(tx->GetHash(), txid_self).second);
        } else {
            Assume(non_v3_txid_to_wtxid.emplace(tx->GetHash(), tx->GetWitnessHash()).second);
        }
    }

    // For each tx, look for in-package parents. Ancestor sets are built in one pass, which means
    // the package must be sorted beforehand.
    Assume(IsTopoSortedPackage(package));
    for (const auto& tx : package) {
        const Txid& my_txid{tx->GetHash()};
        if (tx->nVersion == 3) {
            auto& my_ancestor_set = v3_ancestor_sets.at(my_txid);
            for (const auto& input : tx->vin) {
                const Txid& parent_txid = input.prevout.hash;
                // Look for a non-v3 in-package parent
                if (auto it_nonv3_package_parent = non_v3_txid_to_wtxid.find(parent_txid); it_nonv3_package_parent != non_v3_txid_to_wtxid.end()) {
                    return util::Error{Untranslated(strprintf("v3 tx %s cannot spend from non-v3 tx %s",
                        tx->GetWitnessHash().ToString(), it_nonv3_package_parent->second.ToString()))};
                }

                // Look for a v3 in-package parent. The ancestor set cannot exceed V3_ANCESTOR_LIMIT.
                if (auto it_v3_package_parent = v3_txid_to_wtxid.find(parent_txid); it_v3_package_parent != v3_txid_to_wtxid.end()) {
                    Assume(my_ancestor_set.size() >= 1);
                    // Skip if we've already processed this parent, i.e. because we spend multiple outputs from this tx.
                    if (my_ancestor_set.count(parent_txid) == 0) {
                        // My parent's ancestors are also my ancestors.
                        const auto& parent_ancestor_set = v3_ancestor_sets.at(parent_txid);
                        Assume(parent_ancestor_set.size() >= 1);
                        my_ancestor_set.insert(parent_ancestor_set.cbegin(), parent_ancestor_set.cend());

                        // Check that we do not have too many ancestors.
                        if (my_ancestor_set.size() > V3_ANCESTOR_LIMIT) {
                            return util::Error{Untranslated(strprintf("tx %s would have too many ancestors", tx->GetWitnessHash().ToString()))};
                        }

                        // A v3 transaction with unconfirmed ancestors must be within
                        // V3_CHILD_MAX_VSIZE. This check is not complete as we have not calculated
                        // the sigop cost, which can increase the virtual size.
                        const int64_t vsize = GetVirtualTransactionSize(*tx, /*nSigOpCost=*/0, /*bytes_per_sigop=*/0);
                        if (vsize > V3_CHILD_MAX_VSIZE) {
                            return util::Error{Untranslated(strprintf("v3 child tx %s is too big: %u > %u virtual bytes",
                                tx->GetWitnessHash().ToString(), vsize, V3_CHILD_MAX_VSIZE))};
                        }
                    }
                }
            }
        } else {
            for (const auto& input : tx->vin) {
                if (auto it = v3_txid_to_wtxid.find(input.prevout.hash); it != v3_txid_to_wtxid.end()) {
                    return util::Error{Untranslated(strprintf("non-v3 tx %s cannot spend from v3 tx %s",
                                                              tx->GetWitnessHash().ToString(), it->second.ToString()))};
                }
            }
        }
    }

    // Find violations of descendant limits. When a package is sorted, it's most efficient to build
    // descendant sets by iterating in reverse order.
    for (auto tx_iter = package.rbegin(); tx_iter != package.rend(); ++tx_iter) {
        const auto& curr_txid{(*tx_iter)->GetHash()};
        if ((*tx_iter)->nVersion == 3) {
            const auto& my_ancestor_set = v3_ancestor_sets.at(curr_txid);
            const auto& my_descendant_set = v3_descendant_sets.at(curr_txid);
            Assume(my_ancestor_set.size() >= 1);
            Assume(my_descendant_set.size() >= 1);

            for (const auto& ancestor_txid : my_ancestor_set) {
                // My descendants are also my ancestor's descendants.
                auto& ancestors_descendant_set = v3_descendant_sets.at(ancestor_txid);

                // Skip if we have already been processed.
                if (ancestors_descendant_set.count(curr_txid) == 0) {
                    ancestors_descendant_set.insert(my_descendant_set.cbegin(), my_descendant_set.cend());
                }

                // This is the earliest we can check for descendant limit violations.
                if (ancestors_descendant_set.size() > V3_DESCENDANT_LIMIT) {
                    // Look up the wtxid of this ancestor.
                    const Wtxid& ancestor_wtxid = v3_txid_to_wtxid.at(ancestor_txid);
                    return util::Error{Untranslated(strprintf("tx %u would exceed descendant count limit", ancestor_wtxid.ToString()))};
                }
            }
        }
    }

    return v3_ancestor_sets;
}
#endif

std::optional<std::string> ApplyV3Rules(const CTransactionRef& ptx,
                                        const CTxMemPool::setEntries& mempool_ancestors,
                                        const std::set<Txid>& direct_conflicts,
                                        int64_t vsize)
{
    // Check v3 and non-v3 inheritance.
    for (const auto& entry : mempool_ancestors) {
        if (ptx->nVersion != 3 && entry->GetTx().nVersion == 3) {
            return strprintf("non-v3 tx %s cannot spend from v3 tx %s",
                             ptx->GetWitnessHash().ToString(), entry->GetSharedTx()->GetWitnessHash().ToString());
        } else if (ptx->nVersion == 3 && entry->GetTx().nVersion != 3) {
            return strprintf("v3 tx %s cannot spend from non-v3 tx %s",
                             ptx->GetWitnessHash().ToString(), entry->GetSharedTx()->GetWitnessHash().ToString());
        }
    }

    // This function is specialized for these limits, and must be reimplemented if they ever change.
    static_assert(V3_ANCESTOR_LIMIT == 2);
    static_assert(V3_DESCENDANT_LIMIT == 2);

    // The rest of the rules only apply to transactions with nVersion=3.
    if (ptx->nVersion != 3) return std::nullopt;

    // Check that V3_ANCESTOR_LIMIT would not be violated, including both in-package and in-mempool.
    if (mempool_ancestors.size() + 1 > V3_ANCESTOR_LIMIT) {
        return strprintf("tx %s would have too many ancestors", ptx->GetWitnessHash().ToString());
    }

    // Remaining checks only pertain to transactions with unconfirmed ancestors.
    if (mempool_ancestors.size() > 0) {
        // If this transaction spends V3 parents, it cannot be too large.
        if (vsize > V3_CHILD_MAX_VSIZE) {
            return strprintf("v3 child tx %s is too big: %u > %u virtual bytes", ptx->GetWitnessHash().ToString(), vsize, V3_CHILD_MAX_VSIZE);
        }

        // Check the descendant counts of in-mempool ancestors.
        if (!mempool_ancestors.empty()) {
            const auto& parent_entry = *mempool_ancestors.begin();
            // If there are any ancestors, this is the only child allowed. The parent cannot have any
            // other descendants.
            const auto& children = parent_entry->GetMemPoolChildrenConst();
            // Don't double-count a transaction that is going to be replaced. This logic assumes that
            // any descendant of the V3 transaction is a direct child, which makes sense because a V3
            // transaction can only have 1 descendant.
            const bool child_will_be_replaced = !children.empty() &&
                std::any_of(children.cbegin(), children.cend(),
                    [&direct_conflicts](const CTxMemPoolEntry& child){return direct_conflicts.count(child.GetTx().GetHash()) > 0;});
            if (parent_entry->GetCountWithDescendants() + 1 > V3_DESCENDANT_LIMIT && !child_will_be_replaced) {
                return strprintf("tx %u would exceed descendant count limit", parent_entry->GetSharedTx()->GetWitnessHash().ToString());
            }
        }
    }
    return std::nullopt;
}
