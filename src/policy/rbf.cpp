// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/rbf.h>

#include <consensus/amount.h>
#include <kernel/mempool_entry.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/rbf.h>

#include <limits>
#include <vector>

RBFTransactionState IsRBFOptIn(const CTransaction& tx, const CTxMemPool& pool)
{
    AssertLockHeld(pool.cs);

    // First check the transaction itself.
    if (SignalsOptInRBF(tx)) {
        return RBFTransactionState::REPLACEABLE_BIP125;
    }

    // If this transaction is not in our mempool, then we can't be sure
    // we will know about all its inputs.
    if (!pool.exists(GenTxid::Txid(tx.GetHash()))) {
        return RBFTransactionState::UNKNOWN;
    }

    // If all the inputs have nSequence >= maxint-1, it still might be
    // signaled for RBF if any unconfirmed parents have signaled.
    const auto& entry{*Assert(pool.GetEntry(tx.GetHash()))};
    auto ancestors{pool.CalculateMemPoolAncestors(entry, /*fSearchForParents=*/false)};

    for (auto& entry : ancestors) {
        if (SignalsOptInRBF(entry.get().GetTx())) {
            return RBFTransactionState::REPLACEABLE_BIP125;
        }
    }
    return RBFTransactionState::FINAL;
}

RBFTransactionState IsRBFOptInEmptyMempool(const CTransaction& tx)
{
    // If we don't have a local mempool we can only check the transaction itself.
    return SignalsOptInRBF(tx) ? RBFTransactionState::REPLACEABLE_BIP125 : RBFTransactionState::UNKNOWN;
}

std::optional<std::string> GetEntriesForConflicts(const CTransaction& tx,
                                                  CTxMemPool& pool,
                                                  const CTxMemPool::setEntries& iters_conflicting,
                                                  CTxMemPool::setEntries& all_conflicts)
{
    AssertLockHeld(pool.cs);
    const uint256 txid = tx.GetHash();

    if (iters_conflicting.size() > MAX_REPLACEMENT_CANDIDATES) {
        return strprintf("rejecting replacement %s; too many direct conflicts (%ud > %d)\n",
                txid.ToString(),
                iters_conflicting.size(),
                MAX_REPLACEMENT_CANDIDATES);
    }
    // Calculate the set of all transactions that would have to be evicted.
    for (CTxMemPool::txiter it : iters_conflicting) {
        // The cluster count limit ensures that we won't do too much work on a
        // single invocation of this function.
        pool.CalculateDescendantsSlow(it, all_conflicts);
    }
    return std::nullopt;
}

std::optional<std::string> EntriesAndTxidsDisjoint(const CTxMemPool::setEntries& ancestors,
                                                   const std::set<Txid>& direct_conflicts,
                                                   const uint256& txid)
{
    for (CTxMemPool::txiter ancestorIt : ancestors) {
        const Txid& hashAncestor = ancestorIt->GetTx().GetHash();
        if (direct_conflicts.count(hashAncestor)) {
            return strprintf("%s spends conflicting transaction %s",
                             txid.ToString(),
                             hashAncestor.ToString());
        }
    }
    return std::nullopt;
}

std::optional<std::string> PaysForRBF(CAmount original_fees,
                                      CAmount replacement_fees,
                                      size_t replacement_vsize,
                                      CFeeRate relay_fee,
                                      const uint256& txid)
{
    // Rule #2: The replacement fees must be greater than or equal to fees of the
    // transactions it replaces, otherwise the bandwidth used by those conflicting transactions
    // would not be paid for.
    if (replacement_fees < original_fees) {
        return strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
                         txid.ToString(), FormatMoney(replacement_fees), FormatMoney(original_fees));
    }

    // Rule #3: The new transaction must pay for its own bandwidth. Otherwise, we have a DoS
    // vector where attackers can cause a transaction to be replaced (and relayed) repeatedly by
    // increasing the fee by tiny amounts.
    CAmount additional_fees = replacement_fees - original_fees;
    if (additional_fees < relay_fee.GetFee(replacement_vsize)) {
        return strprintf("rejecting replacement %s, not enough additional fees to relay; %s < %s",
                         txid.ToString(),
                         FormatMoney(additional_fees),
                         FormatMoney(relay_fee.GetFee(replacement_vsize)));
    }
    return std::nullopt;
}

// Compare two feerate points, where one of the points is interpolated from
// existing points in a feerate diagram.
// Return 1 if the interpolated point is greater than fee_compare; 0 if they
// are equal; -1 otherwise.
int InterpolateValueAndCompare(int64_t eval_size, const FeeFrac& p1, const FeeFrac& p2, CAmount fee_compare)
{
    // Interpolate between two points using the formula:
    // y = y1 + (x - x1) * (y2 - y1) / (x2 - x1)
    // where x is eval_size, y is the interpolated fee, x1 and y1 are p1, and x2 and y2 are p2.
    // Then evaluating y > fee_compare is equivalent to checking if y*(x2-x1) > fee_compare*(x2-x1),
    // or y1*(x2-x1) + (x - x1) * (y2 - y1) > fee_compare*(x2-x1).
    int64_t fee_compare_scaled = fee_compare * (p2.size - p1.size); // 1100* 300
    int64_t y_scaled = p1.fee * (p2.size - p1.size) + (eval_size - p1.size) * (p2.fee - p1.fee);
    if (y_scaled > fee_compare_scaled) {
        return 1;
    } else if (y_scaled == fee_compare_scaled) {
        return 0;
    } else {
        return -1;
    }
}

// returns true if the new_diagram is strictly better than the old one; false
// otherwise.
bool CompareFeeSizeDiagram(std::vector<FeeFrac> old_diagram, std::vector<FeeFrac> new_diagram)
{
    size_t old_index=0;
    size_t new_index=0;

    // whether the new diagram has at least one point better than old_diagram
    bool new_better = false;

    // whether the old diagram has at least one point better than new_diagram
    bool old_better = false;

    // Start by padding the smaller diagram with a transaction that pays the
    // tail feerate up to the size of the larger diagram.
    // For now, use an implicit tail feerate of 0, but we can change this if
    // there's an argument to be made that the true tail feerate is higher.
    // Also, if we end up needing to transform the feerates (eg to avoid
    // negative numbers or overflow in the calculations?), then the tail
    // feerate would need to be transformed as well.
    if (old_diagram.back().size < new_diagram.back().size) {
        old_diagram.push_back({old_diagram.back().fee, new_diagram.back().size});
    } else if (old_diagram.back().size > new_diagram.back().size) {
        new_diagram.push_back({new_diagram.back().fee, old_diagram.back().size});
    }

    while (old_index < old_diagram.size() && new_index < new_diagram.size()) {
        int cmp = 0;
        if (old_diagram[old_index].size < new_diagram[new_index].size) {
            cmp = InterpolateValueAndCompare(old_diagram[old_index].size, new_diagram[new_index-1], new_diagram[new_index], old_diagram[old_index].fee);
            old_better |= (cmp == -1);
            new_better |= (cmp == 1);
            old_index++;
        } else if (old_diagram[old_index].size > new_diagram[new_index].size) {
            cmp = InterpolateValueAndCompare(new_diagram[new_index].size, old_diagram[old_index-1], old_diagram[old_index], new_diagram[new_index].fee);
            old_better |= (cmp == 1);
            new_better |= (cmp == -1);
            new_index++;
        } else {
            if (old_diagram[old_index].fee > new_diagram[new_index].fee) {
                old_better = true;
            } else if (old_diagram[old_index].fee < new_diagram[new_index].fee) {
                new_better = true;
            }
            old_index++;
            new_index++;
        }
    }

    if (new_better && !old_better) return true;

    return false;
}

static std::set<uint256> txids_of_interest;

std::optional<std::string> ImprovesFeerateDiagram(CTxMemPool& pool,
                                                const CTxMemPool::setEntries& direct_conflicts,
                                                const CTxMemPool::setEntries& all_conflicts,
                                                CTxMemPoolEntry& entry,
                                                CAmount modified_fee)
{

    if (txids_of_interest.size() == 0) {
        txids_of_interest.insert(uint256S("0312649c3c65e3698cdaf86a7800a1a49d7571a28e518ee01e28d320e88e8f24"));
        txids_of_interest.insert(uint256S("03f27f0e4aef77e12f72a54b041b0c277c8118ed16360d865814dbc160317c21"));
        txids_of_interest.insert(uint256S("086abf07e311f5ace303a6ea2554a6cb000c02c417da57902429a297e0acbe5b"));
        txids_of_interest.insert(uint256S("0a0df0bd2db6c0ded7e102ed18e4a1a87534a5c8b471a32517a3dff2e015b87e"));
        txids_of_interest.insert(uint256S("0c4447b0a5d44f7c1ca875026f10fe2b66eb6ed28e3d2688eb86df8ba022bbca"));
        txids_of_interest.insert(uint256S("0f4cc8dffdf1aabb5df7f646975bdffc4c051743a08ef11f95a1144a573892bf"));
        txids_of_interest.insert(uint256S("106480182f5754d8b77a8a93fd08d9d288314d976fc85c0d414bbc97a8e64863"));
        txids_of_interest.insert(uint256S("137ec013e17c8a27efb2965af6ad273cdf007cde6491e83ba315a096682843d9"));
        txids_of_interest.insert(uint256S("1678cca8ea346618924bfae67621a5c23dee2740a81b46c8e930cdf7b7f5ac71"));
        txids_of_interest.insert(uint256S("17d909683cb0b2a64efbfb649245851e3e1b50f7ee64783c625c66c393fa67e6"));
        txids_of_interest.insert(uint256S("271930212a8f4142b7fac89849a2ca64108468dbb5898da3f0dc47bcb86f99d1"));
        txids_of_interest.insert(uint256S("2a825db371442078ec5ce945854a8073f174c73ba8c9a791b5ed29ec8ae7559b"));
        txids_of_interest.insert(uint256S("2f0f1bb4719450dd121d68102d9d87a13b6169d33f281316b0b1678ac0ce5839"));
        txids_of_interest.insert(uint256S("37ee1111021ec27f69d9dd9de86cc307e84b4b214236682e9f2665def47dd068"));
        txids_of_interest.insert(uint256S("38afcb8d5aae2a66dfa8e6fd06864d888d7952f80953dfc190de773b42ac6a8f"));
        txids_of_interest.insert(uint256S("3c90c68d60cd582620a186a1e7d5cf16afa2076db4f7a4915a62c32a8284adf4"));
        txids_of_interest.insert(uint256S("4d71e33ee62c03f8cbbb46e077e76ae5eaaf2c36e772e71c909c9ac7a74bb8e9"));
        txids_of_interest.insert(uint256S("4e465f9a5681a03e39072dd10dceadaab0c7d563702add1862a918cce8c239d2"));
        txids_of_interest.insert(uint256S("4eb61b40457ba9f9eb51d8d2e6ac44e4f4020d98ff6167d440b603c9a34824dc"));
        txids_of_interest.insert(uint256S("56fbc2ba001539e96e31dc5c9408707dc53b318fc7b0111a96e32aca32f98b8b"));
        txids_of_interest.insert(uint256S("574454d2360fffdac79001e9a250a7c148a3e18cd57145f21ce8f9bb5e32e7a5"));
        txids_of_interest.insert(uint256S("5bf6c73efbcc642afba2e4a988ab020134daa5b9351c01f1612cdd0c9ab102c3"));
        txids_of_interest.insert(uint256S("67473fa99e6a46455f0d9a2706f5ff1aba9936dbd405d1470f0b92319d9e56cb"));
        txids_of_interest.insert(uint256S("67d166214b7ee1afea3c3bddc072470e42c042da5e0d7419547c8845f351b540"));
        txids_of_interest.insert(uint256S("7112c2335e1bc40934c985e55fb5d30ade194d8a20d2673a0ce1c8927b2c75ef"));
        txids_of_interest.insert(uint256S("7cdab0560a4a4f2351cb6fdd518ff7e0e1bd5abe3aa841388812f15eb23385a7"));
        txids_of_interest.insert(uint256S("7ef7fcd329bd07c7c679ae15587a88311f2102e88e9c232378d9d1d482583118"));
        txids_of_interest.insert(uint256S("8b62889d27890cbc67b81f48de0b3d3e95090af356370749bc7694ad3f9295a1"));
        txids_of_interest.insert(uint256S("8f2f9ed47aeaec929f8e1f573b0432182bafa3adc1e2939f71be38783a0d4039"));
        txids_of_interest.insert(uint256S("91754100c6049f9d3026bc3730b717e06c3d4a01169df92745d560a012bad23a"));
        txids_of_interest.insert(uint256S("9429a0f1cdc8ed96df429ba15a36ebca5bf7ce75fc28ef329ea065739b17820a"));
        txids_of_interest.insert(uint256S("972f84d97ea13c0cf35579a6db8c2173fb5b191686432c7ebd9725170f9596f9"));
        txids_of_interest.insert(uint256S("978393042bc74307ffc8b8183f0143c33433404ddee8c6e93bb571da96206a00"));
        txids_of_interest.insert(uint256S("980691ed3ab863f52ebfbf3a56344cce675118b74616f5b05edbeafd496f47f3"));
        txids_of_interest.insert(uint256S("a69461d888cecd7f42d22855db88d9c739abf6fc39e751496cdc07793afee899"));
        txids_of_interest.insert(uint256S("a8a77e3aef6eed05c8d5933ef6d03aeee5770d7e8356dd156b26e59baa639ef5"));
        txids_of_interest.insert(uint256S("ab362a1765c52dd811bc819925496fe80800b4b913fec0cbe5c0ac2e97146117"));
        txids_of_interest.insert(uint256S("afc6a6e9bdef775cf572adfe0fe86109dd764b2cdfa23d4f03fbef2a6cab36aa"));
        txids_of_interest.insert(uint256S("b6be1d42f21f9586b6929cc82d26d11eec0b03fee22ffa1e812c48425c198639"));
        txids_of_interest.insert(uint256S("c0b34161c75cb53af49ad5fee03f499840e2d06ce58df10925f1ce66ccb5f29a"));
        txids_of_interest.insert(uint256S("c0e37c043fb068f40584ce51f90389e5bb757f13f3a426ef3855d55ba78e89ac"));
        txids_of_interest.insert(uint256S("c1aafe1062b965692b97d3c2f53a4a96d97bced7b2be818b5d86067590a8bf3b"));
        txids_of_interest.insert(uint256S("ccf604e56956d56f6610ba8604ed45a4d9b26957da83f53982d302a514a003c8"));
        txids_of_interest.insert(uint256S("d90074ccc93f64482c4e68236aa8ae09f1e7deb7abbbc41f72cbaf9baa7b031c"));
        txids_of_interest.insert(uint256S("df88b1137d0d34a7f52147e6125a2878dacd73c06a0b4f83d96bb4ef8ba7429f"));
        txids_of_interest.insert(uint256S("e4042f22b91fa9a145e18d053896e31ef1697faccec1eff8f34d57432e8ee1ed"));
        txids_of_interest.insert(uint256S("e5c3ef434c3f7235f72a13e303412eeffab3c163575e397dd3495edbedb1cd08"));
        txids_of_interest.insert(uint256S("e77449ea80649457580e354dccfaf4b99e4aba1553a418aa972f061816bbad6e"));
        txids_of_interest.insert(uint256S("e83ce16dbef6db5fd4343caf69338f382ed08412cd099f76cf7889459f375a55"));
        txids_of_interest.insert(uint256S("e915d725450ff1b8d6248d29ac616b2a683a349faf0979f0446bcc0e82e2e59c"));
        txids_of_interest.insert(uint256S("e997f5579576a454e9b708a61f5a42f370c15f10e79926abaaf924e7a2333885"));
        txids_of_interest.insert(uint256S("ea3f94fb48532d373231a4aef7a9fd8637b35943eab679b288823083db892230"));
        txids_of_interest.insert(uint256S("f7d53d6b2c1d91cfc6a58760a474858613f862dd72c41164714329dfe67d6f16"));
        txids_of_interest.insert(uint256S("f811e2fe8357439ba4ca79feb8156ce7881e228731c168a45c8a1433e296d8fc"));
        txids_of_interest.insert(uint256S("fc2c4c8d1165b942e07da1623f79ab07facb13a2ec4e708d664bdea04e3604ba"));
        txids_of_interest.insert(uint256S("fe111038ccc103c1bdf6ee3fd6725551e5d8df992a5c95783ef59c24f14824cb"));
        txids_of_interest.insert(uint256S("fe71afc3c1cfce1743f9540b09ee931c58cb8790ddd54d756d82c399656f86e2"));
    }
    // Require that the replacement strictly improve the mempool's fee vs. size diagram.
    std::vector<FeeFrac> old_diagram, new_diagram;

    bool print{txids_of_interest.contains(entry.GetTx().GetHash())};
    if (!pool.CalculateFeerateDiagramsForRBF(entry, modified_fee, direct_conflicts, all_conflicts, old_diagram, new_diagram, print)) {
        return strprintf("rejecting replacement %s, cluster size limit exceeded", entry.GetTx().GetHash().ToString());
    }

    if (!CompareFeeSizeDiagram(old_diagram, new_diagram)) {
        if (txids_of_interest.contains(entry.GetTx().GetHash())) {
            LogPrintf("diagram info for evaluation of %s -- old diagram: ", entry.GetTx().GetHash().ToString());
            for (auto chunk : old_diagram) {
                LogPrintf("(%ld, %u), ", chunk.size, chunk.fee);
            }
            LogPrintf("new diagram: ");
            for (auto chunk : new_diagram) {
                LogPrintf("(%ld, %u), ", chunk.size, chunk.fee);
            }
            LogPrintf("\n");
        }
        return strprintf("rejecting replacement %s, mempool not strictly improved",
                         entry.GetTx().GetHash().ToString());
    }
    return std::nullopt;
}
