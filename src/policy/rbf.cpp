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
        txids_of_interest.insert(uint256S("000d4aaa70877a847847a22c3e345b00ed5f5730b55761ddd6de9595676eac39"));
        txids_of_interest.insert(uint256S("0bee730f119363532f3e3375972fac0f10b90fd258fb6f89a77fc5e7757f9b59"));
        txids_of_interest.insert(uint256S("0cc042a4fed2d512b19e3226f083ba93515b14404378f6ef24deb3d9fbd47d66"));
        txids_of_interest.insert(uint256S("15f2f97519bb7af6696c81f1b4d60658aa03db2ad3739b3506fa1cbecb333b4c"));
        txids_of_interest.insert(uint256S("1adde56e7a9e5c12ad70be2c21e4239239d0fa7c0c427cd0828a43c84a5a4a06"));
        txids_of_interest.insert(uint256S("1e9c8f093830b90c3d7239cea7c02f44c9f2b178d5ae3ac0d4d8c7fd7a672581"));
        txids_of_interest.insert(uint256S("26f36ec403ec051138445a3fd1bbffacd165d36aa4de86dec7bdba5773a6272f"));
        txids_of_interest.insert(uint256S("2712ff116917cc439b1e8ef224d721f4f17a8809420c037d10827fbcbecff365"));
        txids_of_interest.insert(uint256S("2bf200c924cbfc027c7c574467be373591dbb2957371c7c1a3282718f29811c6"));
        txids_of_interest.insert(uint256S("2fdced2ba8343fdb30ae28d5f15955c13f63fbbd4ddbb4f56a692734ac7f3405"));
        txids_of_interest.insert(uint256S("338d625897346d8deb2bbf6612ad8a909b742c15474344dc8f8c5f805a125507"));
        txids_of_interest.insert(uint256S("35f1bf203fa20e55beadfebc0f14f0e504bce4fcc898a86de3143d9fdd077636"));
        txids_of_interest.insert(uint256S("3ce2e8c76478cbf6da71991893cae510dfaa3ab7fd466764675808fa47641bff"));
        txids_of_interest.insert(uint256S("4137ec23cdd0b806f674e6c043d095948dad3210fcad3e72de66cd2cf3f1a66e"));
        txids_of_interest.insert(uint256S("43554e0888b7fbc4b72968715a8cff43893805e023be917fd3ce052219d049f1"));
        txids_of_interest.insert(uint256S("453cffb70e4edc8f4a570485f4257f807de913ae6b6071d96aad6003716d7edc"));
        txids_of_interest.insert(uint256S("49f5d1596e5c511a4b3663e60e35e9391b7e06c91b76601f87563f6fde60af62"));
        txids_of_interest.insert(uint256S("4dd4d607b59c5ba73e4d7d66d81aae7e9319454aa67f502a0dd99c781ab8d732"));
        txids_of_interest.insert(uint256S("518196e168e1d3d59a92e8a94e2511ee958a1ff7e497c59573148bc17e1854aa"));
        txids_of_interest.insert(uint256S("52c36b194c974ff770815a2d3aecf0efff12aec455c875f92d2ddf3161adfa3a"));
        txids_of_interest.insert(uint256S("56394a821d99b497e75acbc2e95ece51339b4719e1066fc6eac93e20358c279d"));
        txids_of_interest.insert(uint256S("5d85892766a60671a56dd5b650f79cb90eb1937cc2073e80fcc3c85a2f891d64"));
        txids_of_interest.insert(uint256S("6a09489e682a1d9397e50b513d4b1f7c4b788b5c42465a5dc5823bc519f0102f"));
        txids_of_interest.insert(uint256S("710bcc1f2530eababfba1c6286249d502a06e4b57c78a613f4d70b3fa8e196d6"));
        txids_of_interest.insert(uint256S("792e20353936ea1a9064978ae1bf8101024c6795085f56ec0f26ae9057fcbcc6"));
        txids_of_interest.insert(uint256S("7b8ecea9e06bc3d794a0588b67ddb4ea8d1f24791c4a965c0144c23fde71aff6"));
        txids_of_interest.insert(uint256S("7eb61b5eb068874f849ef053553f1f63f99cfc18ca0e403a4d0795685b3fa7d9"));
        txids_of_interest.insert(uint256S("83ad635645d3fd86b29184694803b35c4e0bbe61f664eadf9068ddb1ce942f01"));
        txids_of_interest.insert(uint256S("8c70802f9555d8d4290ceaf9d94ee5818dbe151b059e9224b5785ea1dbb163fc"));
        txids_of_interest.insert(uint256S("8df1985e2230f40b29991fad03a8be94f4573d9c4b828d22535e3084c60b6870"));
        txids_of_interest.insert(uint256S("96b0f1aed04a939b5a7d594b7a99104e93abd7ec323603499233613e3f0f9135"));
        txids_of_interest.insert(uint256S("9d08a3852f1769e698b52f6a98c8096b1bbe8fd3159bedbd161dfa77e713322b"));
        txids_of_interest.insert(uint256S("9df9a46ef661ab0a1f0aee26efe335ff90cabe3027982374a7cf6b7b65cb2204"));
        txids_of_interest.insert(uint256S("a0565bc68b79f72f480324a63e2f1bf26acd5ab6adcd94c31a60d035fb949512"));
        txids_of_interest.insert(uint256S("a6e5f6d19f3eecc24460a12167d17339556338545ec6d8cff62bcde04655b49a"));
        txids_of_interest.insert(uint256S("a9ebd4916d7d1eb9fc53049a377bac71c4d201ab814ca33ffbafd18a6cde9a3c"));
        txids_of_interest.insert(uint256S("aff4f97bc159982dd6b4a4b4ab28e7e0bbb6a105f3116a2f2120f82b2d12ddb5"));
        txids_of_interest.insert(uint256S("b26a736f22585f658691ca0aed30ce00d2fc4fa991cf2ccb47c6faa8fe74dd00"));
        txids_of_interest.insert(uint256S("b597e4b140ec4c8d7bc4da95b2ba05da29f0abe76bee518830eccf428d6aed56"));
        txids_of_interest.insert(uint256S("b7d19ad827d5018bb5b4bb960c9e6d025524f3217c4a24aed25f6377a03a05fe"));
        txids_of_interest.insert(uint256S("c3c11793e87f1cf235c98a15d2404f3498491e36ea0c84937a9b93f352d7fbea"));
        txids_of_interest.insert(uint256S("c704d69010c6a65aea6330f7a01ce2167f4fee71ee49598001c24f41180efdf5"));
        txids_of_interest.insert(uint256S("c7d395374821c434e0365faa02ea6b1c59b45c2764f7bc607eef2aac0af043a3"));
        txids_of_interest.insert(uint256S("cb2daffda6579b3cc440b832a58d632bf3572479f4eabc5396e8f2183eb13cc4"));
        txids_of_interest.insert(uint256S("ccf604e56956d56f6610ba8604ed45a4d9b26957da83f53982d302a514a003c8"));
        txids_of_interest.insert(uint256S("d3f5d18daa0db116a995ae095580832a1af08365a80d80cc4f6ac0121129cdcd"));
        txids_of_interest.insert(uint256S("da0f62c952ff93c71cb7e8bbd1e3ab3ce939c4874444cce274e0bbdef42b32dc"));
        txids_of_interest.insert(uint256S("dde6a2dc3a3e74cb7bb2172f4e8e933ece0771da3303c103363ef65795b93751"));
        txids_of_interest.insert(uint256S("dedf3a5a70a945a998ffb404f3619a10c7f82abc1b80c9b508e29a45f18529e5"));
        txids_of_interest.insert(uint256S("e0be55a9e1c71923c088294e0989f7a53b873442ddfcf5fdd5ad4826a19da507"));
        txids_of_interest.insert(uint256S("e0c46751502cc9d429ef03fcd591d024cdef6a328df2f32b9674e18412b2a048"));
        txids_of_interest.insert(uint256S("e9af1b0023eaa43225a371ae7a837a61bf3df75f07849e6b902be3b44b6e1a1d"));
        txids_of_interest.insert(uint256S("eb3e71dcaaf7c2893688bf0dbcddcc7ea50eb3b8f3ca9bc90eacc2ede724960f"));
        txids_of_interest.insert(uint256S("ec5e88da23e6fa81e156fc5b8f673120a8e8d31711ae52a7b8074a3342f596c1"));
        txids_of_interest.insert(uint256S("eccf833497aa2eb8e8d06e2556542ccafb7837eaa6b494fd9cc102f97cc25b72"));
        txids_of_interest.insert(uint256S("efd7bfb206ef57752483d348cffb5ce5e8b18fdc5133d101ae2705629c293ff3"));
        txids_of_interest.insert(uint256S("f37bf5c0ffad37af85693116847465dd8bd2897b05a2d77154033a5e440c65d4"));
        txids_of_interest.insert(uint256S("f696d224a3acc22f00965e7065eb49caa1710de204d3a4e7065a4a09766a0e29"));
        txids_of_interest.insert(uint256S("fa63ef5590efc74cfc0d0cf8d29ba455644938a6aa195b34f2c4bf2d4edd6dcd"));
        txids_of_interest.insert(uint256S("fad3d309f329a650ef78349cff27b7e9de0c9c2a17154e75adf3f55b19be2964"));
    }
    // Require that the replacement strictly improve the mempool's fee vs. size diagram.
    std::vector<FeeFrac> old_diagram, new_diagram;

    bool print{txids_of_interest.contains(entry.GetTx().GetHash())};
    if (!pool.CalculateFeerateDiagramsForRBF(entry, modified_fee, direct_conflicts, all_conflicts, old_diagram, new_diagram, print)) {
        return strprintf("rejecting replacement %s, cluster size limit exceeded", entry.GetTx().GetHash().ToString());
    }

    if (!CompareFeeSizeDiagram(old_diagram, new_diagram)) {
        if (txids_of_interest.contains(entry.GetTx().GetHash())) {
            LogPrintf("[manual] diagram info for evaluation of %s -- old diagram: ", entry.GetTx().GetHash().ToString());
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
