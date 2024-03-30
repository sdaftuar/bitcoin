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
        txids_of_interest.insert(uint256S("023f9cbe2223432810ca046afa05b3c161e228f9ef2d6ed9a700cf0dd95adaf6"));
        txids_of_interest.insert(uint256S("02af4477809c4743b97bc8450fc9074ceb61d7e5560e8a39e2246c8b72704834"));
        txids_of_interest.insert(uint256S("046277906dc1ff9c9d143f10030c4010935fe46cf000a2d7b1b50157cb3bec7b"));
        txids_of_interest.insert(uint256S("047727419c7589062deddca7b175334d384b30582404a1bd7c1ed4e1c6412e9d"));
        txids_of_interest.insert(uint256S("0485af481a4ba679d7b7b3a4d34cb4e28a3304be9edfdeeaf41f6b5766fd0d2f"));
        txids_of_interest.insert(uint256S("04f63edd32538a3b196aa409bda8f3e0cc1f7ff6feec194835b2a8ded9b6c378"));
        txids_of_interest.insert(uint256S("0568db2637c66f6376aefff7bfd1797ff80d2df1f60e82aecf4065ecf30b4f72"));
        txids_of_interest.insert(uint256S("05a0a714c4083560c9f8b450df6250ce3c263a1ee46f391480e7a72e8cef4131"));
        txids_of_interest.insert(uint256S("0672448eeedb3a9489a45fa19e9326d43d80e5adb24aaa7ca6b62ccdf6a39ff5"));
        txids_of_interest.insert(uint256S("0722723830782bf3f177e4497a019f5d14e1b605b8622017eedbefed12bd2a28"));
        txids_of_interest.insert(uint256S("074d6909adaf01b9df838efe363695adbadf1b28917f1851888b6c3a1a62d8e2"));
        txids_of_interest.insert(uint256S("07b98807e86db626f4808adebafc8200ed9cbdf77ae41b6070b5a58814397b04"));
        txids_of_interest.insert(uint256S("083046b4ff8f3bd37967e226c964df00cc07a5c3a908410870fc1768084a4f76"));
        txids_of_interest.insert(uint256S("093624c359151668edd10c8f7383a916321840695df18e3240e5d045f2724da0"));
        txids_of_interest.insert(uint256S("098f08ec167a22179bf75010d2e0db43ae60f895e75bc90deb2862d86821ddca"));
        txids_of_interest.insert(uint256S("09d56bb84b4b6632b45999f00898566d98e1398e6eee618841995da863d96ad3"));
        txids_of_interest.insert(uint256S("0a1c00fe91bd7861d4ef711050eb677c6d3375f9818e9f436015d3b87c3d9c05"));
        txids_of_interest.insert(uint256S("0bee730f119363532f3e3375972fac0f10b90fd258fb6f89a77fc5e7757f9b59"));
        txids_of_interest.insert(uint256S("0cc042a4fed2d512b19e3226f083ba93515b14404378f6ef24deb3d9fbd47d66"));
        txids_of_interest.insert(uint256S("0dcc9e35abd4fc5244e2bdec1ae56e65b0ad479ace7d98a11d3ea4ed9d3d6cb3"));
        txids_of_interest.insert(uint256S("0e124483c7e3fe617c675d0b1b9bc3dd0c788feb6a832d9d5125908e6572adf7"));
        txids_of_interest.insert(uint256S("0ff7df6758d22076d107399345ef33c13de154a848769c148910947067784e1c"));
        txids_of_interest.insert(uint256S("10b0320aacf84c5e5aac603b69ce01d3d788cfda90404ef934ecb312df6e36d6"));
        txids_of_interest.insert(uint256S("10c281a54e0d62fec36c0781383c8ed9873e5d4def5e9b72e84eecf7acaa4b83"));
        txids_of_interest.insert(uint256S("10ef77af9f82c5ea86e0d0087c312cfb7ad849f767a1f0c1ea9880c7254933ae"));
        txids_of_interest.insert(uint256S("1109607a21d847f1bea49f4add5b398ab63c68214ad60bca4d06765e36186d04"));
        txids_of_interest.insert(uint256S("115ddb43b89c7d45886ceb30b053375b23faf77dd0c70a77a109e133dd6a6de1"));
        txids_of_interest.insert(uint256S("11655362c47429d1397072d03c032b64b087c1754277306cfef30bf08da0d766"));
        txids_of_interest.insert(uint256S("13e52e28d732431bce8536e02349587bb9001cf02ec9b2de16aca613f95cd5e4"));
        txids_of_interest.insert(uint256S("1463ebbdb2f71e2e986441641a4da8b76e57ed2383e01baa28f8ed938e760253"));
        txids_of_interest.insert(uint256S("155293e1acd73fb9bf532e6a5a3337d2f3469a8a21a81f605c24202b832edf1e"));
        txids_of_interest.insert(uint256S("15c70e865a5c606e902ceecd3252a51634e1be9134b805b1dd5e045ea2dfd1bb"));
        txids_of_interest.insert(uint256S("15f2f97519bb7af6696c81f1b4d60658aa03db2ad3739b3506fa1cbecb333b4c"));
        txids_of_interest.insert(uint256S("19f8a42e97078ce3f6a73c5f93f335f1330a3b038c68ee608f8e0e81c476c8ab"));
        txids_of_interest.insert(uint256S("1adde56e7a9e5c12ad70be2c21e4239239d0fa7c0c427cd0828a43c84a5a4a06"));
        txids_of_interest.insert(uint256S("1c52032c2cce98b4cdd1e09623ff81e457d574840dd8436a46f5d016fdadbb66"));
        txids_of_interest.insert(uint256S("1c6150229c264f535bdeb9d5db55034a2625d68cdd61e927881af32a20d903cf"));
        txids_of_interest.insert(uint256S("1d9aa372777c95f2997d9317503722daad5f093b2c389b02c8c2cc0eeaa11b02"));
        txids_of_interest.insert(uint256S("1e0655b79427afef3ed60219c44c77c10e6ed050262a39afeb091e798c16655c"));
        txids_of_interest.insert(uint256S("1e9c8f093830b90c3d7239cea7c02f44c9f2b178d5ae3ac0d4d8c7fd7a672581"));
        txids_of_interest.insert(uint256S("1f24abfaf71b7ab14892f4c1226e401b7eae469457db0b292e29da62f1abf9d4"));
        txids_of_interest.insert(uint256S("205077642ac2e5926db793189a1e0a4c545b42d67b30a9d1c250e0fa1f415549"));
        txids_of_interest.insert(uint256S("2257704475b62acaf2b29869c0a8eafbf5c34f096694967047b4be5465bf7037"));
        txids_of_interest.insert(uint256S("235eb07de5f46415bbb7c0139381c4af60aff365f2c7c0ecd40e8aecf562b9e1"));
        txids_of_interest.insert(uint256S("2377f0c050d83e6f3ef8c88a2c49c8d74a0e07a78b07428000ba315952d07d10"));
        txids_of_interest.insert(uint256S("23bddd0bf464905f97d86e11a173cf73def1a5f9ce74fb05e09f6c44051f468d"));
        txids_of_interest.insert(uint256S("23c69085de9225022d812f1b43a35766b946d25efba919e13e0b640433af2bd7"));
        txids_of_interest.insert(uint256S("25d5cc01a5e1dec7ec9739de41779aee6d209d4424244fe99ba9a36e4ecd6e84"));
        txids_of_interest.insert(uint256S("26f36ec403ec051138445a3fd1bbffacd165d36aa4de86dec7bdba5773a6272f"));
        txids_of_interest.insert(uint256S("2712ff116917cc439b1e8ef224d721f4f17a8809420c037d10827fbcbecff365"));
        txids_of_interest.insert(uint256S("272cd973ca11fb1b11148378e80653dea8eff652da6b97dfbfa8f99565c12ba0"));
        txids_of_interest.insert(uint256S("2752a57654246727e04f09743a947cac1e2d302aa27df816b66f55e279a49708"));
        txids_of_interest.insert(uint256S("292b9dff735181fd3f84e969ca33a9b4faccbd2e544f0af8291c66cd9b495da9"));
        txids_of_interest.insert(uint256S("2a774178b8eda1af3258532d5e27463a175e92faea56beb8747e56709d2ec5fe"));
        txids_of_interest.insert(uint256S("2a78b0581ebbecc82f9d00384785589990263ce10deea99293845c0bf492866b"));
        txids_of_interest.insert(uint256S("2b312d449e056396de72b2d9c13839e934bc84679052819233aa3e9a7704184e"));
        txids_of_interest.insert(uint256S("2bf200c924cbfc027c7c574467be373591dbb2957371c7c1a3282718f29811c6"));
        txids_of_interest.insert(uint256S("2c1fd6af43e7f40e912f281b94603b15541008dbe2b3a3505ee7cfd5de19a246"));
        txids_of_interest.insert(uint256S("2c7d1dd80bbf4f32851705d302d59ffe2f61c0b9f4a1222252d0bd3272eb2684"));
        txids_of_interest.insert(uint256S("2d9eadec28dd81919670fc64ac6057d06a6905029dfce4122931fa6bee3f1d9d"));
        txids_of_interest.insert(uint256S("2dfbe5cbf8bc5d6a9cfc26d25f5e69093175f9661ec5edf84769d6fd78f87fd1"));
        txids_of_interest.insert(uint256S("2e48b7c6ab7155c5e561a1ee0f515f1f6d1c20fbf46f936604c89b1e834348c2"));
        txids_of_interest.insert(uint256S("2fa9f2e2fb7f842bf9f294a2635c6fa31576561996089b6450fb44e496abbfd4"));
        txids_of_interest.insert(uint256S("2fdced2ba8343fdb30ae28d5f15955c13f63fbbd4ddbb4f56a692734ac7f3405"));
        txids_of_interest.insert(uint256S("32be6865ebad937290677080f898ee7c78b4bacbe95e7f1c2f48233a1ca7ba19"));
        txids_of_interest.insert(uint256S("333649d2156e75ee92416dd014b2fc8c9a5f25456196e8a35827727aa33e030e"));
        txids_of_interest.insert(uint256S("33496343a051bbc8fc6babdc7eeb5ba3041209a0f0a806b4d4e732e26df1a9b4"));
        txids_of_interest.insert(uint256S("33721442834b5831a32732b73d0cf864b43db84cb98cb46591a7cbc94341809c"));
        txids_of_interest.insert(uint256S("338d625897346d8deb2bbf6612ad8a909b742c15474344dc8f8c5f805a125507"));
        txids_of_interest.insert(uint256S("3436a5374203f41a0dd45dcd5c38a7497bc3b9a08fa8c9ba1250836457f47ea8"));
        txids_of_interest.insert(uint256S("3588b2876efa704751a0f3805fdb201c5e64b9bd024bf0fd1ae923aa0e6f6f82"));
        txids_of_interest.insert(uint256S("35ba5e2d10b962685917c14520fdcd6c288a94585cd20a4e9b349f7903fafdda"));
        txids_of_interest.insert(uint256S("35eae30748956fee73a6bf47b78010d97c5e4c07cf92bbe4f50d36722688cd55"));
        txids_of_interest.insert(uint256S("35f1aeeaaf77e2ca01d30b7235f905b534a15bfd12fd75a8c314b8fa7aaea17e"));
        txids_of_interest.insert(uint256S("35f1bf203fa20e55beadfebc0f14f0e504bce4fcc898a86de3143d9fdd077636"));
        txids_of_interest.insert(uint256S("35f89bbd9bed29a02c36dd4806fa6a22dbc414f9680999ad2970b83db7e7a1ed"));
        txids_of_interest.insert(uint256S("3682fa6c034494448bf103d1d8b543032c4cfbc38f91564cb3720a5e56a15fba"));
        txids_of_interest.insert(uint256S("36b2868dfa26c60976c9c0514554c2032d898b6b7fe504326d4b173cff0719c4"));
        txids_of_interest.insert(uint256S("3870ce5fefae702d71e84731854d67a910d5ab0353aa046e12b31bccb74f2557"));
        txids_of_interest.insert(uint256S("3a917975fb0f44b7a7dcf7c05d37a996bce78df0947be83081c78fd0505f2b5f"));
        txids_of_interest.insert(uint256S("3c24fd6cdf66a8668e2918b1c81dba666254bd8377f977015cb127773ea12d62"));
        txids_of_interest.insert(uint256S("3c61e541ea6c129b83de34c11e9a932246c8bd9a0cb27fb6f168e963f45b1130"));
        txids_of_interest.insert(uint256S("3ce2e8c76478cbf6da71991893cae510dfaa3ab7fd466764675808fa47641bff"));
        txids_of_interest.insert(uint256S("3db211fdee17aa171d6cedac6c6236f0e1b2adc191e1fd02fc34c0f669bef6bc"));
        txids_of_interest.insert(uint256S("3dedeeb58d1589c4aa3645b9f7fd059524f00401ec5c0f395252a28e4948a577"));
        txids_of_interest.insert(uint256S("3e48b91bf8e1acca141e67ecde4f5202644d3b5b9a5fabf79e572ac949809059"));
        txids_of_interest.insert(uint256S("3ed19b5b5eac91304087e08376d14a5074debf595238f3939fdb455be2e3a61e"));
        txids_of_interest.insert(uint256S("3f6b467b7d54efb2eb966d68f57529c26a87f8c62c83d5d3f1a9f598879bb8b2"));
        txids_of_interest.insert(uint256S("4023385d5791d56389c08b1545b43ad52c0342cd9419fa424c94de08d66cdc20"));
        txids_of_interest.insert(uint256S("40e126e0cf4674bc68a6cd6a21abbcbc2d65c49095bbe59ce22b272e5e087dc5"));
        txids_of_interest.insert(uint256S("4137ec23cdd0b806f674e6c043d095948dad3210fcad3e72de66cd2cf3f1a66e"));
        txids_of_interest.insert(uint256S("413d86620d6f07ff2e714e2b1d2ef9be84b35dd1ca1dac9ba0805a0012f07013"));
        txids_of_interest.insert(uint256S("4166dce43171e60d9ef1661ce0d076073ee3035afb2b9a9cdfa6c3321b61dd69"));
        txids_of_interest.insert(uint256S("428df54c2679dc76b30e8228860d2e2b630b6b44c0f39c787f19032d61b7cf64"));
        txids_of_interest.insert(uint256S("429fb6ec3dfcc607a37effe2c65fc499f61e16c0a9199b9bffb94b9eb2d11364"));
        txids_of_interest.insert(uint256S("4417bb4bc2ae94bf059b48dd07550e8daee6642e45a599c671a9021e5034a020"));
        txids_of_interest.insert(uint256S("453cffb70e4edc8f4a570485f4257f807de913ae6b6071d96aad6003716d7edc"));
        txids_of_interest.insert(uint256S("454f352bbf7b45be2f663f5f224cca3b2ba3e0b1a05d05a43d45dbd065ce9e70"));
        txids_of_interest.insert(uint256S("461b1f32bab102d2b962e8e3819eaa6c4fc126cce96edf50d7e127a69d449c1e"));
        txids_of_interest.insert(uint256S("470402afc673f19dd892ad09fd8e78977eea41d4a1bd302e7d08dd30af4f2370"));
        txids_of_interest.insert(uint256S("47700f86d08b5592a0e57c32014234ffdb0e2ab2cbfc2b5804a1dd6e944f4644"));
        txids_of_interest.insert(uint256S("478a91891186c572f0d26a51b007e9868973d96cb9ec0c4b0e7c5f13aa7b14e1"));
        txids_of_interest.insert(uint256S("47c73cf2d417f2fd7e4f40809664a29212c52103ee90ff16aef2bdbaa0a0c0b4"));
        txids_of_interest.insert(uint256S("48477f47af5ce081d0d1d1768447f9e8c31bbd78a3d7b374a7c3290678cf41a5"));
        txids_of_interest.insert(uint256S("48de6c00a6be02d2f4addff5e3b1a458cd3557f4b67513dc632d14b1e61b4240"));
        txids_of_interest.insert(uint256S("49f5d1596e5c511a4b3663e60e35e9391b7e06c91b76601f87563f6fde60af62"));
        txids_of_interest.insert(uint256S("4bf30ac2e7625f9926558a371b1c82517599e83e6e33e495987f1079e06f9d2e"));
        txids_of_interest.insert(uint256S("4cd924c1ded12d502af42f0b45eb33046dc7b0ebecccab812e5407ed5a896904"));
        txids_of_interest.insert(uint256S("4d9f24533c443bca72cf61e8b863394484abd2ef0a0f95025cdd3ac94197cab4"));
        txids_of_interest.insert(uint256S("4dd4d607b59c5ba73e4d7d66d81aae7e9319454aa67f502a0dd99c781ab8d732"));
        txids_of_interest.insert(uint256S("4e146460f833ae43692739111e56d2bff8e00c5fe92988824d40f241927aab0b"));
        txids_of_interest.insert(uint256S("4ebfbfb5e5ddd0b5292eb4ab02ae377a88f6e146851062a9cc17535d1f54d5d9"));
        txids_of_interest.insert(uint256S("4f7ecbf803d3055271ad2a4d4d399852625b1771adacd2ae4e306defc507ef2a"));
        txids_of_interest.insert(uint256S("508d3eb083431623b36435e57990d2057ade0f146dcc2549bd005afe13f5188b"));
        txids_of_interest.insert(uint256S("50b45ecceefdd5cbffc74d8773ae31145cfa36ba0e61b9537983b128de766be3"));
        txids_of_interest.insert(uint256S("50d77fd42edc49474c1d5d42affe1e7da31dd5f5a2ad63cb173aa3661f48186a"));
        txids_of_interest.insert(uint256S("50e00ad4fdad841b4d806c1295282ca04c782e47f84e3587d0bc2f7d3c5b1ea1"));
        txids_of_interest.insert(uint256S("517a00855c2e0af2aa65b33453635df04d9ec63a7b3f8c8e2f033337ebcac2dd"));
        txids_of_interest.insert(uint256S("518196e168e1d3d59a92e8a94e2511ee958a1ff7e497c59573148bc17e1854aa"));
        txids_of_interest.insert(uint256S("52134fd9ec69a9bd5ccec1a551d6da7ba73abbfd4d48c9521b17d8ab7838ab7e"));
        txids_of_interest.insert(uint256S("52c36b194c974ff770815a2d3aecf0efff12aec455c875f92d2ddf3161adfa3a"));
        txids_of_interest.insert(uint256S("53fb1d262d150640b7845a69140f66980a890f1971c223a3adedd5a86ea0596c"));
        txids_of_interest.insert(uint256S("549cb31f87f84a2f28e6ad5e4b1ae78a397efd9986179a7a7592e18a3dabe377"));
        txids_of_interest.insert(uint256S("54c41aaa3b8f61bdf46747ddcb274e36ae3345d87d324d282a20714ef8e21cbd"));
        txids_of_interest.insert(uint256S("56394a821d99b497e75acbc2e95ece51339b4719e1066fc6eac93e20358c279d"));
        txids_of_interest.insert(uint256S("563efefd9d0a9a4d59337a6547bf9c57e4898ce6d242483c63309d70fc345dba"));
        txids_of_interest.insert(uint256S("5685618efbf0feb3176a9e2cfdbdabcc79820dd57fc2a8cb51243a39fceb60b1"));
        txids_of_interest.insert(uint256S("58a8410ecd24cf73d7dc1aea0f578eec4807fb5ec35b8e3096671a0df64b9f75"));
        txids_of_interest.insert(uint256S("58f3bc248f0949250edeb5e07684fd7f37c6ae7da8ef9a66a63dd1d5e25f8aae"));
        txids_of_interest.insert(uint256S("59943ebe53aa191fd10416ee9ef15974551048349a3317dbc5f0004ac23450b2"));
        txids_of_interest.insert(uint256S("59ca5d1ec8a071abed6d040d119160346eac9fae5b845b0af5b888cf8a6aea79"));
        txids_of_interest.insert(uint256S("5a2bebbac7a0e0f4ca2701cf1d78be8979304498f0047990e2a77e72caf071a2"));
        txids_of_interest.insert(uint256S("5acce60ce31cc9856500d86e77d4645c83981505afb01610082991f15caccefa"));
        txids_of_interest.insert(uint256S("5b23aaf0bc221d2614090e3473d705889d411dfaa061065672004b55dc5825d2"));
        txids_of_interest.insert(uint256S("5c895148cb3094def0080d0ee58506f4de25aba06df03b844428de7b5c397606"));
        txids_of_interest.insert(uint256S("5ca02da4a55a0ab9d9c5581617885f3b34051ab9634a73f6217d4f0f04c0a4da"));
        txids_of_interest.insert(uint256S("5ca535fbf383fd05e980dae0b9c39afbd2e760bb20cf179f7a67ddf978081342"));
        txids_of_interest.insert(uint256S("5cdba98296bc454c4d4e27929c20d6c0f585c65e1f0331d10203da4653a84c73"));
        txids_of_interest.insert(uint256S("5d85892766a60671a56dd5b650f79cb90eb1937cc2073e80fcc3c85a2f891d64"));
        txids_of_interest.insert(uint256S("5dd5b72dd2a50a0a1d000079ac0e78dede457215af79cc7b823980b309cc6254"));
        txids_of_interest.insert(uint256S("5ec08c3ee76cfd2bd874daf519eb543d9def03d743e0244853c60d7dc76e425f"));
        txids_of_interest.insert(uint256S("61333a05060bb53fde043d4aa80e502b9a7786f7dbe44c8aeafa0da0539f707c"));
        txids_of_interest.insert(uint256S("6137b418f293b88ea877f7796fb6e2852cf1bfbde21b03d729886f1f4f8a80f7"));
        txids_of_interest.insert(uint256S("621d77778bd863379229dddf369bc53c21323db64434d3a5f7a8df80cf4ef06c"));
        txids_of_interest.insert(uint256S("64403bde53d9622b567ce84527122eb9bf0062b4b56c2aeb35c620431cffb735"));
        txids_of_interest.insert(uint256S("67c31fb4e581fb76e1207ece838ba61f7e4eaae260a4a5801131ebf5e635a573"));
        txids_of_interest.insert(uint256S("6a0213b980eaad043348db45bfa3c0a5e67cf76bfa43cacdddcd5d1da40ecd11"));
        txids_of_interest.insert(uint256S("6a09489e682a1d9397e50b513d4b1f7c4b788b5c42465a5dc5823bc519f0102f"));
        txids_of_interest.insert(uint256S("6a33187a7dd08d6b43143b955fd3e20b4f75d5fb6471a1e03067121f1e88395a"));
        txids_of_interest.insert(uint256S("6ab2f65ff73d58d0f57c9ad9ad12a810e32a826454dcf0e5ce0a746409b35b46"));
        txids_of_interest.insert(uint256S("6af7e1705957e1183a3df74667f8a6df8a04cf51e084f4cc2b0c5ae31ab8146e"));
        txids_of_interest.insert(uint256S("6b5a540bf4c805dc6b31640bed5df32e2c2d10cdcd5898c25fc9e204ff29150d"));
        txids_of_interest.insert(uint256S("6d0ae900a92fe3dd678284871fed9d3dd18118f488f516a2c1a9e32ee2774472"));
        txids_of_interest.insert(uint256S("6d9165fd224fe7c4e8470e9dcbd5d36c81c8e47138fa5484d55dff1cca4bc2e5"));
        txids_of_interest.insert(uint256S("6e28661b39c3ef8e411f4bf0c53a78349cd5fa7c8014cd64990b78a37746262b"));
        txids_of_interest.insert(uint256S("6e811de9708368f7f2fa594604a2f70187f6fdaf2e43b6913e064b8a54c1dcab"));
        txids_of_interest.insert(uint256S("6f79584ce74840f2162fc73a4c40bf75e493d1d3a9be8f1b209ba9392767f9ed"));
        txids_of_interest.insert(uint256S("70dfddafba435854311d4864d504fa5c9f9c0fbfbf17dd0bb5785642024948e1"));
        txids_of_interest.insert(uint256S("710bcc1f2530eababfba1c6286249d502a06e4b57c78a613f4d70b3fa8e196d6"));
        txids_of_interest.insert(uint256S("7208ab94bc51c31ec503b32a1d343a56f6530144e6e07a66533c30e37e7b4f00"));
        txids_of_interest.insert(uint256S("73d65a15d6e28f9371f9ba617be104849dd49e136a8373296600ff7577dcdff3"));
        txids_of_interest.insert(uint256S("7413329b37e6db9a43a6f363759b7baab5425b29198f1e17d4b6a58864cf7066"));
        txids_of_interest.insert(uint256S("75176bc646049aa0917b55fe3b3351009b326df62868f4988c99f19fd3f777cc"));
        txids_of_interest.insert(uint256S("760141bb25f6e8dd5b3c361c5d3a1565cfecf7c0d019dfb42a64973fbd650d28"));
        txids_of_interest.insert(uint256S("792056f31563e185fccc2157410afe583652b982e9d27fb9eddab2325c361a53"));
        txids_of_interest.insert(uint256S("792e20353936ea1a9064978ae1bf8101024c6795085f56ec0f26ae9057fcbcc6"));
        txids_of_interest.insert(uint256S("79c46b7948a17a57c521bf9bb5a2bb96a30c0e94cbbbdeca512d1c14a9452c71"));
        txids_of_interest.insert(uint256S("79fc71b09f6e1186918ac2dbae40206d1e1765c5c7eba22cd105e62fbcd32b8e"));
        txids_of_interest.insert(uint256S("7a5b6dbc7111f8d33436e7d9985dcc6f89fd970066e203b4f76380818b0b6eb7"));
        txids_of_interest.insert(uint256S("7a65798d90a9f3f5aac817adf7ed09b9fb1ff465714a8a3b3943bb0fadc02429"));
        txids_of_interest.insert(uint256S("7b8ecea9e06bc3d794a0588b67ddb4ea8d1f24791c4a965c0144c23fde71aff6"));
        txids_of_interest.insert(uint256S("7c4eaa5254a3a1438992092d9587c95863005d66768cb0d729979854843b80c4"));
        txids_of_interest.insert(uint256S("7c5f7949fcb339d701902c28db7095d604728f002bdf7a4faeaf76b838b4db40"));
        txids_of_interest.insert(uint256S("7cba2ca70b2ba9f11ea825836f41ed3a1ef54f57638aac0fd70ad803f822125b"));
        txids_of_interest.insert(uint256S("7d8e4cee464562ef0ee65a8fac5002f59b7903dc1819a3fae6d048889ba8092d"));
        txids_of_interest.insert(uint256S("7d98178402113f36cc99b791670e0dbc81c62b68511f1214cdedb54cad789896"));
        txids_of_interest.insert(uint256S("7d984de8c7392cf4658acf99d52ba9c4519d5bf58539f2a21e3c6214e1d8e6a1"));
        txids_of_interest.insert(uint256S("7eb61b5eb068874f849ef053553f1f63f99cfc18ca0e403a4d0795685b3fa7d9"));
        txids_of_interest.insert(uint256S("7f308e6e8dde45a14432a2b7730dcd79edcaf1da5789a1d11e3a757762a6388d"));
        txids_of_interest.insert(uint256S("7faa6880decd6f29e07c2ddafe9841aba0ee2dc7426fbe1f8076c9c15e789391"));
        txids_of_interest.insert(uint256S("8192b0b16f3163800f18aa942870173923fc3b7b4feee199edabe2a3258b5822"));
        txids_of_interest.insert(uint256S("82690a322186d991c2c327df67fc6921fc21ddd2facdd9f67feca2cb3ab7fb6a"));
        txids_of_interest.insert(uint256S("8295f2bfd054c23103db009bfa57019e70f1a2d56445be2d671a57a5ed8ae620"));
        txids_of_interest.insert(uint256S("830922b114ba71c3266e24ea9844651b1442535c7ce32073a4431d350b1b7d68"));
        txids_of_interest.insert(uint256S("83366e9d1dfc0f3830289428e95443205afc4d7bee4e19a0d9b6f1f54669eae6"));
        txids_of_interest.insert(uint256S("8385d7716488db90fd736b82115beb23cc9154052664828af3f049d4d59c509f"));
        txids_of_interest.insert(uint256S("83ad635645d3fd86b29184694803b35c4e0bbe61f664eadf9068ddb1ce942f01"));
        txids_of_interest.insert(uint256S("8476eefd72260402ec10b5b1b8efe88d6e43faa4ce144326ec5f17e82166d2d5"));
        txids_of_interest.insert(uint256S("862463001a9199822516c85bbcdfccbd2c70b82c60b79342bec911914286f5c7"));
        txids_of_interest.insert(uint256S("88aab773ad4ef162c326c96bec14cc4fc942140d4a98d36f8b7e5beae8323a63"));
        txids_of_interest.insert(uint256S("88c9b3c80f7cbe267ca762325cdc60bf53874a3a5bb98ffe608dfe4dbddcc90a"));
        txids_of_interest.insert(uint256S("88ec9b80f22769c933f4b1982b4b4e029417db992fdf70067c76a783da4abb48"));
        txids_of_interest.insert(uint256S("8accaa7d2c87b9a3747d95814a02cd34dfd8ede3918254347647a472785049a2"));
        txids_of_interest.insert(uint256S("8b789803db37a10bfe914666702ad4e13a6e2db28d49fa62433b43c4e0484229"));
        txids_of_interest.insert(uint256S("8b9d2d6b31bf8fd869e3ea60fd9025eb563b036cfa72004a10c7c8c19df9b391"));
        txids_of_interest.insert(uint256S("8c70802f9555d8d4290ceaf9d94ee5818dbe151b059e9224b5785ea1dbb163fc"));
        txids_of_interest.insert(uint256S("8d1eb18854d4419c30f21f44b96693beb5bdb7ce002b4cc68065cfcd66d633fe"));
        txids_of_interest.insert(uint256S("8d634f3cdaa8e2efd3886ba014648cb88379abe9abdeca34e6e01219e6763d9f"));
        txids_of_interest.insert(uint256S("8d9a091e1238c24c5b1269b76c7328e266be3ad0e6a6009392c0f9cb6021fa7b"));
        txids_of_interest.insert(uint256S("8df1985e2230f40b29991fad03a8be94f4573d9c4b828d22535e3084c60b6870"));
        txids_of_interest.insert(uint256S("8e6215dbdc2101c644ee44f353f7901044194ffcc10a2514148244cbb0513c43"));
        txids_of_interest.insert(uint256S("8e621e61986ff1633d5d2250d3350d62baf2a78b27a84678e587766808afc26f"));
        txids_of_interest.insert(uint256S("8f7824734d9e8b19a8f07605c675b825a4f6d5c228c79f2e3d1bbddac79eeaa7"));
        txids_of_interest.insert(uint256S("8fe6311ed7c32d10ba78b6da174fb83ef5e3d8ef741ab6f8a3f7aa74e9d87597"));
        txids_of_interest.insert(uint256S("90bab39262eb08f0e54aba1431f8a7e4baacd64eab801730de0e7b60fec6f926"));
        txids_of_interest.insert(uint256S("911ec7ae8ce2654b05b1a0d3f25df9e47ce866a5a852bb2babb8de275e29b6d2"));
        txids_of_interest.insert(uint256S("93483aa4bf7039c902c996ece38ff1e0c7673aa42ba3ab769e494b27f0569cf7"));
        txids_of_interest.insert(uint256S("93691ca683af7ac86e4498d5bbb1a62492fe91cedf49f9e630cdfd0b630dd4d9"));
        txids_of_interest.insert(uint256S("9392ff4234bf42ddedff78da6544a73644fb9d0b8540028017bc106725334795"));
        txids_of_interest.insert(uint256S("93b5a083e792f11aa000eb00e7d9b24d379cc035c8737565ef2584028a82c925"));
        txids_of_interest.insert(uint256S("93bc38750f51d0f712ff912919ab3f1b50ea126c0bc4ed8f4fb780a4b3479c58"));
        txids_of_interest.insert(uint256S("95a2bdc68468bfa32a6cd5df924bd8859ac2c10f03d6e78a4e74d4185644871c"));
        txids_of_interest.insert(uint256S("95bba3e1533e61e15c678078c4f7cdc1ce2968b0d42cd5590fc151e72df11eef"));
        txids_of_interest.insert(uint256S("96b0f1aed04a939b5a7d594b7a99104e93abd7ec323603499233613e3f0f9135"));
        txids_of_interest.insert(uint256S("96bfcab7927ff2bd645e9274effd8adac45eefe8ec99c55eee5ce92fb4be2cc2"));
        txids_of_interest.insert(uint256S("9722234c0f2b9abc4216bc5d0904a5bed16fc27b4cdf8d1c1100378e4dbea835"));
        txids_of_interest.insert(uint256S("979e67c4a0ad32c71f643f7baf5fab00d0a79faa24bd8e80601182d2ab4ce17e"));
        txids_of_interest.insert(uint256S("98129978efcb21a69f5975caa5517022b8d9dcaec922d79e218db954894b64c7"));
        txids_of_interest.insert(uint256S("985d98e0d63e7455461ba127be124984be75302e5be4c9fc87a2f6264077c359"));
        txids_of_interest.insert(uint256S("99ae4229c23d4f51bb090637c75add27b0ecf20519049bafd4bd6b1cf95d4264"));
        txids_of_interest.insert(uint256S("99e8ff33263c3cf683d97ba65e9a9b90a8316ee7cad54c6cb3c6b4f10258aade"));
        txids_of_interest.insert(uint256S("9a4064519fe76840ae79ebab2403dcfbb493d0f86fe2626fdcfa7f663a354e32"));
        txids_of_interest.insert(uint256S("9a94609f4ad60b58105e87d0172fbdf7bac1d721841a14fccc93e2d030a65c79"));
        txids_of_interest.insert(uint256S("9b4becd466d1b7e7f2506654a0c6f83c192bbd067d5f56df3827305194fc0b51"));
        txids_of_interest.insert(uint256S("9bd9072b4df46bbea7844eea119c505e1179c5ee74c38eb918383db1995ed52a"));
        txids_of_interest.insert(uint256S("9bd91729f318f00883870f23e0ef506b6f78dc514112d8e83ae21b2584d55cb6"));
        txids_of_interest.insert(uint256S("9c15de747d557227c8ec1658427cc63d7e1e4ca07442b1c51cedbeb138bfc298"));
        txids_of_interest.insert(uint256S("9d08a3852f1769e698b52f6a98c8096b1bbe8fd3159bedbd161dfa77e713322b"));
        txids_of_interest.insert(uint256S("9d2dba6860a6adafdb56841a23be864b3edc287d1e3d423c83ddfc9ba3c5945b"));
        txids_of_interest.insert(uint256S("9d3b518b0d65463f3cccf9a3a114b22adad9ddb105006a9c8d9383f2e2c6ec00"));
        txids_of_interest.insert(uint256S("9dafaed0a4eb5d307f12ec094858da44e915e0aa12e6e56869d085a3f17c790b"));
        txids_of_interest.insert(uint256S("9dca14ef780e238231039830bfb2e595c7cee7dfaefe9418f6aab69147866071"));
        txids_of_interest.insert(uint256S("9df9a46ef661ab0a1f0aee26efe335ff90cabe3027982374a7cf6b7b65cb2204"));
        txids_of_interest.insert(uint256S("9e3d13b3f852f83cc6e29261853dd8358a67b295fa2d295ecb73aa5275cc857b"));
        txids_of_interest.insert(uint256S("9e45d689e4ab25371ca2d48243bf597c15307eaad6dc684bf204480b6e07eb16"));
        txids_of_interest.insert(uint256S("9e746c1a13c1148fcc3c7410d26987601eac9fe46e56ee5d59e1136cceb6e941"));
        txids_of_interest.insert(uint256S("9f2017f83e9fba6b0372f0072d7729ae3abd3de8dbd7f504dcb9320decfe53d3"));
        txids_of_interest.insert(uint256S("9f311da5d963095282bd9e88a66860d29d3953b6cd78f82b41e1485dc5a84ae3"));
        txids_of_interest.insert(uint256S("a02baeb704b07af30253f3379f8aa4268b9ff3f054a5f363dc18fecf13adb249"));
        txids_of_interest.insert(uint256S("a032d48df8dc2a3d4907b255ab7ded9c1774cbb3dd74b87ab05366a2d7841c9b"));
        txids_of_interest.insert(uint256S("a04c193bbea86282944fd5c23c1371aea67373eb2e799b9f9de5c0a4fc9818db"));
        txids_of_interest.insert(uint256S("a0565bc68b79f72f480324a63e2f1bf26acd5ab6adcd94c31a60d035fb949512"));
        txids_of_interest.insert(uint256S("a17456f94d596b985b12f20cfebaa0745975da1c48e6f888f8e7d6709c95dcc8"));
        txids_of_interest.insert(uint256S("a28075fb51eeec8e106ec8910c9bd2db7f92ee4407b6d9785752443ba4a30d05"));
        txids_of_interest.insert(uint256S("a288ae4e81f45fe775c6832d977ecdd4c2f5d12592a2fea4c3a5858dccfa1b3e"));
        txids_of_interest.insert(uint256S("a2b0dc70307ff0405f155c3cf449cc9f38014950d01ab6592b0e385e31b65a58"));
        txids_of_interest.insert(uint256S("a2f9ea01119e170b276630f64f0d4717fb30e89c22097959bd97c254a02b3537"));
        txids_of_interest.insert(uint256S("a30238109a36e2ae00acbc37aa61645a7bdd75ff589052e2759795bca5d19239"));
        txids_of_interest.insert(uint256S("a357936a8296f251a02509ec24156a82c091f5667b9c859bd01c15b1cf2e0180"));
        txids_of_interest.insert(uint256S("a3ecb89cc97e45fe9083b00b843c87b451e438a07f5804f4377364baaa639c2f"));
        txids_of_interest.insert(uint256S("a45e2868ad8c0671e9a0fad36cf0f14b0edc1bf22cf6a9bc53530241b64d78bd"));
        txids_of_interest.insert(uint256S("a4e89deb52cc34070e804b93d665f94f4736d781ba058ee9761cc8e8c8e7430f"));
        txids_of_interest.insert(uint256S("a60d1d1eed37d89762e069484f19bc30ff2cea8b50e4ef2387181d34f68ced05"));
        txids_of_interest.insert(uint256S("a6add12bca1521862b6cd1be1d399ac6acf0b15b9b89faaddcf962a831e87b6c"));
        txids_of_interest.insert(uint256S("a6e5f6d19f3eecc24460a12167d17339556338545ec6d8cff62bcde04655b49a"));
        txids_of_interest.insert(uint256S("a7a29d5b39bc9b1654e5aeca89db7a2d6d0318e6816aa1bbf17b7adcb8e61017"));
        txids_of_interest.insert(uint256S("a870224e0da98c255ba23929b3f1d4102b19d67b6f9b30a9a07a2b5a0d28a0ee"));
        txids_of_interest.insert(uint256S("a8a1b4b84330ee393ed60944f73842baffb87416743f3f7850b3f5e823ceeb1c"));
        txids_of_interest.insert(uint256S("a91304d9ff1c2a3e226bb73d0d34bd8b0d5ea5abe86a8477cd36b7fa8b8c332a"));
        txids_of_interest.insert(uint256S("a941b7e7a367c03aa721192307f75cbd5026d6b2a9c8bcf8c1e2c9d931e48dd9"));
        txids_of_interest.insert(uint256S("a9ebd4916d7d1eb9fc53049a377bac71c4d201ab814ca33ffbafd18a6cde9a3c"));
        txids_of_interest.insert(uint256S("acb1f4e8de343ce2640cb53882cbab4077e44b8c721cbb6f0583319437894408"));
        txids_of_interest.insert(uint256S("acdc579528a520bfbae251156c7143fd49b85f51c2c175a2075cf8b52ba832d6"));
        txids_of_interest.insert(uint256S("ad27f7737aa65ebb4ddf7c95e5650c0a2f473ede3f5ee2820492a05408353d73"));
        txids_of_interest.insert(uint256S("ae13c3b202cef2bcf43f06ee76d444908e9e18124a56915e21e8dc36c96009b2"));
        txids_of_interest.insert(uint256S("aeb4f26c3b106b389d709e1a8535fa0ac78b28bd5cc3e3e8d396920e771adc01"));
        txids_of_interest.insert(uint256S("af4835928eede042ebd0b422933e910071111d838335a0c01cdd3c3163cc5440"));
        txids_of_interest.insert(uint256S("afd82712252aa56063013b964393c227db81a1acbde85c72a3587b15a8a9cb52"));
        txids_of_interest.insert(uint256S("aff4f97bc159982dd6b4a4b4ab28e7e0bbb6a105f3116a2f2120f82b2d12ddb5"));
        txids_of_interest.insert(uint256S("b1adadf630f0db31afc606ef34344161622cc6ff14cf509c3fb3310161d86d45"));
        txids_of_interest.insert(uint256S("b26a736f22585f658691ca0aed30ce00d2fc4fa991cf2ccb47c6faa8fe74dd00"));
        txids_of_interest.insert(uint256S("b27fcde50a3dcc5d20a4e78b87213e15a77ab39d7da6c4d5a932b659a74e931e"));
        txids_of_interest.insert(uint256S("b2dc7a515aa34646394d68f5f640833a38aa49eae36a3865ce765839e9abec5d"));
        txids_of_interest.insert(uint256S("b323e321a448e519dc523e3419d745feae41108ed54b9eb729bbb45613851614"));
        txids_of_interest.insert(uint256S("b45d731a247eab7a68ce55005dfe546c5c865cab417ea5c0ebdb44071f754466"));
        txids_of_interest.insert(uint256S("b4f264fc1b2c63cc703f62b3a01f87f12eb390173c089c44dc97dd5f36c42adf"));
        txids_of_interest.insert(uint256S("b530eb9490c1b7b08cdff2ebe30caa9c8c74855f575b8948f66c746671e9aa91"));
        txids_of_interest.insert(uint256S("b597e4b140ec4c8d7bc4da95b2ba05da29f0abe76bee518830eccf428d6aed56"));
        txids_of_interest.insert(uint256S("b61740a4cb30c2afa2185687e800e2c96e22aa73aa774dac31ee223ce6611196"));
        txids_of_interest.insert(uint256S("b6837a2f354c43c1fc7d5d49770ffa82a00e3c6d041e97382c7c4c49dc504a07"));
        txids_of_interest.insert(uint256S("b69b06097eb7f9f84563df3ad30a3c4049a3b62f79410b6483d6da79783f686d"));
        txids_of_interest.insert(uint256S("b7d19ad827d5018bb5b4bb960c9e6d025524f3217c4a24aed25f6377a03a05fe"));
        txids_of_interest.insert(uint256S("b7e86a44c1322ca31eeab1d5e90f8cd58e0c818451ed7823aa4e0684e323c888"));
        txids_of_interest.insert(uint256S("b8c777a0d4ac46719a2816476106ac5190658cbf252d32c32c83f88582812745"));
        txids_of_interest.insert(uint256S("b945fe5ea481dbd6d3baaae40ef176ed145021b7e73c0910bb5a2d8a3f269d9f"));
        txids_of_interest.insert(uint256S("b9ac5cbce99c9a9190153cd310c85c700776c2aef2068664a1b3392566f2d244"));
        txids_of_interest.insert(uint256S("b9f7b93ed5970f8ed5fd707f0fa10b282c5ded4c709074107567506bc9fd5735"));
        txids_of_interest.insert(uint256S("ba1dcf1cb2ec54e077b6c7ba726e5dd7ca63e2738d9b32550b2771535a6060fb"));
        txids_of_interest.insert(uint256S("bc78bc3d4cead8f650f77a6a8818256ba692688b262a860d5f9775ac5df8e989"));
        txids_of_interest.insert(uint256S("bce7a22f883e09e050e9168bb1dc33857eb99475abdc35290d9a409d30e49094"));
        txids_of_interest.insert(uint256S("bd26f01f5b868ad87da00efeed6805a939f8b8503cbef23d6da9c97501933856"));
        txids_of_interest.insert(uint256S("be48e107c03812e003017308fbff76daa700230b13a42a3d52ba16d832030203"));
        txids_of_interest.insert(uint256S("be857e291dc32e8d59835c63223e0d883a208462cce217a2263089f60191fcd0"));
        txids_of_interest.insert(uint256S("beab9d723f0da6570c4a504ef39296568ef97a5363ef28704387fb15ae779dda"));
        txids_of_interest.insert(uint256S("c19ce9355649ae272c2e8a34f915e25cc184e1cefb1aa78243c0244142c726ce"));
        txids_of_interest.insert(uint256S("c2bd8f05ee8a6cf367c7caad17884df78b3aa1506bd8722d2bf1cac1a94278ae"));
        txids_of_interest.insert(uint256S("c36ee0ad9d1e06ad503236f3a3284e0e86a81f1b3c9fc2b1abe0cff674885c79"));
        txids_of_interest.insert(uint256S("c3c11793e87f1cf235c98a15d2404f3498491e36ea0c84937a9b93f352d7fbea"));
        txids_of_interest.insert(uint256S("c485bd544d065e5125ff3c7fc8c186920c10e6d99f1e551d5f334d7d1151bfc7"));
        txids_of_interest.insert(uint256S("c64a4c72b556d2ac38254ad7fa5dbb8eae9207345469f80b4a72c0e08cf65315"));
        txids_of_interest.insert(uint256S("c6553e0d24744803902396d16bb6638fdbeeba02ea50fab4d7581dfbb9bbd846"));
        txids_of_interest.insert(uint256S("c704d69010c6a65aea6330f7a01ce2167f4fee71ee49598001c24f41180efdf5"));
        txids_of_interest.insert(uint256S("c7b2c50c83262914f26e07cd1f8fa8670ce33fba6f49f077609fd082165e61c8"));
        txids_of_interest.insert(uint256S("c7d395374821c434e0365faa02ea6b1c59b45c2764f7bc607eef2aac0af043a3"));
        txids_of_interest.insert(uint256S("c8415a651adca952b8e89d9e774209ec76c3244c90d1b039fa4cc328cd4f4baa"));
        txids_of_interest.insert(uint256S("c8d4c376549bc9cd012301ba1898a8b1e047b81ba7568cb9058cc366bc3b5f05"));
        txids_of_interest.insert(uint256S("cab727d674fdea11ff05a21e399cd87ac8bc67c5d8cb7b11305d31c306a6be52"));
        txids_of_interest.insert(uint256S("cacbcca00e5c00cd5330324a5084434b9f71cfd458330b80ca4a9ebf9b593fd1"));
        txids_of_interest.insert(uint256S("cb2daffda6579b3cc440b832a58d632bf3572479f4eabc5396e8f2183eb13cc4"));
        txids_of_interest.insert(uint256S("ccf604e56956d56f6610ba8604ed45a4d9b26957da83f53982d302a514a003c8"));
        txids_of_interest.insert(uint256S("ce17b876725206b03379ed9932259618cfd6e2ebb49c877edba3de6d887db5c3"));
        txids_of_interest.insert(uint256S("ce3216e2b6871f348f02716a5d3a9e61cb31294e092a1bbf8c50c467c8485e5f"));
        txids_of_interest.insert(uint256S("cf5c84e957e0f9de327af57ce20b81f672168120eb518588649c92e479666030"));
        txids_of_interest.insert(uint256S("cfcd198132d33b133c1fdd2722c89141469b4b3e302950c98520342eb64c8d00"));
        txids_of_interest.insert(uint256S("cfeab4deb8949b17aeda4080ed861118700b79adc3f0a630d6d4dd0b5418bba3"));
        txids_of_interest.insert(uint256S("d1934006c84d58936f6660fdebec7a8aeede4f9f132562168abd24ed0fadbd97"));
        txids_of_interest.insert(uint256S("d295d3a709d1eceaf7966bf86c00acd278de252f66183827313a301ad428be1d"));
        txids_of_interest.insert(uint256S("d2f111d9d583d27dbe51313c75a75c20beb994620e982b4d278429c3d6dbe495"));
        txids_of_interest.insert(uint256S("d3f5d18daa0db116a995ae095580832a1af08365a80d80cc4f6ac0121129cdcd"));
        txids_of_interest.insert(uint256S("d4632a9a7b06dc361e9103e7919d7aa911f9f4728a28dc8925461256d1c96787"));
        txids_of_interest.insert(uint256S("d529b20003fa8e656b8bcaa640e10c2f1baf1b151c32f250c70a8a545c01dfde"));
        txids_of_interest.insert(uint256S("d580e64ea85adc154d7b1d17fa3b846e9d60983978372386ef2e53cbff9c8c03"));
        txids_of_interest.insert(uint256S("d71ee0d76fc1863b1a149b1d57a9ae208987687da426692e4632a7f7ba6af5f0"));
        txids_of_interest.insert(uint256S("d7541665e656a3f40896c044a3b589cbc121d76391b28dbab3010960f9380471"));
        txids_of_interest.insert(uint256S("d8b2245e05b5244b7ce892068851a466daac3d5dea7412d889adaaee4d8a3571"));
        txids_of_interest.insert(uint256S("d98741cf68c26a80ca544ef2c0909d37b664eac9cdb3e33e1b9d8c3c64471a7c"));
        txids_of_interest.insert(uint256S("d9b22fac14d9c0b4806078f0f716c9d5b7d1429a7212ae0b88f35e1a0fe192cb"));
        txids_of_interest.insert(uint256S("da0f62c952ff93c71cb7e8bbd1e3ab3ce939c4874444cce274e0bbdef42b32dc"));
        txids_of_interest.insert(uint256S("dad3b35eae8e4bc2c0f5544e3c296b184cb0f86d8d5113824e2f16afe7a29a62"));
        txids_of_interest.insert(uint256S("daf74a68ddafdba130b9ef190e939c04348ba517200b4cda76f19a5fd690312f"));
        txids_of_interest.insert(uint256S("dc3391f1a6cc9074826eb814cb072e7d762355a16ea5013821743d54662264da"));
        txids_of_interest.insert(uint256S("dce3cdcfd0869e5604d9163003e11cb6f51ce493d4169863a992f3b6033c1b9e"));
        txids_of_interest.insert(uint256S("dd3bef12233893d233288d05f545878ea2106cdc15ed1d091a04e27cc21d3d8b"));
        txids_of_interest.insert(uint256S("dd7cbbeea6bfd33c90feb8c176266f47faa4cec9da75eb3aa119e07a1a0dcc09"));
        txids_of_interest.insert(uint256S("ddc9565e26b664b34c51f87714c10536fd85765f85bdd0b56d547aaa94fdc56b"));
        txids_of_interest.insert(uint256S("dde6a2dc3a3e74cb7bb2172f4e8e933ece0771da3303c103363ef65795b93751"));
        txids_of_interest.insert(uint256S("de957ad2937ea1b37e4b999ceaaacc9626a676b7dca1e2e812cbe40e15cac364"));
        txids_of_interest.insert(uint256S("dedf3a5a70a945a998ffb404f3619a10c7f82abc1b80c9b508e29a45f18529e5"));
        txids_of_interest.insert(uint256S("dfe3c19d4ffb0dc189fefc48adb057a874cbb3174afb572fdbc2139f7fa3d37c"));
        txids_of_interest.insert(uint256S("e0be55a9e1c71923c088294e0989f7a53b873442ddfcf5fdd5ad4826a19da507"));
        txids_of_interest.insert(uint256S("e0c46751502cc9d429ef03fcd591d024cdef6a328df2f32b9674e18412b2a048"));
        txids_of_interest.insert(uint256S("e0d8bd653c0c7545dd7c074a15dc1bdf274f9d622aa69f6d54c66d7b9e19185d"));
        txids_of_interest.insert(uint256S("e15976befc4aab368f74aa760f140247c35415fca3c63405383879588fd4a07c"));
        txids_of_interest.insert(uint256S("e28ae5783a90c43a1502a7b72d3cbf6694d0aeb5d2acb98b4212f5e7d036b446"));
        txids_of_interest.insert(uint256S("e2941e61fc2f88f35c4d587c6b2b0aa0f7488215b57c8c0f64f4c609278c03a2"));
        txids_of_interest.insert(uint256S("e3479a73d25841af90978669c7037cd285eed1205c247fbafa217cc79ce3805c"));
        txids_of_interest.insert(uint256S("e49f2f90905aea74cb55032d0b10b11878cd828b1bfd6bcef3e6a50ee2eba8d4"));
        txids_of_interest.insert(uint256S("e4b0c2bb0d61aae4c5f7eb0c6230601e59a0ad6114defa47215438f912a1ab49"));
        txids_of_interest.insert(uint256S("e4c3bc2ee6f7da804ae76b15545b13a6784521cd0d093bfcafca79d3acd71319"));
        txids_of_interest.insert(uint256S("e54f0ff369c379402a32aff76de85bb3a3857e1135873941d908df1071c6aec7"));
        txids_of_interest.insert(uint256S("e59eddbef9b1f5d385d254455549bd21e961012c4beb58d37b01c527879d3f08"));
        txids_of_interest.insert(uint256S("e93907a75756a15ebcdfa13ee3d5c7fb30ae7f244ef9390d5b551901a207c619"));
        txids_of_interest.insert(uint256S("e9956ed85be3df08bcdc3f2da916308528e926c3989c6e3c9ae0c5e6d24fd233"));
        txids_of_interest.insert(uint256S("e9af1b0023eaa43225a371ae7a837a61bf3df75f07849e6b902be3b44b6e1a1d"));
        txids_of_interest.insert(uint256S("eafcdcecca7a9932b87a53c3c1edecb854021a4e323457a437841a37201bd55f"));
        txids_of_interest.insert(uint256S("eb3e71dcaaf7c2893688bf0dbcddcc7ea50eb3b8f3ca9bc90eacc2ede724960f"));
        txids_of_interest.insert(uint256S("ec47de377f300574c178635cd1f5d2da1d3464ebc8a3ba75d5136acac624dd97"));
        txids_of_interest.insert(uint256S("ec5e88da23e6fa81e156fc5b8f673120a8e8d31711ae52a7b8074a3342f596c1"));
        txids_of_interest.insert(uint256S("ec8cc30efd215588af8df02b25afedaab9ff1fffe0e9b3a1f5fe152e5e136701"));
        txids_of_interest.insert(uint256S("eccf833497aa2eb8e8d06e2556542ccafb7837eaa6b494fd9cc102f97cc25b72"));
        txids_of_interest.insert(uint256S("ecf997083a45a8648d5204140b33453eb27c5c11cbbb03ec4a31bdc88e8dbe3d"));
        txids_of_interest.insert(uint256S("ed69f0d676b635857d8977afeb92651fa0817654878d0873e442836d772d6ee0"));
        txids_of_interest.insert(uint256S("ed81bbc38adc46906083b325d04a23f59740cb52c92d8e0428aa1cdae3ac1e16"));
        txids_of_interest.insert(uint256S("edd6095926079104f63b9bd9eaad680b6f9587d271f725715c581c815aa1e51c"));
        txids_of_interest.insert(uint256S("ee1b95ebb6178aac08e62e6fbb21cfedb569aae205ebce7004c3fbdd0365450b"));
        txids_of_interest.insert(uint256S("ef7a923a6b629c9ee68099beea5d4efe4e1c83d7823b94cc34d65f5a706f2aa5"));
        txids_of_interest.insert(uint256S("efd7bfb206ef57752483d348cffb5ce5e8b18fdc5133d101ae2705629c293ff3"));
        txids_of_interest.insert(uint256S("eff8c37c8730471d1d48a2c05caf9d5da68be362255a7280fad99eb16a2768fb"));
        txids_of_interest.insert(uint256S("f1fbc21e60ffe2e3eaac59fdb2d96a5c15f1a5a2d737f4ee63b733cbf7493ef8"));
        txids_of_interest.insert(uint256S("f27e4dfbeb8c61122d8fe5ee716c8f9b4a5744af8d90fd03f302ded4e6472e79"));
        txids_of_interest.insert(uint256S("f2da144f3ab5fa80d2e75b3fa378cbaa1bae3d87f7a4a32c5b37135206036cd2"));
        txids_of_interest.insert(uint256S("f2e3380c0a74a1cfedb5b7d5e84ea53bff4fa41a431e29ee4a95e4efafebdb1a"));
        txids_of_interest.insert(uint256S("f2f0e63f201263a9cb94b9499be8bb0f5facbcd74ef8c56ec9df06abff5d4bb0"));
        txids_of_interest.insert(uint256S("f343225b11272e0a25c85197d85abe3df35e4ce3e7e5b815ef49c69770c6e29a"));
        txids_of_interest.insert(uint256S("f37bf5c0ffad37af85693116847465dd8bd2897b05a2d77154033a5e440c65d4"));
        txids_of_interest.insert(uint256S("f57bef3d37af0ce117096a000e963f83f7e52fc3da225689a18566ef953f8aea"));
        txids_of_interest.insert(uint256S("f57c66c09fe21779d45877652b2fca4df28fb91fe7e757fca21046a64a60cfa4"));
        txids_of_interest.insert(uint256S("f5948414e00e50b3bee659b33275fe79892b24310d69444e40c8c17feed0c7f7"));
        txids_of_interest.insert(uint256S("f696d224a3acc22f00965e7065eb49caa1710de204d3a4e7065a4a09766a0e29"));
        txids_of_interest.insert(uint256S("f775a9bd452be30781ff6752c0c75371ef17672d3fafb5fa0475180808616545"));
        txids_of_interest.insert(uint256S("f81a8446911fce45ee20e1f6d0631dd1ef3dd70a4c44cd342a6f43dc13343ad2"));
        txids_of_interest.insert(uint256S("fa63ef5590efc74cfc0d0cf8d29ba455644938a6aa195b34f2c4bf2d4edd6dcd"));
        txids_of_interest.insert(uint256S("fad3d309f329a650ef78349cff27b7e9de0c9c2a17154e75adf3f55b19be2964"));
        txids_of_interest.insert(uint256S("fb8924b2546066dcc7376721587c0f7a7c97a138bbeefb0007c4525d44d1d803"));
        txids_of_interest.insert(uint256S("fc4b0792a99e8d88996f9442bfa144564f51510955c7890e211020df66848ea5"));
        txids_of_interest.insert(uint256S("fd3f6a76c81020656d4c33e59b2dd6b95f0ff16ab653815545c643fc9dbb4a90"));
        txids_of_interest.insert(uint256S("fe56234575988f5be6558212b7b44f1b0e33049d7795b16a0771defb7d347121"));
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
