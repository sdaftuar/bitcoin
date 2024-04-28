// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MINI_MINER_H
#define BITCOIN_NODE_MINI_MINER_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdint.h>
#include <vector>

class CFeeRate;
class CTxMemPool;

namespace node {

namespace FeeBumpCalculator {
    /**
     * For each outpoint that does not currently have a mining score of at least the target_feerate,
     * calculate the additional fees required to bump the outpoint (along with any unconfirmed ancestors
     * that also do not have mining scores of at least the target_feerate) to the target feerate.
     */
    std::map<COutPoint, CAmount> CalculateBumpFees(CTxMemPool& mempool, const std::vector<COutPoint>& outpoints, const CFeeRate& target_feerate);

    /**
     * Same as CalculateBumpFees, except return the single fee required to bump *all* ancestors of
     * all txids reflected in the given outpoints to the target feerate, ignoring any ancestors that
     * already have mining scores of at least the target feerate.
     */
    CAmount CalculateTotalBumpFees(CTxMemPool& mempool, const std::vector<COutPoint>& outpoints, const CFeeRate& target_feerate);
}
} // namespace node

#endif // BITCOIN_NODE_MINI_MINER_H
