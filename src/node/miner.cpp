// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/miner.h>

#include <Highs.h>
#include <txmempool.h>
#include <primitives/transaction.h>
#include <util/check.h>  // For Assume
#include <set>
#include <vector>
#include <map>
#include <string>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <logging.h>
#include <node/context.h>
#include <node/kernel_notifications.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <util/moneystr.h>
#include <util/signalinterrupt.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <utility>

namespace node {

int64_t GetMinimumTime(const CBlockIndex* pindexPrev, const int64_t difficulty_adjustment_interval)
{
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    // Height of block to be mined.
    const int height{pindexPrev->nHeight + 1};
    // Account for BIP94 timewarp rule on all networks. This makes future
    // activation safer.
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    return min_time;
}

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime{std::max<int64_t>(GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()),
                                       TicksSinceEpoch<std::chrono::seconds>(NodeClock::now()))};

    if (nOldTime < nNewTime) {
        pblock->nTime = nNewTime;
    }

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
    }

    return nNewTime - nOldTime;
}

void RegenerateCommitments(CBlock& block, ChainstateManager& chainman)
{
    CMutableTransaction tx{*block.vtx.at(0)};
    tx.vout.erase(tx.vout.begin() + GetWitnessCommitmentIndex(block));
    block.vtx.at(0) = MakeTransactionRef(tx);

    const CBlockIndex* prev_block = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock));
    chainman.GenerateCoinbaseCommitment(block, prev_block);

    block.hashMerkleRoot = BlockMerkleRoot(block);
}

static BlockAssembler::Options ClampOptions(BlockAssembler::Options options)
{
    options.block_reserved_weight = std::clamp<size_t>(options.block_reserved_weight, MINIMUM_BLOCK_RESERVED_WEIGHT, MAX_BLOCK_WEIGHT);
    options.coinbase_output_max_additional_sigops = std::clamp<size_t>(options.coinbase_output_max_additional_sigops, 0, MAX_BLOCK_SIGOPS_COST);
    // Limit weight to between block_reserved_weight and MAX_BLOCK_WEIGHT for sanity:
    // block_reserved_weight can safely exceed -blockmaxweight, but the rest of the block template will be empty.
    options.nBlockMaxWeight = std::clamp<size_t>(options.nBlockMaxWeight, options.block_reserved_weight, MAX_BLOCK_WEIGHT);
    return options;
}

BlockAssembler::BlockAssembler(Chainstate& chainstate, const CTxMemPool* mempool, const Options& options)
    : chainparams{chainstate.m_chainman.GetParams()},
      m_mempool{options.use_mempool ? mempool : nullptr},
      m_chainstate{chainstate},
      m_options{ClampOptions(options)}
{
}

void ApplyArgsManOptions(const ArgsManager& args, BlockAssembler::Options& options)
{
    // Block resource limits
    options.nBlockMaxWeight = args.GetIntArg("-blockmaxweight", options.nBlockMaxWeight);
    if (const auto blockmintxfee{args.GetArg("-blockmintxfee")}) {
        if (const auto parsed{ParseMoney(*blockmintxfee)}) options.blockMinFeeRate = CFeeRate{*parsed};
    }
    options.print_modified_fee = args.GetBoolArg("-printpriority", options.print_modified_fee);
    options.block_reserved_weight = args.GetIntArg("-blockreservedweight", options.block_reserved_weight);
}

void BlockAssembler::resetBlock()
{
    // Reserve space for fixed-size block header, txs count, and coinbase tx.
    nBlockWeight = m_options.block_reserved_weight;
    nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock()
{
    const auto time_start{SteadyClock::now()};

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());
    CBlock* const pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction. It is skipped by the
    // getblocktemplate RPC and mining interface consumers must not use it.
    pblock->vtx.emplace_back();

    LOCK(::cs_main);
    CBlockIndex* pindexPrev = m_chainstate.m_chain.Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = m_chainstate.m_chainman.m_versionbitscache.ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand()) {
        pblock->nVersion = gArgs.GetIntArg("-blockversion", pblock->nVersion);
    }

    pblock->nTime = TicksSinceEpoch<std::chrono::seconds>(NodeClock::now());
    m_lock_time_cutoff = pindexPrev->GetMedianTimePast();

    if (m_mempool) {
        LOCK(m_mempool->cs);
        m_mempool->StartBlockBuilding();
        addChunks();
        m_mempool->StopBlockBuilding();
    }

    const auto time_1{SteadyClock::now()};

    m_last_block_num_txs = nBlockTx;
    m_last_block_weight = nBlockWeight;
    pblocktemplate->fee_lower_bound = fee_lower_bound;
    pblocktemplate->fee_achieved = nFees;
    pblocktemplate->fee_upper_bound = fee_upper_bound;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL; // Make sure timelock is enforced.
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = m_options.coinbase_output_script;
    coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    Assert(nHeight > 0);
    coinbaseTx.nLockTime = static_cast<uint32_t>(nHeight - 1);
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    pblocktemplate->vchCoinbaseCommitment = m_chainstate.m_chainman.GenerateCoinbaseCommitment(*pblock, pindexPrev);

    std::vector<CTransactionRef> dummy;
    auto max_fees = OptimizeMempoolSelection(dummy);
    assert(max_fees >= nFees);

    LogPrintf("CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d max_fees: %ld\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost, max_fees);

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nNonce         = 0;

    if (m_options.test_block_validity) {
        if (BlockValidationState state{TestBlockValidity(m_chainstate, *pblock, /*check_pow=*/false, /*check_merkle_root=*/false)}; !state.IsValid()) {
            throw std::runtime_error(strprintf("TestBlockValidity failed: %s", state.ToString()));
        }
    }
    const auto time_2{SteadyClock::now()};

    LogDebug(BCLog::BENCH, "CreateNewBlock() chunks: %.2fms, validity: %.2fms (total %.2fms)\n",
             Ticks<MillisecondsDouble>(time_1 - time_start),
             Ticks<MillisecondsDouble>(time_2 - time_1),
             Ticks<MillisecondsDouble>(time_2 - time_start));

    return std::move(pblocktemplate);
}

bool BlockAssembler::TestPackage(FeePerWeight package_feerate, int64_t packageSigOpsCost) const
{
    if (nBlockWeight + package_feerate.size >= m_options.nBlockMaxWeight) {
        return false;
    }
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST) {
        return false;
    }
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
bool BlockAssembler::TestPackageTransactions(const std::vector<const CTxMemPoolEntry *>& txs) const
{
    for (auto tx : txs) {
        if (!IsFinalTx(tx->GetTx(), nHeight, m_lock_time_cutoff)) {
            return false;
        }
    }
    return true;
}

void BlockAssembler::AddToBlock(const CTxMemPoolEntry& entry)
{
    pblocktemplate->block.vtx.emplace_back(entry.GetSharedTx());
    pblocktemplate->vTxFees.push_back(entry.GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(entry.GetSigOpCost());
    nBlockWeight += entry.GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += entry.GetSigOpCost();
    nFees += entry.GetFee();

    if (m_options.print_modified_fee) {
        LogPrintf("fee rate %s txid %s\n",
                  CFeeRate(entry.GetModifiedFee(), entry.GetTxSize()).ToString(),
                  entry.GetTx().GetHash().ToString());
    }
}

void BlockAssembler::addChunks()
{
    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    constexpr int32_t BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000;
    int64_t nConsecutiveFailed = 0;
    fee_upper_bound = 0;
    fee_lower_bound = 0;
    bool have_skipped = false;

    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> selected_transactions;
    FeePerWeight chunk_feerate;

    chunk_feerate = m_mempool->GetBlockBuilderChunk(selected_transactions);
    FeePerVSize chunk_feerate_vsize = ToFeePerVSize(chunk_feerate);

    std::vector<const CTxMemPoolEntry*> chunk_txs;
    // We'll add at most one chunk per iteration below, and chunk count is bounded by
    // the cluster size limit.
    chunk_txs.reserve(MAX_CLUSTER_COUNT_LIMIT);
    while (selected_transactions.size() > 0) {
        // Check to see if min fee rate is still respected.
        if (chunk_feerate.fee < m_options.blockMinFeeRate.GetFee(chunk_feerate_vsize.size)) {
            // Everything else we might consider has a lower feerate
            if (!have_skipped) {
                fee_lower_bound = nFees;
                fee_upper_bound = nFees;
            }
            return;
        }

        int64_t package_sig_ops = 0;
        chunk_txs.clear();
        for (const auto& tx : selected_transactions) {
            chunk_txs.emplace_back(&tx.get());
            package_sig_ops += tx.get().GetSigOpCost();
        }

        // Check to see if this chunk will fit.
        if (!TestPackage(chunk_feerate, package_sig_ops) || !TestPackageTransactions(chunk_txs)) {
            if (!have_skipped) {
                fee_lower_bound = nFees;
                fee_upper_bound = nFees + chunk_feerate.EvaluateFee<true>(m_options.nBlockMaxWeight - nBlockWeight);
                have_skipped = true;
            }
            m_mempool->SkipBuilderChunk();
            // This chunk won't fit, so we let it be removed from the heap and
            // we'll try the next best.
            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight +
                    BLOCK_FULL_ENOUGH_WEIGHT_DELTA > m_options.nBlockMaxWeight) {
                // Give up if we're close to full and haven't succeeded in a while
                return;
            }
        } else {
            m_mempool->IncludeBuilderChunk();

            // This chunk will fit, so add it to the block.
            nConsecutiveFailed = 0;
            for (const auto& tx : chunk_txs) {
                AddToBlock(*tx);
            }
            pblocktemplate->m_package_feerates.emplace_back(chunk_feerate_vsize);
        }

        selected_transactions.clear();
        auto old_feerate = chunk_feerate;
        chunk_feerate = m_mempool->GetBlockBuilderChunk(selected_transactions);
        assert(FeeRateCompare(chunk_feerate, old_feerate) <= 0);
        chunk_feerate_vsize = ToFeePerVSize(chunk_feerate);
    }
}

// Function to select an optimal subset of mempool transactions to maximize fees
// subject to block weight limit and ancestor dependencies using HiGHS MIP solver.
int64_t BlockAssembler::OptimizeMempoolSelection(std::vector<CTransactionRef>& selected_txs) 
{
    auto &mempool{*m_mempool};
    LOCK(mempool.cs);
    selected_txs.clear();

    // Collect all transactions
    auto txs = mempool.entryAll();
    int n = txs.size();
    if (n == 0) {
        return 0;
    }

    // Map Txid to index
    std::map<Txid, int> tx_index;
    for (int i = 0; i < n; ++i) {
        tx_index[txs[i].get().GetTx().GetHash()] = i;
    }

    // Initialize HiGHS
    Highs highs;
    highs.setOptionValue("output_flag", false);  // Suppress output for brevity

    // Add binary variables (0 or 1) for each transaction
    std::vector<int> integer_vars(n);
    for (int i = 0; i < n; ++i) {
        highs.addVar(0.0, 1.0);  // Lower bound 0, upper bound 1
        integer_vars[i] = i;     // Track indices for integer variables
    }
    // Set variables as integer (binary)
    highs.changeColsIntegrality(0, n - 1, std::vector<HighsVarType>(n, HighsVarType::kInteger).data());

    // Set objective: maximize sum of fees
    std::vector<double> obj_coeffs(n, 0.0);
    for (int i = 0; i < n; ++i) {
        obj_coeffs[i] = static_cast<double>(txs[i].get().GetFee());
    }
    highs.changeObjectiveSense(ObjSense::kMaximize);
    highs.changeColsCost(0, n - 1, obj_coeffs.data());

    // Weight constraint: sum(weight_i * x_i) <= 4,000,000
    std::vector<int> weight_indices(n);
    std::vector<double> weight_values(n);
    for (int i = 0; i < n; ++i) {
        weight_indices[i] = i;
        weight_values[i] = static_cast<double>(txs[i].get().GetTxWeight());
    }
    highs.addRow(0.0, m_options.nBlockMaxWeight, n, weight_indices.data(), weight_values.data());

    // Build direct parent relationships (ancestors)
    for (int i = 0; i < n; ++i) {
        // Get the ancestors of each transaction
        auto ancestors = mempool.CalculateMemPoolAncestors(txs[i].get());
        for (auto parent : ancestors) {
            Txid parent_id = parent->GetTx().GetHash();
            auto it = tx_index.find(parent_id);
            assert(it != tx_index.end());  // Ancestor must be in the mempool
           // Add dependency constraints: for each parent-child pair, x_parent >= x_child (i.e., x_parent - x_child >= 0)
            std::vector<int> dep_indices = {it->second, i};
            std::vector<double> dep_values = {1.0, -1.0};
            highs.addRow(0.0, kHighsInf, 2, dep_indices.data(), dep_values.data());
        }
    }

    // Solve the MIP
    HighsStatus solve_status = highs.run();
    if (solve_status != HighsStatus::kOk) {
        LogPrintf("HiGHS solve failed with status %d\n", static_cast<int>(solve_status));
        return 0;
    }

    // Extract solution
    const HighsSolution& solution = highs.getSolution();
    HighsModelStatus sol_status = highs.getModelStatus();
    if (sol_status != HighsModelStatus::kOptimal) {
        LogPrintf("HiGHS did not find an optimal solution: %d\n", static_cast<int>(sol_status));
        return 0;
    }

    int64_t total_fees = 0;

    // Collect selected transactions (integer solution, threshold 0.5)
    for (int i = 0; i < n; ++i) {
        if (solution.col_value[i] > 0.5) {
            selected_txs.push_back(txs[i].get().GetSharedTx());
            total_fees += txs[i].get().GetFee();
        }
    }
    return total_fees;
    // Note: selected_txs may need topological sorting before inclusion in a block.
    // Use CTxMemPool::GetSortedDepthAndScore or implement topo sort if needed.
}

void AddMerkleRootAndCoinbase(CBlock& block, CTransactionRef coinbase, uint32_t version, uint32_t timestamp, uint32_t nonce)
{
    if (block.vtx.size() == 0) {
        block.vtx.emplace_back(coinbase);
    } else {
        block.vtx[0] = coinbase;
    }
    block.nVersion = version;
    block.nTime = timestamp;
    block.nNonce = nonce;
    block.hashMerkleRoot = BlockMerkleRoot(block);
}

std::unique_ptr<CBlockTemplate> WaitAndCreateNewBlock(ChainstateManager& chainman,
                                                      KernelNotifications& kernel_notifications,
                                                      CTxMemPool* mempool,
                                                      const std::unique_ptr<CBlockTemplate>& block_template,
                                                      const BlockWaitOptions& options,
                                                      const BlockAssembler::Options& assemble_options)
{
    // Delay calculating the current template fees, just in case a new block
    // comes in before the next tick.
    CAmount current_fees = -1;

    // Alternate waiting for a new tip and checking if fees have risen.
    // The latter check is expensive so we only run it once per second.
    auto now{NodeClock::now()};
    const auto deadline = now + options.timeout;
    const MillisecondsDouble tick{1000};
    const bool allow_min_difficulty{chainman.GetParams().GetConsensus().fPowAllowMinDifficultyBlocks};

    do {
        bool tip_changed{false};
        {
            WAIT_LOCK(kernel_notifications.m_tip_block_mutex, lock);
            // Note that wait_until() checks the predicate before waiting
            kernel_notifications.m_tip_block_cv.wait_until(lock, std::min(now + tick, deadline), [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
                AssertLockHeld(kernel_notifications.m_tip_block_mutex);
                const auto tip_block{kernel_notifications.TipBlock()};
                // We assume tip_block is set, because this is an instance
                // method on BlockTemplate and no template could have been
                // generated before a tip exists.
                tip_changed = Assume(tip_block) && tip_block != block_template->block.hashPrevBlock;
                return tip_changed || chainman.m_interrupt;
            });
        }

        if (chainman.m_interrupt) return nullptr;
        // At this point the tip changed, a full tick went by or we reached
        // the deadline.

        // Must release m_tip_block_mutex before locking cs_main, to avoid deadlocks.
        LOCK(::cs_main);

        // On test networks return a minimum difficulty block after 20 minutes
        if (!tip_changed && allow_min_difficulty) {
            const NodeClock::time_point tip_time{std::chrono::seconds{chainman.ActiveChain().Tip()->GetBlockTime()}};
            if (now > tip_time + 20min) {
                tip_changed = true;
            }
        }

        /**
         * We determine if fees increased compared to the previous template by generating
         * a fresh template. There may be more efficient ways to determine how much
         * (approximate) fees for the next block increased, perhaps more so after
         * Cluster Mempool.
         *
         * We'll also create a new template if the tip changed during this iteration.
         */
        if (options.fee_threshold < MAX_MONEY || tip_changed) {
            auto new_tmpl{BlockAssembler{
                chainman.ActiveChainstate(),
                mempool,
                assemble_options}
                              .CreateNewBlock()};

            // If the tip changed, return the new template regardless of its fees.
            if (tip_changed) return new_tmpl;

            // Calculate the original template total fees if we haven't already
            if (current_fees == -1) {
                current_fees = 0;
                for (CAmount fee : block_template->vTxFees) {
                    current_fees += fee;
                }
            }

            CAmount new_fees = 0;
            for (CAmount fee : new_tmpl->vTxFees) {
                new_fees += fee;
                Assume(options.fee_threshold != MAX_MONEY);
                if (new_fees >= current_fees + options.fee_threshold) return new_tmpl;
            }
        }

        now = NodeClock::now();
    } while (now < deadline);

    return nullptr;
}

std::optional<BlockRef> GetTip(ChainstateManager& chainman)
{
    LOCK(::cs_main);
    CBlockIndex* tip{chainman.ActiveChain().Tip()};
    if (!tip) return {};
    return BlockRef{tip->GetBlockHash(), tip->nHeight};
}

std::optional<BlockRef> WaitTipChanged(ChainstateManager& chainman, KernelNotifications& kernel_notifications, const uint256& current_tip, MillisecondsDouble& timeout)
{
    Assume(timeout >= 0ms); // No internal callers should use a negative timeout
    if (timeout < 0ms) timeout = 0ms;
    if (timeout > std::chrono::years{100}) timeout = std::chrono::years{100}; // Upper bound to avoid UB in std::chrono
    auto deadline{std::chrono::steady_clock::now() + timeout};
    {
        WAIT_LOCK(kernel_notifications.m_tip_block_mutex, lock);
        // For callers convenience, wait longer than the provided timeout
        // during startup for the tip to be non-null. That way this function
        // always returns valid tip information when possible and only
        // returns null when shutting down, not when timing out.
        kernel_notifications.m_tip_block_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
            return kernel_notifications.TipBlock() || chainman.m_interrupt;
        });
        if (chainman.m_interrupt) return {};
        // At this point TipBlock is set, so continue to wait until it is
        // different then `current_tip` provided by caller.
        kernel_notifications.m_tip_block_cv.wait_until(lock, deadline, [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
            return Assume(kernel_notifications.TipBlock()) != current_tip || chainman.m_interrupt;
        });
    }
    if (chainman.m_interrupt) return {};

    // Must release m_tip_block_mutex before getTip() locks cs_main, to
    // avoid deadlocks.
    return GetTip(chainman);
}
} // namespace node
