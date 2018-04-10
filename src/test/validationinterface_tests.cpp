// Copyright (c) 2011-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/test_bitcoin.h>
#include <boost/test/unit_test.hpp>
#include <validation.h>
#include <chainparams.h>
#include <validationinterface.h>

BOOST_FIXTURE_TEST_SUITE(validationinterface_tests, TestChain100Setup)

class ValidationCB : public CValidationInterface {
  public:
    void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) override 
    {
        previous_tip = current_tip;
        current_tip = pindexNew;
        fork_point_from_previous_tip = pindexFork;
    }
    void TransactionAddedToMempool(const CTransactionRef &ptxn) override {}
    void TransactionRemovedFromMempool(const CTransactionRef &ptx) override {}
    void BlockConnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex *pindex, const std::vector<CTransactionRef>& vtxConflicted) override
    {
        last_block_connected = pindex;
        // Check that BlockConnected messages come before UpdatedBlockTip messages
        BOOST_CHECK(last_block_connected->nChainWork > current_tip->nChainWork || );
    }
    void BlockDisconnected(const std::shared_ptr<const CBlock> &block) override
    {
        last_block_disconnected = LookupBlockIndex(block->GetHash());
    }
    void SetBestChain(const CBlockLocator &locator) override {}
    void Inventory(const uint256 &hash) override {}
    void ResendWalletTransactions(int64_t nBestBlockTime, CConnman* connman) override {}
    void BlockChecked(const CBlock&, const CValidationState&) override {}
    void NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock>& block) override {}

    // For tracking the best tip via UpdatedBlockTip callbacks:
    const CBlockIndex *current_tip, *previous_tip, *fork_point_from_previous_tip;

    // For tracking the calls from BlockConnected/BlockDisconnected:
    const CBlockIndex *last_block_disconnected;
    const CBlockIndex *last_block_connected;
};

BOOST_AUTO_TEST_CASE(validationinterface_blocktests)
{
    ValidationCB validation_callbacks;
    RegisterValidationInterface(&validation_callbacks);
    // Generate a new block.
    const CChainParams& chainparams = Params();
    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    CBlock block = CreateAndProcessBlock({}, scriptPubKey);
    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
    ProcessNewBlock(chainparams, shared_pblock, true, nullptr);
    SyncWithValidationInterfaceQueue();
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block.GetHash());
    BOOST_CHECK_EQUAL(chainActive.Tip(), validation_callbacks.last_block_connected);
    BOOST_CHECK_EQUAL(chainActive.Tip(), validation_callbacks.current_tip);
}

BOOST_AUTO_TEST_SUITE_END()
