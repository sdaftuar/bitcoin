// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/validation.h"
#include "key.h"
#include "validation.h"
#include "miner.h"
#include "pubkey.h"
#include "txmempool.h"
#include "random.h"
#include "script/standard.h"
#include "script/sign.h"
#include "test/test_bitcoin.h"
#include "utiltime.h"
#include "core_io.h"
#include "keystore.h"
#include "policy/policy.h"

#include <boost/test/unit_test.hpp>

bool CheckInputs(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks);

BOOST_AUTO_TEST_SUITE(tx_validationcache_tests)

static bool
ToMemPool(CMutableTransaction& tx)
{
    LOCK(cs_main);

    CValidationState state;
    return AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), false, NULL, NULL, true, 0);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_block_doublespend, TestChain100Setup)
{
    // Make sure skipping validation of transctions that were
    // validated going into the memory pool does not allow
    // double-spends in blocks to pass validation when they should not.

    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    // Create a double-spend of mature coinbase txn:
    std::vector<CMutableTransaction> spends;
    spends.resize(2);
    for (int i = 0; i < 2; i++)
    {
        spends[i].nVersion = 1;
        spends[i].vin.resize(1);
        spends[i].vin[0].prevout.hash = coinbaseTxns[0].GetHash();
        spends[i].vin[0].prevout.n = 0;
        spends[i].vout.resize(1);
        spends[i].vout[0].nValue = 11*CENT;
        spends[i].vout[0].scriptPubKey = scriptPubKey;

        // Sign:
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(scriptPubKey, spends[i], 0, SIGHASH_ALL, 0, SIGVERSION_BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spends[i].vin[0].scriptSig << vchSig;
    }

    CBlock block;

    // Test 1: block with both of those transactions should be rejected.
    block = CreateAndProcessBlock(spends, scriptPubKey);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() != block.GetHash());

    // Test 2: ... and should be rejected if spend1 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[0]));
    block = CreateAndProcessBlock(spends, scriptPubKey);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() != block.GetHash());
    mempool.clear();

    // Test 3: ... and should be rejected if spend2 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[1]));
    block = CreateAndProcessBlock(spends, scriptPubKey);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() != block.GetHash());
    mempool.clear();

    // Final sanity test: first spend in mempool, second in block, that's OK:
    std::vector<CMutableTransaction> oneSpend;
    oneSpend.push_back(spends[0]);
    BOOST_CHECK(ToMemPool(spends[1]));
    block = CreateAndProcessBlock(oneSpend, scriptPubKey);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block.GetHash());
    // spends[1] should have been removed from the mempool when the
    // block with spends[0] is accepted:
    BOOST_CHECK_EQUAL(mempool.size(), 0);
}

// Run CheckInputs (using pcoinsTip) on the given transaction, for all script
// flags.  Test that CheckInputs passes for all flags that don't overlap with
// the failing_flags argument, but otherwise fails.
// CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY (and future NOP codes that may
// get reassigned) have an interaction with DISCOURAGE_UPGRADABLE_NOPS: if
// the script flags used contain DISCOURAGE_UPGRADABLE_NOPS but don't contain
// CHECKLOCKTIMEVERIFY (or CHECKSEQUENCEVERIFY), but the script does contain
// OP_CHECKLOCKTIMEVERIFY (or OP_CHECKSEQUENCEVERIFY), then script execution
// should fail.
// Capture this interaction with the upgraded_nop argument: set it when evaluating
// any script flag that is implemented as an upgraded NOP code.
void ValidateCheckInputsForAllFlags(CMutableTransaction &tx, uint32_t failing_flags, bool add_to_cache, bool upgraded_nop)
{
    PrecomputedTransactionData txdata(tx);
    // If we add many more flags, this loop can get too expensive, but we can
    // rewrite in the future to randomly pick a set of flags to evaluate.
    for (uint32_t test_flags=0; test_flags < (1U << 16); test_flags += 1) {
        CValidationState state;
        // Filter out incompatible flag choices
        if ((test_flags & SCRIPT_VERIFY_CLEANSTACK)) {
            // CLEANSTACK requires P2SH and WITNESS, see VerifyScript() in
            // script/interpreter.cpp
            test_flags |= SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
        }
        if ((test_flags & SCRIPT_VERIFY_WITNESS)) {
            // WITNESS requires P2SH
            test_flags |= SCRIPT_VERIFY_P2SH;
        }
        bool ret = CheckInputs(tx, state, pcoinsTip, true, test_flags, true, add_to_cache, txdata, nullptr);
        // CheckInputs should succeed iff test_flags doesn't intersect with
        // failing_flags
        bool expected_return_value = !(test_flags & failing_flags);
        if (expected_return_value && upgraded_nop) {
            // If the script flag being tested corresponds to an upgraded NOP,
            // then script execution should fail if DISCOURAGE_UPGRADABLE_NOPS
            // is set.
            expected_return_value = !(test_flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS);
        }
        BOOST_CHECK_EQUAL(ret, expected_return_value);
        if (ret != expected_return_value) {
            printf("%d\n", test_flags);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(checkinputs_test, TestChain100Setup)
{
    // Test that passing CheckInputs with one set of script flags doesn't imply
    // that we would pass again with a different set of flags.
    InitScriptExecutionCache();

    CScript p2pk_scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    CScript p2sh_scriptPubKey = GetScriptForDestination(CScriptID(p2pk_scriptPubKey));
    CScript p2pkh_scriptPubKey = GetScriptForDestination(coinbaseKey.GetPubKey().GetID());
    CScript p2wpkh_scriptPubKey = GetScriptForWitness(p2pkh_scriptPubKey);

    CBasicKeyStore keystore;
    keystore.AddKey(coinbaseKey);

    // flags to test: SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, SCRIPT_VERIFY_CHECKSEQUENCE_VERIFY, SCRIPT_VERIFY_NULLDUMMY, uncompressed pubkey thing

    // Create 2 outputs that match the three scripts above, spending the first
    // coinbase tx.
    CMutableTransaction spend_tx;

    spend_tx.nVersion = 1;
    spend_tx.vin.resize(1);
    spend_tx.vin[0].prevout.hash = coinbaseTxns[0].GetHash();
    spend_tx.vin[0].prevout.n = 0;
    spend_tx.vout.resize(4);
    spend_tx.vout[0].nValue = 11*CENT;
    spend_tx.vout[0].scriptPubKey = p2sh_scriptPubKey;
    spend_tx.vout[1].nValue = 11*CENT;
    spend_tx.vout[1].scriptPubKey = p2wpkh_scriptPubKey;
    spend_tx.vout[2].nValue = 11*CENT;
    spend_tx.vout[2].scriptPubKey = CScript() << OP_CHECKLOCKTIMEVERIFY << OP_DROP << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    spend_tx.vout[3].nValue = 11*CENT;
    spend_tx.vout[3].scriptPubKey = CScript() << OP_CHECKSEQUENCEVERIFY << OP_DROP << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    // Sign, with a non-DER signature
    {
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(p2pk_scriptPubKey, spend_tx, 0, SIGHASH_ALL, 0, SIGVERSION_BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char) 0); // padding byte makes this non-DER
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spend_tx.vin[0].scriptSig << vchSig;
    }

    LOCK(cs_main);

    // Test that invalidity under a set of flags doesn't preclude validity
    // under other (eg consensus) flags.
    // spend_tx is invalid according to DERSIG
    CValidationState state;
    {
        PrecomputedTransactionData ptd_spend_tx(spend_tx);

        BOOST_CHECK(!CheckInputs(spend_tx, state, pcoinsTip, true, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG, true, true, ptd_spend_tx, nullptr));

        // If we call again asking for scriptchecks (as happens in
        // ConnectBlock), we should add a script check object for this -- we're
        // not caching invalidity (if that changes, delete this test case).
        std::vector<CScriptCheck> scriptchecks;
        BOOST_CHECK(CheckInputs(spend_tx, state, pcoinsTip, true, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG, true, true, ptd_spend_tx, &scriptchecks));
        BOOST_CHECK_EQUAL(scriptchecks.size(), 1);

        // Test that CheckInputs returns true iff DERSIG-enforcing flags are
        // not present.  Don't add these checks to the cache, so that we can
        // test later that block validation works fine in the absence of cached
        // successes.
        ValidateCheckInputsForAllFlags(spend_tx, SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC, false, false);

        // And if we produce a block with this tx, it should be valid (DERSIG not
        // enabled yet), even though there's no cache entry.
        CBlock block;

        block = CreateAndProcessBlock({spend_tx}, p2pk_scriptPubKey);
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block.GetHash());
        BOOST_CHECK(pcoinsTip->GetBestBlock() == block.GetHash());
    }

    // Test P2SH: construct a transaction that is valid without P2SH, and
    // then test validity with P2SH.
    {
        CMutableTransaction invalid_under_p2sh_tx;
        invalid_under_p2sh_tx.nVersion = 1;
        invalid_under_p2sh_tx.vin.resize(1);
        invalid_under_p2sh_tx.vin[0].prevout.hash = spend_tx.GetHash();
        invalid_under_p2sh_tx.vin[0].prevout.n = 0;
        invalid_under_p2sh_tx.vout.resize(1);
        invalid_under_p2sh_tx.vout[0].nValue = 11*CENT;
        invalid_under_p2sh_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;
        std::vector<unsigned char> vchSig2(p2pk_scriptPubKey.begin(), p2pk_scriptPubKey.end());
        invalid_under_p2sh_tx.vin[0].scriptSig << vchSig2;

        PrecomputedTransactionData txdata(invalid_under_p2sh_tx);
        // Will test that evaluation of transaction validity doesn't change due
        // to caching flag or after using different script flags.
        for (int i=0; i<2; ++i) {
            for (bool script_cache_flag: {true, false}) {
                BOOST_CHECK(CheckInputs(invalid_under_p2sh_tx, state, pcoinsTip, true, SCRIPT_VERIFY_NONE, true, script_cache_flag, txdata, nullptr));
                BOOST_CHECK(!CheckInputs(invalid_under_p2sh_tx, state, pcoinsTip, true, SCRIPT_VERIFY_P2SH, true, script_cache_flag, txdata, nullptr));
            }
        }

        // Run with new flags, and test the returned script executions.
        std::vector<CScriptCheck> scriptchecks;
        BOOST_CHECK(CheckInputs(invalid_under_p2sh_tx, state, pcoinsTip, true, STANDARD_SCRIPT_VERIFY_FLAGS, true, true, txdata, &scriptchecks));
        BOOST_CHECK_EQUAL(scriptchecks.size(), 1); // Must have generated script executions for the new flags
        scriptchecks.clear();

        BOOST_CHECK(CheckInputs(invalid_under_p2sh_tx, state, pcoinsTip, true, STANDARD_SCRIPT_VERIFY_FLAGS, true, true, txdata, &scriptchecks));
        BOOST_CHECK_EQUAL(scriptchecks.size(), 1); // Can't possibly have cached anything as the checks were returned!
        scriptchecks.clear();

        BOOST_CHECK(CheckInputs(invalid_under_p2sh_tx, state, pcoinsTip, true, SCRIPT_VERIFY_NONE, true, true, txdata, nullptr));
        BOOST_CHECK(CheckInputs(invalid_under_p2sh_tx, state, pcoinsTip, true, SCRIPT_VERIFY_NONE, true, true, txdata, &scriptchecks));
        BOOST_CHECK(scriptchecks.empty()); // Must have generated no script executions

        // Test that CheckInputs correctly validates this transaction under all flags.
        ValidateCheckInputsForAllFlags(invalid_under_p2sh_tx, SCRIPT_VERIFY_P2SH, true, false);
    }

    // Test CHECKLOCKTIMEVERIFY
    {
        CMutableTransaction invalid_with_cltv_tx;
        invalid_with_cltv_tx.nVersion = 1;
        invalid_with_cltv_tx.nLockTime = 100;
        invalid_with_cltv_tx.vin.resize(1);
        invalid_with_cltv_tx.vin[0].prevout.hash = spend_tx.GetHash();
        invalid_with_cltv_tx.vin[0].prevout.n = 2;
        invalid_with_cltv_tx.vin[0].nSequence = 0;
        invalid_with_cltv_tx.vout.resize(1);
        invalid_with_cltv_tx.vout[0].nValue = 11*CENT;
        invalid_with_cltv_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(spend_tx.vout[2].scriptPubKey, invalid_with_cltv_tx, 0, SIGHASH_ALL, 0, SIGVERSION_BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        invalid_with_cltv_tx.vin[0].scriptSig = CScript() << vchSig << 101;

        ValidateCheckInputsForAllFlags(invalid_with_cltv_tx, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, true, true);

        // Make it valid, and check again
        invalid_with_cltv_tx.vin[0].scriptSig = CScript() << vchSig << 100;
        CValidationState state;
        PrecomputedTransactionData txdata(invalid_with_cltv_tx);
        BOOST_CHECK(CheckInputs(invalid_with_cltv_tx, state, pcoinsTip, true, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, true, true, txdata, nullptr));
    }

    // TEST CHECKSEQUENCEVERIFY
    {
        CMutableTransaction invalid_with_csv_tx;
        invalid_with_csv_tx.nVersion = 2;
        invalid_with_csv_tx.vin.resize(1);
        invalid_with_csv_tx.vin[0].prevout.hash = spend_tx.GetHash();
        invalid_with_csv_tx.vin[0].prevout.n = 3;
        invalid_with_csv_tx.vin[0].nSequence = 100;
        invalid_with_csv_tx.vout.resize(1);
        invalid_with_csv_tx.vout[0].nValue = 11*CENT;
        invalid_with_csv_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(spend_tx.vout[3].scriptPubKey, invalid_with_csv_tx, 0, SIGHASH_ALL, 0, SIGVERSION_BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        invalid_with_csv_tx.vin[0].scriptSig = CScript() << vchSig << 101;

        ValidateCheckInputsForAllFlags(invalid_with_csv_tx, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, true, true);

        // Make it valid, and check again
        invalid_with_csv_tx.vin[0].scriptSig = CScript() << vchSig << 100;
        CValidationState state;
        PrecomputedTransactionData txdata(invalid_with_csv_tx);
        BOOST_CHECK(CheckInputs(invalid_with_csv_tx, state, pcoinsTip, true, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, true, true, txdata, nullptr));
    }

    // TODO: add tests for remaining script flags

    // Test that passing CheckInputs with a valid witness doesn't imply success
    // for the same tx with a different witness.
    {
        CMutableTransaction valid_with_witness_tx;
        valid_with_witness_tx.nVersion = 1;
        valid_with_witness_tx.vin.resize(1);
        valid_with_witness_tx.vin[0].prevout.hash = spend_tx.GetHash();
        valid_with_witness_tx.vin[0].prevout.n = 1;
        valid_with_witness_tx.vout.resize(1);
        valid_with_witness_tx.vout[0].nValue = 11*CENT;
        valid_with_witness_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        SignatureData sigdata;
        ProduceSignature(MutableTransactionSignatureCreator(&keystore, &valid_with_witness_tx, 0, 11*CENT, SIGHASH_ALL), spend_tx.vout[1].scriptPubKey, sigdata);
        UpdateTransaction(valid_with_witness_tx, 0, sigdata);

        // Check: this tx is valid.
        std::vector<CScriptCheck> scriptchecks;
        PrecomputedTransactionData txdata(valid_with_witness_tx);
        BOOST_CHECK(CheckInputs(valid_with_witness_tx, state, pcoinsTip, true, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true, true, txdata, nullptr));
        // Check: script executions are not returned when re-evaluating this tx
        BOOST_CHECK(CheckInputs(valid_with_witness_tx, state, pcoinsTip, true, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true, true, txdata, &scriptchecks));
        BOOST_CHECK(scriptchecks.empty());
        // Explicitly test all script combinations.
        ValidateCheckInputsForAllFlags(valid_with_witness_tx, 0, true, false);

        // Remove the witness, and check that it is now invalid.
        valid_with_witness_tx.vin[0].scriptWitness.SetNull();
        PrecomputedTransactionData txdata_invalid(valid_with_witness_tx);
        BOOST_CHECK(!CheckInputs(valid_with_witness_tx, state, pcoinsTip, true, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true, true, txdata_invalid, nullptr));
        BOOST_CHECK(CheckInputs(valid_with_witness_tx, state, pcoinsTip, true, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true, true, txdata_invalid, &scriptchecks));
        BOOST_CHECK_EQUAL(scriptchecks.size(), 1);

        // Make sure that it doesn't get added to cache when calling with
        // scriptchecks.
        BOOST_CHECK(CheckInputs(valid_with_witness_tx, state, pcoinsTip, true, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true, true, txdata_invalid, &scriptchecks));
        BOOST_CHECK_EQUAL(scriptchecks.size(), 2);

        //... Even if the tx is valid
        BOOST_CHECK(CheckInputs(valid_with_witness_tx, state, pcoinsTip, true, SCRIPT_VERIFY_NONE, true, true, txdata_invalid, &scriptchecks));
        BOOST_CHECK_EQUAL(scriptchecks.size(), 3);

        // This transaction is valid without SCRIPT_VERIFY_WITNESS
        BOOST_CHECK(CheckInputs(valid_with_witness_tx, state, pcoinsTip, true, SCRIPT_VERIFY_P2SH, true, true, txdata_invalid, nullptr));
        ValidateCheckInputsForAllFlags(valid_with_witness_tx, SCRIPT_VERIFY_WITNESS, true, false);
    }
}

BOOST_AUTO_TEST_SUITE_END()
