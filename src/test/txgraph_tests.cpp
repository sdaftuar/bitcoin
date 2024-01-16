// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/txgraph.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(txgraph_tests)

BOOST_AUTO_TEST_CASE(TxEntryTest)
{
    TxEntry entry(100, 100);
}

BOOST_AUTO_TEST_SUITE_END()
