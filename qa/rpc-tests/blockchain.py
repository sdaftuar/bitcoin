#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test RPC calls related to blockchain state. Tests correspond to code in
# rpc/blockchain.cpp.
#

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import (
    assert_equal,
    assert_raises,
    assert_is_hex_string,
    assert_is_hash_string,
    start_nodes,
    connect_nodes_bi,
)


class BlockchainTest(BitcoinTestFramework):
    """
    Test blockchain-related RPC calls:

        - gettxoutsetinfo
        - getblockhash
        - getblock
        - getblockheader
        - verifychain

    """

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = False
        self.num_nodes = 2

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        node = self.nodes[0]

        # Test gettxoutsetinfo()
        ########################

        res = node.gettxoutsetinfo()

        assert_equal(res['total_amount'], Decimal('8725.00000000'))
        assert_equal(res['transactions'], 200)
        assert_equal(res['height'], 200)
        assert_equal(res['txouts'], 200)
        assert_equal(res['bytes_serialized'], 13924),
        assert_equal(len(res['bestblock']), 64)
        assert_equal(len(res['hash_serialized']), 64)

        # Test getblockhash()
        #####################

        besthash = node.getbestblockhash()

        # getblockhash(-1) gets the hash of the best block.
        assert_equal(besthash, node.getblockhash(-1))

        # try to get a block higher than the best block (fails)
        assert_raises(
            JSONRPCException, lambda: node.getblockhash(201))

        # Test getblock() and getblockheader()
        ######################################

        # try to get a block with a bad hash (fails)
        assert_raises(
            JSONRPCException, lambda: node.getblockheader('nonsense'))

        secondbesthash = node.getblockhash(199)
        header = node.getblockheader(besthash)

        assert_equal(header['hash'], besthash)
        assert_equal(header['height'], 200)
        assert_equal(header['confirmations'], 1)
        assert_equal(header['previousblockhash'], secondbesthash)
        assert_is_hex_string(header['chainwork'])
        assert_is_hash_string(header['hash'])
        assert_is_hash_string(header['previousblockhash'])
        assert_is_hash_string(header['merkleroot'])
        assert_is_hash_string(header['bits'], length=None)
        assert isinstance(header['time'], int)
        assert isinstance(header['mediantime'], int)
        assert isinstance(header['nonce'], int)
        assert isinstance(header['version'], int)
        assert isinstance(int(header['versionHex'], 16), int)
        assert isinstance(header['difficulty'], Decimal)

        # get a block header by specifying a height
        assert_equal(header, node.getblockheader(height=-1))

        # try to get a block header by specifying a height and a hash (fails)
        assert_raises(
            JSONRPCException, lambda: node.getblockheader(blockhash=besthash, height=-1))

        # Test verifychain()
        ####################

        self.nodes[0].verifychain(4, 0)

if __name__ == '__main__':
    BlockchainTest().main()
