#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the listsincelast RPC."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class ListSinceBlockTest (BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 4

    def test_reorg(self):
        '''
        `listsinceblock` did not behave correctly when handed a block that was
        no longer in the main chain:

             ab0
          /       \
        aa1 [tx0]   bb1
         |           |
        aa2         bb2
         |           |
        aa3         bb3
                     |
                    bb4

        Consider a client that has only seen block `aa3` above. It asks the node
        to `listsinceblock aa3`. But at some point prior the main chain switched
        to the bb chain.

        Previously: listsinceblock would find height=4 for block aa3 and compare
        this to height=5 for the tip of the chain (bb4). It would then return
        results restricted to bb3-bb4.

        Now: listsinceblock finds the fork at ab0 and returns results in the
        range bb1-bb4.

        This test only checks that [tx0] is present.
        '''

        assert_equal(self.is_network_split, False)
        self.nodes[2].generate(101)
        self.sync_all()

        assert_equal(self.nodes[0].getbalance(), 0)
        assert_equal(self.nodes[1].getbalance(), 0)
        assert_equal(self.nodes[2].getbalance(), 50)
        assert_equal(self.nodes[3].getbalance(), 0)

        # Split network into two
        self.split_network()
        assert_equal(self.is_network_split, True)

        # send to nodes[0] from nodes[2]
        senttx = self.nodes[2].sendtoaddress(self.nodes[0].getnewaddress(), 1)

        # generate on both sides
        lastblockhash = self.nodes[1].generate(6)[5]
        self.nodes[2].generate(7)
        print('lastblockhash=%s' % (lastblockhash))

        self.sync_all()

        self.join_network()

        # listsinceblock(lastblockhash) should now include tx, as seen from nodes[0]
        lsbres = self.nodes[0].listsinceblock(lastblockhash)
        found = False
        for tx in lsbres['transactions']:
            if tx['txid'] == senttx:
                found = True
                break
        assert_equal(found, True)

    def test_reorg3(self):
        '''
        Same as above, except there are now three conflicting chains.
        Use invalidateblock() on node1 to allow it to mine different
        chains from a common fork point.
        '''

        assert_equal(self.is_network_split, False)

        # send to nodes[0] from nodes[2]
        senttx = self.nodes[2].sendtoaddress(self.nodes[0].getnewaddress(), 1)

        self.sync_all() # Ensure the tx has propagated to all nodes

        generated_tips = [] # track generated tips to sanity check the test

        # generate 1 chain, and sync
        blockhashes = self.nodes[1].generate(6)
        lastblockhash = blockhashes[-1]
        generated_tips.append(lastblockhash)
        print('lastblockhash=%s' % (lastblockhash))
        self.sync_all()

        # generate an alternate chain that is longer
        self.nodes[1].invalidateblock(blockhashes[0])
        blockhashes = self.nodes[1].generate(7)
        generated_tips.append(blockhashes[-1])
        self.sync_all()

        # generate one more alternate chain that is longer still
        self.nodes[1].invalidateblock(blockhashes[0])
        blockhashes = self.nodes[1].generate(8)
        generated_tips.append(blockhashes[-1])
        self.sync_all()

        # node0 should have all 3 chains (or else this test is broken!)
        tips = [x['hash'] for x in self.nodes[0].getchaintips()]
        assert(len(tips) >= 3)
        for t in generated_tips:
            assert(t in tips)

        # listsinceblock(lastblockhash) should now include tx, as seen from nodes[0]
        lsbres = self.nodes[0].listsinceblock(lastblockhash)
        found = False
        for tx in lsbres['transactions']:
            if tx['txid'] == senttx:
                found = True
                break
        assert_equal(found, True)

    def run_test(self):
        self.test_reorg()
        self.test_reorg3()

if __name__ == '__main__':
    ListSinceBlockTest().main()
