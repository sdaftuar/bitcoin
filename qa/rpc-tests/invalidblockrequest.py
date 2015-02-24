#!/usr/bin/env python2
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from test_framework import BitcoinTestFramework
from util import *
from comptool import *
from mininode import *
from blocktools import *
from blockstore import BlockStore
import logging
import copy


'''
In this test we connect to one node over p2p, and test block requests:
1) Valid blocks should be requested and become chain tip.
2) Invalid block with duplicated transaction should be re-requested.
3) Invalid block with bad coinbase value should be rejected and not
re-requested.
'''

class InvalidBlockRequestTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_option("--testbinary", dest="testbinary", default="bitcoind",
                          help="Binary to test")
        parser.add_option("--refbinary", dest="refbinary", default="bitcoind",
                          help="Binary to use as baseline")

    def setup_chain(self):
        print "Initializing test directory "+self.options.tmpdir
        initialize_chain_clean(self.options.tmpdir, 2)

    ''' Can either run this test as 1 node with expected answers, or two and compare them. 
        Change the "outcome" variable from each TestInstance object to only do the comparison. '''
    def setup_network(self):
        self.nodes = start_nodes(1, self.options.tmpdir, 
                                    extra_args=[['-debug', '-whitelist=127.0.0.1']],
                                    binary=[self.options.testbinary])
        #self.nodes = start_nodes(2, self.options.tmpdir, 
        #                                 extra_args=[['-debug', '-whitelist=127.0.0.1'],
        #                                             ['-debug', '-whitelist=127.0.0.1']],
        #                                 binary=[self.options.refbinary, self.options.testbinary])

    def run_test(self):
        test = TestManager(self, self.options.tmpdir)
        test.add_all_connections(self.nodes)
        self.tip = None
        self.block_time = None
        NetworkThread().start() # Start up network handling in another thread
        test.run()

    def get_next_test_case(self, counter):
        if self.tip is None:
            self.tip = int ("0x" + self.nodes[0].getbestblockhash() + "L", 0)
        if self.block_time is None:
            import time
            self.block_time = int(time.time())+1
        if counter == 1:
            '''
            Create a new block with an anyone-can-spend coinbase
            '''
            block = create_block(self.tip, create_coinbase(), self.block_time)
            self.block_time += 1
            block.solve()
            # Save the coinbase for later
            self.block1 = block
            self.tip = block.sha256
            return TestInstance([[block, True]])
        elif counter == 2:
            ''' 
            Now we need that block to mature so we can spend the coinbase.
            Get the new tip to build the next block.
            '''
            test = TestInstance(sync_every_block=False)
            for i in xrange(100):
                block = create_block(self.tip, create_coinbase(), self.block_time)
                block.solve()
                self.tip = block.sha256
                self.block_time += 1
                test.blocks_and_transactions.append([block, True])
            return test
        elif counter == 3:
            ''' 
            Now we use merkle-root malleability to generate an invalid block with
            same blockheader.
            Manufacture a block with 3 transactions (coinbase, spend of prior
            coinbase, spend of that spend).  Duplicate the 3rd transaction to 
            leave merkle root and blockheader unchanged but invalidate the block.
            '''
            block2 = create_block(self.tip, create_coinbase(), self.block_time)
            self.block_time += 1

            # chr(81) is OP_TRUE
            tx1 = create_transaction(self.block1.vtx[0], chr(81), 50*100000000)
            tx2 = create_transaction(tx1, chr(81), 50*100000000)

            block2.vtx.extend([tx1, tx2])
            block2.hashMerkleRoot = block2.calc_merkle_root()
            block2.rehash()
            block2.solve()
            orig_hash = block2.sha256
            block2_orig = copy.deepcopy(block2)

            # Mutate block 2
            block2.vtx.append(tx2)
            assert_equal(block2.hashMerkleRoot, block2.calc_merkle_root())
            assert_equal(orig_hash, block2.rehash())
            assert(block2_orig.vtx != block2.vtx)

            self.tip = block2.sha256
            return TestInstance([[block2, False], [block2_orig, True]])

        elif counter == 4:
            '''
            Make sure that a totally screwed up block is not valid.
            '''
            block3 = create_block(self.tip, create_coinbase(), self.block_time)
            self.block_time += 1
            block3.vtx[0].vout[0].nValue = 100*100000000 # Too high!
            block3.vtx[0].sha256=None
            block3.vtx[0].calc_sha256()
            block3.hashMerkleRoot = block3.calc_merkle_root()
            block3.rehash()
            block3.solve()

            return TestInstance([[block3, False]])
        else:
            return None


if __name__ == '__main__':
    InvalidBlockRequestTest().main()
