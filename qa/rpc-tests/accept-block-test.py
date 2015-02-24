#!/usr/bin/env python2
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from mininode import *
from test_framework import BitcoinTestFramework
from util import *
import time
from blocktools import create_block, create_coinbase
from expect_framework import ExpectNode

'''
AcceptBlockTest -- test changes to accept block processing.

Can run in 2 modes, with or without --whitelist.

1. Send a block building the tip (should advance the tip).
2. Send a block that forks the chain, building on the original tip
(whitelisted => node should process; otherwise node should only accept header for this block).
3. Send another block that builds on the forking block.
(whitelisted => node should reorg to longer chain; otherwise node should only have that chain
as valid-headers).

Additionally, for non-whitelisted mode only:
4. Send a duplicate of block 2 (should be ignored, since unrequested).
5. Send inv for block 3 (should trigger getdata for block 2).
6. Send block 2 (should advance the tip).
'''

class AcceptBlockTest(BitcoinTestFramework, ExpectNode):

    def __init__(self):
        ExpectNode.__init__(self)

    def add_options(self, parser):
        parser.add_option("--testbinary", dest="testbinary", default="bitcoind",
                          help="bitcoind binary to test")
        parser.add_option("--whitelist", dest="whitelist", default=False, action="store_true",
                          help="Use --whitelist to test behavior when whitelisting peer")

    def setup_chain(self):
        initialize_chain_clean(self.options.tmpdir, 1)

    def setup_network(self):
        args = ['-debug']
        if self.options.whitelist:
            args += ['-whitelist=127.0.0.1']
        self.nodes = start_nodes(1, self.options.tmpdir, extra_args=[args],
                                 binary=[self.options.testbinary])

    def run_test(self):
        self.connection = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self)
        NetworkThread().start() # Start up network handling in another thread

        # Test begins here
        self.wait_for_verack()

        # Leave IBD
        self.connection.rpc.setgenerate(True, 1)
        self.wait_until(msg_inv())  # Expect an inv for the new block

        self.tip = int ("0x" + self.connection.rpc.getbestblockhash() + "L", 0)

        # First send one block that builds on the tip.
        # This should be accepted.
        self.block = create_block(self.tip, create_coinbase(), time.time()+1)
        self.block.solve()
        self.send_message([msg_block(self.block)], response_expected=False)
        time.sleep(1)
        assert(self.connection.rpc.getblockcount() == 2)

        # Now send another block that builds on the original tip.
        self.block2 = create_block(self.tip, create_coinbase(), self.block.nTime+1)
        self.block2.solve()

        self.send_message([msg_block(self.block2)], response_expected=False)
        time.sleep(1)  # Give time to process the block

        for x in self.connection.rpc.getchaintips():
            if x['hash'] == self.block2.hash:
                if self.options.whitelist:
                    assert_equal(x['status'], "valid-headers")
                else:
                    assert_equal(x['status'], "headers-only")

        print "Fork block 2 processed as expected with whitelist =", self.options.whitelist

        # Now send another block that builds on the forking chain.
        block3 = create_block(self.block2.sha256, create_coinbase(), self.block2.nTime+1)
        block3.solve()
        self.send_message([msg_block(block3)], response_expected=False)
        time.sleep(1)  # Time to process the block

        # This block should be accepted since it's got more work...
        if self.options.whitelist:
            assert_equal(self.connection.rpc.getblockcount(), 3)
            print "Successfully reorged to length 3 chain from whitelisted peer"
        else:
            for x in self.connection.rpc.getchaintips():
                if x['hash'] == block3.hash:
                    assert_equal(x['status'], "headers-only")

            # Test handling of duplicate block 2.
            self.send_message([msg_block(self.block2)], response_expected=False)

            # Here, if the sleep is too short, the test could falsely succeed (if the 
            # node hasn't processed the block by the time the sleep returns, and then 
            # the node processes it and incorrectly advances the tip).
            # Luckily this would be caught later on, when we verify that an inv triggers
            # a getdata request for block2.
            time.sleep(1)
            assert_equal(self.connection.rpc.getblockcount(), 2)
            print "Unrequested duplicate block 2 was ignored"

            # Try to get node to request block 2.
            # Poke the node with an inv for block 3 and see if that triggers a
            # getdata on block 2 (it should, unless block 3 hadn't been processed,
            # in which case we'll first see a getdata for block 3).
            self.send_message([msg_inv([CInv(2, block3.sha256)])])
            [gd] = self.expect([msg_getdata()])
            assert_equal(len(gd.inv), 1)
            assert_equal(gd.inv[0].hash, self.block2.sha256)
            print "Inv for block 3 successfully triggered get data for block 2"

            self.send_message([msg_block(self.block2)], response_expected=False)
            time.sleep(1)  # Give time to process the block
            assert_equal(self.connection.rpc.getblockcount(), 3)
            print "Successfully reorged to length 3 chain from non-whitelisted peer"

        print "Success: [%s]" % self.connection.rpc.getblockcount()
        self.connection.disconnect_node()

if __name__ == '__main__':
    AcceptBlockTest().main()
