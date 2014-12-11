#!/usr/bin/env python2
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from test_framework import BitcoinTestFramework
from util import *
from mininode import *
from blocktools import *
import logging


'''
In this test we connect to one node over p2p, and test block requests:
1) Valid blocks should be requested and become chain tip.
2) Invalid block with duplicated transaction should be re-requested.
3) Invalid block with bad coinbase value should be rejected and not
re-requested.
'''

class TestManager(NodeConnCB):

    # set up NodeConnCB callbacks, overriding base class
    def on_getheaders(self, node, message):
        self.log.debug("got getheaders")
        response = self.block_store.headers_for(message.locator, message.hashstop)
        if response is not None:
            node.send_message(response)

    def on_block(self, node, message):
        self.curtime = message.block.nTime
        self.block_store.add_block(message.block)

    def on_reject(self, node, message):
        print "msg_reject ([%s])" % repr(message)

    def on_getdata(self, node, message):
        self.log.debug("got getdata %s" % repr(message))
        # Log the requests
        responses = []
        if len(message.inv) > 1:
            raise AssertionError("Only expect requests for 1 block at a time, got (%d)" % len(message.inv))
        for inv in message.inv:
            if inv.hash not in self.blockReqCounts:
                self.blockReqCounts[inv.hash] = 0
            self.blockReqCounts[inv.hash] += 1
            responses.extend(self.block_store.get_blocks([inv]))
            if self.blockReqCounts[inv.hash] > 1:
                if inv.hash == self.mutated_block_hash:
                    # Remove the dup so we return a legit block
                    # Wait for a signal that it's okay to send out this block
                    while self.okToSend != True:
                        time.sleep(1)
                    del responses[-1].block.vtx[-1]
        [ node.send_message(r) for r in responses ]
        
    def on_close(self, node):
        if not self.disconnectOkay:
            raise EarlyDisconnectError(0)

    def __init__(self):
        NodeConnCB.__init__(self)
        self.log = logging.getLogger("InvalidBlockRequestTest")
        self.create_callback_map()
        self.block_store = BlockStore()
        self.mutated_block_hash = 0L

    def add_new_connection(self, node):
        self.connection = node
        self.blockReqCounts = {}
        self.disconnectOkay = False

    def deliver_block(self, block):
        self.block_store.add_block(block)
        self.connection.send_message(msg_inv([CInv(2, block.sha256)]))

    # Get the tip (as uint256) from node after generating "count" blocks.
    def generate_block(self, count):
        self.connection.rpc.setgenerate(True, count)
        return self.get_tip()

    def get_tip(self):
        return int("0x" + self.connection.rpc.getbestblockhash() + "L", 0)

    # Wait up to max_time (in seconds) for node's tip to be expected_hash; 
    # return current tip
    def wait_for_tip(self, expected_hash, max_time):
        max_tries = max_time
        while self.get_tip() != expected_hash and max_tries > 0:
            time.sleep(1)
            max_tries -= 1
        return self.get_tip()

    def run(self):
        try:
            '''
            Generate a block and get the tip
            '''
            initial_height = self.connection.rpc.getblockcount()  
            tip256 = self.generate_block(1)
            expected_height = initial_height + 1

            time.sleep(1) # Give us time to receive the block

            '''
            Create a new block with an anyone-can-spend coinbase
            '''
            block = create_block(tip256, create_coinbase())
            block.solve()
            self.deliver_block(block)
            expected_height += 1

            '''
            Make sure the node got the right tip
            '''
            assert_equal(self.wait_for_tip(block.sha256, 20), block.sha256)
            print "First block accepted"

            ''' 
            Now we need that block to mature so we can spend the coinbase.
            Get the new tip to build the next block.
            '''
            tip256 = self.generate_block(100)
            expected_height += 100
            assert_equal(expected_height, self.connection.rpc.getblockcount())

            time.sleep(5) # Time to receive the incoming blocks
            
            ''' 
            Now we use merkle-root malleability to generate an invalid block with
            same blockheader.
            Manufacture a block with 3 transactions (coinbase, spend of prior
            coinbase, spend of that spend).  Duplicate the 3rd transaction to 
            leave merkle root and blockheader unchanged but invalidate the block.
            '''
            block2 = create_block(tip256, create_coinbase(), self.curtime)

            # chr(81) is OP_TRUE
            tx1 = create_transaction(block.vtx[0], chr(81), 50*100000000)
            tx2 = create_transaction(tx1, chr(81), 50*100000000)

            block2.vtx.extend([tx1, tx2])
            block2.hashMerkleRoot = block2.calc_merkle_root()
            block2.rehash()
            block2.solve()
            orig_hash = block2.sha256

            # Mutate block 2
            block2.vtx.append(tx2)
            assert_equal(block2.hashMerkleRoot, block2.calc_merkle_root())
            assert_equal(orig_hash, block2.rehash())

            self.mutated_block_hash = block2.sha256

            '''
            Try to deliver block 2
            The node we're testing might immediately re-request the block after receiving
            the bad one, so we use okToSend as a signal to getdata indicating delivery
            of the non-mutated block is permitted. 
            '''
            self.okToSend = False
            self.deliver_block(block2)

            '''
            Make sure block2 doesn't make it to be the tip.
            Wait for the block to be requested, then give it a second to process.
            '''
            while block2.sha256 not in self.blockReqCounts:
                time.sleep(1)

            time.sleep(1) 
            
            current_height = self.connection.rpc.getblockcount() 
            assert_equal(current_height, expected_height)
            print "Mutated block not accepted"

            # Now try delivering again, this time the legit version
            self.okToSend = True
            self.deliver_block(block2)

            assert_equal(self.wait_for_tip(block2.sha256, 20), block2.sha256)
            assert_equal(self.blockReqCounts[block2.sha256], 2)
            print "Fixed block requested again and accepted"

            '''
            Make sure that a totally screwed up block is never re-requested.
            '''
            block3 = create_block(block2.sha256, create_coinbase(), self.curtime)
            block3.vtx[0].vout[0].nValue = 100*100000000 # Too high!
            block3.vtx[0].sha256=None
            block3.vtx[0].calc_sha256()
            block3.hashMerkleRoot = block3.calc_merkle_root()
            block3.rehash()
            block3.solve()

            self.deliver_block(block3)
            while block3.sha256 not in self.blockReqCounts:
                time.sleep(1)
            time.sleep(1) 
            assert_equal(self.get_tip(), block2.sha256)
            print "Invalid block not accepted"

            self.deliver_block(block3)
            time.sleep(10)
            if self.blockReqCounts[block3.sha256] > 1:
                raise AssertionError("Invalid block was re-requested")
            else:
                print "Invalid block not re-requested"

        except AssertionError as e:
            print "TEST FAILED: ", e.args

        self.disconnectOkay = True
        self.connection.disconnect_node()

        
class InvalidBlockRequestTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_option("--testbinary", dest="testbinary", default="bitcoind",
                          help="Binary to test")

    def setup_chain(self):
        print "Initializing test directory "+self.options.tmpdir
        initialize_chain_clean(self.options.tmpdir, 1)

    def setup_network(self):
        self.nodes = start_nodes(1, self.options.tmpdir, 
                                 extra_args=[['-debug', '-whitelist=127.0.0.1']],
                                 binary=[self.options.testbinary])

    def sync_all(self): pass
    def join_network(self): pass
    def split_network(self): pass

    def run_test(self):
        test = TestManager()

        test.add_new_connection(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], test))

        NetworkThread().start() # Start up network handling in another thread
        test.run()

if __name__ == '__main__':
    InvalidBlockRequestTest().main()
