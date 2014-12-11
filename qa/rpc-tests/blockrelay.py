#!/usr/bin/env python2
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from mininode import *
from test_framework import BitcoinTestFramework
from util import *
import logging


'''
In this test we connect to two nodes, node0 and node1.  We turn on
mining on node0, retrieve the blocks, and then inv them to node1, in
several rounds.
We test that node1 requests blocks no more than once, and that its
tip and mempool match node0's after each round of blocks.
'''

class TestManager(NodeConnCB):

    def on_block(self, node, message):
        self.log.debug("got block from node %d" % self.get_node_index(node))
        self.block_store.add_block(message.block)

        inv = CInv(2, message.block.sha256)
        self.current_invs.append(inv) # We'll periodically send these out

    # set up NodeConnCB callbacks, overriding base class
    def on_getheaders(self, node, message):
        self.log.debug("got getheaders from node %d", self.get_node_index(node))
        response = self.block_store.headers_for(message.locator, message.hashstop)
        if response is not None:
            node.send_message(response)

    def on_reject(self, node, message):
        print "msg_reject (node: %d [%s])" % (self.get_node_index(node), repr(message))

    def on_getdata(self, node, message):
        index = self.get_node_index(node)
        self.log.debug("responding to getdata from node %d" % index)
        responses = self.block_store.get_blocks(message.inv)
        [ node.send_message(r) for r in self.block_store.get_blocks(message.inv) ]

        # Log the requests
        for inv in message.inv:
            if inv.hash not in self.blockReqCounts[index]:
                self.blockReqCounts[index][inv.hash] = 0
            self.blockReqCounts[index][inv.hash] += 1

    def on_close(self, node):
        if not self.disconnectOkay[self.get_node_index(node)]:
            raise EarlyDisconnectError(self.get_node_index(node))


    # Return as soon as we get a header from all nodes or
    # or 10 seconds have gone by.  If checkVal is specified,
    # don't return early unless all nodes are at the specified
    # block hash
    def synchronize_nodes(self, checkVal, waitTime=10):
        for i in range(waitTime*10):
            blockhashes = [ x.rpc.getbestblockhash() for x in self.connections ]
            errorValues = [ y for y in blockhashes if y != checkVal ]
            if len(errorValues) > 0:
                time.sleep(0.1)
            else:
                break
        return

    def check_all_same(self):
        # Check for same tip via rpc
        try:
            blockhashes = [ x.rpc.getbestblockhash() for x in self.connections ]
            errorValues = [ y for y in blockhashes if y != blockhashes[0] ]
            if len(errorValues) > 0:
                print "blockhashes differ: ", blockhashes[0], errorValues
                return False
            
            # Check for same mempool via rpc
            rawmempools = [ x.rpc.getrawmempool() for x in self.connections ]
            errorValues = [ y for y in rawmempools if y != rawmempools[0] ]
            if len(errorValues) > 0:
                print "mempools differ", rawmempools[0], errorValues
                return False
        except:
            # Something went wrong, maybe a node died?
            raise EarlyDisconnectError(-1)
        
        return True

    def get_node_index(self, node):
        return self.connections.index(node)

    def __init__(self):
        NodeConnCB.__init__(self)
        self.log = logging.getLogger("BlockRelayTest")

        self.create_callback_map()
        self.block_store = BlockStore()

        self.current_invs = []
        self.failures = []

        # State we keep for each connection (use a common index into each)
        self.connections = []
        self.blockReqCounts = []
        self.disconnectOkay = []

    def add_new_connection(self, node):
        self.connections.append(node)
        self.blockReqCounts.append( {} )
        self.disconnectOkay.append(False)

    def run(self):
        fail = False
        numBlocksToGenerate = [ 1, 1, 1, 1, 2, 4, 8, 16, 32, 64 ]
        for count in range(len(numBlocksToGenerate)):
            try:
                self.current_invs = []

                self.connections[0].rpc.setgenerate(True, numBlocksToGenerate[count])
                tip = self.connections[0].rpc.getbestblockhash()
                tip256 = int("0x" + tip + "L", 0)
                self.log.debug("tip is %064x" %tip256)
                max_tries = 20 # Shouldn't take more than 20 seconds to sync
                while (self.block_store.currentBlock != tip256 and max_tries > 0):
                    time.sleep(1) 
                    max_tries -= 1
                if max_tries == 0:
                    print "Error getting all data from node 0 (did bitcoind die?), test failed"
                    raise EarlyDisconnectError(0)

                # Randomly sort the inv's and try to remove one (assuming it's not the tip):
                # Node1 should figure out how to request everything
                if len(self.current_invs) >= 2:
                    last_inv = self.current_invs[-1]
                    random.shuffle(self.current_invs)
                    if self.current_invs.pop() == last_inv:
                        self.current_invs.append(last_inv)
                    self.log.debug("removed %d elements from inv array", 
                                    numBlocksToGenerate[count] - len(self.current_invs))
                self.connections[1].send_message(msg_inv(self.current_invs))

                self.synchronize_nodes(tip) # Wait until 10 seconds go by or all nodes have expected tip
                
                # check that they have same tip, mempool, etc
                if self.check_all_same() is False:
                    print "Error, test failed on loop iteration %d, tip %064x" % (count, tip256)
                    self.failures.append(count)
                else:
                    print "Round %d: success" % count

                for m in self.blockReqCounts:
                    for key in m:
                        if m[key] > 1:
                            print "Error, test failed: block %064x requested more than once" % key
                            self.failures.append(count)

            except EarlyDisconnectError: 
                print "Error: detected potential early disconnect, exiting test"
                self.failures.append(count)
                break

        self.disconnectOkay = [True, True]
        [ x.disconnect_node() for x in self.connections ]

        
class BlockRelayTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_option("--refbinary", dest="refbinary", default="bitcoind",
                          help="Binary to use for reference node (node 0)")
        parser.add_option("--testbinary", dest="testbinary", default="bitcoind",
                          help="Binary to test block relay behavior (node 1)")

    def setup_chain(self):
        print "Initializing test directory "+self.options.tmpdir
        initialize_chain_clean(self.options.tmpdir, 2)

    def setup_network(self):
        self.nodes = start_nodes(2, self.options.tmpdir, 
                                 extra_args=[['-debug', '-whitelist=127.0.0.1'], 
                                             ['-debug', '-whitelist=127.0.0.1']],
                                 binary=[self.options.refbinary, self.options.testbinary])

    def sync_all(self): pass
    def join_network(self): pass
    def split_network(self): pass

    def run_test(self):
        test = TestManager()

        for i in range(2):
            test.add_new_connection(NodeConn('127.0.0.1', p2p_port(i), self.nodes[i], test))

        NetworkThread().start() # Start up network handling in another thread
        test.run()

        if len(test.failures) > 0:
            raise AssertionError("Iterations failed: " + repr(test.failures))

if __name__ == '__main__':
    BlockRelayTest().main()
