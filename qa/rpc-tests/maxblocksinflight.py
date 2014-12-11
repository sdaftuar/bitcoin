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
In this test we connect to one node over p2p and try various ways
to get the node to request more blocks in flight than it should.
'''

class TestManager(NodeConnCB):

    def on_block(self, node, message):
        pass

    # set up NodeConnCB callbacks, overriding base class
    def on_getheaders(self, node, message):
        pass

    def on_reject(self, node, message):
        print "msg_reject ([%s])" % repr(message)

    def on_getdata(self, node, message):
        self.log.debug("got getdata %s" % repr(message))
        # Log the requests
        for inv in message.inv:
            if inv.hash not in self.blockReqCounts:
                self.blockReqCounts[inv.hash] = 0
            self.blockReqCounts[inv.hash] += 1

    def on_close(self, node):
        if not self.disconnectOkay:
            raise EarlyDisconnectError(0)

    def __init__(self):
        NodeConnCB.__init__(self)
        self.log = logging.getLogger("BlockRelayTest")
        self.create_callback_map()

    def add_new_connection(self, node):
        self.connection = node
        self.blockReqCounts = {}
        self.disconnectOkay = False

    def run(self):
        try:
            fail = False
            numBlocksToGenerate = [ 8, 16, 128, 512, 1024, 4096, 8192, 40000, 80000 ]
            try:
                self.connection.rpc.setmocktime(1296688603)
            except: pass
            for count in range(len(numBlocksToGenerate)):
                current_invs = []
                for i in range(numBlocksToGenerate[count]):
                    current_invs.append(CInv(2, random.randrange(0, 1<<256)))
                    if len(current_invs) >= 50000:
                        self.connection.send_message(msg_inv(current_invs))
                        current_invs = []
                if len(current_invs) > 0:
                    self.connection.send_message(msg_inv(current_invs))
                
                # Wait and see how many blocks were requested
                time.sleep(2)

                total_requests = 0
                for key in self.blockReqCounts:
                    total_requests += self.blockReqCounts[key]
                    if self.blockReqCounts[key] > 1:
                        raise AssertionError("Error, test failed: block %064x requested more than once" % key)
                if total_requests > 128:
                    raise AssertionError("Error, too many blocks (%d) requested" % total_requests)
                print "Round %d: success (total requests: %d)" % (count, total_requests)
        except AssertionError as e:
            print "TEST FAILED: ", e.args

        self.disconnectOkay = True
        self.connection.disconnect_node()

        
class MaxBlocksInFlightTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_option("--testbinary", dest="testbinary", default="bitcoind",
                          help="Binary to test max block requests behavior")

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
    MaxBlocksInFlightTest().main()
