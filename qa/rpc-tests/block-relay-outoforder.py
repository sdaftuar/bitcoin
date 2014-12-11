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
We have two nodes: node0 and node1.
'''

'''
This is a simulation of the relay node client.
It ignores all incoming messages, but when told to provide
a block to the node it sends an inv and the block.
'''
class SimRelayNode(NodeConnCB):
    def __init__(self):
        NodeConnCB.__init__(self)
        self.create_callback_map()
    def add_connection(self, node):
        self.node = node
    def set_block_store(self, block_store):
        self.block_store = block_store

    def on_block(self, node, message):
        print "RelayNode: got block from peer [%s]" % repr(CBlockHeader(message.block))
    def on_getheaders(self, node, message):
        print "RelayNode: ignoring getheaders"
        pass
    def on_headers(self, node, message):
        print "RelayNode: ignoring headers"
        pass
    def on_getdata(self, node, message):
        print "RelayNode: received getdata for %s" % repr(message)
        pass
    def on_inv(self, node, message):
        print "RelayNode: got inv"
        pass
    def provide_block(self, block):
        self.node.send_message(msg_inv([CInv(2, block.sha256)]))
        self.node.send_message(msg_block(block))

    def send_message(self, message):
        self.node.send_message(message)

'''
This is a partial simulation of how a regular outbound connection
might behave -- it responds to getheaders and getdata messages for
blocks it knows about, but otherwise does nothing.
'''

class RegularNode(SimRelayNode):
    def on_getdata(self, node, message):
        responses = self.block_store.get_blocks(message.inv)
        [ node.send_message(r) for r in self.block_store.get_blocks(message.inv) ]
    def on_getheaders(self, node, message):
        response = self.block_store.headers_for(message.locator, message.hashstop)
        if response is not None:
            node.send_message(response)

'''
ListenerNode: save everything we get
'''
class ListenerNode(SimRelayNode):
    def __init__(self):
        SimRelayNode.__init__(self)
        self.current_invs = []
    def on_block(self, node, message):
        self.block_store.add_block(message.block)
        self.current_invs.append(message.block.sha256)
    def on_inv(self, node, message):
        want = msg_getdata()
        for i in message.inv:
            if i.type != 0:
                want.inv.append(i)
        if len(want.inv):
            node.send_message(want)

class TestManager(NodeConnCB):
    def add_relay(self, relay):
        self.relay = relay

    def __init__(self):
        NodeConnCB.__init__(self)
        self.log = logging.getLogger("BlockRelayTest")
        self.block_store = BlockStore()

    def add_connections(self, connections):
        self.connections = connections

    def run(self):
        [ x.set_block_store(self.block_store) for x in self.connections ]
        self.connections[0].node.rpc.setgenerate(True, 10)

        while len(self.connections[0].current_invs) < 10:
            time.sleep(1)
        print "Initial chain complete, using relay to deliver"
        for x in self.connections[0].current_invs:
            self.relay.provide_block(self.block_store.blockMap[x])
        while self.connections[1].node.rpc.getblockcount() < 10:
            time.sleep(1)
        print "Initial chain synced to node1"
            
        print "Creating fork (3 blocks)"
        self.connections[0].current_invs = []

        self.connections[1].node.rpc.setgenerate(True, 1)
        print self.connections[0].node.rpc.setgenerate(True, 3)
        time.sleep(1)

        while len(self.connections[0].current_invs) < 3:
            time.sleep(1)

        print "Got all blocks from node0, sending second to node1 via relay"
        self.relay.provide_block(self.block_store.blockMap[self.connections[0].current_invs[-2]])

        print "Now delivering inv for last block via regular node (nonpreferred) connection"
        self.connections[1].send_message(msg_inv([CInv(2, self.connections[0].current_invs[-1])]))
        time.sleep(5)

        print self.connections[1].node.rpc.getpeerinfo()
        print "Now generating 10 more blocks and directly connect the two nodes"
        connect_nodes(self.connections[0].node.rpc, 1)
        connect_nodes(self.connections[1].node.rpc, 0)
        self.connections[0].node.rpc.setgenerate(True, 10)
        while len(self.connections[0].current_invs) < 10:
            time.sleep(1)
        
        print [ x.node.rpc.getblockcount() for x in self.connections ]

#assert_equal(self.connections[1].node.rpc.getbestblockhash(), self.connections[0].node.rpc.getbestblockhash())

        self.disconnectOkay = [True, True]
        [ x.node.disconnect_node() for x in self.connections ]

    def add_reg_node(self, regnode):
        self.regnode = regnode
        
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
        simrelay = SimRelayNode()
        # ListenerNode is connected to node0, RegularNode to node1. The relay is also connected to node1.
        connections = [ ListenerNode(), RegularNode() ]

        simrelay.add_connection(NodeConn('127.0.0.1', p2p_port(1), self.nodes[1], simrelay))
        for i in range(2):
            connections[i].add_connection(NodeConn('127.0.0.1', p2p_port(i), self.nodes[i], connections[i]))

        test.add_relay(simrelay)
        test.add_connections(connections)
        NetworkThread().start() # Start up network handling in another thread
        test.run()

        if len(test.failures) > 0:
            raise AssertionError("Iterations failed: " + repr(test.failures))

if __name__ == '__main__':
    BlockRelayTest().main()
