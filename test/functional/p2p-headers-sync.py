#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test implementation of getcmpcthdrs/rgetheaders"""

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import create_block, create_coinbase

MAX_CMPCT_HEADER_RESULTS = 2500

class TestNode(NodeConnCB):
    def __init__(self):
        super().__init__()

    def get_headers(self, locator, hashstop):
        msg = msg_getheaders()
        msg.locator.vHave = locator
        msg.hashstop = hashstop
        self.connection.send_message(msg)

    def on_headers(self, conn, message):
        if len(message.headers):
            self.block_announced = True
            message.headers[-1].calc_sha256()
            self.last_blockhash_announced = message.headers[-1].sha256

class HeadersSyncTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    # Send getcmpcthdrs, and verify the response is correct
    def test_cmpctheaders(self, node, peer):
        tip = int(node.getbestblockhash(), 16)
        block_hashes = node.generate(MAX_CMPCT_HEADER_RESULTS + 1)
        req_cmpctheaders = msg_getcmpcthdrs()
        req_cmpctheaders.locator.vHave = [ tip ]
        peer.send_message(req_cmpctheaders)

        assert wait_until(lambda: peer.last_message.get("cmpcthdrs"))

        with mininode_lock:
            headers = peer.last_message["cmpcthdrs"].headers
            assert len(headers) == MAX_CMPCT_HEADER_RESULTS
            assert headers[0].hashPrevBlock == tip
            assert headers[-1].sha256 == int(block_hashes[-2], 16)

    def test_rheaders(self, node, peer):
        if node.getblockcount() < MAX_CMPCT_HEADER_RESULTS:
            node.generate(MAX_CMPCT_HEADER_RESULTS - node.getblockcount())
        tip = int(node.getbestblockhash(), 16)
        tip_prev = int(node.getblockhash(node.getblockcount() - 1), 16)

        req_rheaders = msg_rgetheaders()
        req_rheaders.hashstop = tip
        req_rheaders.count = 10
        peer.send_message(req_rheaders)

        assert wait_until(lambda: peer.last_message.get("rheaders"))

        with mininode_lock:
            headers = peer.last_message["rheaders"].headers
            assert len(headers) == 10
            assert headers[-1].sha256 == tip_prev
            assert headers[0].sha256 == int(node.getblockhash(node.getblockcount() - 10), 16)

    def run_test(self):
        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode()

        connections = []
        connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node))
        self.test_node.add_connection(connections[0])

        NetworkThread().start() # Start up network handling in another thread

        # Test logic begins here
        self.test_node.wait_for_verack()

        self.log.info("Testing getcmpctheaders handling")
        self.test_cmpctheaders(self.nodes[0], self.test_node)

        self.log.info("Testing rgetheaders handling")
        self.test_rheaders(self.nodes[0], self.test_node)

if __name__ == '__main__':
    HeadersSyncTest().main()
