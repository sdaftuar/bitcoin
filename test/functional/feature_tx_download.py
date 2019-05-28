#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Test transaction download behavior
"""

from test_framework.messages import msg_inv, CInv, MSG_TX, MSG_TYPE_MASK, FromHex, CTransaction, msg_notfound
from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import sync_mempools, connect_nodes_bi, wait_until, disconnect_nodes, connect_nodes
import random

class TestP2PConn(P2PInterface):
    def __init__(self):
        super().__init__()
        self.tx_getdata_count = 0

    def on_getdata(self, message):
        for i in message.inv:
            if i.type & MSG_TYPE_MASK == MSG_TX:
                self.tx_getdata_count += 1

class TxDownloadTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4

    def setup_network(self):
        self.setup_nodes()

        # 4 nodes connected to each other
        for i in range(4):
            for j in range(i+1, 4):
                connect_nodes_bi(self.nodes, i, j)

    # Test that we request transactions from all our peers, eventually
    def test_tx_requests(self):
        self.log.info("Testing transaction requests")

        # Generate a random hash, announce it as a txid
        txid = random.getrandbits(256)
        node = random.choice(self.nodes)

        # Announce the txid from each peer
        msg = msg_inv([CInv(t=1, h=txid)])
        for p in node.p2ps:
            p.send_message(msg)

        # Check that all peers eventually get a getdata request for the txid
        i = 0
        for p in node.p2ps:
            wait_until(lambda: p.last_message.get("getdata") and p.last_message["getdata"].inv[-1].hash == txid, timeout=600)
            self.log.debug("peer %d received getdata" % i)
            i += 1

    def test_inv_block(self):
        # Pick a random bitcoind and generate a transaction
        node = random.choice(self.nodes)
        tx = node.createrawtransaction([], { random.choice(self.nodes).getnewaddress() : 1 })
        tx = node.fundrawtransaction(tx)['hex']
        tx = node.signrawtransactionwithwallet(tx)['hex']
        ctx = FromHex(CTransaction(), tx)
        ctx.rehash()
        txid = ctx.hash
        #txid = node.sendtoaddress(random.choice(self.nodes).getnewaddress(), 1)
        self.log.info("---> Generated txid " + txid)
        txid = int(txid, 16)

        # Announce the transaction to all peers
        msg = msg_inv([CInv(t=1, h=txid)])
        for p in self.peers:
            p.send_message(msg)

        node.sendrawtransaction(tx)

        # Since everyone is connected outbound to an honest peer, everyone
        # should get it within 1 minute (plus whatever time it takes the
        # honest peer to announce the transaction, which should be brief)
        sync_mempools(self.nodes, timeout=75)
        self.log.info("---> Mempools synced")

    # Test that we don't request more than 100 transactions from any peer,
    # every 10 minutes
    def test_in_flight_max(self):
        MAX_GETDATA_IN_FLIGHT = 100
        node = random.choice(self.nodes)
        txids = [random.getrandbits(256) for i in range(MAX_GETDATA_IN_FLIGHT+2)]

        p = node.p2ps[0]

        with mininode_lock:
            p.tx_getdata_count = 0

        msg = msg_inv([CInv(t=1, h=i) for i in txids])
        p.send_message(msg)
        wait_until(lambda: p.tx_getdata_count >= MAX_GETDATA_IN_FLIGHT)
        with mininode_lock:
            assert p.tx_getdata_count == MAX_GETDATA_IN_FLIGHT

        # Now check that if we send a NOTFOUND for a transaction, we'll get one
        # more request
        msg = msg_notfound(vec=[CInv(t=1, h=txids[0])])
        p.send_message(msg)
        wait_until(lambda: p.tx_getdata_count >= MAX_GETDATA_IN_FLIGHT+1, timeout=10)
        with mininode_lock:
            assert p.tx_getdata_count == MAX_GETDATA_IN_FLIGHT+1

        # if we wait up to 25 minutes, we should eventually get more requests.
        wait_until(lambda: p.tx_getdata_count == MAX_GETDATA_IN_FLIGHT+2, timeout=1500)

    def run_test(self):
        # Setup the p2p connections
        NUM_INBOUND = 10
        self.peers = []
        for node in self.nodes:
            node.generate(10)
            self.sync_all()
            for i in range(NUM_INBOUND):
                 self.peers.append(node.add_p2p_connection(TestP2PConn()))

        self.nodes[0].generate(100) # mature prior coinbases
        self.sync_all(self.nodes[0:4])
        self.log.info("Nodes are setup with balances")

        # Test the in-flight max first, because we want no transactions in
        # flight ahead of this test.
        self.test_in_flight_max()

        self.test_inv_block()

        self.test_tx_requests()

if __name__ == '__main__':
    TxDownloadTest().main()
