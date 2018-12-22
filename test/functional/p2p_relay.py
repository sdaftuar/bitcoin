#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test transaction download behavior.

- Create two connected bitcoind nodes, and p2p connect to each.
- Create a transaction and announce to one.  Verify we receive a getdata
  request.
- Create a transaction and announce to one, deliver to the other. Verify that
  we sometimes do NOT get a getdata request.
- Send a NOTFOUND in response to the getdata requests. Verify that the node
  gets the transaction in less than 50 seconds.

"""

from time import sleep

from test_framework.messages import msg_ping, FromHex, CTransaction, msg_inv, CInv, msg_notfound
from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import wait_until, connect_nodes_bi

class TestP2PConn(P2PInterface):
    def __init__(self):
        super().__init__()

class TxDownloadTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 5
        # set timeout to receive version/verack to 3 seconds
        self.extra_args = [[], [], ["-walletbroadcast=0"], [], []]

    def setup_network(self):
        self.setup_nodes()
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)
        connect_nodes_bi(self.nodes, 0, 3)
        connect_nodes_bi(self.nodes, 0, 4)
        connect_nodes_bi(self.nodes, 1, 2)
        connect_nodes_bi(self.nodes, 1, 3)
        connect_nodes_bi(self.nodes, 1, 4)

    def run_test(self):
        # Setup the p2p connections
        peer0 = self.nodes[0].add_p2p_connection(TestP2PConn())
        peer1 = self.nodes[1].add_p2p_connection(TestP2PConn())

        self.nodes[2].generate(200)

        self.sync_all()

        # Generate lots of transactions, announce to node0 and deliver to
        # node1.
        # Verify that sometimes we get a GETDATA request, but not always.
        peer0_getdata = 0
        for i in range(1, 21):
            txid_string = self.nodes[2].sendtoaddress(self.nodes[0].getnewaddress(), 1)
            tx_hex = self.nodes[2].gettransaction(txid_string)['hex']
            txid = int(txid_string, 16)
            message = msg_inv([CInv(t=1, h=txid)])
            peer0.send_message(message)
            self.nodes[1].sendrawtransaction(tx_hex)

            sleep(2)
            got_getdata = False
            with mininode_lock:
                if (peer0.last_message.get("getdata")):
                    peer0.last_message.pop("getdata")
                    peer0_getdata += 1
                    got_getdata = True
                else:
                    assert txid_string in self.nodes[0].getrawmempool()
            if got_getdata:
                # Send a NOTFOUND and see that the node still gets it quickly
                sleep(20)
                message = msg_notfound([CInv(t=1, h=txid)])
                peer0.send_message(message)
                wait_until(lambda: txid_string in self.nodes[0].getrawmempool(), timeout=10, lock=mininode_lock)

        assert peer0_getdata < 20

if __name__ == '__main__':
    TxDownloadTest().main()
