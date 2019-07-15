#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test processing of two-transaction packages"""

from decimal import Decimal
from test_framework.messages import msg_tx, FromHex, CTransaction, msg_witness_tx
from test_framework.mininode import mininode_lock, P2PInterface
from test_framework.test_framework import BitcoinTestFramework

# Avoid wildcard * imports
from test_framework.blocktools import (create_block, create_coinbase)
from test_framework.messages import CInv
from test_framework.mininode import (
    P2PInterface,
    mininode_lock,
    msg_block,
    msg_getdata,
)

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes,
    wait_until,
)

# P2PInterface is a class containing callbacks to be executed when a P2P
# message is received from the node-under-test. Subclass P2PInterface and
# override the on_*() methods if you need custom behaviour.
class BaseNode(P2PInterface):
    def __init__(self):
        """Initialize the P2PInterface

        Used to initialize custom properties for the Node that aren't
        included by default in the base class. Be aware that the P2PInterface
        base class already stores a counter for each P2P message type and the
        last received message of each type, which should be sufficient for the
        needs of most tests.

        Call super().__init__() first for standard initialization and then
        initialize custom properties."""
        super().__init__()
        # Stores a dictionary of all blocks received

    def on_block(self, message):
        """Override the standard on_block callback

        Store the hash of a received block in the dictionary."""
        message.block.calc_sha256()
        self.block_receive_map[message.block.sha256] += 1

    def on_inv(self, message):
        """Override the standard on_inv callback"""
        pass


class ExampleTest(BitcoinTestFramework):
    # Each functional test is a subclass of the BitcoinTestFramework class.

    # Override the set_test_params(), skip_test_if_missing_module(), add_options(), setup_chain(), setup_network()
    # and setup_nodes() methods to customize the test setup as required.

    def set_test_params(self):
        """Override test parameters for your individual test.

        This method must be overridden and num_nodes must be explicitly set."""
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [[], ["-minrelaytxfee=0", "-mintxfee=0.00000001"]]


    # Use skip_test_if_missing_module() to skip the test if your test requires certain modules to be present.
    # This test uses generate which requires wallet to be compiled
    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()


    def run_test(self):
        """Main test logic"""

        # Create P2P connections will wait for a verack to make sure the connection is fully up
        self.nodes[0].add_p2p_connection(BaseNode())

        # Generating a block on one of the nodes will get us out of IBD
        blocks = [int(self.nodes[0].generate(nblocks=1)[0], 16)]

        self.nodes[1].generate(101)
        self.sync_all(self.nodes[0:2])

        # On node1, generate a 0-fee transaction, and then a 2-satoshi-per-byte
        # transaction

        utxos = self.nodes[1].listunspent()
        assert len(utxos) == 1

        self.nodes[1].settxfee(Decimal("0.00000002"))
        txid = self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 1)
        print(txid)
        raw_tx = self.nodes[1].gettransaction(txid)['hex']
        print(raw_tx)
        try:
            self.nodes[0].sendrawtransaction(raw_tx)
        except:
            pass
        assert txid not in self.nodes[0].getrawmempool()

        self.nodes[1].settxfee(Decimal("0.0005"))
        txid2 = self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 1)
        print(txid2)
        raw_tx2 = self.nodes[1].gettransaction(txid2)['hex']
        print(raw_tx2)

        assert txid in self.nodes[1].getrawmempool()
        assert txid2 in self.nodes[1].getrawmempool()

        assert txid2 not in self.nodes[0].getrawmempool()

        self.nodes[0].generate(1) # Clear out the reject filter

        p2p = self.nodes[0].add_p2p_connection(BaseNode())
        tx2 = FromHex(CTransaction(), raw_tx2)
        p2p.send_and_ping(msg_witness_tx(tx=tx2))
        tx = FromHex(CTransaction(), raw_tx)
        p2p.send_and_ping(msg_witness_tx(tx=tx))


        assert txid in self.nodes[0].getrawmempool()
        assert txid2 in self.nodes[0].getrawmempool()

        # Relay the 0-fee transaction and observe it doesn't get into the mempool of node0.
        # Then relay the 2-satoshi-per-byte transaction, and observe it doesn't get into the mempool.
        # Then relay the 0-fee transaction again and observe that it does get into the mempool.

if __name__ == '__main__':
    ExampleTest().main()
