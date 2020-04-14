#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Imports should be in PEP8 ordering (std library first, then third party
# libraries then local imports).
from collections import defaultdict

# Avoid wildcard * imports
from test_framework.blocktools import (create_block, create_coinbase)
from test_framework.messages import CInv
from test_framework.mininode import (
    P2PInterface,
    mininode_lock,
    msg_block,
    msg_getdata,
    NetworkThread
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
        self.block_receive_map = defaultdict(int)

    def on_block(self, message):
        """Override the standard on_block callback

        Store the hash of a received block in the dictionary."""
        message.block.calc_sha256()
        self.block_receive_map[message.block.sha256] += 1

    def on_inv(self, message):
        """Override the standard on_inv callback"""
        import time
        print("sleeping for 50 minutes")
        NetworkThread.network_event_loop.stop()
        time.sleep(3000)
        print("done sleeping for 50 minutes")
        pass


class ExampleTest(BitcoinTestFramework):

    def set_test_params(self):
        """Override test parameters for your individual test.

        This method must be overridden and num_nodes must be explicitly set."""
        self.setup_clean_chain = True
        self.num_nodes = 1
        # Use self.extra_args to change command-line arguments for the nodes


    def run_test(self):
        """Main test logic"""

        # Create P2P connections will wait for a verack to make sure the connection is fully up
        self.nodes[0].add_p2p_connection(BaseNode(), wait_for_verack=False)

        self.nodes[0].generate(nblocks=151)

        addr = self.nodes[0].getnewaddress()
        while (True):
            # Send some transactions
            for j in range(50):
                self.nodes[0].sendtoaddress(addr, 0.01)

            # Mine a block
            import time
            time.sleep(3)
            self.nodes[0].generate(1)


if __name__ == '__main__':
    ExampleTest().main()
