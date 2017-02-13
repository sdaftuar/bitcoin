#!/usr/bin/env python3
""" datalogging.py - datalogger and simulation test

DATALOGGER TEST:

 - Start 3 nodes with prefilled 200 block cache and connect them node0 - node1 - node2
 - node2 is running with -dlogdir option to log transactions and blocks
 - mine 1 block with node0
 - create 12 transactions between node0 and node1
 - mine 1 block with node1 (this confirms the 12 previous transactions)
 - create 12 more transactions between node0 and node1
 - assert that:
     - the tx. file contains 24 transactions
     - the block. file contains 2 blocks
     - the headers. file contains 2 block headers
 - stop all nodes

SIMULATION TEST:

 - start node3 with -simulation option, using the data files created by node2 earlier
 - assert that:
     - the block height is 202
     - the most recent block contains 13 transactions (= 12 + 1 coinbase transaction)
     - the mempool contains 12 transactions.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import os.path

class DataLoggingTest(BitcoinTestFramework):

    def setup_network(self):
        self.nodes = []

        self.nodes.append(start_node(0, self.options.tmpdir));
        self.nodes.append(start_node(1, self.options.tmpdir));
        self.nodes.append(start_node(2, self.options.tmpdir,
                            ["-dlogdir=" + self.options.tmpdir, "-debug"]))
        connect_nodes(self.nodes[1], 0)
        connect_nodes(self.nodes[2], 1)

        sync_blocks(self.nodes, wait=1, timeout=60)

    def run_test(self):
        # DATALOGGER TEST
        #################

        mined_blocks = set()

        # Mine one block to leave IBD.
        mined_blocks.add(self.nodes[0].generate(1)[0])
        sync_blocks(self.nodes, wait=1, timeout=60)

        # Send 12 random transactions. These will be included in the next block
        min_fee = Decimal("0.001")
        txnodes = [self.nodes[0], self.nodes[1]]
        [ random_transaction(txnodes, Decimal("1.1"), min_fee, min_fee, 20) for i in range(12)]

        sync_mempools(self.nodes)

        # Mine a block with node1 to confirm the transactions
        mined_blocks.add(self.nodes[1].generate(1)[0])

        # Send 12 random transactions. These aren't confirmed in a block and remain in the mempool
        [ random_transaction(txnodes, Decimal("1.1"), min_fee, min_fee, 20) for i in range(12)]
        sync_mempools(self.nodes)
        stop_nodes(self.nodes)

        # Need to wait for files to be written out
        while (os.path.isfile(self.options.tmpdir+"/node0/regtest/bitcoind.pid")):
            time.sleep(0.1)

        today = time.strftime("%Y%m%d")

        # Check that the size of the tx log is correct
        alltx = subprocess.check_output([ "dataprinter", self.options.tmpdir+"/tx."+today], universal_newlines=True)
        assert_equal(len(re.findall('CTransaction', alltx)), 24)

        # Check that the size of the block log is correct
        allblocks = subprocess.check_output([ "dataprinter", self.options.tmpdir+"/block."+today], universal_newlines=True)
        assert_equal(len(re.findall('CBlock', allblocks)), 2)

        # Check that all the blocks were received as headers or compact blocks
        headers_events = subprocess.check_output([ "dataprinter", self.options.tmpdir+"/headers."+today], universal_newlines=True)
        headers_hashes = re.findall("hash=([0-9a-fA-F]*)", headers_events)
        cmpctblock_events = subprocess.check_output([ "dataprinter", self.options.tmpdir+"/cmpctblock."+today], universal_newlines=True)
        cmpctblock_hashes = re.findall("hash=([0-9a-fA-F]*)", cmpctblock_events)
        assert_equal(set(headers_hashes + cmpctblock_hashes), mined_blocks)

        # SIMULATION TEST
        #################
        self.nodes.append(start_node(3, self.options.tmpdir,
                            ["-simulation", "-simdatadir=" + self.options.tmpdir, "-start=" + today, "-debug"]))

        # Test that a simulation node is able to replay the blocks and transactions logged by the datalogger.
        # After the 200 block cache, there should be:
        # 1 block
        # 12 transactions (confirmed in next block)
        # 1 block
        # 12 transactions in mempool
        assert_equal(self.nodes[0].getblockchaininfo()["blocks"], 202)

        best_block_hash = self.nodes[0].getbestblockhash()
        assert_equal(len(self.nodes[0].getblock(best_block_hash)["tx"]), 13)

        assert_equal(self.nodes[0].getmempoolinfo()["size"], 12)

if __name__ == '__main__':
    DataLoggingTest().main()
