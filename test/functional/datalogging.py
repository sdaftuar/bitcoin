#!/usr/bin/env python3
"""datalogger and simulation test

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

Test that a simulation node is able to replay the blocks and transactions logged by the datalogger.
Start the node in simulation mode, wait for the simulation to complete and then grep the debug.log file
for expected messages updating the tip and accepting transactions to the mempool.

The debug.log file should contain the following lines:
- the tip is updated to the most recent block
- the block contains 13 transactions (coinbase + 12 from mempool)
- 24 transactions have been accepted to the mempool
- the simulation has finished

Note that this test will break if the debug.log file format ever changes."""
from decimal import Decimal
import os.path
import re
import subprocess
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes,
    random_transaction,
    sync_blocks,
    sync_mempools,
)

class DataLoggingTest(BitcoinTestFramework):
    def setup_network(self):
        self.num_nodes = 3
        self.extra_args = [[], [], ["-dlogdir=" + self.options.tmpdir]]
        self.setup_nodes()

        connect_nodes(self.nodes[0], 1)
        connect_nodes(self.nodes[1], 0)
        connect_nodes(self.nodes[1], 2)
        self.sync_all()

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4

    def run_test(self):
        self.log.info("Run DATALOGGER test")

        mined_blocks = set()

        # Mine some blocks
        for i in range(25):
            mined_blocks.add(self.nodes[0].generate(1)[0])
        sync_blocks(self.nodes, wait=1, timeout=60)
        for i in range(25):
            mined_blocks.add(self.nodes[1].generate(1)[0])
        sync_blocks(self.nodes, wait=1, timeout=60)
        for i in range(100):
            mined_blocks.add(self.nodes[0].generate(1)[0])
        sync_blocks(self.nodes, wait=1, timeout=60)

        # Send 12 random transactions. These will be included in the next block
        min_fee = Decimal("0.001")
        txnodes = [self.nodes[0], self.nodes[1]]
        [random_transaction(txnodes, Decimal("1.1"), min_fee, min_fee, 20) for i in range(12)]

        sync_mempools(self.nodes)

        # Mine a block with node1 to confirm the transactions
        best_block_hash = self.nodes[1].generate(1)[0]
        mined_blocks.add(best_block_hash)
        sync_blocks(self.nodes, wait=1, timeout=60)

        # Send 12 random transactions. These aren't confirmed in a block and remain in the mempool
        [random_transaction(txnodes, Decimal("1.1"), min_fee, min_fee, 20) for i in range(12)]
        sync_mempools(self.nodes)
        num_blocks = self.nodes[2].getblockcount()
        self.stop_nodes()
        self.nodes = []

        # Need to wait for files to be written out
        while (os.path.isfile(self.options.tmpdir + "/node0/regtest/bitcoind.pid")):
            time.sleep(0.1)

        today = time.strftime("%Y%m%d")

        self.log.info("Check all transactions were logged")
        alltx = subprocess.check_output(["dataprinter", self.options.tmpdir + "/tx." + today], universal_newlines=True)
        assert_equal(len(re.findall('CTransaction', alltx)), 24)

        self.log.info("Check all blocks were logged")
        allblocks = subprocess.check_output(["dataprinter", self.options.tmpdir + "/block." + today], universal_newlines=True)
        assert_equal(len(list(dict.fromkeys(re.findall('CBlock.hash=([0-9a-fA-F]*)', allblocks)))), num_blocks)

        self.log.info("Check all headers and compact blocks were logged")
        headers_events = subprocess.check_output(["dataprinter", self.options.tmpdir + "/headers." + today], universal_newlines=True)
        headers_hashes = re.findall("hash=([0-9a-fA-F]*)", headers_events)
        cmpctblock_events = subprocess.check_output(["dataprinter", self.options.tmpdir + "/cmpctblock." + today], universal_newlines=True)
        cmpctblock_hashes = re.findall("hash=([0-9a-fA-F]*)", cmpctblock_events)
        assert_equal(set(headers_hashes + cmpctblock_hashes), mined_blocks)

        self.log.info("DATALOGGER tests successful")

        self.log.info("Run SIMULATION test")

        datadir = os.path.join(self.options.tmpdir, "node3")
        args = [os.getenv("BITCOIND", "bitcoind"), "-datadir=" + datadir, "-regtest", "-server", "-keypool=1", "-discover=0", "-rest", "-simulation", "-simdatadir=" + self.options.tmpdir, "-start=" + today, "-debug", "-disablewallet"]
        sim_process = subprocess.Popen(args)

        self.log.info("Wait for simulation to end")
        assert_equal(sim_process.wait(timeout=60), 0)

        block_accepted_match = "UpdateTip: new best=%s height=%d" % (str(best_block_hash), num_blocks)
        all_block_txs_accepted_match = "Connect 13 transactions"
        tx_accepted_match = "AcceptToMemoryPool"
        simulation_ended_match = "Simulation exiting"

        block_accepted, all_block_txs_accepted, number_txs_accepted, simulation_ended = False, False, 0, False

        self.log.info("Read debug.log file")
        with open(os.path.join(datadir, "regtest", "debug.log"), 'r') as log:
            for line in log.readlines():
                if re.search(block_accepted_match, line):
                    # These should be debug logs when #9768 is merged
                    # print("found block %s" % best_block_hash)
                    block_accepted = True
                if re.search(all_block_txs_accepted_match, line):
                    # print("found %s" % all_block_txs_accepted_match)
                    all_block_txs_accepted = True
                if re.search(tx_accepted_match, line):
                    # print("found tx accepted: " + line)
                    number_txs_accepted += 1
                if re.search(simulation_ended_match, line):
                    simulation_ended = True

        assert block_accepted, "debug.log file did not contain the 'UpdateTip' line. Check whether debug.log file formats have changed."
        assert all_block_txs_accepted, "debug.log file did not contain the 'Connect x transactions' line. Check whether debug.log file formats have changed."
        assert number_txs_accepted == 24, "debug.log file did not contain the 'AcceptToMemoryPool' lines. Check whether debug.log file formats have changed."
        assert simulation_ended, "debug.log file did not contain the 'Simulation exiting' line. Check whether debug.log file formats have changed."

        self.log.info("SIMULATION tests successful")

if __name__ == '__main__':
    DataLoggingTest().main()
