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

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import os.path
import re

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
        best_block_hash = self.nodes[1].generate(1)[0]
        mined_blocks.add(best_block_hash)

        # Send 12 random transactions. These aren't confirmed in a block and remain in the mempool
        [ random_transaction(txnodes, Decimal("1.1"), min_fee, min_fee, 20) for i in range(12)]
        sync_mempools(self.nodes)
        stop_nodes(self.nodes)
        self.nodes = []

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

        datadir = os.path.join(self.options.tmpdir, "node3")
        args = [ os.getenv("BITCOIND", "bitcoind"), "-datadir="+datadir, "-server", "-keypool=1", "-discover=0", "-rest", "-mocktime="+str(get_mocktime()),"-simulation", "-simdatadir=" + self.options.tmpdir, "-start=" + today, "-debug"]
        sim_process = subprocess.Popen(args)

        assert sim_process.wait() == 0

        block_accepted_match = "UpdateTip: new best=%s height=202" % str(best_block_hash)
        all_block_txs_accepted_match = "Connect 13 transactions"
        tx_accepted_match = "AcceptToMemoryPool"
        simulation_ended_match = "Simulation exiting"

        block_accepted, all_block_txs_accepted, number_txs_accepted, simulation_ended = False, False, 0, False

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

if __name__ == '__main__':
    DataLoggingTest().main()
