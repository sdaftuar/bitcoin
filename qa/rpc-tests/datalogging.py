#!/usr/bin/env python

#
# Test datalogging code
#

from test_framework import BitcoinTestFramework
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from util import *

class DataLoggingTest(BitcoinTestFramework):

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir,
                            ["-writemempool", "-dlogdir=" + self.options.tmpdir]))

        
        self.nodes.append(start_node(1, self.options.tmpdir));
        self.nodes.append(start_node(2, self.options.tmpdir));
        connect_nodes_bi(self.nodes, 1, 0)
        connect_nodes_bi(self.nodes, 1, 2)

        sync_blocks(self.nodes)
        
    def run_test(self):
        # Prime the memory pool with pairs of transactions
        # (high-priority, random fee and zero-priority, random fee)
        min_fee = Decimal("0.001")
        fees_per_kb = [];
        txnodes = [self.nodes[1], self.nodes[2]]
        for i in range(12):
            (txid, txhex, fee) = random_transaction(txnodes, Decimal("1.1"),
                                                            min_fee, min_fee, 20)

        sync_mempools(self.nodes)

        # Mine blocks with node1 until the memory pool clears:
        count_start = self.nodes[1].getblockcount()
        while len(self.nodes[1].getrawmempool()) > 0:
            self.nodes[1].setgenerate(True, 1)
            sync_blocks(self.nodes)

        for i in range(12):
            (txid, txhex, fee) = random_transaction(txnodes, Decimal("1.1"),
                                                            min_fee, min_fee, 20)
        sync_mempools(self.nodes)
        stop_nodes(self.nodes)

        time.sleep(5) # Need to wait for files to be written out

        today = time.strftime("%Y%m%d")

        # Check that the size of the tx log is correct
        alltx = subprocess.check_output([ "dataprinter", self.options.tmpdir+"/tx."+today])
        txheader = re.findall('CTransaction', alltx)
        if len(txheader) != 24:
                raise AssertionError("Wrong number of logged tx's, expected 24, got %d"%(len(txheader)))
    
        # Check that the size of the block log is correct
        allblocks = subprocess.check_output([ "dataprinter", self.options.tmpdir+"/block."+today])
        blockheaders = re.findall('CBlock', allblocks)
        if len(blockheaders) != 1:
                raise AssertionError("Wrong number of logged blocks, expected 1, got %d" % len(blockheaders))

        # Check that the size of the mempool log is correct
        allmptx = subprocess.check_output([ "dataprinter", self.options.tmpdir+"/mempool."+today])
        mpheaders = re.findall('CTransaction', allmptx)
        if len(mpheaders) != 12:
                raise AssertionError("Wrong number of mempool entries, expected 12, got %d" % len(mpheaders))

        # Check that the size of the headers log is correct
        # TODO: figure out how many headers we should actually get...
        allheaders = subprocess.check_output([ "dataprinter", self.options.tmpdir+"/headers."+today])
        hdrheaders = re.findall('CBlockHeader', allheaders)
        if len(mpheaders) == 0:
                raise AssertionError("Wrong number of blockheader entries, expected some, got %d" % len(hdrheaders))

if __name__ == '__main__':
    DataLoggingTest().main()
