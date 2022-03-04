#!/usr/bin/env python3
# Copyright (c) 2019-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that we reject low difficulty headers to prevent our block tree from filling up with useless bloat"""

from test_framework.test_framework import BitcoinTestFramework

import time

NODE1_BLOCKS_REQUIRED = 16
NODE2_BLOCKS_REQUIRED = 2047


class RejectLowDifficultyHeadersTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        # Node0 has no required chainwork; node1 requires 16 blocks; node2 requires 2048 blocks
        self.extra_args = [["-minimumchainwork=0x0"], ["-minimumchainwork=0x1f"], ["-minimumchainwork=0x1000"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def test_chains_sync_when_long_enough(self):
        self.log.info("Generate blocks on the node with no required chainwork")
        self.generate(self.nodes[0], NODE1_BLOCKS_REQUIRED-2, sync_fun=self.no_op)

        self.log.info("Verify nodes 1 and 2 have no new headers in their headers tree")
        time.sleep(2)
        for i in range(1, 2):
            chaintips = self.nodes[i].getchaintips()
            assert(len(chaintips) == 1)
            assert {
                'height': 0,
                'hash': '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206',
                'branchlen': 0,
                'status': 'active',
            } in chaintips;

        self.generate(self.nodes[0], NODE1_BLOCKS_REQUIRED - self.nodes[0].getblockcount(), sync_fun=self.no_op)
        self.log.info("Verify that node1 syncs node0's chain")
        time.sleep(2)
        self.sync_blocks(self.nodes[0:2])

        self.log.info("Verify that node2 still has no new headers")
        time.sleep(2)
        assert {
            'height': 0,
            'hash': '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206',
            'branchlen': 0,
            'status': 'active',
        } in self.nodes[2].getchaintips()

        assert(len(self.nodes[2].getchaintips()) == 1)

        self.log.info("Generate long chain for node0/node1")
        self.generate(self.nodes[0], NODE2_BLOCKS_REQUIRED-self.nodes[0].getblockcount(), sync_fun=self.no_op)

        self.log.info("Verify that node2 will sync the chain when it gets long enough")
        self.sync_blocks()

    def run_test(self):
        self.test_chains_sync_when_long_enough()


if __name__ == '__main__':
    RejectLowDifficultyHeadersTest().main()
