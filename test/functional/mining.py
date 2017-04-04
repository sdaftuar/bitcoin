#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test transaction selection (CreateNewBlock)."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.blocktools import *
from test_framework.mininode import CTransaction, ToHex, FromHex, CBlock, CTxIn, CTxOut, COutPoint, CTxInWitness, COIN
from test_framework.util import *
from test_framework.script import *

'''
Test goals:
    - Test that block max weight is respected (no blocks too big).
    - Test that if the mempool has a tx that fits in a block, it will always be
      included unless the block is within 4000 of max weight.
    - Test that transaction selection takes into account feerate-with-ancestors
      when creating blocks.
    - Test that recently received transactions aren't selected unless the feerate
      for including them is high.
'''

# CreateNewBlock() can treat recently-received transactions differently
RECENT_TX_THRESHOLD = 10 # seconds

class MiningTest(BitcoinTestFramework):
    def __init__(self):
        self.num_nodes = 6
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        # Set blockmaxweight to be low, to require fewer transactions
        # to fill up a block.
        extra_args = [["-debug", "-blockmaxweight=40000", "-minrelaytxfee=0"]
                      for i in range(self.num_nodes)]
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, extra_args)

        # Connect the network in a loop
        for i in range(self.num_nodes-1):
            connect_nodes(self.nodes[i], i+1)
        connect_nodes(self.nodes[-1], 0)

        self.is_network_split = False

    def create_segwit_coins(self):
        for node in self.nodes:
            # Create 20 segwit coins on each node
            for i in range(20):
                new_addr = node.getnewaddress()
                witness_address = node.addwitnessaddress(new_addr)
                node.sendtoaddress(witness_address, 1)
            node.generate(1)
            self.sync_all()

    def populate_mempool(self, desired_transactions):
        num_transactions = 0
        while (num_transactions < desired_transactions):
            try:
                random_transaction(self.nodes, amount=Decimal("0.1"), min_fee=Decimal("0.00001"), fee_increment=Decimal("0.000005"), fee_variants=1000, confirmations_required=0)
                num_transactions += 1
            except RuntimeError as e:
                # We might run out of funds; just count these as valid attempts
                if ("Insufficient funds" in e.error['message']):
                    num_transactions += 1
                else:
                    raise AssertionError("Unexpected run time error: "+e.error['message'])
            except JSONRPCException as e:
                if ("too-long-mempool" in e.error['message']):
                    num_transactions += 1
                else:
                    raise AssertionError("Unexpected JSON-RPC error: "+e.error['message'])
            except Exception as e:
                raise AssertionError("Unexpected exception raised: "+type(e).__name__)
        self.sync_all()

    # Approximate weight of the transactions in the mempool
    def get_mempool_weight(self, node):
        mempool = node.getrawmempool(verbose=True)
        weight = 0
        ancestor_size = 0
        for txid,entry in mempool.items():
            # Scale by the witness multiplier, since we get vsize back
            weight += entry['size'] * 4
            ancestor_size += entry['ancestorsize']
        return weight

    # Requires mempool to be populated ahead of time
    def test_max_block_weight(self, node):
        block_max_weight = 40000 - 4000 # 4000 reserved for coinbase
        total_weight = 0
        assert(self.get_mempool_weight(node) > block_max_weight)

        template = node.getblocktemplate({"rules":["segwit"]})
        block_weight = 0
        for x in template['transactions']:
            block_weight += x['weight']
        assert(block_weight > block_max_weight - 4000)
        assert(block_weight < block_max_weight)

    def add_empty_block(self, node):
        height = node.getblockcount()
        tip = node.getbestblockhash()
        mtp = node.getblockheader(tip)['mediantime']
        block = create_block(int(tip, 16), create_coinbase(height + 1), mtp + 1)
        block.nVersion = 4
        block.solve()
        node.submitblock(ToHex(block))


    # Test that transaction selection is via ancestor feerate, by showing that
    # it's sufficient to bump a child tx's fee to get it and its parent
    # included.
    def test_ancestor_feerate_sort(self, node):

        # Advance time to the future, to ensure recent-transaction-filtering
        # isn't affecting the test.
        node.setmocktime(int(time.time())+RECENT_TX_THRESHOLD)

        # Call getblocktemplate.  Find a transaction in the mempool that is not
        # in the block, which has an ancestor that is also not in the block.
        # Call prioritisetransaction on the child tx to boost its ancestor
        # feerate to be above the average feerate of the last ancestor_size
        # space in the block, and verify that the child transaction is in the next
        # block template.
        template = node.getblocktemplate({"rules":["segwit"]})
        block_txids = [ x["txid"] for x in template["transactions"] ]
        mempool_txids = node.getrawmempool()

        # Find a transaction that has at least one parent that is not in the
        # block.
        txid_to_bump = None

        for txid in mempool_txids:
            if txid not in block_txids:
                ancestor_txids = node.getmempoolancestors(txid=txid, verbose=False)
                for ancestor_txid in ancestor_txids:
                    if ancestor_txid not in block_txids:
                        txid_to_bump = txid
                        break
            if txid_to_bump is not None:
                break
        if txid_to_bump is None:
            raise AssertionError("Not enough transactions to test ancestor feerate score (test bug?)")

        # Calculate the ancestor feerate of the candidate transaction.
        mempool_entry = node.getmempoolentry(txid_to_bump)
        ancestor_size = mempool_entry['ancestorsize']
        ancestor_fee = mempool_entry['ancestorfees']

        # Determine feerate of the last ancestor_size portion of the block.
        cumulative_weight = 0
        cumulative_fee = 0
        for block_tx in reversed(template["transactions"]):
            cumulative_weight += block_tx["weight"]
            # The fee is the consensus correct one, not the policy modified
            # one, but we haven't prioritized anything yet, so this should be fine.
            cumulative_fee += block_tx["fee"]
            if (cumulative_weight > 4*ancestor_size):
                break

        # Bump the candidate transactin, just enough: 1 satoshi better than
        # what the block contains
        node.prioritisetransaction(txid_to_bump, cumulative_fee - ancestor_fee + 1)

        # Check that the next block template has txid_to_bump in it.
        self.add_empty_block(node) # bypass the gbt cache
        template = node.getblocktemplate({"rules":["segwit"]})
        new_block_txids = [x["txid"] for x in template["transactions"]]

        assert(txid_to_bump in new_block_txids)

        # Get rid of our prioritisation
        node.prioritisetransaction(txid_to_bump, -(cumulative_fee - ancestor_fee + 1))

    def test_recent_transactions_excluded(self, node):
        # Repeatedly try to call getblocktemplate, using mocktime to choose
        # random points at which to call gbt
        # If the block template contains recently-received transactions:
        # - prioritise all recent transactions to 0 fee, and then call gbt again
        # Verify that the orig fee was more than 1% more than the new fee.
        mempool = node.getrawmempool(verbose=True)
        all_times = [ value["time"] for key, value in mempool.items() ]
        earliest_time, latest_time = sorted(all_times)[::len(all_times)-1]
        mock_time = earliest_time + RECENT_TX_THRESHOLD
        max_fee = 0

        # Track how many blocks are found with/without recent transactions
        blocks_with_recent_tx = 0
        blocks_without_recent_tx = 0

        while mock_time < latest_time + RECENT_TX_THRESHOLD:
            node.setmocktime(mock_time)
            self.add_empty_block(self.nodes[0]) # bypass gbt cache
            template = node.getblocktemplate({"rules":["segwit"]})

            block_fee = 0
            contains_recent_tx = False
            for x in template['transactions']:
                block_fee += x['fee']
                if (mempool[x['txid']]['time'] > mock_time - RECENT_TX_THRESHOLD):
                    contains_recent_tx = True
            if block_fee > max_fee:
                self.log.debug("Setting max_fee to %d", block_fee)
                max_fee = block_fee

            if (not contains_recent_tx):
                # If we don't have anything new, we better be close to the max
                # seen so far
                self.log.debug("No recent transactions, block_fee = %d", block_fee)
                assert (block_fee >= 0.99*max_fee)
                blocks_without_recent_tx += 1

            else:
                # Deprioritise everything recent and re-run; the fee delta
                # should be significant
                blocks_with_recent_tx += 1

                for txid, entry in mempool.items():
                    if (entry["time"] > mock_time - RECENT_TX_THRESHOLD):
                        node.prioritisetransaction(txid, int(-(entry["fee"]*COIN)))
                self.add_empty_block(node) # bypass gbt cache
                new_template = node.getblocktemplate({"rules":["segwit"]})
                new_fee = 0
                for x in new_template['transactions']:
                    new_fee += x['fee']
                self.log.debug("Recent transactions: non-recent=%d all=%d", new_fee, block_fee)
                assert(block_fee > 1.01*new_fee)
                # Re-prioritise everything
                for txid, entry in mempool.items():
                    if (entry["time"] > mock_time - RECENT_TX_THRESHOLD):
                        node.prioritisetransaction(txid, int(entry["fee"]*COIN))

            mock_time += RECENT_TX_THRESHOLD

        if (blocks_with_recent_tx == 0 or blocks_without_recent_tx == 0):
            self.log.info("Warning - test_recent_transactions_excluded(): only one branch covered (blocks_with_recent_tx = %d, blocks_without_recent_tx = %d)", blocks_with_recent_tx, blocks_without_recent_tx)

        # Get rid of the mocktime
        node.setmocktime(0)

    def run_test(self):
        # Leave IBD and generate some coins to spend.
        # Give everyone plenty of coins
        self.log.info("Generating initial coins for all nodes")
        for i in range(2):
            for x in self.nodes:
                x.generate(101)
                self.sync_all()

        # Add some segwit coins to everyone
        self.log.info("Generating segwit coins for all nodes")
        self.create_segwit_coins()

        # Run tests...
        self.log.info("Populating mempool with a lot of transactions")
        self.populate_mempool(500)

        self.log.info("Running test_max_block_weight")
        self.test_max_block_weight(self.nodes[0])

        self.sync_all()
        self.log.info("Running test_recent_transactions_excluded")
        self.test_recent_transactions_excluded(self.nodes[0])

        self.sync_all()
        self.log.info("Running test_ancestor_feerate_sort")
        self.test_ancestor_feerate_sort(self.nodes[0])


if __name__ == "__main__":
    MiningTest().main()

