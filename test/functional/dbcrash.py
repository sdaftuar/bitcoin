#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test recovery from a crash during chainstate writing."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import *
from test_framework.mininode import *
import random

'''
Test structure:

- 4 nodes: node0, node1, and node2 will have different dbcrash ratios, and
  different dbcache sizes (maybe also different batchwrite sizes)
  node3 will be a regular node, with no crashing.
  The nodes will not connect to each other.

- use default test framework starting chain. initialize starting_tip_height to tip height.

- loop:
  * generate lots of transactions on node3 (to addresses from the other nodes), enough to fill
    up a block.
  * randomly pick a tip height from starting_tip_height to tip_height (uniform)
    with probability 1/(height_difference+4), invalidate this block.
  * mine enough blocks to overtake tip_height at start of loop.
  * for each node in [node0,node1,node2]:
     - for each mined block:
       - submit block to node
       - catch any exception to see if node crashed.
       - if node crashed, restart until node stays up
         - check that utxo matches node3 using gettxoutsetinfo
'''

class ChainstateWriteCrashTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = False
        # Node0: crashes after 1/4 of batch writes, and generally needs 2 batch
        # writes in order to flush.  And zero out the mempool, so that we don't
        # pick up extra utxo caching there.
        self.base_args = ["-limitdescendantsize=0", "-maxmempool=0"]
        self.node0_args = ["-dbcrashratio=4", "-dbcache=4", "-dbbatchsize=200000"] + self.base_args
        self.node1_args = ["-dbcrashratio=8", "-dbcache=8", "-dbbatchsize=200000"] + self.base_args
        self.node2_args = ["-dbcrashratio=16", "-dbcache=16", "-dbbatchsize=200000"] + self.base_args
        self.node3_args = ["-blockmaxweight=4000000"] # Use defaults, and don't limit mempool
        self.extra_args = [self.node0_args, self.node1_args, self.node2_args, self.node3_args]

    def setup_network(self):
        self.setup_nodes()
        # Leave them unconnected, we'll use submitblock directly in this test

    def restart_node(self, node_index, expected_tip):
        # Basic issue: restarting a node that crashed in db write could crash again
        # during playback.
        # So catch the exceptions that could be thrown, and keep trying to restart.
        MAX_TRIES = 10
        tries = 0
        success = False
        while (tries < MAX_TRIES):
            try:
                self.log.info("Starting node %d", node_index)
                # XXX: Can't get this to work yet restarting with the crash args; first try getting it to work
                # consistently just restarting cleanly, verifying utxo, and then restart with crash args.
                # Then figure out why catching the crashes here isn't working.
                #self.nodes[node_index] = self.start_node(node_index, self.options.tmpdir, self.extra_args[node_index])
                # XXX: Discovered an instance in testing where this restart
                # failed because the block index was corrupt; that shouldn't be
                # possible?
                self.nodes[node_index] = self.start_node(node_index, self.options.tmpdir)
                time.sleep(1) # XXX: is this really necessary?
                assert_equal(self.nodes[node_index].getbestblockhash(), expected_tip)
                self.log.info("Successfully restarted node %d after crash and checked utxo hash; stopping node", node_index)
                self.stop_node(node_index)
                self.log.info("Node %d stopped", node_index)
                time.sleep(1)
                self.log.info("Restarting %d with crash args", node_index)
                self.nodes[node_index] = self.start_node(node_index, self.options.tmpdir, self.extra_args[node_index])
                utxo_hash = self.nodes[node_index].gettxoutsetinfo()['hash_serialized_2']
                self.log.info("Calculated utxo hash; returning")
                return utxo_hash
            except Exception as e:
                import traceback
                self.log.info("Got exception %s", traceback.format_exception(*sys.exc_info()))
                self.log.info("Trying again!")
                # just try again
                tries += 1

        # Couldn't successfully recover with crashing turned on; try again
        # without crashing and make sure utxo recovers correctly.
        self.log.info("Unable to restart %d with crash args, restarting without", node_index)
        self.nodes[node_index] = self.start_node(node_index, self.options.tmpdir)
        assert_equal(self.nodes[node_index].getbestblockhash(), expected_tip)
        self.log.info("Node %d successfully restarted with correct utxo hash, restarting again", node_index)
        self.stop_node(node_index)
        time.sleep(1)

        # Now restart with the correct dbcrash arguments so we can continue the
        # test
        self.log.info("Restarting node %d with dbcrash args again", node_index)
        self.nodes[node_index] = self.start_node(node_index, self.options.tmpdir, self.extra_args[node_index])
        self.log.info("Node is up, blockcount = %d", self.nodes[node_index].getblockcount())
        time.sleep(1)

    # Use submitblock to sync node3's chain with the other nodes
    def sync_node3blocks(self, block_hashes):
        node3_utxo_hash = self.nodes[3].gettxoutsetinfo()['hash_serialized_2']
        for i in range(3):
            nodei_utxo_hash = 0
            self.log.info("Syncing blocks to node %d", i)
            for block_hash in block_hashes:
                # Get the block from node3, and submit to node_i
                block_hex = self.nodes[3].getblock(block_hash, 0)
                try:
                    self.log.info("submitting block %s", block_hash)
                    self.nodes[i].submitblock(block_hex)
                except:
                    # TODO: check that failure is due to crashing
                    # TODO: check the error code of bitcoind
                    # Restart the node, and check that its tip matches
                    # block_hash
                    self.log.info("Restarting node %d after block hash %s", i, block_hash)
                    nodei_utxo_hash = self.restart_node(i, block_hash)
            # Check that the utxo set matches node3's utxo set
            self.log.info("Checking txoutsetinfo matches for node %d", i)
            # NOTE: we only check the utxo set if we had to restart the node; otherwise
            # checking the utxo set hash causes a flush which might not be big enough to
            # trigger a crash
            if nodei_utxo_hash is not 0:
                assert_equal(nodei_utxo_hash, node3_utxo_hash)

    # TODO: Replace all this wallet signing stuff with just making blocks
    # inside the test framework.  Then we can use custom scriptPubKeys to make
    # the utxo cache blow up quicker.
    def estimated_P2PKH_unsigned_tx_size(self, tx):
        # P2PKH inputs require a ~33 byte pubkey, and ~72byte signature
        return len(tx.serialize()) + (72+33)*len(tx.vin)

    def generate_small_transactions(self, node, count, utxo_list):
        FEE = 1000 # TODO: replace this with node relay fee based calculation
        random.shuffle(utxo_list)
        num_transactions = 0
        while len(utxo_list) >= 2 and num_transactions < count:
            tx = CTransaction()
            input_amount = 0
            for i in range(2):
                utxo = utxo_list.pop()
                tx.vin.append(CTxIn(COutPoint(int(utxo['txid'], 16), utxo['vout'])))
                input_amount += int(utxo['amount']*COIN)
            output_amount = (input_amount - FEE)//3
            for i in range(3):
                tx.vout.append(CTxOut(output_amount, hex_str_to_bytes(utxo['scriptPubKey'])))

            # Sign and send the transaction to get into the mempool
            tx_signed_hex = node.signrawtransaction(ToHex(tx))['hex']
            node.sendrawtransaction(tx_signed_hex)
            num_transactions += 1


    def run_test(self):

        ###########################################
        # Start by creating a lot of utxos on node3
        TARGET_UTXO_COUNT = 5000
        TARGET_UTXO_VALUE = 0.01
        TARGET_TX_FEERATE = 10 # sat/byte

        assert self.nodes[3].getbalance() > TARGET_UTXO_COUNT * TARGET_UTXO_VALUE

        utxo_list = self.nodes[3].listunspent()
        node3_address = self.nodes[3].getnewaddress()
        node3_pubkey = int(self.nodes[3].validateaddress(node3_address)['pubkey'], 16)
        node3_spk = hex_str_to_bytes(self.nodes[3].validateaddress(node3_address)['scriptPubKey'])

        block_hashes_to_sync = []

        while len(utxo_list) < TARGET_UTXO_COUNT:
            self.log.debug("node3 utxo count: %d", len(utxo_list))
            random.shuffle(utxo_list)

            # Split every utxo that has more than 10 BTC in it
            tx = CTransaction()

            # Track input/output amounts for fee calculation
            input_amount = 0
            output_amount = 0

            # Add inputs and outputs to this transaction, 1000 outputs at a time
            while len(utxo_list) > 0:
                x = utxo_list.pop()
                if x['amount'] > 1000 * TARGET_UTXO_VALUE:
                    tx.vin.append(CTxIn(COutPoint(int(x['txid'],16), x['vout'])))
                    tx.vout.extend([CTxOut(int(TARGET_UTXO_VALUE*COIN), node3_spk)]*1000)
                    input_amount += int(x['amount']*COIN)
                    output_amount += int(TARGET_UTXO_VALUE*COIN*1000)
                if self.estimated_P2PKH_unsigned_tx_size(tx) > 50000:
                    # Don't let the transaction get too big
                    break

            # Add a change output if there's any change left, after fees
            estimated_size = self.estimated_P2PKH_unsigned_tx_size(tx)
            fee = TARGET_TX_FEERATE * estimated_size
            assert input_amount - output_amount > int(0.1*fee) # otherwise this won't relay
            if input_amount - output_amount > fee:
                tx.vout.append(CTxOut(input_amount-output_amount-fee, node3_spk))

            # Sign and send the transaction to get into the mempool
            tx_signed_hex = self.nodes[3].signrawtransaction(ToHex(tx))['hex']
            self.nodes[3].sendrawtransaction(tx_signed_hex)

            # Mine this transaction
            block_hashes_to_sync.extend(self.nodes[3].generate(1))

            # Recalculate our available utxos for next loop iteration
            all_unspent = self.nodes[3].listunspent()
            utxo_list = [ x for x in all_unspent if int(x['amount']*COIN) >= int(TARGET_UTXO_VALUE*COIN) ]

        self.log.info("%d entries", len(utxo_list))
        ######## DONE CREATING UTXOS #############

        assert len(utxo_list) >= TARGET_UTXO_COUNT

        self.log.info("Syncing %d blocks with other nodes", len(block_hashes_to_sync))
        self.sync_node3blocks(block_hashes_to_sync)

        # Now go into our main test loop.
        starting_tip_height = self.nodes[3].getblockcount()

        for i in range(100):
            self.log.info("Iteration %d, generating 2500 transactions", i)
            # Generate a bunch of 2-input, 3-output transactions
            self.generate_small_transactions(self.nodes[3], 2500, utxo_list)
            # Pick a random block between current tip, and starting tip
            current_height = self.nodes[3].getblockcount()
            random_height = random.randint(starting_tip_height, current_height)
            self.log.info("At height %d, considering height %d", current_height, random_height)
            if random_height > starting_tip_height:
                # Randomly reorg from this point with some probability (1/4 for
                # tip, 1/5 for tip-1, ...)
                if random.random() < 1.0/(current_height + 4 - random_height):
                    self.log.info("Invalidating block at height %d", random_height)
                    self.nodes[3].invalidateblock(self.nodes[3].getblockhash(random_height))

            # Now generate new blocks until we pass the old tip height
            self.log.info("Mining longer tip")
            block_hashes = self.nodes[3].generate(current_height+1-self.nodes[3].getblockcount())
            self.log.info("Syncing %d new blocks...", len(block_hashes))
            self.sync_node3blocks(block_hashes)
            utxo_list = self.nodes[3].listunspent()
            self.log.info("Node3 utxo count: %d", len(utxo_list))


if __name__ == "__main__":
    ChainstateWriteCrashTest().main()
