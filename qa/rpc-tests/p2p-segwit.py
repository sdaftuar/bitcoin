#!/usr/bin/env python2
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import *
import time
from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment, WITNESS_COMMITMENT_HEADER

# The versionbit bit used to signal activation of SegWit
VB_WITNESS_BIT = 1
VB_PERIOD = 144
VB_ACTIVATION_THRESHOLD = 108
VB_TOP_BITS = 0x20000000

'''
SegWit p2p test.
'''

# TODO:
# - test preferential peering
# - test rewind mechanism for upgrade after activation
# - test that before and after activation, blocks with no witness tx's can omit commitment
# - test hashing

# Calculate the virtual size of a witness block:
# (base + witness/4)
def get_virtual_size(witness_block):
    base_size = len(witness_block.serialize())
    total_size = len(witness_block.serialize(with_witness=True))
    # the "+3" is so we round up
    vsize = int((3*base_size + total_size + 3)/4)
    return vsize

# TODO: trim this down once we know what we need/don't need.
class TestNode(NodeConnCB):
    def __init__(self):
        NodeConnCB.__init__(self)
        self.connection = None
        self.ping_counter = 1
        self.last_pong = msg_pong(0)
        self.sleep_time = 0.05
        self.got_close = False

    def add_connection(self, conn):
        self.connection = conn

    def on_close(self, conn):
        self.got_close = True

    # Request data for a list of block hashes
    def get_data(self, block_hashes):
        msg = msg_getdata()
        invtype = 2 # Block
        if self.got_have_witness:
            invtype |= MSG_WITNESS_FLAG
        for x in block_hashes:
            msg.inv.append(CInv(invtype, x))
        self.connection.send_message(msg)

    def get_headers(self, locator, hashstop):
        msg = msg_getheaders()
        msg.locator.vHave = locator
        msg.hashstop = hashstop
        self.connection.send_message(msg)

    def send_block_inv(self, blockhash):
        msg = msg_inv()
        msg.inv = [CInv(2, blockhash)]
        self.connection.send_message(msg)

    # Wrapper for the NodeConn's send_message function
    def send_message(self, message):
        self.connection.send_message(message)

    def on_inv(self, conn, message):
        self.last_inv = message

    def on_headers(self, conn, message):
        self.last_headers = message

    def on_block(self, conn, message):
        self.last_block = message.block
        self.last_block.calc_sha256()

    def on_getdata(self, conn, message):
        self.last_getdata = message

    def on_pong(self, conn, message):
        self.last_pong = message

    def on_reject(self, conn, message):
        self.last_reject = message
        #print message

    # Syncing helpers
    def sync(self, test_function, timeout=60):
        while timeout > 0:
            with mininode_lock:
                if test_function():
                    return
            time.sleep(self.sleep_time)
            timeout -= self.sleep_time
        raise AssertionError("Sync failed to complete")
        
    def sync_with_ping(self, timeout=60):
        self.send_message(msg_ping(nonce=self.ping_counter))
        test_function = lambda: self.last_pong.nonce == self.ping_counter
        self.sync(test_function, timeout)
        self.ping_counter += 1
        return

    def wait_for_close(self, timeout=60):
        test_function = lambda: self.got_close == True
        self.sync(test_function, timeout)
        return

    def wait_for_block(self, blockhash, timeout=60):
        test_function = lambda: self.last_block != None and self.last_block.sha256 == blockhash
        self.sync(test_function, timeout)
        return

    def send_header_for_blocks(self, new_blocks):
        headers_message = msg_headers()
        headers_message.headers = [ CBlockHeader(b) for b in new_blocks ]
        self.send_message(headers_message)

    def wait_for_getdata(self, timeout=60):
        test_function = lambda: self.last_getdata != None
        self.sync(test_function, timeout)

    def announce_tx_and_wait_for_getdata(self, tx, timeout=60):
        with mininode_lock:
            self.last_getdata = None
        self.send_message(msg_inv(inv=[CInv(1, tx.sha256)]))
        self.wait_for_getdata()
        return

    def announce_block_and_wait_for_getdata(self, block, use_header, timeout=60):
        with mininode_lock:
            self.last_getdata = None
        if use_header:
            msg = msg_headers()
            msg.headers = [ CBlockHeader(block) ]
            self.send_message(msg)
        else:
            self.send_message(msg_inv(inv=[CInv(2, block.sha256)]))
        self.wait_for_getdata()
        return


class SegWitTest(BitcoinTestFramework):
    def setup_chain(self):
        initialize_chain_clean(self.options.tmpdir, 1)

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug", "-logtimemicros=1", "-whitelist=127.0.0.1"]))

    def test_witness_services(self):
        print "\tVerifying NODE_WITNESS service bit\n"
        assert((self.test_node.connection.nServices & NODE_WITNESS) != 0)

    # Build a block on top of node0's tip.
    def build_next_block(self, nVersion=4):
        tip = self.nodes[0].getbestblockhash()
        height = self.nodes[0].getblockcount() + 1
        block_time = self.nodes[0].getblockheader(tip)["mediantime"] + 1
        block = create_block(int(tip, 16), create_coinbase(height), block_time)
        block.nVersion = nVersion
        block.rehash()
        return block

    # Test whether a witness block had the correct effect on the tip
    def test_witness_block(self, block, accepted):
        self.test_node.send_message(msg_witness_block(block))
        self.test_node.sync_with_ping()
        assert_equal(self.nodes[0].getbestblockhash() == block.hash, accepted)

    def test_witness_tx(self, tx, accepted):
        self.test_node.send_message(msg_witness_tx(tx))
        self.test_node.sync_with_ping()
        assert_equal(tx.hash in self.nodes[0].getrawmempool(), accepted)

    # Adds list of transactions to block, adds witness commitment, then solves.
    def update_witness_block_with_transactions(self, block, tx_list, nonce=0L):
        block.vtx.extend(tx_list)
        add_witness_commitment(block, nonce)
        block.solve()
        return


    # See if sending a regular transaction works
    def test_non_witness_transaction(self):
        # Mine a block with an anyone-can-spend coinbase,
        # let it mature, then try to spend it.
        print "\tTesting non-witness transaction"
        block = self.build_next_block(nVersion=1)
        block.solve()
        self.test_node.send_message(msg_block(block))
        self.test_node.sync_with_ping() # make sure the block was processed
        txid = block.vtx[0].sha256

        self.nodes[0].generate(99) # let the block mature

        # Create a transaction that spends the coinbase
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(txid, 0), ""))
        tx.vout.append(CTxOut(49*100000000, CScript([OP_TRUE])))
        tx.calc_sha256()

        # Check that serializing it with or without witness is the same
        # This is a sanity check of our testing framework.
        assert_equal(msg_tx(tx).serialize(), msg_witness_tx(tx).serialize())

        self.test_node.send_message(msg_witness_tx(tx))
        self.test_node.sync_with_ping() # make sure the tx was processed
        assert(tx.hash in self.nodes[0].getrawmempool())
        # Save this transaction for later
        self.utxo.append([tx.sha256, 0, 49*100000000])
        self.nodes[0].generate(1)

    # Verify that the mempool rejects witness transactions before activation,
    # and that witness blocks are rejected before activation.
    def test_unnecessary_witness_before_segwit_activation(self):
        print "\tTesting behavior of unnecessary witnesses (pre-activation)"
        # For now, rely on earlier tests to have created at least one utxo for
        # us to use
        # TODO: create a new utxo to use if necessary
        assert(len(self.utxo) > 0)
        assert(get_bip9_status(self.nodes[0], 'witness')['status'] != 'active')

        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0][0], self.utxo[0][1]), ""))
        tx.vout.append(CTxOut(self.utxo[0][2]-1000, CScript([OP_TRUE])))
        tx.wit.vtxinwit.append(CTxinWitness())
        tx.wit.vtxinwit[0].scriptWitness.stack = [CScript([OP_TRUE])]

        # Verify the hash with witness differs from the txid
        # (otherwise our testing framework must be broken!)
        tx.rehash()
        assert(tx.sha256 != tx.calc_sha256(with_witness=True))

        # Try sending the transaction, should fail to get added
        self.test_node.send_message(msg_witness_tx(tx))
        self.test_node.sync_with_ping()
        assert_equal(self.test_node.last_reject.reason, "no-witness-yet")
        assert(tx.hash not in self.nodes[0].getrawmempool())

        # TODO: verify that mempool acceptance succeeds after dropping the
        # witness.
        # TODO: try this with trickier cases too, eg non-DER or HIGH_S sigs
        # in witness.

        # Construct a segwit-signaling block that includes the transaction.
        block = self.build_next_block(nVersion=(VB_TOP_BITS|(1 << VB_WITNESS_BIT)))
        self.update_witness_block_with_transactions(block, [tx])
        # Sending witness data before activation is not allowed (anti-spam
        # rule).
        self.test_witness_block(block, accepted=False)
        # TODO: fix synchronization so we can test reject reason
        #assert_equal(self.test_node.last_reject.reason, "unexpected-witness")

        # But it should not be permanently marked bad...
        # Resend without witness information.
        self.test_node.send_message(msg_block(block))
        self.test_node.sync_with_ping()
        assert_equal(self.nodes[0].getbestblockhash(), block.hash)

        # Update our utxo list; we spent the first entry.
        self.utxo.pop(0)
        self.utxo.append([tx.sha256, 0, tx.vout[0].nValue])

    # Mine enough blocks to lock in segwit, but don't activate.
    # TODO: we could verify that lockin only happens at the right threshold of
    # signalling blocks, rather than just at the right period boundary.
    def advance_to_segwit_lockin(self):
        height = self.nodes[0].getblockcount()
        # Will need to rewrite the tests here if we are past the first period
        assert(height < VB_PERIOD - 1)
        # Genesis block is 'defined'.
        assert_equal(get_bip9_status(self.nodes[0], 'witness')['status'], 'defined')
        # Advance to end of period, status should now be 'started'
        self.nodes[0].generate(VB_PERIOD-height-1)
        assert_equal(get_bip9_status(self.nodes[0], 'witness')['status'], 'started')
        # Advance to end of period, and verify lock-in happens at the end
        self.nodes[0].generate(VB_PERIOD-1)
        height = self.nodes[0].getblockcount()
        assert((height % VB_PERIOD) == VB_PERIOD - 2)
        assert_equal(get_bip9_status(self.nodes[0], 'witness')['status'], 'started')
        self.nodes[0].generate(1)
        assert_equal(get_bip9_status(self.nodes[0], 'witness')['status'], 'locked_in')

    # Mine enough blocks to activate segwit.
    # TODO: we could verify that activation only happens at the right threshold
    # of signalling blocks, rather than just at the right period boundary.
    def advance_to_segwit_active(self):
        assert_equal(get_bip9_status(self.nodes[0], 'witness')['status'], 'locked_in')
        height = self.nodes[0].getblockcount()
        self.nodes[0].generate(VB_PERIOD - (height%VB_PERIOD) - 2)
        assert_equal(get_bip9_status(self.nodes[0], 'witness')['status'], 'locked_in')
        self.nodes[0].generate(1)
        assert_equal(get_bip9_status(self.nodes[0], 'witness')['status'], 'active')

    # This test can only be run after segwit has activated
    def test_witness_commitments(self):
        print "\tTesting witness commitments (post activation)"

        # First try a correct witness commitment.
        block = self.build_next_block()
        add_witness_commitment(block)
        block.solve()

        # Test the test -- witness serialization should be different
        assert(msg_witness_block(block).serialize() != msg_block(block).serialize())

        # This empty block should be valid.
        self.test_witness_block(block, accepted=True)

        # Try to tweak the nonce
        block_2 = self.build_next_block()
        add_witness_commitment(block_2, nonce=28L)
        block_2.solve()

        # The commitment should have changed!
        assert(block_2.vtx[0].vout[-1] != block.vtx[0].vout[-1])

        # This should also be valid.
        self.test_witness_block(block_2, accepted=True)

        # Now test commitments with actual transactions
        # TODO: handle the case that we're out of utxo's to spend
        assert (len(self.utxo) > 0)
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0][0], self.utxo[0][1]), ""))

        # Let's construct a witness program
        witness_program = CScript([OP_TRUE])
        witness_hash = sha256(witness_program)
        scriptPubKey = CScript([OP_0, witness_hash])
        tx.vout.append(CTxOut(self.utxo[0][2]-1000, scriptPubKey))
        tx.rehash()

        # tx2 will spend tx1, and send back to a regular anyone-can-spend address
        tx2 = CTransaction()
        tx2.vin.append(CTxIn(COutPoint(tx.sha256, 0), ""))
        tx2.vout.append(CTxOut(tx.vout[0].nValue-1000, witness_program))
        tx2.wit.vtxinwit.append(CTxinWitness())
        tx2.wit.vtxinwit[0].scriptWitness.stack = [witness_program]
        tx2.rehash()

        block_3 = self.build_next_block()
        self.update_witness_block_with_transactions(block_3, [tx, tx2], nonce=1L)
        # Add an extra OP_RETURN output that matches the witness commitment template,
        # even though it has extra data after the incorrect commitment.
        # This block should fail.
        block_3.vtx[0].vout.append(CTxOut(0, CScript([OP_RETURN, WITNESS_COMMITMENT_HEADER + ser_uint256(2), 10])))
        block_3.vtx[0].rehash()
        block_3.hashMerkleRoot = block_3.calc_merkle_root()
        block_3.rehash()
        block_3.solve()

        self.test_witness_block(block_3, accepted=False)

        # Add a different commitment with different nonce, but in the
        # right location, and with some funds burned(!).
        # This should succeed (nValue shouldn't affect finding the
        # witness commitment).
        add_witness_commitment(block_3, nonce=0L)
        block_3.vtx[0].vout[0].nValue -= 1
        block_3.vtx[0].vout[-1].nValue += 1
        block_3.vtx[0].rehash()
        block_3.hashMerkleRoot = block_3.calc_merkle_root()
        block_3.rehash()
        assert(len(block_3.vtx[0].vout) == 4) # 3 OP_returns
        block_3.solve()
        self.test_witness_block(block_3, accepted=True)

        # Update available utxo's for use in later test.
        self.utxo.pop(0)
        self.utxo.append([tx2.sha256, 0, tx2.vout[0].nValue])
       
    def test_block_malleability(self):
        print "\tTesting witness block malleability"

        # Make sure that a block that has too big a virtual size
        # because of a too-large coinbase witness is not permanently
        # marked bad.
        block = self.build_next_block()
        add_witness_commitment(block)
        block.solve()

        block.vtx[0].wit.vtxinwit[0].scriptWitness.stack.append('a'*5000000)
        assert(get_virtual_size(block) > MAX_BLOCK_SIZE)

        # We can't send over the p2p network, because this is too big to relay
        # TODO: repeat this test with a block that can be relayed
        self.nodes[0].submitblock(binascii.hexlify(block.serialize(True)))

        assert(self.nodes[0].getbestblockhash() != block.hash)

        block.vtx[0].wit.vtxinwit[0].scriptWitness.stack.pop()
        assert(get_virtual_size(block) < MAX_BLOCK_SIZE)
        self.nodes[0].submitblock(binascii.hexlify(block.serialize(True)))

        assert(self.nodes[0].getbestblockhash() == block.hash)

        # Now make sure that malleating the witness nonce doesn't
        # result in a block permanently marked bad.
        block = self.build_next_block()
        add_witness_commitment(block)
        block.solve()

        # Change the nonce -- should not cause the block to be permanently
        # failed
        block.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [ ser_uint256(1L) ]
        self.test_witness_block(block, accepted=False)

        # Changing the witness nonce doesn't change the block hash
        block.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [ ser_uint256(0) ]
        self.test_witness_block(block, accepted=True)


    def test_witness_block_size(self):
        print "\tTesting enforcement of witness block size limit"
        # TODO: Test that non-witness carrying blocks can't exceed 1MB
        # Skipping this test for now; this is covered in p2p-fullblocktest.py

        # Test that witness-bearing blocks are limited at ceil(base + wit/4) <= 1MB.
        block = self.build_next_block()

        assert(len(self.utxo) > 0)
        
        # Create a P2WSH transaction.
        # The witness program will be a bunch of OP_2DROP's, followed by OP_TRUE.
        # This should give us plenty of room to tweak the spending tx's
        # virtual size.
        NUM_DROPS = 200 # 201 max ops per script!
        NUM_OUTPUTS = 50

        witness_program = CScript([OP_2DROP]*NUM_DROPS + [OP_TRUE])
        witness_hash = uint256_from_str(sha256(witness_program))
        scriptPubKey = CScript([OP_0, ser_uint256(witness_hash)])

        prevout = COutPoint(self.utxo[0][0], self.utxo[0][1])
        value = self.utxo[0][2]

        parent_tx = CTransaction()
        parent_tx.vin.append(CTxIn(prevout, ""))
        child_value = int(value/NUM_OUTPUTS)
        for i in xrange(NUM_OUTPUTS):
            parent_tx.vout.append(CTxOut(child_value, scriptPubKey))
        parent_tx.vout[0].nValue -= 50000
        assert(parent_tx.vout[0].nValue > 0)
        parent_tx.rehash()

        child_tx = CTransaction()
        for i in xrange(NUM_OUTPUTS):
            child_tx.vin.append(CTxIn(COutPoint(parent_tx.sha256, i), ""))
        child_tx.vout = [CTxOut(value - 100000, CScript([OP_TRUE]))]
        for i in xrange(NUM_OUTPUTS):
            child_tx.wit.vtxinwit.append(CTxinWitness())
            child_tx.wit.vtxinwit[-1].scriptWitness.stack = ['a'*195]*(2*NUM_DROPS) + [witness_program]
        child_tx.rehash()
        self.update_witness_block_with_transactions(block, [parent_tx, child_tx])

        vsize = get_virtual_size(block)
        additional_bytes = (MAX_BLOCK_SIZE - vsize)*4
        i = 0
        while additional_bytes > 0:
            # Add some more bytes to each input until we hit MAX_BLOCK_SIZE+1
            extra_bytes = min(additional_bytes+1, 55)
            block.vtx[-1].wit.vtxinwit[int(i/(2*NUM_DROPS))].scriptWitness.stack[i%(2*NUM_DROPS)] = 'a'*(195+extra_bytes)
            additional_bytes -= extra_bytes
            i += 1

        block.vtx[0].vout.pop()  # Remove old commitment
        add_witness_commitment(block)
        block.solve()
        vsize = get_virtual_size(block)
        assert_equal(vsize, MAX_BLOCK_SIZE + 1)
        # Make sure that our test case would exceed the old max-network-message
        # limit
        assert(len(block.serialize(True)) > 2*1024*1024)

        self.test_witness_block(block, accepted=False)

        # Now resize the second transaction to make the block fit.
        cur_length = len(block.vtx[-1].wit.vtxinwit[0].scriptWitness.stack[0])
        block.vtx[-1].wit.vtxinwit[0].scriptWitness.stack[0] = 'a'*(cur_length-1)
        block.vtx[0].vout.pop()
        add_witness_commitment(block)
        block.solve()
        assert(get_virtual_size(block) == MAX_BLOCK_SIZE)

        self.test_witness_block(block, accepted=True)

        # Update available utxo's
        self.utxo.pop(0)
        self.utxo.append([block.vtx[-1].sha256, 0, block.vtx[-1].vout[0].nValue])


    # submitblock will try to add the nonce automatically, so that mining
    # software doesn't need to worry about doing so itself.
    def test_submit_block(self):
        block = self.build_next_block()

        # Try using a custom nonce and then don't supply it.
        # This shouldn't possibly work.
        add_witness_commitment(block, nonce=1L)
        block.vtx[0].wit = CTxWitness() # drop the nonce
        block.solve()
        self.nodes[0].submitblock(binascii.hexlify(block.serialize(True)))
        assert(self.nodes[0].getbestblockhash() != block.hash)

        # Now redo commitment with the standard nonce, but let bitcoind fill it in.
        add_witness_commitment(block, nonce=0L)
        block.vtx[0].wit = CTxWitness()
        block.solve()
        self.nodes[0].submitblock(binascii.hexlify(block.serialize(True)))
        assert_equal(self.nodes[0].getbestblockhash(), block.hash)

        # This time, add a tx with non-empty witness, but don't supply
        # the commitment.
        block_2 = self.build_next_block()

        add_witness_commitment(block_2)

        block_2.solve()

        # Drop commitment and nonce -- submitblock should not fill in.
        block_2.vtx[0].vout.pop()
        block_2.vtx[0].wit = CTxWitness()

        self.nodes[0].submitblock(binascii.hexlify(block_2.serialize(True)))
        # Tip should not advance!
        assert(self.nodes[0].getbestblockhash() != block_2.hash)

    # TODO: add testing of mempool acceptance to this test.
    def test_extra_witness_data(self):
        print "Testing extra witness data in tx after segwit activation"

        assert(len(self.utxo) > 0)
        
        block = self.build_next_block()

        witness_program = CScript([OP_DROP, OP_TRUE])
        witness_hash = sha256(witness_program)
        scriptPubKey = CScript([OP_0, witness_hash])

        # First try extra witness data on a tx that doesn't require a witness
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0][0], self.utxo[0][1]), ""))
        tx.vout.append(CTxOut(self.utxo[0][2]-1000, scriptPubKey))
        tx.wit.vtxinwit.append(CTxinWitness())
        tx.wit.vtxinwit[0].scriptWitness.stack = [CScript([])]
        tx.rehash()
        self.update_witness_block_with_transactions(block, [tx])

        # Extra witness data should not be allowed.
        self.test_witness_block(block, accepted=False)

        # Try extra signature data.  Ok if we're not spending a P2WSH
        # address.
        block.vtx[1].wit.vtxinwit = []
        block.vtx[1].vin[0].scriptSig = CScript([OP_0])
        block.vtx[1].rehash()
        add_witness_commitment(block)
        block.solve()

        self.test_witness_block(block, accepted=True)

        # Now try extra witness/signature data on a tx that DOES require a
        # witness 
        tx2 = CTransaction()
        tx2.vin.append(CTxIn(COutPoint(tx.sha256, 0), ""))
        tx2.vout.append(CTxOut(tx.vout[0].nValue-1000, CScript([OP_TRUE])))
        tx2.wit.vtxinwit.append(CTxinWitness())
        tx2.wit.vtxinwit[0].scriptWitness.stack = [ CScript([OP_TRUE]), CScript([OP_TRUE]), witness_program ]

        block = self.build_next_block()
        self.update_witness_block_with_transactions(block, [tx2])

        # This has extra witness data, so it should fail.
        self.test_witness_block(block, accepted=False)

        # Now get rid of the extra witness, but add extra scriptSig data
        tx2.vin[0].scriptSig = CScript([OP_TRUE])
        tx2.wit.vtxinwit[0].scriptWitness.stack.pop(0)
        tx2.rehash()
        add_witness_commitment(block)
        block.solve()

        # This has extra signature data, so it should fail.
        self.test_witness_block(block, accepted=False)

        # Now get rid of the extra scriptsig, and verify success
        tx2.vin[0].scriptSig = ""
        tx2.rehash()
        add_witness_commitment(block)
        block.solve()

        self.test_witness_block(block, accepted=True)

        # Update utxo for later tests
        self.utxo.pop(0)
        self.utxo.append([tx2.sha256, 0, tx2.vout[0].nValue])


    def test_max_witness_push_length(self):
        ''' Should only allow up to 520 byte pushes in witness stack '''
        print "Testing maximum witness push size"
        MAX_SCRIPT_ELEMENT_SIZE = 520
        assert(len(self.utxo))

        block = self.build_next_block()

        witness_program = CScript([OP_DROP, OP_TRUE])
        witness_hash = sha256(witness_program)
        scriptPubKey = CScript([OP_0, witness_hash])

        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0][0], self.utxo[0][1]), ""))
        tx.vout.append(CTxOut(self.utxo[0][2]-1000, scriptPubKey))
        tx.rehash()

        tx2 = CTransaction()
        tx2.vin.append(CTxIn(COutPoint(tx.sha256, 0), ""))
        tx2.vout.append(CTxOut(tx.vout[0].nValue-1000, CScript([OP_TRUE])))
        tx2.wit.vtxinwit.append(CTxinWitness())
        # First try a 521-byte stack element
        tx2.wit.vtxinwit[0].scriptWitness.stack = [ 'a'*(MAX_SCRIPT_ELEMENT_SIZE+1), witness_program ]
        tx2.rehash()

        self.update_witness_block_with_transactions(block, [tx, tx2])
        self.test_witness_block(block, accepted=False)

        # Now reduce the length of the stack element
        tx2.wit.vtxinwit[0].scriptWitness.stack[0] = 'a'*(MAX_SCRIPT_ELEMENT_SIZE)

        add_witness_commitment(block)
        block.solve()
        self.test_witness_block(block, accepted=True)

        # Update the utxo for later tests
        self.utxo.pop()
        self.utxo.append([tx2.sha256, 0, tx2.vout[0].nValue])

    def test_max_witness_program_length(self):
        # Can create witness outputs that are long, but can't be greater than
        # 10k bytes to successfully spend
        print "Testing witness program max length"
        assert(len(self.utxo))
        MAX_PROGRAM_LENGTH = 10000

        # This program is 19 max pushes (9937 bytes), then 64 more opcode-bytes.
        long_witness_program = CScript(['a'*520]*19 + [OP_DROP]*63 + [OP_TRUE])
        assert(len(long_witness_program) == MAX_PROGRAM_LENGTH+1)
        long_witness_hash = sha256(long_witness_program)
        long_scriptPubKey = CScript([OP_0, long_witness_hash])

        block = self.build_next_block()

        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0][0], self.utxo[0][1]), ""))
        tx.vout.append(CTxOut(self.utxo[0][2]-1000, long_scriptPubKey))
        tx.rehash()

        tx2 = CTransaction()
        tx2.vin.append(CTxIn(COutPoint(tx.sha256, 0), ""))
        tx2.vout.append(CTxOut(tx.vout[0].nValue-1000, CScript([OP_TRUE])))
        tx2.wit.vtxinwit.append(CTxinWitness())
        tx2.wit.vtxinwit[0].scriptWitness.stack = ['a']*44 + [long_witness_program]
        tx2.rehash()

        self.update_witness_block_with_transactions(block, [tx, tx2])

        self.test_witness_block(block, accepted=False)

        # Try again with one less byte in the witness program
        witness_program = CScript(['a'*520]*19 + [OP_DROP]*62 + [OP_TRUE])
        assert(len(witness_program) == MAX_PROGRAM_LENGTH)
        witness_hash = sha256(witness_program)
        scriptPubKey = CScript([OP_0, witness_hash])

        tx.vout[0] = CTxOut(tx.vout[0].nValue, scriptPubKey)
        tx.rehash()
        tx2.vin[0].prevout.hash = tx.sha256
        tx2.wit.vtxinwit[0].scriptWitness.stack = ['a']*43 + [witness_program]
        tx2.rehash()
        block.vtx = [block.vtx[0]]
        self.update_witness_block_with_transactions(block, [tx, tx2])
        self.test_witness_block(block, accepted=True)

        self.utxo.pop()

        self.utxo.append([tx2.sha256, 0, tx2.vout[0].nValue])


    def test_witness_input_length(self):
        ''' Ensure that vin length must match vtxinwit length '''
        print "Testing witness input length"
        assert(len(self.utxo))

        witness_program = CScript([OP_DROP, OP_TRUE])
        witness_hash = sha256(witness_program)
        scriptPubKey = CScript([OP_0, witness_hash])
        
        # Create a transaction that splits our utxo into many outputs
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0][0], self.utxo[0][1]), ""))
        nValue = self.utxo[0][2]
        for i in xrange(10):
            tx.vout.append(CTxOut(int(nValue/10), scriptPubKey))
        tx.vout[0].nValue -= 1000
        assert(tx.vout[0].nValue >= 0)

        block = self.build_next_block()
        self.update_witness_block_with_transactions(block, [tx])
        self.test_witness_block(block, accepted=True)

        # Try various ways to spend tx that should all break.
        # This "broken" transaction serializer will not normalize
        # the length of vtxinwit.
        class BrokenCTransaction(CTransaction):
            def serialize_with_witness(self):
                flags = 0
                if not self.wit.is_null():
                    flags |= 1
                r = ""
                r += struct.pack("<i", self.nVersion)
                if flags:
                    dummy = []
                    r += ser_vector(dummy)
                    r += struct.pack("<B", flags)
                r += ser_vector(self.vin)
                r += ser_vector(self.vout)
                if flags & 1:
                    r += self.wit.serialize()
                r += struct.pack("<I", self.nLockTime)
                return r

        tx2 = BrokenCTransaction()
        for i in xrange(10):
            tx2.vin.append(CTxIn(COutPoint(tx.sha256, i), ""))
        tx2.vout.append(CTxOut(nValue-3000, CScript([OP_TRUE])))

        # First try using a too long vtxinwit
        for i in xrange(11):
            tx2.wit.vtxinwit.append(CTxinWitness())
            tx2.wit.vtxinwit[i].scriptWitness.stack = ['a', witness_program]

        block = self.build_next_block()
        self.update_witness_block_with_transactions(block, [tx2])
        self.test_witness_block(block, accepted=False)

        # Now try using a too short vtxinwit
        tx2.wit.vtxinwit.pop()
        tx2.wit.vtxinwit.pop()

        block.vtx = [block.vtx[0]]
        self.update_witness_block_with_transactions(block, [tx2])
        self.test_witness_block(block, accepted=False)

        # Now make one of the intermediate witnesses be incorrect
        tx2.wit.vtxinwit.append(CTxinWitness())
        tx2.wit.vtxinwit[-1].scriptWitness.stack = ['a', witness_program]
        tx2.wit.vtxinwit[5].scriptWitness.stack = [ witness_program ]

        block.vtx = [block.vtx[0]]
        self.update_witness_block_with_transactions(block, [tx2])
        self.test_witness_block(block, accepted=False)

        # Fix the broken witness and the block should be accepted.
        tx2.wit.vtxinwit[5].scriptWitness.stack = ['a', witness_program]
        block.vtx = [block.vtx[0]]
        self.update_witness_block_with_transactions(block, [tx2])
        self.test_witness_block(block, accepted=True)

        self.utxo.pop()
        self.utxo.append([tx2.sha256, 0, tx2.vout[0].nValue])

    def test_witness_tx_relay_before_segwit_activation(self):
        print "Testing relay of witness transactions - before segwit activation"
        # Generate a transaction that doesn't require a witness, but send it
        # with a witness.  Should be rejected for premature-witness, but should
        # not be added to recently rejected list.
        assert(len(self.utxo))
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0][0], self.utxo[0][1]), ""))
        tx.vout.append(CTxOut(self.utxo[0][2]-1000, CScript([OP_TRUE])))
        tx.wit.vtxinwit.append(CTxinWitness())
        tx.wit.vtxinwit[0].scriptWitness.stack = [ 'a' ]
        tx.rehash()

        tx_hash = tx.sha256
        tx_value = tx.vout[0].nValue

        # TODO: Verify that if we don't set nServices to include NODE_WITNESS,
        # the getdata is jsut for the non-witness portion.
        self.test_node.announce_tx_and_wait_for_getdata(tx)
        #assert(self.test_node.last_getdata.inv[0].type == 1)

        # Delivering this transaction should fail
        self.test_witness_tx(tx, accepted=False)

        # But eliminating the witness should fix it
        tx.wit = CTxWitness()
        self.test_witness_tx(tx, accepted=True)

        # Now send a havewitness message, and verify that future inv's
        # come with getdata's for witness tx's
        # self.test_node.send_message(msg_havewitness())
        # Tweak the transaction, announce it, and verify we get a getdata
        # for a witness_tx
        tx.vout[0].scriptPubKey = CScript([OP_TRUE, OP_TRUE])
        tx.rehash()
        self.test_node.announce_tx_and_wait_for_getdata(tx)
        assert(self.test_node.last_getdata.inv[0].type == 1|MSG_WITNESS_FLAG)

        # Mine the transaction and update utxo
        self.nodes[0].generate(1)
        assert_equal(len(self.nodes[0].getrawmempool()),  0)

        self.utxo.pop(0)
        self.utxo.append([tx_hash, 0, tx_value])


    # TODO: test witness block relay from old node
    # Test that block requests to NODE_WITNESS peer are with MSG_WITNESS_FLAG
    def test_witness_block_relay(self):
        print "Testing witness block relay"

        # test_node has set NODE_WITNESS, so all getdata requests should be for
        # witness blocks.
        # Test announcing a block via inv results in a getdata, and that
        # announcing a version 4 or random VB block with a header results in a getdata

        block1 = self.build_next_block()
        block1.solve()

        self.test_node.announce_block_and_wait_for_getdata(block1, use_header=False)
        assert(self.test_node.last_getdata.inv[0].type == 2|MSG_WITNESS_FLAG)
        self.test_witness_block(block1, True)

        block2 = self.build_next_block(nVersion=4)
        block2.solve()

        self.test_node.announce_block_and_wait_for_getdata(block2, use_header=True)
        assert(self.test_node.last_getdata.inv[0].type == 2|MSG_WITNESS_FLAG)
        self.test_witness_block(block2, True)

        block3 = self.build_next_block(nVersion=(VB_TOP_BITS | (1<<15)))
        block3.solve()
        self.test_node.announce_block_and_wait_for_getdata(block3, use_header=True)
        assert(self.test_node.last_getdata.inv[0].type == 2|MSG_WITNESS_FLAG)
        self.test_witness_block(block3, True)


    def run_test(self):
        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode() # sets NODE_WITNESS|NODE_NETWORK
        self.old_node = TestNode()  # only NODE_NETWORK

        self.p2p_connections = [self.test_node, self.old_node]

        self.connections = []
        self.connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node, services=NODE_NETWORK|NODE_WITNESS))
        self.connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.old_node, services=NODE_NETWORK))
        self.test_node.add_connection(self.connections[0])
        self.old_node.add_connection(self.connections[1])

        NetworkThread().start() # Start up network handling in another thread

        # Keep a place to store utxo's that can be used in later tests
        self.utxo = []

        # Test logic begins here
        self.test_node.wait_for_verack()

        print "Starting tests before segwit lock in:"
        self.test_witness_services()

        self.test_non_witness_transaction()

        self.test_unnecessary_witness_before_segwit_activation()

        self.test_witness_block_relay()

        # At lockin, nothing should change.
        print "Testing behavior post lockin, pre-activation"
        self.advance_to_segwit_lockin()

        # Retest unnecessary witnesses
        self.test_unnecessary_witness_before_segwit_activation()

        self.test_witness_tx_relay_before_segwit_activation()

        self.test_witness_block_relay()

        # Now activate segwit
        print "Testing behavior after segwit activation"
        self.advance_to_segwit_active()

        self.test_witness_commitments()

        self.test_block_malleability()

        self.test_witness_block_size()

        self.test_submit_block()

        self.test_extra_witness_data()

        self.test_max_witness_push_length()

        self.test_max_witness_program_length()

        self.test_witness_input_length()

        self.test_witness_block_relay()

        # TODO: test that mempool acceptance rules don't allow valid witness
        # tx's until after segwit activation

        # TODO: input value covered by hash? first reimplement transaction
        # hashing for signature.  verify that we can sign stuff!

        print "success!"
        


if __name__ == '__main__':
    SegWitTest().main()
