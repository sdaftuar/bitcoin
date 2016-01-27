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

'''
SegWit p2p test.
'''

def get_virtual_size(witness_block):
    base_size = len(witness_block.serialize())
    total_size = len(witness_block.serialize(with_witness=True))
    # the "+3" is so we round up
    vsize = int((3*base_size + total_size + 3)/4)
    return vsize

class TestNode(NodeConnCB):
    def __init__(self):
        NodeConnCB.__init__(self)
        self.connection = None
        self.ping_counter = 1
        self.last_pong = msg_pong(0)
        self.sleep_time = 0.05
        self.got_have_witness = False
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

    def on_havewitness(self, conn, message):
        self.got_have_witness = True

    def on_reject(self, conn, message):
        self.last_reject = message
        print message

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

    def wait_for_havewitness(self, timeout=60):
        test_function = lambda: self.got_have_witness == True
        self.sync(test_function, timeout)
        return

    def send_header_for_blocks(self, new_blocks):
        headers_message = msg_headers()
        headers_message.headers = [ CBlockHeader(b) for b in new_blocks ]
        self.send_message(headers_message)

class SegWitTest(BitcoinTestFramework):
    def setup_chain(self):
        initialize_chain_clean(self.options.tmpdir, 1)

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug", "-logtimemicros=1", "-whitelist=127.0.0.1"]))
    def test_havewitness(self):
        print "Testing receipt of havewitness p2p message"
        self.test_node.wait_for_havewitness()

    def build_next_block(self, nVersion=5):
        tip = self.nodes[0].getbestblockhash()
        height = self.nodes[0].getblockcount() + 1
        block_time = self.nodes[0].getblockheader(tip)["mediantime"] + 1
        block = create_block(int(tip, 16), create_coinbase(height), block_time)
        block.nVersion = nVersion
        block.rehash()
        return block

    # See if sending a regular transaction works
    def test_non_witness_transaction(self):
        # Mine a block with an anyone-can-spend coinbase,
        # let it mature, then try to spend it.
        print "Testing non-witness transaction"
        block = self.build_next_block(nVersion=1)
        block.solve()
        self.test_node.send_message(msg_block(block))
        print "  Sent a new block"
        self.test_node.sync_with_ping() # make sure the block was processed
        print "  Block synced"
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

    def test_unnecessary_witness_before_block_upgrade(self):
        print "Testing behavior of unnecessary witnesses (before 75% threshold)"
        # For now, rely on earlier tests to have created at least one utxo for
        # us to use
        # TODO: create a new utxo to use if necessary
        assert(len(self.utxo) > 0)
        # TODO: check that 75% hasn't triggered yet
        # (needs to be added to softforks)
        for i in self.nodes[0].getblockchaininfo()["softforks"]:
            if (i["version"] >= 4):
                assert(not i["enforce"]["status"])
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

        # Construct a v5 block that includes the transaction.
        block = self.build_next_block(nVersion=5)
        block.vtx.append(tx)
        add_witness_commitment(block) # this will update the merkle root for us
        block.solve()

        # Sending witness data before 75% threshold is reached is
        # not allowed (anti-spam rule).
        self.test_node.send_message(msg_witness_block(block))
        self.test_node.sync_with_ping()
        assert(self.nodes[0].getbestblockhash() != block.hash)
        assert_equal(self.test_node.last_reject.reason, "unexpected-witness")

        # But it should not be permanently marked bad...
        # Resend without witness information.
        self.test_node.send_message(msg_block(block))
        self.test_node.sync_with_ping()
        assert_equal(self.nodes[0].getbestblockhash(), block.hash)

        # Update our utxo list; we spent the first entry.
        self.utxo.pop(0)
        self.utxo.append([tx.sha256, 0, tx.vout[0].nValue])

    def advance_to_enforce_upgrade(self):
        # We could carefully look at each block header and test that the
        # switchover is correct.  However that is covered in another test
        # already, so skip it.
        self.nodes[0].generate(max(751 - self.nodes[0].getblockcount(), 1))
        # TODO: replace this with nVersion >= 5
        for i in self.nodes[0].getblockchaininfo()["softforks"]:
            if (i["version"] >= 4):
                assert(i["enforce"]["status"])

    # This test can only be run after 75% threshold is reached.
    def test_witness_commitments(self):
        print "Testing witness commitments"

        # First try a correct witness commitment.
        block = self.build_next_block(nVersion=5)
        add_witness_commitment(block)
        block.solve()

        # Test the test -- witness serialization should be different
        assert(msg_witness_block(block).serialize() != msg_block(block).serialize())

        # This empty block should be valid.
        self.test_node.send_message(msg_witness_block(block))
        self.test_node.sync_with_ping()
        assert_equal(self.nodes[0].getbestblockhash(), block.hash)

        # Try to tweak the nonce
        block_2 = self.build_next_block(nVersion=5)
        add_witness_commitment(block_2, nonce=28L)
        block_2.solve()

        # The commitment should have changed!
        assert(block_2.vtx[0].vout[-1] != block.vtx[0].vout[-1])

        # This should also be valid.
        self.test_node.send_message(msg_witness_block(block_2))
        self.test_node.sync_with_ping()
        assert_equal(self.nodes[0].getbestblockhash(), block_2.hash)

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

        block_3 = self.build_next_block(nVersion=5)
        block_3.vtx.extend([tx, tx2])
        add_witness_commitment(block_3, nonce=1L)
        # Add an extra OP_RETURN output that matches the witness commitment template,
        # even though it has extra data after the incorrect commitment.
        # This block should fail.
        block_3.vtx[0].vout.append(CTxOut(0, CScript([OP_RETURN, WITNESS_COMMITMENT_HEADER + ser_uint256(2), 10])))
        block_3.vtx[0].rehash()
        block_3.hashMerkleRoot = block_3.calc_merkle_root()
        block_3.rehash()
        block_3.solve()

        self.test_node.send_message(msg_witness_block(block_3))
        self.test_node.sync_with_ping()
        assert_equal(self.nodes[0].getbestblockhash(), block_2.hash)

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
        self.test_node.send_message(msg_witness_block(block_3))
        self.test_node.sync_with_ping()
        assert_equal(self.nodes[0].getbestblockhash(), block_3.hash)

        # Update available utxo's for use in later test.
        self.utxo.pop(0)
        self.utxo.append([tx2.sha256, 0, tx2.vout[0].nValue])
       

    def test_witness_block_size(self):
        print "Testing enforcement of witness block size limit"
        # TODO: Test that non-witness carrying blocks can't exceed 1MB
        # Skipping this test for now; this is covered in p2p-fullblocktest.py

        # Test that witness-bearing blocks are limited at ceil(base + wit/4) <= 1MB.
        block = self.build_next_block(nVersion=5)

        assert(len(self.utxo) > 0)
        
        # Create a P2WSH transaction.
        # The witness program will be a bunch of OP_DROP's, followed by OP_TRUE.
        # This should give us plenty of room to tweak the spending tx's
        # virtual size.
        NUM_DROPS = 197 # max ops per script!

        witness_program = CScript([OP_2DROP]*NUM_DROPS + [OP_TRUE])
        witness_hash = uint256_from_str(sha256(witness_program))
        scriptPubKey = CScript([OP_0, ser_uint256(witness_hash)])

        prevout = COutPoint(self.utxo[0][0], self.utxo[0][1])
        value = self.utxo[0][2]

        # Create 20 transactions, each of which will be approximately 50k in virtual size
        txs = []
        for i in xrange(21):
            txs.append(CTransaction())
            txs[i].vin.append(CTxIn(prevout, ""))
            txs[i].vout.append(CTxOut(value-1000, scriptPubKey))
            txs[i].rehash()

            # From the second transaction, we'll start adding witness data
            if (i > 0):
                txs[i].wit.vtxinwit.append(CTxinWitness())
                txs[i].wit.vtxinwit[0].scriptWitness.stack = [CScript(['a'*500])]*(2*NUM_DROPS) + [witness_program]
                
            txs[i].rehash()
            # ...and add it to the block.
            block.vtx.append(txs[i])

            prevout = COutPoint(txs[i].sha256, 0)
            value = txs[i].vout[0].nValue
            print i, ": ", 1000000 - get_virtual_size(block)
        
        vsize = get_virtual_size(block)
        additional_bytes = (MAX_BLOCK_SIZE - vsize)

        print "additional_bytes = ", additional_bytes

        # Just add an extra OP_RETURN output to use up the remaining bytes
        block.vtx[-1].vout.append(CTxOut(0, CScript(['OP_RETURN', 'a'*(additional_bytes-20)])))

        vsize = get_virtual_size(block)
        print "vsize= ", vsize
        # Get rid of the old commitment, and add a new one. 
        add_witness_commitment(block)

        block.hashMerkleRoot = block.calc_merkle_root()
        for i in block.vtx:
            print repr(i.hash)

        # Make sure we made a too-big block.
        #assert(get_virtual_size(block) > MAX_BLOCK_SIZE)
        #assert(len(block.serialize(True)) < 2*MAX_BLOCK_SIZE) # make sure it will relay

        block.solve()

        self.test_node.send_message(msg_witness_block(block))
        self.test_node.sync_with_ping()
        assert(self.nodes[0].getbestblockhash() == block.hash)

        # Now resize the second transaction to make the block fit.
        tx2.wit.vtxinwit[0].scriptWitness.stack[0] = CScript(['a'*(100000+additional_bytes)])
        # Get rid of the old commitment, and add a new one. 
        block.vtx[0].vout.pop()
        add_witness_commitment(block)
        assert(get_virtual_size(block) == MAX_BLOCK_SIZE)
        assert(len(block.serialize(True)) < 2*MAX_BLOCK_SIZE) # make sure it will relay
        block.solve()
        self.test_node.send_message(msg_witness_block(block))
        self.test_node.sync_with_ping()
        assert(self.nodes[0].getbestblockhash() == block.hash)

        # Now test the max size of a message sent over the p2p protocol.
        # Needs to be able to handle 4MB blocks.
        block_2 = self.build_next_block(nVersion=5)

        # Build a transaction that spends tx2's output.
        tx3 = CTransaction()
        tx3.vin.append(CTxIn(COutPoint(tx2.sha256, 0), ""))
        tx3.vout.append(CTxOut(tx2.vout[0].nValue-1000, CScript([OP_TRUE])))
        tx3.rehash()
        tx3.wit.vtxinwit.append(CTxinWitness())

        # Make this really big.
        tx3.wit.vtxinwit[0].scriptWitness.stack = [CScript(['a'*3000000]), witness_program]
        block_2.vtx.append(tx3)
        add_witness_commitment(block_2)
        block_2.solve()

        # This block is not too big for consensus
        assert(get_virtual_size(block_2) < MAX_BLOCK_SIZE)
        # But it is bigger than 2MiB on the wire
        assert(len(block_2.serialize(True)) > 2*1024*1024)
        self.test_node.send_message(msg_witness_block(block_2))
        
        if (self.nodes[0].getbestblockhash() != block_2.hash):
            # Try using submitblock instead
            self.nodes[0].submitblock(binascii.hexlify(block_2.serialize(True)))
            assert(self.nodes[0].getbestblockhash() == block_2.hash)
            print "ERROR bug found: submitblock accepts bigger blocks than p2p!"

            # Verify we got disconnected:
            self.test_node.wait_for_close()
            # Now switch to our backup connection
            self.test_node.add_connection(self.connections[-1])
            self.connections[-1].cb = self.test_node
            self.test_node.sync_with_ping()
        else:
            print "P2P successfully relayed block with size = ", len(block_2.serialize(True))

        # Update available utxo's
        self.utxo.pop(0)
        self.utxo.append([tx3.sha256, 0, tx3.vout[0].nValue])


    # submitblock will try to add the nonce automatically, so that mining
    # software doesn't need to worry about doing so itself.
    def test_submit_block(self):
        block = self.build_next_block(nVersion=5)

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
        block_2 = self.build_next_block(nVersion=5)

        add_witness_commitment(block_2)

        block_2.solve()

        # Drop commitment and nonce -- submitblock should not fill in.
        block_2.vtx[0].vout.pop()
        block_2.vtx[0].wit = CTxWitness()

        self.nodes[0].submitblock(binascii.hexlify(block_2.serialize(True)))
        # Tip should not advance!
        assert(self.nodes[0].getbestblockhash() != block_2.hash)

    def test_extra_witness_data(self):
        print "Testing extra witness data in tx after upgrade enforcement"

        assert(len(self.utxo) > 0)
        
        block = self.build_next_block(nVersion=5)

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
        block.vtx.append(tx)
        add_witness_commitment(block)
        block.solve()

        self.test_node.send_message(msg_witness_block(block))
        self.test_node.sync_with_ping()
        assert(self.nodes[0].getbestblockhash() != block.hash)

        # Try extra signature data as well.
        block.vtx[1].wit.vtxinwit = []
        block.vtx[1].vin[0].scriptSig = CScript([OP_0])
        block.vtx[1].rehash()
        add_witness_commitment(block)
        block.solve()

        # Extra data in signature is okay...
        self.test_node.send_message(msg_witness_block(block))
        self.test_node.sync_with_ping()
        assert(self.nodes[0].getbestblockhash() == block.hash)

        # Now try extra witness data on a tx that DOES require a witness 
        tx.wit.vtxinwit = []

        tx2 = CTransaction()
        tx2.vin.append(CTxIn(COutPoint(tx.sha256, 0), ""))

        '''
        self.test_node.send_message(msg_block(block))
        self.test_node.sync_with_ping()
        assert(self.nodes[0].getbestblockhash() == block.hash)
        '''

    def test_block_malleability(self):
        print "Testing witness block malleability"

        # Make sure that a block that has too big a virtual size
        # because of a too-large coinbase witness is not permanently
        # marked bad.
        block = self.build_next_block(nVersion=5)

        add_witness_commitment(block)
        block.solve()
        block.vtx[0].wit.vtxinwit[0].scriptWitness.stack.append(CScript(['a']*5000000))
        assert(get_virtual_size(block) > MAX_BLOCK_SIZE)

        self.nodes[0].submitblock(binascii.hexlify(block.serialize(True)))

        assert(self.nodes[0].getbestblockhash() != block.hash)

        block.vtx[0].wit.vtxinwit[0].scriptWitness.stack.pop()
        assert(get_virtual_size(block) < MAX_BLOCK_SIZE)
        self.nodes[0].submitblock(binascii.hexlify(block.serialize(True)))

        assert(self.nodes[0].getbestblockhash() == block.hash)


    def test_max_witness_program_length(self):
        pass

    def run_test(self):
        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode()

        self.p2p_connections = [self.test_node]

        self.connections = []
        self.connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node))
        # Add an extra one, we'll use it after disconnecting on the first one.
        self.connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], NodeConnCB()))
        self.test_node.add_connection(self.connections[0])

        NetworkThread().start() # Start up network handling in another thread

        # Keep a place to store utxo's that can be used in later tests
        self.utxo = []

        # Test logic begins here
        self.test_node.wait_for_verack()

        self.test_havewitness()

        self.test_non_witness_transaction()

        self.test_unnecessary_witness_before_block_upgrade()

        # Mine enough version 5 blocks so that witness commitments are now
        # enforced in version 5 blocks.
        self.advance_to_enforce_upgrade()

        self.test_witness_commitments()

        self.test_block_malleability()

        # TODO: fix and re-enable this test
        self.test_witness_block_size()

        self.test_submit_block()

        self.test_extra_witness_data()

        self.test_max_witness_program_length()

        # TODO: test that extra witness data in a transaction is rejected after
        # the 75% threshold.

        # TODO: test that mempool standardness rules don't allow valid witness
        # tx's until after 95% threshold.

        # TODO: test max size of a witness (is there one?)
        # 
        # TODO: test wrong number of witness inputs
        #
        # TODO: test 2?4MB (serialized) witness block is okay, but more is
        # not okay
        #
        # TODO: input value covered by hash? first reimplement transaction
        # hashing for signature.  verify that we can sign stuff!
        #
        # TODO: check that malleating the witness nonce doesn't permanently
        # mark a block as invalid.
        #
        # TODO:
        # 1. check that the block size limits are properly calculated
        #    for v4 and v5 blocks. what happens if you send a v4 block with
        #    a witness?
        # 2. check that the sigops limits are properly calculated for
        #    v5 blocks.
        # 3. go through 

        print "success!"
        


if __name__ == '__main__':
    SegWitTest().main()
