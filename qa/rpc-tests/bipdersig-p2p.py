#!/usr/bin/env python2
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from test_framework import BitcoinTestFramework
from util import *
from mininode import CTransaction, NetworkThread
from blocktools import create_coinbase, create_block
from binascii import hexlify, unhexlify
import cStringIO
from comptool import TestInstance, TestManager
from script import CScript

# A canonical signature consists of: 
# <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
def unDERify(tx, method):
    '''
    Make the signature in vin 0 of a tx non-DER-compliant.
    We implement three methods...
    '''
    if (method == 1):  # Add padding to end of signature (after S-value)
        scriptSig = CScript(tx.vin[0].scriptSig)
        # print ("before: " + hexlify(scriptSig))
        newscript = []
        for i in scriptSig:
            if (len(newscript) == 0):
                newscript.append(i[0:-1] + '\0' + i[-1])
            else:
                newscript.append(i)
        tx.vin[0].scriptSig = CScript(newscript)
        # print('after: ' + hexlify(tx.vin[0].scriptSig))
    elif (method == 2):  # Add padding to R-value (prepend zero byte)
        scriptSig = CScript(tx.vin[0].scriptSig)
        # print('before: ' + hexlify(scriptSig))
        newscript = []
        for i in scriptSig:
            if len(newscript) == 0:
                prefix = i[0]
                total_len = chr(ord(i[1])+1)
                int_type = i[2]
                assert(int_type == '\2')
                r_len = chr(ord(i[3])+1)
                newscript.append(prefix + total_len + int_type + r_len + '\0' + i[4:])
            else:
                newscript.append(i)
        tx.vin[0].scriptSig = CScript(newscript)
        # print('after: ' + hexlify(tx.vin[0].scriptSig))
    elif (method == 3):
        # Add padding to S-value (prepend zero byte)
        # print('before: ' + hexlify(tx.vin[0].scriptSig))
        scriptSig = CScript(tx.vin[0].scriptSig)
        newscript = []
        for i in scriptSig:
            if len(newscript) == 0:
                b = bytearray(i)
                prefix = b[0]
                total_len = b[1]+1
                int_type = b[2]
                assert(int_type == 2)
                r_len = b[3]
                r = b[4:4+b[3]]
                int_type = b[4+b[3]]
                s_len = b[5+b[3]]+1
                newval = bytearray([prefix, total_len, int_type, r_len])
                newval += bytearray(r) + bytearray([2, s_len, 0])
                newval += b[6+b[3]:]
                newscript.append(bytes(newval))
            else:
                newscript.append(i)
        tx.vin[0].scriptSig = CScript(newscript)
        # print('after : ' + hexlify(tx.vin[0].scriptSig))

'''
This test is meant to exercise BIP66 (DER SIG).
Connect to a single node.
Mine 2 (version 2) blocks (save the coinbases for later).
Generate 98 more version 2 blocks, verify the node accepts.
Mine 749 version 3 blocks, verify the node accepts.
Check that the new DERSIG rules are not enforced on the 750th version 3 block.
Check that the new DERSIG rules are enforced on the 751st version 3 block.
Mine 199 new version blocks.
Mine 1 old-version block.
Mine 1 new version block.
Mine 1 old version block, see that the node rejects.
'''
            
class BIP66Test(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_option("--testbinary", dest="testbinary", default="bitcoind",
                          help="Binary to test")

    def setup_chain(self):
        print "Initializing test directory "+self.options.tmpdir
        initialize_chain_clean(self.options.tmpdir, 1)

    def setup_network(self):
        self.nodes = start_nodes(1, self.options.tmpdir, 
                                 extra_args=[['-debug', '-whitelist=127.0.0.1', '-blockversion=2']],
                                 binary=[self.options.testbinary])

    def run_test(self):
        test = TestManager(self, self.options.tmpdir)
        test.add_all_connections(self.nodes)
        self.tip = None
        self.last_block_time = None
        NetworkThread().start() # Start up network handling in another thread
        test.run()

    def create_transaction(self, node, coinbase, to_address, amount):
        from_txid = node.getblock(coinbase)['tx'][0]
        inputs = [{ "txid" : from_txid, "vout" : 0}]
        outputs = { to_address : amount }
        rawtx = node.createrawtransaction(inputs, outputs)
        signresult = node.signrawtransaction(rawtx)
        tx = CTransaction()
        f = cStringIO.StringIO(unhexlify(signresult['hex']))
        tx.deserialize(f)
        return tx

    def get_next_test_case(self, counter):
        if self.tip is None:
            self.coinbase_blocks = self.nodes[0].setgenerate(True, 2)
            self.tip = int ("0x" + self.nodes[0].getbestblockhash() + "L", 0)
            self.nodeaddress = self.nodes[0].getnewaddress()
        if self.last_block_time is None:
            import time
            self.last_block_time = time.time()

        if counter == 1:
            ''' 98 more version 2 blocks '''
            test_blocks = []
            for i in xrange(98):
                block = create_block(self.tip, create_coinbase(2), self.last_block_time + 1)
                block.nVersion = 2
                block.rehash()
                block.solve()
                test_blocks.append([block, True])
                self.last_block_time += 1
                self.tip = block.sha256
            return TestInstance(test_blocks, sync_every_block=False)
        elif counter == 2:
            ''' Mine 749 version 3 blocks '''
            test_blocks = []
            for i in xrange(749):
                block = create_block(self.tip, create_coinbase(2), self.last_block_time + 1)
                block.nVersion = 3
                block.rehash()
                block.solve()
                test_blocks.append([block, True])
                self.last_block_time += 1
                self.tip = block.sha256
            return TestInstance(test_blocks, sync_every_block=False)
        elif counter == 3:
            ''' 
            Check that the new DERSIG rules are not enforced in the 750th
            version 3 block.
            '''
            spendtx = self.create_transaction(self.nodes[0],
                    self.coinbase_blocks[0], self.nodeaddress,
                    1.0)
            unDERify(spendtx, 3)
            spendtx.rehash()
            block = create_block(self.tip, create_coinbase(2), self.last_block_time + 1)
            block.nVersion = 3
            block.vtx.append(spendtx)
            block.hashMerkleRoot = block.calc_merkle_root()
            block.rehash()
            block.solve()
            self.block_dersig_invalid = block
            self.last_block_time += 1
            self.tip = block.sha256
            return TestInstance([[block, True]])
        elif counter == 4:
            ''' 
            Check that the new DERSIG rules are enforced in the 751st version 3
            block.
            '''
            spendtx = self.create_transaction(self.nodes[0], self.coinbase_blocks[1], self.nodeaddress, 1.0)
            unDERify(spendtx, 3)
            spendtx.rehash()
            block = create_block(self.tip, create_coinbase(1), self.last_block_time + 1)
            block.nVersion = 3
            block.vtx.append(spendtx)
            block.hashMerkleRoot = block.calc_merkle_root()
            block.rehash()
            block.solve()
            self.last_block_time += 1
            return TestInstance([[block, False]])
        elif counter == 5:
            ''' Mine 199 new version blocks on last valid tip '''
            test_blocks = []
            for i in xrange(199):
                block = create_block(self.tip, create_coinbase(1), self.last_block_time + 1)
                block.nVersion = 3
                block.rehash()
                block.solve()
                test_blocks.append([block, True])
                self.last_block_time += 1
                self.tip = block.sha256
            return TestInstance(test_blocks, sync_every_block=False)
        elif counter == 6:
            ''' Mine 1 old version block '''
            block = create_block(self.tip, create_coinbase(1), self.last_block_time + 1)
            block.nVersion = 2
            block.rehash()
            block.solve()
            self.last_block_time += 1
            self.tip = block.sha256
            return TestInstance([[block, True]])
        elif counter == 7:
            ''' Mine 1 new version block '''
            block = create_block(self.tip, create_coinbase(1), self.last_block_time + 1)
            block.nVersion = 3
            block.rehash()
            block.solve()
            self.last_block_time += 1
            self.tip = block.sha256
            return TestInstance([[block, True]])
        elif counter == 8:
            ''' Mine 1 old version block, should be invalid '''
            block = create_block(self.tip, create_coinbase(1), self.last_block_time + 1)
            block.nVersion = 2
            block.rehash()
            block.solve()
            self.last_block_time += 1
            return TestInstance([[block, False]])
        return None

if __name__ == '__main__':
    BIP66Test().main()
