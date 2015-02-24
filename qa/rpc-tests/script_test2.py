#!/usr/bin/env python2
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

'''
Test notes:
We have a few options for how this test could work.
The overall goal is to use the script_valid and script_invalid tests from the unittest framework
to do end-to-end testing of a node or multiple nodes.
 The main limitation[*] in end-to-end testing is that we can't separately test each script verification
flag; we're limited to either testing consensus flags (by creating a transaction that we mine in a block,
and test whether the block is accepted) or the full set of policy flags the node is enforcing for its
mempool (which can be either stricter than the flags indicated on the test, or not strict enough).
 
Some ideas for approaches:
1) Ignore the script flags for each test, and just test everything assuming we're testing consensus.
   The only problem with this is that some of the invalid scripts may actually be valid under consensus
   flags, so we can't necessarily know what answer to expect.  However, we could do a 2-node comparison
   where we're just testing that the nodes either both accept or both reject every block.

2) Look at the script flags for each test. For tests we expect to be valid, just do a consensus test.  For
   tests we expect to be invalid, check to see if the flags are exercising any of the policy flags we 
   think the node is enforcing, and if so do the test as a mempool acceptance test.  This is how the test
   is currently written.  [Throw out any tests that are exercising flags that are not consensus or policy.]

[*] One tricky issue we can workaround is SCRIPT_VERIFY_P2SH, which is a consensus flag for blocks mined
after a certain time.  For tests without that flag, we just set the block time to be before the switchover
date; for tests with the flag we bump the block time to be after that switchover date.

'''

from test_framework import BitcoinTestFramework
from util import *
from comptool import *
from mininode import *
from blocktools import *
from blockstore import BlockStore, TxStore
from script import *
import logging
import copy
import json

script_valid_file   = "../../src/test/data/script_valid.json"
script_invalid_file = "../../src/test/data/script_invalid.json"

# Pass in a set of json files to open. 
class ScriptTestFile(object):
    def __init__(self, files):
        self.files = files
        self.index = -1
        self.data = []
    def load_files(self):
        for f in self.files:
            self.data.extend(json.loads(open(f).read()))
    # Skip over records that are not long enough to be tests
    def get_next_record(self):
        self.index += 1
        while (True):
            if self.index >= len(self.data):
                return None
            elif len(self.data[self.index]) < 3:
                self.index += 1
            else:
                return self.data[self.index]

SCRIPT_VERIFY_NONE = 0
SCRIPT_VERIFY_P2SH = 1 
SCRIPT_VERIFY_STRICTENC = 1 << 1
SCRIPT_VERIFY_DERSIG = 1 << 2
SCRIPT_VERIFY_LOW_S = 1 << 3
SCRIPT_VERIFY_NULLDUMMY = 1 << 4
SCRIPT_VERIFY_SIGPUSHONLY = 1 << 5
SCRIPT_VERIFY_MINIMALDATA = 1 << 6
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = 1 << 7
SCRIPT_VERIFY_CLEANSTACK = 1 << 8

flag_map = { 
    "": SCRIPT_VERIFY_NONE,
    "NONE": SCRIPT_VERIFY_NONE, 
    "P2SH": SCRIPT_VERIFY_P2SH,
    "STRICTENC": SCRIPT_VERIFY_STRICTENC,
    "DERSIG": SCRIPT_VERIFY_DERSIG,
    "LOW_S": SCRIPT_VERIFY_LOW_S,
    "NULLDUMMY": SCRIPT_VERIFY_NULLDUMMY,
    "SIGPUSHONLY": SCRIPT_VERIFY_SIGPUSHONLY,
    "MINIMALDATA": SCRIPT_VERIFY_MINIMALDATA,
    "DISCOURAGE_UPGRADABLE_NOPS": SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    "CLEANSTACK": SCRIPT_VERIFY_CLEANSTACK,
}

def ParseScriptFlags(flag_string):
    flags = 0
    for x in flag_string.split(","):
        if x in flag_map:
            flags |= flag_map[x]
        else:
            print "Error: unrecognized script flag: ", x
    return flags

''' 
Given a string that is a scriptsig or scriptpubkey from the .json files above,
convert it to a CScript()
'''
# Replicates behavior from core_read.cpp
def ParseScript(json_script):
    script = json_script.split(" ")
    parsed_script = CScript()
    for x in script:
        if len(x) == 0:
            pass
        elif x.isdigit() or (len(x) >= 1 and x[0] == "-" and x[1:].isdigit()):
            n = int(x, 0)
            if (n == -1) or (n >= 1 and n <= 16):
                parsed_script = CScript(bytes(parsed_script) + bytes(CScript([n])))
            else:
                parsed_script += CScriptNum(int(x, 0))
        elif x.startswith("0x"):
            # Is there a better way to do this?
            for i in xrange(2, len(x), 2):
                parsed_script = CScript(bytes(parsed_script) + bytes(chr(int(x[i:i+2],16))))
        elif x.startswith("'") and x.endswith("'") and len(x) >= 2:
            parsed_script += CScript([x[1:-1]]) # Does this work?
        else:
            tryopname = "OP_" + x
            if tryopname in OPCODES_BY_NAME:
                parsed_script += CScriptOp(OPCODES_BY_NAME["OP_" + x])
            else:
                print "ParseScript: error parsing '%s'" % x
                return ""
    return parsed_script
            
COIN = 100000000

class TestBuilder(object):
    def create_credit_tx(self, scriptPubKey):
        # self.tx1 is a coinbase transaction, modeled after the one created by script_tests.cpp
        # This allows us to reuse signatures created in the unit test framework.
        self.tx1 = create_coinbase() # this has a bip34 vin[0] scriptsig
        self.tx1.vin[0].scriptSig = CScript([0, 0]) # this matches the unit tests
        self.tx1.vout[0].nValue = 0 # matches the unit tests
        self.tx1.vout[0].scriptPubKey = scriptPubKey
        self.tx1.rehash()
    def create_spend_tx(self, scriptSig):
        self.tx2 = create_transaction(self.tx1, CScript(), 0)
        self.tx2.vin[0].scriptSig = scriptSig
        self.tx2.vout[0].scriptPubKey = CScript()
        self.tx2.rehash()
    def rehash(self):
        self.tx1.rehash()
        self.tx2.rehash()

class ScriptTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_option("--testbinary", dest="testbinary", default="bitcoind",
                          help="Binary to test")
        parser.add_option("--refbinary", dest="refbinary", default="bitcoind",
                          help="Binary to use as baseline")

    def setup_chain(self):
        print "Initializing test directory "+self.options.tmpdir
        initialize_chain_clean(self.options.tmpdir, 2)

    def setup_network(self):
        self.nodes = start_nodes(2, self.options.tmpdir, 
                                         extra_args=[['-debug', '-whitelist=127.0.0.1'],
                                                     ['-debug', '-whitelist=127.0.0.1']],
                                         binary=[self.options.refbinary, self.options.testbinary])
        connect_nodes(self.nodes[0], 1)

    def run_test(self):
        test = TestManager(self, self.options.tmpdir)
        test.add_all_connections(self.nodes)
        self.scripts = ScriptTestFile([script_valid_file, script_invalid_file])
        self.scripts.load_files()
        self.tip = None
        self.block_time = None
        NetworkThread().start() # Start up network handling in another thread
        test.run()

    def generate_test_instance(self, pubkeystring, scriptsigstring):
        scriptpubkey = ParseScript(pubkeystring)
        scriptsig = ParseScript(scriptsigstring)

        test = TestInstance(sync_every_block=False)
        test_build = TestBuilder()
        test_build.create_credit_tx(scriptpubkey)
        test_build.create_spend_tx(scriptsig)
        test_build.rehash()

        block = create_block(self.tip, test_build.tx1, self.block_time)
        self.block_time += 1
        block.solve()
        self.tip = block.sha256
        test.blocks_and_transactions = [[block, True]]

        for i in xrange(100):
            block = create_block(self.tip, create_coinbase(), self.block_time)
            self.block_time += 1
            block.solve()
            self.tip = block.sha256
            test.blocks_and_transactions.append([block, True])

        block = create_block(self.tip, create_coinbase(), self.block_time)
        self.block_time += 1
        block.vtx.append(test_build.tx2)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.rehash()
        block.solve()
        test.blocks_and_transactions.append([block, None])
        return test   

    def get_next_test_case(self, counter):
        if self.tip is None:
            self.tip = int ("0x" + self.nodes[0].getbestblockhash() + "L", 0)
        if self.block_time is None:
            self.block_time = 1333230000 # before the BIP16 switchover

        if counter == 1:
            '''
            Create a new block with an anyone-can-spend coinbase
            '''
            block = create_block(self.tip, create_coinbase(), self.block_time)
            self.block_time += 1
            block.solve()
            self.tip = block.sha256
            return TestInstance(objects=[[block, True]])
        elif counter == 2:
            ''' 
            Build out to 11 blocks total, to get around the 
            '''
            test = TestInstance(objects=[], sync_every_block=False, sync_every_tx=False)
            for i in xrange(100):
                b = create_block(self.tip, create_coinbase(), self.block_time)
                b.solve()
                test.blocks_and_transactions.append([b, True])
                self.tip = b.sha256
                self.block_time += 1
            return test
 
        else:
            ''' Reset the blockchain to genesis block + 10 blocks. '''
            if self.nodes[0].getblockcount() > 101:
                self.nodes[0].invalidateblock(self.nodes[0].getblockhash(102))
                self.nodes[1].invalidateblock(self.nodes[1].getblockhash(102))

            self.tip = int ("0x" + self.nodes[0].getbestblockhash() + "L", 0)
            # intentionally let the block time grow... by 1 each time.
            self.block_time = 1333230000 + counter # before the BIP16 switchover 

            ''' Iterate through script tests. '''
            script_test = self.scripts.get_next_record()
            if (script_test is not None):
                [scriptsig, scriptpubkey, flags] = script_test[0:3]
                flags = ParseScriptFlags(flags)

                if (flags & SCRIPT_VERIFY_P2SH):
                    self.block_time = 1333238400 + counter # Advance to enforcing BIP16
                else:
                    self.block_time = 1333230000 + counter

                print "Script test: [%s]" % script_test

                return self.generate_test_instance(scriptpubkey, scriptsig)
            else:
                return None

if __name__ == '__main__':
    ScriptTest().main()
