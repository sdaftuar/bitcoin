#!/usr/bin/env python2
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from mininode import *
import tempfile
from threading import Lock
from threading import Thread
import os
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "python-bitcoinrpc"))
from util import *
from util import _rpchost_to_args


class EarlyDisconnectError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

# This test plays a set of blocks to each node and verifies that
# a) The nodes request each block the same number of times
# b) The nodes have the same chain tip after each block
# c) The nodes have the same mempool after each block


class TestManager(Thread, NodeConnCB):
    # set up NodeConnCB callbacks, overriding base class
    def on_getheaders(self, node, message):
        try:
            if self.currentBlockHash == 0L:  # Haven't started yet
                return
            response = msg_headers()
            # TODO: eliminate the need for 2 arrays by making hashes part of the block header
            headersList = [ CBlockHeader(self.blockMap[self.currentBlockHash]) ]
            # TODO: fix this to not go past genesis block or 2000 hashes
            maxheaders = 2000
            while (headersList[-1] not in message.locator.vHave and
                    len(headersList) < maxheaders):
                prevBlockHash = self.blockMap[headersList[-1].sha256].hashPrevBlock
                if prevBlockHash in self.blockMap:
                    headersList.append(CBlockHeader(self.blockMap[prevBlockHash]))
                else:
                    break
            response.headers = headersList
            # Now prune anything that is after hash_stop
            if (message.hashstop in headersHashes):
                index = headersHashes.index(message.hashstop) 
                response.headers = headersList[index:]
                response.headers.reverse()
            node.send_message(response)
        except:
            print "Unexpected error: ", sys.exc_info()[0]

    def on_headers(self, node, message):
        try:
            print "got headers from node %d" % self.get_node_index(node)
            if len(message.headers) == 0:
                return
            tip = message.headers[-1]
            fakeBlock = CBlock(tip)
            self.bestblockhashes[self.get_node_index(node)] = fakeBlock.sha256
        except TypeError as e:
            print "Unexpected error: ", sys.exc_info()[0], e.args

    def on_reject(self, node, message):
        print "msg_reject (node: %d [%s])" % (self.get_node_index(node), repr(message))

    def on_getdata(self, node, message):
        try:
            index = self.get_node_index(node)
            print "responding to getdata from node %d" % index
            # Hopefully a block we have!
            for inv in message.inv:
                self.blockReqCounts[index][inv.hash] += 1
                if inv.hash in self.blockMap:
                    response = msg_block()
                    response.block = self.blockMap[inv.hash]
                    print "delivering block %064x to node %d" % (inv.hash, index)
                    node.send_message(response)
            h = msg_getheaders()
            h.locator.vHave = self.get_locator(self.blockMap[self.currentBlockHash].hashPrevBlock)
            node.send_message(h)
        except NameError as e:
            print "Unexpected error: ", sys.exc_info()[0], e.args
        except KeyError as e:
            print "Unexpected error: ", sys.exc_info()[0], e.args
        except AttributeError as e:
            print "Unexpected error: ", sys.exc_info()[0], e.args

    def on_close(self, node):
        if not self.disconnectOkay[get_node_index(node)]:
            raise EarlyDisconnectError(get_node_index(node))

    def get_locator(self, last):
        r = []
        counter = 0
        step = 1
        while last in self.blockMap:
            r.append(self.blockMap[last].hashPrevBlock)
            for i in range(step):
                if last in self.blockMap:
                    last = self.blockMap[last].hashPrevBlock
                else:
                    break
            counter += 1
            if counter > 10:
                step *= 2
        return r

    def synchronize_nodes(self):
        # Return as soon as either both nodes have requested the current block
        # or 10 seconds have gone by
        for i in range(100):
            # TODO: does this need to be protected with a lock acquire?
            if self.currentBlockHash in self.blockReqCounts[0]:
                if self.currentBlockHash in self.blockReqCounts[1]:
                    if self.blockReqCounts[0][self.currentBlockHash] * self.blockReqCounts[1][self.currentBlockHash] > 0:
                        if self.bestblockhashes[0] != 0 and self.bestblockhashes[1] != 0:
                            break
            time.sleep(0.1)
        return

    # TODO: make these all not depend on number of connections??
    def check_all_same(self):
        # Check for same tip via rpc
        try:
            blockhashes = [ x.rpc.getbestblockhash() for x in self.connections ]
            for y in blockhashes:
                if y != blockhashes[0]:
                    print "blockhashes differ"
                    return False
            
            # Check for same mempool via rpc
            rawmempools = [ x.rpc.getrawmempool() for x in self.connections ]
            for y in rawmempools:
                if y != rawmempools[0]:
                    print "mempools differ"
                    return False
        except:
            raise EarlyDisconnectError(-1)
        
        # Check that block request counts were the same
        if cmp(self.blockReqCounts[0], self.blockReqCounts[1]) != 0:
            print "request counts differ"
            return False
        return True

    def get_node_index(self, node):
        return self.connections.index(node)

    def __init__(self, blockfile, connections):
        Thread.__init__(self)
        self.blocks = blockfile
        self.connections = connections
        self.create_callback_map()
        self.blockReqCounts = [ {}, {} ]
        self.currentBlockHash = 0L
        self.blockMap = {}
        self.cbLock = Lock() # Acquire on all callbacks
        self.bestblockhashes = [0, 0]
        self.disconnectOkay = [ False, False ]
        self.endTest = False

    # Set up an inv to go out and make this the current block
    def add_inv(self, node, block):
        inv = CInv()
        inv.type = 2
        inv.hash = block.sha256
        m = msg_inv()
        m.inv.append(inv)
        node.send_message(m)

    def cleanup(self):
        print "Stopping nodes"
        for c in self.connections:
            try:
                print "c.dstport=%d" % c.dstport
                c.rpc.stop()
                bitcoind_processes[self.connections.index(c)].wait()
            except:
                # Might fail if we had an early disconnect
                print "RPC stop failed for node %d (is bitcoind already down?)" % self.get_node_index(c)

    def end(self):
        self.endTest = True

    def run(self):
        try:
            inFile = open(self.blocks, "rb");
        except IOError:
            print("Cannot open block file");
            self.cleanup()
            return;

        time.sleep(2)
        while self.endTest == False:
            try:
                block = CBlock()
                block.deserialize(inFile);
                block.calc_sha256()

                self.currentBlockHash = block.sha256
                self.blockMap[block.sha256] = block
                self.blockReqCounts[0][block.sha256] = 0
                self.blockReqCounts[1][block.sha256] = 0

                print "On block %s" % block.hash

                # send block out to all nodes
                self.bestblockhashes = [0, 0]
                for node in self.connections:
                    self.add_inv(node, block)

                # synchronize nodes
                # java code waits for the block to be requested, etc...
                self.synchronize_nodes()

                # check that they have same tip, mempool, etc
                if self.check_all_same() == False:
                    print "Error, test failed on %s" % block.hash
                    break
                # Can we do better memory management?? TODO
                if self.blockReqCounts[0][block.sha256] > 0:
                    self.blockMap[block.sha256].vtx = []

                for m in self.blockReqCounts:
                    for key in m:
                        m[key] = 0
            except IOError:
                print "test exiting, out of data"
                break
            except EarlyDisconnectError: 
                print "Error: detected early disconnect, exiting test"
                break
        self.cleanup()
        
def start_node(i, dirname, program, extra_args=None, rpchost=None):
    """
    Start a bitcoind and return RPC connection to it
    """
    datadir = os.path.join(dirname, "node"+str(i))
    print program
    args = [ program, "-datadir="+datadir, "-keypool=1", "-discover=0", "-rest" ]
    if extra_args is not None: args.extend(extra_args)
    bitcoind_processes[i] = subprocess.Popen(args)
    devnull = open("/dev/null", "w+")
    subprocess.check_call([ os.getenv("BITCOINCLI", "bitcoin-cli"), "-datadir="+datadir] +
                          _rpchost_to_args(rpchost)  +
                          ["-rpcwait", "getblockcount"], stdout=devnull)
    devnull.close()
    url = "http://rt:rt@%s:%d" % (rpchost or '127.0.0.1', rpc_port(i))
    proxy = AuthServiceProxy(url)
    proxy.url = url # store URL on proxy for info
    return proxy
 
if __name__ == '__main__':
    if len(sys.argv) == 2:
        f = open(sys.argv[1])
        for line in f:
            m = re.search('^(\w+)\s*=\s*(\S.*)$', line)
            if m is None:
                continue
            settings[m.group(1)] = m.group(2)
        f.close()
    else:
        print "Usage: comptool.py <settingsfile>"
        sys.exit()

    import logging
#logging.basicConfig(level=logging.DEBUG)

    # TODO: fix this
    srcdir = "/home/sdaftuar/projects/ccl-bitcoin/src/"
    os.environ['PATH'] = srcdir+":"+os.environ['PATH']
    tmpdir = tempfile.mkdtemp(prefix="test")
    if not os.path.isdir(tmpdir):
        os.makedirs(tmpdir)
   
    initialize_chain_clean(tmpdir, 2)

    # This test will start up 2 bitcoind's running in regtest mode.
    # settings should have a testbinary and a refbinary with bitcoind's to evaluate

    # Slightly hacky... TODO Fix this up
    start_node(0, tmpdir, settings['testbinary'], ["-debug", "-debug=net", "-whitelist=127.0.0.1"])
    start_node(1, tmpdir, settings['refbinary'], ["-debug", "-debug=net", "-whitelist=127.0.0.1"])

    # TODO: clean this up, stupid circularity in constructors
    connections = []
    test = TestManager(settings['blockfile'], connections)
    connections.append(NodeConn('127.0.0.1', p2p_port(0), rpc_port(0), test))
    connections.append(NodeConn('127.0.0.1', p2p_port(1), rpc_port(1), test))
    test.connections = connections
    
    test.start()
    try:
        asyncore.loop(0.1, True)
    except EarlyDisconnectError as e:
        test.end()
        print "Error: early disconnect from node ", e.value
        print "Test failed"
        
    print "comptool exiting"
    # TODO: clean up --
    # Need to exit the asyncore loop gracefully and shut down the bitcoind's and
    # clean up the datadirs
