#!/usr/bin/env python2
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from mininode import *

'''
ExpectNode handles communication with a NodeConn object to create
a framework where tests can be written as:

node.send_message([msg1,...,msgn])
node.expect([response1, ..., responsen])

or

node.send_message([msg1, ..., msgn])
node.wait_until(responsen)

Where expect() and wait_until() block until the expected response
is received. Expect and wait_until only compare the types of the messages
received against the expected responses, and on success return the expected 
responses.

wait_until() quietly ignores messages that are not expected and waits until
messages of the specified type arrive. 
expect() is strict and will assert on any unexpected messages.
'''

# ExpectNode behaves as follows:
# version, ping and verack get handled by NodeConnCB
# everything else gets recorded to self.received[]
# On send_message(), we clear out self.received[]
# On expect(), we compare that the types of each received message
# match what we were expecting, and either raise an exception on failure
# or return the received messages on success.
# On wait_until(), we throw away messages received until either we
# receive the expected message, or the timeout is reached and an exception
# is thrown.

class ExpectNode(NodeConnCB):
    def __init__(self):
        NodeConnCB.__init__(self)
        self.received = []
        self.create_callback_map()
        # Point everything at our listener which stores all incoming traffic
        for k in self.cbmap.keys():
            if (k != "version" and k != "ping" and k != "verack"):
                self.cbmap[k] = self.on_message
        self.no_data_expected = False

    def send_message(self, messages, node=None, response_expected=True):
        if type(messages) is not list:
            messages = [messages]
        if node is None:
            node = self.connection
        self.received = []
        self.no_data_expected = not response_expected
        for x in messages:
            node.send_message(x)

    def wait_for_verack(self):
        while not self.verack_received:
            time.sleep(0.05)
    
    def on_message(self, node, message):
        if (self.no_data_expected):
            raise AssertionError("Unexpected message received: " + type(message));
        self.received.append(message)

    # Spin on the received queue until a message of type "response"
    # arrives.  Discard previous messages and return the response.
    def wait_until(self, response, timeout=2):
        maxTries = timeout / 0.05
        while (maxTries > 0):
            with self.cbLock:
                while (len(self.received) > 0):
                    m = self.received.pop(0)
                    if type(m) == type(response):
                        return m
            time.sleep(0.05)
            maxTries -= 1
        raise AssertionError("Test failure: expected response never arrived")

    # default to 2 second timeout
    def expect(self, response_list, timeout=2):
        # Wrap the passed in response in a list type, if wrong
        # argument was given.
        if type(response_list) is not list:
            response_list = [response_list]
        # Spin on the number of received messages until either
        # we receive at least as many as expected or our timer
        # runs out.
        maxTries = timeout / 0.05
        while (maxTries > 0):
            recv_len = 0
            with self.cbLock:
                recv_len = len(self.received)
            if (recv_len < len(response_list)):
                time.sleep(0.05)
                maxTries -= 1
            else:
                break

        self.no_data_expected = True  # If more data comes in, it's an error

        if (len(response_list) != len(self.received)):
            raise AssertionError("Test failure: expected %s, received %s"
                                  % (response_list, self.received))
        for i in xrange(len(response_list)):
            if type(response_list[i]) != type(self.received[i]):
                raise AssertionError("Type mismatch: expected %s, received %s"
                                     % (type(response_list[i]),
                                        type(self.received[i])))
        return self.received                     
