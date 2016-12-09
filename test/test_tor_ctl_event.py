#!/usr/bin/env python
# Test that a local control port (IP or unix socket) provides PrivCount events

import logging
import sys

from collections import Sequence
from os import path

from twisted.internet import reactor
from twisted.internet.protocol import ReconnectingClientFactory

from privcount.connection import connect, transport_info
from privcount.protocol import TorControlClientProtocol, get_valid_events

## Usage:
#
## Setup
# cd privcount/tor
# ./configure && make check && make test-network-all
#
## Control Socket (relies on filesystem security, more secure)
# mkdir -p /var/run/tor
# chmod go-rwx /var/run/tor
# src/or/tor PublishServerDescriptor 0 ORPort 9001 DirPort 9030 ExitRelay 0 DataDirectory `mktemp -d` ControlSocket /var/run/tor/control
#
## OR
#
## Control Port (any local process can access the control port, less secure)
# src/or/tor PublishServerDescriptor 0 ORPort 9001 DirPort 9030 ExitRelay 0 DataDirectory `mktemp -d` ControlPort 9051
#
## Testing
# source venv/bin/activate
# python test/test_tor_ctl_event.py
## wait a few minutes for the first events to arrive

# The default control socket path used by Debian
TOR_CONTROL_PATH = '/var/run/tor/control'

# The typical control port listed in the tor manual
TOR_CONTROL_PORT = 9051
# Try localhost on this IP version
TOR_CONTROL_IP_VERSION = 4

class TorCtlClient(ReconnectingClientFactory):
    '''
    Connects to a local Tor Control port to test if events of type
    'PRIVCOUNT_*' are properly exported by Tor.
    '''

    def __init__(self):
        '''
        Make sure the stored nickname is initialised
        '''
        self.nickname = None
        self.client = None

    def buildProtocol(self, addr):
        '''
        Called by twisted
        '''
        self.client = TorControlClientProtocol(self)
        # ask for all the events
        self.client.startCollection(None, event_list=get_valid_events())
        return self.client

    def set_nickname(self, nickname):
        '''
        Called when the relay provides its nickname
        '''
        self.nickname = nickname
        return True

    def set_fingerprint(self, fingerprint):
        '''
        Called when the relay provides its fingerprint
        '''
        print "Relay fingerprint: {}".format(fingerprint)
        if self.nickname is not None:
            print "Relay nickname: {}".format(self.nickname)
        return True

    def handle_event(self, event):
        '''
        Called when an event occurs.
        event is a space-separated list of tokens from the event line
        '''
        if self.nickname is None:
            nickname = ""
        else:
            nickname = self.nickname + " "
        address = transport_info(self.client.transport)
        print "{}{} got PRIVCOUNT_* event: {}".format(nickname,
                                                      address,
                                                      " ".join(event))
        return True

# Set defaults
control_path = TOR_CONTROL_PATH
control_port = TOR_CONTROL_PORT

# Process command-line arguments
if len(sys.argv) > 1:
    # UNIX socket path
    if path.exists(sys.argv[1]):
        control_path = sys.argv[1]
    else:
        control_path = None

    # IP port
    try:
        control_port = int(sys.argv[1])
    except ValueError:
        control_port = None

# Just try every possible method, and let the ones that don't work fail
# (if they all succeed, it will be terribly confusing)
# Don't use multiple configs in production, it's only useful for testing
config_list = []

if control_path is not None:
    path_config = { 'unix' : control_path }
    config_list.append(path_config)

if control_port is not None:
    port_config = { 'port' : control_port }
    config_list.append(port_config)


# Trying localhost is sufficient: a service bound to all ports will answer
# on localhost (and expose control of your tor to the entire world).
connector = connect(TorCtlClient(),
                    config_list,
                    ip_version_default = TOR_CONTROL_IP_VERSION)

if isinstance(connector, (Sequence)):
    logging.warning("If you have ControlPorts listening on both path {} and IPv{} localhost port {}, some events may be attributed to the wrong address, or duplicated."
                    .format(TOR_CONTROL_IP_VERSION,
                            control_path,
                            control_port))
reactor.run()
