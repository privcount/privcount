from twisted.internet import reactor
from twisted.internet.protocol import ReconnectingClientFactory
from privcount.protocol import TorControlClientProtocol

# Usage:
# cd privcount/tor
# ./configure && make check && make test-network-all
# src/or/tor PublishServerDescriptor 0 ControlPort 9051 ORPort 9001 DirPort 9030 ExitRelay 0 EnablePrivCount 1 DataDirectory `mktemp -d`
# source venv/bin/activate
# python test/test_tor_ctl_event.py
# wait a few minutes for the first events to arrive

# The typical control port listed in the tor manual
TOR_CONTROL_PORT=9051

class TorCtlClient(ReconnectingClientFactory):
    '''
    Connects to a local Tor Control port to test if events of type
    'PRIVCOUNT' are properly exported by Tor.
    '''

    def buildProtocol(self, addr):
        return TorControlClientProtocol(self)
    def handle_event(self, event):
        print "got PRIVCOUNT event: " + event
        return True

reactor.connectTCP("127.0.0.1", TOR_CONTROL_PORT, TorCtlClient())
reactor.run()
