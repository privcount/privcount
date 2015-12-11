
import sys, argparse

from twisted.internet import reactor
from twisted.internet.protocol import ClientFactory
from twisted.protocols.basic import LineReceiver

ap = argparse.ArgumentParser(description='')
ap.add_argument('-p','--port', help="port of privex DC to inject data to",required=True)
ap.add_argument('-l', '--log', help="a file PATH to a privex event log file, may be '-' for STDIN", required=True, default='-')
args = ap.parse_args()

class PrivexInjector(LineReceiver):
    delimiter = '\n'

    def connectionMade(self):
        print "Injecting data"
        fin = open(sys.stdin, 'r') if args.log == '-' else open(args.log, 'r')
        for line in fin:
            self.sendLine(line.strip())
        fin.close()
        self.transport.loseConnection()

class PrivexInjectorFactory(ClientFactory):
    protocol = PrivexInjector

    def clientConnectionFailed(self, connector, reason):
        print "Connection failed - goodbye!"
        reactor.stop()

    def clientConnectionLost(self, connector, reason):
        print "Connection lost - goodbye!"
        reactor.stop()

def main():
    cf = PrivexInjectorFactory()
    reactor.connectTCP("127.0.0.1", int(args.port), PrivexInjectorFactory())
    reactor.run()

if __name__ == "__main__":
    main()
