from privexUtils import q, epoch, tkg_start_delay
#from router import router
from tkgserver import tkgserver
from twisted.internet import reactor, protocol, task, ssl
from twisted.protocols import basic
import ast
import json
import argparse
import time
import pprint

parser = argparse.ArgumentParser(description='')
parser.add_argument('-p','--port', help='port to listen on',required=True)
parser.add_argument('-thp','--tally', help='tallyserver IP and port',required=True)

args = parser.parse_args()


class tkgListener(protocol.Protocol):

     def __init__(self):
       self.buffer = ''
       self.delimiter = '\n'

     def dataReceived(self, data):
         if not data: return
         global a
         self.buffer += data
         if '\n' in self.buffer:
             #pprint.pprint(self.buffer)
             #got_data = json.loads(self.buffer)
             got_data = ast.literal_eval(self.buffer)
             #pprint.pprint(got_data)
             a.register_router(got_data)

class tkgStatSend(basic.LineReceiver):

    def connectionMade(self):
        self.send_stats()
        self.transport.loseConnection()

    def send_stats(self):
        global should_send
        global a

        self.send_data = json.dumps(a.publish())

        print "TKG: Sending TS our stats!"
        self.sendLine(self.send_data)
        # Reset for new epoch
        a = None
        a = tkgserver(q)

if __name__ == "__main__":

    with open(args.tally,'r') as f1:
        for tallyline in f1:
            tallyhost, tallyport = tallyline.strip().split()

    a = tkgserver(q)

    time.sleep((epoch - int(time.time())%epoch) + tkg_start_delay)
    print "TKG starting up..."
    last_epoch_start = int(time.time())/epoch

    def epoch_change():
        global last_epoch_start
        global should_send
        now = int(time.time())/epoch
        if now > last_epoch_start:
            print "Epoch change!\n"
            last_epoch_start = now
            reactor.connectSSL(tallyhost, int(tallyport), sendtallyfactory, ssl.ClientContextFactory())


    def cleanup():
        reactor.stop()

    epoch_check = task.LoopingCall(epoch_change)
    epoch_check.start(1)

    sendtallyfactory = protocol.ClientFactory()
    sendtallyfactory.protocol = tkgStatSend

    listenfactory = protocol.ServerFactory()
    listenfactory.protocol = tkgListener

    reactor.listenSSL(int(args.port), listenfactory, ssl.DefaultOpenSSLContextFactory("keys/tks.key", "keys/tks.cert"))
    print "TKG ready!"
    reactor.run()
