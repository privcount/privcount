from privexUtils import q, epoch
#from router import router
from tkgserver import tkgserver
from twisted.internet import reactor, protocol, task, ssl
from twisted.protocols import basic
import ast
import argparse
import time

parser = argparse.ArgumentParser(description='')
#parser.add_argument('-i','--input', help='File containing websites to collect stats for, one on each line',required=True)
parser.add_argument('-p','--port', help='port to listen on',required=True)
parser.add_argument('-thp','--tally', help='tallyserver IP and port',required=True)

args = parser.parse_args()


class tkgListener(protocol.Protocol):
#class tkgListener(basic.LineReceiver):

     def __init__(self):
       self.buffer = ''
          
     def dataReceived(self, data):
	if not data: return
	global a
	self.buffer += data       
        if '\n' in self.buffer:
	  got_data = ast.literal_eval(self.buffer)
	  a.register_router(got_data)


#class tkgStatSend(protocol.Protocol):
class tkgStatSend(basic.LineReceiver):

    def __init__(self):
        self.lc = task.LoopingCall(self.send_stats)
        self.lc.start(0.5)
    
    def send_stats(self):
        global should_send
        global a
        if should_send:
            self.send_data = repr(a.publish())
#	    print self.send_data
	    #self.transport.write(self.send_data)    
#            print "Sending TS this much data:", len(self.send_data)
	    self.sendLine(self.send_data)
            should_send = False
            a = None
            a = tkgserver(q)


if __name__ == "__main__":
    should_send = False
#    labels = []
#    with open(args.input,'r') as f1:
#        for line in f1:
#            labels.append(line.strip())
#        labels.append("Other")
    
    with open(args.tally,'r') as f1:
        for tallyline in f1:
            tallyhost, tallyport = tallyline.strip().split()
    
    a = tkgserver(q)

    time.sleep(int(time.time())%epoch + 3)
    print "TKG starting up..."
    last_epoch_start = int(time.time())/epoch

    def epoch_change():
        global last_epoch_start
        global should_send
        now = int(time.time())/epoch
        if now > last_epoch_start: 
            last_epoch_start = now
            should_send = True
    
    def cleanup():
        reactor.stop()
            
    epoch_check = task.LoopingCall(epoch_change)
    epoch_check.start(0.5)

    sendtallyfactory = protocol.ClientFactory()
    sendtallyfactory.protocol = tkgStatSend
    #reactor.connectTCP("localhost", int(args.tallyport), sendtallyfactory)
    reactor.connectSSL(tallyhost, int(tallyport), sendtallyfactory, ssl.ClientContextFactory())

    listenfactory = protocol.ServerFactory()
    listenfactory.protocol = tkgListener
    #reactor.listenTCP(int(args.port), listenfactory)
    reactor.listenSSL(int(args.port), listenfactory, ssl.DefaultOpenSSLContextFactory("keys/tks.key", "keys/tks.cert"))
    print "TKG ready!"
    reactor.run()
                

