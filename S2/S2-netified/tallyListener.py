from privexUtils import q, resolution, epoch, ts_pub_delay
#from router import router
#from tkgserver import tkgserver
from twisted.internet import reactor, protocol, task, ssl
from twisted.protocols import basic
import ast
import json
import time
import argparse

parser = argparse.ArgumentParser(description='')
parser.add_argument('-p','--port', help='port to listen on',required=True)
args = parser.parse_args()

recv_data = []

class tallyListener(protocol.Protocol):
#class tallyListener(basic.LineReceiver):

    def __init__(self):
      self.buffer = ''

    def dataReceived(self, data):
      if not data: return
      global recv_data
      self.buffer += data
      if '\n' in self.buffer:
        self.data = json.loads(self.buffer)
#        self.data = ast.literal_eval(self.buffer)
        self.buffer = ''
        if self.data:
          recv_data.append(self.data)
          print "TS: Appended data!"

if __name__ == "__main__":
    #recv_data = []
    tkg_count = 0
    exit_count = 0

    def sumdata(dataset, q):
        totals = {}
        if dataset:
#            print dataset
            for k in dataset[0]:
                for data in dataset:
                    totals[k] = (totals.get(k, 0) + data.get(k, 0)) % q
		if totals[k] <= q/2:
                    totals[k] = totals[k]*resolution
                else:
                    totals[k] = (totals[k]-q)*resolution
            return totals
        else:
            return {}

    def publish_stats():
        print "TS: Publishing stats!"
        global recv_data
	if recv_data:
            stats = sumdata(recv_data, q)
            pretty_print(stats)
            recv_data[:] = []
            stats = {}
        else:
            pretty_print(None)

    def pretty_print(data):
        with open('results.txt','a') as f1:
            if data:
                for i in data:
                    res_line = str(i)+':'+str(data[i])
                    f1.write(res_line)
                    f1.write('\n')
            else:
                f1.write('No stats for this epoch\n')

    #start at the beginning of an epoch
    time.sleep(epoch - int(time.time())%epoch)
    print "TS starting up..."
    last_epoch_start = int(time.time())/epoch

    def epoch_change():
        global last_epoch_start
        now = int(time.time())/epoch
        #print last_epoch_start, now
        if now > last_epoch_start:
            print "Epoch change!\n"
            last_epoch_start = now
            reactor.callLater(ts_pub_delay, publish_stats)

    epoch_check = task.LoopingCall(epoch_change)
    epoch_check.start(1)

    factory = protocol.ServerFactory()
    factory.protocol = tallyListener

#    reactor.listenTCP(int(args.port), factory)
    reactor.listenSSL(int(args.port), factory, ssl.DefaultOpenSSLContextFactory('keys/tally.key', 'keys/tally.cert'))
    print "TS started!"
    reactor.run()
