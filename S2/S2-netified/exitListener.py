from collections import defaultdict
from privexUtils import q, epoch, dc_start_delay, dc_reg_delay
from router import router
from tkgserver import tkgserver
from twisted.internet import reactor, protocol, task, ssl
from twisted.protocols import basic
import time
import json
import argparse
import pprint

parser = argparse.ArgumentParser(description='')
parser.add_argument('-i','--input', help='Input website list, one on each line',required=True)
parser.add_argument('-tkg','--tkgList', help='Input tkg list, IP and port, one on each line',required=True)
parser.add_argument('-thp','--tally', help='Input tally server IP and port.',required=True)
parser.add_argument('-p','--port', help='port to listen on',required=True)
parser.add_argument('-f','--fingerprint', help='fingerprint file of exit',required=True)
parser.add_argument('-c','--consensus', help='consensus file of exit',required=True)

args = parser.parse_args()

class exitListener(basic.LineReceiver):
    delimiter = '\n' # change the default ('\r\n')

    def lineReceived(self, line):
        action, data_remaining = [v.strip('\n') for v in line.split(" ", 1)]

        if action == "a":
            channelID, circuitID, website = [v.strip() for v in data_remaining.split(" ", 2)]
            channelID, circuitID = int(channelID), int(circuitID)

            if channelID not in site_seen:
                site_seen[channelID] = {}
            if circuitID not in site_seen[channelID]:
                site_seen[channelID][circuitID] = {}
            if website not in site_seen[channelID][circuitID]:
                site_seen[channelID][circuitID][website] = 1
                if website != "Other" and website != "Censored":
                  if website in labels:
                      r.inc(website)
                      r.inc("Censored")
#                      print website + " incremented exitListener!\n"
                  else:
                      r.inc("Other")
#                      print "Other incremented exitListener!\n"
        elif action == 's':
            # 's', ChanID, CircID, StreamID, ExitPort, ReadBW, WriteBW, TimeStart, TimeEnd
            items = [v.strip('\n') for v in data_remaining.split(" ", 7)]
            channelID, circuitID, streamID, exitPort, readBW, writeBW  = [int(v) for v in items[0:-2]]
            timeStart, timeEnd = float(items[-2]), float(items[-1])
            # TODO do something
            print "found stream: {0} {1} {2} {3} {4} {5} {6} {7}".format(channelID, circuitID, streamID, exitPort, readBW, writeBW, timeStart, timeEnd)
        elif action == 'c':
            # 'c', ChanID, CircID, ReadBW, WriteBW, TimeStart, TimeEnd, ClientIP
            items = [v.strip('\n') for v in data_remaining.split(" ", 6)]
            channelID, circuitID, readBW, writeBW = [int(v) for v in items[0:-3]]
            timeStart, timeEnd = float(items[-3]),  float(items[-2])
            clientIP = items[-1]
            # TODO do something
            print "found circuit: {0} {1} {2} {3} {4} {5} {6}".format(channelID, circuitID, readBW, writeBW, timeStart, timeEnd, clientIP)

class exitRegister(basic.LineReceiver):
    def __init__(self):
        self.delimiter = '\n'

    def connectionMade(self):
        self.register_exit()
        self.transport.loseConnection()

    def register_exit(self):
        global msg
        print "DC: Registered with a TKG!"
        #self.sendLine(msg[0])
        #self.send_msg = json.dumps(msg[0])
        #pprint.pprint(self.send_msg)
        #self.sendLine(self.send_msg)
        self.sendLine(repr(msg[0]))
        msg.pop(0)

class exitStatSend(basic.LineReceiver):

    def connectionMade(self):
      self.send_stats()
      self.transport.loseConnection()

    def send_stats(self):

        global r

        global msg
        global site_seen

        self.send_data = json.dumps(r.publish())

        print "DC: Sending TS our stats!"
        self.sendLine(self.send_data)

        #clean up objects and refresh
        site_seen.clear()
        r = None
        msg = []
        r = router(q, labels, tkgs, args.fingerprint, args.consensus)
        for kid, a in zip(r.keys, tkgs):
            msg.append(r.authority_msg(kid))

        time.sleep(dc_reg_delay)
        for host, port in tkg_info:

            reactor.connectSSL(host, int(port), c_factory, ssl.ClientContextFactory())

if __name__ == "__main__":


    labels = []
    tkgs = []
    site_seen = {}
    r = None

    tkg_info = []
    msg = []

    with open(args.input,'r') as f1:
        for line in f1:
          site = line.strip()
          if site not in labels:  
            labels.append(site)
        labels.append("Other")
        labels.append("Censored")

    with open(args.tally,'r') as f3:
        for tallyline in f3:
            tallyhost, tallyport = tallyline.strip().split()

    with open(args.tkgList,'r') as f2:
        for tkgline in f2:
            tkgs.append(tkgserver(tkgline.strip()))
            host, port = tkgline.strip().split()
            tkg_info.append((host, port))

    r = router(q, labels, tkgs, args.fingerprint, args.consensus)

    for kid, a in zip(r.keys, tkgs):
        msg.append(r.authority_msg(kid))

    time.sleep((epoch - int(time.time())%epoch) + dc_start_delay)
    print "DC starting up..."
    last_epoch_start = int(time.time())/epoch

    def epoch_change():
        global last_epoch_start
        global should_send
        now = int(time.time())/epoch
        if now > last_epoch_start:
            last_epoch_start = now
            print "Epoch Change!\n"
            reactor.connectSSL(tallyhost, int(tallyport), sendtallyfactory, ssl.ClientContextFactory())


    epoch_check = task.LoopingCall(epoch_change)
    epoch_check.start(1)
    sendtallyfactory = protocol.ClientFactory()
    sendtallyfactory.protocol = exitStatSend


    c_factory = protocol.ClientFactory()
    c_factory.protocol = exitRegister
    time.sleep(dc_reg_delay)
    for host, port in tkg_info:
        reactor.connectSSL(host, int(port), c_factory, ssl.ClientContextFactory())

    s_factory = protocol.ServerFactory()
    s_factory.protocol = exitListener
    reactor.listenTCP(int(args.port), s_factory, interface='127.0.0.1') # Local Tor connection
    print "DC ready!"
    reactor.run()
