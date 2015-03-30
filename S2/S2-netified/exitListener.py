from collections import defaultdict
from privexUtils import q, epoch, dc_start_delay, dc_reg_delay
from router import router
from tkgserver import tkgserver
from twisted.internet import reactor, protocol, task, ssl
from twisted.protocols import basic
import time
import json
import argparse

parser = argparse.ArgumentParser(description='')
parser.add_argument('-i','--input', help='Input website list, one on each line',required=True)
parser.add_argument('-tkg','--tkgList', help='Input tkg list, IP and port, one on each line',required=True)
parser.add_argument('-thp','--tally', help='Input tally server IP and port.',required=True)
parser.add_argument('-p','--port', help='port to listen on',required=True)
parser.add_argument('-f','--fingerprint', help='fingerprint file of exit',required=True)
parser.add_argument('-c','--consensus', help='consensus file of exit',required=True)

args = parser.parse_args()

class exitListener(protocol.Protocol):
#class exitListener(basic.LineRecevier):
    def dataReceived(self, data):
        action, channelID, circuitID, website = data.split(" ", 4)
        action = action.strip()
        channelID = int(channelID.strip())
        circuitID = int(circuitID.strip())
        website = website.strip()

        if action == "a":
            if channelID not in site_seen:
		site_seen[channelID] = {}
            if circuitID not in site_seen[channelID]:
                site_seen[channelID][circuitID] = {}
            if website not in site_seen[channelID][circuitID]:
	        site_seen[channelID][circuitID][website] = 1
		if website in labels:
                  r.inc(website)
		  #print website + " incremented!\n"
                else:
		  r.inc("Other")
                  #print "Other incremented!\n"

#	Not yet needed I think
#	elif action  == "d" and circuitID in site_seen:
#            site_seen.pop(circuitID)

#class exitRegister(protocol.Protocol):
class exitRegister(basic.LineReceiver):

    def connectionMade(self):
        self.register_exit()
        self.transport.loseConnection()

    def register_exit(self):
        global msg
#	time.sleep(dc_reg_delay)
        #self.transport.write(repr(msg[0]))
        print "DC: Registered with a TKG!"
        self.sendLine(repr(msg[0]))
	msg.pop(0)


#class exitStatSend(protocol.Protocol):
class exitStatSend(basic.LineReceiver):

#    def connectionMade(self):
#      self.send_stats()
#      self.transport.loseConnection()

    def __init__(self):
        should_send = False
        self.lc = task.LoopingCall(self.send_stats)
        self.lc.start(0.5)

    def send_stats(self):
        global should_send
#        global should_reg
        global r
#        global labels
#        global tkgs
        global msg
        global site_seen

        if should_send:
            should_send = False
	    self.send_data = json.dumps(r.publish())
#            self.send_data = repr(r.publish())
	    #print self.send_data # For debugging
	    #self.transport.write(self.send_data)
	    print "DC: Sending TS our stats!"
	    self.sendLine(self.send_data)
            #clean up objects and refresh
            site_seen.clear()
            r = None
            msg = []
            r = router(q, labels, tkgs, args.fingerprint, args.consensus)
            for kid, a in zip(r.keys, tkgs):
                msg.append(r.authority_msg(kid))
# TODO is this step neccesary??
            c_factory = protocol.ClientFactory()
            c_factory.protocol = exitRegister
            time.sleep(dc_reg_delay)
            for host, port in tkg_info:
                #reactor.connectTCP(host, int(port), c_factory)
                reactor.connectSSL(host, int(port), c_factory, ssl.ClientContextFactory())

if __name__ == "__main__":
    should_send = False
    labels = []
    tkgs = []
    site_seen = {}
    r = None

    tkg_info = []
    msg = []

    with open(args.input,'r') as f1:
        for line in f1:
            labels.append(line.strip())
        labels.append("Other")

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
            should_send = True


    epoch_check = task.LoopingCall(epoch_change)
    epoch_check.start(0.5)

    sendtallyfactory = protocol.ClientFactory()
    sendtallyfactory.protocol = exitStatSend
    #reactor.connectTCP("localhost", int(args.tallyport), sendtallyfactory)
    reactor.connectSSL(tallyhost, int(tallyport), sendtallyfactory, ssl.ClientContextFactory())

    c_factory = protocol.ClientFactory()
    c_factory.protocol = exitRegister
    time.sleep(dc_reg_delay)
    for host, port in tkg_info:
        #reactor.connectTCP(host, int(port), c_factory)
        reactor.connectSSL(host, int(port), c_factory, ssl.ClientContextFactory())

    s_factory = protocol.ServerFactory()
    s_factory.protocol = exitListener
    reactor.listenTCP(int(args.port), s_factory) # Local Tor connection
    print "DC ready!"
    reactor.run()
