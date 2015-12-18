'''
Created on Dec 15, 2015

@author: rob
'''
import sys
import os
import struct
import traceback
import logging

from random import gauss
from math import sqrt

from hashlib import sha256 as Hash
import binascii
from base64 import b64encode

from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet.protocol import ClientFactory, ServerFactory

import yaml

def log_error():
    _, _, tb = sys.exc_info()
    #traceback.print_tb(tb) # Fixed format
    tb_info = traceback.extract_tb(tb)
    filename, line, func, text = tb_info[-1]
    logging.warning("An error occurred in file '%s', at line %d, in func %s, in statement '%s'", filename, line, func, text)

def write_results(filename, ts_start, ts_end, totals):
    with open(filename, 'a') as fout:
        if totals:
            for i in totals:
                fout.write("{} {} {}:{}\n".format(ts_start, ts_end, i, totals[i]))
        else:
            fout.write("{} {} None\n".format(ts_start, ts_end))

def get_valid_config(config_filepath, ts=False, tks=False, dc=False):
    config = None
    try:
        logging.info("reading config file from '%s'", config_filepath)

        # read in the config from the given path
        with open(config_filepath, 'r') as fin:
            conf = yaml.load(fin)

        # make sure we have the required global vals
        assert conf['global']['q'] > 0
        assert conf['global']['resolution'] > 0
        assert conf['global']['epoch'] > 0
        assert conf['global']['sigma'] > 0
        assert conf['global']['clock_skew'] > 0

        if ts:
            # check the tally server specific vals
            expanded_path = os.path.expanduser(conf['tally_server']['key'])
            conf['tally_server']['key'] = os.path.abspath(expanded_path)
            expanded_path = os.path.expanduser(conf['tally_server']['cert'])
            conf['tally_server']['cert'] = os.path.abspath(expanded_path)
            expanded_path = os.path.expanduser(conf['tally_server']['results'])
            conf['tally_server']['results'] = os.path.abspath(expanded_path)

            assert conf['tally_server']['publish_delay'] >= 0
            assert conf['tally_server']['listen_port'] > 0
            assert os.path.exists(conf['tally_server']['key'])
            assert os.path.exists(conf['tally_server']['cert'])
            assert os.path.exists(os.path.dirname(conf['tally_server']['results']))

        if tks:
            # check the tally key server specific vals
            expanded_path = os.path.expanduser(conf['tally_key_server']['key'])
            conf['tally_key_server']['key'] = os.path.abspath(expanded_path)
            expanded_path = os.path.expanduser(conf['tally_key_server']['cert'])
            conf['tally_key_server']['cert'] = os.path.abspath(expanded_path)

            assert conf['tally_key_server']['start_delay'] >= 0
            assert conf['tally_key_server']['listen_port'] > 0
            assert conf['tally_key_server']['tally_server_info']['ip'] is not None
            assert conf['tally_key_server']['tally_server_info']['port'] > 0
            assert os.path.exists(conf['tally_key_server']['key'])
            assert os.path.exists(conf['tally_key_server']['cert'])

        if dc:
            # check the data collector specific vals
            expanded_path = os.path.expanduser(conf['data_collector']['fingerprint'])
            conf['data_collector']['fingerprint'] = os.path.abspath(expanded_path)
            expanded_path = os.path.expanduser(conf['data_collector']['consensus'])
            conf['data_collector']['consensus'] = os.path.abspath(expanded_path)

            assert conf['data_collector']['start_delay'] >= 0
            assert conf['data_collector']['register_delay'] >= 0
            assert conf['data_collector']['listen_port'] > 0
            assert os.path.exists(conf['data_collector']['fingerprint'])
            assert os.path.exists(conf['data_collector']['consensus'])
            assert conf['data_collector']['tally_server_info']['ip'] is not None
            assert conf['data_collector']['tally_server_info']['port'] > 0
            for item in conf['data_collector']['tally_key_server_infos']:
                assert item['ip'] is not None
                assert item['port'] >= 0

        config = {'global': conf['global']}
        if ts:
            config['tally_server'] = conf['tally_server']
        if tks:
            config['tally_key_server'] = conf['tally_key_server']
        if dc:
            config['data_collector'] = conf['data_collector']
    except AssertionError:
        logging.warning("problem reading config file: invalid data")
        log_error()
    except KeyError:
        logging.warning("problem reading config file: missing required keys")
        log_error()

    return config

def noise(sigma, fingerprint, sum_of_sq, p_exit):
    sigma_i = p_exit * sigma / sqrt(sum_of_sq)
    random_sample = gauss(0, sigma_i)
    return random_sample

def PRF(key, IV):
    return Hash("PRF1|KEY:%s|IV:%s|" % (key, IV)).digest()

def sample(s, q):
    ## Unbiased sampling through rejection sampling
    while True:
        v = struct.unpack("<L", s[:4])[0]
        if 0 <= v < q:
            break
        s = Hash(s).digest()
    return v

def keys_from_labels(labels, key, pos=True, q=2147483647):
    shares = []
    for l in labels:
        ## Keyed share derivation
        s = PRF(key, l)
        v = sample(s, q)
        s0 = v if pos else q - v

        ## Save the share
        shares.append((l, s0))
    return shares

def prob_exit(consensus, fingerprint):
    priv_exits = []
    weights = []

    DBW = 0
    EBW = 0

    DW = 0
    EW = 0

    prob = 0
    myWB = 0
    num_exits = 0
    biggest_bw = 0
    sum_of_sq_bw = 0

    with open(fingerprint,'r') as f:
        _, id_hex = f.readline().strip().split(" ") # has a nick in front
        id_bin = binascii.a2b_hex(id_hex)
        my_id = b64encode(id_bin).rstrip("=")

    with open("exit_prints.txt",'r') as h:
        for line in h:
            exit_id_hex = line.strip()
            exit_id_bin = binascii.a2b_hex(exit_id_hex)
            exit_id = b64encode(exit_id_bin).rstrip("=")
            priv_exits.append(exit_id)

    with open(consensus,'r') as g:
        for line in g:
            if "bandwidth-weights" in line:
                sline = line.split()
                sline = sline[7:9] ## only the exit weights that matter
                for i in sline:
                    weights.append(i.split("="))
                DW = float(weights[0][1])/10000
                EW = float(weights[1][1])/10000
    with open(consensus,'r') as f:
        ge = 0
        e = 0
        me = 0
        relay_fingerprint = ''
        for line in f:
            if line.startswith("r "):
                relay_fingerprint = line.strip().split()
                relay_fingerprint = relay_fingerprint[2:3]

            if line.startswith("r ") and my_id in line:
                me = 1
            if line.startswith("s ") and "BadExit" not in line and relay_fingerprint[0] in priv_exits:
                if "Guard" in line and "Exit" in line:
                    ge = 1
                    num_exits += 1
                elif "Exit" in line:
                    e = 1
                    num_exits += 1

            if line.startswith("w "):
                bandwidth = line.strip()
                if " Unmeasured" not in line:
                    _, bandwidth = bandwidth.split("=")
                else:
                    _, bandwidth, _ = bandwidth.split("=")
                    bandwidth , _ = bandwidth.split(" ")
                bandwidth = float(bandwidth)
                #print ge, e
                DBW += bandwidth*ge
                sum_of_sq_bw += (bandwidth*ge)**2
                EBW += bandwidth*e
                sum_of_sq_bw += (bandwidth*e)**2
                if me == 1:
                    myWB = bandwidth*ge + bandwidth*e
                ge = e = me = 0
                if biggest_bw < bandwidth:
                    biggest_bw = bandwidth

    TEWBW = DBW*DW + EBW*EW
    prob = myWB/TEWBW
    sum_of_sq = sum_of_sq_bw/(TEWBW**2)
#    print TEWBW, prob, num_exits, sum_of_sq
    return prob, sum_of_sq

class MessageReceiver(LineOnlyReceiver):
    '''
    send incoming messages to the given message handling queue
    '''

    def __init__(self, factory, handler_queue):
        self.factory = factory
        assert handler_queue
        self.handler_queue = handler_queue

    def lineReceived(self, line):
        self.handler_queue.put(('message', [line, self.transport.getPeer().host]))

class MessageReceiverFactory(ServerFactory):
    '''
    builds message receivers with the given queue
    '''
    protocol = MessageReceiver # not really needed, since we build our own protocol below

    def __init__(self, handler_queue):
        assert handler_queue
        self.handler_queue = handler_queue

    def buildProtocol(self, addr):
        return MessageReceiver(self, self.handler_queue)

class MessageSender(LineOnlyReceiver):
    '''
    send a message and close
    '''

    def __init__(self, factory, message):
        self.factory = factory
        self.message = message

    def connectionMade(self):
        self.sendLine(self.message)
        self.transport.loseConnection()

class MessageSenderFactory(ClientFactory):
    '''
    builds message senders with the given message
    '''
    protocol = MessageSender # not really needed, since we build our own protocol below

    def __init__(self, message):
        self.message = message

    def buildProtocol(self, addr):
        return MessageSender(self, self.message)

class CounterStore(object):
    '''
    this is used at the data collector to keep counts of statistics
    the counts start out random (blinded) and with noise
    the counts are incremented during collection
    the blinding factors are sent to the TKSes and the full counts to the TS
    '''

    def __init__(self, q, resolution, sigma, labels, num_tkses, fingerprint, consensus):
        self.data = {l:0 for l in labels}
        self.q = q
        self.resolution = resolution

        self.keys = [os.urandom(20) for _ in xrange(num_tkses)]
        self.keys = dict([(PRF(K, "KEYID"), K) for K in self.keys])

        for _, K in self.keys.iteritems():
            shares = keys_from_labels(labels, K, True, q)
            for (l, s0) in shares:
                self.data[l] = (self.data[l] + int(s0/self.resolution)) % self.q

	    # Add noise for each website independently
        p_exit, sum_of_sq = prob_exit(consensus, fingerprint)
        for label in self.data:
            noise_gen = noise(sigma, fingerprint, sum_of_sq, p_exit)
            self.data[label] = (self.data[label] + int(noise_gen/self.resolution)) % self.q

    def get_blinding_factor(self, kid):
        assert kid in self.keys and self.keys[kid] is not None
        msg = (sorted(self.data.keys()), (kid, self.keys[kid]), self.q)

        # TODO: secure delete
        del self.keys[kid]
        self.keys[kid] = None

        return msg

    def increment(self, label):
        if label in self.data:
            self.data[label] = (self.data[label] + int(1/self.resolution)) % self.q

    def get_blinded_noisy_counts(self):
        data = self.data
        ## Ensure we can only do this once!
        self.data = None
        self.keys = None
        return data

class KeyStore(object):
    '''
    this is used at the TKS nodes to store the blinding factor received from the DC nodes
    '''

    def __init__(self, q, resolution):
        self.data = {}
        self.keyIDs = {}
        self.q = q
        self.resolution = resolution

    def register_keyshare(self, labels, kid, K, q):
        assert q == self.q

        ## We have already registered this key
        if kid in self.keyIDs:
            return None

        ## Add shares
        shares = keys_from_labels(labels, K, False, q)
        for (l, s0) in shares:
            self.data[l] = (self.data.get(l, 0) + int(s0/self.resolution)) % self.q

        self.keyIDs[kid] = None  # TODO: registed client info
        return kid

    def get_combined_shares(self):
        data = self.data
        ## Ensure we can only do this once!
        self.data = None
        self.keyIDs = None
        return data
