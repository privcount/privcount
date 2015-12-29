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

from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet.protocol import ClientFactory, ServerFactory
from stem.descriptor import parse_file

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
            for i in sorted(totals.keys()):
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
        assert conf['global']['epoch'] > 0
        assert conf['global']['clock_skew'] > 0
        assert conf['global']['q'] > 0

        if ts:
            # check the tally server specific vals
            expanded_path = os.path.expanduser(conf['tally_server']['key'])
            conf['tally_server']['key'] = os.path.abspath(expanded_path)
            assert os.path.exists(conf['tally_server']['key'])

            expanded_path = os.path.expanduser(conf['tally_server']['cert'])
            conf['tally_server']['cert'] = os.path.abspath(expanded_path)
            assert os.path.exists(conf['tally_server']['cert'])

            expanded_path = os.path.expanduser(conf['tally_server']['results'])
            conf['tally_server']['results'] = os.path.abspath(expanded_path)
            assert os.path.exists(os.path.dirname(conf['tally_server']['results']))

            assert conf['tally_server']['publish_delay'] >= 0
            assert conf['tally_server']['listen_port'] > 0

        if tks:
            # check the tally key server specific vals
            expanded_path = os.path.expanduser(conf['tally_key_server']['key'])
            conf['tally_key_server']['key'] = os.path.abspath(expanded_path)
            assert os.path.exists(conf['tally_key_server']['key'])

            expanded_path = os.path.expanduser(conf['tally_key_server']['cert'])
            conf['tally_key_server']['cert'] = os.path.abspath(expanded_path)
            assert os.path.exists(conf['tally_key_server']['cert'])

            assert conf['tally_key_server']['start_delay'] >= 0
            assert conf['tally_key_server']['listen_port'] > 0
            assert conf['tally_key_server']['tally_server_info']['ip'] is not None
            assert conf['tally_key_server']['tally_server_info']['port'] > 0

        if dc:
            # check the data collector specific vals
            expanded_path = os.path.expanduser(conf['data_collector']['consensus'])
            conf['data_collector']['consensus'] = os.path.abspath(expanded_path)
            assert os.path.exists(conf['data_collector']['consensus'])

            assert conf['data_collector']['fingerprint'] is not None
            assert len(conf['data_collector']['colocated_fingerprints']) > 0
            assert conf['data_collector']['diversity_weight'] > 0.0
            assert conf['data_collector']['start_delay'] >= 0
            assert conf['data_collector']['register_delay'] >= 0
            assert conf['data_collector']['listen_port'] > 0
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

def noise(sigma, sum_of_sq, p_exit):
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

def prob_exit(consensus_path, my_fingerprint, fingerprint_pool=None):
    if fingerprint_pool == None:
        fingerprint_pool = [my_fingerprint]

    net_status = next(parse_file(consensus_path, document_handler='DOCUMENT', validate=False))
    DW = float(net_status.bandwidth_weights['Wed'])/10000
    EW = float(net_status.bandwidth_weights['Wed'])/10000

    my_bandwidth, DBW, EBW, sum_of_sq_bw = 0, 0, 0, 0

    if my_fingerprint in net_status.routers:
        my_bandwidth = net_status.routers[my_fingerprint].bandwidth

    for (fingerprint, router_entry) in net_status.routers.items():
        if fingerprint not in fingerprint_pool or 'BadExit' in router_entry.flags:
            continue

        if 'Guard' in router_entry.flags and 'Exit' in router_entry.flags:
            DBW += router_entry.bandwidth
            sum_of_sq_bw += router_entry.bandwidth**2

        elif 'Exit' in router_entry.flags:
            EBW += router_entry.bandwidth
            sum_of_sq_bw += router_entry.bandwidth**2

    TEWBW = DBW*DW + EBW*EW
    prob = my_bandwidth/TEWBW
    sum_of_sq = sum_of_sq_bw/(TEWBW**2)
    return prob, sum_of_sq

def get_noise_weight(diversity_weight, consensus_path, my_fingerprint, fingerprint_pool=None):
    # the weight of this relay relative to others running on the same machine
    my_weight, _ = prob_exit(consensus_path, my_fingerprint, fingerprint_pool)
    # the fraction of the weight allocated to this machine that this relay's stats are weighted
    return my_weight * diversity_weight

class CounterStore(object):
    '''
    this is used at the data collector to keep counts of statistics
    the counts start out random (blinded) and with noise
    the counts are incremented during collection
    the blinding factors are sent to the TKSes and the full counts to the TS
    '''

    def __init__(self, q, num_tkses, noise_weight, stats):
        labels = stats.keys()
        self.data = {l:0 for l in labels}
        self.q = q

        self.keys = [os.urandom(20) for _ in xrange(num_tkses)]
        self.keys = dict([(PRF(K, "KEYID"), K) for K in self.keys])

        for _, K in self.keys.iteritems():
            shares = keys_from_labels(labels, K, True, q)
            for (l, s0) in shares:
                self.data[l] = (self.data[l] + int(s0)) % self.q

	    # Add noise for each stat independently
        for label in stats:
            sigma = stats[label]
            noise_gen = noise(sigma, 1, noise_weight)
            assert label in self.data
            self.data[label] = (self.data[label] + int(noise_gen)) % self.q

    def get_blinding_factor(self, kid):
        assert kid in self.keys and self.keys[kid] is not None
        msg = (sorted(self.data.keys()), (kid, self.keys[kid]), self.q)

        # TODO: secure delete
        del self.keys[kid]
        self.keys[kid] = None

        return msg

    def increment(self, label):
        if label in self.data:
            self.data[label] = (self.data[label] + int(1)) % self.q

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

    def __init__(self, q):
        self.data = {}
        self.keyIDs = {}
        self.q = q

    def register_keyshare(self, labels, kid, K, q):
        assert q == self.q

        ## We have already registered this key
        if kid in self.keyIDs:
            return None

        ## Add shares
        shares = keys_from_labels(labels, K, False, q)
        for (l, s0) in shares:
            self.data[l] = (self.data.get(l, 0) + int(s0)) % self.q

        self.keyIDs[kid] = None  # TODO: registed client info
        return kid

    def get_combined_shares(self):
        data = self.data
        ## Ensure we can only do this once!
        self.data = None
        self.keyIDs = None
        return data

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
