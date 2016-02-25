import os
import logging
import math
import cPickle as pickle

from time import time
from copy import deepcopy
from base64 import b64decode

from protocol import PrivCountClientProtocol, TorControlClientProtocol
from tally_server import log_tally_server_status
from util import SecureCounters, log_error, get_public_digest_string, load_public_key_string, encrypt

import yaml

from twisted.internet import task, reactor, ssl
from twisted.internet.protocol import ReconnectingClientFactory

# using reactor: pylint: disable=E1101
# method docstring missing: pylint: disable=C0111
# line too long: pylint: disable=C0301

class DataCollector(ReconnectingClientFactory):
    '''
    receive key share data from the DC message receiver
    keep the shares during collection epoch
    send the shares to the TS at end of epoch
    '''

    def __init__(self, config_filepath):
        self.config_filepath = config_filepath
        self.config = None
        self.aggregator = None
        self.aggregator_defer_id = None

    def buildProtocol(self, addr):
        return PrivCountClientProtocol(self)

    def startFactory(self):
        # TODO
        return
        # load any state we may have from a previous run
        state_filepath = self.config['state']
        if os.path.exists(state_filepath):
            with open(state_filepath, 'r') as fin:
                state = pickle.load(fin)
                self.aggregator = state['aggregator']
                self.aggregator_defer_id = state['aggregator_defer_id']

    def stopFactory(self):
        # TODO
        return
        state_filepath = self.config['state']
        if self.aggregator is not None:
            # export everything that would be needed to survive an app restart
            state = {'aggregator': self.aggregator, 'aggregator_defer_id': self.aggregator_defer_id}
            with open(state_filepath, 'w') as fout:
                pickle.dump(state, fout)

    def run(self):
        # load iniital config
        self.refresh_config()
        if self.config is None:
            logging.critical("cannot start due to error in config file")
            return

        # connect to the tally server, register, and wait for commands
        self.do_checkin()
        reactor.run()

    def get_status(self): # called by protocol
        return {'type':'DataCollector', 'name':self.config['name'],
        'state': 'active' if self.aggregator is not None else 'idle'}

    def set_server_status(self, status): # called by protocol
        log_tally_server_status(status)

    def do_checkin(self): # called by protocol
        self.refresh_config()
        # turn on reconnecting mode and reset backoff
        self.resetDelay()
        ts_ip = self.config['tally_server_info']['ip']
        ts_port = self.config['tally_server_info']['port']
        logging.info("checking in with TallyServer at {}:{}".format(ts_ip, ts_port))
        reactor.connectSSL(ts_ip, ts_port, self, ssl.ClientContextFactory()) # pylint: disable=E1101

    def do_start(self, config): # called by protocol
        # return None if failure, otherwise json will encode result
        if 'q' not in config or 'sharekeepers' not in config or 'counters' not in config:
            return None
        # if we are still running from a previous incarnation, we need to stop first
        if self.aggregator is not None:
            return None

        ts_counters, dc_counters = deepcopy(config['counters']), deepcopy(self.config['counters'])

        # we keep our local config for which keys we are counting and the sigmas for noise
        # we allow the tally server to update only the bin widths for each counter
        for key in ts_counters:
            if key in dc_counters and 'bins' in ts_counters[key]:
                dc_counters[key]['bins'] = deepcopy(ts_counters[key]['bins'])

        # we cant count keys for which we don't have configured bins
        for key in dc_counters:
            if 'bins' not in dc_counters[key]:
                logging.warning("skipping counter '{}' because we do not have any bins configured".format(key))
                dc_counters.pop(key, None)

        # we require that only the configured share keepers be used in the collection phase
        # because we must be able to encrypt messages to them
        expected_sk_digests = set()
        for digest in self.config['share_keepers']:
            expected_sk_digests.add(digest)

        # verify that we have the public cert for each share keeper that the TS wants to use
        digest_error = False
        for sk_uid in config['sharekeepers']:
            pub_key_str = b64decode(config['sharekeepers'][sk_uid])
            requested_sk_digest = get_public_digest_string(pub_key_str, is_private_key=False)

            if requested_sk_digest not in expected_sk_digests:
                logging.info('we received an unexpected key for share keeper {}'.format(sk_uid))
                digest_error = True

            expected_sk_digests.remove(requested_sk_digest)

        if digest_error or len(expected_sk_digests) != 0:
            logging.info('refusing to start collecting without required share keepers')
            return None

        self.aggregator = Aggregator(dc_counters, config['sharekeepers'], self.config['noise_weight'], config['q'], self.config['event_source'])

        defer_time = config['defer_time'] if 'defer_time' in config else 0.0
        minutes = defer_time / 60.0
        logging.info("got start command from tally server, starting aggregator in {} minutes (at {})".format(minutes, time()+defer_time))

        # sync the time that we start listening for Tor events
        self.aggregator_defer_id = reactor.callLater(defer_time, self._start_aggregator_deferred)

        # return the generated shares now
        shares = self.aggregator.get_shares()
        # this is a dict {sk_uid : sk_msg} for each sk
        for sk_uid in shares:
            # TODO encrypt shares[sk_uid] for that sk
            pub_key_str = b64decode(config['sharekeepers'][sk_uid])
            sk_pub_key = load_public_key_string(pub_key_str)
            encrypted_secret = encrypt(sk_pub_key, shares[sk_uid]['secret'])
            shares[sk_uid]['secret'] = encrypted_secret

        logging.info("successfully started and generated {} blinding shares for {} counters".format(len(shares), len(dc_counters)))
        return shares

    def _start_aggregator_deferred(self):
        self.aggregator_defer_id = None
        self.aggregator.start()

    def do_stop(self, config): # called by protocol
        # stop the node from running
        # return None if failure, otherwise json will encode result
        logging.info("got command to stop collection phase")
        if 'send_counters' not in config:
            return None

        wants_counters = 'send_counters' in config and config['send_counters'] is True
        logging.info("tally server {} final counts".format("wants" if wants_counters else "does not want"))

        response = {}
        if self.aggregator_defer_id is not None:
            self.aggregator_defer_id.cancel()
            self.aggregator_defer_id = None
            assert self.aggregator is None

        elif self.aggregator is not None:
            counts = self.aggregator.stop()
            del self.aggregator
            self.aggregator = None
            if wants_counters:
                logging.info("sending counts from {} counters".format(len(counts)))
                response = counts

        logging.info("collection phase was stopped")
        return response

    def refresh_config(self):
        # re-read config and process any changes
        try:
            logging.debug("reading config file from '%s'", self.config_filepath)

            # read in the config from the given path
            with open(self.config_filepath, 'r') as fin:
                conf = yaml.load(fin)
            dc_conf = conf['data_collector']

            if 'counters' in dc_conf:
                expanded_path = os.path.expanduser(dc_conf['counters'])
                dc_conf['counters'] = os.path.abspath(expanded_path)
                assert os.path.exists(os.path.dirname(dc_conf['counters']))
                with open(dc_conf['counters'], 'r') as fin:
                    counters_conf = yaml.load(fin)
                dc_conf['counters'] = counters_conf['counters']
            else:
                dc_conf['counters'] = conf['counters']

            expanded_path = os.path.expanduser(dc_conf['state'])
            dc_conf['state'] = os.path.abspath(expanded_path)
            assert os.path.exists(os.path.dirname(dc_conf['state']))

            assert dc_conf['name'] != ''
            assert dc_conf['noise_weight'] >= 0
            assert dc_conf['tally_server_info']['ip'] is not None
            assert dc_conf['tally_server_info']['port'] > 0

            assert dc_conf['event_source'] is not None
            assert dc_conf['event_source'] > 0

            for key in dc_conf['counters']:
                assert dc_conf['counters'][key]['sigma'] >= 0.0

            assert 'share_keepers' in dc_conf

            if self.config == None:
                self.config = dc_conf
                logging.info("using config = %s", str(self.config))
            else:
                changed = False
                for k in dc_conf:
                    if k not in self.config or dc_conf[k] != self.config[k]:
                        logging.info("updated config for key {} from {} to {}".format(k, self.config[k], dc_conf[k]))
                        self.config[k] = dc_conf[k]
                        changed = True
                if not changed:
                    logging.debug('no config changes found')

        except AssertionError:
            logging.warning("problem reading config file: invalid data")
            log_error()
        except KeyError:
            logging.warning("problem reading config file: missing required keys")
            log_error()

class Aggregator(ReconnectingClientFactory):
    '''
    receive data from Tor control port
    parse the contents for valid events and stats
    aggregate stats during collection epoch
    add noise to aggregated stats at end of epoch
    send results for tallying
    '''

    def __init__(self, counters, sk_uids, noise_weight, param_q, tor_control_port):
        self.secure_counters = SecureCounters(counters, param_q)
        self.secure_counters.generate(sk_uids, noise_weight)

        self.connector = None
        self.protocol = None
        self.rotator = None
        self.tor_control_port = tor_control_port

        self.last_event_time = 0
        self.num_rotations = 0
        self.n_streams_per_circ = {}
        self.cli_ips_rotated = time()
        self.cli_ips_current = {}
        self.cli_ips_previous = {}

    def buildProtocol(self, addr):
        self.protocol = TorControlClientProtocol(self)
        return self.protocol

    def startFactory(self):
        # TODO
        return

    def stopFactory(self):
        # TODO
        return

    def start(self):
        self.connector = reactor.connectTCP("127.0.0.1", self.tor_control_port, self)
        self.rotator = task.LoopingCall(self._do_rotate).start(600, now=False)
        self.cli_ips_rotated = time()

    def stop(self):
        # dont try to reconnect
        self.stopTrying()

        # stop reading from Tor control port
        if self.protocol is not None:
            self.protocol.quit()
        if self.rotator is not None:
            self.rotator.cancel()
        if self.connector is not None:
            self.connector.disconnect()

        # return the final counts and make sure we cant be restarted
        counts = self.secure_counters.detach_counts()
        del self.secure_counters
        self.secure_counters = None
        return counts

    def get_shares(self):
        return self.secure_counters.detach_blinding_shares()

    def handle_event(self, event):
        if not self.secure_counters:
            return False

        event_code, line_remaining = [v.strip() for v in event.split(' ', 1)]
        self.last_event_time = time()

        # hand valid events off to the aggregator
        if event_code == 's':
            # 's', ChanID, CircID, StreamID, ExitPort, ReadBW, WriteBW, TimeStart, TimeEnd, isDNS, isDir
            items = [v.strip() for v in line_remaining.split(' ', 10)]
            if len(items) == 10:
                self._handle_stream_event(items[0:10])

        elif event_code == 'c':
            # 'c', ChanID, CircID, nCellsIn, nCellsOut, ReadBWDNS, WriteBWDNS, ReadBWExit, WriteBWExit, TimeStart, TimeEnd, PrevIP, prevIsClient, prevIsRelay, NextIP, nextIsClient, nextIsRelay
            items = [v.strip() for v in line_remaining.split(' ', 16)]
            if len(items) == 16:
                self._handle_circuit_event(items[0:16])

        elif event_code == 't':
            # 't', ChanID, TimeStart, TimeEnd, IP, isClient, isRelay
            items = [v.strip() for v in line_remaining.split(' ', 6)]
            if len(items) == 6:
                self._handle_connection_event(items[0:6])

        return True

    def _handle_stream_event(self, items):
        chanid, circid, strmid, port, readbw, writebw = [int(v) for v in items[0:6]]
        start, end = float(items[6]), float(items[7])
        is_dns = True if int(items[8]) == 1 else False
        is_dir = True if int(items[9]) == 1 else False

        self.secure_counters.increment("StreamsAll", 1)

        stream_class = self._classify_port(port)
        self.n_streams_per_circ.setdefault(chanid, {}).setdefault(circid, {'interactive':0, 'web':0, 'p2p':0, 'other':0})
        self.n_streams_per_circ[chanid][circid][stream_class] += 1

        # only count bytes on streams with legitimate transfers
        if readbw+writebw > 0:
            # the amount we read from the stream is bound for the client
            # the amount we write to the stream is bound to the server
            ratio = self._encode_ratio(readbw, writebw)
            lifetime = end-start

            if stream_class == 'web':
                self.secure_counters.increment("StreamLifeTimeWeb", lifetime)
                self.secure_counters.increment("StreamBytesOutWeb", writebw)
                self.secure_counters.increment("StreamBytesInWeb", readbw)
                self.secure_counters.increment("StreamBytesRatioWeb", ratio)
            elif stream_class == 'interactive':
                self.secure_counters.increment("StreamLifeTimeInteractive", lifetime)
                self.secure_counters.increment("StreamBytesOutInteractive", writebw)
                self.secure_counters.increment("StreamBytesInInteractive", readbw)
                self.secure_counters.increment("StreamBytesRatioInteractive", ratio)
            elif stream_class == 'p2p':
                self.secure_counters.increment("StreamLifeTimeP2P", lifetime)
                self.secure_counters.increment("StreamBytesOutP2P", writebw)
                self.secure_counters.increment("StreamBytesInP2P", readbw)
                self.secure_counters.increment("StreamBytesRatioP2P", ratio)
            elif stream_class == 'other':
                self.secure_counters.increment("StreamLifeTimeOther", lifetime)
                self.secure_counters.increment("StreamBytesOutOther", writebw)
                self.secure_counters.increment("StreamBytesInOther", readbw)
                self.secure_counters.increment("StreamBytesRatioOther", ratio)

    def _classify_port(self, port):
        if port == 22 or (port >= 6660 and port <= 6669) or port == 6697 or port == 7000:
            return 'interactive'
        elif port == 80 or port == 443:
            return 'web'
        elif (port >= 6881 and port <= 6889) or port == 6969 or port >= 10000:
            return 'p2p'
        else:
            return 'other'

    def _encode_ratio(self, inval, outval):
        if inval == outval:
            return 0.0
        elif inval == 0.0:
            return float('inf')
        elif outval == 0.0:
            return float('-inf')
        else:
            return math.log(float(outval)/float(inval), 2) # log base 2

    def _handle_circuit_event(self, items):
        chanid, circid, ncellsin, ncellsout, readbwdns, writebwdns, readbwexit, writebwexit = [int(v) for v in items[0:8]]
        start, end = float(items[8]), float(items[9])
        previp = items[10]
        prevIsClient = True if int(items[11]) > 0 else False
        prevIsRelay = True if int(items[12]) > 0 else False
        nextip = items[13]
        nextIsClient = True if int(items[14]) > 0 else False
        nextIsRelay = True if int(items[15]) > 0 else False

        # we get circuit events on both exits and entries
        # stream bw info is only avail on exits
        # isclient is based on CREATE_FAST and I'm not sure that is always used by clients
        if not prevIsRelay:
            # previous hop is unkown, we are entry
            self.secure_counters.increment("CircuitLifeTime", end - start)

            # only count cells ratio on active circuits with legitimate transfers
            active_key = 'active' if ncellsin + ncellsout >= 8 else 'inactive'
            if active_key == 'active':
                self.secure_counters.increment("CircuitCellsIn", ncellsin)
                self.secure_counters.increment("CircuitCellsOut", ncellsout)
                self.secure_counters.increment("CircuitCellsRatio", self._encode_ratio(ncellsin, ncellsout))

            # count unique client ips
            if start >= self.cli_ips_rotated:
                self.cli_ips_current.setdefault(previp, {'active':0, 'inactive':0})[active_key] += 1
            elif start >= self.cli_ips_rotated-600.0:
                self.cli_ips_previous.setdefault(previp, {'active':0, 'inactive':0})[active_key] += 1

        elif not nextIsRelay:
            # prev hop is known relay but next is not, we are exit
            is_circ_known = chanid in self.n_streams_per_circ and circid in self.n_streams_per_circ[chanid]

            if is_circ_known and sum(self.n_streams_per_circ[chanid][circid].values()) > 0:
                # we have circuit info and at least one stream ended on it
                self.secure_counters.increment("CircuitsActive", 1)
                # only increment the protocols that have positive counts
                counts = self.n_streams_per_circ[chanid][circid]
                if counts['web'] > 0:
                    self.secure_counters.increment("CircuitStreamsWeb", counts['web'])
                if counts['interactive'] > 0:
                    self.secure_counters.increment("CircuitStreamsInteractive", counts['interactive'])
                if counts['p2p'] > 0:
                    self.secure_counters.increment("CircuitStreamsP2P", counts['p2p'])
                if counts['other'] > 0:
                    self.secure_counters.increment("CircuitStreamsOther", counts['other'])
            else:
                # either we dont know circ, or no streams ended on it
                self.secure_counters.increment("CircuitsInactive", 1)

            # cleanup
            if is_circ_known:
                # remove circ from channel
                self.n_streams_per_circ[chanid].pop(circid, None)
                # if that was the last circuit on channel, remove the channel too
                if len(self.n_streams_per_circ[chanid]) == 0:
                    self.n_streams_per_circ.pop(chanid, None)

    def _handle_connection_event(self, items):
        chanid = int(items[0])
        start, end = float(items[1]), float(items[2])
        ip = items[3]
        isclient = True if int(items[4]) > 0 else False
        isrelay = True if int(items[5]) > 0 else False
        if not isrelay:
            self.secure_counters.increment("ConnectionsAll", 1)

    def _do_rotate(self):
        logging.info("rotating circuit window now, last event received from Tor was %s seconds ago", str(time() - self.last_event_time))

        # dont count anything in the first rotation period, since events that ended up in the
        # previous list will be skewed torward longer lived circuits
        if True:#self.num_rotations > 0:
            self.secure_counters.increment("ClientIPsUnique", len(self.cli_ips_previous))
            for ip in self.cli_ips_previous:
                self.secure_counters.increment("ClientIPCircuitsActive", self.cli_ips_previous[ip]['active'])
                self.secure_counters.increment("ClientIPCircuitsInactive", self.cli_ips_previous[ip]['inactive'])

        # reset for next interval
        self.cli_ips_previous = self.cli_ips_current
        self.cli_ips_current = {}
        self.cli_ips_rotated = time()
        self.num_rotations += 1
