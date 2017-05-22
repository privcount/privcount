# See LICENSE for licensing information

import os
import logging
import math
import string
import sys
import cPickle as pickle
import yaml

from time import time
from copy import deepcopy
from base64 import b64decode

from twisted.internet import task, reactor, ssl
from twisted.internet.protocol import ReconnectingClientFactory

from privcount.config import normalise_path, choose_secret_handshake_path
from privcount.connection import connect, disconnect, validate_connection_config, choose_a_connection, get_a_control_password
from privcount.counter import SecureCounters, counter_modulus, add_counter_limits_to_config, combine_counters, has_noise_weight, get_noise_weight
from privcount.crypto import get_public_digest_string, load_public_key_string, encrypt
from privcount.log import log_error, format_delay_time_wait, format_last_event_time_since
from privcount.node import PrivCountClient
from privcount.protocol import PrivCountClientProtocol, TorControlClientProtocol, errorCallback
from privcount.traffic_model import TrafficModel, check_traffic_model_config

SINGLE_BIN = SecureCounters.SINGLE_BIN

# using reactor: pylint: disable=E1101
# method docstring missing: pylint: disable=C0111
# line too long: pylint: disable=C0301

class DataCollector(ReconnectingClientFactory, PrivCountClient):
    '''
    receive key share data from the DC message receiver
    keep the shares during collection epoch
    send the shares to the TS at end of epoch
    '''

    def __init__(self, config_filepath):
        PrivCountClient.__init__(self, config_filepath)
        self.aggregator = None
        self.is_aggregator_pending = False
        self.context = {}

    def buildProtocol(self, addr):
        '''
        Called by twisted
        '''
        return PrivCountClientProtocol(self)

    def startFactory(self):
        '''
        Called by twisted
        '''
        # TODO
        return
        state = self.load_state()
        if state is not None:
            self.aggregator = state['aggregator']
            self.is_aggregator_pending = state['is_aggregator_pending']

    def stopFactory(self):
        '''
        Called by twisted
        '''
        # TODO
        return
        if self.aggregator is not None:
            # export everything that would be needed to survive an app restart
            state = {'aggregator': self.aggregator, 'is_aggregator_pending': self.is_aggregator_pending}
            self.dump_state(state)

    def run(self):
        '''
        Called by twisted
        '''
        # load initial config
        self.refresh_config()
        if self.config is None:
            logging.critical("cannot start due to error in config file")
            return

        # connect to the tally server, register, and wait for commands
        self.do_checkin()
        reactor.run()

    def get_status(self):
        '''
        Called by protocol
        Returns a dictionary containing status information
        '''
        status = {'type':'DataCollector', 'name':self.config['name'],
                  'state': 'active' if self.aggregator is not None else 'idle'}
        # store the latest context, so we have it even when the aggregator goes away
        if self.aggregator is not None:
            self.context.update(self.aggregator.get_context())
        # and include the latest context values in the status
        status.update(self.context)
        return status

    def do_checkin(self):
        '''
        Called by protocol
        Refresh the config, and try to connect to the server
        This function is usually called using LoopingCall, so any exceptions
        will be turned into log messages.
        '''
        # TODO: Refactor common client code - issue #121
        self.refresh_config()
        ts_ip = self.config['tally_server_info']['ip']
        ts_port = self.config['tally_server_info']['port']
        # turn on reconnecting mode and reset backoff
        self.resetDelay()
        logging.info("checking in with TallyServer at {}:{}".format(ts_ip, ts_port))
        reactor.connectSSL(ts_ip, ts_port, self, ssl.ClientContextFactory()) # pylint: disable=E1101

    def do_start(self, config):
        '''
        this is called by the protocol when we receive a command from the TS
        to start a new collection phase
        return None if failure, otherwise json will encode result
        '''
        # keep the start config to send to the TS at the end of the collection
        # deepcopy in case we make any modifications later
        self.start_config = deepcopy(config)

        if ('sharekeepers' not in config):
            logging.warning("start command from tally server cannot be completed due to missing sharekeepers")
            return None

        dc_counters = self.check_start_config(config)

        if dc_counters is None:
            return None

        # if we are still running from a previous incarnation, we need to stop
        # first
        if self.aggregator is not None:
            return None

        # we require that only the configured share keepers be used in the
        # collection phase, because we must be able to encrypt messages to them
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

        # if we got a traffic model from the tally server and it passes validation,
        # then load the traffic model object that we will use during aggregation
        traffic_model_config = None
        if 'traffic_model' in config:
            traffic_model_config = config['traffic_model']

        # The aggregator doesn't care about the DC threshold
        self.aggregator = Aggregator(dc_counters,
                                     traffic_model_config,
                                     config['sharekeepers'],
                                     config['noise_weight'],
                                     counter_modulus(),
                                     self.config['event_source'],
                                     self.config['rotate_period'])

        defer_time = config['defer_time'] if 'defer_time' in config else 0.0
        logging.info("got start command from tally server, starting aggregator in {}".format(format_delay_time_wait(defer_time, 'at')))

        # sync the time that we start listening for Tor events
        aggregator_deferred = task.deferLater(reactor, defer_time,
                                              self._start_aggregator_deferred)
        self.is_aggregator_pending = True
        aggregator_deferred.addErrback(errorCallback)
        # return the generated shares now
        shares = self.aggregator.get_shares()
        # this is a dict {sk_uid : sk_msg} for each sk
        for sk_uid in shares:
            # add the sender's name for debugging purposes
            shares[sk_uid]['dc_name'] = self.config['name']
            # encrypt shares[sk_uid] for that sk
            pub_key_str = b64decode(config['sharekeepers'][sk_uid])
            sk_pub_key = load_public_key_string(pub_key_str)
            encrypted_secret = encrypt(sk_pub_key, shares[sk_uid]['secret'])
            # TODO: secure delete
            shares[sk_uid]['secret'] = encrypted_secret

        logging.info("successfully started and generated {} blinding shares for {} counters".format(len(shares), len(dc_counters)))
        return shares

    def _start_aggregator_deferred(self):
        '''
        This function is called using deferLater, so any exceptions will be
        handled by errorCallback.
        '''
        if self.is_aggregator_pending:
            self.is_aggregator_pending = False
            self.aggregator.start()

    def do_stop(self, config):
        '''
        called by protocol
        the TS wants us to stop the current collection phase
        they may or may not want us to send back our counters
        stop the node from running
        return a dictionary containing counters (if available and wanted)
        and the local and start configs
        '''
        logging.info("got command to stop collection phase")

        counts = None
        if self.is_aggregator_pending:
            self.is_aggregator_pending = False
            assert self.aggregator is None
            logging.info("Aggregator deferred, counts never started")
        elif self.aggregator is not None:
            counts = self.aggregator.stop()
            del self.aggregator
            self.aggregator = None
        else:
            logging.info("No aggregator, counts never started")

        return self.check_stop_config(config, counts)

    DEFAULT_ROTATE_PERIOD = 600

    def refresh_config(self):
        '''
        re-read config and process any changes
        '''
        # TODO: refactor common code: see ticket #121
        try:
            logging.debug("reading config file from '%s'", self.config_filepath)

            # read in the config from the given path
            with open(self.config_filepath, 'r') as fin:
                conf = yaml.load(fin)
            dc_conf = conf['data_collector']

            # find the path for the secret handshake file
            dc_conf['secret_handshake'] = choose_secret_handshake_path(
                dc_conf, conf)

            # the state file
            dc_conf['state'] = normalise_path(dc_conf['state'])
            assert os.path.exists(os.path.dirname(dc_conf['state']))

            dc_conf['delay_period'] = self.get_valid_delay_period(dc_conf)

            dc_conf.setdefault('always_delay', False)
            assert isinstance(dc_conf['always_delay'], bool)

            dc_conf['rotate_period'] = dc_conf.get('rotate_period',
                                          conf.get('rotate_period',
                                                   DataCollector.DEFAULT_ROTATE_PERIOD))
            assert dc_conf['rotate_period'] > 0

            dc_conf['sigma_decrease_tolerance'] = \
                self.get_valid_sigma_decrease_tolerance(dc_conf)

            assert dc_conf['name'] != ''

            assert validate_connection_config(dc_conf['tally_server_info'],
                                           must_have_ip=True)
            assert validate_connection_config(dc_conf['event_source'])

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

    def __init__(self, counters, traffic_model_config, sk_uids,
                 noise_weight, modulus, tor_control_port, rotate_period):
        self.secure_counters = SecureCounters(counters, modulus)
        self.collection_counters = counters
        # we can't generate the noise yet, because we don't know the
        # DC fingerprint
        self.secure_counters.generate_blinding_shares(sk_uids)

        # the traffic model is optional
        self.traffic_model = None
        if traffic_model_config is not None:
            self.traffic_model = TrafficModel(traffic_model_config)

        self.noise_weight_config = noise_weight
        self.noise_weight_value = None

        self.connector = None
        self.connector_list = None
        self.protocol = None
        self.rotator = None
        self.tor_control_port = tor_control_port
        self.rotate_period = rotate_period

        self.last_event_time = None
        self.num_rotations = 0
        self.circ_info = {}
        self.strm_bytes = {}
        self.cli_ips_rotated = time()
        self.cli_ips_current = {}
        self.cli_ips_previous = {}

        self.nickname = None
        self.orport = None
        self.dirport = None
        self.version = None
        self.address = None
        self.fingerprint = None

    def buildProtocol(self, addr):
        self.protocol = TorControlClientProtocol(self)
        # if we didn't build the protocol until after starting
        if self.connector is not None:
            self.protocol.startCollection(self.collection_counters)
        return self.protocol

    def startFactory(self):
        # TODO
        return

    def stopFactory(self):
        # TODO
        return

    def start(self):
        '''
        start the aggregator, and connect to the control port
        '''
        # This call can return a list of connectors, or a single connector
        self.connector_list = connect(self, self.tor_control_port)
        # Twisted doesn't want a list of connectors, it only wants one
        self.connector = choose_a_connection(self.connector_list)
        self.rotator = task.LoopingCall(self._do_rotate)
        rotator_deferred = self.rotator.start(self.rotate_period, now=False)
        rotator_deferred.addErrback(errorCallback)
        self.cli_ips_rotated = time()
        # if we've already built the protocol before starting
        if self.protocol is not None:
            self.protocol.startCollection(self.collection_counters)

    def _stop_protocol(self):
        '''
        Stop protocol and connection activities.
        '''
        # don't try to reconnect
        self.stopTrying()

        # stop reading from Tor control port
        if self.protocol is not None:
            self.protocol.stopCollection()
            self.protocol.quit()
            self.protocol = None
        if self.rotator is not None and self.rotator.running:
            self.rotator.stop()
            self.rotator = None
        if self.connector_list is not None:
            disconnect(self.connector_list)
            self.connector_list = None
            self.connector = None

    def _stop_secure_counters(self, counts_are_valid=True):
        '''
        If counts_are_valid, detach and return the counts from secure counters.
        Otherwise, return None.
        '''
        # if we've already stopped counting due to an error, there are no
        # counters
        if self.secure_counters is None:
            return None

        # return the final counts and make sure we cant be restarted
        counts = self.secure_counters.detach_counts()
        # TODO: secure delete?
        del self.secure_counters
        self.secure_counters = None
        if counts_are_valid:
            return counts
        else:
            return None

    def stop(self, counts_are_valid=True):
        '''
        Stop counting, and stop connecting to the ControlPort and Tally Server.
        Retrieve the counts, and delete the counters.
        If counts_are_valid is True, return the counts.
        Otherwise, return None.
        '''
        # make sure we added noise
        if self.noise_weight_value is None and counts_are_valid:
            logging.warning("Noise was not added to counters when the control port connection was opened. Adding now.")
            self.generate_noise()

        # stop trying to collect data
        self._stop_protocol()

        # stop using the counters
        return self._stop_secure_counters(counts_are_valid=counts_are_valid)

    def get_shares(self):
        return self.secure_counters.detach_blinding_shares()

    def generate_noise(self):
        '''
        If self.fingerprint is included in the noise weight config from the
        tally server, add noise to the counters based on the weight for that
        fingerprint.
        If not, stop participating in the round and delete all counters.
        Must be called before detaching counters.
        '''
        if self.noise_weight_value is not None:
            logging.warning("Asked to add noise twice. Ignoring.")
            return

        if has_noise_weight(self.noise_weight_config, self.fingerprint):
            self.noise_weight_value = get_noise_weight(
                self.noise_weight_config, self.fingerprint)
        else:
            logging.warning("Tally Server did not provide a noise weight for our fingerprint {} in noise weight config {}, we will not count in this round."
                            .format(self.fingerprint,
                                    self.noise_weight_config))
            # stop collecting and stop counting
            self._stop_protocol()
            self._stop_secure_counters(counts_are_valid=False)

    def get_control_password(self):
        '''
        Return the configured control password for this data collector, or
        None if no connections have a control password.
        '''
        # Multiple different control passwords are not supported
        return get_a_control_password(self.tor_control_port)

    def set_nickname(self, nickname):
        nickname = nickname.strip()

        # Do some basic validation of the nickname
        if len(nickname) < 1 or len(nickname) > 19:
            logging.warning("Bad nickname length %d: %s", len(nickname), nickname)
            return False
        if not all(c in (string.ascii_letters + string.digits) for c in nickname):
            logging.warning("Bad nickname characters: %s", nickname)
            return False

        # Are we replacing an existing nickname?
        if self.nickname is not None:
            if self.nickname != nickname:
                logging.warning("Replacing nickname %s with %s", self.nickname, nickname)
            else:
                logging.debug("Duplicate nickname received %s", nickname)

        self.nickname = nickname

        return True

    def get_nickname(self):
        return self.nickname

    def set_orport(self, orport):
        orport = orport.strip()

        # Do some basic validation of the orport
        if len(orport) < 1 or len(orport) > 5:
            logging.warning("Bad orport length %d: %s", len(orport), orport)
            return False
        if not all(c in string.digits for c in orport):
            logging.warning("Bad orport characters: %s", orport)
            return False
        orport_n = int(orport)
        if orport_n < 1 or orport_n > 65535:
            logging.warning("Bad orport: out of range: %s", orport)
            return False

        # Are we replacing an existing nickname?
        if self.orport is not None:
            if self.orport != orport:
                logging.warning("Replacing orport %s with %s", self.orport, orport)
            else:
                logging.debug("Duplicate orport received %s", orport)

        self.orport = orport

        return True

    def get_orport(self):
        return self.orport

    def set_dirport(self, dirport):
        dirport = dirport.strip()

        # Do some basic validation of the dirport
        if len(dirport) < 1 or len(dirport) > 5:
            logging.warning("Bad dirport length %d: %s", len(dirport), dirport)
            return False
        if not all(c in string.digits for c in dirport):
            logging.warning("Bad dirport characters: %s", dirport)
            return False
        dirport_n = int(dirport)
        if dirport_n < 1 or dirport_n > 65535:
            logging.warning("Bad dirport: out of range: %s", dirport)
            return False

        # Are we replacing an existing nickname?
        if self.dirport is not None:
            if self.dirport != dirport:
                logging.warning("Replacing dirport %s with %s", self.dirport, dirport)
            else:
                logging.debug("Duplicate dirport received %s", dirport)

        self.dirport = dirport

        return True

    def get_dirport(self):
        return self.dirport

    def set_version(self, version):
        version = version.strip()

        # Do some basic validation of the version
        # This is hard, because versions can be almost anything
        if not len(version) > 0:
            logging.warning("Bad version length %d: %s", len(version), version)
            return False
        # This means unicode printables, there's no ASCII equivalent
        if not all(c in string.printable for c in version):
            logging.warning("Bad version characters: %s", version)
            return False

        # Are we replacing an existing version?
        if self.version is not None:
            if self.version != version:
                if self.version.lower() in version.lower():
                    # we just added a git tag to the version
                    # this happens because GETINFO version has the tag, but
                    # PROTOCOLINFO does not
                    logging_level = logging.debug
                else:
                    # did someone just restart tor with a new version?
                    logging_level = logging.warning
                logging_level("Replacing version %s with %s", self.version, version)
            else:
                logging.debug("Duplicate version received %s", version)

        self.version = version

        return True

    def get_version(self):
        return self.version

    def set_address(self, address):
        address = address.strip()

        # Do some basic validation of the address
        # Relays must all have IPv4 addresses, so just checking for IPv4 is ok
        if len(address) < 7 or len(address) > 15:
            logging.warning("Bad address length %d: %s", len(address), address)
            return False
        if not all(c in (string.digits + '.') for c in address):
            logging.warning("Bad address characters: %s", address)
            return False
        # We could check each component is between 0 and 255, but that's overkill

        # Are we replacing an existing address?
        if self.address is not None:
            if self.address != address:
                logging.warning("Replacing address %s with %s", self.address, address)
            else:
                logging.debug("Duplicate address received %s", address)

        self.address = address

        return True

    def get_address(self):
        return self.address

    def set_fingerprint(self, fingerprint):
        '''
        If fingerprint is valid, set our stored fingerprint to fingerprint, and
        return True.
        Otherwise, return False.
        Called by TorControlClientProtocol.
        '''
        fingerprint = fingerprint.strip()

        # Do some basic validation of the fingerprint
        if not len(fingerprint) == 40:
            logging.warning("Bad fingerprint length %d: %s", len(fingerprint), fingerprint)
            return False
        if not all(c in string.hexdigits for c in fingerprint):
            logging.warning("Bad fingerprint characters: %s", fingerprint)
            return False

        # Is this the first time we've been told a fingerprint?
        if self.fingerprint is None:
            self.fingerprint = fingerprint
            self.generate_noise()
        else:
            if self.fingerprint != fingerprint:
                logging.warning("Received different fingerprint %s, keeping original fingerprint %s",
                                self.fingerprint, fingerprint)
            else:
                logging.debug("Duplicate fingerprint received %s", fingerprint)

        return True

    def get_fingerprint(self):
        '''
        Return the stored fingerprint for this relay.
        '''
        return self.fingerprint

    def get_context(self):
        '''
        return a dictionary containing each available context item
        '''
        context = {}
        if self.get_nickname() is not None:
            context['nickname'] = self.get_nickname()
        if self.get_orport() is not None:
            context['orport'] = self.get_orport()
        if self.get_dirport() is not None:
            context['dirport'] = self.get_dirport()
        if self.get_version() is not None:
            context['version'] = self.get_version()
        if self.get_address() is not None:
            context['address'] = self.get_address()
        if self.get_fingerprint() is not None:
            context['fingerprint'] = self.get_fingerprint()
        if self.last_event_time is not None:
            context['last_event_time'] = self.last_event_time
        if self.noise_weight_value is not None:
            context['noise_weight_value'] = self.noise_weight_value
        return context

    def handle_event(self, event):
        if not self.secure_counters:
            return False

        # fail on empty events
        if len(event) <= 1:
            return False

        event_code, items = event[0], event[1:]
        self.last_event_time = time()

        # hand valid events off to the aggregator
        if event_code == 'PRIVCOUNT_STREAM_BYTES_TRANSFERRED':
            if len(items) == Aggregator.STREAM_BYTES_ITEMS:
                return self._handle_bytes_event(items[:Aggregator.STREAM_BYTES_ITEMS])
            else:
                return False

        elif event_code == 'PRIVCOUNT_STREAM_ENDED':
            if len(items) == Aggregator.STREAM_ENDED_ITEMS:
                return self._handle_stream_event(items[:Aggregator.STREAM_ENDED_ITEMS])
            else:
                return False


        elif event_code == 'PRIVCOUNT_CIRCUIT_ENDED':
            if len(items) == Aggregator.CIRCUIT_ENDED_ITEMS:
                return self._handle_circuit_event(items[:Aggregator.CIRCUIT_ENDED_ITEMS])
            else:
                return False

        elif event_code == 'PRIVCOUNT_CONNECTION_ENDED':
            if len(items) == Aggregator.CONNECTION_ENDED_ITEMS:
                return self._handle_connection_event(items[:Aggregator.CONNECTION_ENDED_ITEMS])
            else:
                return False

        return True

    STREAM_BYTES_ITEMS = 6

    # 'PRIVCOUNT_STREAM_BYTES_TRANSFERRED', ChanID, CircID, StreamID, isOutbound, BW, Time
    def _handle_bytes_event(self, items):
        assert(len(items) == Aggregator.STREAM_BYTES_ITEMS)

        # if we get an unexpected byte event, warn but ignore
        if self.traffic_model == None:
            logging.warning("No traffic model for stream bytes event")
            return True

        chanid, circid, strmid, is_outbound, bw_bytes = [int(v) for v in items[0:5]]
        ts = float(items[5])

        self.strm_bytes.setdefault(strmid, {}).setdefault(circid, [])
        self.strm_bytes[strmid][circid].append([bw_bytes, is_outbound, ts])
        return True

    STREAM_ENDED_ITEMS = 10

    # 'PRIVCOUNT_STREAM_ENDED', ChanID, CircID, StreamID, ExitPort, ReadBW, WriteBW, TimeStart, TimeEnd, RemoteHost, RemoteIP
    def _handle_stream_event(self, items):
        assert(len(items) == Aggregator.STREAM_ENDED_ITEMS)

        chanid, circid, strmid, port, readbw, writebw = [int(v) for v in items[0:6]]
        start, end = float(items[6]), float(items[7])
        remote_host = items[8]
        remote_ip = items[9]

        # only count streams with legitimate transfers
        totalbw = readbw + writebw
        if readbw < 0 or writebw < 0 or totalbw <= 0:
            return True

        self.circ_info.setdefault(chanid, {}).setdefault(circid, {'num_streams': {'interactive':0, 'web':0, 'p2p':0, 'other':0}, 'stream_starttimes': {'interactive':[], 'web':[], 'p2p':[], 'other':[]}})

        stream_class = Aggregator._classify_port(port)
        self.circ_info[chanid][circid]['num_streams'][stream_class] += 1
        self.circ_info[chanid][circid]['stream_starttimes'][stream_class].append(start)

        # the amount we read from the stream is bound for the client
        # the amount we write to the stream is bound to the server
        ratio = Aggregator._encode_ratio(readbw, writebw)
        lifetime = end-start

        self.secure_counters.increment('ExitStreamCount', SINGLE_BIN)
        self.secure_counters.increment('ExitStreamByteCount', SINGLE_BIN, totalbw)
        self.secure_counters.increment('ExitStreamOutboundByteCount', writebw)
        self.secure_counters.increment('ExitStreamInboundByteCount', readbw)
        self.secure_counters.increment('ExitStreamByteRatio', ratio)
        self.secure_counters.increment('ExitStreamLifeTime', lifetime)

        if stream_class == 'web':
            self.secure_counters.increment('ExitWebStreamCount', SINGLE_BIN)
            self.secure_counters.increment('ExitWebStreamByteCount', SINGLE_BIN, totalbw)
            self.secure_counters.increment('ExitWebStreamOutboundByteCount', writebw)
            self.secure_counters.increment('ExitWebStreamInboundByteCount', readbw)
            self.secure_counters.increment('ExitWebStreamByteRatio', ratio)
            self.secure_counters.increment('ExitWebStreamLifeTime', lifetime)
        elif stream_class == 'interactive':
            self.secure_counters.increment('ExitInteractiveStreamCount', SINGLE_BIN)
            self.secure_counters.increment('ExitInteractiveStreamByteCount', SINGLE_BIN, totalbw)
            self.secure_counters.increment('ExitInteractiveStreamOutboundByteCount', writebw)
            self.secure_counters.increment('ExitInteractiveStreamInboundByteCount', readbw)
            self.secure_counters.increment('ExitInteractiveStreamByteRatio', ratio)
            self.secure_counters.increment('ExitInteractiveStreamLifeTime', lifetime)
        elif stream_class == 'p2p':
            self.secure_counters.increment('ExitP2PStreamCount', SINGLE_BIN)
            self.secure_counters.increment('ExitP2PStreamByteCount', SINGLE_BIN, totalbw)
            self.secure_counters.increment('ExitP2PStreamOutboundByteCount', writebw)
            self.secure_counters.increment('ExitP2PStreamInboundByteCount', readbw)
            self.secure_counters.increment('ExitP2PStreamByteRatio', ratio)
            self.secure_counters.increment('ExitP2PStreamLifeTime', lifetime)
        elif stream_class == 'other':
            self.secure_counters.increment('ExitOtherPortStreamCount', SINGLE_BIN)
            self.secure_counters.increment('ExitOtherPortStreamByteCount', SINGLE_BIN, totalbw)
            self.secure_counters.increment('ExitOtherPortStreamOutboundByteCount', writebw)
            self.secure_counters.increment('ExitOtherPortStreamInboundByteCount', readbw)
            self.secure_counters.increment('ExitOtherPortStreamByteRatio', ratio)
            self.secure_counters.increment('ExitOtherPortStreamLifeTime', lifetime)

        # if we have a traffic model object, then we should use our observations to find the
        # most likely path through the HMM, and then count some aggregate statistics
        # about that path
        if self.traffic_model is not None and strmid in self.strm_bytes and circid in self.strm_bytes[strmid]:
            byte_events = self.strm_bytes[strmid][circid]
            strm_start_ts = start
            # let the model handle the model-specific counter increments
            self.traffic_model.increment_traffic_counters(strm_start_ts, byte_events, self.secure_counters)

        # clear all 'traffic' data for this stream
        if strmid in self.strm_bytes:
            self.strm_bytes[strmid].pop(circid, None)
            if len(self.strm_bytes[strmid]) == 0:
                self.strm_bytes.pop(strmid, None)
        return True

    @staticmethod
    def _classify_port(port):
        '''
        Classify port into web, interactive, p2p, or other.
        '''
        p2p_ports = [1214]
        for p in xrange(4661, 4666+1): p2p_ports.append(p)
        for p in xrange(6346, 6429+1): p2p_ports.append(p)
        p2p_ports.append(6699)
        for p in xrange(6881, 6999+1): p2p_ports.append(p)

        if port in [80, 443]:
            return 'web'
        elif port in [22, 194, 994, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6670, 6679, 6697, 7000]:
            return 'interactive'
        elif port in p2p_ports:
            return 'p2p'
        else:
            return 'other'

    @staticmethod
    def _encode_ratio(inval, outval):
        '''
        Calculate the log ratio between inbound and outbound traffic.
        Positive when outval > inval, and negative when inval > outval.
        Returns a non-infinite floating point value:
        - zero when inval and outval are zero,
        - a large negative number (< -100) when outval is zero, and
        - a large positive number (> 100) when inval is zero, and
        - log(base 2)(outval/inval) otherwise.
        '''
        inval = float(inval)
        outval = float(outval)
        if inval == 0.0 and outval == 0.0:
            return 0.0
        elif inval == 0.0:
            return sys.float_info.max_exp
        elif outval == 0.0:
            return sys.float_info.min_exp
        else:
            return math.log(outval/inval, 2)

    @staticmethod
    def _compute_interstream_creation_times(start_times):
        '''
        Sort start_times, and return a list of the differences between each
        pair of times.
        '''
        start_times.sort()
        isc_times = []
        for i in xrange(len(start_times)):
            if i == 0: continue
            isc_times.append(start_times[i] - start_times[i-1])
        return isc_times

    CIRCUIT_ENDED_ITEMS = 12

    # 'PRIVCOUNT_CIRCUIT_ENDED', ChanID, CircID, NCellsIn, NCellsOut, ReadBWExit, WriteBWExit, TimeStart, TimeEnd, PrevIP, PrevIsClient, NextIP, NextIsEdge
    def _handle_circuit_event(self, items):
        assert(len(items) == Aggregator.CIRCUIT_ENDED_ITEMS)

        chanid, circid, ncellsin, ncellsout, readbwexit, writebwexit = [int(v) for v in items[0:6]]
        start, end = float(items[6]), float(items[7])
        previp = items[8]
        prevIsClient = True if int(items[9]) > 0 else False
        nextip = items[10]
        nextIsEdge = True if int(items[11]) > 0 else False

        # we get circuit events on both exits and entries
        # stream bw info is only avail on exits
        if prevIsClient:
            # prev hop is a client, we are entry
            self.secure_counters.increment('EntryCircuitCount', SINGLE_BIN)

            # only count cells ratio on active circuits with legitimate transfers
            is_active = True if ncellsin + ncellsout >= 8 else False
            if is_active:
                self.secure_counters.increment('EntryActiveCircuitCount', SINGLE_BIN)
                self.secure_counters.increment('EntryCircuitInboundCellCount', ncellsin)
                self.secure_counters.increment('EntryCircuitOutboundCellCount', ncellsout)
                self.secure_counters.increment('EntryCircuitCellRatio', Aggregator._encode_ratio(ncellsin, ncellsout))
            else:
                self.secure_counters.increment('EntryInactiveCircuitCount', SINGLE_BIN)

            # count unique client ips
            # we saw this client within current rotation window
            self.cli_ips_current.setdefault(previp, {'is_active':False})
            if is_active:
                self.cli_ips_current[previp]['is_active'] = True
            if start < self.cli_ips_rotated:
                # we also saw the client in the previous rotation window
                self.cli_ips_previous.setdefault(previp, {'is_active':False})
                if is_active:
                    self.cli_ips_previous[previp]['is_active'] = True

            # count number of completed circuits per client
            if is_active:
                if 'num_active_completed' not in self.cli_ips_current[previp]:
                    self.cli_ips_current[previp]['num_active_completed'] = 0
                self.cli_ips_current[previp]['num_active_completed'] += 1
            else:
                if 'num_inactive_completed' not in self.cli_ips_current[previp]:
                    self.cli_ips_current[previp]['num_inactive_completed'] = 0
                self.cli_ips_current[previp]['num_inactive_completed'] += 1

        elif nextIsEdge:
            # prev hop is a relay and next is an edge connection, we are exit
            # don't count single-hop exits
            self.secure_counters.increment('ExitCircuitCount', SINGLE_BIN)
            self.secure_counters.increment('ExitCircuitLifeTime', end - start)

            # check if we have any stream info in this circuit
            circ_is_known, has_completed_stream = False, False
            if chanid in self.circ_info and circid in self.circ_info[chanid]:
                circ_is_known = True
                if sum(self.circ_info[chanid][circid]['num_streams'].values()) > 0:
                    has_completed_stream = True

            if circ_is_known and has_completed_stream:
                # we have circuit info and at least one stream ended on it
                self.secure_counters.increment('ExitActiveCircuitCount', SINGLE_BIN)
                self.secure_counters.increment('ExitActiveCircuitLifeTime', end - start)

                # convenience
                counts = self.circ_info[chanid][circid]['num_streams']
                times = self.circ_info[chanid][circid]['stream_starttimes']

                # first increment general counters
                self.secure_counters.increment('ExitCircuitStreamCount', sum(counts.values()))
                for isct in Aggregator._compute_interstream_creation_times(times['web'] + times['interactive'] + times['p2p'] + times['other']):
                    self.secure_counters.increment('ExitCircuitInterStreamCreationTime', isct)

                # now only increment the classes that have positive counts
                if counts['web'] > 0:
                    self.secure_counters.increment('ExitWebCircuitCount', SINGLE_BIN)
                    self.secure_counters.increment('ExitCircuitWebStreamCount', counts['web'])
                    for isct in Aggregator._compute_interstream_creation_times(times['web']):
                        self.secure_counters.increment('ExitCircuitWebInterStreamCreationTime', isct)
                if counts['interactive'] > 0:
                    self.secure_counters.increment('ExitInteractiveCircuitCount', SINGLE_BIN)
                    self.secure_counters.increment('ExitCircuitInteractiveStreamCount', counts['interactive'])
                    for isct in Aggregator._compute_interstream_creation_times(times['interactive']):
                        self.secure_counters.increment('ExitCircuitInteractiveInterStreamCreationTime', isct)
                if counts['p2p'] > 0:
                    self.secure_counters.increment('ExitP2PCircuitCount', SINGLE_BIN)
                    self.secure_counters.increment('ExitCircuitP2PStreamCount', counts['p2p'])
                    for isct in Aggregator._compute_interstream_creation_times(times['p2p']):
                        self.secure_counters.increment('ExitCircuitP2PInterStreamCreationTime', isct)
                if counts['other'] > 0:
                    self.secure_counters.increment('ExitOtherPortCircuitCount', SINGLE_BIN)
                    self.secure_counters.increment('ExitCircuitOtherPortStreamCount', counts['other'])
                    for isct in Aggregator._compute_interstream_creation_times(times['other']):
                        self.secure_counters.increment('ExitCircuitOtherPortInterStreamCreationTime', isct)

            else:
                # either we dont know circ, or no streams ended on it
                self.secure_counters.increment('ExitInactiveCircuitCount', SINGLE_BIN)
                self.secure_counters.increment('ExitInactiveCircuitLifeTime', end - start)

            # cleanup
            if circ_is_known:
                # remove circ from channel
                self.circ_info[chanid].pop(circid, None)
                # if that was the last circuit on channel, remove the channel too
                if len(self.circ_info[chanid]) == 0:
                    self.circ_info.pop(chanid, None)
        return True

    CONNECTION_ENDED_ITEMS = 5

    # 'PRIVCOUNT_CONNECTION_ENDED', ChanID, TimeStart, TimeEnd, IP, isClient
    def _handle_connection_event(self, items):
        assert(len(items) == Aggregator.CONNECTION_ENDED_ITEMS)

        chanid = int(items[0])
        start, end = float(items[1]), float(items[2])
        ip = items[3]
        isclient = True if int(items[4]) > 0 else False
        if isclient:
            self.secure_counters.increment('EntryConnectionCount', SINGLE_BIN)
            self.secure_counters.increment('EntryConnectionLifeTime', end - start)
        return True

    def _do_rotate(self):
        '''
        This function is called using LoopingCall, so any exceptions will be
        turned into log messages.
        '''
        logging.info("rotating circuit window now, {}".format(format_last_event_time_since(self.last_event_time)))

        # it is safe to count the first rotation, because Tor only sends us
        # events that started inside the collection period
        client_ips_active = 0
        client_ips_inactive = 0

        # cli_ips_previous are the IPs from 2*period to period seconds ago,
        # or are empty for the first rotation
        for ip in self.cli_ips_previous:
            client = self.cli_ips_previous[ip]

            if client['is_active']:
                client_ips_active += 1
            else:
                client_ips_inactive += 1

            if 'num_active_completed' in client:
                self.secure_counters.increment('EntryClientIPActiveCircuitCount', client['num_active_completed'])
            if 'num_inactive_completed' in client:
                self.secure_counters.increment('EntryClientIPInactiveCircuitCount', client['num_inactive_completed'])

        self.secure_counters.increment('EntryClientIPCount', SINGLE_BIN, client_ips_active + client_ips_inactive)
        self.secure_counters.increment('EntryActiveClientIPCount', SINGLE_BIN, client_ips_active)
        self.secure_counters.increment('EntryInactiveClientIPCount', SINGLE_BIN, client_ips_inactive)

        # reset for next interval
        # make cli_ips_previous the IPs from period to 0 seconds ago
        # TODO: secure delete IP addresses
        self.cli_ips_previous = self.cli_ips_current
        self.cli_ips_current = {}
        self.cli_ips_rotated = time()
        self.num_rotations += 1
