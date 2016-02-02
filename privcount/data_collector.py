'''
Created on Dec 12, 2015

@author: rob
'''
import logging
import time
import json

from threading import Thread
from Queue import Queue
from copy import deepcopy

from twisted.internet import reactor, task, ssl

from util import MessageReceiverFactory, MessageSenderFactory, CounterStore, get_valid_config, wait_epoch_change, get_epoch_info

class DataAggregator(Thread):
    '''
    receive data from Tor via the message receiver
    parse the contents for valid events and stats
    aggregate stats during collection epoch
    add noise to aggregated stats at end of epoch
    send results to TKS nodes
    '''

    def __init__(self, input_queue):
        super(DataAggregator, self).__init__()
        assert input_queue
        self.input_queue = input_queue
        self.stats = None
        self.counter = None
        self.last_event_time = 0

        self.n_streams_per_circ = {}
        self.num_rotations = 0
        self.cli_ips_rotated = time.time()
        self.cli_ips_current = {}
        self.cli_ips_previous = {}

    def run(self):
        keep_running = True
        while keep_running:
            (event, items) = self.input_queue.get()

            if event == 'message':
                self._handle_message_event(items)

            elif event == 'register':
                self._handle_register_event(items)

            elif event == 'rotate':
                self._handle_rotate_event(items)

            elif event == 'publish':
                self._handle_publish_event(items)

            elif event == 'stop':
                keep_running = False

            self.input_queue.task_done()

    def _handle_message_event(self, items):
        msg, host = items[0], items[1]
        event, line_remaining = [v.strip() for v in msg.split(' ', 1)]
        logging.debug("collected new event '%s' from %s", event, host)
        self.last_event_time = time.time()

        # hand valid events off to the aggregator
        if event == 's':
            # 's', ChanID, CircID, StreamID, ExitPort, ReadBW, WriteBW, TimeStart, TimeEnd, isDNS, isDir
            items = [v.strip() for v in line_remaining.split(' ', 10)]
            if len(items) == 10:
                self._handle_stream_event(items[0:10])

        elif event == 'c':
            # 'c', ChanID, CircID, nCellsIn, nCellsOut, ReadBWDNS, WriteBWDNS, ReadBWExit, WriteBWExit, TimeStart, TimeEnd, PrevIP, prevIsClient, prevIsRelay, NextIP, nextIsClient, nextIsRelay
            items = [v.strip() for v in line_remaining.split(' ', 16)]
            if len(items) == 16:
                self._handle_circuit_event(items[0:16])

        elif event == 't':
            # 't', ChanID, TimeStart, TimeEnd, IP, isClient, isRelay
            items = [v.strip() for v in line_remaining.split(' ', 6)]
            if len(items) == 6:
                self._handle_connection_event(items[0:6])

    def _handle_stream_event(self, items):
        chanid, circid, strmid, port, readbw, writebw = [int(v) for v in items[0:6]]
        start, end = float(items[6]), float(items[7])
        is_dns = True if int(items[8]) == 1 else False
        is_dir = True if int(items[9]) == 1 else False

        self._increment_matching_labels("Streams_Count", 1)

        stream_class = self.classify_port(port)
        self.n_streams_per_circ.setdefault(chanid, {}).setdefault(circid, {'interactive':0, 'web':0, 'p2p':0, 'other':0})
        self.n_streams_per_circ[chanid][circid][stream_class] += 1

        # only count bytes ratio on streams with legitimate transfers
        ratio = float(writebw)/float(readbw) if readbw > 0 and writebw > 0 else 0.0

        if stream_class == 'web':
            self._increment_matching_labels("WebStreamLifeTime", end-start)
            self._increment_matching_labels("BytesSentPerWebStream", writebw)
            self._increment_matching_labels("BytesReceivedPerWebStream", readbw)
            if ratio > 0.0:
                self._increment_matching_labels("BytesSentReceivedRatioPerWebStream", ratio)
        elif stream_class == 'interactive':
            self._increment_matching_labels("InteractiveStreamLifeTime", end-start)
            self._increment_matching_labels("BytesSentPerInteractiveStream", writebw)
            self._increment_matching_labels("BytesReceivedPerInteractiveStream", readbw)
            if ratio > 0.0:
                self._increment_matching_labels("BytesSentReceivedRatioPerInteractiveStream", ratio)
        elif stream_class == 'p2p':
            self._increment_matching_labels("P2PStreamLifeTime", end-start)
            self._increment_matching_labels("BytesSentPerP2PStream", writebw)
            self._increment_matching_labels("BytesReceivedPerP2PStream", readbw)
            if ratio > 0.0:
                self._increment_matching_labels("BytesSentReceivedRatioPerP2PStream", ratio)
        elif stream_class == 'other':
            self._increment_matching_labels("OtherStreamLifeTime", end-start)
            self._increment_matching_labels("BytesSentPerOtherStream", writebw)
            self._increment_matching_labels("BytesReceivedPerOtherStream", readbw)
            if ratio > 0.0:
                self._increment_matching_labels("BytesSentReceivedRatioPerOtherStream", ratio)

    def classify_port(self, port):
        if port == 22 or (port >= 6660 and port <= 6669) or port == 6697 or port == 7000:
            return 'interactive'
        elif port == 80 or port == 443:
            return 'web'
        elif (port >= 6881 and port <= 6889) or port == 6969 or port >= 10000:
            return 'p2p'
        else:
            return 'other'

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
            self._increment_matching_labels("CircuitLifeTime", end - start)

            # only count cells ratio on active circuits with legitimate transfers
            active_key = 'active' if ncellsin + ncellsout >= 8 else 'inactive'
            if active_key == 'active':
                self._increment_matching_labels("CellsInPerCircuit", ncellsin)
                self._increment_matching_labels("CellsOutPerCircuit", ncellsout)
                if ncellsin > 0 and ncellsout > 0:
                    self._increment_matching_labels("CellsInOutRatioPerCircuit", float(ncellsin)/float(ncellsout))

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
                counts = self.n_streams_per_circ[chanid][circid]
                self._increment_matching_labels("Circuits_Count", 1)
                self._increment_matching_labels("WebStreamsPerCircuit", counts['web'])
                self._increment_matching_labels("InteractiveStreamsPerCircuit", counts['interactive'])
                self._increment_matching_labels("P2PStreamsPerCircuit_", counts['p2p'])
                self._increment_matching_labels("OtherStreamsPerCircuit", counts['other'])
            else:
                # we dont know circ or no streams ended on it
                self._increment_matching_labels("InactiveCircuits_Count", 1)

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
            self._increment_matching_labels("Connections_Count", 1)

    def _handle_rotate_event(self, items):
        logging.info("rotating circuit window now, last event received from Tor was %s seconds ago", str(time.time() - self.last_event_time))

        # dont count anything in the first rotation period, since events that ended up in the
        # previous list will be skewed torward longer lived circuits
        if self.num_rotations > 0:
            self._increment_matching_labels("UniqueClientIPs", len(self.cli_ips_previous))
            for ip in self.cli_ips_previous:
                self._increment_matching_labels("CircuitsPerClientIP", self.cli_ips_previous[ip]['active'])
                self._increment_matching_labels("InactiveCircuitsPerClientIP", self.cli_ips_previous[ip]['inactive'])

        # reset for next interval
        self.cli_ips_previous = self.cli_ips_current
        self.cli_ips_current = {}
        self.cli_ips_rotated = time.time()
        self.num_rotations += 1

    def _handle_register_event(self, items):
        conf = items
        # make sure the other servers are up, which they will be by the end of the clock_skew period
        logging.info("delaying epoch registration by %d seconds", conf['global']['clock_skew'])
        time.sleep(conf['global']['clock_skew'])

        dconf = conf['data_collector']
        tks_infos = dconf['tally_key_server_infos']

        prime_q = conf['global']['q']
        num_tkses = len(tks_infos)
        noise_weight = dconf['noise_weight']

        if self.stats is not None:
            del self.stats
            self.stats = None
        if self.counter is not None:
            del self.counter
            self.counter = None

        self.stats = self._get_all_counter_labels(dconf['statistics'])
        self.counter = CounterStore(prime_q, num_tkses, noise_weight, self.stats)

        logging.info("enabling stats counters for labels: %s", str(sorted(self.stats.keys())))

        for key, tks_info in zip(self.counter.keys, tks_infos):
            msg = repr(self.counter.get_blinding_factor(key))
            # TODO: Encrypt msg to TKS here
            sender_factory = MessageSenderFactory(msg)

            tks_ip, tks_port = tks_info['ip'], tks_info['port']
            # pylint: disable=E1101
            reactor.connectSSL(tks_ip, tks_port, sender_factory, ssl.ClientContextFactory())
            logging.info("registered with TKS at %s:%d", tks_ip, tks_port)

    def _handle_publish_event(self, items):
        ts_ip, ts_port = items

        msg = json.dumps(self.counter.get_blinded_noisy_counts())
        server_factory = MessageSenderFactory(msg)

        # pylint: disable=E1101
        reactor.connectSSL(ts_ip, ts_port, server_factory, ssl.ClientContextFactory())
        logging.info("sent stats to TS at %s:%d", ts_ip, ts_port)

    def _get_all_counter_labels(self, stats_list):
        labels = {}
        for stat in stats_list:
            if 'Histogram' in stat['type']:
                bins = [float(i.strip()) for i in stat['bins'].split(',')]
                if len(bins) == 1:
                    # we only have one key to add
                    stat_type = "{0}_{1}_+".format(stat['type'], bins[0])
                    labels[stat_type] = stat['sigma']
                elif len(bins) > 1:
                    for i in xrange(len(bins)-1): # first add all but the last
                        stat_type = "{0}_{1}_{2}".format(stat['type'], bins[i], bins[i+1])
                        labels[stat_type] = stat['sigma']
                    # now add the last
                    stat_type = "{0}_{1}_+".format(stat['type'], bins[-1])
                    labels[stat_type] = stat['sigma']
            else:
                labels[stat['type']] = stat['sigma']
        return labels

    def _get_matching_labels(self, prefix):
        matches = []
        for label in sorted(self.stats.keys()):
            if label.startswith(prefix):
                matches.append(label)
        return matches

    def _increment_matching_labels(self, key, val):
        labels = self._get_matching_labels(key)
        for label in labels:
            parts = label.split('_')
            if len(parts) < 4:
                # single counter, eg Circuits_Count
                self.counter.increment(label)
            else:
                # histogram counter, eg StreamsPerCircuit_Histogram_0_2 or StreamsPerCircuit_Histogram_2_+
                if val >= float(parts[2]) and (parts[3] == '+' or val < float(parts[3])):
                    self.counter.increment(label)

class DataCollectorManager(object):
    '''
    run a data collector to gather and aggregate data from Tor, add noise,
    and send it off to the PrivCount tally key servers
    '''

    def __init__(self, config_filepath):
        self.config_filepath = config_filepath
        self.config = None
        self.last_epoch = 0
        self.data_aggregator = None
        self.cmd_queue = None

    def run(self):
        self._refresh_config()
        if self.config is None:
            logging.critical("cannot start due to error in config file")
            return

        # sync on configured epoch
        wait_epoch_change(self.config['global']['start_time'], self.config['global']['epoch'])
        self.last_epoch, _, _ = get_epoch_info(self.config['global']['start_time'], self.config['global']['epoch'])
        self._wait_start_delay()

        logging.info("initializing server components...")

        # start the stats keeper thread
        self.cmd_queue = Queue()
        self.data_aggregator = DataAggregator(self.cmd_queue)
        self.data_aggregator.start()

        # register with TKSes
        self._send_register_command()

        # check for epoch change every second
        task.LoopingCall(self._trigger_epoch_check).start(1)

        # rotate IP counter every 10 minutes
        task.LoopingCall(self._send_rotate_command, now=False).start(600)

        # set up our tcp server for receiving data from Tor on localhost only
        listen_port = self.config['data_collector']['listen_port']
        server_factory = MessageReceiverFactory(self.cmd_queue)
        # pylint: disable=E1101
        reactor.listenTCP(listen_port, server_factory, interface='127.0.0.1')

        try:
            logging.info("setup complete; passing control to twisted event loop")
            reactor.run()
        except KeyboardInterrupt:
            logging.info("interrupt received, please wait for graceful shutdown")
        finally:
            self.cmd_queue.put(('stop', []))
            self.cmd_queue.join()
            self.data_aggregator.join()

    def _wait_start_delay(self):
        seconds = self.config['global']['clock_skew']
        logging.info("delaying start by %d seconds", seconds)
        time.sleep(seconds)

    def _send_publish_command(self):
        # set up a publish event to send stats to the TS
        ts_ip = self.config['data_collector']['tally_server_info']['ip']
        ts_port = self.config['data_collector']['tally_server_info']['port']
        self.cmd_queue.put(('publish', [ts_ip, ts_port]))

    def _send_register_command(self):
        # setup event to register with the TKSes in the new round
        self.cmd_queue.put(('register', deepcopy(self.config)))

    def _send_rotate_command(self):
        # setup event to register with the TKSes in the new round
        self.cmd_queue.put(('rotate', None))

    def _refresh_config(self):
        # re-read config and process any changes
        new_config = get_valid_config(self.config_filepath, dc=True)
        if new_config is not None:
            # NOTE this wont apply listen_port or key/cert changes
            self.config = new_config
            logging.info("parsed config successfully!")
            logging.info("using config = %s", str(self.config))

    def _trigger_epoch_check(self):
        epoch_num, ts_epoch_start, ts_epoch_end = get_epoch_info(self.config['global']['start_time'], self.config['global']['epoch'])

        if epoch_num > self.last_epoch:
            logging.info("the epoch from %d to %d just ended", ts_epoch_start, ts_epoch_end)
            self.last_epoch = epoch_num
            self._send_publish_command()
            self._refresh_config()
            self._send_register_command()
