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

from util import MessageReceiverFactory, MessageSenderFactory, CounterStore, get_valid_config, get_noise_weight

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
        self.ext_circs = {}
        self.cli_conns = {}

    def run(self):
        keep_running = True
        while keep_running:
            (event, items) = self.input_queue.get()

            if event == 'message':
                self._handle_message_event(items)

            elif event == 'register':
                self._handle_register_event(items)

            elif event == 'publish':
                self._handle_publish_event(items)

            elif event == 'stop':
                keep_running = False

            self.input_queue.task_done()

    def _handle_message_event(self, items):
        msg, host = items[0], items[1]
        event, line_remaining = [v.strip() for v in msg.split(' ', 1)]
        logging.info("collected new event '%s' from %s", event, host)

        # hand valid events off to the aggregator
        if event == 's':
            # 's', ChanID, CircID, StreamID, ExitPort, ReadBW, WriteBW, TimeStart, TimeEnd
            items = [v.strip() for v in line_remaining.split(' ', 8)]
            if len(items) == 8:
                self._handle_stream_event(items[0:8])

        elif event == 'c':
            # 'c', ChanID, CircID, ReadBW, WriteBW, TimeStart, TimeEnd, ClientIP
            items = [v.strip('\n') for v in line_remaining.split(' ', 7)]
            if len(items) == 7:
                self._handle_circuit_event(items[0:7])

    def _handle_stream_event(self, items):
        chanid, circid, strmid, port, readbw, writebw = [int(v) for v in items[0:6]]
        start, end = float(items[6]), float(items[7])

        self._increment_matching_labels("BytesReceivedPerStream", readbw)
        self._increment_matching_labels("BytesSentPerStream", writebw)
        self._increment_matching_labels("StreamLifeTime", end - start)

        self.ext_circs.setdefault(circid, {"strm_count":0, "strm_create":[]})
        self.ext_circs[circid]["strm_count"] += 1
        self.ext_circs[circid]["strm_create"].append(start)

        # TODO classify port

    def _finish_exit_circuit(self, circid):
        strm_count = 0
        if circid in self.ext_circs:
            strm_count = self.ext_circs[circid]["strm_count"]
            self._increment_matching_labels("StreamsPerCircuit", strm_count)

            strm_create = sorted(self.ext_circs[circid]["strm_create"])
            for i in xrange(0, len(strm_create)-1):
                time_between_creates = strm_create[i+1] - strm_create[i]
                self._increment_matching_labels("StreamIntercreationTime", time_between_creates)

        if strm_count > 0:
            self._increment_matching_labels("Circuits_Count", 1)
        else:
            self._increment_matching_labels("InactiveCircuits_Count", 1)

        if circid in self.ext_circs:
            self.ext_circs.pop(circid, None)

    def _handle_circuit_event(self, items):
        chanid, circid, readbw, writebw = [int(v) for v in items[0:4]]
        start, end = float(items[4]), float(items[5])
        clientip = items[6] # TODO probabilistic counter

        if False: # TODO our Tor needs to change to emit circuits on exits
            self._finish_exit_circuit(circid)
            return

        # this is a circuit on an OR conn to client
        self._increment_matching_labels("BytesReceivedPerCircuit", readbw)
        self._increment_matching_labels("BytesSentPerCircuit", writebw)

        self.cli_conns.setdefault(chanid, {"circ_count_active":0, "circ_count_inactive":0})
        if readbw + writebw > 4096:
            self.cli_conns[chanid]['circ_count_active'] += 1
        else:
            self.cli_conns[chanid]['circ_count_inactive'] += 1

    def _finish_client_connection(self, chanid):
        if chanid in self.cli_conns:
            self._increment_matching_labels("Connections_Count", 1)

            active_count = self.cli_conns[chanid]['circ_count_active']
            self._increment_matching_labels("CircuitsPerConnection", active_count)

            inactive_count = self.cli_conns[chanid]['circ_count_inactive']
            self._increment_matching_labels("InactiveCircuitsPerConnection", inactive_count)

            self.cli_conns.pop(chanid, None)

    def _handle_register_event(self, items):
        conf = items
        dconf = conf['data_collector']

        logging.info("delaying epoch registration by %d seconds", dconf['register_delay'])
        time.sleep(dconf['register_delay'])

        tks_infos = dconf['tally_key_server_infos']

        prime_q = conf['global']['q']
        num_tkses = len(tks_infos)
        noise_weight = get_noise_weight(dconf['diversity_weight'], dconf['consensus'], dconf['fingerprint'], dconf['colocated_fingerprints'])

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

        for circid in sorted(self.ext_circs.keys()): # avoid iteration error by using list of keys
            self._finish_exit_circuit(circid)

        for chanid in sorted(self.cli_conns.keys()): # avoid iteration error by using list of keys
            self._finish_client_connection(chanid)

        msg = json.dumps(self.counter.get_blinded_noisy_counts())
        server_factory = MessageSenderFactory(msg)

        # pylint: disable=E1101
        reactor.connectSSL(ts_ip, ts_port, server_factory, ssl.ClientContextFactory())
        logging.info("sent stats to TS at %s:%d", ts_ip, ts_port)

    def _get_all_counter_labels(self, stats_list):
        labels = {}
        for stat in stats_list:
            if 'Histogram' in stat['type']:
                bins = [int(i.strip()) for i in stat['bins'].split(',')]
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
                if val >= int(parts[2]) and (parts[3] == '+' or val < int(parts[3])):
                    self.counter.increment(label)

class DataCollectorManager(object):
    '''
    run a data collector to gather and aggregate data from Tor, add noise,
    and send it off to the privex tally key servers
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
        self._wait_epoch_change()
        self.last_epoch = int(time.time()) / self.config['global']['epoch']
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

    def _wait_epoch_change(self):
        epoch = self.config['global']['epoch']
        seconds = epoch - int(time.time()) % epoch
        logging.info("waiting for %d seconds until the start of the next epoch...", seconds)
        time.sleep(seconds)

    def _wait_start_delay(self):
        seconds = self.config['data_collector']['start_delay']
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

    def _refresh_config(self):
        # re-read config and process any changes
        new_config = get_valid_config(self.config_filepath, dc=True)
        if new_config is not None:
            # NOTE this wont apply listen_port or key/cert changes
            self.config = new_config
            logging.info("parsed config successfully!")
            logging.info("using config = %s", str(self.config))

    def _trigger_epoch_check(self):
        epoch_period = self.config['global']['epoch']
        this_epoch = int(time.time()) / epoch_period

        if this_epoch > self.last_epoch:
            self.last_epoch = this_epoch
            ts_end = this_epoch * epoch_period
            ts_start = ts_end - epoch_period
            logging.info("the epoch from %d to %d just ended", ts_start, ts_end)

            self._send_publish_command()
            self._refresh_config()
            self._send_register_command()
