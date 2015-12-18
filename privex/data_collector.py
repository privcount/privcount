'''
Created on Dec 12, 2015

@author: rob
'''
import os
import logging
import time
import json

from threading import Thread
from Queue import Queue

from twisted.internet import reactor, task, ssl

from util import MessageReceiverFactory, MessageSenderFactory, get_valid_config, CounterStore

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
        self.labels = ["StreamsPerCircuit"]
        self.counter = None
        self.ext_strms = {}
        self.cli_circs = {}

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

        dat = {'port':port, 'readbw':readbw, 'writebw':writebw, 'start':start, 'end':end}
        self.ext_strms.setdefault(chanid, {}).setdefault(circid, {}).setdefault(strmid, dat)

    def _handle_circuit_event(self, items):
        chanid, circid, readbw, writebw = [int(v) for v in items[0:4]]
        start, end = float(items[4]), float(items[5])
        clientip = items[6]

        dat = {'readbw':readbw, 'writebw':writebw, 'start':start, 'end':end}
        self.cli_circs.setdefault(chanid, {}).setdefault(circid, dat)

    def _handle_register_event(self, items):
        register_delay, tks_infos, prime_q, resolution, sigma, fingerprint_hex, consensus_path, relay_fingerprints = items
        logging.info("delaying epoch registration by %d seconds", register_delay)
        time.sleep(register_delay)

        if self.counter is not None:
            del self.counter
            self.counter = None

        self.counter = CounterStore(prime_q, resolution, sigma, self.labels, len(tks_infos), fingerprint_hex, consensus_path, relay_fingerprints)

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

        count = self._count_streams_per_circuit()
        logging.info("StreamsPerCircuit_Max = %d", count)
        for _ in xrange(count):
            self.counter.increment("StreamsPerCircuit")

        msg = json.dumps(self.counter.get_blinded_noisy_counts())
        server_factory = MessageSenderFactory(msg)

        # pylint: disable=E1101
        reactor.connectSSL(ts_ip, ts_port, server_factory, ssl.ClientContextFactory())
        logging.info("sent stats to TS at %s:%d", ts_ip, ts_port)

    def _count_streams_per_circuit(self):
        data = self.ext_strms
        counts = []
        for chanid in data:
            for circid in data[chanid]:
                n_streams = len(data[chanid][circid])
                counts.append(n_streams)
        return max(counts) if len(counts) > 0 else 0

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

        # check for epoch change every second
        task.LoopingCall(self._trigger_epoch_check).start(1)

        # register with TKSes
        self._send_register_command()

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
        reg_delay = self.config['data_collector']['register_delay']
        fp_hex = self.config['data_collector']['fingerprint']
        cons_path = self.config['data_collector']['consensus']
        prime_q = self.config['global']['q']
        resolution = self.config['global']['resolution']
        sigma = self.config['global']['sigma']
        tks_infos = self.config['data_collector']['tally_key_server_infos']
        relay_fingerprints = sigma = self.config['global']['relay_fingerprints']
        items = [reg_delay, tks_infos, prime_q, resolution, sigma, fp_hex, cons_path, relay_fingerprints]
        self.cmd_queue.put(('register', items))

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
