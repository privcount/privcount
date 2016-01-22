'''
Created on Dec 12, 2015

@author: rob
'''
import json
import logging

from threading import Thread
from Queue import Queue

from twisted.internet import reactor, task, ssl

from util import MessageReceiverFactory, get_valid_config, write_results, wait_epoch_change, get_epoch_info

class StatsKeeper(Thread):
    '''
    receive blinded stats from the DCs
    receive key shares from the TKSes
    sum counters at end of epoch
    publish the final results to a file
    '''

    def __init__(self, input_queue):
        super(StatsKeeper, self).__init__()
        assert input_queue
        self.input_queue = input_queue
        self.stats = []

    def run(self):
        keep_running = True
        while keep_running:
            (event, items) = self.input_queue.get()

            if event == 'message':
                self._handle_message_event(items)

            elif event == 'publish':
                self._handle_publish_event(items)

            elif event == 'stop':
                keep_running = False

            self.input_queue.task_done()

    def _handle_message_event(self, items):
        logging.debug("collected new stats event")
        msg, host = items[0], items[1]
        stats = json.loads(msg)
        logging.info("received counter values from DC/TKS on host %s", host)
        self.stats.append(stats)

    def _handle_publish_event(self, items):
        prime_q, ts_start, ts_end, filename = items[0:4]

        if len(self.stats) > 0:
            totals = self._sum_stats(prime_q)
            write_results(filename, ts_start, ts_end, totals)
            del totals
            totals = {}
            del self.stats
            self.stats = []
        else:
            write_results(filename, ts_start, ts_end, None)

        logging.info("published results for epoch from %d to %d to file '%s'", ts_start, ts_end, filename)

    def _sum_stats(self, prime_q):
        totals = {}

        for k in self.stats[0]:
            for data in self.stats:
                totals[k] = (totals.get(k, 0) + data.get(k, 0)) % prime_q
            if totals[k] <= prime_q/2:
                totals[k] = totals[k]
            else:
                totals[k] = (totals[k]-prime_q)

        return totals

class TallyServerManager(object):
    '''
    run a tally server to receive and sum data from the tally key servers and write results to disk
    '''

    def __init__(self, config_filepath):
        self.config_filepath = config_filepath
        self.config = None
        self.last_epoch = 0
        self.stats_keeper = None
        self.cmd_queue = None

    def run(self):
        self._refresh_config()
        if self.config is None:
            logging.critical("cannot start due to error in config file")
            return

        # sync on configured epoch
        wait_epoch_change(self.config['global']['start_time'], self.config['global']['epoch'])
        self.last_epoch, _, _ = get_epoch_info(self.config['global']['start_time'], self.config['global']['epoch'])

        logging.info("initializing server components...")

        # start the stats keeper thread
        self.cmd_queue = Queue()
        self.stats_keeper = StatsKeeper(self.cmd_queue)
        self.stats_keeper.start()

        # check for epoch change every second
        task.LoopingCall(self._trigger_epoch_check).start(1)

        # setup server for receiving data from the DC nodes and key shares from the TKS nodes
        listen_port = self.config['tally_server']['listen_port']
        server_factory = MessageReceiverFactory(self.cmd_queue)
        key_path = self.config['tally_server']['key']
        cert_path = self.config['tally_server']['cert']
        ssl_context = ssl.DefaultOpenSSLContextFactory(key_path, cert_path)

        # pylint: disable=E1101
        reactor.listenSSL(listen_port, server_factory, ssl_context)

        try:
            logging.info("setup complete; passing control to twisted event loop")
            reactor.run()
        except KeyboardInterrupt:
            logging.info("interrupt received, please wait for graceful shutdown")
        finally:
            self.cmd_queue.put(('stop', []))
            self.cmd_queue.join()
            self.stats_keeper.join()

    def _schedule_publish_command(self, ts_start, ts_end):
        # set up a publish event
        prime_q = self.config['global']['q']
        results_path = self.config['tally_server']['results']

        items = [prime_q, ts_start, ts_end, results_path]

        delay_seconds = self.config['global']['clock_skew']
        reactor.callLater(delay_seconds, self._send_publish_command, items) # pylint: disable=E1101

    def _refresh_config(self):
        # re-read config and process any changes
        new_config = get_valid_config(self.config_filepath, ts=True)
        if new_config is not None:
            # NOTE this wont apply listen_port or key/cert changes
            self.config = new_config
            logging.info("using config = %s", str(self.config))

    def _trigger_epoch_check(self):
        epoch_num, ts_epoch_start, ts_epoch_end = get_epoch_info(self.config['global']['start_time'], self.config['global']['epoch'])

        if epoch_num > self.last_epoch:
            logging.info("the epoch from %d to %d just ended", ts_epoch_start, ts_epoch_end)
            self.last_epoch = epoch_num
            self._schedule_publish_command(ts_epoch_start, ts_epoch_end)
            self._refresh_config()

    def _send_publish_command(self, items):
        self.cmd_queue.put(('publish', items))
