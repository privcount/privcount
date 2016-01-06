'''
Created on Dec 12, 2015

@author: rob
'''
import ast
import json
import logging

from threading import Thread
from Queue import Queue

from twisted.internet import reactor, task, ssl

from util import MessageReceiverFactory, MessageSenderFactory, KeyStore, get_valid_config, wait_epoch_change, get_epoch_info

class KeyShareKeeper(Thread):
    '''
    receive key share data from the DC message receiver
    keep the shares during collection epoch
    send the shares to the TS at end of epoch
    '''

    def __init__(self, input_queue, prime_q):
        super(KeyShareKeeper, self).__init__()
        assert input_queue
        self.input_queue = input_queue
        self.keystore = KeyStore(prime_q)

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
        msg, host = items[0], items[1]
        logging.info("received key share from DC on host %s", host)

        # TODO: decrypt msg from DC here
        labels, (kid, K), q = ast.literal_eval(msg)
        self.keystore.register_keyshare(labels, kid, K, q)

    def _handle_publish_event(self, items):
        ts_ip, ts_port, prime_q = items
        msg = json.dumps(self.keystore.get_combined_shares())
        reactor.connectSSL(ts_ip, ts_port, MessageSenderFactory(msg), ssl.ClientContextFactory()) # pylint: disable=E1101

        del self.keystore
        self.keystore = KeyStore(prime_q)

class TallyKeyServerManager(object):

    def __init__(self, config_filepath):
        self.config_filepath = config_filepath
        self.config = None
        self.last_epoch = 0
        self.share_keeper = None
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

        prime_q = self.config['global']['q']

        # start the stats keeper thread
        self.cmd_queue = Queue()
        self.share_keeper = KeyShareKeeper(self.cmd_queue, prime_q)
        self.share_keeper.start()

        # check for epoch change every second
        task.LoopingCall(self._trigger_epoch_check).start(1)

        # set up our tcp server for receiving data from the DC nodes
        listen_port = self.config['tally_key_server']['listen_port']
        server_factory = MessageReceiverFactory(self.cmd_queue)
        key_path = self.config['tally_key_server']['key']
        cert_path = self.config['tally_key_server']['cert']
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
            self.share_keeper.join()

    def _send_publish_command(self):
        # set up a publish event
        ts_ip = self.config['tally_key_server']['tally_server_info']['ip']
        ts_port = self.config['tally_key_server']['tally_server_info']['port']
        prime_q = self.config['global']['q']
        self.cmd_queue.put(('publish', [ts_ip, ts_port, prime_q]))

    def _refresh_config(self):
        # re-read config and process any changes
        new_config = get_valid_config(self.config_filepath, tks=True)
        if new_config is not None:
            # NOTE this wont apply listen_port or key/cert changes
            self.config = new_config
            logging.info("using config = %s", str(self.config))

    def _trigger_epoch_check(self):
        epoch_num, ts_epoch_start, ts_epoch_end = get_epoch_info(self.config['global']['start_time'], self.config['global']['epoch'])

        if epoch_num > self.last_epoch:
            logging.info("the epoch from %d to %d just ended", ts_epoch_start, ts_epoch_end)
            self.last_epoch = epoch_num
            self._send_publish_command()
            self._refresh_config()
