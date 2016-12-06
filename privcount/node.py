'''
Created on Dec 6, 2016

@author: teor
'''

import logging

from time import time

from privcount.counter import check_counters_config, check_noise_weight_config, combine_counters, CollectionDelay, float_accuracy, add_counter_limits_to_config
from privcount.log import format_delay_time_until, format_elapsed_time_since
from privcount.statistics_noise import DEFAULT_SIGMA_TOLERANCE
from privcount.util import normalise_path

def get_remaining_rounds(num_phases, continue_config):
        '''
        If the TS is configured to continue collecting a limited number of
        rounds, return the number of rounds. Otherwise, if it will continue
        forever, return None.
        '''
        if num_phases == 0:
            return 1
        if isinstance(continue_config, bool):
            if continue_config:
                return None
            else:
                return 0
        else:
            return continue_config - num_phases

def continue_collecting(num_phases, continue_config):
        '''
        If the TS is configured to continue collecting more rounds,
        return True. Otherwise, return False.
        '''
        if num_phases == 0:
            return True
        if isinstance(continue_config, bool):
            return continue_config
        else:
            return continue_config > num_phases

def log_tally_server_status(status):
    '''
    clients must only use the expected end time for logging: the tally
    server may end the round early, or extend it slightly to allow for
    network round trip times
    '''
    # until the collection round starts, the tally server doesn't know when it
    # is expected to end
    expected_end_msg = ""
    if 'expected_end_time' in status:
        stopping_ts = status['expected_end_time']
        # we're waiting for the collection to stop
        if stopping_ts > time():
            expected_end_msg = ", expect collection to end in {}".format(format_delay_time_until(stopping_ts, 'at'))
        # we expect the collection to have stopped, and the TS should be
        # collecting results
        else:
            expected_end_msg = ", expect collection has ended for {}".format(format_elapsed_time_since(stopping_ts, 'since'))
    logging.info("--server status: PrivCount is {} for {}{}".format(status['state'], format_elapsed_time_since(status['time'], 'since'), expected_end_msg))
    t, r = status['dcs_total'], status['dcs_required']
    a, i = status['dcs_active'], status['dcs_idle']
    logging.info("--server status: DataCollectors: have {}, need {}, {}/{} active, {}/{} idle".format(t, r, a, t, i, t))
    t, r = status['sks_total'], status['sks_required']
    a, i = status['sks_active'], status['sks_idle']
    logging.info("--server status: ShareKeepers: have {}, need {}, {}/{} active, {}/{} idle".format(t, r, a, t, i, t))
    if continue_collecting(status['completed_phases'],
                           status['continue']):
        rem = get_remaining_rounds(status['completed_phases'],
                                   status['continue'])
        if rem is not None:
            continue_str = "continue for {} more rounds".format(rem)
        else:
            continue_str = "continue indefinitely"
        next_start_time = status['delay_until']
        if next_start_time > time():
            next_round_str = " in {}".format(format_delay_time_until(
                                                 next_start_time, 'at'))
        else:
            next_round_str = " as soon as clients are ready"
    else:
        continue_str = "stop"
        next_round_str = " after this collection round"
    logging.info("--server status: Rounds: completed {}, configured to {} collecting{}"
                 .format(status['completed_phases'],
                         continue_str,
                         next_round_str))

class PrivCountNode(object):
    '''
    A mixin class that hosts common functionality for PrivCount client and
    server factories: TallyServer, ShareKeeper, and DataCollector.
    '''

    def __init__(self, config_filepath):
        '''
        Initialise the common data structures used by all PrivCount nodes.
        '''
        self.config_filepath = normalise_path(config_filepath)
        self.config = None
        self.collection_delay = CollectionDelay()

    def load_state(self):
        '''
        Load the state from the saved state file
        Return the loaded state, or None if there is no state file
        '''
        # load any state we may have from a previous run
        state_filepath = normalise_path(self.config['state'])
        if os.path.exists(state_filepath):
            with open(state_filepath, 'r') as fin:
                state = pickle.load(fin)
                return state
        return None

    def dump_state(self, state):
        '''
        Dump the state dictionary to a saved state file.
        If state is none or an empty dictionary, do not write a file.
        '''
        if state is None or len(state.keys()) == 0:
            return
        state_filepath = normalise_path(self.config['state'])
        with open(state_filepath, 'w') as fout:
            pickle.dump(state, fout)

    def get_secret_handshake_path(self):
        '''
        Return the path of the secret handshake key file, or None if the config
        has not been loaded.
        Called by the protocol after a connection is opened.
        '''
        # The config must have been loaded by this point:
        # - the server reads the config before opening a listener port
        # - the clients read the config before opening a connection
        assert self.config
        # The secret handshake path should be loaded (or assigned a default)
        # whenever the config is loaded
        return self.config['secret_handshake']

    @staticmethod
    def get_valid_sigma_decrease_tolerance(conf):
        '''
        Read sigma_decrease_tolerance from conf (if present), and check that
        it is within a valid range.
        Returns the configured sigma tolerance, or the default tolerance.
        Asserts on failure.
        '''
        tolerance = conf.get('sigma_decrease_tolerance',
                             DEFAULT_SIGMA_TOLERANCE)

        # we can't guarantee that floats are transmitted with any more
        # accuracy than approximately 1 part in 1e-14, due to python
        # float to string conversion
        # so we limit the tolerance to an absolute value of ~1e-14,
        # which assumes the sigma values are close to 1.
        # larger sigma values should have a larger absolute limit, because
        # float_accuracy() is a proportion of the value,
        # but we can't do that calculation here
        assert tolerance >= float_accuracy()
        return tolerance

    @staticmethod
    def get_valid_delay_period(delay_period, collect_period):
        '''
        Validate and return the delay period, comparing it with the collect
        period.
        Returns a (potentially modified) valid value.
        Asserts if the collect period is invalid.
        '''
        assert collect_period is not None
        assert collect_period > 0
        if delay_period is None:
            logging.warning("delay_period not specified, using collect_period %d",
                            collect_period)
            return collect_period
        if delay_period < 0:
            logging.warning("delay_period invalidd, using collect_period %d",
                            collect_period)
            return collect_period
        # The delay period must be greater than or equal to the collect
        # period
        delay_min = collect_period
        delay_increase = delay_min - delay_period
        # if we're increasing the delay, log something
        if delay_increase > 0.0:
            # adjust the log level based on the severity of the increase
            # we have to use absolute and relative checks to account for
            # both local test networks and globe-spanning networks
            if (delay_increase < 2.0 and
                delay_increase < collect_period/100.0):
                # probably just network latency
                logging_function = logging.debug
            elif (delay_increase < 60.0 and
                  delay_increase < collect_period/10.0):
                # interesting, but not bad
                logging_function = logging.info
            else:
                logging_function = logging.warning

            logging_function("delay_period %.1f too small for collect_period %.1f, increasing to %.1f",
                            delay_period,
                            collect_period,
                            delay_min)
            return delay_min
        # If it passes all the checks
        return delay_period

class PrivCountServer(PrivCountNode):
    '''
    A mixin class that hosts common functionality for PrivCount server
    factories: TallyServer.
    (Since there is only one server factory class, this class only hosts
    generic functionality that is substantially similar to PrivCountClient,
    but not identical - if it were identical, it would go in PrivCountNode.)
    '''

    def __init__(self, config_filepath):
        '''
        Initialise the common data structures used by all PrivCount clients.
        '''
        PrivCountNode.__init__(self, config_filepath)

    @staticmethod
    def get_valid_sigma_decrease_tolerance(conf):
        '''
        Read sigma_decrease_tolerance from conf (if present), and check that
        it is withing a valid range, taking the noise allocation config into
        account (if present).
        '''
        tolerance = PrivCountNode.get_valid_sigma_decrease_tolerance(conf)

        # it makes no sense to have a sigma decrease tolerance that is
        # less than the sigma calculation tolerance
        # (if we use hard-coded sigmas, calculation accuracy is not
        # an issue - skip this check)
        if 'sigma_tolerance' in conf['noise'].get('privacy',{}):
            assert (tolerance >=
                    conf['noise']['privacy']['sigma_tolerance'])
        elif 'privacy' in conf['noise']:
            assert (tolerance >=
                    DEFAULT_SIGMA_TOLERANCE)
        else:
            # no extra checks
            pass

        return tolerance

class PrivCountClient(PrivCountNode):
    '''
    A mixin class that hosts common functionality for PrivCount client
    factories: ShareKeeper and DataCollector.
    '''

    def __init__(self, config_filepath):
        '''
        Initialise the common data structures used by all PrivCount clients.
        '''
        PrivCountNode.__init__(self, config_filepath)
        self.start_config = None
        # the collect period supplied by the tally server
        self.collect_period = None
        # the delay period after the current collection, if any
        self.delay_period = None
        # the noise config used to start the most recent round
        self.last_noise_config = None
        # the start time of the most recent round
        self.collection_start_time = None

    def set_server_status(self, status):
        '''
        Called by protocol
        status is a dictionary containing server status information
        '''
        log_tally_server_status(status)

    def set_delay_period(self, collect_period):
        '''
        Set the delay period to a valid value, based on the configured
        delay period and the supplied collect period.
        '''
        self.delay_period = \
            self.get_valid_delay_period(self.config.get('delay_period'),
                                        collect_period)

    def set_round_start(self, start_config):
        '''
        Set the round start variables:
         - the delay period after this round,
         - the noise config,
         - the start time,
         based on the start config and loaded config.
        '''
        self.collect_period = start_config['collect_period']
        self.set_delay_period(start_config['collect_period'])
        self.last_noise_config = start_config['noise']
        self.collection_start_time = time()

    def check_start_config(self, start_config):
        '''
        Perform the common client checks on the start config.
        Return the combined counters if the start_config is valid,
        or None if it is not.
        '''
        if ('counters' not in start_config or
            'noise' not in start_config or
            'noise_weight' not in start_config or
            'dc_threshold' not in start_config or
            'collect_period' not in start_config):
            logging.warning("start command from tally server cannot be completed due to missing data")
            return None

        # if the counters don't pass the validity checks, fail
        if not check_counters_config(start_config['counters'],
                                     start_config['noise']['counters']):
            return None

        # if the noise weights don't pass the validity checks, fail
        if not check_noise_weight_config(start_config['noise_weight'],
                                         start_config['dc_threshold']):
            return None

        delay = self.delay_period
        # if it's the first round, there won't be a delay anyway
        if delay is None:
            delay = 0

        # check if we need to delay this round
        if not self.collection_delay.round_start_permitted(
            start_config['noise'],
            time(),
            delay,
            self.config['always_delay'],
            self.config['sigma_decrease_tolerance']):
            # we can't start the round yet
            return None

        # save various config items for the end of the round
        self.set_round_start(start_config)

        # combine bins and sigmas
        return combine_counters(start_config['counters'],
                                start_config['noise']['counters'])

    def check_stop_config(self, stop_config, counts):
        '''
        When the round stops, perform common client actions:
        - log a message
        - tell the collection_delay
        '''
        end_time = time()
        response = {}
        round_successful = False

        wants_counters = stop_config.get('send_counters', False)
        logging.info("tally server {} final counts"
                     .format("wants" if wants_counters else "does not want"))

        if wants_counters and counts is not None:
            logging.info("sending counts from {} counters".format(len(counts)))
            response['Counts'] = counts
            # only delay a round if we have sent our counters
            round_successful = True
        else:
            logging.info("No counts available")

        # even though the counter limits are hard-coded, include them anyway
        response['Config'] = add_counter_limits_to_config(self.config)

        # and include the config sent by the tally server in do_start
        if self.start_config is not None:
            response['Config']['Start'] = self.start_config

        # and include the config sent by the tally server to stop
        if stop_config is not None:
            response['Config']['Stop'] = stop_config

        # if we never started, there's no point in registering end of round
        if (self.collect_period is None or
            self.delay_period is None or
            self.last_noise_config is None or
            self.collection_start_time is None):
            logging.warning("TS sent stop command before start command")
            return response

        # We use the collect_period if the delay_period is not configured.
        # But using the collect_period from the tally server is insecure,
        # because the DCs and SKs do not check that the actual collection time
        # matches the collection period
        config_delay = self.config.get('delay_period')
        actual_collect = end_time - self.collection_start_time
        actual_delay = self.get_valid_delay_period(config_delay,
                                                   actual_collect)

        # so we use the maximum of the delay period from:
        # - the TS collect period and the config at start time, and
        # - the actual collect period and the current config.
        delay = max(self.delay_period, actual_delay)

        # add this info to the context
        response['Config']['Time'] = {}
        response['Config']['Time']['Start'] = self.collection_start_time
        response['Config']['Time']['Stop'] = end_time
        response['Config']['Time']['Delay'] = actual_delay

        # Register the stop with the collection delay
        self.collection_delay.set_stop_result(
            round_successful,
            # set when the round started
            self.last_noise_config,
            self.collection_start_time,
            end_time,
            delay,
            self.config['always_delay'],
            self.config['sigma_decrease_tolerance'])

        logging.info("collection phase was stopped")

        return response
