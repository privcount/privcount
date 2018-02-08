'''
Created on Dec 6, 2016

@author: teor

See LICENSE for licensing information
'''

import logging
import sys

from random import SystemRandom
from copy import deepcopy
from math import sqrt, isnan

from privcount.config import _extra_keys, _common_keys
from privcount.log import format_period, format_elapsed_time_since, format_delay_time_until, summarise_list

DEFAULT_SIGMA_TOLERANCE = 1e-6
DEFAULT_EPSILON_TOLERANCE = 1e-15
DEFAULT_SIGMA_RATIO_TOLERANCE = 1e-6

DEFAULT_DUMMY_COUNTER_NAME = 'ZeroCount'
# The label used for the default noise weight for testing
# Labels are typically data collector relay fingerprints
DEFAULT_NOISE_WEIGHT_NAME = '*'

def counter_modulus():
    '''
    The hard-coded modulus value for a blinded counter
    Blinded counters are unsigned
    In PrivCount, this does not have to be prime, and there is no need for it
    to be configurable
    All PrivCount counters should use unlimited-length Python longs, so that
    counter_modulus can exceed 64 bits, the size of a native C long
    '''
    # PrivCount counters are limited by the modulus, so it needs to be large
    # Here's an over-estimate of PrivCount's capacity:
    # In 2016, Tor traffic was 75 Gbits, or ~2**34 bytes per second
    # (In 2015, Internet traffic was 230 Tbits, or ~2**43 bytes per second)
    # Tor traffic might grow by 2**10 while PrivCount is in use
    # A year has ~2**25 seconds
    # PrivCount counters overflow at modulus/2
    # 2**34 * 2**10 * 2**25 * 2 = 2**70
    # Using modulus > 2**64 also ensures PrivCount is unlimited-integer clean
    # and that it can handle longs that just happen to be integers
    # (1 in 2**6 blinding factors are less than 2**64)
    return 2L**70L
    # historical q values
    #return 2147483647L
    #return 999999999959L
    # modulus was limited to 2**64 when sample() only unpacked 8 bytes
    #return 2L**64L

def min_blinded_counter_value():
    '''
    The hard-coded minimum value for a blinded counter
    Blinded counters are unsigned
    Always zero
    '''
    return 0L

def max_blinded_counter_value():
    '''
    The hard-coded maximum value for a blinded counter
    Blinded counters are unsigned
    '''
    return counter_modulus() - 1L

def min_tally_counter_value():
    '''
    The hard-coded minimum value for a tallied counter
    Tallied counters are signed, to allow for negative noise
    '''
    return adjust_count_signed((counter_modulus() + 1L)//2L,
                               counter_modulus())

def max_tally_counter_value():
    '''
    The hard-coded maximum value for a tallied counter
    Tallied counters are signed, to allow for negative noise
    '''
    return adjust_count_signed((counter_modulus() + 1L)//2L - 1L,
                               counter_modulus())

def add_counter_limits_to_config(config):
    '''
    Add the hard-coded counter limits to a deep copy of the config dictionary
    Returns the modified deep copy of the config dictionary
    '''
    assert config is not None
    config = deepcopy(config)
    # call this modulus so it sorts near the other values
    config['modulus'] = counter_modulus()
    config['min_blinded_counter_value'] = min_blinded_counter_value()
    config['max_blinded_counter_value'] = max_blinded_counter_value()
    config['min_tally_counter_value'] = min_tally_counter_value()
    config['max_tally_counter_value'] = max_tally_counter_value()
    return config

MAX_DC_COUNT = 10**6

def check_dc_threshold(dc_threshold, description="threshold"):
    '''
    Check that dc_threshold is a valid dc threshold.
    DC thresholds must be positive non-zero, and less than or equal to
    MAX_DC_COUNT.
    Returns True if the dc threshold is valid.
    Logs a specific warning using description and returns False if it is not.
    '''
    if dc_threshold <= 0:
        logging.warning("Data collector {} must be at least 1, was {}"
                        .format(description, dc_threshold))
        return False
    if dc_threshold > MAX_DC_COUNT:
        logging.warning("Data collector {} can be at most {}, was {}"
                        .format(description, MAX_DC_COUNT, dc_threshold))
        return False
    return True

def check_noise_weight_value(noise_weight_value, description="value"):
    '''
    Check that noise_weight_value is a valid noise weight.
    Noise weights must be positive and less than or equal to the maximum
    tallied counter value.
    Returns True if the noise weight value is valid.
    Logs a specific warning using description, and returns False if it is not.
    '''
    if noise_weight_value < 0.0:
        logging.warning("Noise weight {} must be positive, was {}".format(
                description, noise_weight_value))
        return False
    if noise_weight_value > max_tally_counter_value():
        logging.warning("Noise weight {} can be at most {}, was {}".format(
                description, max_tally_counter_value(), noise_weight_value))
        return False
    return True

def check_noise_weight_sum(noise_weight_sum, description="sum"):
    '''
    Check that noise_weight_sum is a valid summed noise weight.
    Noise weight sums must pass check_noise_weight_value().
    Returns True if the noise weight sum is valid.
    Logs a specific warning using description and returns False if it is not.
    '''
    if not check_noise_weight_value(noise_weight_sum, description):
        return False
    return True

def get_noise_weight_default(noise_weight_config):
    '''
    Returns the default noise weight, if present in noise_weight_config.
    Otherwise, returns None.
    '''
    return noise_weight_config.get(DEFAULT_NOISE_WEIGHT_NAME, None)

def has_noise_weight_default(noise_weight_config):
    '''
    Returns True if noise_weight_config has a default noise weight.
    Otherwise, returns False.
    '''
    return get_noise_weight_default(noise_weight_config) is not None

def get_noise_weight(noise_weight_config, fingerprint):
    '''
    Returns the noise weight for fingerprint, which can be None.
    If fingerprint does not have a noise weight (or is None), return the
    default noise weight (if any).
    Otherwise, returns None.
    '''
    if fingerprint is not None and fingerprint in noise_weight_config:
        return noise_weight_config[fingerprint]
    elif has_noise_weight_default(noise_weight_config):
        return get_noise_weight_default(noise_weight_config)
    else:
        return None

def has_noise_weight(noise_weight_config, fingerprint):
    '''
    Returns True if fingerprint has a noise weight. fingerprint can be None.
    If fingerprint is None or missing, returns True if there is a default
    noise weight.
    If fingerprint does not have a noise weight, returns False.
    '''
    return get_noise_weight(noise_weight_config, fingerprint) is not None

def check_noise_weight_config(noise_weight_config, dc_threshold):
    '''
    Check that noise_weight_config is a valid noise weight configuration.
    Each noise weight must also pass check_noise_weight_value().
    Returns True if the noise weight config is valid.
    Logs a specific warning and returns False if it is not.
    '''
    if not check_dc_threshold(dc_threshold):
        return False
    # there must be noise weights for a threshold of DCs, or there must be
    # a default noise weight
    if (len(noise_weight_config) < dc_threshold and
        not has_noise_weight_default(noise_weight_config)):
        logging.warning("There must be at least as many noise weights as the threshold of data collectors, or there must be a default noise weight. Noise weights: {}, Threshold: {}."
                        .format(len(noise_weight_config), dc_threshold))
        return False
    # each noise weight must be individually valid
    for dc in noise_weight_config:
        if not check_noise_weight_value(noise_weight_config[dc]):
            return False
    # calculate the maximum possible noise weight
    noise_weight_sum = sum(noise_weight_config.values())
    # if there is a default, assume a threshold of relays might use it
    if has_noise_weight_default(noise_weight_config):
        default_weight = get_noise_weight_default(noise_weight_config)
        # adjust the sum for the extra default value
        noise_weight_sum -= default_weight
        # add a threshold of that weight
        assert dc_threshold > 0
        noise_weight_sum += dc_threshold*default_weight
    # the sum must be valid
    if not check_noise_weight_sum(noise_weight_sum):
        return False
    return True

def check_event_set_case(event_set):
    '''
    Check that event_set is a set, and each event in it has the correct case
    Returns True if all checks pass, and False if any check fails
    '''
    if not isinstance(event_set, (set, frozenset)):
        return False
    for event in event_set:
        if event != event.upper():
            return False
    return True

def check_event_set_valid(event_set):
    '''
    Check that event_set passes check_event_set_case, and also that each event
    is in the set of valid events
    Returns True if all checks pass, and False if any check fails
    '''
    if not check_event_set_case(event_set):
        return False
    for event in event_set:
        if event not in get_valid_events():
            return False
    return True

# internal
CELL_EVENT = 'PRIVCOUNT_CIRCUIT_CELL'
BYTES_EVENT = 'PRIVCOUNT_STREAM_BYTES_TRANSFERRED'
STREAM_EVENT = 'PRIVCOUNT_STREAM_ENDED'
CIRCUIT_EVENT = 'PRIVCOUNT_CIRCUIT_CLOSE'
CONNECTION_EVENT = 'PRIVCOUNT_CONNECTION_CLOSE'
HSDIR_STORE_EVENT = 'PRIVCOUNT_HSDIR_CACHE_STORE'
HSDIR_FETCH_EVENT = 'PRIVCOUNT_HSDIR_CACHE_FETCH'

# Unused events
# PrivCount never used this event, it was used by PrivEx
DNS_EVENT = 'PRIVCOUNT_DNS_RESOLVED'
# We don't use this event any more, but the Tor patch still produces it, for
# compatibility with older versions
LEGACY_CIRCUIT_EVENT = 'PRIVCOUNT_CIRCUIT_ENDED'
LEGACY_CONNECTION_EVENT = 'PRIVCOUNT_CONNECTION_ENDED'

def get_valid_events():
    '''
    Return a set containing the name of each privcount event, in uppercase
    '''
    event_set = { CELL_EVENT,
                  BYTES_EVENT,
                  STREAM_EVENT,
                  CIRCUIT_EVENT,
                  CONNECTION_EVENT,
                  HSDIR_STORE_EVENT,
                  HSDIR_FETCH_EVENT,
                  # Unused events
                  DNS_EVENT,
                  LEGACY_CIRCUIT_EVENT,
                  LEGACY_CONNECTION_EVENT,
                  }
    assert check_event_set_case(event_set)
    return event_set

# when you modify this list, update the test counters, and run:
# test/test_counter_match.sh
PRIVCOUNT_COUNTER_EVENTS = {

# these counters depend on the cell sent/received event
# they are updated in _handle_circuit_cell_event

# Don't collect this counter, it's inefficient
# Instead, collect Rend2ClientCircuitOutboundCellCount at the circuit level
'Rend2ClientSentCellCount' : { CELL_EVENT },

# these counters depend on bytes transferred event
# they are updated in _handle_circuit_cell_event_traffic_model

# model-specific counters are added in register_dynamic_counter
'ExitStreamTrafficModelEmissionCount' : { CELL_EVENT, STREAM_EVENT },
'ExitStreamTrafficModelTransitionCount' : { CELL_EVENT, STREAM_EVENT },
'ExitStreamTrafficModelLogDelayTime' : { CELL_EVENT, STREAM_EVENT },
'ExitStreamTrafficModelSquaredLogDelayTime' : { CELL_EVENT, STREAM_EVENT },

'ExitStreamCount' : { STREAM_EVENT },
'ExitStreamByteCount' : { STREAM_EVENT },
'ExitStreamOutboundByteCount' : { STREAM_EVENT },
'ExitStreamInboundByteCount' : { STREAM_EVENT },
'ExitStreamByteHistogram' : { STREAM_EVENT },
'ExitStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitStreamByteRatio' : { STREAM_EVENT },
'ExitStreamLifeTime' : { STREAM_EVENT },

# Port Classification
'ExitWebStreamCount' : { STREAM_EVENT },
'ExitWebStreamByteCount' : { STREAM_EVENT },
'ExitWebStreamOutboundByteCount' : { STREAM_EVENT },
'ExitWebStreamInboundByteCount' : { STREAM_EVENT },
'ExitWebStreamByteHistogram' : { STREAM_EVENT },
'ExitWebStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitWebStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitWebStreamByteRatio' : { STREAM_EVENT },
'ExitWebStreamLifeTime' : { STREAM_EVENT },
'ExitInteractiveStreamCount' : { STREAM_EVENT },
'ExitInteractiveStreamByteCount' : { STREAM_EVENT },
'ExitInteractiveStreamOutboundByteCount' : { STREAM_EVENT },
'ExitInteractiveStreamInboundByteCount' : { STREAM_EVENT },
'ExitInteractiveStreamByteHistogram' : { STREAM_EVENT },
'ExitInteractiveStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitInteractiveStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitInteractiveStreamByteRatio' : { STREAM_EVENT },
'ExitInteractiveStreamLifeTime' : { STREAM_EVENT },
'ExitP2PStreamCount' : { STREAM_EVENT },
'ExitP2PStreamByteCount' : { STREAM_EVENT },
'ExitP2PStreamOutboundByteCount' : { STREAM_EVENT },
'ExitP2PStreamInboundByteCount' : { STREAM_EVENT },
'ExitP2PStreamByteHistogram' : { STREAM_EVENT },
'ExitP2PStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitP2PStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitP2PStreamByteRatio' : { STREAM_EVENT },
'ExitP2PStreamLifeTime' : { STREAM_EVENT },
'ExitOtherPortStreamCount' : { STREAM_EVENT },
'ExitOtherPortStreamByteCount' : { STREAM_EVENT },
'ExitOtherPortStreamOutboundByteCount' : { STREAM_EVENT },
'ExitOtherPortStreamInboundByteCount' : { STREAM_EVENT },
'ExitOtherPortStreamByteHistogram' : { STREAM_EVENT },
'ExitOtherPortStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitOtherPortStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitOtherPortStreamByteRatio' : { STREAM_EVENT },
'ExitOtherPortStreamLifeTime' : { STREAM_EVENT },

# Is this stream *not* on port 80 or 443?
# Includes Interactive, P2P, and Other
'ExitNonWebStreamCount' : { STREAM_EVENT },
'ExitNonWebStreamByteCount' : { STREAM_EVENT },
'ExitNonWebStreamOutboundByteCount' : { STREAM_EVENT },
'ExitNonWebStreamInboundByteCount' : { STREAM_EVENT },
'ExitNonWebStreamByteHistogram' : { STREAM_EVENT },
'ExitNonWebStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitNonWebStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitNonWebStreamByteRatio' : { STREAM_EVENT },
'ExitNonWebStreamLifeTime' : { STREAM_EVENT },

# IP version after DNS resolution
'ExitIPv4StreamCount' : { STREAM_EVENT },
'ExitIPv4StreamByteCount' : { STREAM_EVENT },
'ExitIPv4StreamOutboundByteCount' : { STREAM_EVENT },
'ExitIPv4StreamInboundByteCount' : { STREAM_EVENT },
'ExitIPv4StreamByteHistogram' : { STREAM_EVENT },
'ExitIPv4StreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitIPv4StreamInboundByteHistogram' : { STREAM_EVENT },
'ExitIPv4StreamByteRatio' : { STREAM_EVENT },
'ExitIPv4StreamLifeTime' : { STREAM_EVENT },

'ExitIPv6StreamCount' : { STREAM_EVENT },
'ExitIPv6StreamByteCount' : { STREAM_EVENT },
'ExitIPv6StreamOutboundByteCount' : { STREAM_EVENT },
'ExitIPv6StreamInboundByteCount' : { STREAM_EVENT },
'ExitIPv6StreamByteHistogram' : { STREAM_EVENT },
'ExitIPv6StreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitIPv6StreamInboundByteHistogram' : { STREAM_EVENT },
'ExitIPv6StreamByteRatio' : { STREAM_EVENT },
'ExitIPv6StreamLifeTime' : { STREAM_EVENT },

# IP version or hostname before DNS resolution
'ExitIPv4LiteralStreamCount' : { STREAM_EVENT },
'ExitIPv4LiteralStreamByteCount' : { STREAM_EVENT },
'ExitIPv4LiteralStreamOutboundByteCount' : { STREAM_EVENT },
'ExitIPv4LiteralStreamInboundByteCount' : { STREAM_EVENT },
'ExitIPv4LiteralStreamByteHistogram' : { STREAM_EVENT },
'ExitIPv4LiteralStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitIPv4LiteralStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitIPv4LiteralStreamByteRatio' : { STREAM_EVENT },
'ExitIPv4LiteralStreamLifeTime' : { STREAM_EVENT },

'ExitIPv6LiteralStreamCount' : { STREAM_EVENT },
'ExitIPv6LiteralStreamByteCount' : { STREAM_EVENT },
'ExitIPv6LiteralStreamOutboundByteCount' : { STREAM_EVENT },
'ExitIPv6LiteralStreamInboundByteCount' : { STREAM_EVENT },
'ExitIPv6LiteralStreamByteHistogram' : { STREAM_EVENT },
'ExitIPv6LiteralStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitIPv6LiteralStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitIPv6LiteralStreamByteRatio' : { STREAM_EVENT },
'ExitIPv6LiteralStreamLifeTime' : { STREAM_EVENT },

'ExitHostnameStreamCount' : { STREAM_EVENT },
'ExitHostnameStreamByteCount' : { STREAM_EVENT },
'ExitHostnameStreamOutboundByteCount' : { STREAM_EVENT },
'ExitHostnameStreamInboundByteCount' : { STREAM_EVENT },
'ExitHostnameStreamByteHistogram' : { STREAM_EVENT },
'ExitHostnameStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameStreamByteRatio' : { STREAM_EVENT },
'ExitHostnameStreamLifeTime' : { STREAM_EVENT },

# Hostnames on Web and Non-Web streams
'ExitHostnameWebStreamCount' : { STREAM_EVENT },
'ExitHostnameWebStreamByteCount' : { STREAM_EVENT },
'ExitHostnameWebStreamOutboundByteCount' : { STREAM_EVENT },
'ExitHostnameWebStreamInboundByteCount' : { STREAM_EVENT },
'ExitHostnameWebStreamByteHistogram' : { STREAM_EVENT },
'ExitHostnameWebStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameWebStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameWebStreamByteRatio' : { STREAM_EVENT },
'ExitHostnameWebStreamLifeTime' : { STREAM_EVENT },

'ExitHostnameNonWebStreamCount' : { STREAM_EVENT },
'ExitHostnameNonWebStreamByteCount' : { STREAM_EVENT },
'ExitHostnameNonWebStreamOutboundByteCount' : { STREAM_EVENT },
'ExitHostnameNonWebStreamInboundByteCount' : { STREAM_EVENT },
'ExitHostnameNonWebStreamByteHistogram' : { STREAM_EVENT },
'ExitHostnameNonWebStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameNonWebStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameNonWebStreamByteRatio' : { STREAM_EVENT },
'ExitHostnameNonWebStreamLifeTime' : { STREAM_EVENT },

# Position of stream on circuit
# These also use CIRCUIT_EVENT, because that avoids collisions between old and
# new streams with the same circuit id. See #451.
'ExitInitialStreamCount' : { STREAM_EVENT },
'ExitInitialStreamByteCount' : { STREAM_EVENT },
'ExitInitialStreamOutboundByteCount' : { STREAM_EVENT },
'ExitInitialStreamInboundByteCount' : { STREAM_EVENT },
'ExitInitialStreamByteHistogram' : { STREAM_EVENT },
'ExitInitialStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitInitialStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitInitialStreamByteRatio' : { STREAM_EVENT },
'ExitInitialStreamLifeTime' : { STREAM_EVENT },

'ExitSubsequentStreamCount' : { STREAM_EVENT },
'ExitSubsequentStreamByteCount' : { STREAM_EVENT },
'ExitSubsequentStreamOutboundByteCount' : { STREAM_EVENT },
'ExitSubsequentStreamInboundByteCount' : { STREAM_EVENT },
'ExitSubsequentStreamByteHistogram' : { STREAM_EVENT },
'ExitSubsequentStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitSubsequentStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitSubsequentStreamByteRatio' : { STREAM_EVENT },
'ExitSubsequentStreamLifeTime' : { STREAM_EVENT },

# IP version after DNS resolution and position
'ExitIPv4InitialStreamCount' : { STREAM_EVENT },
'ExitIPv4InitialStreamByteCount' : { STREAM_EVENT },
'ExitIPv4InitialStreamOutboundByteCount' : { STREAM_EVENT },
'ExitIPv4InitialStreamInboundByteCount' : { STREAM_EVENT },
'ExitIPv4InitialStreamByteHistogram' : { STREAM_EVENT },
'ExitIPv4InitialStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitIPv4InitialStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitIPv4InitialStreamByteRatio' : { STREAM_EVENT },
'ExitIPv4InitialStreamLifeTime' : { STREAM_EVENT },

'ExitIPv6InitialStreamCount' : { STREAM_EVENT },
'ExitIPv6InitialStreamByteCount' : { STREAM_EVENT },
'ExitIPv6InitialStreamOutboundByteCount' : { STREAM_EVENT },
'ExitIPv6InitialStreamInboundByteCount' : { STREAM_EVENT },
'ExitIPv6InitialStreamByteHistogram' : { STREAM_EVENT },
'ExitIPv6InitialStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitIPv6InitialStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitIPv6InitialStreamByteRatio' : { STREAM_EVENT },
'ExitIPv6InitialStreamLifeTime' : { STREAM_EVENT },

# IP version or hostname before DNS resolution and position
'ExitIPv4LiteralInitialStreamCount' : { STREAM_EVENT },
'ExitIPv4LiteralInitialStreamByteCount' : { STREAM_EVENT },
'ExitIPv4LiteralInitialStreamOutboundByteCount' : { STREAM_EVENT },
'ExitIPv4LiteralInitialStreamInboundByteCount' : { STREAM_EVENT },
'ExitIPv4LiteralInitialStreamByteHistogram' : { STREAM_EVENT },
'ExitIPv4LiteralInitialStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitIPv4LiteralInitialStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitIPv4LiteralInitialStreamByteRatio' : { STREAM_EVENT },
'ExitIPv4LiteralInitialStreamLifeTime' : { STREAM_EVENT },

'ExitIPv6LiteralInitialStreamCount' : { STREAM_EVENT },
'ExitIPv6LiteralInitialStreamByteCount' : { STREAM_EVENT },
'ExitIPv6LiteralInitialStreamOutboundByteCount' : { STREAM_EVENT },
'ExitIPv6LiteralInitialStreamInboundByteCount' : { STREAM_EVENT },
'ExitIPv6LiteralInitialStreamByteHistogram' : { STREAM_EVENT },
'ExitIPv6LiteralInitialStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitIPv6LiteralInitialStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitIPv6LiteralInitialStreamByteRatio' : { STREAM_EVENT },
'ExitIPv6LiteralInitialStreamLifeTime' : { STREAM_EVENT },

'ExitHostnameInitialStreamCount' : { STREAM_EVENT },
'ExitHostnameInitialStreamByteCount' : { STREAM_EVENT },
'ExitHostnameInitialStreamOutboundByteCount' : { STREAM_EVENT },
'ExitHostnameInitialStreamInboundByteCount' : { STREAM_EVENT },
'ExitHostnameInitialStreamByteHistogram' : { STREAM_EVENT },
'ExitHostnameInitialStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameInitialStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameInitialStreamByteRatio' : { STREAM_EVENT },
'ExitHostnameInitialStreamLifeTime' : { STREAM_EVENT },

# The base counts for the ExitDomain*Web*Stream* counters
'ExitHostnameWebInitialStreamCount' : { STREAM_EVENT },
'ExitHostnameWebInitialStreamByteCount' : { STREAM_EVENT },
'ExitHostnameWebInitialStreamOutboundByteCount' : { STREAM_EVENT },
'ExitHostnameWebInitialStreamInboundByteCount' : { STREAM_EVENT },
'ExitHostnameWebInitialStreamByteHistogram' : { STREAM_EVENT },
'ExitHostnameWebInitialStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameWebInitialStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameWebInitialStreamByteRatio' : { STREAM_EVENT },
'ExitHostnameWebInitialStreamLifeTime' : { STREAM_EVENT },

'ExitHostnameWebSubsequentStreamCount' : { STREAM_EVENT },
'ExitHostnameWebSubsequentStreamByteCount' : { STREAM_EVENT },
'ExitHostnameWebSubsequentStreamOutboundByteCount' : { STREAM_EVENT },
'ExitHostnameWebSubsequentStreamInboundByteCount' : { STREAM_EVENT },
'ExitHostnameWebSubsequentStreamByteHistogram' : { STREAM_EVENT },
'ExitHostnameWebSubsequentStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameWebSubsequentStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameWebSubsequentStreamByteRatio' : { STREAM_EVENT },
'ExitHostnameWebSubsequentStreamLifeTime' : { STREAM_EVENT },

# The non-web equivalents of ExitHostnameWebInitial/SubsequentStream*
'ExitHostnameNonWebInitialStreamCount' : { STREAM_EVENT },
'ExitHostnameNonWebInitialStreamByteCount' : { STREAM_EVENT },
'ExitHostnameNonWebInitialStreamOutboundByteCount' : { STREAM_EVENT },
'ExitHostnameNonWebInitialStreamInboundByteCount' : { STREAM_EVENT },
'ExitHostnameNonWebInitialStreamByteHistogram' : { STREAM_EVENT },
'ExitHostnameNonWebInitialStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameNonWebInitialStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameNonWebInitialStreamByteRatio' : { STREAM_EVENT },
'ExitHostnameNonWebInitialStreamLifeTime' : { STREAM_EVENT },

'ExitHostnameNonWebSubsequentStreamCount' : { STREAM_EVENT },
'ExitHostnameNonWebSubsequentStreamByteCount' : { STREAM_EVENT },
'ExitHostnameNonWebSubsequentStreamOutboundByteCount' : { STREAM_EVENT },
'ExitHostnameNonWebSubsequentStreamInboundByteCount' : { STREAM_EVENT },
'ExitHostnameNonWebSubsequentStreamByteHistogram' : { STREAM_EVENT },
'ExitHostnameNonWebSubsequentStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameNonWebSubsequentStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameNonWebSubsequentStreamByteRatio' : { STREAM_EVENT },
'ExitHostnameNonWebSubsequentStreamLifeTime' : { STREAM_EVENT },

# IP version after DNS resolution and position
'ExitIPv4SubsequentStreamCount' : { STREAM_EVENT },
'ExitIPv4SubsequentStreamByteCount' : { STREAM_EVENT },
'ExitIPv4SubsequentStreamOutboundByteCount' : { STREAM_EVENT },
'ExitIPv4SubsequentStreamInboundByteCount' : { STREAM_EVENT },
'ExitIPv4SubsequentStreamByteHistogram' : { STREAM_EVENT },
'ExitIPv4SubsequentStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitIPv4SubsequentStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitIPv4SubsequentStreamByteRatio' : { STREAM_EVENT },
'ExitIPv4SubsequentStreamLifeTime' : { STREAM_EVENT },

'ExitIPv6SubsequentStreamCount' : { STREAM_EVENT },
'ExitIPv6SubsequentStreamByteCount' : { STREAM_EVENT },
'ExitIPv6SubsequentStreamOutboundByteCount' : { STREAM_EVENT },
'ExitIPv6SubsequentStreamInboundByteCount' : { STREAM_EVENT },
'ExitIPv6SubsequentStreamByteHistogram' : { STREAM_EVENT },
'ExitIPv6SubsequentStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitIPv6SubsequentStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitIPv6SubsequentStreamByteRatio' : { STREAM_EVENT },
'ExitIPv6SubsequentStreamLifeTime' : { STREAM_EVENT },

# IP version or hostname before DNS resolution and position
'ExitIPv4LiteralSubsequentStreamCount' : { STREAM_EVENT },
'ExitIPv4LiteralSubsequentStreamByteCount' : { STREAM_EVENT },
'ExitIPv4LiteralSubsequentStreamOutboundByteCount' : { STREAM_EVENT },
'ExitIPv4LiteralSubsequentStreamInboundByteCount' : { STREAM_EVENT },
'ExitIPv4LiteralSubsequentStreamByteHistogram' : { STREAM_EVENT },
'ExitIPv4LiteralSubsequentStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitIPv4LiteralSubsequentStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitIPv4LiteralSubsequentStreamByteRatio' : { STREAM_EVENT },
'ExitIPv4LiteralSubsequentStreamLifeTime' : { STREAM_EVENT },

'ExitIPv6LiteralSubsequentStreamCount' : { STREAM_EVENT },
'ExitIPv6LiteralSubsequentStreamByteCount' : { STREAM_EVENT },
'ExitIPv6LiteralSubsequentStreamOutboundByteCount' : { STREAM_EVENT },
'ExitIPv6LiteralSubsequentStreamInboundByteCount' : { STREAM_EVENT },
'ExitIPv6LiteralSubsequentStreamByteHistogram' : { STREAM_EVENT },
'ExitIPv6LiteralSubsequentStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitIPv6LiteralSubsequentStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitIPv6LiteralSubsequentStreamByteRatio' : { STREAM_EVENT },
'ExitIPv6LiteralSubsequentStreamLifeTime' : { STREAM_EVENT },

'ExitHostnameSubsequentStreamCount' : { STREAM_EVENT },
'ExitHostnameSubsequentStreamByteCount' : { STREAM_EVENT },
'ExitHostnameSubsequentStreamOutboundByteCount' : { STREAM_EVENT },
'ExitHostnameSubsequentStreamInboundByteCount' : { STREAM_EVENT },
'ExitHostnameSubsequentStreamByteHistogram' : { STREAM_EVENT },
'ExitHostnameSubsequentStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameSubsequentStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitHostnameSubsequentStreamByteRatio' : { STREAM_EVENT },
'ExitHostnameSubsequentStreamLifeTime' : { STREAM_EVENT },

# The first domain list is used for the ExitDomain*MatchWebInitialStream Ratio, LifeTime, and Histogram counters
# Their ExitDomainNo*MatchWebInitialStream* equivalents are used when there is no match in the first list

# Does the initial domain on the circuit match any domain in the first list?
'ExitDomainExactMatchWebInitialStreamByteHistogram' : { STREAM_EVENT },
'ExitDomainExactMatchWebInitialStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitDomainExactMatchWebInitialStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitDomainExactMatchWebInitialStreamByteRatio' : { STREAM_EVENT },
'ExitDomainExactMatchWebInitialStreamLifeTime' : { STREAM_EVENT },

'ExitDomainNoExactMatchWebInitialStreamByteHistogram' : { STREAM_EVENT },
'ExitDomainNoExactMatchWebInitialStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitDomainNoExactMatchWebInitialStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitDomainNoExactMatchWebInitialStreamByteRatio' : { STREAM_EVENT },
'ExitDomainNoExactMatchWebInitialStreamLifeTime' : { STREAM_EVENT },

# Does the initial domain on the circuit have any domain in the first list as a suffix?
'ExitDomainSuffixMatchWebInitialStreamByteHistogram' : { STREAM_EVENT },
'ExitDomainSuffixMatchWebInitialStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitDomainSuffixMatchWebInitialStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitDomainSuffixMatchWebInitialStreamByteRatio' : { STREAM_EVENT },
'ExitDomainSuffixMatchWebInitialStreamLifeTime' : { STREAM_EVENT },

'ExitDomainNoSuffixMatchWebInitialStreamByteHistogram' : { STREAM_EVENT },
'ExitDomainNoSuffixMatchWebInitialStreamOutboundByteHistogram' : { STREAM_EVENT },
'ExitDomainNoSuffixMatchWebInitialStreamInboundByteHistogram' : { STREAM_EVENT },
'ExitDomainNoSuffixMatchWebInitialStreamByteRatio' : { STREAM_EVENT },
'ExitDomainNoSuffixMatchWebInitialStreamLifeTime' : { STREAM_EVENT },

# The number of bins in the ExitDomain*MatchWebInitialStream*CountList counters is
# determined at runtime, based on the number of configured domain lists
# Each domain list gets a bin in each counter, and there is a final bin
# for "no match in any list" (multiple lists may match: all matching bins
# will be incremented). Since there is an unmatched bin, there are no
# ExitDomainNo*MatchWebInitialStream*CountList counters.

# Does the initial domain on the circuit match any domain in the list for each bin? Or is it unmatched by all the lists?
'ExitDomainExactMatchWebInitialStreamCountList' : { STREAM_EVENT },
'ExitDomainExactMatchWebInitialStreamByteCountList' : { STREAM_EVENT },
'ExitDomainExactMatchWebInitialStreamOutboundByteCountList' : { STREAM_EVENT },
'ExitDomainExactMatchWebInitialStreamInboundByteCountList' : { STREAM_EVENT },

# Does the initial domain on the circuit have any domain in the list for each bin as a suffix? Or is it unmatched by all the lists?
'ExitDomainSuffixMatchWebInitialStreamCountList' : { STREAM_EVENT },
'ExitDomainSuffixMatchWebInitialStreamByteCountList' : { STREAM_EVENT },
'ExitDomainSuffixMatchWebInitialStreamOutboundByteCountList' : { STREAM_EVENT },
'ExitDomainSuffixMatchWebInitialStreamInboundByteCountList' : { STREAM_EVENT },

# these counters depend on circuit end
# they are updated in _handle_circuit_close_event

# Non-HS Circuit Positions

# Circuit Counts
'OriginCircuitCount' : { CIRCUIT_EVENT },
'EntryCircuitCount' : { CIRCUIT_EVENT },
'MidCircuitCount' : { CIRCUIT_EVENT },
'EndCircuitCount' : { CIRCUIT_EVENT },
'SingleHopCircuitCount' : { CIRCUIT_EVENT },
'ExitCircuitCount' : { CIRCUIT_EVENT },
'DirCircuitCount' : { CIRCUIT_EVENT },

# Circuit Cell Counts
# Inbound cells travel towards the origin
'OriginCircuitInboundCellCount' : { CIRCUIT_EVENT },
'EntryCircuitInboundCellCount' : { CIRCUIT_EVENT },
'MidCircuitInboundCellCount' : { CIRCUIT_EVENT },
'EndCircuitInboundCellCount' : { CIRCUIT_EVENT },
'SingleHopCircuitInboundCellCount' : { CIRCUIT_EVENT },
'ExitCircuitInboundCellCount' : { CIRCUIT_EVENT },
'DirCircuitInboundCellCount' : { CIRCUIT_EVENT },

# Outbound cells travel towards the end
'OriginCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'EntryCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'MidCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'EndCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'SingleHopCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'ExitCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'DirCircuitOutboundCellCount' : { CIRCUIT_EVENT },

# HSDir
# You probably want the HSDir*Store/Fetch* events instead of these events

# HSDir 2/3 /Client/Service /Failure/Success Circuit /InboundCell/OutboundCell Count
'HSDir2CircuitCount' : { CIRCUIT_EVENT },
'HSDir2CircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2CircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2FailureCircuitCount' : { CIRCUIT_EVENT },
'HSDir2FailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2FailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2SuccessCircuitCount' : { CIRCUIT_EVENT },
'HSDir2SuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2SuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2ClientCircuitCount' : { CIRCUIT_EVENT },
'HSDir2ClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2ClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2ClientFailureCircuitCount' : { CIRCUIT_EVENT },
'HSDir2ClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2ClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2ClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'HSDir2ClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2ClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2ServiceCircuitCount' : { CIRCUIT_EVENT },
'HSDir2ServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2ServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2ServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'HSDir2ServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2ServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2ServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'HSDir2ServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2ServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3CircuitCount' : { CIRCUIT_EVENT },
'HSDir3CircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3CircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3FailureCircuitCount' : { CIRCUIT_EVENT },
'HSDir3FailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3FailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3SuccessCircuitCount' : { CIRCUIT_EVENT },
'HSDir3SuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3SuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3ClientCircuitCount' : { CIRCUIT_EVENT },
'HSDir3ClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3ClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3ClientFailureCircuitCount' : { CIRCUIT_EVENT },
'HSDir3ClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3ClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3ClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'HSDir3ClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3ClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3ServiceCircuitCount' : { CIRCUIT_EVENT },
'HSDir3ServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3ServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3ServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'HSDir3ServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3ServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3ServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'HSDir3ServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3ServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },

# HSDir 2/3 Tor2WebClient/SingleOnionService/MultiHopClient/MultiHopService /Failure/Success Circuit /InboundCell/OutboundCell Count
'HSDir2Tor2WebClientCircuitCount' : { CIRCUIT_EVENT },
'HSDir2Tor2WebClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2Tor2WebClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2Tor2WebClientFailureCircuitCount' : { CIRCUIT_EVENT },
'HSDir2Tor2WebClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2Tor2WebClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2Tor2WebClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'HSDir2Tor2WebClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2Tor2WebClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2SingleOnionServiceCircuitCount' : { CIRCUIT_EVENT },
'HSDir2SingleOnionServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2SingleOnionServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2SingleOnionServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'HSDir2SingleOnionServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2SingleOnionServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2SingleOnionServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'HSDir2SingleOnionServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2SingleOnionServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopClientCircuitCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopClientFailureCircuitCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopServiceCircuitCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir2MultiHopServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3Tor2WebClientCircuitCount' : { CIRCUIT_EVENT },
'HSDir3Tor2WebClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3Tor2WebClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3Tor2WebClientFailureCircuitCount' : { CIRCUIT_EVENT },
'HSDir3Tor2WebClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3Tor2WebClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3Tor2WebClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'HSDir3Tor2WebClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3Tor2WebClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3SingleOnionServiceCircuitCount' : { CIRCUIT_EVENT },
'HSDir3SingleOnionServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3SingleOnionServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3SingleOnionServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'HSDir3SingleOnionServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3SingleOnionServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3SingleOnionServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'HSDir3SingleOnionServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3SingleOnionServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopClientCircuitCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopClientFailureCircuitCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopServiceCircuitCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'HSDir3MultiHopServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },

# We collect these combined counters so there is only one lot of noise added
'ExitAndRend2ClientCircuitCount' : { CIRCUIT_EVENT },
'ExitAndRend2ServiceCircuitCount' : { CIRCUIT_EVENT },

# Intro/Rend 2/3 Circuit /InboundCell/OutboundCell Count
'Intro2CircuitCount' : { CIRCUIT_EVENT },
'Intro2CircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2CircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3CircuitCount' : { CIRCUIT_EVENT },
'Intro3CircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3CircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2CircuitCount' : { CIRCUIT_EVENT },
'Rend2CircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2CircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3CircuitCount' : { CIRCUIT_EVENT },
'Rend3CircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3CircuitOutboundCellCount' : { CIRCUIT_EVENT },

# Intro/Rend 2/3 Failure/Success Circuit /InboundCell/OutboundCell Count
'Intro2FailureCircuitCount' : { CIRCUIT_EVENT },
'Intro2FailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2FailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro2SuccessCircuitCount' : { CIRCUIT_EVENT },
'Intro2SuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2SuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3FailureCircuitCount' : { CIRCUIT_EVENT },
'Intro3FailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3FailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3SuccessCircuitCount' : { CIRCUIT_EVENT },
'Intro3SuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3SuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2FailureCircuitCount' : { CIRCUIT_EVENT },
'Rend2FailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2FailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2SuccessCircuitCount' : { CIRCUIT_EVENT },
'Rend2SuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2SuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3FailureCircuitCount' : { CIRCUIT_EVENT },
'Rend3FailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3FailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3SuccessCircuitCount' : { CIRCUIT_EVENT },
'Rend3SuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3SuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },

# Intro/Rend 2/3 Client/Service Circuit /InboundCell/OutboundCell Count
'Intro2ClientCircuitCount' : { CIRCUIT_EVENT },
'Intro2ClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2ClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro2ServiceCircuitCount' : { CIRCUIT_EVENT },
'Intro2ServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2ServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3ClientCircuitCount' : { CIRCUIT_EVENT },
'Intro3ClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3ClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3ServiceCircuitCount' : { CIRCUIT_EVENT },
'Intro3ServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3ServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2ClientCircuitCount' : { CIRCUIT_EVENT },
'Rend2ClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2ClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2ServiceCircuitCount' : { CIRCUIT_EVENT },
'Rend2ServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2ServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3ClientCircuitCount' : { CIRCUIT_EVENT },
'Rend3ClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3ClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3ServiceCircuitCount' : { CIRCUIT_EVENT },
'Rend3ServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3ServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },

# Intro/Rend 2/3 Client/Service Failure/Success Circuit /InboundCell/OutboundCell Count
'Intro2ClientFailureCircuitCount' : { CIRCUIT_EVENT },
'Intro2ClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2ClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro2ClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'Intro2ClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2ClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro2ServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'Intro2ServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2ServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro2ServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'Intro2ServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2ServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3ClientFailureCircuitCount' : { CIRCUIT_EVENT },
'Intro3ClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3ClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3ClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'Intro3ClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3ClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3ServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'Intro3ServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3ServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3ServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'Intro3ServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3ServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2ClientFailureCircuitCount' : { CIRCUIT_EVENT },
'Rend2ClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2ClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2ClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'Rend2ClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2ClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2ServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'Rend2ServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2ServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2ServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'Rend2ServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2ServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3ClientFailureCircuitCount' : { CIRCUIT_EVENT },
'Rend3ClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3ClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3ClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'Rend3ClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3ClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3ServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'Rend3ServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3ServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3ServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'Rend3ServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3ServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },

# Intro/Rend 2/3 Tor2WebClient/SingleOnionService/MultiHopClient/MultiHopService Circuit /InboundCell/OutboundCell Count
'Intro2Tor2WebClientCircuitCount' : { CIRCUIT_EVENT },
'Intro2Tor2WebClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2Tor2WebClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro2SingleOnionServiceCircuitCount' : { CIRCUIT_EVENT },
'Intro2SingleOnionServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2SingleOnionServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro2MultiHopClientCircuitCount' : { CIRCUIT_EVENT },
'Intro2MultiHopClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2MultiHopClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro2MultiHopServiceCircuitCount' : { CIRCUIT_EVENT },
'Intro2MultiHopServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2MultiHopServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3Tor2WebClientCircuitCount' : { CIRCUIT_EVENT },
'Intro3Tor2WebClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3Tor2WebClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3SingleOnionServiceCircuitCount' : { CIRCUIT_EVENT },
'Intro3SingleOnionServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3SingleOnionServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3MultiHopClientCircuitCount' : { CIRCUIT_EVENT },
'Intro3MultiHopClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3MultiHopClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3MultiHopServiceCircuitCount' : { CIRCUIT_EVENT },
'Intro3MultiHopServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3MultiHopServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2Tor2WebClientCircuitCount' : { CIRCUIT_EVENT },
'Rend2Tor2WebClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2Tor2WebClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2SingleOnionServiceCircuitCount' : { CIRCUIT_EVENT },
'Rend2SingleOnionServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2SingleOnionServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2MultiHopClientCircuitCount' : { CIRCUIT_EVENT },
'Rend2MultiHopClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2MultiHopClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2MultiHopServiceCircuitCount' : { CIRCUIT_EVENT },
'Rend2MultiHopServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2MultiHopServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3Tor2WebClientCircuitCount' : { CIRCUIT_EVENT },
'Rend3Tor2WebClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3Tor2WebClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3SingleOnionServiceCircuitCount' : { CIRCUIT_EVENT },
'Rend3SingleOnionServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3SingleOnionServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3MultiHopClientCircuitCount' : { CIRCUIT_EVENT },
'Rend3MultiHopClientCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3MultiHopClientCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3MultiHopServiceCircuitCount' : { CIRCUIT_EVENT },
'Rend3MultiHopServiceCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3MultiHopServiceCircuitOutboundCellCount' : { CIRCUIT_EVENT },

# Intro/Rend 2/3 Tor2WebClient/SingleOnionService/MultiHopClient/MultiHopService Failure/Success Circuit /InboundCell/OutboundCell Count
'Intro2Tor2WebClientFailureCircuitCount' : { CIRCUIT_EVENT },
'Intro2Tor2WebClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2Tor2WebClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro2Tor2WebClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'Intro2Tor2WebClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2Tor2WebClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro2SingleOnionServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'Intro2SingleOnionServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2SingleOnionServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro2SingleOnionServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'Intro2SingleOnionServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2SingleOnionServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro2MultiHopClientFailureCircuitCount' : { CIRCUIT_EVENT },
'Intro2MultiHopClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2MultiHopClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro2MultiHopClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'Intro2MultiHopClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2MultiHopClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro2MultiHopServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'Intro2MultiHopServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2MultiHopServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro2MultiHopServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'Intro2MultiHopServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro2MultiHopServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3Tor2WebClientFailureCircuitCount' : { CIRCUIT_EVENT },
'Intro3Tor2WebClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3Tor2WebClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3Tor2WebClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'Intro3Tor2WebClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3Tor2WebClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3SingleOnionServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'Intro3SingleOnionServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3SingleOnionServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3SingleOnionServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'Intro3SingleOnionServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3SingleOnionServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3MultiHopClientFailureCircuitCount' : { CIRCUIT_EVENT },
'Intro3MultiHopClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3MultiHopClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3MultiHopClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'Intro3MultiHopClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3MultiHopClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3MultiHopServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'Intro3MultiHopServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3MultiHopServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Intro3MultiHopServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'Intro3MultiHopServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Intro3MultiHopServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2Tor2WebClientFailureCircuitCount' : { CIRCUIT_EVENT },
'Rend2Tor2WebClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2Tor2WebClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2Tor2WebClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'Rend2Tor2WebClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2Tor2WebClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2SingleOnionServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'Rend2SingleOnionServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2SingleOnionServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2SingleOnionServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'Rend2SingleOnionServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2SingleOnionServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2MultiHopClientFailureCircuitCount' : { CIRCUIT_EVENT },
'Rend2MultiHopClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2MultiHopClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2MultiHopClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'Rend2MultiHopClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2MultiHopClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2MultiHopServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'Rend2MultiHopServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2MultiHopServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend2MultiHopServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'Rend2MultiHopServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend2MultiHopServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3Tor2WebClientFailureCircuitCount' : { CIRCUIT_EVENT },
'Rend3Tor2WebClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3Tor2WebClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3Tor2WebClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'Rend3Tor2WebClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3Tor2WebClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3SingleOnionServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'Rend3SingleOnionServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3SingleOnionServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3SingleOnionServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'Rend3SingleOnionServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3SingleOnionServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3MultiHopClientFailureCircuitCount' : { CIRCUIT_EVENT },
'Rend3MultiHopClientFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3MultiHopClientFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3MultiHopClientSuccessCircuitCount' : { CIRCUIT_EVENT },
'Rend3MultiHopClientSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3MultiHopClientSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3MultiHopServiceFailureCircuitCount' : { CIRCUIT_EVENT },
'Rend3MultiHopServiceFailureCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3MultiHopServiceFailureCircuitOutboundCellCount' : { CIRCUIT_EVENT },
'Rend3MultiHopServiceSuccessCircuitCount' : { CIRCUIT_EVENT },
'Rend3MultiHopServiceSuccessCircuitInboundCellCount' : { CIRCUIT_EVENT },
'Rend3MultiHopServiceSuccessCircuitOutboundCellCount' : { CIRCUIT_EVENT },

# these counters depend on circuit end
# they are updated in _do_rotate,
# and use data updated in _handle_legacy_exit_circuit_event
'EntryClientIPCount' : { CIRCUIT_EVENT },
'EntryActiveClientIPCount' : { CIRCUIT_EVENT },
'EntryInactiveClientIPCount' : { CIRCUIT_EVENT },
'EntryClientIPActiveCircuitHistogram' : { CIRCUIT_EVENT },
'EntryClientIPInactiveCircuitHistogram' : { CIRCUIT_EVENT },

# these counters depend on circuit end
# they are updated in _handle_legacy_exit_circuit_event
'EntryActiveCircuitCount' : { CIRCUIT_EVENT },
'EntryCircuitInboundCellHistogram' : { CIRCUIT_EVENT },
'EntryCircuitOutboundCellHistogram' : { CIRCUIT_EVENT },
'EntryCircuitCellRatio' : { CIRCUIT_EVENT },
'EntryInactiveCircuitCount' : { CIRCUIT_EVENT },
'ExitCircuitLifeTime' : { CIRCUIT_EVENT },

# these counters depend on stream end and circuit end
# they are updated in _handle_legacy_exit_circuit_event,
# and use data updated in _handle_stream_event
'ExitActiveCircuitCount' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitInactiveCircuitCount' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitActiveCircuitLifeTime' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitInactiveCircuitLifeTime' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitCircuitStreamHistogram' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitCircuitInterStreamCreationTime' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitWebCircuitCount' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitCircuitWebStreamHistogram' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitCircuitWebInterStreamCreationTime' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitInteractiveCircuitCount' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitCircuitInteractiveStreamHistogram' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitCircuitInteractiveInterStreamCreationTime' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitP2PCircuitCount' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitCircuitP2PStreamHistogram' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitCircuitP2PInterStreamCreationTime' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitOtherPortCircuitCount' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitCircuitOtherPortStreamHistogram' : { STREAM_EVENT, CIRCUIT_EVENT },
'ExitCircuitOtherPortInterStreamCreationTime' : { STREAM_EVENT, CIRCUIT_EVENT },

# these counters depend on connection close

# simple connection counts
'EntryConnectionCount' : { CONNECTION_EVENT },
'NonEntryConnectionCount' : { CONNECTION_EVENT },

# connection counts based on the number of relays sharing the remote address
'Entry0RelayOnAddressConnectionCount' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCount' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCount' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCount' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCount' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCount' : { CONNECTION_EVENT },

# byte counts
'EntryConnectionByteCount' : { CONNECTION_EVENT },
'NonEntryConnectionByteCount' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionByteCount' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionByteCount' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionByteCount' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionByteCount' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionByteCount' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionByteCount' : { CONNECTION_EVENT },

'EntryConnectionInboundByteCount' : { CONNECTION_EVENT },
'NonEntryConnectionInboundByteCount' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionInboundByteCount' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionInboundByteCount' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionInboundByteCount' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionInboundByteCount' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionInboundByteCount' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionInboundByteCount' : { CONNECTION_EVENT },

'EntryConnectionOutboundByteCount' : { CONNECTION_EVENT },
'NonEntryConnectionOutboundByteCount' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionOutboundByteCount' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionOutboundByteCount' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionOutboundByteCount' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionOutboundByteCount' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionOutboundByteCount' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionOutboundByteCount' : { CONNECTION_EVENT },

# byte histograms per connection
'EntryConnectionByteHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionByteHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionByteHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionByteHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionByteHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionByteHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionByteHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionByteHistogram' : { CONNECTION_EVENT },

'EntryConnectionInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionInboundByteHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionInboundByteHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionInboundByteHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionInboundByteHistogram' : { CONNECTION_EVENT },

'EntryConnectionOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionOutboundByteHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionOutboundByteHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionOutboundByteHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionOutboundByteHistogram' : { CONNECTION_EVENT },

# circuit counts
'EntryConnectionCircuitCount' : { CONNECTION_EVENT },
'NonEntryConnectionCircuitCount' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCircuitCount' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCircuitCount' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCircuitCount' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCircuitCount' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCircuitCount' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCircuitCount' : { CONNECTION_EVENT },

'EntryConnectionInboundCircuitCount' : { CONNECTION_EVENT },
'NonEntryConnectionInboundCircuitCount' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionInboundCircuitCount' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionInboundCircuitCount' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionInboundCircuitCount' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionInboundCircuitCount' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionInboundCircuitCount' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionInboundCircuitCount' : { CONNECTION_EVENT },

'EntryConnectionOutboundCircuitCount' : { CONNECTION_EVENT },
'NonEntryConnectionOutboundCircuitCount' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionOutboundCircuitCount' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionOutboundCircuitCount' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionOutboundCircuitCount' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionOutboundCircuitCount' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionOutboundCircuitCount' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionOutboundCircuitCount' : { CONNECTION_EVENT },

# circuit count histograms by connection
'EntryConnectionCircuitHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionCircuitHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCircuitHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCircuitHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCircuitHistogram' : { CONNECTION_EVENT },

'EntryConnectionInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionInboundCircuitHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionInboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionInboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionInboundCircuitHistogram' : { CONNECTION_EVENT },

'EntryConnectionOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionOutboundCircuitHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionOutboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionOutboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionOutboundCircuitHistogram' : { CONNECTION_EVENT },

# connection lifetime histograms
'EntryConnectionLifeTime' : { CONNECTION_EVENT },
'NonEntryConnectionLifeTime' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionLifeTime' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionLifeTime' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionLifeTime' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionLifeTime' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionLifeTime' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionLifeTime' : { CONNECTION_EVENT },

# the number of simultaneous connections from the same IP address as a histogram
'EntryConnectionOverlapHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionOverlapHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionOverlapHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionOverlapHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionOverlapHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionOverlapHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionOverlapHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionOverlapHistogram' : { CONNECTION_EVENT },

# histograms for country codes that match the first list specified
# byte histograms per connection
'EntryConnectionCountryMatchByteHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionCountryMatchByteHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryMatchByteHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryMatchByteHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryMatchByteHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryMatchByteHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryMatchByteHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryMatchByteHistogram' : { CONNECTION_EVENT },

'EntryConnectionCountryMatchInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionCountryMatchInboundByteHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryMatchInboundByteHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryMatchInboundByteHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryMatchInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryMatchInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryMatchInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryMatchInboundByteHistogram' : { CONNECTION_EVENT },

'EntryConnectionCountryMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionCountryMatchOutboundByteHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryMatchOutboundByteHistogram' : { CONNECTION_EVENT },

# circuit count histograms by connection
'EntryConnectionCountryMatchCircuitHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionCountryMatchCircuitHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryMatchCircuitHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryMatchCircuitHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryMatchCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryMatchCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryMatchCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryMatchCircuitHistogram' : { CONNECTION_EVENT },

'EntryConnectionCountryMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionCountryMatchInboundCircuitHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryMatchInboundCircuitHistogram' : { CONNECTION_EVENT },

'EntryConnectionCountryMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionCountryMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },

# connection lifetime histograms
'EntryConnectionCountryMatchLifeTime' : { CONNECTION_EVENT },
'NonEntryConnectionCountryMatchLifeTime' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryMatchLifeTime' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryMatchLifeTime' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryMatchLifeTime' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryMatchLifeTime' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryMatchLifeTime' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryMatchLifeTime' : { CONNECTION_EVENT },

# the number of simultaneous connections from the same IP address as a histogram
'EntryConnectionCountryMatchOverlapHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionCountryMatchOverlapHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryMatchOverlapHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryMatchOverlapHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryMatchOverlapHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryMatchOverlapHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryMatchOverlapHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryMatchOverlapHistogram' : { CONNECTION_EVENT },

# histograms for country codes that don't match the first list specified
# byte histograms per connection
'EntryConnectionCountryNoMatchByteHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionCountryNoMatchByteHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryNoMatchByteHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryNoMatchByteHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryNoMatchByteHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryNoMatchByteHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryNoMatchByteHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryNoMatchByteHistogram' : { CONNECTION_EVENT },

'EntryConnectionCountryNoMatchInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionCountryNoMatchInboundByteHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryNoMatchInboundByteHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryNoMatchInboundByteHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryNoMatchInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryNoMatchInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryNoMatchInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryNoMatchInboundByteHistogram' : { CONNECTION_EVENT },

'EntryConnectionCountryNoMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionCountryNoMatchOutboundByteHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryNoMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryNoMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryNoMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryNoMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryNoMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryNoMatchOutboundByteHistogram' : { CONNECTION_EVENT },

# circuit count histograms by connection
'EntryConnectionCountryNoMatchCircuitHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionCountryNoMatchCircuitHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryNoMatchCircuitHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryNoMatchCircuitHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryNoMatchCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryNoMatchCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryNoMatchCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryNoMatchCircuitHistogram' : { CONNECTION_EVENT },

'EntryConnectionCountryNoMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionCountryNoMatchInboundCircuitHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryNoMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryNoMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryNoMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryNoMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryNoMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryNoMatchInboundCircuitHistogram' : { CONNECTION_EVENT },

'EntryConnectionCountryNoMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionCountryNoMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryNoMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryNoMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryNoMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryNoMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryNoMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryNoMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },

# connection lifetime histograms
'EntryConnectionCountryNoMatchLifeTime' : { CONNECTION_EVENT },
'NonEntryConnectionCountryNoMatchLifeTime' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryNoMatchLifeTime' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryNoMatchLifeTime' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryNoMatchLifeTime' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryNoMatchLifeTime' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryNoMatchLifeTime' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryNoMatchLifeTime' : { CONNECTION_EVENT },

# the number of simultaneous connections from the same IP address as a histogram
'EntryConnectionCountryNoMatchOverlapHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionCountryNoMatchOverlapHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryNoMatchOverlapHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryNoMatchOverlapHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryNoMatchOverlapHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryNoMatchOverlapHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryNoMatchOverlapHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryNoMatchOverlapHistogram' : { CONNECTION_EVENT },

# count lists for country codes that match each list
# the final bin is used for country codes that don't match any list
# simple connection counts
'EntryConnectionCountryMatchCountList' : { CONNECTION_EVENT },
'NonEntryConnectionCountryMatchCountList' : { CONNECTION_EVENT },

# connection counts based on the number of relays sharing the remote address
'Entry0RelayOnAddressConnectionCountryMatchCountList' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryMatchCountList' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryMatchCountList' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryMatchCountList' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryMatchCountList' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryMatchCountList' : { CONNECTION_EVENT },

# byte counts
'EntryConnectionCountryMatchByteCountList' : { CONNECTION_EVENT },
'NonEntryConnectionCountryMatchByteCountList' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryMatchByteCountList' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryMatchByteCountList' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryMatchByteCountList' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryMatchByteCountList' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryMatchByteCountList' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryMatchByteCountList' : { CONNECTION_EVENT },

'EntryConnectionCountryMatchInboundByteCountList' : { CONNECTION_EVENT },
'NonEntryConnectionCountryMatchInboundByteCountList' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryMatchInboundByteCountList' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryMatchInboundByteCountList' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryMatchInboundByteCountList' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryMatchInboundByteCountList' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryMatchInboundByteCountList' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryMatchInboundByteCountList' : { CONNECTION_EVENT },

'EntryConnectionCountryMatchOutboundByteCountList' : { CONNECTION_EVENT },
'NonEntryConnectionCountryMatchOutboundByteCountList' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryMatchOutboundByteCountList' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryMatchOutboundByteCountList' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryMatchOutboundByteCountList' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryMatchOutboundByteCountList' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryMatchOutboundByteCountList' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryMatchOutboundByteCountList' : { CONNECTION_EVENT },

# circuit counts
'EntryConnectionCountryMatchCircuitCountList' : { CONNECTION_EVENT },
'NonEntryConnectionCountryMatchCircuitCountList' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryMatchCircuitCountList' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryMatchCircuitCountList' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryMatchCircuitCountList' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryMatchCircuitCountList' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryMatchCircuitCountList' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryMatchCircuitCountList' : { CONNECTION_EVENT },

'EntryConnectionCountryMatchInboundCircuitCountList' : { CONNECTION_EVENT },
'NonEntryConnectionCountryMatchInboundCircuitCountList' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryMatchInboundCircuitCountList' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryMatchInboundCircuitCountList' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryMatchInboundCircuitCountList' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryMatchInboundCircuitCountList' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryMatchInboundCircuitCountList' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryMatchInboundCircuitCountList' : { CONNECTION_EVENT },

'EntryConnectionCountryMatchOutboundCircuitCountList' : { CONNECTION_EVENT },
'NonEntryConnectionCountryMatchOutboundCircuitCountList' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionCountryMatchOutboundCircuitCountList' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionCountryMatchOutboundCircuitCountList' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionCountryMatchOutboundCircuitCountList' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionCountryMatchOutboundCircuitCountList' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionCountryMatchOutboundCircuitCountList' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionCountryMatchOutboundCircuitCountList' : { CONNECTION_EVENT },

# histograms for AS numbers that match the first list specified
# byte histograms per connection
'EntryConnectionASMatchByteHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionASMatchByteHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASMatchByteHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASMatchByteHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASMatchByteHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASMatchByteHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASMatchByteHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASMatchByteHistogram' : { CONNECTION_EVENT },

'EntryConnectionASMatchInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionASMatchInboundByteHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASMatchInboundByteHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASMatchInboundByteHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASMatchInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASMatchInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASMatchInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASMatchInboundByteHistogram' : { CONNECTION_EVENT },

'EntryConnectionASMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionASMatchOutboundByteHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASMatchOutboundByteHistogram' : { CONNECTION_EVENT },

# circuit count histograms by connection
'EntryConnectionASMatchCircuitHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionASMatchCircuitHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASMatchCircuitHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASMatchCircuitHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASMatchCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASMatchCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASMatchCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASMatchCircuitHistogram' : { CONNECTION_EVENT },

'EntryConnectionASMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionASMatchInboundCircuitHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASMatchInboundCircuitHistogram' : { CONNECTION_EVENT },

'EntryConnectionASMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionASMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },

# connection lifetime histograms
'EntryConnectionASMatchLifeTime' : { CONNECTION_EVENT },
'NonEntryConnectionASMatchLifeTime' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASMatchLifeTime' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASMatchLifeTime' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASMatchLifeTime' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASMatchLifeTime' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASMatchLifeTime' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASMatchLifeTime' : { CONNECTION_EVENT },

# the number of simultaneous connections from the same IP address as a histogram
'EntryConnectionASMatchOverlapHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionASMatchOverlapHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASMatchOverlapHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASMatchOverlapHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASMatchOverlapHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASMatchOverlapHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASMatchOverlapHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASMatchOverlapHistogram' : { CONNECTION_EVENT },

# histograms for AS numbers that don't match the first list specified
# byte histograms per connection
'EntryConnectionASNoMatchByteHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionASNoMatchByteHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASNoMatchByteHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASNoMatchByteHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASNoMatchByteHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASNoMatchByteHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASNoMatchByteHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASNoMatchByteHistogram' : { CONNECTION_EVENT },

'EntryConnectionASNoMatchInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionASNoMatchInboundByteHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASNoMatchInboundByteHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASNoMatchInboundByteHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASNoMatchInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASNoMatchInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASNoMatchInboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASNoMatchInboundByteHistogram' : { CONNECTION_EVENT },

'EntryConnectionASNoMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionASNoMatchOutboundByteHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASNoMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASNoMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASNoMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASNoMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASNoMatchOutboundByteHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASNoMatchOutboundByteHistogram' : { CONNECTION_EVENT },

# circuit count histograms by connection
'EntryConnectionASNoMatchCircuitHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionASNoMatchCircuitHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASNoMatchCircuitHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASNoMatchCircuitHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASNoMatchCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASNoMatchCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASNoMatchCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASNoMatchCircuitHistogram' : { CONNECTION_EVENT },

'EntryConnectionASNoMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionASNoMatchInboundCircuitHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASNoMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASNoMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASNoMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASNoMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASNoMatchInboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASNoMatchInboundCircuitHistogram' : { CONNECTION_EVENT },

'EntryConnectionASNoMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionASNoMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASNoMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASNoMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASNoMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASNoMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASNoMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASNoMatchOutboundCircuitHistogram' : { CONNECTION_EVENT },

# connection lifetime histograms
'EntryConnectionASNoMatchLifeTime' : { CONNECTION_EVENT },
'NonEntryConnectionASNoMatchLifeTime' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASNoMatchLifeTime' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASNoMatchLifeTime' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASNoMatchLifeTime' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASNoMatchLifeTime' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASNoMatchLifeTime' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASNoMatchLifeTime' : { CONNECTION_EVENT },

# the number of simultaneous connections from the same IP address as a histogram
'EntryConnectionASNoMatchOverlapHistogram' : { CONNECTION_EVENT },
'NonEntryConnectionASNoMatchOverlapHistogram' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASNoMatchOverlapHistogram' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASNoMatchOverlapHistogram' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASNoMatchOverlapHistogram' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASNoMatchOverlapHistogram' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASNoMatchOverlapHistogram' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASNoMatchOverlapHistogram' : { CONNECTION_EVENT },

# count lists for AS numbers that match each list
# the final bin is used for AS numbers that don't match any list
# simple connection counts
'EntryConnectionASMatchCountList' : { CONNECTION_EVENT },
'NonEntryConnectionASMatchCountList' : { CONNECTION_EVENT },

# connection counts based on the number of relays sharing the remote address
'Entry0RelayOnAddressConnectionASMatchCountList' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASMatchCountList' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASMatchCountList' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASMatchCountList' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASMatchCountList' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASMatchCountList' : { CONNECTION_EVENT },

# byte counts
'EntryConnectionASMatchByteCountList' : { CONNECTION_EVENT },
'NonEntryConnectionASMatchByteCountList' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASMatchByteCountList' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASMatchByteCountList' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASMatchByteCountList' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASMatchByteCountList' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASMatchByteCountList' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASMatchByteCountList' : { CONNECTION_EVENT },

'EntryConnectionASMatchInboundByteCountList' : { CONNECTION_EVENT },
'NonEntryConnectionASMatchInboundByteCountList' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASMatchInboundByteCountList' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASMatchInboundByteCountList' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASMatchInboundByteCountList' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASMatchInboundByteCountList' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASMatchInboundByteCountList' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASMatchInboundByteCountList' : { CONNECTION_EVENT },

'EntryConnectionASMatchOutboundByteCountList' : { CONNECTION_EVENT },
'NonEntryConnectionASMatchOutboundByteCountList' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASMatchOutboundByteCountList' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASMatchOutboundByteCountList' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASMatchOutboundByteCountList' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASMatchOutboundByteCountList' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASMatchOutboundByteCountList' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASMatchOutboundByteCountList' : { CONNECTION_EVENT },

# circuit counts
'EntryConnectionASMatchCircuitCountList' : { CONNECTION_EVENT },
'NonEntryConnectionASMatchCircuitCountList' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASMatchCircuitCountList' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASMatchCircuitCountList' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASMatchCircuitCountList' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASMatchCircuitCountList' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASMatchCircuitCountList' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASMatchCircuitCountList' : { CONNECTION_EVENT },

'EntryConnectionASMatchInboundCircuitCountList' : { CONNECTION_EVENT },
'NonEntryConnectionASMatchInboundCircuitCountList' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASMatchInboundCircuitCountList' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASMatchInboundCircuitCountList' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASMatchInboundCircuitCountList' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASMatchInboundCircuitCountList' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASMatchInboundCircuitCountList' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASMatchInboundCircuitCountList' : { CONNECTION_EVENT },

'EntryConnectionASMatchOutboundCircuitCountList' : { CONNECTION_EVENT },
'NonEntryConnectionASMatchOutboundCircuitCountList' : { CONNECTION_EVENT },

'Entry0RelayOnAddressConnectionASMatchOutboundCircuitCountList' : { CONNECTION_EVENT },
'Entry1RelayOnAddressConnectionASMatchOutboundCircuitCountList' : { CONNECTION_EVENT },
'Entry2RelayOnAddressConnectionASMatchOutboundCircuitCountList' : { CONNECTION_EVENT },
'NonEntry0RelayOnAddressConnectionASMatchOutboundCircuitCountList' : { CONNECTION_EVENT },
'NonEntry1RelayOnAddressConnectionASMatchOutboundCircuitCountList' : { CONNECTION_EVENT },
'NonEntry2RelayOnAddressConnectionASMatchOutboundCircuitCountList' : { CONNECTION_EVENT },

# these counters depend on HSDir stored
# Keep versions separate
'HSDir2StoreCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreCount' : { HSDIR_STORE_EVENT },
# HSDirStoreCount, for 2/3, Add/Reject
'HSDir2StoreAddCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreAddCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreRejectCount' : { HSDIR_STORE_EVENT },

# HSDirStoreCount, for 2 only, ClientAuth
'HSDir2StoreClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreNoClientAuthCount' : { HSDIR_STORE_EVENT },
# HSDirStoreCount, for 2 only, Add, ClientAuth
'HSDir2StoreAddClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddNoClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectNoClientAuthCount' : { HSDIR_STORE_EVENT },

# HSDirStoreCount, for each valid version, action, reason and
# optional have cached descriptor combination
'HSDir2StoreAddNewCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreAddNewCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddUpdatedCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreAddUpdatedCount' : { HSDIR_STORE_EVENT },
# v2 only
'HSDir2StoreRejectDuplicateCount' : { HSDIR_STORE_EVENT },
# All other reasons imply HaveCached or NoCached
'HSDir2StoreRejectExpiredHaveCachedCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectExpiredNoCachedCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectFutureHaveCachedCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectFutureNoCachedCount' : { HSDIR_STORE_EVENT },
# Both versions
'HSDir2StoreRejectObsoleteCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreRejectObsoleteCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectUnparseableCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreRejectUnparseableCount' : { HSDIR_STORE_EVENT },

# HSDirStoreCount, for v2 only, and each valid action, reason, client auth and
# optional have cached descriptor combination
'HSDir2StoreAddNewClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddNewNoClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddUpdatedClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddUpdatedNoClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectDuplicateClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectDuplicateNoClientAuthCount' : { HSDIR_STORE_EVENT },
# All other reasons imply HaveCached or NoCached
# Unparseable descriptors have unknown Client Auth
'HSDir2StoreRejectExpiredHaveCachedClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectExpiredHaveCachedNoClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectExpiredNoCachedClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectExpiredNoCachedNoClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectFutureHaveCachedClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectFutureHaveCachedNoClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectFutureNoCachedClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectFutureNoCachedNoClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectObsoleteClientAuthCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectObsoleteNoClientAuthCount' : { HSDIR_STORE_EVENT },

# From here on, we just focus on the subcategories we're interested in
# To add extra subcategories, add the counter name here (and in the TS config)
# (No extra code is required in the Aggregator)

# v2 only, NoClientAuth only
'HSDir2StoreIntroPointHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddIntroPointHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectIntroPointHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddNewIntroPointHistogram' : { HSDIR_STORE_EVENT },

# Total Counts
# Both versions, but a different format
'HSDir2StoreIntroByteCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreIntroByteCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddIntroByteCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreAddIntroByteCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectIntroByteCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreRejectIntroByteCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddNewIntroByteCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreAddNewIntroByteCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddUpdatedIntroByteCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreAddUpdatedIntroByteCount' : { HSDIR_STORE_EVENT },
# v2 only
'HSDir2StoreClientAuthIntroByteCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreNoClientAuthIntroByteCount' : { HSDIR_STORE_EVENT },

# Value Distribution Details
# Both versions, but a different format
'HSDir2StoreIntroByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir3StoreIntroByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddIntroByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir3StoreAddIntroByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectIntroByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir3StoreRejectIntroByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddNewIntroByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir3StoreAddNewIntroByteHistogram' : { HSDIR_STORE_EVENT },
# v2 only
'HSDir2StoreClientAuthIntroByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreNoClientAuthIntroByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddClientAuthIntroByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddNoClientAuthIntroByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddNewClientAuthIntroByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddNewNoClientAuthIntroByteHistogram' : { HSDIR_STORE_EVENT },

# Total Counts
# Both versions, but a different format
'HSDir2StoreDescriptorByteCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreDescriptorByteCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddDescriptorByteCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreAddDescriptorByteCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectDescriptorByteCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreRejectDescriptorByteCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddNewDescriptorByteCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreAddNewDescriptorByteCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddUpdatedDescriptorByteCount' : { HSDIR_STORE_EVENT },
'HSDir3StoreAddUpdatedDescriptorByteCount' : { HSDIR_STORE_EVENT },
# v2 only
'HSDir2StoreClientAuthDescriptorByteCount' : { HSDIR_STORE_EVENT },
'HSDir2StoreNoClientAuthDescriptorByteCount' : { HSDIR_STORE_EVENT },

# Value Distribution Details
# Both versions, but a different format
'HSDir2StoreDescriptorByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir3StoreDescriptorByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddDescriptorByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir3StoreAddDescriptorByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectDescriptorByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir3StoreRejectDescriptorByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddNewDescriptorByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir3StoreAddNewDescriptorByteHistogram' : { HSDIR_STORE_EVENT },
# v2 only
'HSDir2StoreClientAuthDescriptorByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreNoClientAuthDescriptorByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddClientAuthDescriptorByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddNoClientAuthDescriptorByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddNewClientAuthDescriptorByteHistogram' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddNewNoClientAuthDescriptorByteHistogram' : { HSDIR_STORE_EVENT },

# v2 only
'HSDir2StoreUploadDelayTime' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddUploadDelayTime' : { HSDIR_STORE_EVENT },
'HSDir2StoreRejectUploadDelayTime' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddNewUploadDelayTime' : { HSDIR_STORE_EVENT },
'HSDir2StoreAddUpdatedUploadDelayTime' : { HSDIR_STORE_EVENT },

# v3 only
'HSDir3StoreRevisionHistogram' : { HSDIR_STORE_EVENT },
'HSDir3StoreAddRevisionHistogram' : { HSDIR_STORE_EVENT },
'HSDir3StoreRejectRevisionHistogram' : { HSDIR_STORE_EVENT },
'HSDir3StoreAddNewRevisionHistogram' : { HSDIR_STORE_EVENT },
'HSDir3StoreAddUpdatedRevisionHistogram' : { HSDIR_STORE_EVENT },

# descriptor fetch counters
'HSDir2FetchCount' : { HSDIR_FETCH_EVENT },
'HSDir3FetchCount' : { HSDIR_FETCH_EVENT },

'HSDir2FetchCachedCount' : { HSDIR_FETCH_EVENT },
'HSDir2FetchUncachedCount' : { HSDIR_FETCH_EVENT },
'HSDir3FetchCachedCount' : { HSDIR_FETCH_EVENT },
'HSDir3FetchUncachedCount' : { HSDIR_FETCH_EVENT },

# the sanity check counter doesn't depend on any events
DEFAULT_DUMMY_COUNTER_NAME : set(),
}

def register_dynamic_counter(counter_name, counter_events):
    '''
    Register counter_name as a counter which uses the events in counter_events.
    If counter_name is already a registered counter, updates the list of events
    for counter.
    This should be called before the counters are checked:
    - in the Tally Server, early in refresh_config,
    - in PrivCountClient, early in check_start_config
      (PrivCountClient is a parent class of Data Collector and Share Keeper)
    Any event updates are applied the next time the data collector starts a
    collection phase.
    Logs a message and ignores unknown events.
    '''
    event_set = set()
    for event in counter_events:
        if event in get_valid_events():
            event_set.add(event)
        else:
            logging.warning("Ignoring unknown event {} for dynamic counter {}"
                            .format(event, counter_name))
    PRIVCOUNT_COUNTER_EVENTS[counter_name] = event_set

def get_valid_counters():
    '''
    Return a set containing the name of each privcount counter, in titlecase.
    (Or whatever the canonical case of the counter name is.)
    '''
    counter_set = set(PRIVCOUNT_COUNTER_EVENTS.keys())
    # we can't check case consistency, so just return the set
    return counter_set

def get_events_for_counter(counter):
    '''
    Return the set of events required by counter
    '''
    # when you add an event, but forget to update the table above,
    # you will get an error here
    logging.debug("Finding events for counter: '{}'".format(counter))
    try:
        event_set = PRIVCOUNT_COUNTER_EVENTS[counter]
    except KeyError as e:
        logging.error("Missing events for counter: '{}'".format(counter))
        raise
    assert check_event_set_valid(event_set)
    return event_set

def get_events_for_counters(counter_list):
    '''
    Return the set of events required by at least one of the counters in
    counter_list.
    '''
    event_set = set()
    if counter_list is not None:
        for counter in counter_list:
            counter_events = get_events_for_counter(counter)
            event_set = event_set.union(counter_events)
    assert check_event_set_valid(event_set)
    return event_set

def get_events_for_known_counters():
    '''
    Return the set of events required by at least one of the counters we know
    about.
    '''
    return get_events_for_counters(PRIVCOUNT_COUNTER_EVENTS.keys())

def get_circuit_sample_events():
    '''
    Return the set of events affected by circuit_sample_rate.
    '''
    event_set = { CELL_EVENT,
                  BYTES_EVENT,
                  STREAM_EVENT,
                  CIRCUIT_EVENT,
                  # Not affected
                  #CONNECTION_EVENT,
                  #HSDIR_STORE_EVENT,
                  # Unused events
                  DNS_EVENT,
                  LEGACY_CIRCUIT_EVENT,
                  }
    return event_set

def is_circuit_sample_counter(counter):
    '''
    If counter uses an event affected by circuit_sample_rate, return True.
    Otherwise, return False.
    '''
    counter_events = get_events_for_counter(counter)
    circuit_sample_events = get_circuit_sample_events()
    common_events = counter_events.intersection(circuit_sample_events)
    return len(common_events) > 0

def are_events_expected(counter_list, relay_flag_list):
    '''
    Return True if we expect to receive regular events while collecting
    counter_list, on a relay with the consensus flags in relay_flag_list.
    relay_flag_list must be a list, not a string.
    Return False if we don't expect to receive events regularly.
    '''
    # It really does need to be a list
    if isinstance(relay_flag_list, (str, unicode)):
        relay_flag_list = relay_flag_list.split()
    # no counters
    if counter_list is None or len(counter_list) == 0:
        return False
    event_list = get_events_for_counters(counter_list)
    # no events: ZeroCount only
    if event_list is None or len(event_list) == 0:
        return False
    has_entry = "Guard" in relay_flag_list
    has_exit = "Exit" in relay_flag_list
    # relay_flag_list must be a list to avoid a substring match
    has_hsdir2 = "HSDir" in relay_flag_list
    has_hsdir3 = "HSDir3" in relay_flag_list
    for counter_name in counter_list:
        if has_entry and counter_name.startswith("Entry"):
            return True
        if has_exit and counter_name.startswith("Exit"):
            return True
        if has_hsdir2 and counter_name.startswith("HSDir2"):
            return True
        if has_hsdir3 and counter_name.startswith("HSDir3"):
            return True
    # no matching counters and flags
    return False

def check_counter_names(counters):
    '''
    Check that each counter's name is in the set of valid counter names.
    Returns False if any counter name is unknown, True if all are known.
    '''
    # sort names alphabetically, so the logs are in a sensible order
    for counter_name in sorted(counters.keys()):
        if counter_name not in get_valid_counters():
            logging.warning("counter name {} is unknown"
                            .format(counter_name))
            return False
    return True

def count_bins(counters):
    '''
    Returns the total number of bins in counters.
    '''
    return sum([len(counter_config['bins'])
                for counter_config in counters.values()])

def check_bin_count_matches_name(bins):
    '''
    Check that counter names that end in "Count" have a single bin, and
    counter names that end in anything else have multiple bins.
    '''
    # sort names alphabetically, so the logs are in a sensible order
    for key in sorted(bins.keys()):
        bin_count = len(bins[key]['bins'])
        # handle template counters by stripping the non-template part
        key_template, _, _ = key.partition("_")
        # the TrafficModel LogDelayTime counters are single bin
        if key_template.endswith("Count") or key_template.endswith("LogDelayTime"):
            if bin_count != 1:
                logging.warning("counter {} ends in Count, but has {} bins: {}"
                                .format(key, bin_count, bins[key]))
                return False
        else: # Histogram, Ratio, LifeTime, DelayTime, CountList, ...
            if bin_count <= 1:
                logging.warning("counter {} does not end in Count, but has {} bins: {}"
                                .format(key, bin_count, bins[key]))
                return False
    return True

def check_bins_config(bins, allow_unknown_counters=False):
    '''
    Check that bins are non-overlapping.
    Returns True if all bins are non-overlapping, and False if any overlap.
    If allow_unknown_counters is False, also check that all counter names are
    in the set of known counter names for this PrivCount version, returning
    False if there are any unknown counters.
    Raises an exception if any counter does not have bins, or if any bin does
    not have a lower and upper bound
    '''
    if not allow_unknown_counters:
        if not check_counter_names(bins):
            return False
        # unknown counters may have different rules for bin counts
        if not check_bin_count_matches_name(bins):
            return False
    # sort names alphabetically, so the logs are in a sensible order
    for key in sorted(bins.keys()):
        # this sorts the bins by the first element in ascending order
        # (if the first elements are equal, the bins are sorted by the second
        # element)
        sorted_bins = sorted(bins[key]['bins'])
        prev_bin = None
        for bin in sorted_bins:
            # bins are an array [l, u, c], where c counts values such that:
            # l <= value < u
            # c is optional, and is ignored by this code
            l = bin[0]
            u = bin[1]
            # check for inverted bounds
            if l >= u:
                logging.warning("bin {} in counter {} will never count any values, because its lower bound is greater than or equal to its upper bound"
                                .format(bin, key))
                return False
            # make sure we have a bin to compare to
            if prev_bin is not None:
                prev_l = prev_bin[0]
                prev_u = prev_bin[1]
                # two sorted bins overlap if:
                # - their lower bounds are equal, or
                # - the upper bound of a bin is greater than the lower bound
                #   of the next bin
                if prev_l == l:
                    logging.warning("bin {} in counter {} overlaps bin {}: their lower bounds are equal"
                                    .format(prev_bin, key, bin))
                    return False
                elif prev_u > l:
                    logging.warning("bin {} in counter {} overlaps bin {}: the first bin's upper bound is greater than the second bin's lower bound"
                                    .format(prev_bin, key, bin))
                    return False
            prev_bin = bin
    return True

def check_sigmas_config(sigmas, allow_unknown_counters=False):
    '''
    Check that each sigma value in sigmas is valid.
    Returns True if all sigma values are valid, and False if any are invalid.
    If allow_unknown_counters is False, also check that all counter names are
    in the set of known counter names for this PrivCount version, returning
    False if there are any unknown counters.
    Raises an exception if any sigma value is missing.
    '''
    if not allow_unknown_counters:
        if not check_counter_names(sigmas):
            return False
    # sort names alphabetically, so the logs are in a sensible order
    for key in sorted(sigmas.keys()):
        if sigmas[key]['sigma'] < 0.0:
            logging.warning("invalid sigma for counter {}: less than zero".format(key))
            return False
    return True

def extra_counters(first, second, first_name, second_name, action_name):
    '''
    Return the extra counter keys in first that are not in second.
    Warn about taking action_name on any missing counters.
    '''
    extra_keys = _extra_keys(first, second)
    # Log missing keys
    if len(extra_keys) > 0:
        logging.info("{} counters '{}' because they have a {}, but no {}"
                     .format(action_name, summarise_list(extra_keys),
                             first_name, second_name))

    return extra_keys

def common_counters(first, second, first_name, second_name, action_name):
    '''
    Return the counter keys shared by first and second.
    Warn about taking action_name on any missing counters.
    '''
    # ignore the extra counters return values, we just want the logging
    extra_counters(first, second, first_name, second_name, action_name)
    extra_counters(second, first, second_name, first_name, action_name)

    # return common keys
    return _common_keys(first, second)

def _skip_missing(counters, expected_subkey, detailed_source=None):
    '''
    Check that each key in counters has a subkey with the name expected_subkey.
    If any key does not have a subkey named expected_subkey, skip it and log a
    warning.
    If detailed_source is not None, use it to describe the counters.
    Otherwise, use expected_subkey.
    Returns a copy of counters with invalid keys skipped.
    '''
    if detailed_source is None:
        detailed_source = expected_subkey
    valid_counters = {}
    invalid_counters = []
    for key in sorted(counters.keys()):
        if expected_subkey in counters[key]:
            valid_counters[key] = counters[key]
        else:
            invalid_counters.append(key)
    if len(invalid_counters) > 0:
        logging.warning("ignoring counters {} because they are configured as {} counters, but they do not have any {} value"
                        .format(summarise_list(invalid_counters),
                                detailed_source, expected_subkey))
    return valid_counters

def skip_missing_bins(bins, detailed_source=None):
    '''
    Check each key in bins has a bins list.
    If any key does not have a bins list, skip it and log a warning.
    Returns a copy of counters with invalid keys skipped.
    '''
    return _skip_missing(bins, 'bins', detailed_source)

def skip_missing_sigmas(sigmas, detailed_source=None):
    '''
    Check each key in sigmas has a sigma value.
    If any key does not have a sigma, skip it and log a warning.
    Returns a copy of counters with invalid keys skipped.
    '''
    return _skip_missing(sigmas, 'sigma')

def combine_counters(bins, sigmas):
    '''
    Combine the counters in bins and sigmas, excluding any counters that are
    missing from either bins or sigmas.
    Combine the keys and values from both bins and sigmas in the output
    counters, according to what the tally server is permitted to update.
    (Both bins and sigmas are configured at the tally server.)
    Return a dictionary containing the combined keys.
    '''
    # Remove invalid counters
    bins = skip_missing_bins(bins)
    sigmas = skip_missing_sigmas(sigmas)

    # we allow the tally server to update the set of counters
    # (we can't count keys for which we don't have both bins and sigmas)
    common_keys = common_counters(bins, sigmas, 'bins', 'sigma',
                                  'ignoring')

    counters_combined = {}
    for key in common_keys:
        # skip_missing_* ensures these exist
        assert 'bins' in bins[key]
        assert 'sigma' in sigmas[key]
        # Use the values from the sigmas
        counters_combined[key] = deepcopy(sigmas[key])
        # Except for the bin values, which come from bins
        # we allow the tally server to update the bin widths
        counters_combined[key]['bins'] = deepcopy(bins[key]['bins'])
    return counters_combined

def check_combined_counters(bins, sigmas):
    '''
    Sanity check bins against sigmas.
    Returns False if:
      - the set of counters in bins and sigmas is not the same, or
      - any counter is missing bins, or
      - any counter is missing a sigma, or
      - any counter is duplicated.
    '''
    combined_counters = combine_counters(bins, sigmas)
    return (len(combined_counters) == len(bins) and
            len(combined_counters) == len(sigmas))

def check_counters_config(bins, sigmas, allow_unknown_counters=False):
    '''
    Sanity check bins and sigmas individually.
    Check that bins and sigmas have the same set of counters.
    If allow_unknown_counters is False, also check that all counter names are
    in the set of known counter names for this PrivCount version.
    '''
    return (check_bins_config(bins,
                          allow_unknown_counters=allow_unknown_counters) and
            check_sigmas_config(sigmas,
                          allow_unknown_counters=allow_unknown_counters) and
            check_combined_counters(bins, sigmas))

def float_representation_accuracy():
    '''
    When converting an exact number to a python float, the maximum possible
    proportional change in the value of the float.
    For the exact number n, converting n to a float could change the value by
    at most +/- n * float_representation_accuracy().
    Returns a floating point number representing the maximum relative increase
    or decrease in the value of the original exact number.
    '''
    # When converting an exact value to a python float, the maximum possible
    # proportional change is half the distance between one float value and the
    # next largest or smallest float value.
    # Conventiently, the distance between adjacent floats is at most the float
    # epsilon multiplied by the value of the float, as the distance between
    # adjacent floats scales as they get larger or smaller.
    # On most platforms, the float epsilon is 2 ** -53.
    return sys.float_info.epsilon/2.0

def float_string_accuracy():
    '''
    When converting a python float to a string and back, the maximum possible
    proportional change in the value of the float.
    For the float f, converting f to a string and back could change the value
    by at most +/- f * float_string_accuracy().
    Returns a floating point number representing the maximum relative increase
    or decrease in the value of the original float.
    '''
    # sys.float_info.dig is the number of significant figures that are
    # guaranteed to be preserved when converting a float to a string and
    # then back to a float (PrivCount does this when sending sigma between
    # the TS and the SKs/DCs).
    # This is based on python's float repr() rule, introduced in versions 2.7
    # and 3.1:
    # Python "displays a value based on the shortest decimal fraction that
    # rounds correctly back to the true binary value"
    # On most 32 and 64-bit platforms, sys.float_info.dig is 15 digits.
    # Therefore, the maximum change in value that can occur is the 15th digit
    # (of least significance) changing by +/- 1.
    # But we can't just multiply the original value by 10 ** -15, because
    # the (significand of the) float can have any value in [0.1, 0.999...].
    # Therefore, we need to multiply the tolerance by another 10x.
    # This gives us a tolerance of 10 ** -14 on most systems.
    return 10.0 ** (-sys.float_info.dig + 1)

def float_accuracy():
    '''
    The maximum proportional change in an exact value when converted to a
    float, then a string, then back to a float.
    For the exact number n, converting n to a float then string then float
    could change the value by at most +/- n * float_accuracy().
    Returns a floating point number representing the maximum relative increase
    or decrease in the value of the original exact number.
    '''
    # If the inaccuracies are both in the same direction, the total inaccuracy
    # is the sum of all inaccuracies
    return float_representation_accuracy() + float_string_accuracy()

class CollectionDelay(object):
    '''
    Ensures a configurable delay between rounds with different noise
    allocations.
    Usage:
    (the SKs must enforce these checks for the protocol to be secure
     the TS does these checks for convenience, the DCs for defence in depth)
    TS: configures round
        uses get_next_round_start_time() for status updates
        checks round_start_permitted() before starting collection
    DC: checks round_start_permitted() before sending blinding shares
    SK: checks round_start_permitted() before accepting blinding shares
    (round runs)
    DC: set_delay_for_stop() when round stops and counters are sent
    SK: set_delay_for_stop() when round stops and blinding shares are sent
    TS: set_delay_for_stop() when round ends successfully
    (repeat for next round, if TS has continue set in its config)
    '''

    def __init__(self):
        '''
        Initialise the noise allocations and times required to track collection
        delays.
        '''
        # The earliest noise allocation in a series of equivalent noise
        # allocations
        self.starting_noise_allocation = None
        # The end time of the successful round to use an equivalent allocation
        self.last_round_end_time = None

    DEFAULT_SIGMA_DECREASE_TOLERANCE = DEFAULT_SIGMA_TOLERANCE

    @staticmethod
    def sigma_change_needs_delay(
            previous_sigma, proposed_sigma,
            tolerance=DEFAULT_SIGMA_DECREASE_TOLERANCE,
            logging_label=None):
        '''
        Check if there should be a delay between rounds using the previous
        and proposed sigma values for the same counter.
        A counter can use two sigma values without a delay between them if:
        - The values are equal (within a small tolerance), or
        - The proposed value is greater than the previous value.
        Returns True if the sigma values need a delay, False if they do not.
        '''
        assert previous_sigma >= 0
        assert proposed_sigma >= 0
        assert tolerance >= 0
        if proposed_sigma >= previous_sigma:
            # the sigma has increased: no delay required
            return False
        elif previous_sigma - proposed_sigma <= tolerance:
            # the sigma has decreased, but not by enough to matter
            return False
        # the sigma has decreased too much - enforce a delay
        if logging_label is not None:
            logging.warning("Delaying round: proposed sigma %.2g is less than previous sigma %.2g, and not within tolerance %.2g, in counter %s",
                            proposed_sigma,
                            previous_sigma,
                            tolerance,
                            logging_label)
        return True

    @staticmethod
    def noise_change_needs_delay(
            previous_allocation, proposed_allocation,
            tolerance=DEFAULT_SIGMA_DECREASE_TOLERANCE):
        '''
        Check if there should be a delay between rounds using the previous
        and proposed noise allocations.
        Two allocations can be used without a delay between them if:
        - They have the same keys, and
        - The sigma values for those keys do not need a delay, using the
          acceptable sigma decrease tolerance.
        Returns True if the allocations need a delay, False if they do not.
        '''
        # There must be an allocation for a valid round
        assert proposed_allocation is not None
        assert tolerance >= 0
        # No delay for the first round
        if previous_allocation is None:
            return False

        # Ignore and log missing sigmas
        previous_sigmas = skip_missing_sigmas(previous_allocation['counters'],
                                              'previous sigma')
        proposed_sigmas = skip_missing_sigmas(proposed_allocation['counters'],
                                              'proposed sigma')

        # Check that we have the same set of counters
        common_sigmas = common_counters(previous_sigmas, proposed_sigmas,
                                        'previous sigma', 'proposed sigma',
                                        "can't compare sigmas on")
        if len(common_sigmas) != len(previous_sigmas):
            return True
        if len(common_sigmas) != len(proposed_sigmas):
            return True

        # check the sigma values are the same
        for key in sorted(common_sigmas):
            if CollectionDelay.sigma_change_needs_delay(
                previous_sigmas[key]['sigma'],
                proposed_sigmas[key]['sigma'],
                tolerance=tolerance,
                logging_label=key):
                return True
        return False

    def get_next_round_start_time(
            self, noise_allocation, delay_period,
            max_client_rtt=0.0,
            always_delay=False,
            tolerance=DEFAULT_SIGMA_DECREASE_TOLERANCE):
        '''
        Return the earliest time at which a round with noise allocation could
        start, where delay_period is the configurable delay.
        If always_delay is True, always delay the round by delay_period.
        (This is intended for use while testing.)
        max_client_rtt is the maximum client RTT of all clients (only used by
        the Tally Server).
        tolerance is the acceptable sigma decrease.
        '''
        # there must be a configured delay_period (or a default must be used)
        assert delay_period >= 0
        # that is, it must be boolean-coercible
        assert always_delay or not always_delay
        # there must be a noise allocation for the next round
        assert noise_allocation is not None
        assert tolerance >= 0

        noise_change_delay = self.noise_change_needs_delay(
                                      self.starting_noise_allocation,
                                      noise_allocation,
                                      tolerance=tolerance)
        needs_delay = always_delay or noise_change_delay

        if noise_change_delay:
            # if there was a change, there must have been a previous allocation
            assert self.starting_noise_allocation

        if self.last_round_end_time is None:
            # a delay is meaningless, there have been no previous successful
            # rounds
            # we can start any time
            return 0
        elif needs_delay:
            # if there was a previous round, and we need to delay after it,
            # there must have been an end time for that round
            next_start_time = self.last_round_end_time + delay_period + max_client_rtt
            return next_start_time
        else:
            # we can start any time after the last round ended
            return self.last_round_end_time

    def round_start_permitted(
            self, noise_allocation, start_time, delay_period,
            max_client_rtt=0.0,
            always_delay=False,
            tolerance=DEFAULT_SIGMA_DECREASE_TOLERANCE,
            logging_function=logging.debug):
        '''
        Check if we are permitted to start a round with noise allocation
        at start time, with the configured delay_period and max_client_rtt.
        If always_delay is True, always delay the round by delay_period.
        (This is intended for use while testing.)
        max_client_rtt is the maximum client RTT of all clients (only used by
        the Tally Server).
        tolerance is the acceptable sigma decrease.
        Return True if starting the round is permitted.
        If it is not, return False, and log a message using logging_function.
        '''
        # there must be a start time
        assert start_time >= 0
        # all the other assertions are in this function
        next_start_time = self.get_next_round_start_time(noise_allocation,
                                                         delay_period,
                                                         max_client_rtt=max_client_rtt,
                                                         always_delay=always_delay,
                                                         tolerance=tolerance)
        if start_time >= next_start_time:
            return True
        else:
            if always_delay:
                delay_reason = "we are configured to always delay"
            else:
                delay_reason = "noise allocation changed"
            logging_function("Delaying round for %s because %s",
                             format_delay_time_until(next_start_time,
                                                     'until'),
                             delay_reason)
            return False

    def set_delay_for_stop(
            self, round_successful, noise_allocation, start_time, end_time,
            delay_period,
            max_client_rtt=0.0,
            always_delay=False,
            tolerance=DEFAULT_SIGMA_DECREASE_TOLERANCE):
        '''
        Called when a round ends.
        If the new noise allocation is not equivalent to the stored noise,
        update the stored noise. Update the stored last round end time.
        No updates are performed for failed rounds.
        Log a warning if it appears that the round was started too early.
        (This can also occur if the config is changed mid-round.)
        If always_delay is True, assume the round was delayed, regardless of
        the noise allocation. (This is intended for use while testing.)
        max_client_rtt is the maximum client RTT of all clients (only used by
        the Tally Server).
        tolerance is the acceptable sigma decrease.
        '''
        # make sure we haven't violated our own preconditions
        # that is, it must be boolean-coercible
        assert round_successful or not round_successful
        assert noise_allocation is not None
        assert start_time >= 0
        assert end_time >= 0
        assert start_time < end_time
        assert delay_period >= 0
        assert always_delay or not always_delay
        assert tolerance >= 0
        # did we forget to check if we needed to delay this round?
        # warn, because this can happen if the delay is reconfigured,
        # or if another node fails a round because it starts sooner than its
        # configured delay, or if the Tally server asks for results twice
        if not self.round_start_permitted(noise_allocation,
                                          start_time,
                                          delay_period,
                                          max_client_rtt=max_client_rtt,
                                          always_delay=always_delay,
                                          tolerance=tolerance):
            expected_start = self.get_next_round_start_time(noise_allocation,
                                                            delay_period,
                                                            max_client_rtt=max_client_rtt,
                                                            always_delay=always_delay,
                                                            tolerance=tolerance)
            status = "successfully stopped" if round_successful else "stopped unexpectedly (failure or duplicate event)"
            logging.warning("Round that just {} was started {} before enforced delay elapsed. Round started {}, expected start {}."
                            .format(status,
                                    format_period(expected_start - start_time),
                                    format_elapsed_time_since(start_time,
                                                              'at'),
                                    format_elapsed_time_since(expected_start,
                                                              'at')))
        if round_successful:
            # The end time is always updated
            self.last_round_end_time = end_time
            if self.starting_noise_allocation is None or always_delay:
                # It's the first noise allocation this run, or it's a
                # noise allocation for which we've delayed collection
                self.starting_noise_allocation = noise_allocation
            elif not self.noise_change_needs_delay(
                              self.starting_noise_allocation,
                              noise_allocation,
                              tolerance=tolerance):
                # The latest noise allocation could have been used immediately
                # after the starting noise allocation.
                # Keep the starting noise allocation, so that a TS can't
                # gradually decrease the noise each round
                pass
            else:
                # It's a noise allocation from a successful round, and it's
                # different enough from the starting allocation. Assume we
                # waited for the enforced delay before the round started.
                self.starting_noise_allocation = noise_allocation

def noise(sigma, sum_of_sq, p_exit):
    '''
    Sample noise from a gussian distribution
    the distribution is over +/- sigma, scaled by the noise weight, which is
    calculated from the exit probability p_exit, and the overall sum_of_sq
    bandwidth
    returns a floating-point value between +sigma and -sigma, scaled by
    noise_weight
    '''
    sigma_i = p_exit * sigma / sqrt(sum_of_sq)
    # the noise needs to be cryptographically secure, because knowing the RNG
    # state could allow an adversary to remove the noise
    random_sample = SystemRandom().gauss(0, sigma_i)
    return random_sample

def sample(modulus):
    '''
    Sample a uniformly distributed value from the SystemRandom CSPRNG
    (uses rejection sampling to avoid bias)
    returns a long uniformly distributed in [0, modulus)
    '''
    # sanitise input
    modulus = long(modulus)
    assert modulus > 0
    # to get values up to modulus-1, we need this many bits
    sample_bit_count = (modulus-1).bit_length()
    # handle the case where modulus is 1
    if sample_bit_count == 0:
        sample_bit_count = 1
    # check the bit count is sane
    assert modulus <= 2L**sample_bit_count
    assert modulus >= 2L**(sample_bit_count-1)
    ## Unbiased sampling through rejection sampling
    while True:
        # sample that many bits
        v = SystemRandom().getrandbits(sample_bit_count)
        assert v >= 0
        assert v < 2L**sample_bit_count
        # the maximum rejection rate is 1 in 2, when modulus is 2**N + 1
        if 0L <= v < modulus:
            break
    return v

def sample_randint(a, b):
    """
    Like random.randint(), returns a random long N such that a <= N <= b.
    """
    return a + sample(b - a + 1)

def derive_blinding_factor(secret, modulus, positive=True):
    '''
    Calculate a blinding factor less than modulus, based on secret
    If secret is None, sample a blinding factor and return it
    When positive is True, returns the blinding factor, and when positive is
    False, returns the unblinding factor (the inverse value mod modulus)
    Typically called as:
      blinding   = derive_blinding_factor(None,     counter_modulus(), True)
      unblinding = derive_blinding_factor(blinding, counter_modulus(), False)
    '''
    # sanitise input
    modulus = long(modulus)
    if secret is None:
        v = sample(modulus)
    else:
        # sanitise input
        v = long(secret)
    assert v < modulus
    s0 = v if positive else modulus - v
    return s0

def adjust_count_signed(count, modulus):
    '''
    Adjust the unsigned 0 <= count < modulus, returning a signed integer
    For odd  modulus, returns { -modulus//2, ... , 0, ... , modulus//2 }
    For even modulus, returns { -modulus//2, ... , 0, ... , modulus//2 - 1 }
    The smallest positive values >= modulus//2 [- 1] become the largest
    negative values
    This is the inverse operation of x % modulus, when x is in the appropriate
    range (x % modulus always returns a positive integer when modulus is
    positive)
    '''
    # sanitise input
    count = long(count)
    modulus = long(modulus)
    # sanity check input
    assert count < modulus
    # When implementing this adjustment,
    # { 0, ... , (modulus + 1)//2 - 1}  is interpreted as that value,
    # { (modulus + 1)//2, ... , modulus - 1 } is interpreted as
    # that value minus modulus, or
    # { (modulus + 1)//2 - modulus, ... , modulus - 1 - modulus }
    #
    # For odd modulus, (modulus + 1)//2 rounds up to modulus//2 + 1, so the
    # positive case simplifies to:
    # { 0, ... , modulus//2 + 1 - 1 }
    # { 0, ... , modulus//2 }
    # and because modulus == modulus//2 + modulus//2 + 1 for odd modulus, the
    # negative case simplifies to:
    # { modulus//2 + 1 - modulus//2 - modulus//2 - 1, ... ,
    #   modulus - 1 - modulus}
    # { -modulus//2, ... , -1 }
    # Odd modulus has the same number of values above and below 0:
    # { -modulus//2, ... , 0, ... , modulus//2 }
    #
    # For even modulus, (modulus+1)//2 rounds down to modulus//2, so the
    # positive case simplifies to:
    # { 0, ... , modulus//2 - 1 }
    # and because modulus == modulus//2 + modulus//2 for even modulus, the
    # negative case simplifies to:
    # { modulus//2 - modulus//2 - modulus//2, ... , modulus - 1 - modulus}
    # { -modulus//2, ... , -1 }
    # Even modulus has the 1 more value below 0 than above it:
    # { -modulus//2, ... , 0, ... , modulus//2 - 1 }
    # This is equivalent to signed two's complement, if modulus is an integral
    # power of two
    if count >= ((modulus + 1L) // 2L):
        signed_count = count - modulus
    else:
        signed_count = count
    # sanity check output
    assert signed_count >= -modulus//2L
    if modulus % 2L == 1L:
        # odd case
        assert signed_count <= modulus//2L
    else:
        # even case
        assert signed_count <= modulus//2L - 1L
    return signed_count

class SecureCounters(object):
    '''
    securely count any number of labels
    counters should be in the form like this:
    {
      'CircuitCellsInOutRatio': {
        'bins':
        [
          [0.0, 0.1],
          [0.1, 0.25],
          [0.25, 0.5],
          [0.5, 0.75],
          [0.75, 0.9],
          [0.9, 1.0],
          [1.0, float('inf')],
        ],
        'sigma': 2090007.68996
      },
      'EntryCircuitInboundCellHistogram': {
        'bins':
        [
          [0.0, 512.0],
          [512.0, 1024.0],
          [1024.0, 2048.0],
          [2048.0, 4096.0],
          [4096.0, float('inf')],
        ],
        'sigma': 2090007.68996
      }
    }
    All of data collectors, share keepers, and tally server use this to store
    counters.
    It is used approximately like this:

    data collector:
    init(), generate_blinding_shares(), detach_blinding_shares(),
    generate_noise(), increment()[repeated],
    detach_counts()
    the blinding shares are sent to each share keeper
    the counts are sent to the tally server at the end

    share keeper:
    init(), import_blinding_share()[repeated], detach_counts()
    import..() uses the shares from each data collector
    the counts are sent to the tally server at the end

    tally server:
    init(), tally_counters(), detach_counts()
    tally..() uses the counts received from all of the data collectors and
    share keepers
    this produces the final, unblinded, noisy counts of the privcount process

    see privcount/test/test_counters.py for some test cases
    '''

    def __init__(self, counters, modulus, require_generate_noise=True):
        '''
        deepcopy counters and initialise each counter to 0L
        cast modulus to long and store it
        If require_generate_noise is True, assert if we did not add noise
        before detaching the counters
        '''
        self.counters = deepcopy(counters)
        self.modulus = long(modulus)
        self.shares = None
        self.is_noise_pending = require_generate_noise

        # initialize all counters to 0L
        # counters use unlimited length integers to avoid overflow
        for key in self.counters:
            assert('bins' in self.counters[key])
            for item in self.counters[key]['bins']:
                assert len(item) == 2
                # bin is now, e.g.: [0.0, 512.0, 0L] for bin_left, bin_right,
                # count
                item.append(0L)

        # take a copy of the zeroed counters to use when generating blinding
        # factors
        self.zero_counters = deepcopy(self.counters)

    def _check_counter(self, counter):
        '''
        Check that the keys and bins in counter match self.counters
        Also check that each bin has a count.
        If these checks pass, return True. Otherwise, return False.
        '''
        for key in self.counters:
            if key not in counter:
                return False
            # disregard sigma, it's only required at the data collectors
            if 'bins' not in counter[key]:
                return False
            num_bins = len(self.counters[key]['bins'])
            if num_bins == 0:
                return False
            if num_bins != len(counter[key]['bins']):
                return False
            for i in xrange(num_bins):
                tally_item = counter[key]['bins'][i]
                if len(tally_item) != 3:
                    return False
        return True

    def _derive_all_counters(self, blinding_factors, positive):
        '''
        If blinding_factors is None, generate and apply a counters structure
        containing uniformly random blinding factors.
        Otherwise, apply the passed blinding factors.
        If positive is True, apply blinding factors. Otherwise, apply
        unblinding factors.
        Returns the applied (un)blinding factors, or None on error.
        '''
        # if there are no blinding_factors, initialise them to zero
        generate_factors = False
        if blinding_factors is None:
            blinding_factors = deepcopy(self.zero_counters)
            generate_factors = True

        # validate that the counter data structures match
        if not self._check_counter(blinding_factors):
            return None

        # determine the blinding factors
        for key in blinding_factors:
            for item in blinding_factors[key]['bins']:
                if generate_factors:
                    original_factor = None
                else:
                    original_factor = long(item[2])
                blinding_factor = derive_blinding_factor(original_factor,
                                                         self.modulus,
                                                         positive=positive)
                item[2] = blinding_factor

        # add the blinding factors to the counters
        self._tally_counter(blinding_factors)

        # return the applied blinding factors
        return blinding_factors

    def _blind(self):
        '''
        Generate and apply a counters structure containing uniformly random
        blinding factors.
        Returns the generated blinding factors.
        '''
        generated_counters = self._derive_all_counters(None, True)
        # since we generate blinding factors based on our own inputs, a
        # failure here is a programming bug
        assert generated_counters is not None
        return generated_counters

    def _unblind(self, blinding_factors):
        '''
        Generate unblinding factors from blinding_factors, and apply them to
        self.counters.
        Returns the applied unblinding factors.
        '''
        # since we generate unblinding factors based on network input, a
        # failure here should be logged, and the counters ignored
        return self._derive_all_counters(blinding_factors, False)

    def generate_blinding_shares(self, uids):
        '''
        Generate and apply blinding factors for each counter and share keeper
        uid.
        '''
        self.shares = {}
        for uid in uids:
            # add blinding factors to all of the counters
            blinding_factors = self._blind()
            # the caller can add additional annotations to this dictionary
            self.shares[uid] = {'secret': blinding_factors, 'sk_uid': uid}

    def generate_noise(self, noise_weight):
        '''
        Generate and apply noise for each counter.
        '''
        # generate noise for each counter independently
        noise_values = deepcopy(self.zero_counters)
        for key in noise_values:
            for item in noise_values[key]['bins']:
                sigma = noise_values[key]['sigma']
                sampled_noise = noise(sigma, 1, noise_weight)
                # exact halfway values are rounded towards even integers
                # values over 2**53 are not integer-accurate
                # but we don't care, because it's just noise
                item[2] = long(round(sampled_noise))

        # add the noise to each counter
        self._tally_counter(noise_values)
        self.is_noise_pending = False

    def detach_blinding_shares(self):
        '''
        Deletes this class' reference to self.shares.
        Does not securely delete, as python does not have secure delete.
        Detaches and returns the value of self.shares.
        Typically, the caller then uses encrypt() on the returned shares.
        '''
        shares = self.shares
        # TODO: secure delete
        # del only deletes the reference binding
        # deallocation is implementation-dependent
        del self.shares
        self.shares = None
        return shares

    def import_blinding_share(self, share):
        '''
        Generate and apply reverse blinding factors to all of the counters.
        If encrypted, these blinding factors must be decrypted and decoded by
        the caller using decrypt(), before calling this function.
        Returns True if unblinding was successful, and False otherwise.
        '''
        unblinding_factors = self._unblind(share['secret'])
        if unblinding_factors is None:
            return False
        return True


    SINGLE_BIN = float('nan')
    '''
    A placeholder for the bin value of a counter with a single bin.
    This constant must be outside the range of every possible counter.
    '''

    @staticmethod
    def is_single_bin_value(value):
        if isnan(SecureCounters.SINGLE_BIN):
            return isnan(value)
        else:
            return SecureCounters.SINGLE_BIN == value

    @staticmethod
    def is_in_bin(bin_min, bin_max, bin_value):
        '''
        Is bin_value between bin_min and bin_max?
        bin_min is always inclusive. bin_max is exclusive, except when it is
        inf, it includes inf.
        '''
        # make everything float for consistent comparisons
        bin_min = float(bin_min)
        bin_max = float(bin_max)
        bin_value = float(bin_value)
        if bin_value >= bin_min:
            # any value is <= inf, so we don't need to check if bin_value is inf
            if bin_value < bin_max or bin_max == float('inf'):
                return True
        return False

    def increment(self, counter_name, bin=SINGLE_BIN, inc=1):
        '''
        Increment a bin in counter counter_name by inc.
        Uses is_in_bin() to work out which bin to increment.
        Example:
            secure_counters.increment('ExampleHistogram',
                                      bin=25,
                                      inc=1)

        If there is only one bin for the counter, you must pass SINGLE_BIN
        for bin:
            secure_counters.increment('ExampleCount',
                                      bin=SINGLE_BIN,
                                      inc=1)
        '''
        if self.counters is not None and counter_name in self.counters:
            # check that we have the right types, and that we're not losing
            # precision
            bin = float(bin)
            if float(inc) != float(int(inc)):
                logging.warning("Ignoring fractional part of counter {} bin {} increment {}: {}"
                                .format(counter_name, bin, inc,
                                        float(inc) - float(int(inc))))
                assert float(inc) == float(int(inc))
            inc = int(inc)
            # You must pass SINGLE_BIN if counter_name is a single bin
            if len(self.counters[counter_name]['bins']) == 1:
                assert(SecureCounters.is_single_bin_value(bin))
                bin = 1.0
            else:
                assert(not SecureCounters.is_single_bin_value(bin))
                bin = float(bin)
            for item in self.counters[counter_name]['bins']:
                if SecureCounters.is_in_bin(item[0], item[1], bin):
                    item[2] = ((int(item[2]) + int(inc))
                               % self.modulus)

    def _tally_counter(self, counter):
        if self.counters == None:
            return False

        # validate that the counter data structures match
        if not self._check_counter(counter):
            return False

        # ok, the counters match
        for key in self.counters:
            num_bins = len(self.counters[key]['bins'])
            for i in xrange(num_bins):
                tally_bin = self.counters[key]['bins'][i]
                tally_bin[2] = ((long(tally_bin[2]) +
                                 long(counter[key]['bins'][i][2]))
                                % self.modulus)

        # success
        return True

    def tally_counters(self, counters):
        # first add up all of the counters together
        for counter in counters:
            if not self._tally_counter(counter):
                return False
        # now adjust so our tally can register negative counts
        # (negative counts are possible if noise is negative)
        for key in self.counters:
            for tally_bin in self.counters[key]['bins']:
                tally_bin[2] = adjust_count_signed(tally_bin[2], self.modulus)
        return True

    def detach_counts(self):
        '''
        Asserts if we needed to add noise, and didn't add it
        '''
        assert not self.is_noise_pending
        counts = self.counters
        self.counters = None
        return counts


"""
def prob_exit(consensus_path, my_fingerprint, fingerprint_pool=None):
    '''
    this func is currently unused
    if it becomes used later, we must add stem as a required python library
    '''
    from stem.descriptor import parse_file

    if fingerprint_pool == None:
        fingerprint_pool = [my_fingerprint]

    net_status = next(parse_file(consensus_path, document_handler='DOCUMENT', validate=False))
    DW = float(net_status.bandwidth_weights['Wed'])/10000
    EW = float(net_status.bandwidth_weights['Wee'])/10000

    # we must use longs here, because otherwise sum_of_sq_bw can overflow on
    # platforms where python has 32-bit ints
    # (on these platforms, this happens when router_entry.bandwidth > 65535)
    my_bandwidth, DBW, EBW, sum_of_sq_bw = 0L, 0L, 0L, 0L

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
"""
