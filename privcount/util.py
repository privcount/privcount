'''
Created on Dec 15, 2015

@author: rob
'''
import sys
import struct
import traceback
import logging
import socket
import datetime
import uuid

from random import gauss, randint
from os import urandom
from math import sqrt
from time import time, strftime, gmtime
from copy import deepcopy
from base64 import b64encode, b64decode

from hashlib import sha256 as Hash

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def load_private_key_string(key_string):
    return serialization.load_pem_private_key(key_string, password=None, backend=default_backend())

def load_private_key_file(key_file_path):
    with open(key_file_path, 'rb') as key_file:
        private_key = load_private_key_string(key_file.read())
    return private_key

def load_public_key_string(key_string):
    return serialization.load_pem_public_key(key_string, backend=default_backend())

def load_public_key_file(key_file_path):
    with open(key_file_path, 'rb') as key_file:
        public_key = load_public_key_string(key_file.read())
    return public_key

def get_public_bytes(key_string, is_private_key=True):
    if is_private_key:
        private_key = load_private_key_string(key_string)
        public_key = private_key.public_key()
    else:
        public_key = load_public_key_string(key_string)
    return public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

def get_public_digest_string(key_string, is_private_key=True):
    return Hash(get_public_bytes(key_string, is_private_key)).hexdigest()

def get_public_digest(key_path, is_private_key=True):
    with open(key_path, 'rb') as key_file:
        digest = get_public_digest_string(key_file.read(), is_private_key)
    return digest

def get_serialized_public_key(key_path, is_private_key=True):
    with open(key_path, 'rb') as key_file:
        data = get_public_bytes(key_file.read(), is_private_key)
    return data

def encrypt(pub_key, plaintext):
    ciphertext = pub_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return b64encode(ciphertext)

def decrypt(priv_key, ciphertext):
    plaintext = priv_key.decrypt(
        b64decode(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return plaintext

def generate_keypair(key_out_path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    with open(key_out_path, 'wb') as outf:
        print >>outf, pem

def generate_cert(key_path, cert_out_path):
    private_key = load_private_key_file(key_path)
    public_key = private_key.public_key()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(x509.OID_COMMON_NAME, u'PrivCount User'),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(x509.OID_COMMON_NAME, u'PrivCount Authority'),
    ]))
    builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))
    builder = builder.not_valid_after(datetime.datetime(2020, 1, 1))
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(public_key)
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())

    with open(cert_out_path, 'wb') as outf:
        print >>outf, certificate.public_bytes(encoding=serialization.Encoding.PEM)

def get_random_free_port():
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = randint(10000, 60000)
        rc = s.connect_ex(('127.0.0.1', port))
        s.close()
        if rc != 0: # error connecting, port is available
            return port

## Logging ##

def log_error():
    _, _, tb = sys.exc_info()
    #traceback.print_tb(tb) # Fixed format
    tb_info = traceback.extract_tb(tb)
    filename, line, func, text = tb_info[-1]
    logging.warning("An error occurred in file '%s', at line %d, in func %s, in statement '%s'", filename, line, func, text)

## Logging: Time Formatting Functions ##
## a timestamp is an absolute point in time, in seconds since unix epoch
## a period is a relative time duration, in seconds
## a time argument is either a period or a timestamp
## a desc argument is a string description of the timestamp's meaning
## All period and timestamp arguments are normalised using normalise_time()
## before any calculations or formatting are performed


# Return the normalised value of time
# An abstraction used for consistent time rounding behaviour
def normalise_time(time):
    # we ignore microseconds
    return int(time)

# Return the normalised value of the current time
def current_time():
    return normalise_time(time())

# Format a time period as a human-readable string
# period is in seconds
# Returns a string of the form:
# 1w 3d 12h 20m 32s
# starting with the first non-zero period (seconds are always included)
def format_period(period):
    period = normalise_time(period)
    period_str = ""
    # handle negative times by prepending a minus sign
    if period < 0:
        period_str += "-"
        period = -period
    # there's no built-in way of formatting a time period like this in python.
    # strftime is almost there, but would have issues with year-long periods.
    # divmod gives us the desired floor division result, and the remainder,
    # which will be floating point if normalise_time() returns floating point
    (week,   period) = divmod(period, 7*24*60*60)
    (day,    period) = divmod(period,   24*60*60)
    (hour,   period) = divmod(period,      60*60)
    (minute, period) = divmod(period,         60)
    # if normalise_time yields floating point values (microseconds), this will
    # produce a floating point result, which will be formatted as NN.NN
    # if it's an integer, it will format as NN. This is the desired behaviour.
    second           =        period % (      60)
    # now build the formatted string starting with the first non-zero period
    larger_period = 0
    if week > 0:
        period_str += "{}w ".format(week)
        larger_period = 1
    if day > 0 or larger_period:
        period_str += "{}d ".format(day)
        larger_period = 1
    if hour > 0 or larger_period:
        period_str += "{}h ".format(hour)
        larger_period = 1
    if minute > 0 or larger_period:
        period_str += "{}m ".format(minute)
    # seconds are always included, even if they are zero, or if there is no
    # larger period
    period_str += "{}s".format(second)
    return period_str

# Format a timestamp as a human-readable UTC date and time string
# timestamp is in seconds since the epoch
# Returns a string of the form:
# 2016-07-16 17:58:00
def format_datetime(timestamp):
    timestamp = normalise_time(timestamp)
    return strftime("%Y-%m-%d %H:%M:%S", gmtime(timestamp))

# Format a timestamp as a unix epoch numeric string
# timestamp is in seconds since the epoch
# Returns a string of the form:
# 1468691880
def format_epoch(timestamp):
    timestamp = normalise_time(timestamp)
    return str(timestamp)

# Format a period and timestamp as a human-readable string in UTC
# period is in seconds, and timestamp is in seconds since the epoch
# Returns a string of the form:
# 1w 3d 12h 20m 32s (desc 2016-07-16 17:58:00 1468691880)
def format_time(period, desc, timestamp):
    return "{} ({} {} {})".format(format_period(period),
                                  desc,
                                  format_datetime(timestamp),
                                  format_epoch(timestamp))

# Format a period and two interval timestamps as a human-readable string in UTC
# period is in seconds, and the timestamps are in seconds since the epoch
# Returns a string of the form:
# 1w 3d 12h 20m 32s (desc 2016-07-16 17:58:00 to 2016-07-27 06:18:32,
# 1468691880 to 1469600312)
def format_interval(period, desc, begin_timestamp, end_timestamp):
  return "{} ({} {} to {}, {} to {})".format(format_period(period),
                                             desc,
                                             format_datetime(begin_timestamp),
                                             format_datetime(end_timestamp),
                                             format_epoch(begin_timestamp),
                                             format_epoch(end_timestamp))

# Format the time elapsed since a past event, and that event's time in UTC
# past_timestamp is in seconds since the epoch
# The elapsed time is from past_timestamp to the current time
# past_timestamp is typically status['time'], and desc is typically 'since'
# Returns a string of the form:
# 1w 3d 12h 20m 32s (desc 2016-07-16 17:58:00 1468691880)
def format_elapsed_time_since(past_timestamp, desc):
    # Normalise before calculation to avoid truncation errors
    past_timestamp = normalise_time(past_timestamp)
    elapsed_period = current_time() - past_timestamp
    return format_time(elapsed_period, desc, past_timestamp)

# Format the time delay until a future event, and the expected event time
# in UTC
# delay_period is in seconds
# The event time is the current time plus delay_period
# delay_period is typically config['defer_time'], and desc is typically 'at'
# Returns a string of the form:
# 1w 3d 12h 20m 32s (desc 2016-07-27 06:18:32 1469600312)
def format_delay_time_wait(delay_period, desc):
    # Normalise before calculation to avoid truncation errors
    delay_period = normalise_time(delay_period)
    future_timestamp = current_time() + delay_period
    return format_time(delay_period, desc, future_timestamp)

# Format the time delay until a future event, and the expected event time
# in UTC
# The time delay is the difference between future_timestamp and the current
# time
# future_timestamp is in seconds since the epoch
# future_timestamp is typically config['defer_time'], and desc is typically 'at'
# Returns a string of the form:
# 1w 3d 12h 20m 32s (desc 2016-07-27 06:18:32 1469600312)
def format_delay_time_until(future_timestamp, desc):
    # Normalise before calculation to avoid truncation errors
    future_timestamp = normalise_time(future_timestamp)
    delay_period = future_timestamp - current_time()
    return format_time(delay_period, desc, future_timestamp)

# Format the interval elapsed between two events, and the times of those
# events in UTC
# The timestamps are in seconds since the epoch
# The interval is between begin_time and end_time
# desc is typically 'from'
# Returns a string of the form:
# 1w 3d 12h 20m 32s (desc 2016-07-16 17:58:00 to 2016-07-27 06:18:32,
# 1468691880 to 1469600312)
def format_interval_time_between(begin_timestamp, desc, end_timestamp):
    # Normalise before calculation to avoid truncation errors
    begin_timestamp = normalise_time(begin_timestamp)
    end_timestamp = normalise_time(end_timestamp)
    period = end_timestamp - begin_timestamp
    return format_interval(period, desc, begin_timestamp, end_timestamp)

# Format the time elapsed since the last Tor event, and that event's time
# in UTC
# last_event_timestamp is in seconds since the epoch, and can be None
# for no events
# The elapsed time is from last_event_timestamp to the current time
# Returns a string in one of the following forms:
# no Tor events received
# last Tor event was 1w 3d 12h 20m 32s (at 2016-07-16 17:58:00 1468691880)
def format_last_event_time_since(last_event_timestamp):
    if last_event_timestamp is None:
        return "no Tor events received"
    else:
        return "last Tor event was {}".format(format_elapsed_time_since(
                                                  last_event_timestamp, 'at'))

## Calculation ##

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

def derive_blinding_factor(label, secret, q, positive=True):
    ## Keyed share derivation
    s = PRF(secret, label)
    v = sample(s, q)
    s0 = v if positive else q - v
    return s0

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
      'CircuitCellsIn': {
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
    All of data collectors, share keepers, and tally server use this to store counters
    it is used approximately like this:

    data collector:
    init(), generate(), detach_blinding_shares(), increment()[repeated], detach_counts()
    the blinding shares are sent to each share keeper
    the counts are sent to the tally server at the end

    share keeper:
    init(), import_blinding_share()[repeated], detach_counts()
    import..() uses the shares from each data collector
    the counts are sent to the tally server at the end

    tally server:
    init(), tally_counters(), detach_counts()
    tally..() uses the counts received from all of the data collectors and share keepers
    this produces the final, unblinded, noisy counts of the privcount process

    see privcount/test/test_counters.py for a test case
    '''

    def __init__(self, counters, q):
        self.counters = deepcopy(counters)
        self.q = q
        self.shares = None

        # initialize all counters to 0
        for key in self.counters:
            if 'bins' not in self.counters[key]:
                return None
            for item in self.counters[key]['bins']:
                assert len(item) == 2
                item.append(0.0) # bin is now, e.g.: [0.0, 512.0, 0.0] for bin_left, bin_right, count

    def _derive_all_counters(self, secret, positive):
        for key in self.counters:
            for item in self.counters[key]['bins']:
                label = "{}_{}_{}".format(key, item[0], item[1])
                blinding_factor = derive_blinding_factor(label, secret, self.q, positive=positive)
                item[2] = (item[2] + blinding_factor) % self.q

    def _blind(self, secret):
        self._derive_all_counters(secret, True)

    def _unblind(self, secret):
        self._derive_all_counters(secret, False)

    def generate(self, uids, noise_weight):
        self.shares = {}
        for uid in uids:
            secret = urandom(20)
            hash_id = PRF(secret, "KEYID")
            self.shares[uid] = {'secret': secret, 'hash_id': hash_id}
            # add blinding factors to all of the counters
            self._blind(secret)

	    # Add noise for each counter independently
        for key in self.counters:
            for item in self.counters[key]['bins']:
                sigma = self.counters[key]['sigma']
                sampled_noise = noise(sigma, 1, noise_weight)
                noise_val = int(round(sampled_noise))
                item[2] = (item[2] + noise_val) % self.q

    def detach_blinding_shares(self):
        shares = self.shares
        # TODO: secure delete
        del self.shares
        self.shares = None
        for uid in shares:
            shares[uid]['secret'] = b64encode(shares[uid]['secret'])
            shares[uid]['hash_id'] = b64encode(shares[uid]['hash_id'])
        return shares

    def import_blinding_share(self, share):
        # reverse blinding factors for all of the counters
        self._unblind(b64decode(share['secret']))

    def increment(self, counter_key, bin_value, num_increments=1.0):
        if self.counters is not None and counter_key in self.counters:
            for item in self.counters[counter_key]['bins']:
                if bin_value >= item[0] and bin_value < item[1]:
                    item[2] = (item[2] + num_increments) % self.q

    def _tally_counter(self, counter):
        if self.counters == None:
            return False

        # validate that the counters match
        for key in self.counters:
            if key not in counter:
                return False
            if 'bins' not in counter[key]:
                return False
            num_bins = len(self.counters[key]['bins'])
            if num_bins != len(counter[key]['bins']):
                return False
            for i in xrange(num_bins):
                tally_item = counter[key]['bins'][i]
                if len(tally_item) != 3:
                    return False

        # ok, the counters match
        for key in self.counters:
            num_bins = len(self.counters[key]['bins'])
            for i in xrange(num_bins):
                tally_bin = self.counters[key]['bins'][i]
                tally_bin[2] = (tally_bin[2] + counter[key]['bins'][i][2]) % self.q

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
                if tally_bin[2] > (self.q / 2):
                    tally_bin[2] -= self.q
        return True

    def detach_counts(self):
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
"""
