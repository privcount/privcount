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
from os import urandom, path
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

## File Paths ##

# Return the abolute path corresponding to path_str, with user directories
# expanded, and the current working directory assumed for relative paths
def normalise_path(path_str):
    expanded_path = path.expanduser(path_str)
    return path.abspath(expanded_path)

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

# Sample noise from a gussian distribution
# the distribution is over +/- sigma, scaled by the noise weight
# calculated from the exit probability p_exit, and the overall sum_of_sq
# bandwidth
# returns a floating-point value between +sigma and -sigma, scaled by
# noise_weight
def noise(sigma, sum_of_sq, p_exit):
    sigma_i = p_exit * sigma / sqrt(sum_of_sq)
    random_sample = gauss(0, sigma_i)
    return random_sample

# Calculate pseudo-random bytes using a keyed hash based on key and IV
# Given the same key and IV, the same pseudo-random bytes will be produced
# key must contain at least as many bits of entropy as the hash
# Therefore, it must be at least 32 bytes long
# returns 32 pseudo-random bytes
def PRF(key, IV):
    assert len(key) >= Hash().digest_size
    prv = Hash("PRF1|KEY:%s|IV:%s|" % (key, IV)).digest()
    # for security, the key input must have at least as many bytes as the hash
    # output (we do not depend on the length or content of IV for security)
    assert len(key) >= len(prv)
    return prv

Q_BYTE_MAX = 8L
Q_BIT_MAX = Q_BYTE_MAX * 8L

# Sample a uniformly pseudo-random value from the random byte array s,
# returning a value with maximum q
# s must be at least 8 bytes long
# the returned value has a maximum of 2**64 - 1, so q is limited to 2**64
# returns a uniformly distributed in [0, q)
def sample(s, q):
    # in order for this function to return v in {0, ... , q-1}, q-1 must be
    # representable in Q_BIT_MAX bits or less
    # (2**N is the first number not representable in an N-bit unsigned integer)
    assert long(q-1) < 2L**Q_BIT_MAX
    ## Unbiased sampling through rejection sampling
    while True:
        # s must have enough bytes for us to extract 8
        assert len(s) >= Q_BYTE_MAX
        # to get a value of q-1, we need this many bits
        q_bit_count = long(q-1).bit_length()
        # and this many bytes
        q_byte_count = (q_bit_count+7)//8
        assert q_byte_count <= Q_BYTE_MAX
        # Pad the bytes we'll never use with zeroes, otherwise we reject
        # a large number of values
        # Since the extraction is little-endian, and we want to pad unused
        # bytes, the zero bytes go in the larger indexes
        s_bytes = s[:q_byte_count] + ('\0' * (Q_BYTE_MAX - q_byte_count))
        # <Q means unpack 8 little-endian bytes into a C unsigned long long
        v = long(struct.unpack("<Q", s_bytes)[0])
        # this will fail if we have mismatching endianness and padding
        assert v < 2L**(q_byte_count*8L)
        if 0L <= v < q:
            break
        # when we reject the value, re-hash s and try again
        s = Hash(s).digest()
    return v

# Calculate a blinding factor with maximum q, based on label and secret
# when positive is True, return the blinding factor, and when positive is
# False, returns the unblinding factor (the inverse value mod q)
def derive_blinding_factor(label, secret, q, positive=True):
    ## Keyed share derivation
    s = PRF(secret, label)
    v = sample(s, q)
    assert v < q
    s0 = v if positive else q - v
    return s0

# adjust the unsigned 0 <= count < q, returning a signed integer
# for odd  q, returns { -q//2, ... , 0, ... , q//2 }
# for even q, returns { -q//2, ... , 0, ... , q//2 - 1 }
# with the smaller positive values >= q//2 [- 1] becoming the largest negative
# values
# this is the inverse operation of x % q, when x is in the appropriate range
def adjust_count_signed(count, q):
    # sanity check input
    assert count < q
    # When implementing this adjustment,
    # { 0, ... , (q + 1)//2 - 1}  is interpreted as that value,
    # { (q + 1)//2, ... , q - 1 } is interpreted as that value minus q, or
    # { (q + 1)//2 - q, ... , q - 1 - q }
    #
    # For odd q, (q + 1)//2 rounds up to q//2 + 1, so positive simplifies to:
    # { 0, ... , q//2 + 1 - 1 }
    # { 0, ... , q//2 }
    # and because q == q//2 + q//2 + 1 for odd q, negative simplifies to:
    # { q//2 + 1 - q//2 - q//2 - 1, ... , q - 1 - q}
    # { -q//2, ... , -1 }
    # Odd q has the same number of values above and below 0:
    # { -q//2, ... , 0, ... , q//2 }
    #
    # For even q, (q+1)//2 rounds down to q//2, so positive simplifies to:
    # { 0, ... , q//2 - 1 }
    # and because q == q//2 + q//2 for even q, negative simplifies to:
    # { q//2 - q//2 - q//2, ... , q - 1 - q}
    # { -q//2, ... , -1 }
    # Even q has the 1 more value below 0 than above it:
    # { -q//2, ... , 0, ... , q//2 - 1 }
    # This is equivalent to signed two's complement, if q is an integral power
    # of two
    if count >= ((q + 1L) // 2L):
        signed_count = count - q
    else:
        signed_count = count
    # sanity check output
    assert signed_count >= -q//2L
    if q % 2L == 1L:
        # odd case
        assert signed_count <= q//2L
    else:
        # even case
        assert signed_count <= q//2L - 1L
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

    see privcount/test/test_counters.py for some test cases
    '''

    def __init__(self, counters, q):
        self.counters = deepcopy(counters)
        self.q = long(q)
        self.shares = None

        # initialize all counters to 0L
        # counters use unlimited length integers to avoid overflow
        for key in self.counters:
            if 'bins' not in self.counters[key]:
                return None
            for item in self.counters[key]['bins']:
                assert len(item) == 2
                item.append(0L) # bin is now, e.g.: [0.0, 512.0, 0L] for bin_left, bin_right, count

    def _derive_all_counters(self, secret, positive):
        for key in self.counters:
            for item in self.counters[key]['bins']:
                label = "{}_{}_{}".format(key, item[0], item[1])
                blinding_factor = derive_blinding_factor(label, secret, self.q, positive=positive)
                item[2] = (item[2] + long(blinding_factor)) % self.q

    def _blind(self, secret):
        self._derive_all_counters(secret, True)

    def _unblind(self, secret):
        self._derive_all_counters(secret, False)

    def generate(self, uids, noise_weight):
        self.shares = {}
        for uid in uids:
            # the secret should be at least as large as the hash output
            secret = urandom(Hash().digest_size)
            hash_id = PRF(secret, "KEYID")
            self.shares[uid] = {'secret': secret, 'hash_id': hash_id}
            # add blinding factors to all of the counters
            self._blind(secret)

	    # Add noise for each counter independently
        for key in self.counters:
            for item in self.counters[key]['bins']:
                sigma = self.counters[key]['sigma']
                sampled_noise = noise(sigma, 1, noise_weight)
                noise_val = long(round(sampled_noise))
                # if noise_val is negative, modulus produces a positive result
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

    def increment(self, counter_key, bin_value, num_increments=1L):
        if self.counters is not None and counter_key in self.counters:
            for item in self.counters[counter_key]['bins']:
                if bin_value >= item[0] and bin_value < item[1]:
                    item[2] = (item[2] + long(num_increments)) % self.q

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
                tally_bin[2] = adjust_count_signed(tally_bin[2], self.q)
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
