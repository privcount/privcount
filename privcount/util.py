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
import json

from os import path
from math import ceil
from time import time, strftime, gmtime
from base64 import b64encode, b64decode

from hashlib import sha256 as DigestHash
# encryption using SHA256 requires cryptography >= 1.4
from cryptography.hazmat.primitives.hashes import SHA256 as CryptoHash

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import UnsupportedAlgorithm, InvalidSignature

from privcount.counter import check_counters_config, check_noise_weight_config, combine_counters, CollectionDelay, float_accuracy, add_counter_limits_to_config
from privcount.statistics_noise import DEFAULT_SIGMA_TOLERANCE

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
    return DigestHash(get_public_bytes(key_string, is_private_key)).hexdigest()

def get_public_digest(key_path, is_private_key=True):
    with open(key_path, 'rb') as key_file:
        digest = get_public_digest_string(key_file.read(), is_private_key)
    return digest

def get_serialized_public_key(key_path, is_private_key=True):
    with open(key_path, 'rb') as key_file:
        data = get_public_bytes(key_file.read(), is_private_key)
    return data

def choose_secret_handshake_path(local_conf, global_conf):
    '''
    Determine the secret handshake path using the first path from:
    - local_conf,
    - global_conf, or
    - the default hard-coded path,
    and return that path.
    '''
    if 'secret_handshake' in local_conf:
        return normalise_path(local_conf['secret_handshake'])
    # unlike other top-level configs, this is a file path, not data
    elif 'secret_handshake' in global_conf:
        return normalise_path(global_conf['secret_handshake'])
    # if the path is not specified, use the default path
    else:
        return normalise_path('privcount.secret_handshake.yaml')

def get_hmac(secret_key, unique_prefix, data):
    '''
    Perform a HMAC using the secret key, unique hash prefix, and data.
    The key must be kept secret.
    The prefix ensures hash uniqueness.
    Returns HMAC-SHA256(secret_key, unique_prefix | data) as bytes.
    '''
    # If the secret key is shorter than the digest size, security is reduced
    assert secret_key
    assert len(secret_key) >= CryptoHash.digest_size
    h = hmac.HMAC(bytes(secret_key), CryptoHash(), backend=default_backend())
    h.update(bytes(unique_prefix))
    h.update(bytes(data))
    return bytes(h.finalize())

def verify_hmac(expected_result, secret_key, unique_prefix, data):
    '''
    Perform a HMAC using the secret key, unique hash prefix, and data, and
    verify that the result of:
    HMAC-SHA256(secret_key, unique_prefix | data)
    matches the bytes in expected_result.
    The key must be kept secret. The prefix ensures hash uniqueness.
    Returns True if the signature matches, and False if it does not.
    '''
    # If the secret key is shorter than the digest size, security is reduced
    assert secret_key
    assert len(secret_key) >= CryptoHash.digest_size
    h = hmac.HMAC(bytes(secret_key), CryptoHash(), backend=default_backend())
    h.update(bytes(unique_prefix))
    h.update(bytes(data))
    try:
        h.verify(bytes(expected_result))
        return True
    except cryptography.exceptions.InvalidSignature:
        return False

def b64_raw_length(byte_count):
    '''
    Note: base64.b64encode returns b64_padded_length bytes of output.
    Return the raw base64-encoded length of byte_count bytes.
    '''
    if byte_count < 0:
        raise ValueError("byte_count must be non-negative")
    return long(ceil(byte_count*8.0/6.0))

B64_PAD_TO_MULTIPLE = 4

def b64_padded_length(byte_count):
    '''
    Return the padded base64-encoded length of byte_count bytes, as produced
    by base64.b64encode.
    '''
    raw_length = b64_raw_length(byte_count)
    # base64 padding rounds up to the nearest multiple of 4
    trailing_bytes = raw_length % B64_PAD_TO_MULTIPLE
    if trailing_bytes > 0:
        padding_bytes = B64_PAD_TO_MULTIPLE - trailing_bytes
    else:
        padding_bytes = 0
    padded_length = raw_length + padding_bytes
    assert padded_length % B64_PAD_TO_MULTIPLE == 0
    return padded_length

def encode_data(data_structure):
    """
    Encode an arbitrary python data structure in a format that is suitable
    for encryption (encrypt() expects bytes).
    The data structure can only contain basic python types, those supported
    by json.dumps (including longs, but no arbitrary objects).
    Performs the following transformations, in order:
    - dump the data structure using json: b64encode doesn't encode objects
    - b64encode the json: avoid any round-trip string encoding issues
    Returns a base64 blob that can safely be encrypted, decrypted, then passed
    to decode_data to produce the original data structure.
    """
    json_string = json.dumps(data_structure)
    return b64encode(json_string)

def decode_data(encoded_string):
    """
    Decode an arbitrary python data structure from the format provided by
    encode_data().
    The data structure can only contain basic python types, those supported
    by json.loads (including longs, but no arbitrary objects).
    Performs the inverse transformations to encode_data().
    Returns a python data structure.
    """
    json_string = b64decode(encoded_string)
    # json.loads is safe to use on untrusted data (from the network)
    return json.loads(json_string)

def generate_symmetric_key():
    """
    Generate and return a new secret key that can be used for symmetric
    encryption.
    """
    return Fernet.generate_key()

def encrypt_symmetric(secret_key, plaintext):
    """
    Encrypt plaintext with the Fernet symmetric key secret_key.
    This key must be kept secret, as it can be used to decrypt the message.
    The encrypted message contains its own creation time in plaintext:
    this time is visible to an attacker.
    See https://cryptography.io/en/latest/fernet/ for the details of this
    encryption scheme.
    Returns the encrypted ciphertext.
    """
    f = Fernet(secret_key)
    return f.encrypt(plaintext)

def decrypt_symmetric(secret_key, ciphertext, ttl=None):
    """
    Decrypt ciphertext with the Fernet symmetric key secret_key.
    See https://cryptography.io/en/latest/fernet/ for the details of this
    encryption scheme.
    Returns the decrypted plaintext
    Throws an exception if secret_key or ciphertext are invalid, or the
    message is older than ttl seconds.
    """
    f = Fernet(secret_key)
    # fernet requires the ciphertext to be bytes, it will raise an exception
    # if it is a string
    return f.decrypt(bytes(ciphertext), ttl)

def encrypt_pk(pub_key, plaintext):
    """
    Encrypt plaintext with the RSA public key pub_key, using CryptoHash()
    as the OAEP/MGF1 padding hash.
    plaintext is limited to the size of the RSA key, minus the padding, or a
    few hundred bytes.
    Returns a b64encoded ciphertext string.
    Encryption failures result in an exception being raised.
    """
    try:
        ciphertext = pub_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=CryptoHash()),
                algorithm=CryptoHash(),
                label=None
                )
            )
    except UnsupportedAlgorithm as e:
        # a failure to encrypt our own data is a fatal error
        # the most likely cause of this error is an old cryptography library
        # although some newer binary cryptography libraries are linked with
        # old OpenSSL versions, to fix, check 'openssl version' >= 1.0.2, then:
        # pip install -I --no-binary cryptography cryptography
        logging.error("Fatal error: encryption hash {} unsupported, try upgrading to cryptography >= 1.4 compiled with OpenSSL >= 1.0.2. Exception: {}".format(
                          CryptoHash, e))
        # re-raise the exception for the caller to handle
        raise e
    return b64encode(ciphertext)

def decrypt_pk(priv_key, ciphertext):
    """
    Decrypt a b64encoded ciphertext string with the RSA private key priv_key,
    using CryptoHash() as the OAEP/MGF1 padding hash.
    Returns the plaintext.
    Fails and calls os._exit on an UnsupportedAlgorithm exception.
    (Other decryption failures result in an exception being raised.)
    """
    try:
        plaintext = priv_key.decrypt(
            b64decode(ciphertext),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=CryptoHash()),
                algorithm=CryptoHash(),
                label=None
                )
            )
    except UnsupportedAlgorithm as e:
        # a failure to dencrypt someone else's data is not typically a fatal
        # error, but in this particular case, the most likely cause of this
        # error is an old cryptography library
        logging.error("Fatal error: encryption hash {} unsupported, try upgrading to cryptography >= 1.4. Exception: {}".format(
                          CryptoHash, e))
        # re-raise the exception for the caller to handle
        raise e
    return plaintext

def encrypt(pub_key, data_structure):
    """
    Encrypt an arbitrary python data structure, using the following scheme:
    - transform the data structure into a b64encoded json string
    - encrypt the string with a single-use symmetric encryption key
    - encrypt the single-use key using asymmetric encryption with pub_key
    The data structure can contain any number of nested dicts, lists, strings,
    doubles, ints, and longs.
    Returns a data structure containing ciphertexts, which should be treated
    as opaque.
    Encryption failures result in an exception being raised.
    """
    encoded_string = encode_data(data_structure)
    # TODO: secure delete
    secret_key = generate_symmetric_key()
    sym_encrypted_data = encrypt_symmetric(secret_key, encoded_string)
    pk_encrypted_secret_key = encrypt_pk(pub_key, secret_key)
    return { 'pk_encrypted_secret_key': pk_encrypted_secret_key,
             'sym_encrypted_data': sym_encrypted_data}

def decrypt(priv_key, ciphertext):
    """
    Decrypt ciphertext, yielding an arbitrary python data structure, using the
    same scheme as encrypt().
    ciphertext is a data structure produced by encrypt(), and should be
    treated as opaque.
    Returns a python data structure.
    Decryption failures result in an exception being raised.
    """
    pk_encrypted_secret_key = ciphertext['pk_encrypted_secret_key']
    sym_encrypted_data = ciphertext['sym_encrypted_data']
    # TODO: secure delete
    secret_key = decrypt_pk(priv_key, pk_encrypted_secret_key)
    encoded_string = decrypt_symmetric(secret_key, sym_encrypted_data)
    return decode_data(encoded_string)

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
        # choose an evenly distributed port that doesn't leak RNG state
        port = sample_randint(10000, 60000)
        rc = s.connect_ex(('127.0.0.1', port))
        s.close()
        if rc != 0: # error connecting, port is available
            return port

## File Paths ##

def normalise_path(path_str):
    '''
    Return the abolute path corresponding to path_str, with user directories
    expanded, and the current working directory assumed for relative paths
    '''
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

def normalise_time(time):
    '''
    Return the normalised value of time
    An abstraction used for consistent time rounding behaviour
    '''
    # we ignore microseconds
    return int(time)

def current_time():
    '''
    Return the normalised value of the current time
    '''
    return normalise_time(time())

def format_period(period):
    '''
    Format a time period as a human-readable string
    period is in seconds
    Returns a string of the form:
    1w 3d 12h 20m 32s
    starting with the first non-zero period (seconds are always included)
    '''
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

def format_datetime(timestamp):
    '''
    Format a timestamp as a human-readable UTC date and time string
    timestamp is in seconds since the epoch
    Returns a string of the form:
    2016-07-16 17:58:00
    '''
    timestamp = normalise_time(timestamp)
    return strftime("%Y-%m-%d %H:%M:%S", gmtime(timestamp))

def format_epoch(timestamp):
    '''
    Format a timestamp as a unix epoch numeric string
    timestamp is in seconds since the epoch
    Returns a string of the form:
    1468691880
    '''
    timestamp = normalise_time(timestamp)
    return str(timestamp)

def format_time(period, desc, timestamp):
    '''
    Format a period and timestamp as a human-readable string in UTC
    period is in seconds, and timestamp is in seconds since the epoch
    Returns a string of the form:
    1w 3d 12h 20m 32s (desc 2016-07-16 17:58:00 1468691880)
    '''
    return "{} ({} {} {})".format(format_period(period),
                                  desc,
                                  format_datetime(timestamp),
                                  format_epoch(timestamp))

def format_interval(period, desc, begin_timestamp, end_timestamp):
    '''
    Format a period and two interval timestamps as a human-readable string in UTC
    period is in seconds, and the timestamps are in seconds since the epoch
    Returns a string of the form:
    1w 3d 12h 20m 32s (desc 2016-07-16 17:58:00 to 2016-07-27 06:18:32,
    1468691880 to 1469600312)
    '''
    return "{} ({} {} to {}, {} to {})".format(format_period(period),
                                               desc,
                                               format_datetime(begin_timestamp),
                                               format_datetime(end_timestamp),
                                               format_epoch(begin_timestamp),
                                               format_epoch(end_timestamp))

def format_elapsed_time_wait(elapsed_period, desc):
    '''
    Format the time elapsed since a past event, and the past event time in UTC
    elapsed_period is in seconds
    The event time is the current time minus elapsed_period
    elapsed_period is typically time_since_checkin, and desc is typically 'at'
    Returns a string of the form:
    1w 3d 12h 20m 32s (desc 2016-07-27 06:18:32 1469600312)
    '''
    # Normalise before calculation to avoid truncation errors
    elapsed_period = normalise_time(elapsed_period)
    past_timestamp = current_time() - elapsed_period
    return format_time(elapsed_period, desc, past_timestamp)

def format_elapsed_time_since(past_timestamp, desc):
    '''
    Format the time elapsed since a past event, and that event's time in UTC
    past_timestamp is in seconds since the epoch
    The elapsed time is from past_timestamp to the current time
    past_timestamp is typically status['time'], and desc is typically 'since'
    Returns a string of the form:
    1w 3d 12h 20m 32s (desc 2016-07-16 17:58:00 1468691880)
    '''
    # Normalise before calculation to avoid truncation errors
    past_timestamp = normalise_time(past_timestamp)
    elapsed_period = current_time() - past_timestamp
    return format_time(elapsed_period, desc, past_timestamp)

def format_delay_time_wait(delay_period, desc):
    '''
    Format the time delay until a future event, and the expected event time
    in UTC
    delay_period is in seconds
    The event time is the current time plus delay_period
    delay_period is typically config['defer_time'], and desc is typically 'at'
    Returns a string of the form:
    1w 3d 12h 20m 32s (desc 2016-07-27 06:18:32 1469600312)
    '''
    # Normalise before calculation to avoid truncation errors
    delay_period = normalise_time(delay_period)
    future_timestamp = current_time() + delay_period
    return format_time(delay_period, desc, future_timestamp)

def format_delay_time_until(future_timestamp, desc):
    '''
    Format the time delay until a future event, and the expected event time
    in UTC
    The time delay is the difference between future_timestamp and the current
    time
    future_timestamp is in seconds since the epoch
    future_timestamp is typically config['defer_time'], and desc is typically 'at'
    returns a string of the form:
    1w 3d 12h 20m 32s (desc 2016-07-27 06:18:32 1469600312)
    '''
    # Normalise before calculation to avoid truncation errors
    future_timestamp = normalise_time(future_timestamp)
    delay_period = future_timestamp - current_time()
    return format_time(delay_period, desc, future_timestamp)

def format_interval_time_between(begin_timestamp, desc, end_timestamp):
    '''
    Format the interval elapsed between two events, and the times of those
    events in UTC
    The timestamps are in seconds since the epoch
    The interval is between begin_time and end_time
    desc is typically 'from'
    Returns a string of the form:
    1w 3d 12h 20m 32s (desc 2016-07-16 17:58:00 to 2016-07-27 06:18:32,
    1468691880 to 1469600312)
    '''
    # Normalise before calculation to avoid truncation errors
    begin_timestamp = normalise_time(begin_timestamp)
    end_timestamp = normalise_time(end_timestamp)
    period = end_timestamp - begin_timestamp
    return format_interval(period, desc, begin_timestamp, end_timestamp)

def format_last_event_time_since(last_event_timestamp):
    '''
    Format the time elapsed since the last Tor event, and that event's time
    in UTC
    last_event_timestamp is in seconds since the epoch, and can be None
    for no events
    The elapsed time is from last_event_timestamp to the current time
    Returns a string in one of the following forms:
    no Tor events received
    last Tor event was 1w 3d 12h 20m 32s (at 2016-07-16 17:58:00 1468691880)
    '''
    if last_event_timestamp is None:
        return "no Tor events received"
    else:
        return "last Tor event was {}".format(format_elapsed_time_since(
                                                  last_event_timestamp, 'at'))

## Nodes

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
