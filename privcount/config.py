'''
Created on Dec 8, 2016

@author: teor

Based on previous code

See LICENSE for licensing information
'''

import ipaddress

from os import path

def normalise_path(path_str):
    '''
    Return the abolute path corresponding to path_str, with user directories
    expanded, and the current working directory assumed for relative paths
    '''
    expanded_path = path.expanduser(path_str)
    return path.abspath(expanded_path)

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

def check_domain_name(domain_str):
    '''
    Check if domain_str is a potentially valid domain name.
    Allows underscores, even though they are technically not permitted,
    because they are used in some popular domain names.
    Assumes that the string has already been stripped of leading and trailing
    whitespace.

    Returns True if it is valid, and False if it is not.
    '''
    # We just care about character sets, because they help us ensure the
    # config is set to the right domain file.
    # Any malformed domains will never match a real domain anyway.
    domain_str = domain_str.lower()
    bad_chars = domain_str.strip(".-_abcdefghijklmnopqrstuvwxyz0123456789")
    return len(bad_chars) == 0 and len(domain_str) > 0

def check_country_code(country_str):
    '''
    Check if country_str is a potentially valid Tor/MaxMind Country Code.
    Assumes that the string has already been stripped of leading and trailing
    whitespace.

    Returns True if it is valid, and False if it is not.
    '''
    # We check character sets and length, but don't check against a list of
    # valid codes
    if country_str == "??" or country_str == "!!":
        # Unknown country or missing geoip database
        return True
    country_str = country_str.lower()
    bad_chars = country_str.strip("abcdefghijklmnopqrstuvwxyz01213456789")
    return len(bad_chars) == 0 and len(country_str) == 2

def check_as_number(as_number):
    '''
    Check if as_number is a potentially valid CAIDA AS Number.
    as_number can be an integer or string.

    CAIDA AS Numbers can also be AS Sets (",") and multi-origin ASs ("_"),
    but these must be stripped out of the files before they are loaded.
    Assumes that any strings have already been stripped of leading and
    trailing whitespace.

    Returns True if it is valid, and False if it is not.
    '''
    # We check if it's an integer
    try:
        as_number = int(as_number)
        return as_number > 0
    except ValueError as e:
        # not an integer
        return False

def check_reason_str(reason_str):
    '''
    Check if reason_str is a potentially valid hsdir or failure reason.
    Assumes that the string has already been stripped of leading and trailing
    whitespace.

    Returns True if it is valid, and False if it is not.
    '''
    # We just care about character sets, because they help us ensure the
    # config is set to the right file.
    # Any malformed or missing reasons will never match an actual reason anyway.
    reason_str = reason_str.lower()
    bad_chars = reason_str.strip("abcdefghijklmnopqrstuvwxyz0123456789")
    return len(bad_chars) == 0 and len(reason_str) > 0

def strip_onion_str(onion_str):
    '''
    Strip onion_str of:
    * all non-domain URL components, and
    * all non-onion-address domain components.

    And return the resulting string, lowercased.
    If stripping removes the entire string, returns an empty string.
    '''
    # remove the url scheme
    # take the entire string after the first colon
    # if there is no colon, take the entire string
    if ':' in onion_str:
        _, _, onion_str = onion_str.partition(':')
    # find the domain component
    # take the first non-empty string after splitting on slashes
    # if there are no slashes, take the entire string
    onion_url_components = onion_str.split('/')
    for onion_str in onion_url_components:
        if len(onion_str) == 0:
            continue
        else:
            break
    # find the onion address itself
    # take the last non-empty, non-"onion" string after splitting on dots
    # if there are no dots, take the entire string
    onion_domain_components = onion_str.split('.')
    for onion_str in reversed(onion_domain_components):
        if len(onion_str) == 0 or onion_str == "onion":
            continue
        else:
            return onion_str.lower()
    # if there is nothing left, return an empty string
    return ""

def check_onion_address(onion_str):
    '''
    Check if onion_str is a potentially valid onion address.
    Assumes that the string has already been stripped of leading and trailing
    whitespace, all non-domain URL components, and all non-onion-address
    domain components.

    That is, onion_str should be a 16-character base32 string.

    Returns True if it is valid, and False if it is not.
    '''
    # We check character sets and length
    onion_str = onion_str.lower()
    # RFC 4648, as implemented in tor
    bad_chars = onion_str.strip("abcdefghijklmnopqrstuvwxyz234567")
    # We only support v2 onion addresses, because HSDirs don't know v3 onion
    # addresses
    return len(bad_chars) == 0 and len(onion_str) == 16

def validate_ip_address(address):
    '''
    If address is a valid IP address, return it as an ipaddress object.
    Otherwise, return None.
    '''
    try:
        return ipaddress.ip_address(unicode(address))
    except ValueError:
        return None

def validate_ip_network(network, strict=True):
    '''
    If network is a valid IP network when parsed according to strict,
    return it as an ipnetwork object.
    Otherwise, return None.
    '''
    try:
        return ipaddress.ip_network(unicode(address), strict=strict)
    except ValueError:
        return None

def validate_ip_network_address_prefix(address, prefix, strict=True):
    '''
    If address/prefix is a valid IP network when parsed according to strict,
    return it as an ipnetwork object.
    Otherwise, return None.
    '''
    ip_address = validate_ip_address(address)
    if ip_address is None or ip_address.version not in [4,6]:
        return None
    try:
        if ip_address.version == 4:
            return ipaddress.IPv4Network((ip_address, prefix), strict=strict)
        else:
            return ipaddress.IPv6Network((ip_address, prefix), strict=strict)
    except ValueError:
        return None

def _extra_keys(first, second):
    '''
    Return the extra keys in first that are not in second.
    '''
    return set(first.keys()).difference(second.keys())

def _common_keys(first, second):
    '''
    Return the set of keys shared by first and second.
    '''
    return set(first.keys()).intersection(second.keys())
