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
    bad_chars = country_str.strip("abcdefghijklmnopqrstuvwxyz")
    return len(bad_chars) == 0 and len(country_str) == 2

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
