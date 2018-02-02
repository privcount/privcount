'''
Created on Jun 14, 2017

@author: teor

See LICENSE for licensing information
'''

import logging

from privcount.config import validate_ip_address
from privcount.log import summarise_string

def parse_tagged_event(event_field_list):
    '''
    Parse event_field_list from an event with tagged fields.
    Each tagged field in event_field_list is a 'Key=Value' pair.
    A specification for the tagged event format is in doc/TorEvents.markdown

    The list must not include the event code (650) or event type (PRIVCOUNT_*).

    Returns a dictionary of Key: Value pairs, where Key and Value are both
    strings. (To retrieve typed values, use the is_type_valid and
    get_type_value functions.)
    Key must be at least one character, and '=' must be present, or the event
    is malformed.
    If there is no Value after the '=', result[Key] is a zero-length string.
    If any field is not in the correct format, returns an empty dictionary.

    '''
    result = dict()
    for field in event_field_list:
        # validate the field
        # tolerate multiple spaces between fields
        if len(field) == 0:
            logging.warning("Ignoring empty tagged event field")
            continue
        # fields must not contain whitespace or C NULs
        if ' ' in field or '\r' in field or '\n' in field or '\0' in field:
            logging.warning("Ignoring tagged event with malformed whitespace: '{}'"
                            .format(field))
            return dict()
        # split the field
        key, eq, value = field.partition("=")
        # validate the key, eq, and value
        # values must not contain =
        if '=' in value:
            logging.warning("Ignoring tagged event with multiple separators: '{}'"
                            .format(field))
            return dict()
        # the key and the '=' must be present
        if len(eq) != 1:
            logging.warning("Ignoring tagged event with missing or malformed '=': '{}'"
                            .format(field))
            return dict()
        if len(key) == 0:
            logging.warning("Ignoring tagged event with missing key: '{}'"
                            .format(field))
            return dict()
        # the list can't have duplicate keys
        if key in result:
            logging.warning("Ignoring tagged event with duplicate key: '{}'"
                            .format(field))
            return dict()
        result[key] = value
    return result

def is_field_valid(field_name, fields, event_desc,
                   is_mandatory=False):
    '''
    If is_mandatory is True, check that fields[field_name] exists.
    If it is missing, return False and log a warning using event_desc.

    Otherwise, return True (the event should be processed).
    '''
    if is_mandatory and field_name not in fields:
        logging.warning("Rejected missing {} {}"
                        .format(field_name, event_desc))
        return False

    return True

def is_string_valid(field_name, fields, event_desc,
                    is_mandatory=False,
                    min_len=None, max_len=None):
    '''
    Check that fields[field_name] passes is_field_valid() and has a length
    between min_len and max_len (inclusive). Use None for no length check.
    Don't pass floating-point values for min_len and max_len: they can be
    inaccurate when compared with integer lengths.

    If any check fails, return False (the event is ignored), and log a
    warning using event_desc.
    Otherwise, return True (the event should be processed).
    '''
    if not is_field_valid(field_name, fields, event_desc,
                          is_mandatory=is_mandatory):
        return False
    if field_name not in fields:
        # valid optional field, keep on processing other fields
        return True
    field_value = fields[field_name]
    field_len = len(field_value)
    field_value_summary = summarise_string(field_value)
    if min_len is not None and field_len < min_len:
        logging.warning("Ignored {} length {}: '{}', must be at least {} characters {}"
                        .format(field_name, field_len, field_value_summary,
                                min_len, event_desc))
        logging.debug("Ignored {} length {} (full string): '{}', must be at least {} characters {}"
                      .format(field_name, field_len, field_value,
                              min_len, event_desc))
        # we can't process it
        return False
    if max_len is not None and field_len > max_len:
        logging.warning("Ignored {} length {}: '{}', must be at most {} characters {}"
                        .format(field_name, field_len, field_value_summary,
                                max_len, event_desc))
        logging.debug("Ignored {} length {} (full string): '{}', must be at most {} characters {}"
                      .format(field_name, field_len, field_value,
                              max_len, event_desc))
        # we can't process it
        return False
    # it is valid and we want to keep on processing
    return True

def is_list_valid(field_name, fields, event_desc,
                  is_mandatory=False,
                  min_count=None, max_count=None):
    '''
    Check that fields[field_name] passes is_field_valid(), and has between
    min_count and max_count elements (inclusive). Use None for no count check.
    
    Assumes a zero-length value is a list with no items.

    Don't pass floating-point values for min_count and max_count: they can
    be inaccurate when compared with integer counts.

    Return values are like is_string_valid.
    '''
    if not is_field_valid(field_name, fields, event_desc,
                          is_mandatory=is_mandatory):
        return False
    if field_name not in fields:
        # valid optional field, keep on processing
        return True
    field_value = fields[field_name]
    field_value_summary = summarise_string(field_value)
    # Assume a zero-length value is a list with no items
    if len(field_value) > 0:
        list_count = field_value.count(',') + 1
    else:
        list_count = 0
    if min_count is not None and list_count < min_count:
        logging.warning("Ignored {} '{}', must have at least {} items {}"
                        .format(field_name, field_value_summary, min_count,
                                event_desc))
        logging.debug("Ignored {} (full list) '{}', must have at least {} items {}"
                      .format(field_name, field_value, min_count,
                              event_desc))
        # we can't process it
        return False
    if max_count is not None and list_count > max_count:
        logging.warning("Ignored {} '{}', must have at most {} items {}"
                        .format(field_name, field_value_summary, max_count,
                                event_desc))
        logging.debug("Ignored {} (full list) '{}', must have at most {} items {}"
                      .format(field_name, field_value, max_count,
                              event_desc))
        # we can't process it
        return False
    # it is valid and we want to keep on processing
    return True

def is_int_valid(field_name, fields, event_desc,
                     is_mandatory=False,
                     min_value=None, max_value=None):
    '''
    Check that fields[field_name] passes is_field_valid(), is a valid int,
    and is between min_value and max_value (inclusive). Use None for no
    range check.

    Return values are like is_string_valid.
    '''
    if not is_field_valid(field_name, fields, event_desc,
                          is_mandatory=is_mandatory):
        return False
    if field_name not in fields:
        # valid optional field, keep on processing
        return True
    try:
        field_value = int(fields[field_name])
    except ValueError as e:
        # not an integer
        logging.warning("Ignored {} '{}', must be an integer: '{}' {}"
                        .format(field_name, fields[field_name], e,
                                event_desc))
        return False
    if min_value is not None and field_value < min_value:
        logging.warning("Ignored {} '{}', must be at least {} {}"
                        .format(field_name, field_value, min_value,
                                event_desc))
        # we can't process it
        return False
    if max_value is not None and field_value > max_value:
        logging.warning("Ignored {} '{}', must be at most {} {}"
                        .format(field_name, field_value, max_value,
                                event_desc))
        # we can't process it
        return False
    # it is valid and we want to keep on processing
    return True

def is_flag_valid(field_name, fields, event_desc,
                  is_mandatory=False):
    '''
    Check that fields[field_name] passes is_field_valid() and is 0 or 1.
    See is_int_valid for details.
    '''
    return is_int_valid(field_name, fields, event_desc,
                            is_mandatory=is_mandatory,
                            min_value=0,
                            max_value=1)

def is_float_valid(field_name, fields, event_desc,
                   is_mandatory=False,
                   min_value=None, max_value=None):
    '''
    Check that fields[field_name] passes is_field_valid(), is a valid
    float (includes integral values), and is between min_value and
    max_value (inclusive). Use None for no range check.

    Floating-point values can be inaccurate when compared: if you want equal
    values to be included, use a slightly larger range. Don't use Inf to skip
    a range check, it may not do what you want. None is much more reliable.

    Return values are like is_string_valid.
    '''
    if not is_field_valid(field_name, fields, event_desc,
                          is_mandatory=is_mandatory):
        return False
    if field_name not in fields:
        # valid optional field, keep on processing
        return True
    try:
        field_value = float(fields[field_name])
    except ValueError as e:
        # not a float
        logging.warning("Ignored {} '{}', must be a float: '{}' {}"
                        .format(field_name, fields[field_name], e,
                                event_desc))
        return False
    if min_value is not None and field_value < min_value:
        logging.warning("Ignored {} '{}', must be at least {} {}"
                        .format(field_name, field_value, min_value,
                                event_desc))
        # we can't process it
        return False
    if max_value is not None and field_value > max_value:
        logging.warning("Ignored {} '{}', must be at most {} {}"
                        .format(field_name, field_value, max_value,
                                event_desc))
        # we can't process it
        return False
    # it is valid and we want to keep on processing
    return True

def is_ip_address_valid(field_name, fields, event_desc,
                        is_mandatory=False):
    '''
    Check that fields[field_name] passes is_field_valid(), and is a valid
    IPv4 or IPv6 address.

    Return values are like is_string_valid.
    '''
    if not is_field_valid(field_name, fields, event_desc,
                          is_mandatory=is_mandatory):
        return False
    if field_name not in fields:
        # valid optional field, keep on processing
        return True
    field_value = validate_ip_address(fields[field_name])
    if field_value is None:
        # not an IP address
        logging.warning("Ignored {} '{}', must be an IP address {}"
                        .format(field_name, fields[field_name], event_desc))
        return False
    # it is valid and we want to keep on processing
    return True

def get_string_value(field_name, fields, event_desc,
                     is_mandatory=False,
                     default=None):
    '''
    Check that fields[field_name] exists.
    Asserts if is_mandatory is True and it does not exist.

    If it does exist, return it as a string.
    If it is missing, return default.
    (There are no invalid strings.)
    '''
    if field_name not in fields:
        assert not is_mandatory
        return default

    # This should have been checked earlier
    # There are no non-length string checks, but we do this for consistency
    assert is_string_valid(field_name, fields, event_desc)

    return fields[field_name]

def get_list_value(field_name, fields, event_desc,
                   is_mandatory=False,
                   default=None):
    '''
    Check that fields[field_name] exists.
    Asserts if is_mandatory is True and it does not exist.

    If it does exist, return it as a list of strings, splitting on commas.
    If the field is a zero-length string, returns a list with no items.
    If the field is missing, return default.
    (There are no invalid lists.)
    '''
    if field_name not in fields:
        assert not is_mandatory
        return default

    # This should have been checked earlier
    # There are no non-count list checks, but we do this for consistency
    assert is_list_valid(field_name, fields, event_desc)

    field_value = fields[field_name]
    # Assume a zero-length value is a list with no items
    if len(field_value) > 0:
        return field_value.split(',')
    else:
        return []

def get_int_value(field_name, fields, event_desc,
                  is_mandatory=False,
                  default=None):
    '''
    Check that fields[field_name] exists and is a valid integer.
    Asserts if is_mandatory is True and it does not exist.
    If it is an invalid integer, assert.

    If it exists and is valid, return it as an int or long.
    (Large integers are automatically promoted to long in Python >= 2.7.)
    If it is missing, return default.
    '''
    if field_name not in fields:
        assert not is_mandatory
        return default

    # This should have been checked earlier
    # We're just using this for its integer format check
    assert is_int_valid(field_name, fields, event_desc)

    return int(fields[field_name])

def get_flag_value(field_name, fields, event_desc,
                   is_mandatory=False,
                   default=None):
    '''
    Check that fields[field_name] exists and is a valid numeric boolean
    flag.
    Asserts if is_mandatory is True and it does not exist.
    If it is an invalid integer or out of range of a bool, assert.

    If it exists and is valid, return it as an int or long.

    If it exists and is valid, return it as a bool (True or False).
    If it is missing, return default.
    '''
    if field_name not in fields:
        assert not is_mandatory
        return default

    # This should have been checked earlier
    # We're just using this for its integer format and bool range check
    assert is_flag_valid(field_name, fields, event_desc)

    return bool(int(fields[field_name]))

def get_float_value(field_name, fields, event_desc,
                    is_mandatory=False,
                    default=None):
    '''
    Check that fields[field_name] exists and is a valid float (including
    integral values).
    Asserts if is_mandatory is True and it does not exist.
    If it is an invalid float, assert.

    If it exists and is valid, return it as a float.
    If it is missing, return default.
    '''
    if field_name not in fields:
        assert not is_mandatory
        return default

    # This should have been checked earlier
    # We're just using this for its float format check
    assert is_float_valid(field_name, fields, event_desc)

    return float(fields[field_name])

def get_ip_address_object(field_name, fields, event_desc,
                          is_mandatory=False,
                          default=None):
    '''
    Check that fields[field_name] exists and is a valid IP address.
    Asserts if is_mandatory is True and it does not exist.
    If it is an invalid IP address, assert.

    If it exists and is valid, return it as an ipaddress object.
    If it is missing, return default.
    '''
    if field_name not in fields:
        assert not is_mandatory
        return default

    # This should have been checked earlier
    # We're just using this for its IP address format check
    assert is_ip_address_valid(field_name, fields, event_desc)

    # Convert the IP address to an object, returning None on failure
    return validate_ip_address(fields[field_name])

def get_ip_address_value(field_name, fields, event_desc,
                         is_mandatory=False,
                         default=None):
    '''
    Convert the output of get_ip_address_object() to a string.

    Returns fields[field_name] as a string in canonical IP address form.
    If it is missing, return default.
    '''
    # Canonicalise the IP address and return it as a string
    # This provides maximum compatibility with existing code
    return str(get_ip_address_object(field_name, fields, event_desc,
                                     is_mandatory=is_mandatory,
                                     default=default))
