#!/usr/bin/env python

'''
python match.py match_type list_path search_count

Prepare list_path for match_type matching.
Search through it for search_count items in the list, and
search_count items that are probably not in the list.
Report how long each step takes. (This is the minimum of 3 repetitions).

ipasn map lookups are supported, but the timings do not include the AS exact
match lookup.

Typical results:
(Try to get total match times greater than 0.2s, to mitigate jitter.)

$ privcount/match.py exact test/domain-top-1m.txt 100000
2.9s to run 1 exact load on test/domain-top-1m.txt
1.3s to run 1 exact prepare on test/domain-top-1m.txt
0.000005 per lookup to run 100000 exact matches on test/domain-top-1m.txt (total time 0.5s)
0.000018 per lookup to run 100000 exact non-matches on test/domain-top-1m.txt (total time 1.8s)

$ privcount/match.py suffix test/domain-top-1m.txt 100000
3.6s to run 1 suffix load on test/domain-top-1m.txt
23.7s to run 1 suffix prepare on test/domain-top-1m.txt
0.000007 per lookup to run 100000 suffix matches on test/domain-top-1m.txt (total time 0.7s)
0.000016 per lookup to run 100000 suffix non-matches on test/domain-top-1m.txt (total time 1.6s)

$ privcount/match.py suffix_reverse test/domain-top-1m.txt 100000;
3.6s to run 1 suffix_reverse load on test/domain-top-1m.txt
4.1s to run 1 suffix_reverse prepare on test/domain-top-1m.txt
0.000011 per lookup to run 100000 suffix_reverse matches on test/domain-top-1m.txt (total time 1.1s)
0.000022 per lookup to run 100000 suffix_reverse non-matches on test/domain-top-1m.txt (total time 2.2s)

$ privcount/match.py ipasn test/as-ipv4.ipasn 100000
0.5s to run 1 ipasn load on test/as-ipv4.ipasn
0.2s to run 1 ipasn prepare on test/as-ipv4.ipasn
0.000008 per lookup to run 100000 ipasn matches on test/as-ipv4.ipasn (total time 0.8s)
0.000030 per lookup to run 100000 ipasn non-matches on test/as-ipv4.ipasn (total time 3.0s)

$ privcount/match.py ipasn test/as-ipv6.ipasn 100000
0.1s to run 1 ipasn load on test/as-ipv6.ipasn
0.0s to run 1 ipasn prepare on test/as-ipv6.ipasn
0.000006 per lookup to run 100000 ipasn matches on test/as-ipv6.ipasn (total time 0.6s)
0.000026 per lookup to run 100000 ipasn non-matches on test/as-ipv6.ipasn (total time 2.6s)

Created on Nov 17, 2017

@author: teor

See LICENSE for licensing information
'''

import bisect
import logging
import os
import pyasn

from privcount.config import normalise_path, check_domain_name, check_country_code, check_as_number
from privcount.crypto import json_serialise
from privcount.log import summarise_string, format_bytes, summarise_list

def line_is_comment(line):
    '''
    Is line a comment line?
    Comment lines are empty, or start with #, //, or ;
    Line should be stripped before calling this function.
    '''
    return (len(line) == 0 or line.startswith('#') or line.startswith('//')
            or line.startswith(';'))

def load_match_list(file_path,
                    check_domain=False, check_country=False, check_as=False):
    '''
    Load a match list from file_path, checking the format based on check_*.
    Return a tuple with the normalised file path, and the match list.
    '''
    file_path = normalise_path(file_path)
    assert os.path.exists(file_path)

    # import and validate this list of match names
    # This can take a few seconds
    match_list = []
    with open(file_path, 'r') as fin:
        for line in fin:
            # Ignore leading or trailing whitespace
            line = line.strip()
            # Ignore comments
            if line_is_comment(line):
                continue
            if check_domain:
                assert check_domain_name(line)
                # Always lowercase matches, IANA likes them uppercase
                line = line.lower()
                line = line.strip(".")
            if check_country:
                assert check_country_code(line)
                # Always lowercase matches, MaxMind likes them uppercase
                line = line.lower()
            if check_as:
                # Now convert the AS number to an integer
                line = int(line)
                assert check_as_number(line)
            match_list.append(line)

    return (file_path, match_list)

def load_as_prefix_map(file_path):
    '''
    Load an AS map from file_path. Never checks the format.
    Return a tuple with the normalised file path, and the AS map.
    '''
    file_path = normalise_path(file_path)
    assert os.path.exists(file_path)

    map_list = []
    with open(file_path, 'r') as fin:
        for line in fin:
            # Ignore leading or trailing whitespace
            line = line.strip()
            # Ignore comments
            if line_is_comment(line):
                continue
            map_list.append(line)

    return (file_path, map_list)

def lower_if_hasattr(obj):
    '''
    If obj has a lower attribute, return obj.lower().
    Otherwise, return obj.
    '''
    return obj.lower() if hasattr(obj, 'lower') else obj

def exact_match_validate_item(exact_obj, search_string,
                              original_list):
    '''
    Search exact_obj for search_string.

    If the search fails, log a warning using original_list, and raise an
    exception.
    '''
    try:
        assert exact_match(exact_obj, search_string)
    except:
        logging.warning("Validating exact {} failed:\nOriginal:\n{}\nSet:\n{}"
                        .format(search_string,
                                summarise_list(original_list),
                                summarise_list(exact_obj)))
        logging.debug("Validating exact {} failed:\nOriginal (full):\n{}\nSet (full):\n{}"
                      .format(search_string,
                              original_list,
                              exact_obj))
        raise

def exact_match_prepare_collection(exact_collection,
                                   existing_exacts=None,
                                   validate=True):
    '''
    Prepare a hashable object collection for efficient exact matching.
    If the objects in the collection are strings, lowercases them.

    existing_exacts is a list of previously prepared collections.

    If existing_exacts is not None, append the new collection to
    existing_exacts, as well as returning the prepared collection.

    If multiple lists are prepared using the same existing_exacts, then
    the final lists are disjoint. Any duplicate items are ignored, and a
    warning is logged. (An item that appears in multiple input lists is
    output in the earliest list it appears in.)

    If validate is True, checks that exact_match() returns True for each
    item in exact_collection.

    Returns an object that can be passed to exact_match().
    This object must be treated as opaque and read-only.
    '''
    assert exact_collection is not None
    # Set matching uses a hash table, so it's more efficient
    exact_collection_lower = [lower_if_hasattr(obj) for obj in exact_collection]
    exact_set = frozenset(exact_collection_lower)
    # Log a message if there were any duplicates
    # Finding each duplicate takes a lot longer
    if len(exact_collection) != len(exact_set):
      dups = [obj for obj in exact_set
              if exact_collection_lower.count(lower_if_hasattr(obj)) > 1]
      logging.warning("Removing {} duplicates within this collection"
                      .format(summarise_list(dups)))
    # the encoded json measures transmission size, not RAM size
    logging.info("Exact match prepared {} items ({})"
                 .format(len(exact_set),
                         format_bytes(len(json_serialise(list(exact_set))))))

    # Check that each item actually matches the list
    if validate:
        for item in exact_collection:
            exact_match_validate_item(exact_set, item, exact_collection)

    if existing_exacts is None:
        return exact_set
    else:
        # Remove any items that appear in earlier lists
        disjoint_exact_set = exact_set.difference(*existing_exacts)
        duplicate_exact_set = exact_set.difference(disjoint_exact_set)
        if len(duplicate_exact_set) > 0:
            logging.warning("Removing {} duplicates that are also in an earlier collection"
                            .format(summarise_list(duplicate_exact_set)))
        existing_exacts.append(disjoint_exact_set)
        return disjoint_exact_set

def exact_match(exact_obj, search_obj):
    '''
    Performs an efficient O(1) exact match for search_obj in exact_obj.
    If search_obj is a string, performs a case-insensitive match.
    exact_obj must have been created by exact_match_prepare_collection().
    '''
    if exact_obj is None:
        return False
    # This code only works efficiently on sets
    assert hasattr(exact_obj, 'issubset')
    # This is a single hash table lookup
    return lower_if_hasattr(search_obj) in exact_obj

def suffix_match_split(suffix_string, separator=""):
    '''
    Lowercase suffix_string, and split it into components.
    If separator is the empty string, returns a list of characters.
    Otherwise, returns a list of string components separated by separator.
    '''
    # make sure it's in a consistent format
    suffix_string = suffix_string.lower()
    suffix_string = suffix_string.strip(separator)
    # now split on separator
    if len(separator) == 0:
        # a string is an iterator on its own characters
        return list(reversed(list(suffix_string)))
    else:
        return list(reversed(suffix_string.split(separator)))

def is_collection_tag_valid(collection_tag):
    '''
    Collection tags can be any non-dict object that is not None.
    '''
    return type(collection_tag) != dict and collection_tag is not None

def suffix_match_validate_item(suffix_obj, search_string,
                               original_list, separator="",
                               expected_collection_tag=-1,
                               expect_disjoint=True):
    '''
    Search suffix_obj for search_string using separator.
    If expect_disjoint is True, make sure it yields expected_collection_tag.
    Otherwise, make sure it yields a collection tag that is not None.

    If the search fails, log a warning using original_list, and raise an
    exception.
    '''
    try:
        found_collection_tag = suffix_match(suffix_obj, search_string,
                                            separator=separator)
        if expect_disjoint:
            assert found_collection_tag == expected_collection_tag
        else:
            assert found_collection_tag is not None
    except:
        logging.warning("Validating suffix {} -> {} found {} ({}):\nOriginal:\n{}\nTree:\n{}"
                        .format(search_string,
                                expected_collection_tag,
                                found_collection_tag,
                                "required disjoint" if expect_disjoint else "allowed overlaps",
                                summarise_list(original_list),
                                summarise_list(suffix_obj.keys())))
        logging.debug("Validating suffix {} -> {} found {} ({}):\nOriginal (full):\n{}\nTree (full):\n{}"
                      .format(search_string,
                              expected_collection_tag,
                              found_collection_tag,
                              "required disjoint" if expect_disjoint else "allowed overlaps",
                              original_list,
                              suffix_obj))
        raise

def suffix_match_prepare_collection(suffix_collection, separator="",
                                    existing_suffixes=None, collection_tag=-1,
                                    validate=True):
    '''
    Prepare a collection of strings for efficient suffix matching.
    If specified, the separator is also required before the suffix.
    For example, domain suffixes use "." as a separator between components.

    existing_suffixes is a previously prepared suffix data structure.

    If existing_suffixes is not None, add the new suffixes to
    existing_suffixes, and return existing_suffixes. Each suffix is terminated
    with collection_tag, which can be used to distinguish between suffixes
    from different lists. collection_tag must be a non-dict type that is not
    None.

    If multiple lists are prepared using the same existing_suffixes, then the
    final suffix data structure is disjoint. Any duplicate or longer
    suffixes are eliminated, and a warning is logged. (A suffix that appears
    in multiple input lists is output in the earliest list it appears in.
    A shorter suffix in a later list replaces any longer suffixes in earlier
    lists.)

    If validate is True, checks that suffix_match() returns True for each
    item in suffix_collection.

    Returns a tuple containing an object that can be passed to suffix_match(),
    and a boolean that is True if any duplicate domains were found.
    The object must be treated as opaque and read-only.
    '''
    assert suffix_collection is not None
    assert is_collection_tag_valid(collection_tag)
    #assert type(existing_suffixes) == dict
    # Create a tree of suffix components using nested python dicts
    # the terminal object is an empty dict
    if existing_suffixes is None:
        suffix_obj = {}
    else:
        suffix_obj = existing_suffixes
    longer_suffix_list = []
    duplicates = False
    for insert_string in suffix_collection:
        #assert type(suffix_obj) == dict
        insert_list = suffix_match_split(insert_string, separator=separator)
        prev_suffix_node = None
        suffix_node = suffix_obj
        # did we terminate the loop early due to a longer suffix?
        has_longer_suffix = False
        for insert_component in insert_list:
            # since we have stripped periods from the start and end, a double
            # dot is almost certainly a typo
            assert len(insert_component) > 0

            # we are allowed to add any child to the root
            # but we cannot add a child to an existing terminal object
            # because the existing tree contains a shorter suffix of
            # the string we are inserting
            #assert type(suffix_node) == dict
            next_suffix_node = suffix_node.get(insert_component)
            if (is_collection_tag_valid(next_suffix_node)):
                # there is an existing suffix that terminates here, and we are
                # about to insert a longer suffix. Instead, ignore the longer
                # suffix
                has_longer_suffix = True
                longer_suffix_list.append(insert_string)
                break

            # walk the tree, adding an entry for this suffix
            prev_suffix_node = suffix_node
            suffix_node = (next_suffix_node if next_suffix_node is not None else
                           suffix_node.setdefault(insert_component, {}))

        # we cannot have children in our terminal object
        # because the existing tree contains longer strings, and we are
        # a shorter suffix of all those existing strings
        if (not has_longer_suffix and
            not is_collection_tag_valid(suffix_node) and len(suffix_node) > 0):
            duplicates = True
            child_summary = summarise_list(suffix_node.keys())
            child_all = " ".join(suffix_node.keys())
            logging.warning("Adding shorter suffix {} for collection {}, pruning existing children {}"
                            .format(insert_string, collection_tag, child_summary))
            logging.debug("Adding shorter suffix {} for collection {}, pruning existing children {}"
                          .format(insert_string, collection_tag, child_all))

        # now, place (or replace) the end of the domain with the collection tag
        if not has_longer_suffix:
            #assert prev_suffix_node is not None
            prev_suffix_node[insert_component] = collection_tag

        # Now check that each item actually matches the list
        if validate:
            suffix_match_validate_item(suffix_obj, insert_string,
                                       suffix_collection,
                                       separator=separator,
                                       expected_collection_tag=collection_tag,
                                       expect_disjoint=False)

    if len(longer_suffix_list) > 0:
        duplicates = True
        suffix_summary = summarise_list(longer_suffix_list)
        suffix_all = " ".join(longer_suffix_list)
        logging.warning("Suffix match for {} ignored longer suffixes {}"
                        .format(collection_tag, suffix_summary))
        logging.debug("Suffix match for {} ignored longer suffixes {}"
                      .format(collection_tag, suffix_all))

    # the encoded json measures transmission size, not RAM size
    logging.info("Suffix match {} prepared {} items ({})"
                 .format(collection_tag, len(suffix_collection),
                         format_bytes(len(json_serialise(suffix_obj)))))

    return (suffix_obj, duplicates)

def suffix_match(suffix_obj, search_string, separator=""):
    '''
    Performs an efficient O(min(M,N)) case-insensitive suffix match on
    search_string in suffix_obj, where M is the number of components in
    search_string, and N is the maximum number of components in any string in
    suffix_obj.

    If specified, the separator is also required before the suffix.
    For example, domain suffixes use "." as a separator between components.

    suffix_obj must have been created by suffix_match_prepare_collection(),
    with the same separator.

    Returns the original collection_tag on a suffix match and exact match, and
    None on no match. If you are only looking for exact matches, use
    exact_match() to find them more efficiently.
    '''
    if suffix_obj is None or search_string is None or separator is None:
        return None
    # Split and reverse the string for matching
    search_list = suffix_match_split(search_string, separator=separator)
    # Walk the tree
    suffix_node = suffix_obj
    for search_component in search_list:
        #logging.debug("{} in {}:\nTree:\n{}"
        #              .format(search_component, search_list, suffix_node))
        # an empty string can never match anything
        if len(search_component) == 0:
            return None
        # we reached a component that isn't in the tree, so the suffix does
        # not match
        if search_component not in suffix_node:
            return None
        # walk the tree with the search components
        suffix_node = suffix_node[search_component]
        # we reached a terminal component, so the suffix matches
        if is_collection_tag_valid(suffix_node):
            return suffix_node
    # we reached the end of the search string, and was there, but there wasn't
    # a terminator, so the suffix does not match
    # try to speed up the worst case
    assert not is_collection_tag_valid(suffix_node)
    return None

def reverse_string(s):
    '''
    Reverse the string s
    '''
    return "".join(reversed(s))

def suffix_reverse_match_collate_collection(suffix_collection, separator=""):
    '''
    Collate a collection of strings for efficient suffix matching.
    If specified, the separator is also required before the suffix.
    For example, domain suffixes use "." as a separator between components.

    If suffix_collection contains any strings that are exact duplicates,
    log an warning-level message, and remove them.

    Returns an object that can be passed to suffix_match().
    This object must be treated as opaque and read-only.
    But in most cases, you will want to use suffix_match_prepare_collection()
    to uniquify the suffixes in the collection as well.
    '''
    # A binary search requires a prefix match, so we have to reverse all the
    # strings, then sort them. Stripping any separators makes sure that the
    # match works.
    # A generalised suffix tree might be faster here.

    suffix_collection = [s.lower() for s in suffix_collection]
    sorted_suffix_list = sorted([reverse_string(s.strip(separator)) + separator
                                 for s in suffix_collection])

    # This takes about 2 seconds on the Alexa Top 1 million, and doesn't find
    # any duplicates. So we avoid doing it
    #suffix_set = set(sorted_suffix_list)
    # Log a message if there were any duplicates
    # Finding each duplicate takes a lot longer
    #if len(suffix_collection) != len(suffix_set):
    #    logging.warning("Removing {} duplicate suffixes from the collection"
    #                    .format(len(suffix_collection) - len(suffix_set)))

    return sorted_suffix_list

def suffix_reverse_match_uniquify_collection(suffix_obj, separator=""):
    '''
    Check if suffix_obj contains any strings that are a suffix of any other
    strings, log an warning-level message, and remove them.

    If specified, the separator is also required before the suffix.
    For example, domain suffixes use "." as a separator between components.
    '''
    # Find longer suffixes that match shorter suffixes in the list
    longer_suffix_matches = []
    for s in suffix_obj:
        # this doesn't match s itself, only longer duplicates
        if suffix_reverse_match(suffix_obj, reverse_string(s), separator):
            # don't modify the list while iterating it
            longer_suffix_matches.append(s)

    # Removing the longer suffixes is safe, because the list remains in-order
    logging.warning("Removing {} duplicate longer suffixes from the collection"
                    .format(len(longer_suffix_matches)))
    for s in longer_suffix_matches:
        # if there are multiple duplicates, they will all be removed
        suffix_obj.remove(s)

def suffix_reverse_match_prepare_collection(suffix_collection, separator=""):
    '''
    Prepare a collection of strings for efficient suffix matching.
    If specified, the separator is also required before the suffix.
    For example, domain suffixes use "." as a separator between components.

    Returns an object that can be passed to suffix_match().
    This object must be treated as opaque and read-only.
    '''
    assert suffix_collection is not None
    assert separator is not None
    # A binary search is efficient, even if it does double the RAM
    # requirement. And it's unlikely we could get rid of all the references to
    # the strings in the collection after reversing them, anyway.

    suffix_obj = suffix_reverse_match_collate_collection(suffix_collection,
                                                         separator)
    # This takes about 20 seconds for the Alexa Top 1 million, and only finds
    # 239 duplicates. So maybe it's not worth doing.
    #suffix_match_uniquify_collection(suffix_obj, separator)

    # the encoded json measures transmission size, not RAM size
    logging.info("Suffix match prepared {} items ({})"
                 .format(len(suffix_obj),
                         format_bytes(len(json_serialise(suffix_obj)))))

    return suffix_obj

def suffix_reverse_match(suffix_obj, search_string, separator=""):
    '''
    Performs an efficient O(log(N)) case-insensitive suffix match on
    search_string in suffix_obj.
    If specified, the separator is also required before the suffix.
    For example, domain suffixes use "." as a separator between components.

    suffix_obj must have been created by suffix_match_prepare_collection(),
    with the same separator.

    Returns True on a suffix match, but False on exact match and no match.
    Use exact_match() to find exact matches.
    '''
    if suffix_obj is None or search_string is None:
        return False
    # This code works on sorted lists, but checking is expensive
    # assert suffix_obj == sorted(suffix_obj)
    # We could also store the separator, and check it is the same

    # this is O(log(N)) because it's a binary search followed by a string
    # prefix match
    # We need to strip separators to make sure the match works.
    reversed_search_string = reverse_string(search_string.lower().strip(separator))
    # Longer strings sort after shorter strings, so our candidate is the
    # previous string. This works when there are multiple possible matches,
    # but it is inefficient.
    candidate_idx = bisect.bisect_left(suffix_obj, reversed_search_string) - 1
    # We should always get an entry in the list
    assert candidate_idx < len(suffix_obj)
    # If there is no previous entry, the string is definitely not a match
    if candidate_idx < 0:
        return False
    candidate_reversed_suffix = suffix_obj[candidate_idx]
    #logging.warning("{} -> {} candidate {} -> {} in {}"
    #                .format(search_string, reversed_search_string, candidate_idx,
    #                        candidate_reversed_suffix, suffix_obj))
    return reversed_search_string.startswith(candidate_reversed_suffix)

def ipasn_prefix_match_prepare_string(ipasn_string):
    '''
    Prepare ipasn data for efficient IP prefix matching.
    ipasn_string is a string containing a newline-separated list of IP prefix
    to AS mappings.

    Returns an object that can be passed to ipasn_prefix_match().
    This object must be treated as opaque and read-only.
    '''
    assert ipasn_string is not None
    obj = pyasn.pyasn(None, ipasn_string=ipasn_string)
    # we want to measure transmission size, not RAM size
    # we don't transmit obj, because it's opaque C
    # instead, we assume that the json-serialised string will be about the
    # same size as the actual string
    logging.info("IP-ASN match prepared {} items ({})"
                 .format(len(ipasn_string.splitlines()),
                         format_bytes(len(ipasn_string))))
    return obj

def ipasn_prefix_match(ipasn_prefix_obj, search_ip):
    '''
    Performs an efficient radix prefix match on search_ip in ipasn_prefix_obj.

    prefix_obj must have been created by
    ipasn_prefix_match_prepare_string().

    Returns the corresponding AS number, or None on no match.
    '''
    if ipasn_prefix_obj is None or search_ip is None:
        return None
    (as_number, ip_prefix) = ipasn_prefix_obj.lookup(str(search_ip))
    return as_number

# Main function

import ipaddress
import random
import sys
import timeit

from privcount.config import validate_ip_address

def load_domain_list(file_path, check_domain=True):
    '''
    Adapter for easy domain list loading
    '''
    return load_match_list(file_path, check_domain=check_domain)

def suffix_match_prepare_domains(suffix_collection):
    '''
    Adapter for easy domain list preparation
    '''
    (obj, _) = suffix_match_prepare_collection(suffix_collection,
                                               separator=".")
    return obj

def suffix_reverse_match_prepare_domains(suffix_collection):
    '''
    Adapter for easy reverse domain list preparation
    '''
    return suffix_reverse_match_prepare_collection(suffix_collection,
                                                   separator=".")

def suffix_match_domain(suffix_obj, search_string):
    '''
    Adapter for easy domain matching
    '''
    return suffix_match(suffix_obj, search_string, separator=".")

def suffix_reverse_match_domain(suffix_obj, search_string):
    '''
    Adapter for easy reverse domain matching
    '''
    return suffix_reverse_match(suffix_obj, search_string, separator=".")

def ipasn_prefix_match_prepare_list(ipasn_list):
    '''
    Adapter for easy AS list preparation
    '''
    return ipasn_prefix_match_prepare_string("\n".join(ipasn_list))

MATCH_FUNCTION = {
# exact domain, country, and AS counters use exact matching
'exact'          : { 'load' : load_domain_list,   'prepare' : exact_match_prepare_collection,       'match' : exact_match                 },
# suffix domain counters use exact matching
'suffix'         : { 'load' : load_domain_list,   'prepare' : suffix_match_prepare_domains,         'match' : suffix_match_domain         },
# legacy code for comparison
'suffix_reverse' : { 'load' : load_domain_list,   'prepare' : suffix_reverse_match_prepare_domains, 'match' : suffix_reverse_match_domain },
# AS counters use a map lookup, and then they use exact matching. This only times the map lookup.
'ipasn'          : { 'load' : load_as_prefix_map, 'prepare' : ipasn_prefix_match_prepare_list,      'match' : ipasn_prefix_match },
}

match_func_result = {}

def call_match_func(func_type, *args):
    '''
    Call MATCH_FUNCTION[sys.argv[1]][func_type](*args), and put the result
    in match_func_result.
    '''
    global match_func_result
    match_func_result[func_type] = MATCH_FUNCTION[sys.argv[1]][func_type](*args)

def get_match_func_result(func_type):
    '''
    Return match_func_result[func_type].
    '''
    global match_func_result
    return match_func_result[func_type]

def get_random_load_entry():
    '''
    Return a random item from match_func_result['load'].
    '''
    global match_func_result
    match_type = sys.argv[1]
    line = random.choice(match_func_result['load'][1])
    if match_type == 'ipasn':
        ip, _, _ = line.partition("/")
        return ip
    else:
        return line

def get_random_load_nonentry():
    '''
    Return a random item that probably isn't in match_func_result['load'].
    '''
    match_type = sys.argv[1]
    if match_type == 'ipasn':
        # Yes, we could do IPv6 here. But the type of the list doesn't matter:
        # a random IPv4 might not be in an IPv4 list, and it won't be in an
        # IPv6 list
        random_32_bit = random.randint(0, 2**32 - 1)
        ip = ipaddress.ip_address(random_32_bit)
        return ip
    else:
        char_list = list(get_random_load_entry())
        random.shuffle(char_list)
        return "".join(char_list)

# try to make sure that other processes don't warp the results too much
DEFAULT_REPETITIONS = 10

def main():
    if len(sys.argv) != 4:
        print ("Usage: {} match_type list_path search_count"
               .format(sys.argv[0]))
        return -1

    match_type = sys.argv[1]
    list_path = sys.argv[2]
    match_count = long(sys.argv[3])

    # the garbage collector needs to be on for some tests, because otherwise
    # they run out of RAM using too many small objects

    # we don't really care how long loading and processing takes, so we only
    # repeat the tests once
    reps = timeit.repeat("call_match_func('load', sys.argv[2])",
                         setup="""\
from __main__ import call_match_func
gc.enable()""",
                         number=1, repeat=1)
    print ("{:.1f}s to run 1 {} load on {}"
           .format(min(reps), match_type, list_path))
    reps = timeit.repeat("call_match_func('prepare', get_match_func_result('load')[1])",
                         setup="""\
from __main__ import call_match_func, get_match_func_result
gc.enable()""",
                         number=1, repeat=1)
    print ("{:.1f}s to run 1 {} prepare on {}"
           .format(min(reps), match_type, list_path))
    reps = timeit.repeat("call_match_func('match', get_match_func_result('prepare'), get_random_load_entry())",
                         setup="""\
from __main__ import call_match_func, get_match_func_result, get_random_load_entry
gc.enable()""",
                         number=match_count, repeat=DEFAULT_REPETITIONS)
    print ("{:.6f} per lookup to run {} {} matches on {} (total time {:.1f}s)"
           .format(min(reps)/match_count, match_count, match_type, list_path, min(reps)))
    reps = timeit.repeat("call_match_func('match', get_match_func_result('prepare'), get_random_load_nonentry())",
                           setup="""\
from __main__ import call_match_func, get_match_func_result, get_random_load_nonentry
gc.enable()""",
                         number=match_count, repeat=DEFAULT_REPETITIONS)
    print ("{:.6f} per lookup to run {} {} non-matches on {} (total time {:.1f}s)"
           .format(min(reps)/match_count, match_count, match_type, list_path, min(reps)))

    return 0

if __name__ == "__main__":
  sys.exit(main())
