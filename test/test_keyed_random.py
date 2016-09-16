#!/usr/bin/python

# a simple range and bin test for privcount's random constructions
# this test can not prove that these constructs produce uniformly random
# results, it can only reveal obvious range or partition issues

from os import urandom
from random import randrange
from privcount.util import sample, derive_blinding_factor, Hash

# some of the privcount random functions expect additional arguments
IV = "TEST"
POSITIVE = True

# this should be equal to privcount's hard-coded key length
# key should contain at least 32 bytes of entropy, as the hash is 32 bytes
# (this lack of entropy won't be apparent in the output, because it is hashed)
PRIV_KEY_LEN = Hash().digest_size

# this should be equal to privcount's hard-coded q value
#PRIV_COUNT_MAX = 2147483647L
PRIV_COUNT_MAX = 999999999959L
#PRIV_COUNT_MAX = 2L**64L

# the number of random values used in each trial
N_TRIALS = 100000

# the number of partitions used to check that values are uniformly distributed
BIN_COUNT = 2

# Each of these value functions should return a uniformly distributed
# pseudo-random value in [0, max)
# (we don't check PRF, because it returns raw bytes, and we'd only be finding
# errors in our own unpacking and sampling code)


# call python's random.randrange(max), ignoring key
def random_value(key, max):
    # random.randrange() takes one argument: a maximum value
    # and returns a random value in [0, max)
    # it is *NOT* uniformy distributed in python versions < 3.2
    # but this test is not sophisticated enough to pick that up
    # https://docs.python.org/3.5/library/random.html#random.randrange
    return randrange(max)

# call privcount.util.sample with key and max
def sample_value(key, max):
    # sample takes two arguments: a key string, and a maximum value
    # and returns a random value in [0, max)
    return sample(key, max)

# call privcount.util.blinding_value with IV, key, max, and POSITIVE
def blinding_value(key, max):
    # derive_blinding_factor takes four arguments: a label string,
    # a secret string, a maximum value, and a boolean indicating
    # the direction of blinding
    # and returns a random value in [0, max) for blinding,
    # and (0, max] for unblinding
    value = derive_blinding_factor(IV, key, max, POSITIVE)
    if not POSITIVE:
        # adjust (0, max] to [0, max), ignoring max
        value -= 1
    return value

# Observe the range of func(key, max) with random keys for result_count trials
# Return (min_value, max_value)
def range_trial(result_count, func, max):
    min_value = None
    max_value = None
    count = 0
    while count < result_count:
        key = urandom(PRIV_KEY_LEN)
        value = func(key, max)
        if min_value is None or value < min_value:
            min_value = value
        if max_value is None or value > max_value:
            max_value = value
        count += 1
    return (min_value, max_value)

# Bin a value in [0, max) into one of n_bins
# returns a bin number in [0, n_bins) corresponding to value, or None if value
# does not fit in any bin (this can happen if n_bins does not divide evenly
# into max)
def bin(value, max, n_bins):
    # find values that don't fit evenly in any bin
    residual = max % n_bins
    bin_width = (max - residual) // n_bins
    # make sure we didn't lose any values
    assert bin_width * n_bins + residual == max
    # make sure at least some values go in each bin
    assert bin_width > 0
    if value >= (max - residual):
        return None
    return value // bin_width

# Bin the value of func(key, max) into one of n_bins, returning the bin number
# return the bin corresponding to func's output for key
def key_bin(func, key, max, n_bins):
    value = func(key, max)
    assert value >= 0L
    assert value < max
    bin_number = bin(value, max, n_bins)
    if bin_number is None:
        return None
    assert bin_number >= 0
    assert bin_number < n_bins
    return bin_number

# Do result_count trials of func(key, max) with random keys, and bin each
# result, returning a list of bin counts
def bin_trial(result_count, func, max, n_bins):
    bins = list(0 for i in range(n_bins))
    count = 0
    while count < result_count:
        key = urandom(PRIV_KEY_LEN)
        bin_number = key_bin(func, key, max, n_bins)
        if bin_number is not None:
            bins[bin_number] += 1
            count += 1
    return bins

# Calculate the difference between actual and expected
# Calculate the percentage of total that difference represents
# return a formatted string
def format_difference(actual, expected, total):
    difference = actual - expected
    percentage = round(difference * 100.0 / total, 1)
    return "{} - {} = {} ({} %)".format(actual, expected, difference,
                                        percentage)

# Calculate the difference_list between actual and expected_list
# Calculate the percentage_list of total that difference_list represents
# return a formatted string
def format_difference_list(actual_list, expected, total):
    difference_list = [actual - expected for actual in actual_list]
    percentage_list = [round(difference * 100.0 / total, 1)
                       for difference in difference_list]
    return "{} - {} = {} ({} %)".format(actual_list, expected, difference_list,
                                 percentage_list)

# Run a randomness trial on func and print the results
def run_trial(result_count, func, max, n_bins):
    (obs_min, obs_max) = range_trial(result_count, func, max)
    bin_list = bin_trial(result_count, func, max, n_bins)
    print "Actual - Expected = Difference (% Difference of Max)"
    print "Min: {}".format(format_difference(obs_min, 0, max))
    print "Max: {}".format(format_difference(obs_max, max, max))
    expected_bin_count = result_count / n_bins
    print "Bin: {}".format(format_difference_list(bin_list,
                                                  expected_bin_count,
                                                  expected_bin_count))

print "random.randrange:"
run_trial(N_TRIALS, random_value, PRIV_COUNT_MAX, BIN_COUNT)
print ""

print "privcount.sample:"
run_trial(N_TRIALS, sample_value, PRIV_COUNT_MAX, BIN_COUNT)
print ""

print "privcount.derive_blinding_factor:"
run_trial(N_TRIALS, blinding_value, PRIV_COUNT_MAX, BIN_COUNT)
