#!/usr/bin/python

# this test will fail if any counter inconsistencies are detected

from privcount.util import SecureCounters, adjust_count_signed
from math import sqrt
import sys

# This q must be kept the same as privcount's configured q value
q = 999999999959L
# When testing q itself, use this range of values
# We have to limit the lower value, because sample() re-hashes when the first
# 4 bytes of the hash are greater than q
q_min = 2L**24L
q_max = 2L**64L

# A simple set of byte counters
counters = {
  'SanityCheck': {
    'bins':
    [
      [0.0, float('inf')],
    ],
    'sigma': 0.0
  },
  'Bytes': {
    'bins':
    [
      [0.0, 512.0],
      [512.0, 1024.0],
      [1024.0, 2048.0],
      [2048.0, 4096.0],
      [4096.0, float('inf')],
    ],
    'sigma': 0.0
  }
}

# check that adjust_count_signed works as expected for q
def check_adjust_count_signed(q):
    # for any q, returns { (q + 1)//2 - q, ... , 0, ... , (q + 1)//2 - 1 }
    assert adjust_count_signed(0, q) == 0
    # we assume here that q is large
    assert q >= 3
    assert adjust_count_signed(1, q) == 1
    assert adjust_count_signed((q + 1)//2 - 1, q) == (q + 1)//2 - 1
    assert adjust_count_signed((q + 1)//2, q) == (q + 1)//2 - q
    assert adjust_count_signed(q - 1, q) == -1

# check that each blinding share is unique
# if not, there is a coding error that affects the security of the system
def check_blinding_shares(shares):
    blinding_share_list = []
    for sk_name in shares:
        blinding_share_list.append(shares[sk_name]['secret'])
    # are all the blinding shares unique?
    # since there are only 2 x 256 bit values, collisions are very unlikely
    assert len(blinding_share_list) == len(set(blinding_share_list))

# check that each blinding value is unique
# if not, there is a coding error that affects the security of the system
def check_blinding_values(secure_counters, q):
    blinding_value_list = []
    for key in secure_counters.counters:
        for item in secure_counters.counters[key]['bins']:
            blinding_value_list.append(item[2])
    # are all the blinding values unique?
    # only check this if the number of items is very small compared with q
    # RAM bit error rates are up to 10^-13 per second
    # http://www.cs.toronto.edu/~bianca/papers/sigmetrics09.pdf
    # So this check should fail by chance less often than a hardware error
    # Using the approximation from
    # https://en.wikipedia.org/wiki/Birthday_problem#Square_approximation
    # n = sqrt(2m * p(n)) where m is q and p(n) is 10^-13
    max_blinding_value_count = sqrt(2.0 * (q / (10L**13L)))
    blinding_value_count = len(blinding_value_list)
    unique_blinding_value_count = len(set(blinding_value_list))
    print "q: {} max_blinding: {} actual blinding: {}".format(
        q, max_blinding_value_count, blinding_value_count)
    if blinding_value_count < max_blinding_value_count:
        assert blinding_value_count == unique_blinding_value_count
    else:
        print "skipping blinding value collision test: collisions too likely"

# create the counters for a data collector, who will generate the shares and
# noise
# uses q to generate the appropriate blinding factors
# returns a tuple containing a list of DCs and a list of SKs
def create_counters(counters, q):
    sc_dc = SecureCounters(counters, q)
    sc_dc.generate(['sk1', 'sk2'], 1.0)
    check_blinding_values(sc_dc, q)
    # get the shares used to init the secure counters on the share keepers
    shares = sc_dc.detach_blinding_shares()

    # make sure the blinding shares are unique
    check_blinding_shares(shares)

    # create share keeper versions of the counters
    sc_sk1 = SecureCounters(counters, q)
    sc_sk1.import_blinding_share(shares['sk1'])
    check_blinding_values(sc_sk1, q)
    sc_sk2 = SecureCounters(counters, q)
    sc_sk2.import_blinding_share(shares['sk2'])
    check_blinding_values(sc_sk2, q)
    return ([sc_dc], [sc_sk1, sc_sk2])

# run a set of increments at the dc N times, using the two-argument form of
# increment() to increment by 1 each time
# each bin has 0, 1, or 2 values added per increment when multi_bin is True,
# and 0 or 1 values added per increment when multi_bin is False
# Returns long(N)
def increment_counters(dc_list, N, multi_bin=True):
    sc_dc = dc_list[0]
    # xrange only accepts python ints, which is ok, because it's impossible to
    # increment more than 2**31 times in any reasonable test duration
    assert N <= sys.maxint
    for _ in xrange(int(N)):
        # bin[0]
        sc_dc.increment('Bytes', 0.0)
        if multi_bin:
            sc_dc.increment('Bytes', 511.0)
        #bin[1]
        sc_dc.increment('Bytes', 600.0)
        #bin[2]
        if multi_bin:
            sc_dc.increment('Bytes', 1024.0)
        sc_dc.increment('Bytes', 2047.0)
        #bin[3]
        pass
        #bin[4]
        sc_dc.increment('Bytes', 4096.0)
        if multi_bin:
            sc_dc.increment('Bytes', 10000.0)
    return long(N)

# run a set of increments at the dc N times, incrementing by X each time
# each bin has 0, 1, or 2 values added per increment when multi_bin is True,
# and 0 or 1 values added per increment when multi_bin is False
# Returns long(N) * long(X)
def increment_counters_num(dc_list, N, X=1L, multi_bin=True):
    sc_dc = dc_list[0]
    # xrange only accepts python ints, which is ok, because it's impossible to
    # increment more than 2**31 times in any reasonable test duration
    assert N <= sys.maxint
    for _ in xrange(int(N)):
        # bin[0]
        sc_dc.increment('Bytes', 0.0, long(X))
        if multi_bin:
            sc_dc.increment('Bytes', 511.0, long(X))
        #bin[1]
        sc_dc.increment('Bytes', 600.0, long(X))
        #bin[2]
        if multi_bin:
            sc_dc.increment('Bytes', 1024.0, long(X))
        sc_dc.increment('Bytes', 2047.0, long(X))
        #bin[3]
        pass
        #bin[4]
        sc_dc.increment('Bytes', 4096.0, long(X))
        if multi_bin:
            sc_dc.increment('Bytes', 10000.0, long(X))
    return long(N)*long(X)

# Sums the counters in dc_list and sk_list, with maximum count q
# Returns a tallies object populated with the resulting counts
def sum_counters(counters, q, dc_list, sk_list):
    # get all of the counts, send for tallying
    counts_dc_list = [sc_dc.detach_counts() for sc_dc in dc_list]
    counts_sk_list = [sc_sk.detach_counts() for sc_sk in sk_list]

    # tally them up
    sc_ts = SecureCounters(counters, q)
    counts_list = counts_dc_list + counts_sk_list
    is_tally_success = sc_ts.tally_counters(counts_list)
    assert is_tally_success
    return sc_ts.detach_counts()

# Checks that the tallies are the expected values, based on the number of
# repetitions N, and whether we're in multi_bin mode
def check_counters(tallies, N, multi_bin=True):
    print tallies
    if multi_bin:
        assert tallies['Bytes']['bins'][0][2] == 2*N
    else:
        assert tallies['Bytes']['bins'][0][2] == 1*N
    assert tallies['Bytes']['bins'][1][2] == 1*N
    if multi_bin:
        assert tallies['Bytes']['bins'][2][2] == 2*N
    else:
        assert tallies['Bytes']['bins'][2][2] == 1*N
    assert tallies['Bytes']['bins'][3][2] == 0*N
    if multi_bin:
        assert tallies['Bytes']['bins'][4][2] == 2*N
    else:
        assert tallies['Bytes']['bins'][4][2] == 1*N
    assert tallies['SanityCheck']['bins'][0][2] == 0
    print "all counts are correct!"

# Validate that a counter run with counters, q, N, X, and multi_bin works,
# and produces consistent results
# If X is None, use the 2-argument form of increment, otherwise, use the
# 3-argument form
def try_counters(counters, q, N, X=None, multi_bin=True):
    (dc_list, sk_list) = create_counters(counters, q)
    if X is None:
        # use the 2-argument form
        amount = increment_counters(dc_list, N, multi_bin)
        assert amount == N
    else:
        # use the 3-argument form
        amount = increment_counters_num(dc_list, N, X, multi_bin)
        assert amount == N*X
    tallies = sum_counters(counters, q, dc_list, sk_list)
    check_counters(tallies, amount, multi_bin)

# Check that unsigned to signed conversion works with odd and even q
print "Unsigned to signed counter conversion, q = 3:"
# for odd  q, returns { -q//2, ... , 0, ... , q//2 }
assert adjust_count_signed(0, 3) == 0
assert adjust_count_signed(1, 3) == 1
assert adjust_count_signed(2, 3) == -1
print ""

print "Unsigned to signed counter conversion, q = 4:"
# for even q, returns { -q//2, ... , 0, ... , q//2 - 1 }
assert adjust_count_signed(0, 4) == 0
assert adjust_count_signed(1, 4) == 1
assert adjust_count_signed(2, 4) == -2
assert adjust_count_signed(3, 4) == -1
print ""

print "Unsigned to signed counter conversion, q = {}:".format(q)
check_adjust_count_signed(q)
print ""

print "Unsigned to signed counter conversion, q = {}:".format(q+1)
check_adjust_count_signed(q+1)
print ""

print "Unsigned to signed counter conversion, q = {}:".format(q-1)
check_adjust_count_signed(q-1)
print ""

# Check that secure counters increment correctly for small values of N
# using the default increment of 1
print "Multiple increments, 2-argument form of increment:"
N = 500L
try_counters(counters, q, N)
print ""

# Check that secure counters increment correctly for a single increment
# using a small value of num_increment
print "Single increment, 3-argument form of increment:"
N = 1L
X = 500L
try_counters(counters, q, N, X)
print ""

# And multiple increments using the 3-argument form
print "Multiple increments, 3-argument form of increment, explicit +1:"
N = 500L
X = 1L
try_counters(counters, q, N, X)

print "Multiple increments, 3-argument form of increment, explicit +2:"
N = 250L
X = 2L
try_counters(counters, q, N, X)

print "Multiple increments, 2-argument form of increment, multi_bin=False:"
N = 20L
try_counters(counters, q, N, multi_bin=False)

print "Multiple increments, 3-argument form of increment, multi_bin=False:"
N = 20L
X = 1L
try_counters(counters, q, N, X, multi_bin=False)
print ""

print "Increasing increments, designed to trigger an overflow:"
N = 1L

a = 1L
X = 2L**a
# we interpret values >= q/2 as negative, so there's no point testing them
# (privcount requires that the total counts are much less than q/2)
while X < q/2L:
    print "Trying count 2**{} = {} < q/2 ({})".format(a, X, q/2)
    try_counters(counters, q, N, X, multi_bin=False)
    print ""
    # This should terminate in at most ~log2(q) steps
    a += 1L
    X = 2L**a

# Now try q/2-1 explicitly
N = 1L
X = q/2L - 1L
print "Trying count = q/2 - 1 = {}".format(X)
try_counters(counters, q, N, X, multi_bin=False)
print "Reached count of q/2 - 1 = {} without overflowing".format(X)
print ""

print "Increasing q, designed to trigger floating-point inaccuracies:"
N = 1L

b = 1L
q = 2L**b

assert q_max >= q_min
while q <= q_max:
    # Skip the sampling if q is too low
    if q >= q_min:
        a = 1L
        X = 2L**a
        print "Trying q = 2**{} = {}".format(b, q)
        print "Unsigned to signed counter conversion, q = {}:".format(q)
        check_adjust_count_signed(q)
        print ""
        # we interpret values >= q/2 as negative
        # So make sure that q is larger than 2*(N*X + 1)
        while X < q/2L:
            print "Trying count 2**{} = {} < q/2 ({})".format(a, X, q/2)
            try_counters(counters, q, N, X, multi_bin=False)
            print ""
            # This inner loop should terminate in at most ~log2(q) steps
            a += 1L
            X = 2L**a
    print ""
    # This outer loop should terminate in at most ~log2(q_max) steps
    b += 1L
    q = 2L**b

# Now try q = q_max explicitly
N = 1L
q = q_max
assert q_max >= q_min
a = 1L
X = 2L**a
print "Trying q = q_max = {}".format(q)
print "Unsigned to signed counter conversion, q = {}:".format(q)
check_adjust_count_signed(q)
print ""
# we interpret values >= q/2 as negative
# So make sure that q is larger than 2*(N*X + 1)
while X < q/2L:
    print "Trying count 2**{} = {} < q/2 ({})".format(a, X, q/2)
    try_counters(counters, q, N, X, multi_bin=False)
    print ""
    # This should terminate in at most ~log2(q) steps
    a += 1L
    X = 2L**a

print "Reached q = q_max = {} without overflow or inaccuracy".format(q)
