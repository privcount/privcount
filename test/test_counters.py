#!/usr/bin/python

from privcount.util import SecureCounters

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

q = 2147483647

# create the counter for a data collector, who will generate the shares and noise
sc_dc = SecureCounters(counters, q)
sc_dc.generate(['sk1', 'sk2'], 1.0)
# get the shares used to init the secure counters on the share keepers
shares = sc_dc.detach_blinding_shares()

# create share keeper versions of the counters
sc_sk1 = SecureCounters(counters, q)
sc_sk1.import_blinding_share(shares['sk1'])
sc_sk2 = SecureCounters(counters, q)
sc_sk2.import_blinding_share(shares['sk2'])

# do some increments at the dc
N = 500.0
for _ in xrange(int(N)):
    # bin[0]
    sc_dc.increment('Bytes', 0.0)
    sc_dc.increment('Bytes', 511.0)
    #bin[1]
    sc_dc.increment('Bytes', 600.0)
    #bin[2]
    sc_dc.increment('Bytes', 1024.0)
    sc_dc.increment('Bytes', 2047.0)
    #bin[3]
    pass
    #bin[4]
    sc_dc.increment('Bytes', 4096.0)
    sc_dc.increment('Bytes', 10000.0)

# get all of the counts, send for tallying
counts_dc = sc_dc.detach_counts()
counts_sk1 = sc_sk1.detach_counts()
counts_sk2 = sc_sk2.detach_counts()

# tally them up
sc_ts = SecureCounters(counters, q)
is_tally_success = sc_ts.tally_counters([counts_dc, counts_sk1, counts_sk2])
assert is_tally_success

tallies = sc_ts.detach_counts()
print tallies
assert tallies['Bytes']['bins'][0][2] == 2.0*N
assert tallies['Bytes']['bins'][1][2] == 1.0*N
assert tallies['Bytes']['bins'][2][2] == 2.0*N
assert tallies['Bytes']['bins'][3][2] == 0.0*N
assert tallies['Bytes']['bins'][4][2] == 2.0*N
assert tallies['SanityCheck']['bins'][0][2] == 0.0
print "all counts are correct!"
