#!/usr/bin/env python
# See LICENSE for licensing information

import os, json
from privcount.traffic_model import TrafficModel

# The path to the model file, based on the location of privcount/test
PRIVCOUNT_DIRECTORY = os.environ.get('PRIVCOUNT_DIRECTORY', os.getcwd())
TEST_DIRECTORY = os.path.join(PRIVCOUNT_DIRECTORY, 'test')
MODEL_FILENAME = os.path.join(TEST_DIRECTORY, "traffic.model.json")

# a sample model
model = {
    'states': ['Blabbing', 'Thinking'],
    'start_probability': {'Blabbing': 0.6, 'Thinking': 0.4},
    'transition_probability': {
        'Blabbing' : {'Blabbing': 0.7, 'Thinking': 0.3},
        'Thinking' : {'Blabbing': 0.4, 'Thinking': 0.6},
    },
    'emission_probability': {
        'Blabbing':{'+': (0.8,0.05), '-': (0.2,0.001)},
        'Thinking':{'+': (0.95,0.0001),'-': (0.05,0.0001)},
    }
}

# write an uncompressed json file
if not os.path.exists(MODEL_FILENAME):
    with open(MODEL_FILENAME, 'w') as outf:
        json.dump(model, outf, sort_keys=True, separators=(',', ': '), indent=2)

del(model)
model = None

print "Testing traffic model..."
print ""

# now test reading in a model
inf = open(MODEL_FILENAME, 'r')
model = json.load(inf)
inf.close()

tmod = TrafficModel(model)
assert tmod

print "Here is the list of all counter labels:"
for label in sorted(tmod.get_all_counter_labels()):
    print label
print ""

# sample observations
#packet_bundle = [is_sent, micros_since_prev_cell, bundle_ts, num_packets, payload_bytes_last_packet]
bundles = []

# first add something like a GET request from client to server
bundles.append([0, 0, 123456.000000, 1, 200])

# then add several packets as responses
# the exit reads these as cells and combines similar chunks into 'packet bundles'
# if the packets arrive at the same-ish time within some tolerance, they go in the same bundle
bundles.append([1, 0, 123456.500000, 100, 498]) # 100 packets, 99 are full 1500 bytes, the last is 498 bytes
# more packets arrive after the tolerance so that requires a new bundle
bundles.append([1, 0, 123456.501000, 50, 0]) # 10 packets, all are full 1500 bytes
bundles.append([0, 0, 123456.600000, 1, 200]) # another upstream request
bundles.append([1, 0, 123456.650000, 50, 0]) # more packets down after 50 ms delay

print "The most likly path through the traffic model given the observations is:"
print "->".join(tmod._run_viterbi(bundles))
print ""
