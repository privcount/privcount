from hashlib import sha256 as Hash
import os
import struct

# 2^31 - 1 happens to be a prime
q = 2**31 - 1
# A sensible resolution
resolution = 0.01
#the time frame of stats collection
epoch = 3600 # in seconds
#the sigma we want for privacy and utility
sigma = 240

#some time vairables to deal with clock skews, latency, etc.
clock_skew = 300
tkg_start_delay = 3
dc_start_delay =  5
dc_reg_delay = dc_start_delay + 3
ts_pub_delay = clock_skew + 20

def PRF(key, IV):
    return Hash("PRF1|KEY:%s|IV:%s|" % (key, IV)).digest()

def sample(s, q):
    ## Unbiased sampling through rejection sampling
    while True:
        v = struct.unpack("<L", s[:4])[0]
        if 0 <= v < q:
            break
        s = Hash(s).digest()
    return v


def keys_from_labels(labels, key, pos=True, q=2147483647):
    shares = []
    for l in labels:
        ## Keyed share derivation
        s = PRF(key, l)
        v = sample(s, q)
        s0 = v if pos else q - v

        ## Save the share
        shares.append((l, s0))
    return shares
