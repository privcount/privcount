#!/usr/bin/env python
from hashlib import sha256 as Hash
import os
import struct

from StatKeeper import StatKeeper
from noise import Noise
from exit_weight import * 
# 2^31 - 1 happens to be a prime
q = 2**31 - 1

# A sensible resolution
resolution = 0.01
sigma = 240

num_DC = 1000
num_TKS = 10
num_websites = 1000

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


def sumdata(dataset, q):
    totals = {}
    for k in dataset[0]:
        for data in dataset:
            totals[k] = (totals.get(k, 0) + data.get(k, 0)) % q
    	if totals[k] <= q/2:
	    totals[k] = totals[k]*resolution
	else:
	    totals[k] = (totals[k]-q)*resolution
    return totals


class authority:
    def __init__(self, q):
        self.data = {}
        self.keyIDs = {}
        self.q = q

    def register_router(self, msg):
        ## TODO: decrypt the msg
        labels, (kid, K), q = msg
        assert q == self.q

        ## We have already registered this key
        if kid in self.keyIDs:
            return None

        ## Add shares
        shares = keys_from_labels(labels, K, False, q)
        for (l, s0) in shares:
            self.data[l] = (self.data.get(l, 0) + int(s0/resolution)) % q
        self.keyIDs[kid] = None  # TODO: registed client info        
        return kid

    def publish(self):
        data = self.data
        ## Ensure we can only do this once!
        self.data = None
        self.keyIDs = None
        return data


class router:
    def __init__(self, q, labels, authorities, fingerprint):
        self.data = {}
        self.q = q
        for l in labels:
            self.data[l] = 0

        self.keys = [os.urandom(20) for _ in authorities]
        self.keys = dict([(PRF(K, "KEYID"), K) for K in self.keys])
       
	twbw, p_exit, number_exits, sum_of_sq = prob_exit(consensus, fingerprint) 
        for _, K in self.keys.iteritems():
            shares = keys_from_labels(labels, K, True, q)            
            for (l, s0) in shares:
        	noise = Noise(sigma,fingerprint,sum_of_sq,p_exit)
		self.data[l] = (self.data[l] + int((s0+noise)/resolution)) % q
		
    def authortity_msg(self, kid):
        assert kid in self.keys and self.keys[kid] is not None
        msg = (sorted(self.data.keys()), (kid, self.keys[kid]), self.q)
        self.keys[kid] = None  # TODO: secure delete
        ## TODO: Encrypt msg to authority here
        return msg

    def inc(self, label):
        assert label in self.data
        self.data[label] = (self.data[label] + int(1/resolution)) % self.q

    def publish(self):
        data = self.data
        ## Ensure we can only do this once!
        self.data = None
        self.keys = None
        return data

if __name__ == "__main__":

    stats = StatKeeper()

    # Simple set of labels
    labels = range(num_websites)

    # Generate 1000 routers and 10 authorities
    auths = []
    for _ in range(num_TKS):
        with(stats["authority_init"]):
            auths.append(authority(q))

    clients = []
    for _ in range(num_DC):
        with(stats["client_init"]):
            clients.append(router(q, labels, auths, "fingerprint"))

    # Register clients with authorities
    for c in clients:
        for kid, a in zip(c.keys, auths):
            with(stats["client_reg"]):
                msg = c.authortity_msg(kid)
            with(stats["authority_reg"]):
                a.register_router(msg)

    # Do the stats
    clen = len(clients)
    for idx in xrange(1000000):
    	with(stats["client_inc"]):
            clients[idx % clen].inc(1)

    # Collect the publihed data from everyone
    data = []
    for c in clients:
        with(stats["client_pub"]):
            data.append(c.publish())
    for a in auths:
        with(stats["authority_pub"]):
            data.append(a.publish())
    # Add up and check
    with(stats["TS_sumdata"]):
    	D = sumdata(data, q)
	print D.values()
#    assert sum(D.values()) == 1000000

    # Timing stats
    stats.print_stats()
