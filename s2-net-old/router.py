from privexUtils import *
from noise import Noise
from exit_weight import *
import pprint

class router:
    def __init__(self, q, labels, authorities, fingerprint, consensus):
        self.data = {}
        self.q = q
        for l in labels:
            self.data[l] = 0

        twbw, p_exit, num_exits, sum_of_sq = prob_exit(consensus, fingerprint)
        self.keys = [os.urandom(20) for _ in authorities]
        self.keys = dict([(PRF(K, "KEYID"), K) for K in self.keys])
        for _, K in self.keys.iteritems():
            shares = keys_from_labels(labels, K, True, q)
	    for (l, s0) in shares:
#        	noise = Noise(sigma, fingerprint, sum_of_sq, p_exit)
#                self.data[l] = (self.data[l] + int((s0+noise)/resolution)) % self.q
                 self.data[l] = (self.data[l] + int(s0/resolution)) % self.q 
	# Add noise for each website independently
        for label in self.data:
            noise = Noise(sigma, fingerprint, sum_of_sq, p_exit)
            self.data[label] = (self.data[label] + int(noise/resolution)) % self.q

    def authority_msg(self, kid):
        assert kid in self.keys and self.keys[kid] is not None
        msg = (sorted(self.data.keys()), (kid, self.keys[kid]), self.q)
        self.keys[kid] = None  # TODO: secure delete
        ## TODO: Encrypt msg to authority here
        #pprint.pprint(msg)
        return msg

    def inc(self, label):
        if label in self.data:
            self.data[label] = (self.data[label] + int(1/resolution)) % self.q
#	    print 'inside router.inc: ', label
#            self.data['Censored'] = (self.data['Censored'] + int(1/resolution)) % self.q
#        else:
#            self.data['Other'] = (self.data['Other'] + int(1/resolution)) % self.q

    def publish(self):
        data = self.data
        ## Ensure we can only do this once!
        self.data = None
        self.keys = None
        return data
