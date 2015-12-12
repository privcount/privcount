from privexUtils import *

class tkgserver:
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
            self.data[l] = (self.data.get(l, 0) + int(s0/resolution)) % self.q
            #print "tkgserver share:", l, int(s0/resolution)%self.q
	    #print "self.data[l] ", self.data[l]
#        print "TKG Initialized database:", repr(self.data) 
        self.keyIDs[kid] = None  # TODO: registed client info
        return kid
    
    def publish(self):
        data = self.data
        ## Ensure we can only do this once!
        self.data = None
        self.keyIDs = None
        return data
