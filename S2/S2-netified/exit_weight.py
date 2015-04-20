import argparse
import binascii
from base64 import b64encode

#parser = argparse.ArgumentParser(description='')
#parser.add_argument('-c','--consensus', help='consensus filei of exit',required=True)
#parser.add_argument('-p','--fingerprint', help='Input fingerprint file',required=True)
#args = parser.parse_args()

#fingerprint = "fingerprint"
#consensus = "/home/mtelahi/Downloads/consensuses-2011-05/01/2011-05-01-00-00-00-consensus"
#consensus = "consensus"
priv_exits_fingerprints = "exit_prints.txt"
#Chutney consensus
#consensus = "/home/mtelahi/work/research/tariq-thesis/chutney/net/nodes/003r/cached-consensus"

def prob_exit(consensus, fingerprint):
    priv_exits = []
    weights = []

    DBW = 0
    EBW = 0

    DW = 0
    EW = 0

    prob = 0
    myWB = 0
    num_exits = 0
    biggest_bw = 0
    sum_of_sq_bw = 0

    with open(fingerprint,'r') as f:
	_, id_hex = f.readline().strip().split(" ") # has a nick in front
        id_bin = binascii.a2b_hex(id_hex)
        my_id = b64encode(id_bin).rstrip("=")

    with open(priv_exits_fingerprints,'r') as h:
	for line in h:
	  exit_id_hex = line.strip()
          exit_id_bin = binascii.a2b_hex(exit_id_hex)
          exit_id = b64encode(exit_id_bin).rstrip("=")
	  priv_exits.append(exit_id)

    with open(consensus,'r') as g:
        for line in g:
            if "bandwidth-weights" in line:
                sline = line.split()
                sline = sline[7:9] ## only the exit weights that matter
                for i in sline:
                    weights.append(i.split("="))
                DW = float(weights[0][1])/10000
                EW = float(weights[1][1])/10000
    with open(consensus,'r') as f:
        ge = 0
        e = 0
        me = 0
	relay_fingerprint = ''
        for line in f:
	    if line.startswith("r "):
	      relay_fingerprint = line.strip().split()
	      relay_fingerprint = relay_fingerprint[2:3]

            if line.startswith("r ") and my_id in line:
                me = 1
            if line.startswith("s ") and "BadExit" not in line and relay_fingerprint[0] in priv_exits:
                if "Guard" in line and "Exit" in line:
                    ge = 1
                    num_exits += 1
                elif "Exit" in line:
                    e = 1
                    num_exits += 1

            if line.startswith("w "):
                bandwidth = line.strip()
                if " Unmeasured" not in line:
			_, bandwidth = bandwidth.split("=")
		else:
			_, bandwidth, _ = bandwidth.split("=")
			bandwidth , _ = bandwidth.split(" ")
                bandwidth = float(bandwidth)
                DBW += bandwidth*ge
                sum_of_sq_bw += (bandwidth*ge)**2
                EBW += bandwidth*e
                sum_of_sq_bw += (bandwidth*e)**2
                if me == 1:
                    myWB = bandwidth*ge + bandwidth*e
                ge = e = me = 0
                if biggest_bw < bandwidth:
                    biggest_bw = bandwidth

    TEWBW = DBW*DW + EBW*EW
    prob = myWB/TEWBW
    sum_of_sq = sum_of_sq_bw/(TEWBW**2)
#    print TEWBW, prob, num_exits, sum_of_sq
    return TEWBW, prob, num_exits, sum_of_sq

if __name__ == '__main__':
    prob_exit(consensus, fingerprint)
