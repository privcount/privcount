import argparse
import binascii
from base64 import b64encode

#parser = argparse.ArgumentParser(description='')
#parser.add_argument('-c','--consensus', help='Input consensus file',required=True)
#parser.add_argument('-p','--fingerprint', help='Input fingerprint file',required=True)
#args = parser.parse_args()

#fingerprint = "fingerprint"
#consensus = "/home/mtelahi/Downloads/consensuses-2011-05/01/2011-05-01-00-00-00-consensus"
consensus = "consensus"

def prob_exit(consensus, fingerprint):
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
        id_hex = f.readline().strip()
        id_bin = binascii.a2b_hex(id_hex)
        my_id = b64encode(id_bin).rstrip("=")
    
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
        for line in f:
            if line.startswith("r ") and my_id in line:
                me = 1
            if line.startswith("s ") and "BadExit" not in line:
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
    return TEWBW, prob, num_exits, sum_of_sq

