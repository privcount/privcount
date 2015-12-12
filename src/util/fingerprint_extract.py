import argparse
import binascii
import base64

parser = argparse.ArgumentParser(description='')
parser.add_argument('-c','--consensus', help='Input consensus file',required=True)
parser.add_argument('-o','--output', help='Output fingerprint file',required=True)
args = parser.parse_args()
#consensus = "/home/mtelahi/Downloads/consensuses-2014-04/01/2014-04-01-00-00-00-consensus"

def extract_fingerprints(consensus):
    print "let's start"
    with open(consensus,'r') as f1:
        print "Opened the consensus file!"
        for line in f1:
            if line.startswith("r "):
                sline = line.split()
                b64_print = sline[2:3] ## only the fingerprint
                b64_print = b64_print[0] + "="
                bin_print = base64.b64decode(b64_print)
                hex_print = binascii.b2a_hex(bin_print)
            if line.startswith("s ") and "BadExit" not in line and "Exit" in line:
                with open(args.output,'a') as f2:
                    f2.write(hex_print)
                    f2.write("\n")

if __name__ == '__main__':
    extract_fingerprints(args.consensus)
