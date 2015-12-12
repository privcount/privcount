#!/bin/bash
# usage: ./startup.py <tallyserverport> <number_of_tks> <number_of_exits> <website_list_file>
# files: 
#<website_list_file> - domains to log, one on a line
#tkglist.txt - ports of tks one to a line. Should be as many as <number_of_tks>
#<fingerprintX> - files with exit fingerprints. The X increases from 1 through to <number_of_exits>.

python tallyListener.py -p $1 &

for tks in `seq 1 $2`; 
do
	port=$((19000 + $tks))
	echo $port
	python tkgListener.py -p $port -thp thp.txt &
done    

for fngprt in `seq 1 $3`; 
do
	port=$((39000 + $fngprt))
	fingerprint="fingerprint${fngprt}"
	echo $port $fingerprint
	python exitListener.py -i $4 -tkg tkglist.txt -p $port -f $fingerprint -thp thp.txt &
done    
