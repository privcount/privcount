======================
old setup notes
======================

This README provides instructions on how to set up Privex, with its various types of nodes.

0. GENERAL
There are three types of nodes: Tally Server (TS), Tally Key Server(TKS), and Data Collector (DC).
There should be at least 2 TKSs and 1 Taller Server, and any number of Data Collectors.
The TKSs should be operated by independent entities that do not share coercible relationships. The TS and one DC can be operated by the same entity.

1. SETUP
We now descibe the setup and operation of each of the node types. The order of setup is to start the TS, then the TKSs, and finally the DCs.

1.0 TS
The Tally Server needs to have a public IP and port exposed for listening for connections from the other two node types.
In the keys/ directory place the public key and certificate for that key to be used for the TLS connections between the TS and TKS and DC nodes.

To start the server up run the following command:
python tallyListener.py -p <port> &

Where <port> is the open port as described above.

1.1 TKS
The Tally Key Server needs to have a public IP and port exposed. It also needs to be able to make outbound connections to the TS on the port selected in 1.0 above.
Create a file called thp.txt which contains the IP and port of the TS on a single space delimited line. See example file in directory.

In the keys/ directory place the public key and certificate for that key to be used for t
he TLS connections between the TKS and DC nodes.

To start the server up run the following command:
python tkgListener.py -p <port> -thp thp.txt &

Where <port> is open to inbound connections.

1.2 DC
The Data Collectors need to only be able to make outbound connections to the TKS and TS nodes.
Create a file called thp.txt which contains the IP and port of the TS on a single space d
elimited line.
Create a file called tkglist.txt which contains the IP and port on  a line each of each of the TKS nodes on a single space d
elimited line.
The exit_prints.txt file contains the fingerprints of all the privex exits. Make sure you have the latest file.
See example files in the directory.

The torrc file needs to have the following two lines added:
UsePrivex 1
PrivexPort <the port the DC listens on>

The Tor exit needs to be started after the DC node has come online. If the node fails while Tor is running, it will not cause Tor to fail, but will output error messages to Tor's info.logfile. Simply restart the DC and then restart the Tor exit.

To start the DC up run the following command:
python exitListener.py -i websites.txt -tkg tkglist.txt -p <port> -f <fingerprint_file> -c <consensus_file> -thp thp.txt &

Where websites.txt is the file containing the domain names that we want to collect statistics for (use the example file websites.txt by default), <port> is the port listening to Tor connections on localhost, <fingerprint_file> is the Tor fingerprint file in the Tor data directory, and <consensus> is the Tor consensus file in the Tor data directory.


======================
old deploy notes
======================

Dependencies (non-exhaustive):
  1. twisted
  2. libevent
  3. openssl
  4. python openssl
  5. libffi

Steps used to deploy PrivEx:

1. Clone PrivEx: git clone git://git-crysp.uwaterloo.ca/privex

2. Build PrivEx Tor branch:
  a. git clone git://git-crysp.uwaterloo.ca/tor privex-tor.git
  b. cd privex-tor.git
  c. git checkout -b privex-0.2.6.7 origin/privex-0.2.6.7
  d. ./autogen.sh && ./configure && make

3. Clone PrivEx deployment repository: git clone https://bitbucket.org/ohmygodel/privex-deploy.git privex-deploy.git

4. Copy input files from privex repo to deployment repo
  a. cp privex.git/S2/S2-netified/thp.txt thp.txt
  b. cp privex.git/S2/S2-netified/tkglist.txt tkglist.txt
  c. cp privex.git/S2/S2-netified/exit_prints.txt exit_prints.txt
  d. cp privex.git/S2/S2-netified/websites-20150509.txt websites-20150509.txt

5. Create keys for TKS:
  a. Generate keys: openssl genrsa -out tks.key 1024
  b. Create self-signed certificate: openssl req -new -x509 -key tks.key -out tks.cert -days 1825
  c. Move to keys directory: mkdir keys; mv tks.* keys

4. Run Tally Key Server: [in screen] /usr/local/bin/python2.7 privex.git/S2/S2-netified/tkgListener.py -p 10000 -thp thp.txt

5. Add new TKS line to tkglist.txt: 198.58.94.206 10000

6. Add new exit fingerprint to exit_prints.txt: D53793315E290D250E9AFC431A4C9068A1E53C98

7. Add PrivEx lines to torrc:
  a. UsePrivex 1
  b. PrivexPort 9005

8. Run Data Collector: [in screen] /usr/local/bin/python2.7 privex.git/S2/S2-netified/exitListener.py -i websites-20150509.txt -tkg tkglist.txt -p 9005 -f ../privex-tor/data/fingerprint -c ../privex-tor/data/cached-consensus -thp thp.txt

9. Run Tor: ../privex-tor/bin/tor -f ../privex-tor/etc/tor/torrc
