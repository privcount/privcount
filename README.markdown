# intro

PrivCount is an independent implementation of the Privex Secret Sharing (S2) variant, that has
been customized in order to be able to aggregate a large variety of statistical counts from Tor
while providing differential privacy guarantees. For more information, see the associated
publication:
TBA

For more information about Privex, see:
Elahi, Tariq, George Danezis, and Ian Goldberg. "PrivEx: Private Collection of Traffic Statistics
for Anonymous Communication Networks." Proceedings of the 2014 ACM SIGSAC Conference on Computer
and Communications Security. ACM, 2014.

# requirements

    system libs: libssl libssl-dev cffi
    python libs: pyyaml, stem, twisted, pyopenssl, service-identity

System libs can be install with `apt-get`, `yum`, `brew`, etc. Python libs can be installed with `pip`,
as we explain below.

# installation

I recommend using virtual environments to isolate the python environment and avoid conflicts.
Run the following from the base directory of this package (i.e., the same location of this README).

    pip install virtualenv
    virtualenv --no-site-packages venv
    source venv/bin/activate
    pip install pyyaml stem twisted pyopenssl service-identity
    pip install .
    deactivate

You can replace the `pip install ...` above with the following to mirror my dev environment:

    pip install -r requirements.txt

During PrivCount development, include your latest development changes by forcing a reinstall:

    pip install -I .

# running

To run PrivCount, simply activate the virtual environment that you created earlier and then run
PrivCount as normal. For example:

    source venv/bin/activate # enter the virtual environment
    privcount --help
    ...
    deactivate # exit the virtual environment

# testing

See `test/README.markdown` for notes about testing PrivCount with a private local deployment.

# deploying PrivCount entities

Example of the global section for a `privcount-config.yml` file, which all nodes need:

    global:
        start_time: 1452520800 # 2016-01-11 at 2pm UTC
        epoch: 604800 # (1 week = 604800 seconds) the safe time frame of stats collection for all stats
        clock_skew: 300 # seconds - to deal with clock skews and latency
        q: 2147483647 # ((2**31)-1) 2^31 - 1 happens to be a prime

## tally server

Generate key and create self signed cert in a new base directory:

    mkdir privcount_ts
    cd privcount_ts
    touch privcount-config.yml # add above global config in here
    openssl genrsa -out ts.key 1024
    openssl req -new -x509 -key ts.key -out ts.cert -days 1825

Choose an address W1.X1.Y1.Z1 and port P1 that is accessible on the Internet, and append the
following as a new section under the global section of the `privcount-config.yml` file:

    tally_server:
        listen_port: P1 # open port on which to listen for remote connections from TKSes
        key: 'ts.key' # path to the key file
        cert: 'ts.cert' # path to the certificate file
        results: 'results.txt'

Then run PrivCount in tally server mode:

    privcount privcount-config.yml ts

## tally key server

Generate key and create self signed cert in a new base directory:

    mkdir privcount_tks
    cd privcount_tks
    touch privcount-config.yml # add above global config in here
    openssl genrsa -out tks.key 1024
    openssl req -new -x509 -key tks.key -out tks.cert -days 1825

Choose an address W2.X2.Y2.Z2 port P2 that is accessible on the Internet, and append the
following as a new section under the global section of the `privcount-config.yml` file:

    tally_key_server:
        listen_port: P2 # open port on which to listen for remote connections from DCs
        key: 'tks.key' # path to the key file
        cert: 'tks.cert' # path to the certificate file
        tally_server_info: # where the tally server is located
            ip: W1.X1.Y1.Z1
            port: P1

Then run PrivCount in tally key server mode:

    privcount privcount-config.yml tks

## data collector

Create a new base directory:

    mkdir privcount_dc
    cd privcount_dc
    touch privcount-config.yml # add above global config in here

Choose a local port L that will listen for connections from Tor.

data_collector:
    listen_port: L # local port on which to listen for local connections from Tor
    noise_weight: 1.0 # distribute noise among all machines / data collectors
    tally_server_info: # where the tally server is located
        ip: W1.X1.Y1.Z1
        port: P1
    tally_key_server_infos: # where the tally key servers are located
        -
            ip: W2.X2.Y2.Z2
            port: P2
    statistics: ... # see test/privcount-test-config.yaml