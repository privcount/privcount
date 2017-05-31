# Intro

PrivCount is an independent implementation of the PrivEx Secret Sharing (S2)
variant, that has been customized in order to be able to aggregate a large
variety of statistical counts from Tor while providing differential privacy
guarantees. For more information, see the associated publication:

```
Safely Measuring Tor
23rd ACM Conference on Computer and Communication Security (CCS 2016)
Rob Jansen and Aaron Johnson
http://www.robgjansen.com/publications/privcount-ccs2016.pdf
```

For more information about PrivEx, see:

```
PrivEx: Private Collection of Traffic Statistics for Anonymous Communication Networks
21st ACM Conference on Computer and Communications Security (CCS 2014)
Tariq Elahi, George Danezis, and Ian Goldberg
http://www.cypherpunks.ca/~iang/pubs/privex-ccs14.pdf
```

See LICENSE for licensing information.

# Installing

To run the Tally Server or a Share Keeper, install PrivCount and its
dependencies.

To run a Data Collector, install PrivCount, a PrivCount-patched Tor instance,
and all their dependencies.

See INSTALL.markdown for details.

# Running

To run PrivCount, simply activate the virtual environment that you created
earlier and then run PrivCount as normal. For example:

    source venv/bin/activate # enter the virtual environment
    privcount --help
    ...
    deactivate # exit the virtual environment

PrivCount will log messages prefixed with your local timezone. Times within
PrivCount log messages are in UTC.

# Deployment

To deploy a PrivCount network, install and start the Tally Server. Use a
signed, encrypted transport (email works well) to send the shared symmetric
network key to all participants.

Install, configure, and start all the Share Keepers. Use a signed transport to
send the public key fingerprints of the Share Keepers to the Data Collectors.

Install, configure and start all the Data Collectors. Your network should
start collecting automatically.

See DEPLOY.markdown for details.

# Testing

See `test/README.markdown` for notes about testing PrivCount in a private
local deployment, `doc/CounterTests.markdown` for details of how we tested
each counter, or check out the options on the unit and integration test script:

    test/run_test.sh --help
