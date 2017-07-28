# Intro

PrivCount makes Tor statistics collection more secure. PrivCount produces
totals across all participating relays. Noise is added to each total to hide
typical user activity.

PrivCount protects individual relay totals by adding a blinding factor, which
is only removed when the statistics are aggregated.

## Should I Run PrivCount?

Don't run PrivCount unless you enjoy running experimental code.
We're still working on getting the instructions right.

Be careful collecting and releasing PrivCount results: the configured noise
and the length of collection must protect user privacy.
(If you don't know what this means, find out before running PrivCount!)

PrivCount isn't ready for production deployment:
* there are many known security and robustness issues,
* there are some known inaccuracies in the statistics,
* it doesn't scale to the size of the public Tor network,
* we haven't tested the PrivCount python code in enough environments, and
* we haven't tested the PrivCount Tor Patch on enough Tor relays
  (nor has it undergone code review by other Tor developers).

## How does PrivCount compare to Tor's existing statistics?

Tor relays currently collect and publish statistics for each relay. Some
statistics have noise added, but the amount of noise is calculated on an
ad-hoc basis. Tor's statistics collection is a stable, proven process that
scales well to production networks.

PrivCount collects totals for all participating relays. Individual relay totals
are not published. Noise is calculated across the entire set of statistics
collected. PrivCount is experimental code. It does not scale well beyond tens
of relays.

# Research Background

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
https://www.cypherpunks.ca/~iang/pubs/privex-ccs14.pdf
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

To deploy a PrivCount network, install and start the Tally Server. The
configured collection period and noise must protect typical user activity.

Use a signed, encrypted transport (email works well) to send the shared
symmetric network key to all participants.

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
