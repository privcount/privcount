# PrivCount - Local Deployment Test

This directory contains the necessary components to run a local deployment of PrivCount and to test
its ability to correctly gather statistics using safe test data.

It also contains some unit tests that exercise various PrivCount subsystems.

## Prerequisites

You should have followed the main README to setup and install PrivCount. You should have your
PYTHONPATH setup properly so that you can call `privcount` without providing a full path to it.

## Running the test

### Automated testing

The automated test script runs all the testing steps listed below, terminating all the privcount processes after the tally server produces a results file:

    ./run_test.sh ..

The first argument is the privcount source directory, which is '..' if you're in privcount/test.

It can optionally install the latest version of privcount using 'pip install', and then run the tests:

    ./run_test.sh -I <privcount-directory>

For quick integration testing, reduce the collect_period to 2, and the event_period and checkin_period to 1. This will only capture a few of the injected events.

### Manual testing

#### Unit Tests

Activate your python virtual environment (if you have one):

    source ../venv/bin/activate

Run the unit tests: (optional)

    python test_format_time.py
    python test_encryption.py
    python test_random.py
    python test_counter.py
    python test_traffic_model.py

If you have a local privcount-patched Tor instance, you can test that it is returning PRIVCOUNT events:

    python test_tor_ctl_event.py <control-port-or-path>

#### Integration Tests

Start the event server that will supply events to the data collector:

    gzip -c -d events2.txt.gz | privcount inject --port 20003 --log -

Start the PrivCount components:

    privcount ts config.yaml
    privcount sk config.yaml
    privcount dc config.yaml

Now wait until the end of the epoch and check the tally results json file published by the
tally server. The results for the 'ZeroCount' counter should indicate a zero count for the
bin representing counts in the range [-Infinity, Infinity].

If you have matplotlib installed, you can then visualize the results:

    privcount plot -d privcount.tallies.*.json test

and open the PDF file that was created.

The full results, including context, are in:

    privcount.outcome.*.json

#### Generating an events.txt file

Here is how I generate an events.txt file:

1. Find the chutney control port of the node (Guard, Middle, Exit, Dir, HSDir,
   Intro, Rend, or even Origin) you are interested in. Control ports start at
   8000, and are assigned in order of node creation in the
   chutney/networks/* file.

2. Open another terminal in a privcount-patched tor directory:

    ../chutney/tools/test-network.sh --flavour hs-exit-min --data 100

   The single client in this network will produce 1 stream with 100 bytes of
   data, to both the exit and the onion service in the network.
   You might need to run the the network a few times to see all the different
   events.

   If your chutney doesn't have hs-exit-min, get the latest version using:

   git clone https://git.torproject.org/chutney.git

3. Open a terminal in a privcount directory and run:

    source venv/bin/activate
    pip install -I .
    test/test_tor_ctl_event.py 8002 > raw_events.txt

   Where 8002 is the port you are interested in.

   You might need to be careful with the timing here: too early, and the
   reconnecting client will timeout, or Tor will end up in a broken state
   (tor trac #9990 and #15421).

4. Wait around 60 seconds for chutney to finish

5. Process the raw file(s) with:

    cat raw_events.txt | grep -v "^Relay" | cut -d" " -f 9- > events.txt

6. Optionally, use 'localhost' instead of '127.0.0.1' for hostnames:

    sed "s/\(PRIVCOUNT_STREAM_ENDED.*\)127.0.0.1 127.0.0.1/\1localhost 127.0.0.1/" events.txt > local_events.txt
    mv local_events.txt events.txt

   (Chutney's automatic tests have no way of specifying a hostname.)

7. Check the events file actually has some entries:

    head -10 events.txt
    wc -l events.txt

    If there are more than a few hundred events in the file, you might want
    to remove similar event lines. This makes the integration tests faster.

8. Append the extreme test events to the events file:

    cat extreme_events.txt >> events.txt

   We don't parse DNS_RESOLVED events, so they are kept separate in
   extreme_dns_resolved_events.txt

9. Test the new events file in privcount using:

    test/run_test.sh -I . -x -s inject

Each chutney client conntects via a random exit. If you use a chutney flavour
with onion services, a random client connects to each hidden service.

Chutney does not use DNS by default, so there are no PRIVCOUNT_DNS_RESOLVED
events.
