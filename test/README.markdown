# PrivCount - Local Deployment Test

This directory contains the necessary components to run a local deployment of PrivCount and to test
its ability to correctly gather statistics using safe test data.

## Prerequisites

You should have followed the main README to setup and install PrivCount. You should have your
PYTHONPATH setup properly so that you can call `privcount` and `privcount-inject` without providing full
paths to those scripts.

## Running the test

Start the tally server and wait for it to cycle an epoch:

    privcount privcount-test-config.yaml ts

 Start the tally key server and wait for it to cycle an epoch:

    privcount privcount-test-config.yaml tks

 Start the data collector and wait for it to report that it has registered with the TKS:

    privcount privcount-test-config.yaml dc

Finally, inject some test data into the data collector:

    privcount-inject --port 20003 --log tor-test-events.txt

Now wait until the end of the epoch and check the results published by the tally server (in `results.txt`).
