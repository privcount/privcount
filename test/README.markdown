# Privex - Local Deployment Test

This directory contains the necessary components to run a local deployment of privex and to test
its ability to correctly gather statistics using safe test data.

## Prerequisites

You should have followed the main README to setup and install Privex. You should have your
PYTHONPATH setup properly so that you can call `privex` and `privex-inject` without providing full
paths to those scripts.

## Running the test

Start the tally server and wait for it to cycle an epoch:

    cd ts
    privex ../privex-config.yml ts

 Start the tally key server and wait for it to cycle an epoch:

    cd tks
    privex ../privex-config.yml tks

 Start the data collector and wait for it to report that it has registered with the TKS:

    cd dc
    privex ../privex-config.yml dc

Finally, inject some test data into the data collector:

    privex-inject --port 20003 --log tor-test-events.txt

Now wait until the end of the epoch and check the results published by the tally server (in `ts/results.txt`).
