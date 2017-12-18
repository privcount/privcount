# Testing PrivCount Counters

Each PrivCount counter can be tested by sending data through a test tor
network.

You will need:
* the PrivCount python code,
* a PrivCount-patched Tor binary,
* Chutney, and
* a JSON parser (I like jq, but any JSON parser will do).

The terms used to name each counter are documented in
CounterDefinitions.markdown.

Each line in this file that names a counter starts with '- '. This helps us
check that we have tested all the counters.

## Test Setup

Each set of counter variants has a test with expected results for the least
specific variant. More specific variants can be tested by changing the chutney
bytes, connections, ports, or flavour.

To run a test, use:

    test/run_test.sh -I . -x -s chutney

You can pass the following arguments to run_test.sh:

    -n chutney-flavour
    -o chutney-connections (streams)
    -b chutney-bytes (per stream)

For more advanced options, use the environmental variables in the chutney
README.

### Useful jq Expressions

To display all the bins for a counter, use:

    jq .Tally.CounterName.bins test/privcount.outcome.latest.json

Where 'CounterName' can be replaced by any PrivCount counter name.

More specific jq expressions are used in some tests to retrieve particular
values. Expressions that need shell quoting are in double quotes.

Extract the lower bound and count out of a histogram:

    jq '.Tally.CounterName.bins | map([.[0,2]])'

Extract only the bins with non-zero counts from a histogram:

    jq '.Tally.CounterName.bins | map(select(.[2] > 0))'

Show counter names containing "Circuit":

    jq '.Tally | with_entries(select(.key | contains("Circuit")))'

Filter out counters with all-zero bins:

    jq '.Tally | with_entries(select(.value.bins[][2] > 0))'

Filter out zero bins:
(There is probably a nicer way of doing this)

    jq '.Tally | with_entries(.value = (.value
                   | with_entries(.value = (.value
                       | map(select(.[2] > 0))))))'

Remove the "bins" key, and place its value underneath the counter name:

    jq '.Tally | with_entries(.value = .value.bins)'

I like to use them combined, like this:

    jq '.Tally | with_entries(select(.value.bins[][2] > 0))
               | with_entries(.value = (.value
                   | with_entries(.value = (.value
                       | map(select(.[2] > 0))))))
               | with_entries(.value = .value.bins)'

### Updating This Documentation

When you add new counters, you can add their names to this file using:

    privcount/tools/add_counter.sh

This sorts by reversed counter name, to sort similar suffixes together.

Then test the counters, and fill in the results.

## All Nodes Counter Tests

Every PrivCount counter has at least one test in this section.
(Checked by test/test_counter_match.sh)

Any specific values listed in the tests are from the chutney basic-min network,
unless otherwise indicated.

Bins are half-open intervals, and use the notation [min, max).
(The final bin is considered a closed interval if it ends with inf.)

### Validity Check

- ZeroCount

    '.Tally.ZeroCount.bins[0][2] == 0'

The ZeroCount is 0 in all valid outcome files.

## Exit Counter Tests

### Exit Circuits

- ExitCircuitCount

    '.Tally.ExitActiveCircuitCount.bins[0][2] +
     .Tally.ExitInactiveCircuitCount.bins[0][2] ==
     .Tally.ExitCircuitCount.bins[0][2]'

This is the sum of ExitActiveCircuitCount and ExitInactiveCircuitCount.

There are approximately 3 exit circuits per chutney tor (including
authorities, relays, and clients). These circuits are created
pre-emptively, and are only used (made active) if needed. Once a circuit is
used, there is a short delay before another pre-emptive circuit is created
to replace it.

- ExitActiveCircuitCount

    '.Tally.ExitActiveCircuitCount.bins[0][2] == 1'

There is 1 active circuit per chutney Tor client. To add more active
circuits, use a chutney flavour with more clients, or add more clients to
chutney's basic-min. (chutney can also be modified to create a new
circuit for each data source connection, by modifying the circuit isolation
options and user/password sent to the SOCKSPort.)

For example:

    run_test.sh ... -n basic -p `seq 8000 8007`

Produces 2 active circuits.
(Sometimes larger chutney networks don't work with PrivCount due to
timing issues, see bug #272 for details.)

- ExitInactiveCircuitCount

    .Tally.ExitInactiveCircuitCount.bins[0][2] is ~10

See the note under ExitCircuitCount.

- ExitInteractiveCircuitCount
- ExitOtherPortCircuitCount
- ExitP2PCircuitCount
- ExitWebCircuitCount

The sum of the port variants is equal to ExitActiveCircuitCount. (Inactive
circuits are not counted, as they have no Stream and therefore no port.)
Chutney uses port 4747 by default, which is in the OtherPort range.

TODO: test other ports.

- ExitCircuitLifeTime

    '(.Tally.ExitCircuitLifeTime.bins | map(.[2]) | add) ==
     .Tally.ExitCircuitCount.bins[0][2]'

The sum of all the bins is equal to ExitCircuitCount. Typically, chutney
runs for less than 2 minutes, so all circuit lifetimes are in the [0, 120)
bin. To extend circuit lifetimes, change the PrivCount collect_period to
240 seconds, and run:

    CHUTNEY_STOP_TIME=120 test/run_test.sh ...

- ExitActiveCircuitLifeTime
- ExitInactiveCircuitLifeTime

The counts for the ExitActiveCircuitCount and ExitInactiveCircuitCount
variants also match, just like ExitCircuitLifeTime.

### Exit Streams

- ExitStreamCount

    '.Tally.ExitStreamCount.bins[0][2] == 1'

There is 1 stream per chutney Tor client.

To add more streams, use:

    run_test.sh ... -o 10

to ask clients to make multiple data source connections, or add more
clients. (See the notes under ExitActiveCircuitCount.)

- ExitInteractiveStreamCount
- ExitOtherPortStreamCount
- ExitP2PStreamCount
- ExitWebStreamCount

See the port variant notes under ExitInteractiveCircuitCount.

- ExitStreamLifeTime

Typically, chutney exit streams take less than a second to complete.
The counts for ExitStreamLifeTime match ExitStreamCount, just like
ExitCircuitLifeTime.

To increase stream lifetime, send more bytes:

    run_test.sh ... -b 100000000

On my machine, sending 100MB takes about 3 seconds.

- ExitInteractiveStreamLifeTime
- ExitOtherPortStreamLifeTime
- ExitP2PStreamLifeTime
- ExitWebStreamLifeTime

See the port variant notes under ExitInteractiveCircuitCount.

- ExitCircuitStreamHistogram

The counts for ExitCircuitStreamHistogram match ExitStreamCount, but since
ExitCircuitStreamHistogram is a per-circuit stream count histogram, there may
be some inaccuracy due to bucket sizes.
Increasing ExitStreamCount also increases ExitCircuitStreamHistogram.

- ExitCircuitInteractiveStreamHistogram
- ExitCircuitOtherPortStreamHistogram
- ExitCircuitP2PStreamHistogram
- ExitCircuitWebStreamHistogram

See the port variant notes under ExitInteractiveCircuitCount.

- ExitCircuitInterStreamCreationTime

The time in seconds between stream creation requests on the same circuit.
This is zero when there are zero or one streams on a circuit.
(There is one fewer InterStreamCreationTime than the number of streams.)

Chutney creates streams for each exit connection simultaneously, so
multiple connections will result in 0 InterStreamCreationTimes, even if
they transmit a large number of bytes.

To see non-zero InterStreamCreationTimes, add multiple chutney verification
rounds, and send more data:

    run_test.sh ... -u 3 -b 70000000

On my machine, sending 3 x 70 MB streams results in an [0,3) second time
and a [3, 30) second time.
(To increase stream times, use the instructions under ExitStreamLifeTime.)

- ExitCircuitInteractiveInterStreamCreationTime
- ExitCircuitOtherPortInterStreamCreationTime
- ExitCircuitP2PInterStreamCreationTime
- ExitCircuitWebInterStreamCreationTime

The InterStreamCreationTimes are calculated separately using a list of
stream creation times for each port variant. So the variants may not be
a subset of the ExitCircuitInterStreamCreationTimes.
See the port variant notes under ExitInteractiveCircuitCount for more
details.

### Exit Bytes

- ExitStreamByteCount

    '.Tally.ExitStreamByteCount.bins[0][2] == 10240'

The byte count is the sum of the Inbound and Outbound byte counts, but
there is no simple formula, because the Inbound and Outbound counts are
binned, but the ExitStreamByteCount is a single counter.

Use the instructions under:
  * ExitStreamLifeTime to change the number of bytes sent by chutney,
  * ExitStreamCount or ExitCircuitInterStreamCreationTime to change the
    number of streams opened by chutney.
Zero-byte requests are ignored by chutney, so they can't be tested.

TODO: send zero-byte requests.

- ExitInteractiveStreamByteCount
- ExitOtherPortStreamByteCount
- ExitP2PStreamByteCount
- ExitWebStreamByteCount

See the port variant notes under ExitInteractiveCircuitCount.

- ExitStreamInboundByteHistogram

See the note under ExitStreamByteRatio that explains why this isn't tested.

TODO: test Inbound bytes.

- ExitInteractiveStreamInboundByteHistogram
- ExitOtherPortStreamInboundByteHistogram
- ExitP2PStreamInboundByteHistogram
- ExitWebStreamInboundByteHistogram

See the port variant notes under ExitInteractiveCircuitCount.

- ExitStreamOutboundByteHistogram

    '.Tally.ExitStreamOutboundByteHistogram.bins[1][2] == 1'

The total count of all bins matches the ExitStreamCount.
Use the instructions under ExitStreamByteCount to change the byte count.
The ExitStreamOutboundByteHistogram is binned, so you will need to send at
least 32768 bytes to see the bin counts change.

- ExitInteractiveStreamOutboundByteHistogram
- ExitOtherPortStreamOutboundByteHistogram
- ExitP2PStreamOutboundByteHistogram
- ExitWebStreamOutboundByteHistogram

See the port variant notes under ExitInteractiveCircuitCount.

- ExitStreamByteRatio

    '.Tally.ExitStreamByteRatio.bins[-1][2] == 1'

The total count of all bins also matches the ExitStreamCount.
Chutney only sends Outbound bytes, so every stream will be in the highest
bin.

TODO: test non-zero Inbound bytes and test zero Outbound bytes.
This is less critical, because we test non-zero Inbound cells using the
EntryCircuitCellRatio.

- ExitInteractiveStreamByteRatio
- ExitOtherPortStreamByteRatio
- ExitP2PStreamByteRatio
- ExitWebStreamByteRatio

See the port variant notes under ExitInteractiveCircuitCount.

### Exit Traffic Model

- ExitStreamTrafficModelEmissionCount

    '.Tally.ExitStreamTrafficModelEmissionCount.bins[0][2] == 1'

There is one Emission for every 1500 bytes (or non-zero remainder)
transmitted. Inbound and Outbound emissions are calculated separately.
Use the instructions under ExitStreamByteCount to change the byte count.

- ExitStreamTrafficModelLogDelayTime
- ExitStreamTrafficModelSquaredLogDelayTime

Delay times are calculated from Emissions using socket read/write
timestamps in a similar way to InterStreamCreationTimes. See the notes
under ExitCircuitInterStreamCreationTime for more details.

Typically, LogDelayTimes are small integers or zero (depending on your OS
timestamp resolution). If there is only one write, the SquaredLogDelayTime
will be the square of the LogDelayTime. Use the instructions under
ExitStreamLifeTime to increase the number of bytes sent: this will
increase the [Squared]LogDelayTime.

- ExitStreamTrafficModelTransitionCount

    '.Tally.ExitStreamTrafficModelTransitionCount.bins[0][2] == 0'

Transitions depend on the specific traffic model.
In the default test model, you need at least 2 Emissions (1501 bytes) to
have 1 Transition. See the instructions under ExitStreamByteCount for
changing the byte count.

Transitions from the START state are not counted in this total.

#### Exit Traffic Model Template Counters

- ExitStreamTrafficModelEmissionCount_<STATE>_<DIRECTION>

    '.Tally["ExitStreamTrafficModelEmissionCount_Thinking_+"].bins[0][2] == 1'

These counters sum to the ExitStreamTrafficModelEmissionCount.
See the notes under ExitStreamTrafficModelEmissionCount.

TODO: test Inbound bytes ('-' direction).

- ExitStreamTrafficModelLogDelayTime_<STATE>_<DIRECTION>
- ExitStreamTrafficModelSquaredLogDelayTime_<STATE>_<DIRECTION>

These counters sum to the ExitStreamTrafficModel[Squared]LogDelayTime.
See the notes under ExitStreamTrafficModelLogDelayTime.

TODO: test Inbound bytes ('-' direction).

- ExitStreamTrafficModelTransitionCount_<SRCSTATE>_<DSTSTATE>

These counters sum to the ExitStreamTrafficModelTransitionCount.
See the notes under ExitStreamTrafficModelTransitionCount.

On my machine, for 1501 bytes, the transition is:

    '.Tally.ExitStreamTrafficModelTransitionCount_Thinking_Blabbing.bins[0][2] == 1'

- ExitStreamTrafficModelTransitionCount_START_<STATE>

    '.Tally.ExitStreamTrafficModelTransitionCount_START_Thinking.bins[0][2] == 1'

Transitions from the START state are not counted in
ExitStreamTrafficModelTransitionCount.
See the notes under ExitStreamTrafficModelTransitionCount.

## Entry Counter Tests

### Entry Connections

- EntryConnectionCount

    '.Tally.EntryConnectionCount.bins[0][2] == 3'

Each client makes EntryConnections to one or more Guards. Connections from
relays are ignored. In the smallest networks, clients use multiple guards,
so they can build multiple distinct paths.

- EntryConnectionLifeTime

    '.Tally.EntryConnectionLifeTime.bins[0][2] == 3'

Since the chutney network only runs for ~60 seconds, all
ConnectionLifeTimes fall in the [0, 120) bin.
Use the instructions under ExitCircuitLifeTime to increase the network
run time to 150 seconds.

### Entry Circuits

- EntryCircuitCount

Just like ExitCircuitCount, this is the sum of the EntryActiveCircuitCount
and EntryInactiveCircuitCount. But the EntryCircuitCount is different to
the ExitCircuitCount, because Guards ignore client circuits, but Exits
cannot know which circuits are from clients and which are from relays.

- EntryActiveCircuitCount

    '.Tally.EntryActiveCircuitCount.bins[0][2] == 1'

    '.Tally.EntryActiveCircuitCount.bins[0][2] ==
     .Tally.ExitActiveCircuitCount.bins[0][2]'

The EntryActiveCircuitCount is the same as the ExitActiveCircuitCount, as
setting up a 3-hop circuit takes ~6 cells, opening a stream ~2 cells, and
sending data takes 1 Outbound cell per 498 bytes.

- EntryInactiveCircuitCount

See the notes under EntryCircuitCount and ExitInactiveCircuitCount.

- EntryCircuitInboundCellHistogram

    '.Tally.EntryCircuitInboundCellHistogram.bins[1][2] == 1'


Even though we don't receive any data, we still receive cells in response
to circuit extension, stream establishment, and circuit teardown. We also
receive acknowledgement (SENDME) cells, approximately 1 per 50 Outbound
cells.

Use the instructions under ExitStreamByteCount to change the Outbound byte
count. This indirectly increases the number of Inbound cells. You will
need to send around 500000 bytes to get more than 32 Inbound cells.

TODO: test increased Inbound cell counts using Inbound bytes.
This is less critical, because Inbound cells increase when Outbound cells
increase due to acknowledgements. See the note under ExitStreamByteRatio
that explains why we only send data (and don't receive data) via chutney.

- EntryCircuitOutboundCellHistogram

    '.Tally.EntryCircuitOutboundCellHistogram.bins[1][2] == 1'

Use the instructions under ExitStreamByteCount to change the byte count,
and therefore the number of Outbound cells. You will need to send around
16384 bytes to use more than 32 cells.

- EntryCircuitCellRatio

    '.Tally.EntryCircuitCellRatio.bins | map(select(.[2] > 0)) | .[0][1] == 1'

When sending a small amount of Outbound data, the number of Outbound cells
exceeds the number of Inbound cells by a small margin.

Use the instructions under ExitStreamByteCount to change the byte count,
and therefore the number of Outbound cells. You will need to send around
5000 bytes to increase the ratio to [1,2).

### Entry Client IPs

- EntryClientIPCount

Since chutney only uses 127.0.0.1, there will only ever be one unique
EntryClientIP per rotation period.

PrivCount only increments the ClientIP counters when it rotates the
previous ClientIPs out of memory. So to test this counter, you need to run
a round for more than 20 minutes after a circuit ends, or decrease the
rotation time in the code.

Use the instructions under ExitCircuitLifeTime to increase the round
time. (Increasing the chutney network time should be avoided: the circuit
will not end until the client shuts down or times out.) Increasing the
number of verification rounds also allows more time for rotations. Use the
instructions under ExitCircuitInterStreamCreationTime to do this.

With a 5 second PrivCount rotation verification rounds, I see ~30 counts
in the [0,100) unique IP addresses bin.

TODO: test with IPv6 addresses.
The python code treats addresses as opaque strings, so this is not
important.

- EntryActiveClientIPCount
- EntryInactiveClientIPCount

A ClientIP can have both active and inactive circuits in a period, and
therefore appear in both counters.

Using the instructions under EntryClientIPCount, I see ~30 counts in the
[0,100) unique IP addresses bin for both Active and Inactive ClientIPs.

- EntryClientIPActiveCircuitHistogram

The bins are a histogram based on EntryActiveCircuitCounts per client
over the rotation period.

Using the instructions under EntryClientIPCount, I see 1 count in the
[0,4) circuits per unique IP address bin.

- EntryClientIPInactiveCircuitHistogram

The bins are a histogram based on EntryInactiveCircuitCounts per client
over the rotation period.

Using the instructions under EntryClientIPCount, I see 2 counts in the
[0,4) circuits per unique IP address bin.

## HSDir Counter Tests

### HSDir Store Counts

Most of these counters are used, and show the distributions that we would
expect.

TODO: go into much more detail under each counter group

The following HSDir sub-categories appear to be unused or negligible:
* RejectExpired
* RejectFuture
* RejectObsolete
* RejectUnparseable

If we assume that HS v2 basic auth descriptor sizes are similar to no
auth descriptor sizes, then the use of basic auth appears to be negligible.

- HSDir2StoreCount
- HSDir3StoreCount
- HSDir2StoreAddCount
- HSDir3StoreAddCount
- HSDir2StoreRejectExpiredHaveCachedCount
- HSDir2StoreRejectFutureHaveCachedCount
- HSDir2StoreRejectExpiredNoCachedCount
- HSDir2StoreRejectFutureNoCachedCount
- HSDir2StoreAddUpdatedCount
- HSDir3StoreAddUpdatedCount
- HSDir2StoreRejectUnparseableCount
- HSDir3StoreRejectUnparseableCount
- HSDir2StoreRejectDuplicateCount
- HSDir2StoreRejectObsoleteCount
- HSDir3StoreRejectObsoleteCount
- HSDir2StoreAddClientAuthCount
- HSDir2StoreRejectExpiredHaveCachedClientAuthCount
- HSDir2StoreRejectFutureHaveCachedClientAuthCount
- HSDir2StoreRejectExpiredNoCachedClientAuthCount
- HSDir2StoreRejectFutureNoCachedClientAuthCount
- HSDir2StoreAddUpdatedClientAuthCount
- HSDir2StoreClientAuthCount
- HSDir2StoreRejectDuplicateClientAuthCount
- HSDir2StoreRejectObsoleteClientAuthCount
- HSDir2StoreAddNoClientAuthCount
- HSDir2StoreRejectExpiredHaveCachedNoClientAuthCount
- HSDir2StoreRejectFutureHaveCachedNoClientAuthCount
- HSDir2StoreRejectExpiredNoCachedNoClientAuthCount
- HSDir2StoreRejectFutureNoCachedNoClientAuthCount
- HSDir2StoreAddUpdatedNoClientAuthCount
- HSDir2StoreNoClientAuthCount
- HSDir2StoreRejectDuplicateNoClientAuthCount
- HSDir2StoreRejectObsoleteNoClientAuthCount
- HSDir2StoreRejectNoClientAuthCount
- HSDir2StoreAddNewNoClientAuthCount
- HSDir2StoreRejectClientAuthCount
- HSDir2StoreAddNewClientAuthCount
- HSDir2StoreRejectCount
- HSDir3StoreRejectCount
- HSDir2StoreAddNewCount
- HSDir3StoreAddNewCount

### TODO: Category Name

- HSDir2StoreAddUploadDelayTime
- HSDir2StoreAddUpdatedUploadDelayTime
- HSDir2StoreUploadDelayTime
- HSDir2StoreRejectUploadDelayTime
- HSDir2StoreAddNewUploadDelayTime

### TODO: Category Name

- HSDir2StoreAddIntroPointHistogram
- HSDir2StoreIntroPointHistogram
- HSDir2StoreRejectIntroPointHistogram
- HSDir2StoreAddNewIntroPointHistogram

### TODO: Category Name

- HSDir2StoreAddIntroByteCount
- HSDir3StoreAddIntroByteCount
- HSDir2StoreAddUpdatedIntroByteCount
- HSDir3StoreAddUpdatedIntroByteCount
- HSDir2StoreIntroByteCount
- HSDir3StoreIntroByteCount
- HSDir2StoreClientAuthIntroByteCount
- HSDir2StoreNoClientAuthIntroByteCount
- HSDir2StoreRejectIntroByteCount
- HSDir3StoreRejectIntroByteCount
- HSDir2StoreAddNewIntroByteCount
- HSDir3StoreAddNewIntroByteCount

### TODO: Category Name

- HSDir2StoreAddIntroByteHistogram
- HSDir3StoreAddIntroByteHistogram
- HSDir2StoreIntroByteHistogram
- HSDir3StoreIntroByteHistogram
- HSDir2StoreAddClientAuthIntroByteHistogram
- HSDir2StoreClientAuthIntroByteHistogram
- HSDir2StoreAddNoClientAuthIntroByteHistogram
- HSDir2StoreNoClientAuthIntroByteHistogram
- HSDir2StoreAddNewNoClientAuthIntroByteHistogram
- HSDir2StoreAddNewClientAuthIntroByteHistogram
- HSDir2StoreRejectIntroByteHistogram
- HSDir3StoreRejectIntroByteHistogram
- HSDir2StoreAddNewIntroByteHistogram
- HSDir3StoreAddNewIntroByteHistogram

### TODO: Category Name

- HSDir2StoreAddDescriptorByteCount
- HSDir3StoreAddDescriptorByteCount
- HSDir2StoreAddUpdatedDescriptorByteCount
- HSDir3StoreAddUpdatedDescriptorByteCount
- HSDir2StoreDescriptorByteCount
- HSDir3StoreDescriptorByteCount
- HSDir2StoreClientAuthDescriptorByteCount
- HSDir2StoreNoClientAuthDescriptorByteCount
- HSDir2StoreRejectDescriptorByteCount
- HSDir3StoreRejectDescriptorByteCount
- HSDir2StoreAddNewDescriptorByteCount
- HSDir3StoreAddNewDescriptorByteCount

### TODO: Category Name

- HSDir2StoreAddDescriptorByteHistogram
- HSDir3StoreAddDescriptorByteHistogram
- HSDir2StoreDescriptorByteHistogram
- HSDir3StoreDescriptorByteHistogram
- HSDir2StoreAddClientAuthDescriptorByteHistogram
- HSDir2StoreClientAuthDescriptorByteHistogram
- HSDir2StoreAddNoClientAuthDescriptorByteHistogram
- HSDir2StoreNoClientAuthDescriptorByteHistogram
- HSDir2StoreAddNewNoClientAuthDescriptorByteHistogram
- HSDir2StoreAddNewClientAuthDescriptorByteHistogram
- HSDir2StoreRejectDescriptorByteHistogram
- HSDir3StoreRejectDescriptorByteHistogram
- HSDir2StoreAddNewDescriptorByteHistogram
- HSDir3StoreAddNewDescriptorByteHistogram

### TODO: Category Name

- HSDir3StoreAddRevisionHistogram
- HSDir3StoreAddUpdatedRevisionHistogram
- HSDir3StoreRevisionHistogram
- HSDir3StoreRejectRevisionHistogram
- HSDir3StoreAddNewRevisionHistogram

## Circuit Counter Tests

### Circuit Position Counters

- OriginCircuitCount
x EntryCircuitCount

TODO: Re-test and merge previous counter

- MidCircuitCount
- EndCircuitCount
- SingleHopCircuitCount

### Circuit End Position Subcategory Counters

x ExitCircuitCount

TODO: Re-test and merge previous counter

- DirCircuitCount

- HSDir2CircuitCount
- Intro2CircuitCount

- Rend2CircuitCount
- ExitAndRend2ClientCircuitCount
- ExitAndRend2ServiceCircuitCount

- Rend2ServiceCircuitCount
- Rend2SingleOnionServiceCircuitCount
- Rend2MultiHopServiceCircuitCount

- Rend2ClientCircuitCount
- Rend2Tor2WebClientCircuitCount
- Rend2MultiHopClientCircuitCount

## Cell Counter Tests

### TODO: Category Name

- Rend2ClientSentCellCount

## Connection Counter Tests

### TODO: Category Name

TODO: merge and integrate with existing counter tests

- Entry0RelayOnAddressConnectionOverlapHistogram
- NonEntry0RelayOnAddressConnectionOverlapHistogram
- Entry1RelayOnAddressConnectionOverlapHistogram
- NonEntry1RelayOnAddressConnectionOverlapHistogram
- Entry2RelayOnAddressConnectionOverlapHistogram
- NonEntry2RelayOnAddressConnectionOverlapHistogram
- EntryConnectionOverlapHistogram
- NonEntryConnectionOverlapHistogram
- Entry0RelayOnAddressConnectionLifeTime
- NonEntry0RelayOnAddressConnectionLifeTime
- Entry1RelayOnAddressConnectionLifeTime
- NonEntry1RelayOnAddressConnectionLifeTime
- Entry2RelayOnAddressConnectionLifeTime
- NonEntry2RelayOnAddressConnectionLifeTime
- NonEntryConnectionLifeTime
- Entry0RelayOnAddressConnectionCount
- NonEntry0RelayOnAddressConnectionCount
- Entry1RelayOnAddressConnectionCount
- NonEntry1RelayOnAddressConnectionCount
- Entry2RelayOnAddressConnectionCount
- NonEntry2RelayOnAddressConnectionCount
- NonEntryConnectionCount
- Intro2ServiceCircuitCount
- Rend2FailureCircuitCount
- Intro2FailureCircuitCount
- Rend2ServiceFailureCircuitCount
- Intro2ServiceFailureCircuitCount
- Rend2ClientFailureCircuitCount
- Intro2ClientFailureCircuitCount
- Rend2SuccessCircuitCount
- Intro2SuccessCircuitCount
- Rend2ServiceSuccessCircuitCount
- Intro2ServiceSuccessCircuitCount
- Rend2ClientSuccessCircuitCount
- Intro2ClientSuccessCircuitCount
- Intro2ClientCircuitCount
- ExitP2PStreamByteHistogram
- ExitWebStreamByteHistogram
- ExitInteractiveStreamByteHistogram
- ExitStreamByteHistogram
- ExitOtherPortStreamByteHistogram
- ExitP2PStreamInboundByteCount
- ExitWebStreamInboundByteCount
- ExitInteractiveStreamInboundByteCount
- ExitStreamInboundByteCount
- ExitOtherPortStreamInboundByteCount
- ExitP2PStreamOutboundByteCount
- ExitWebStreamOutboundByteCount
- ExitInteractiveStreamOutboundByteCount
- ExitStreamOutboundByteCount
- ExitOtherPortStreamOutboundByteCount
- ExitIPv4StreamLifeTime
- ExitIPv6StreamLifeTime
- ExitIPv4InitialStreamLifeTime
- ExitIPv6InitialStreamLifeTime
- ExitIPv4LiteralInitialStreamLifeTime
- ExitIPv6LiteralInitialStreamLifeTime
- ExitInitialStreamLifeTime
- ExitIPv4LiteralStreamLifeTime
- ExitIPv6LiteralStreamLifeTime
- ExitIPv4SubsequentStreamLifeTime
- ExitIPv6SubsequentStreamLifeTime
- ExitIPv4LiteralSubsequentStreamLifeTime
- ExitIPv6LiteralSubsequentStreamLifeTime
- ExitSubsequentStreamLifeTime
- ExitIPv4StreamInboundByteHistogram
- ExitIPv6StreamInboundByteHistogram
- ExitIPv4InitialStreamInboundByteHistogram
- ExitIPv6InitialStreamInboundByteHistogram
- ExitIPv4LiteralInitialStreamInboundByteHistogram
- ExitIPv6LiteralInitialStreamInboundByteHistogram
- ExitInitialStreamInboundByteHistogram
- ExitIPv4LiteralStreamInboundByteHistogram
- ExitIPv6LiteralStreamInboundByteHistogram
- ExitIPv4SubsequentStreamInboundByteHistogram
- ExitIPv6SubsequentStreamInboundByteHistogram
- ExitIPv4LiteralSubsequentStreamInboundByteHistogram
- ExitIPv6LiteralSubsequentStreamInboundByteHistogram
- ExitSubsequentStreamInboundByteHistogram
- ExitIPv4StreamOutboundByteHistogram
- ExitIPv6StreamOutboundByteHistogram
- ExitIPv4InitialStreamOutboundByteHistogram
- ExitIPv6InitialStreamOutboundByteHistogram
- ExitIPv4LiteralInitialStreamOutboundByteHistogram
- ExitIPv6LiteralInitialStreamOutboundByteHistogram
- ExitInitialStreamOutboundByteHistogram
- ExitIPv4LiteralStreamOutboundByteHistogram
- ExitIPv6LiteralStreamOutboundByteHistogram
- ExitIPv4SubsequentStreamOutboundByteHistogram
- ExitIPv6SubsequentStreamOutboundByteHistogram
- ExitIPv4LiteralSubsequentStreamOutboundByteHistogram
- ExitIPv6LiteralSubsequentStreamOutboundByteHistogram
- ExitSubsequentStreamOutboundByteHistogram
- ExitIPv4StreamByteHistogram
- ExitIPv6StreamByteHistogram
- ExitIPv4InitialStreamByteHistogram
- ExitIPv6InitialStreamByteHistogram
- ExitIPv4LiteralInitialStreamByteHistogram
- ExitIPv6LiteralInitialStreamByteHistogram
- ExitInitialStreamByteHistogram
- ExitIPv4LiteralStreamByteHistogram
- ExitIPv6LiteralStreamByteHistogram
- ExitIPv4SubsequentStreamByteHistogram
- ExitIPv6SubsequentStreamByteHistogram
- ExitIPv4LiteralSubsequentStreamByteHistogram
- ExitIPv6LiteralSubsequentStreamByteHistogram
- ExitSubsequentStreamByteHistogram
- ExitIPv4StreamByteRatio
- ExitIPv6StreamByteRatio
- ExitIPv4InitialStreamByteRatio
- ExitIPv6InitialStreamByteRatio
- ExitIPv4LiteralInitialStreamByteRatio
- ExitIPv6LiteralInitialStreamByteRatio
- ExitInitialStreamByteRatio
- ExitIPv4LiteralStreamByteRatio
- ExitIPv6LiteralStreamByteRatio
- ExitIPv4SubsequentStreamByteRatio
- ExitIPv6SubsequentStreamByteRatio
- ExitIPv4LiteralSubsequentStreamByteRatio
- ExitIPv6LiteralSubsequentStreamByteRatio
- ExitSubsequentStreamByteRatio
- ExitIPv4StreamInboundByteCount
- ExitIPv6StreamInboundByteCount
- ExitIPv4InitialStreamInboundByteCount
- ExitIPv6InitialStreamInboundByteCount
- ExitIPv4LiteralInitialStreamInboundByteCount
- ExitIPv6LiteralInitialStreamInboundByteCount
- ExitInitialStreamInboundByteCount
- ExitIPv4LiteralStreamInboundByteCount
- ExitIPv6LiteralStreamInboundByteCount
- ExitIPv4SubsequentStreamInboundByteCount
- ExitIPv6SubsequentStreamInboundByteCount
- ExitIPv4LiteralSubsequentStreamInboundByteCount
- ExitIPv6LiteralSubsequentStreamInboundByteCount
- ExitSubsequentStreamInboundByteCount
- ExitIPv4StreamOutboundByteCount
- ExitIPv6StreamOutboundByteCount
- ExitIPv4InitialStreamOutboundByteCount
- ExitIPv6InitialStreamOutboundByteCount
- ExitIPv4LiteralInitialStreamOutboundByteCount
- ExitIPv6LiteralInitialStreamOutboundByteCount
- ExitInitialStreamOutboundByteCount
- ExitIPv4LiteralStreamOutboundByteCount
- ExitIPv6LiteralStreamOutboundByteCount
- ExitIPv4SubsequentStreamOutboundByteCount
- ExitIPv6SubsequentStreamOutboundByteCount
- ExitIPv4LiteralSubsequentStreamOutboundByteCount
- ExitIPv6LiteralSubsequentStreamOutboundByteCount
- ExitSubsequentStreamOutboundByteCount
- ExitIPv4StreamByteCount
- ExitIPv6StreamByteCount
- ExitIPv4InitialStreamByteCount
- ExitIPv6InitialStreamByteCount
- ExitIPv4LiteralInitialStreamByteCount
- ExitIPv6LiteralInitialStreamByteCount
- ExitInitialStreamByteCount
- ExitIPv4LiteralStreamByteCount
- ExitIPv6LiteralStreamByteCount
- ExitIPv4SubsequentStreamByteCount
- ExitIPv6SubsequentStreamByteCount
- ExitIPv4LiteralSubsequentStreamByteCount
- ExitIPv6LiteralSubsequentStreamByteCount
- ExitSubsequentStreamByteCount
- ExitIPv4StreamCount
- ExitIPv6StreamCount
- ExitIPv4InitialStreamCount
- ExitIPv6InitialStreamCount
- ExitIPv4LiteralInitialStreamCount
- ExitIPv6LiteralInitialStreamCount
- ExitInitialStreamCount
- ExitIPv4LiteralStreamCount
- ExitIPv6LiteralStreamCount
- ExitIPv4SubsequentStreamCount
- ExitIPv6SubsequentStreamCount
- ExitIPv4LiteralSubsequentStreamCount
- ExitIPv6LiteralSubsequentStreamCount
- ExitSubsequentStreamCount
- ExitDomainExactMatchWebInitialStreamLifeTime
- ExitDomainNoExactMatchWebInitialStreamLifeTime
- ExitDomainSuffixMatchWebInitialStreamLifeTime
- ExitDomainNoSuffixMatchWebInitialStreamLifeTime
- ExitDomainExactMatchWebInitialStreamInboundByteHistogram
- ExitDomainNoExactMatchWebInitialStreamInboundByteHistogram
- ExitDomainSuffixMatchWebInitialStreamInboundByteHistogram
- ExitDomainNoSuffixMatchWebInitialStreamInboundByteHistogram
- ExitDomainExactMatchWebInitialStreamOutboundByteHistogram
- ExitDomainNoExactMatchWebInitialStreamOutboundByteHistogram
- ExitDomainSuffixMatchWebInitialStreamOutboundByteHistogram
- ExitDomainNoSuffixMatchWebInitialStreamOutboundByteHistogram
- ExitDomainExactMatchWebInitialStreamByteHistogram
- ExitDomainNoExactMatchWebInitialStreamByteHistogram
- ExitDomainSuffixMatchWebInitialStreamByteHistogram
- ExitDomainNoSuffixMatchWebInitialStreamByteHistogram
- ExitDomainExactMatchWebInitialStreamByteRatio
- ExitDomainNoExactMatchWebInitialStreamByteRatio
- ExitDomainSuffixMatchWebInitialStreamByteRatio
- ExitDomainNoSuffixMatchWebInitialStreamByteRatio
- ExitDomainExactMatchWebInitialStreamInboundByteCountList
- ExitDomainSuffixMatchWebInitialStreamInboundByteCountList
- ExitDomainExactMatchWebInitialStreamOutboundByteCountList
- ExitDomainSuffixMatchWebInitialStreamOutboundByteCountList
- ExitDomainExactMatchWebInitialStreamByteCountList
- ExitDomainSuffixMatchWebInitialStreamByteCountList
- ExitDomainExactMatchWebInitialStreamCountList
- ExitDomainSuffixMatchWebInitialStreamCountList
- Entry0RelayOnAddressConnectionInboundByteHistogram
- NonEntry0RelayOnAddressConnectionInboundByteHistogram
- Entry1RelayOnAddressConnectionInboundByteHistogram
- NonEntry1RelayOnAddressConnectionInboundByteHistogram
- Entry2RelayOnAddressConnectionInboundByteHistogram
- NonEntry2RelayOnAddressConnectionInboundByteHistogram
- EntryConnectionInboundByteHistogram
- NonEntryConnectionInboundByteHistogram
- Entry0RelayOnAddressConnectionOutboundByteHistogram
- NonEntry0RelayOnAddressConnectionOutboundByteHistogram
- Entry1RelayOnAddressConnectionOutboundByteHistogram
- NonEntry1RelayOnAddressConnectionOutboundByteHistogram
- Entry2RelayOnAddressConnectionOutboundByteHistogram
- NonEntry2RelayOnAddressConnectionOutboundByteHistogram
- EntryConnectionOutboundByteHistogram
- NonEntryConnectionOutboundByteHistogram
- Entry0RelayOnAddressConnectionByteHistogram
- NonEntry0RelayOnAddressConnectionByteHistogram
- Entry1RelayOnAddressConnectionByteHistogram
- NonEntry1RelayOnAddressConnectionByteHistogram
- Entry2RelayOnAddressConnectionByteHistogram
- NonEntry2RelayOnAddressConnectionByteHistogram
- EntryConnectionByteHistogram
- NonEntryConnectionByteHistogram
- Entry0RelayOnAddressConnectionInboundByteCount
- NonEntry0RelayOnAddressConnectionInboundByteCount
- Entry1RelayOnAddressConnectionInboundByteCount
- NonEntry1RelayOnAddressConnectionInboundByteCount
- Entry2RelayOnAddressConnectionInboundByteCount
- NonEntry2RelayOnAddressConnectionInboundByteCount
- EntryConnectionInboundByteCount
- NonEntryConnectionInboundByteCount
- Entry0RelayOnAddressConnectionOutboundByteCount
- NonEntry0RelayOnAddressConnectionOutboundByteCount
- Entry1RelayOnAddressConnectionOutboundByteCount
- NonEntry1RelayOnAddressConnectionOutboundByteCount
- Entry2RelayOnAddressConnectionOutboundByteCount
- NonEntry2RelayOnAddressConnectionOutboundByteCount
- EntryConnectionOutboundByteCount
- NonEntryConnectionOutboundByteCount
- Entry0RelayOnAddressConnectionByteCount
- NonEntry0RelayOnAddressConnectionByteCount
- Entry1RelayOnAddressConnectionByteCount
- NonEntry1RelayOnAddressConnectionByteCount
- Entry2RelayOnAddressConnectionByteCount
- NonEntry2RelayOnAddressConnectionByteCount
- EntryConnectionByteCount
- NonEntryConnectionByteCount
- Entry0RelayOnAddressConnectionInboundCircuitHistogram
- NonEntry0RelayOnAddressConnectionInboundCircuitHistogram
- Entry1RelayOnAddressConnectionInboundCircuitHistogram
- NonEntry1RelayOnAddressConnectionInboundCircuitHistogram
- Entry2RelayOnAddressConnectionInboundCircuitHistogram
- NonEntry2RelayOnAddressConnectionInboundCircuitHistogram
- EntryConnectionInboundCircuitHistogram
- NonEntryConnectionInboundCircuitHistogram
- Entry0RelayOnAddressConnectionOutboundCircuitHistogram
- NonEntry0RelayOnAddressConnectionOutboundCircuitHistogram
- Entry1RelayOnAddressConnectionOutboundCircuitHistogram
- NonEntry1RelayOnAddressConnectionOutboundCircuitHistogram
- Entry2RelayOnAddressConnectionOutboundCircuitHistogram
- NonEntry2RelayOnAddressConnectionOutboundCircuitHistogram
- EntryConnectionOutboundCircuitHistogram
- NonEntryConnectionOutboundCircuitHistogram
- Entry0RelayOnAddressConnectionCircuitHistogram
- NonEntry0RelayOnAddressConnectionCircuitHistogram
- Entry1RelayOnAddressConnectionCircuitHistogram
- NonEntry1RelayOnAddressConnectionCircuitHistogram
- Entry2RelayOnAddressConnectionCircuitHistogram
- NonEntry2RelayOnAddressConnectionCircuitHistogram
- EntryConnectionCircuitHistogram
- NonEntryConnectionCircuitHistogram
- Entry0RelayOnAddressConnectionInboundCircuitCount
- NonEntry0RelayOnAddressConnectionInboundCircuitCount
- Entry1RelayOnAddressConnectionInboundCircuitCount
- NonEntry1RelayOnAddressConnectionInboundCircuitCount
- Entry2RelayOnAddressConnectionInboundCircuitCount
- NonEntry2RelayOnAddressConnectionInboundCircuitCount
- EntryConnectionInboundCircuitCount
- NonEntryConnectionInboundCircuitCount
- Entry0RelayOnAddressConnectionOutboundCircuitCount
- NonEntry0RelayOnAddressConnectionOutboundCircuitCount
- Entry1RelayOnAddressConnectionOutboundCircuitCount
- NonEntry1RelayOnAddressConnectionOutboundCircuitCount
- Entry2RelayOnAddressConnectionOutboundCircuitCount
- NonEntry2RelayOnAddressConnectionOutboundCircuitCount
- EntryConnectionOutboundCircuitCount
- NonEntryConnectionOutboundCircuitCount
- Entry0RelayOnAddressConnectionCircuitCount
- NonEntry0RelayOnAddressConnectionCircuitCount
- Entry1RelayOnAddressConnectionCircuitCount
- NonEntry1RelayOnAddressConnectionCircuitCount
- Entry2RelayOnAddressConnectionCircuitCount
- NonEntry2RelayOnAddressConnectionCircuitCount
- EntryConnectionCircuitCount
- NonEntryConnectionCircuitCount
- Entry0RelayOnAddressConnectionCountryNoMatchLifeTime
- NonEntry0RelayOnAddressConnectionCountryNoMatchLifeTime
- Entry1RelayOnAddressConnectionCountryNoMatchLifeTime
- NonEntry1RelayOnAddressConnectionCountryNoMatchLifeTime
- Entry2RelayOnAddressConnectionCountryNoMatchLifeTime
- NonEntry2RelayOnAddressConnectionCountryNoMatchLifeTime
- EntryConnectionCountryNoMatchLifeTime
- NonEntryConnectionCountryNoMatchLifeTime
- Entry0RelayOnAddressConnectionCountryMatchLifeTime
- NonEntry0RelayOnAddressConnectionCountryMatchLifeTime
- Entry1RelayOnAddressConnectionCountryMatchLifeTime
- NonEntry1RelayOnAddressConnectionCountryMatchLifeTime
- Entry2RelayOnAddressConnectionCountryMatchLifeTime
- NonEntry2RelayOnAddressConnectionCountryMatchLifeTime
- EntryConnectionCountryMatchLifeTime
- NonEntryConnectionCountryMatchLifeTime
- Entry0RelayOnAddressConnectionCountryNoMatchInboundByteHistogram
- NonEntry0RelayOnAddressConnectionCountryNoMatchInboundByteHistogram
- Entry1RelayOnAddressConnectionCountryNoMatchInboundByteHistogram
- NonEntry1RelayOnAddressConnectionCountryNoMatchInboundByteHistogram
- Entry2RelayOnAddressConnectionCountryNoMatchInboundByteHistogram
- NonEntry2RelayOnAddressConnectionCountryNoMatchInboundByteHistogram
- EntryConnectionCountryNoMatchInboundByteHistogram
- NonEntryConnectionCountryNoMatchInboundByteHistogram
- Entry0RelayOnAddressConnectionCountryMatchInboundByteHistogram
- NonEntry0RelayOnAddressConnectionCountryMatchInboundByteHistogram
- Entry1RelayOnAddressConnectionCountryMatchInboundByteHistogram
- NonEntry1RelayOnAddressConnectionCountryMatchInboundByteHistogram
- Entry2RelayOnAddressConnectionCountryMatchInboundByteHistogram
- NonEntry2RelayOnAddressConnectionCountryMatchInboundByteHistogram
- EntryConnectionCountryMatchInboundByteHistogram
- NonEntryConnectionCountryMatchInboundByteHistogram
- Entry0RelayOnAddressConnectionCountryNoMatchOutboundByteHistogram
- NonEntry0RelayOnAddressConnectionCountryNoMatchOutboundByteHistogram
- Entry1RelayOnAddressConnectionCountryNoMatchOutboundByteHistogram
- NonEntry1RelayOnAddressConnectionCountryNoMatchOutboundByteHistogram
- Entry2RelayOnAddressConnectionCountryNoMatchOutboundByteHistogram
- NonEntry2RelayOnAddressConnectionCountryNoMatchOutboundByteHistogram
- EntryConnectionCountryNoMatchOutboundByteHistogram
- NonEntryConnectionCountryNoMatchOutboundByteHistogram
- Entry0RelayOnAddressConnectionCountryMatchOutboundByteHistogram
- NonEntry0RelayOnAddressConnectionCountryMatchOutboundByteHistogram
- Entry1RelayOnAddressConnectionCountryMatchOutboundByteHistogram
- NonEntry1RelayOnAddressConnectionCountryMatchOutboundByteHistogram
- Entry2RelayOnAddressConnectionCountryMatchOutboundByteHistogram
- NonEntry2RelayOnAddressConnectionCountryMatchOutboundByteHistogram
- EntryConnectionCountryMatchOutboundByteHistogram
- NonEntryConnectionCountryMatchOutboundByteHistogram
- Entry0RelayOnAddressConnectionCountryNoMatchByteHistogram
- NonEntry0RelayOnAddressConnectionCountryNoMatchByteHistogram
- Entry1RelayOnAddressConnectionCountryNoMatchByteHistogram
- NonEntry1RelayOnAddressConnectionCountryNoMatchByteHistogram
- Entry2RelayOnAddressConnectionCountryNoMatchByteHistogram
- NonEntry2RelayOnAddressConnectionCountryNoMatchByteHistogram
- EntryConnectionCountryNoMatchByteHistogram
- NonEntryConnectionCountryNoMatchByteHistogram
- Entry0RelayOnAddressConnectionCountryMatchByteHistogram
- NonEntry0RelayOnAddressConnectionCountryMatchByteHistogram
- Entry1RelayOnAddressConnectionCountryMatchByteHistogram
- NonEntry1RelayOnAddressConnectionCountryMatchByteHistogram
- Entry2RelayOnAddressConnectionCountryMatchByteHistogram
- NonEntry2RelayOnAddressConnectionCountryMatchByteHistogram
- EntryConnectionCountryMatchByteHistogram
- NonEntryConnectionCountryMatchByteHistogram
- Entry0RelayOnAddressConnectionCountryNoMatchOverlapHistogram
- NonEntry0RelayOnAddressConnectionCountryNoMatchOverlapHistogram
- Entry1RelayOnAddressConnectionCountryNoMatchOverlapHistogram
- NonEntry1RelayOnAddressConnectionCountryNoMatchOverlapHistogram
- Entry2RelayOnAddressConnectionCountryNoMatchOverlapHistogram
- NonEntry2RelayOnAddressConnectionCountryNoMatchOverlapHistogram
- EntryConnectionCountryNoMatchOverlapHistogram
- NonEntryConnectionCountryNoMatchOverlapHistogram
- Entry0RelayOnAddressConnectionCountryMatchOverlapHistogram
- NonEntry0RelayOnAddressConnectionCountryMatchOverlapHistogram
- Entry1RelayOnAddressConnectionCountryMatchOverlapHistogram
- NonEntry1RelayOnAddressConnectionCountryMatchOverlapHistogram
- Entry2RelayOnAddressConnectionCountryMatchOverlapHistogram
- NonEntry2RelayOnAddressConnectionCountryMatchOverlapHistogram
- EntryConnectionCountryMatchOverlapHistogram
- NonEntryConnectionCountryMatchOverlapHistogram
- Entry0RelayOnAddressConnectionCountryNoMatchInboundCircuitHistogram
- NonEntry0RelayOnAddressConnectionCountryNoMatchInboundCircuitHistogram
- Entry1RelayOnAddressConnectionCountryNoMatchInboundCircuitHistogram
- NonEntry1RelayOnAddressConnectionCountryNoMatchInboundCircuitHistogram
- Entry2RelayOnAddressConnectionCountryNoMatchInboundCircuitHistogram
- NonEntry2RelayOnAddressConnectionCountryNoMatchInboundCircuitHistogram
- EntryConnectionCountryNoMatchInboundCircuitHistogram
- NonEntryConnectionCountryNoMatchInboundCircuitHistogram
- Entry0RelayOnAddressConnectionCountryMatchInboundCircuitHistogram
- NonEntry0RelayOnAddressConnectionCountryMatchInboundCircuitHistogram
- Entry1RelayOnAddressConnectionCountryMatchInboundCircuitHistogram
- NonEntry1RelayOnAddressConnectionCountryMatchInboundCircuitHistogram
- Entry2RelayOnAddressConnectionCountryMatchInboundCircuitHistogram
- NonEntry2RelayOnAddressConnectionCountryMatchInboundCircuitHistogram
- EntryConnectionCountryMatchInboundCircuitHistogram
- NonEntryConnectionCountryMatchInboundCircuitHistogram
- Entry0RelayOnAddressConnectionCountryNoMatchOutboundCircuitHistogram
- NonEntry0RelayOnAddressConnectionCountryNoMatchOutboundCircuitHistogram
- Entry1RelayOnAddressConnectionCountryNoMatchOutboundCircuitHistogram
- NonEntry1RelayOnAddressConnectionCountryNoMatchOutboundCircuitHistogram
- Entry2RelayOnAddressConnectionCountryNoMatchOutboundCircuitHistogram
- NonEntry2RelayOnAddressConnectionCountryNoMatchOutboundCircuitHistogram
- EntryConnectionCountryNoMatchOutboundCircuitHistogram
- NonEntryConnectionCountryNoMatchOutboundCircuitHistogram
- Entry0RelayOnAddressConnectionCountryMatchOutboundCircuitHistogram
- NonEntry0RelayOnAddressConnectionCountryMatchOutboundCircuitHistogram
- Entry1RelayOnAddressConnectionCountryMatchOutboundCircuitHistogram
- NonEntry1RelayOnAddressConnectionCountryMatchOutboundCircuitHistogram
- Entry2RelayOnAddressConnectionCountryMatchOutboundCircuitHistogram
- NonEntry2RelayOnAddressConnectionCountryMatchOutboundCircuitHistogram
- EntryConnectionCountryMatchOutboundCircuitHistogram
- NonEntryConnectionCountryMatchOutboundCircuitHistogram
- Entry0RelayOnAddressConnectionCountryNoMatchCircuitHistogram
- NonEntry0RelayOnAddressConnectionCountryNoMatchCircuitHistogram
- Entry1RelayOnAddressConnectionCountryNoMatchCircuitHistogram
- NonEntry1RelayOnAddressConnectionCountryNoMatchCircuitHistogram
- Entry2RelayOnAddressConnectionCountryNoMatchCircuitHistogram
- NonEntry2RelayOnAddressConnectionCountryNoMatchCircuitHistogram
- EntryConnectionCountryNoMatchCircuitHistogram
- NonEntryConnectionCountryNoMatchCircuitHistogram
- Entry0RelayOnAddressConnectionCountryMatchCircuitHistogram
- NonEntry0RelayOnAddressConnectionCountryMatchCircuitHistogram
- Entry1RelayOnAddressConnectionCountryMatchCircuitHistogram
- NonEntry1RelayOnAddressConnectionCountryMatchCircuitHistogram
- Entry2RelayOnAddressConnectionCountryMatchCircuitHistogram
- NonEntry2RelayOnAddressConnectionCountryMatchCircuitHistogram
- EntryConnectionCountryMatchCircuitHistogram
- NonEntryConnectionCountryMatchCircuitHistogram
- Entry0RelayOnAddressConnectionCountryMatchInboundByteCountList
- NonEntry0RelayOnAddressConnectionCountryMatchInboundByteCountList
- Entry1RelayOnAddressConnectionCountryMatchInboundByteCountList
- NonEntry1RelayOnAddressConnectionCountryMatchInboundByteCountList
- Entry2RelayOnAddressConnectionCountryMatchInboundByteCountList
- NonEntry2RelayOnAddressConnectionCountryMatchInboundByteCountList
- EntryConnectionCountryMatchInboundByteCountList
- NonEntryConnectionCountryMatchInboundByteCountList
- Entry0RelayOnAddressConnectionCountryMatchOutboundByteCountList
- NonEntry0RelayOnAddressConnectionCountryMatchOutboundByteCountList
- Entry1RelayOnAddressConnectionCountryMatchOutboundByteCountList
- NonEntry1RelayOnAddressConnectionCountryMatchOutboundByteCountList
- Entry2RelayOnAddressConnectionCountryMatchOutboundByteCountList
- NonEntry2RelayOnAddressConnectionCountryMatchOutboundByteCountList
- EntryConnectionCountryMatchOutboundByteCountList
- NonEntryConnectionCountryMatchOutboundByteCountList
- Entry0RelayOnAddressConnectionCountryMatchByteCountList
- NonEntry0RelayOnAddressConnectionCountryMatchByteCountList
- Entry1RelayOnAddressConnectionCountryMatchByteCountList
- NonEntry1RelayOnAddressConnectionCountryMatchByteCountList
- Entry2RelayOnAddressConnectionCountryMatchByteCountList
- NonEntry2RelayOnAddressConnectionCountryMatchByteCountList
- EntryConnectionCountryMatchByteCountList
- NonEntryConnectionCountryMatchByteCountList
- Entry0RelayOnAddressConnectionCountryMatchCountList
- NonEntry0RelayOnAddressConnectionCountryMatchCountList
- Entry1RelayOnAddressConnectionCountryMatchCountList
- NonEntry1RelayOnAddressConnectionCountryMatchCountList
- Entry2RelayOnAddressConnectionCountryMatchCountList
- NonEntry2RelayOnAddressConnectionCountryMatchCountList
- EntryConnectionCountryMatchCountList
- NonEntryConnectionCountryMatchCountList
- Entry0RelayOnAddressConnectionCountryMatchInboundCircuitCountList
- NonEntry0RelayOnAddressConnectionCountryMatchInboundCircuitCountList
- Entry1RelayOnAddressConnectionCountryMatchInboundCircuitCountList
- NonEntry1RelayOnAddressConnectionCountryMatchInboundCircuitCountList
- Entry2RelayOnAddressConnectionCountryMatchInboundCircuitCountList
- NonEntry2RelayOnAddressConnectionCountryMatchInboundCircuitCountList
- EntryConnectionCountryMatchInboundCircuitCountList
- NonEntryConnectionCountryMatchInboundCircuitCountList
- Entry0RelayOnAddressConnectionCountryMatchOutboundCircuitCountList
- NonEntry0RelayOnAddressConnectionCountryMatchOutboundCircuitCountList
- Entry1RelayOnAddressConnectionCountryMatchOutboundCircuitCountList
- NonEntry1RelayOnAddressConnectionCountryMatchOutboundCircuitCountList
- Entry2RelayOnAddressConnectionCountryMatchOutboundCircuitCountList
- NonEntry2RelayOnAddressConnectionCountryMatchOutboundCircuitCountList
- EntryConnectionCountryMatchOutboundCircuitCountList
- NonEntryConnectionCountryMatchOutboundCircuitCountList
- Entry0RelayOnAddressConnectionCountryMatchCircuitCountList
- NonEntry0RelayOnAddressConnectionCountryMatchCircuitCountList
- Entry1RelayOnAddressConnectionCountryMatchCircuitCountList
- NonEntry1RelayOnAddressConnectionCountryMatchCircuitCountList
- Entry2RelayOnAddressConnectionCountryMatchCircuitCountList
- NonEntry2RelayOnAddressConnectionCountryMatchCircuitCountList
- EntryConnectionCountryMatchCircuitCountList
- NonEntryConnectionCountryMatchCircuitCountList
- ExitNonWebStreamLifeTime
- ExitNonWebStreamInboundByteHistogram
- ExitNonWebStreamOutboundByteHistogram
- ExitNonWebStreamByteHistogram
- ExitNonWebStreamByteRatio
- ExitNonWebStreamInboundByteCount
- ExitNonWebStreamOutboundByteCount
- ExitNonWebStreamByteCount
- ExitNonWebStreamCount
- ExitHostnameWebStreamLifeTime
- ExitHostnameNonWebStreamLifeTime
- ExitHostnameStreamLifeTime
- ExitHostnameInitialStreamLifeTime
- ExitHostnameSubsequentStreamLifeTime
- ExitHostnameWebStreamInboundByteHistogram
- ExitHostnameNonWebStreamInboundByteHistogram
- ExitHostnameStreamInboundByteHistogram
- ExitHostnameInitialStreamInboundByteHistogram
- ExitHostnameSubsequentStreamInboundByteHistogram
- ExitHostnameWebStreamOutboundByteHistogram
- ExitHostnameNonWebStreamOutboundByteHistogram
- ExitHostnameStreamOutboundByteHistogram
- ExitHostnameInitialStreamOutboundByteHistogram
- ExitHostnameSubsequentStreamOutboundByteHistogram
- ExitHostnameWebStreamByteHistogram
- ExitHostnameNonWebStreamByteHistogram
- ExitHostnameStreamByteHistogram
- ExitHostnameInitialStreamByteHistogram
- ExitHostnameSubsequentStreamByteHistogram
- ExitHostnameWebStreamByteRatio
- ExitHostnameNonWebStreamByteRatio
- ExitHostnameStreamByteRatio
- ExitHostnameInitialStreamByteRatio
- ExitHostnameSubsequentStreamByteRatio
- ExitHostnameWebStreamInboundByteCount
- ExitHostnameNonWebStreamInboundByteCount
- ExitHostnameStreamInboundByteCount
- ExitHostnameInitialStreamInboundByteCount
- ExitHostnameSubsequentStreamInboundByteCount
- ExitHostnameWebStreamOutboundByteCount
- ExitHostnameNonWebStreamOutboundByteCount
- ExitHostnameStreamOutboundByteCount
- ExitHostnameInitialStreamOutboundByteCount
- ExitHostnameSubsequentStreamOutboundByteCount
- ExitHostnameWebStreamByteCount
- ExitHostnameNonWebStreamByteCount
- ExitHostnameStreamByteCount
- ExitHostnameInitialStreamByteCount
- ExitHostnameSubsequentStreamByteCount
- ExitHostnameWebStreamCount
- ExitHostnameNonWebStreamCount
- ExitHostnameStreamCount
- ExitHostnameInitialStreamCount
- ExitHostnameSubsequentStreamCount
- Entry0RelayOnAddressConnectionASMatchLifeTime
- NonEntry0RelayOnAddressConnectionASMatchLifeTime
- Entry1RelayOnAddressConnectionASMatchLifeTime
- NonEntry1RelayOnAddressConnectionASMatchLifeTime
- Entry2RelayOnAddressConnectionASMatchLifeTime
- NonEntry2RelayOnAddressConnectionASMatchLifeTime
- EntryConnectionASMatchLifeTime
- NonEntryConnectionASMatchLifeTime
- Entry0RelayOnAddressConnectionASNoMatchLifeTime
- NonEntry0RelayOnAddressConnectionASNoMatchLifeTime
- Entry1RelayOnAddressConnectionASNoMatchLifeTime
- NonEntry1RelayOnAddressConnectionASNoMatchLifeTime
- Entry2RelayOnAddressConnectionASNoMatchLifeTime
- NonEntry2RelayOnAddressConnectionASNoMatchLifeTime
- EntryConnectionASNoMatchLifeTime
- NonEntryConnectionASNoMatchLifeTime
- Entry0RelayOnAddressConnectionASMatchInboundByteHistogram
- NonEntry0RelayOnAddressConnectionASMatchInboundByteHistogram
- Entry1RelayOnAddressConnectionASMatchInboundByteHistogram
- NonEntry1RelayOnAddressConnectionASMatchInboundByteHistogram
- Entry2RelayOnAddressConnectionASMatchInboundByteHistogram
- NonEntry2RelayOnAddressConnectionASMatchInboundByteHistogram
- EntryConnectionASMatchInboundByteHistogram
- NonEntryConnectionASMatchInboundByteHistogram
- Entry0RelayOnAddressConnectionASNoMatchInboundByteHistogram
- NonEntry0RelayOnAddressConnectionASNoMatchInboundByteHistogram
- Entry1RelayOnAddressConnectionASNoMatchInboundByteHistogram
- NonEntry1RelayOnAddressConnectionASNoMatchInboundByteHistogram
- Entry2RelayOnAddressConnectionASNoMatchInboundByteHistogram
- NonEntry2RelayOnAddressConnectionASNoMatchInboundByteHistogram
- EntryConnectionASNoMatchInboundByteHistogram
- NonEntryConnectionASNoMatchInboundByteHistogram
- Entry0RelayOnAddressConnectionASMatchOutboundByteHistogram
- NonEntry0RelayOnAddressConnectionASMatchOutboundByteHistogram
- Entry1RelayOnAddressConnectionASMatchOutboundByteHistogram
- NonEntry1RelayOnAddressConnectionASMatchOutboundByteHistogram
- Entry2RelayOnAddressConnectionASMatchOutboundByteHistogram
- NonEntry2RelayOnAddressConnectionASMatchOutboundByteHistogram
- EntryConnectionASMatchOutboundByteHistogram
- NonEntryConnectionASMatchOutboundByteHistogram
- Entry0RelayOnAddressConnectionASNoMatchOutboundByteHistogram
- NonEntry0RelayOnAddressConnectionASNoMatchOutboundByteHistogram
- Entry1RelayOnAddressConnectionASNoMatchOutboundByteHistogram
- NonEntry1RelayOnAddressConnectionASNoMatchOutboundByteHistogram
- Entry2RelayOnAddressConnectionASNoMatchOutboundByteHistogram
- NonEntry2RelayOnAddressConnectionASNoMatchOutboundByteHistogram
- EntryConnectionASNoMatchOutboundByteHistogram
- NonEntryConnectionASNoMatchOutboundByteHistogram
- Entry0RelayOnAddressConnectionASMatchByteHistogram
- NonEntry0RelayOnAddressConnectionASMatchByteHistogram
- Entry1RelayOnAddressConnectionASMatchByteHistogram
- NonEntry1RelayOnAddressConnectionASMatchByteHistogram
- Entry2RelayOnAddressConnectionASMatchByteHistogram
- NonEntry2RelayOnAddressConnectionASMatchByteHistogram
- EntryConnectionASMatchByteHistogram
- NonEntryConnectionASMatchByteHistogram
- Entry0RelayOnAddressConnectionASNoMatchByteHistogram
- NonEntry0RelayOnAddressConnectionASNoMatchByteHistogram
- Entry1RelayOnAddressConnectionASNoMatchByteHistogram
- NonEntry1RelayOnAddressConnectionASNoMatchByteHistogram
- Entry2RelayOnAddressConnectionASNoMatchByteHistogram
- NonEntry2RelayOnAddressConnectionASNoMatchByteHistogram
- EntryConnectionASNoMatchByteHistogram
- NonEntryConnectionASNoMatchByteHistogram
- Entry0RelayOnAddressConnectionASMatchOverlapHistogram
- NonEntry0RelayOnAddressConnectionASMatchOverlapHistogram
- Entry1RelayOnAddressConnectionASMatchOverlapHistogram
- NonEntry1RelayOnAddressConnectionASMatchOverlapHistogram
- Entry2RelayOnAddressConnectionASMatchOverlapHistogram
- NonEntry2RelayOnAddressConnectionASMatchOverlapHistogram
- EntryConnectionASMatchOverlapHistogram
- NonEntryConnectionASMatchOverlapHistogram
- Entry0RelayOnAddressConnectionASNoMatchOverlapHistogram
- NonEntry0RelayOnAddressConnectionASNoMatchOverlapHistogram
- Entry1RelayOnAddressConnectionASNoMatchOverlapHistogram
- NonEntry1RelayOnAddressConnectionASNoMatchOverlapHistogram
- Entry2RelayOnAddressConnectionASNoMatchOverlapHistogram
- NonEntry2RelayOnAddressConnectionASNoMatchOverlapHistogram
- EntryConnectionASNoMatchOverlapHistogram
- NonEntryConnectionASNoMatchOverlapHistogram
- Entry0RelayOnAddressConnectionASMatchInboundCircuitHistogram
- NonEntry0RelayOnAddressConnectionASMatchInboundCircuitHistogram
- Entry1RelayOnAddressConnectionASMatchInboundCircuitHistogram
- NonEntry1RelayOnAddressConnectionASMatchInboundCircuitHistogram
- Entry2RelayOnAddressConnectionASMatchInboundCircuitHistogram
- NonEntry2RelayOnAddressConnectionASMatchInboundCircuitHistogram
- EntryConnectionASMatchInboundCircuitHistogram
- NonEntryConnectionASMatchInboundCircuitHistogram
- Entry0RelayOnAddressConnectionASNoMatchInboundCircuitHistogram
- NonEntry0RelayOnAddressConnectionASNoMatchInboundCircuitHistogram
- Entry1RelayOnAddressConnectionASNoMatchInboundCircuitHistogram
- NonEntry1RelayOnAddressConnectionASNoMatchInboundCircuitHistogram
- Entry2RelayOnAddressConnectionASNoMatchInboundCircuitHistogram
- NonEntry2RelayOnAddressConnectionASNoMatchInboundCircuitHistogram
- EntryConnectionASNoMatchInboundCircuitHistogram
- NonEntryConnectionASNoMatchInboundCircuitHistogram
- Entry0RelayOnAddressConnectionASMatchOutboundCircuitHistogram
- NonEntry0RelayOnAddressConnectionASMatchOutboundCircuitHistogram
- Entry1RelayOnAddressConnectionASMatchOutboundCircuitHistogram
- NonEntry1RelayOnAddressConnectionASMatchOutboundCircuitHistogram
- Entry2RelayOnAddressConnectionASMatchOutboundCircuitHistogram
- NonEntry2RelayOnAddressConnectionASMatchOutboundCircuitHistogram
- EntryConnectionASMatchOutboundCircuitHistogram
- NonEntryConnectionASMatchOutboundCircuitHistogram
- Entry0RelayOnAddressConnectionASNoMatchOutboundCircuitHistogram
- NonEntry0RelayOnAddressConnectionASNoMatchOutboundCircuitHistogram
- Entry1RelayOnAddressConnectionASNoMatchOutboundCircuitHistogram
- NonEntry1RelayOnAddressConnectionASNoMatchOutboundCircuitHistogram
- Entry2RelayOnAddressConnectionASNoMatchOutboundCircuitHistogram
- NonEntry2RelayOnAddressConnectionASNoMatchOutboundCircuitHistogram
- EntryConnectionASNoMatchOutboundCircuitHistogram
- NonEntryConnectionASNoMatchOutboundCircuitHistogram
- Entry0RelayOnAddressConnectionASMatchCircuitHistogram
- NonEntry0RelayOnAddressConnectionASMatchCircuitHistogram
- Entry1RelayOnAddressConnectionASMatchCircuitHistogram
- NonEntry1RelayOnAddressConnectionASMatchCircuitHistogram
- Entry2RelayOnAddressConnectionASMatchCircuitHistogram
- NonEntry2RelayOnAddressConnectionASMatchCircuitHistogram
- EntryConnectionASMatchCircuitHistogram
- NonEntryConnectionASMatchCircuitHistogram
- Entry0RelayOnAddressConnectionASNoMatchCircuitHistogram
- NonEntry0RelayOnAddressConnectionASNoMatchCircuitHistogram
- Entry1RelayOnAddressConnectionASNoMatchCircuitHistogram
- NonEntry1RelayOnAddressConnectionASNoMatchCircuitHistogram
- Entry2RelayOnAddressConnectionASNoMatchCircuitHistogram
- NonEntry2RelayOnAddressConnectionASNoMatchCircuitHistogram
- EntryConnectionASNoMatchCircuitHistogram
- NonEntryConnectionASNoMatchCircuitHistogram
- Entry0RelayOnAddressConnectionASMatchInboundByteCountList
- NonEntry0RelayOnAddressConnectionASMatchInboundByteCountList
- Entry1RelayOnAddressConnectionASMatchInboundByteCountList
- NonEntry1RelayOnAddressConnectionASMatchInboundByteCountList
- Entry2RelayOnAddressConnectionASMatchInboundByteCountList
- NonEntry2RelayOnAddressConnectionASMatchInboundByteCountList
- EntryConnectionASMatchInboundByteCountList
- NonEntryConnectionASMatchInboundByteCountList
- Entry0RelayOnAddressConnectionASMatchOutboundByteCountList
- NonEntry0RelayOnAddressConnectionASMatchOutboundByteCountList
- Entry1RelayOnAddressConnectionASMatchOutboundByteCountList
- NonEntry1RelayOnAddressConnectionASMatchOutboundByteCountList
- Entry2RelayOnAddressConnectionASMatchOutboundByteCountList
- NonEntry2RelayOnAddressConnectionASMatchOutboundByteCountList
- EntryConnectionASMatchOutboundByteCountList
- NonEntryConnectionASMatchOutboundByteCountList
- Entry0RelayOnAddressConnectionASMatchByteCountList
- NonEntry0RelayOnAddressConnectionASMatchByteCountList
- Entry1RelayOnAddressConnectionASMatchByteCountList
- NonEntry1RelayOnAddressConnectionASMatchByteCountList
- Entry2RelayOnAddressConnectionASMatchByteCountList
- NonEntry2RelayOnAddressConnectionASMatchByteCountList
- EntryConnectionASMatchByteCountList
- NonEntryConnectionASMatchByteCountList
- Entry0RelayOnAddressConnectionASMatchCountList
- NonEntry0RelayOnAddressConnectionASMatchCountList
- Entry1RelayOnAddressConnectionASMatchCountList
- NonEntry1RelayOnAddressConnectionASMatchCountList
- Entry2RelayOnAddressConnectionASMatchCountList
- NonEntry2RelayOnAddressConnectionASMatchCountList
- EntryConnectionASMatchCountList
- NonEntryConnectionASMatchCountList
- Entry0RelayOnAddressConnectionASMatchInboundCircuitCountList
- NonEntry0RelayOnAddressConnectionASMatchInboundCircuitCountList
- Entry1RelayOnAddressConnectionASMatchInboundCircuitCountList
- NonEntry1RelayOnAddressConnectionASMatchInboundCircuitCountList
- Entry2RelayOnAddressConnectionASMatchInboundCircuitCountList
- NonEntry2RelayOnAddressConnectionASMatchInboundCircuitCountList
- EntryConnectionASMatchInboundCircuitCountList
- NonEntryConnectionASMatchInboundCircuitCountList
- Entry0RelayOnAddressConnectionASMatchOutboundCircuitCountList
- NonEntry0RelayOnAddressConnectionASMatchOutboundCircuitCountList
- Entry1RelayOnAddressConnectionASMatchOutboundCircuitCountList
- NonEntry1RelayOnAddressConnectionASMatchOutboundCircuitCountList
- Entry2RelayOnAddressConnectionASMatchOutboundCircuitCountList
- NonEntry2RelayOnAddressConnectionASMatchOutboundCircuitCountList
- EntryConnectionASMatchOutboundCircuitCountList
- NonEntryConnectionASMatchOutboundCircuitCountList
- Entry0RelayOnAddressConnectionASMatchCircuitCountList
- NonEntry0RelayOnAddressConnectionASMatchCircuitCountList
- Entry1RelayOnAddressConnectionASMatchCircuitCountList
- NonEntry1RelayOnAddressConnectionASMatchCircuitCountList
- Entry2RelayOnAddressConnectionASMatchCircuitCountList
- NonEntry2RelayOnAddressConnectionASMatchCircuitCountList
- EntryConnectionASMatchCircuitCountList
- NonEntryConnectionASMatchCircuitCountList
- ExitHostnameWebInitialStreamLifeTime
- ExitHostnameWebSubsequentStreamLifeTime
- ExitHostnameWebInitialStreamInboundByteHistogram
- ExitHostnameWebSubsequentStreamInboundByteHistogram
- ExitHostnameWebInitialStreamOutboundByteHistogram
- ExitHostnameWebSubsequentStreamOutboundByteHistogram
- ExitHostnameWebInitialStreamByteHistogram
- ExitHostnameWebSubsequentStreamByteHistogram
- ExitHostnameWebInitialStreamByteRatio
- ExitHostnameWebSubsequentStreamByteRatio
- ExitHostnameWebInitialStreamInboundByteCount
- ExitHostnameWebSubsequentStreamInboundByteCount
- ExitHostnameWebInitialStreamOutboundByteCount
- ExitHostnameWebSubsequentStreamOutboundByteCount
- ExitHostnameWebInitialStreamByteCount
- ExitHostnameWebSubsequentStreamByteCount
- ExitHostnameWebInitialStreamCount
- ExitHostnameWebSubsequentStreamCount
- ExitHostnameNonWebInitialStreamLifeTime
- ExitHostnameNonWebSubsequentStreamLifeTime
- ExitHostnameNonWebInitialStreamInboundByteHistogram
- ExitHostnameNonWebSubsequentStreamInboundByteHistogram
- ExitHostnameNonWebInitialStreamOutboundByteHistogram
- ExitHostnameNonWebSubsequentStreamOutboundByteHistogram
- ExitHostnameNonWebInitialStreamByteHistogram
- ExitHostnameNonWebSubsequentStreamByteHistogram
- ExitHostnameNonWebInitialStreamByteRatio
- ExitHostnameNonWebSubsequentStreamByteRatio
- ExitHostnameNonWebInitialStreamInboundByteCount
- ExitHostnameNonWebSubsequentStreamInboundByteCount
- ExitHostnameNonWebInitialStreamOutboundByteCount
- ExitHostnameNonWebSubsequentStreamOutboundByteCount
- ExitHostnameNonWebInitialStreamByteCount
- ExitHostnameNonWebSubsequentStreamByteCount
- ExitHostnameNonWebInitialStreamCount
- ExitHostnameNonWebSubsequentStreamCount
