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
EntryActiveCircuitCellRatio.

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

- EntryActiveCircuitCellRatio

    '.Tally.EntryActiveCircuitCellRatio.bins | map(select(.[2] > 0)) | .[0][1] == 1'

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
- HSDir2StoreRejectExpiredCachedCount
- HSDir2StoreRejectFutureCachedCount
- HSDir2StoreRejectExpiredUncachedCount
- HSDir2StoreRejectFutureUncachedCount
- HSDir2StoreAddUpdatedCount
- HSDir3StoreAddUpdatedCount
- HSDir2StoreRejectUnparseableCount
- HSDir3StoreRejectUnparseableCount
- HSDir2StoreRejectDuplicateCount
- HSDir2StoreRejectObsoleteCount
- HSDir3StoreRejectObsoleteCount
- HSDir2StoreAddClientAuthCount
- HSDir2StoreRejectExpiredCachedClientAuthCount
- HSDir2StoreRejectFutureCachedClientAuthCount
- HSDir2StoreRejectExpiredUncachedClientAuthCount
- HSDir2StoreRejectFutureUncachedClientAuthCount
- HSDir2StoreAddUpdatedClientAuthCount
- HSDir2StoreClientAuthCount
- HSDir2StoreRejectDuplicateClientAuthCount
- HSDir2StoreRejectObsoleteClientAuthCount
- HSDir2StoreAddNoClientAuthCount
- HSDir2StoreRejectExpiredCachedNoClientAuthCount
- HSDir2StoreRejectFutureCachedNoClientAuthCount
- HSDir2StoreRejectExpiredUncachedNoClientAuthCount
- HSDir2StoreRejectFutureUncachedNoClientAuthCount
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
- HSDir2FetchCachedCount
- HSDir3FetchCachedCount
- HSDir2FetchUncachedCount
- HSDir3FetchUncachedCount
- HSDir2FetchCount
- HSDir3FetchCount
- Rend2CircuitInboundCellCount
- Intro2CircuitInboundCellCount
- HSDir2CircuitInboundCellCount
- Rend3CircuitInboundCellCount
- Intro3CircuitInboundCellCount
- HSDir3CircuitInboundCellCount
- MidCircuitInboundCellCount
- EndCircuitInboundCellCount
- Rend2ServiceCircuitInboundCellCount
- Intro2ServiceCircuitInboundCellCount
- Rend3ServiceCircuitInboundCellCount
- Intro3ServiceCircuitInboundCellCount
- Rend2SingleOnionServiceCircuitInboundCellCount
- Intro2SingleOnionServiceCircuitInboundCellCount
- Rend3SingleOnionServiceCircuitInboundCellCount
- Intro3SingleOnionServiceCircuitInboundCellCount
- Rend2MultiHopServiceCircuitInboundCellCount
- Intro2MultiHopServiceCircuitInboundCellCount
- Rend3MultiHopServiceCircuitInboundCellCount
- Intro3MultiHopServiceCircuitInboundCellCount
- Rend2FailureCircuitInboundCellCount
- Intro2FailureCircuitInboundCellCount
- Rend3FailureCircuitInboundCellCount
- Intro3FailureCircuitInboundCellCount
- Rend2ServiceFailureCircuitInboundCellCount
- Intro2ServiceFailureCircuitInboundCellCount
- Rend3ServiceFailureCircuitInboundCellCount
- Intro3ServiceFailureCircuitInboundCellCount
- Rend2SingleOnionServiceFailureCircuitInboundCellCount
- Intro2SingleOnionServiceFailureCircuitInboundCellCount
- Rend3SingleOnionServiceFailureCircuitInboundCellCount
- Intro3SingleOnionServiceFailureCircuitInboundCellCount
- Rend2MultiHopServiceFailureCircuitInboundCellCount
- Intro2MultiHopServiceFailureCircuitInboundCellCount
- Rend3MultiHopServiceFailureCircuitInboundCellCount
- Intro3MultiHopServiceFailureCircuitInboundCellCount
- Rend2ClientFailureCircuitInboundCellCount
- Intro2ClientFailureCircuitInboundCellCount
- Rend3ClientFailureCircuitInboundCellCount
- Intro3ClientFailureCircuitInboundCellCount
- Rend2Tor2WebClientFailureCircuitInboundCellCount
- Intro2Tor2WebClientFailureCircuitInboundCellCount
- Rend3Tor2WebClientFailureCircuitInboundCellCount
- Intro3Tor2WebClientFailureCircuitInboundCellCount
- Rend2MultiHopClientFailureCircuitInboundCellCount
- Intro2MultiHopClientFailureCircuitInboundCellCount
- Rend3MultiHopClientFailureCircuitInboundCellCount
- Intro3MultiHopClientFailureCircuitInboundCellCount
- OriginCircuitInboundCellCount
- SingleHopCircuitInboundCellCount
- DirCircuitInboundCellCount
- Rend2SuccessCircuitInboundCellCount
- Intro2SuccessCircuitInboundCellCount
- Rend3SuccessCircuitInboundCellCount
- Intro3SuccessCircuitInboundCellCount
- Rend2ServiceSuccessCircuitInboundCellCount
- Intro2ServiceSuccessCircuitInboundCellCount
- Rend3ServiceSuccessCircuitInboundCellCount
- Intro3ServiceSuccessCircuitInboundCellCount
- Rend2SingleOnionServiceSuccessCircuitInboundCellCount
- Intro2SingleOnionServiceSuccessCircuitInboundCellCount
- Rend3SingleOnionServiceSuccessCircuitInboundCellCount
- Intro3SingleOnionServiceSuccessCircuitInboundCellCount
- Rend2MultiHopServiceSuccessCircuitInboundCellCount
- Intro2MultiHopServiceSuccessCircuitInboundCellCount
- Rend3MultiHopServiceSuccessCircuitInboundCellCount
- Intro3MultiHopServiceSuccessCircuitInboundCellCount
- Rend2ClientSuccessCircuitInboundCellCount
- Intro2ClientSuccessCircuitInboundCellCount
- Rend3ClientSuccessCircuitInboundCellCount
- Intro3ClientSuccessCircuitInboundCellCount
- Rend2Tor2WebClientSuccessCircuitInboundCellCount
- Intro2Tor2WebClientSuccessCircuitInboundCellCount
- Rend3Tor2WebClientSuccessCircuitInboundCellCount
- Intro3Tor2WebClientSuccessCircuitInboundCellCount
- Rend2MultiHopClientSuccessCircuitInboundCellCount
- Intro2MultiHopClientSuccessCircuitInboundCellCount
- Rend3MultiHopClientSuccessCircuitInboundCellCount
- Intro3MultiHopClientSuccessCircuitInboundCellCount
- ExitCircuitInboundCellCount
- Rend2ClientCircuitInboundCellCount
- Intro2ClientCircuitInboundCellCount
- Rend3ClientCircuitInboundCellCount
- Intro3ClientCircuitInboundCellCount
- Rend2Tor2WebClientCircuitInboundCellCount
- Intro2Tor2WebClientCircuitInboundCellCount
- Rend3Tor2WebClientCircuitInboundCellCount
- Intro3Tor2WebClientCircuitInboundCellCount
- Rend2MultiHopClientCircuitInboundCellCount
- Intro2MultiHopClientCircuitInboundCellCount
- Rend3MultiHopClientCircuitInboundCellCount
- Intro3MultiHopClientCircuitInboundCellCount
- EntryCircuitInboundCellCount
- Rend2CircuitOutboundCellCount
- Intro2CircuitOutboundCellCount
- HSDir2CircuitOutboundCellCount
- Rend3CircuitOutboundCellCount
- Intro3CircuitOutboundCellCount
- HSDir3CircuitOutboundCellCount
- MidCircuitOutboundCellCount
- EndCircuitOutboundCellCount
- Rend2ServiceCircuitOutboundCellCount
- Intro2ServiceCircuitOutboundCellCount
- Rend3ServiceCircuitOutboundCellCount
- Intro3ServiceCircuitOutboundCellCount
- Rend2SingleOnionServiceCircuitOutboundCellCount
- Intro2SingleOnionServiceCircuitOutboundCellCount
- Rend3SingleOnionServiceCircuitOutboundCellCount
- Intro3SingleOnionServiceCircuitOutboundCellCount
- Rend2MultiHopServiceCircuitOutboundCellCount
- Intro2MultiHopServiceCircuitOutboundCellCount
- Rend3MultiHopServiceCircuitOutboundCellCount
- Intro3MultiHopServiceCircuitOutboundCellCount
- Rend2FailureCircuitOutboundCellCount
- Intro2FailureCircuitOutboundCellCount
- Rend3FailureCircuitOutboundCellCount
- Intro3FailureCircuitOutboundCellCount
- Rend2ServiceFailureCircuitOutboundCellCount
- Intro2ServiceFailureCircuitOutboundCellCount
- Rend3ServiceFailureCircuitOutboundCellCount
- Intro3ServiceFailureCircuitOutboundCellCount
- Rend2SingleOnionServiceFailureCircuitOutboundCellCount
- Intro2SingleOnionServiceFailureCircuitOutboundCellCount
- Rend3SingleOnionServiceFailureCircuitOutboundCellCount
- Intro3SingleOnionServiceFailureCircuitOutboundCellCount
- Rend2MultiHopServiceFailureCircuitOutboundCellCount
- Intro2MultiHopServiceFailureCircuitOutboundCellCount
- Rend3MultiHopServiceFailureCircuitOutboundCellCount
- Intro3MultiHopServiceFailureCircuitOutboundCellCount
- Rend2ClientFailureCircuitOutboundCellCount
- Intro2ClientFailureCircuitOutboundCellCount
- Rend3ClientFailureCircuitOutboundCellCount
- Intro3ClientFailureCircuitOutboundCellCount
- Rend2Tor2WebClientFailureCircuitOutboundCellCount
- Intro2Tor2WebClientFailureCircuitOutboundCellCount
- Rend3Tor2WebClientFailureCircuitOutboundCellCount
- Intro3Tor2WebClientFailureCircuitOutboundCellCount
- Rend2MultiHopClientFailureCircuitOutboundCellCount
- Intro2MultiHopClientFailureCircuitOutboundCellCount
- Rend3MultiHopClientFailureCircuitOutboundCellCount
- Intro3MultiHopClientFailureCircuitOutboundCellCount
- OriginCircuitOutboundCellCount
- SingleHopCircuitOutboundCellCount
- DirCircuitOutboundCellCount
- Rend2SuccessCircuitOutboundCellCount
- Intro2SuccessCircuitOutboundCellCount
- Rend3SuccessCircuitOutboundCellCount
- Intro3SuccessCircuitOutboundCellCount
- Rend2ServiceSuccessCircuitOutboundCellCount
- Intro2ServiceSuccessCircuitOutboundCellCount
- Rend3ServiceSuccessCircuitOutboundCellCount
- Intro3ServiceSuccessCircuitOutboundCellCount
- Rend2SingleOnionServiceSuccessCircuitOutboundCellCount
- Intro2SingleOnionServiceSuccessCircuitOutboundCellCount
- Rend3SingleOnionServiceSuccessCircuitOutboundCellCount
- Intro3SingleOnionServiceSuccessCircuitOutboundCellCount
- Rend2MultiHopServiceSuccessCircuitOutboundCellCount
- Intro2MultiHopServiceSuccessCircuitOutboundCellCount
- Rend3MultiHopServiceSuccessCircuitOutboundCellCount
- Intro3MultiHopServiceSuccessCircuitOutboundCellCount
- Rend2ClientSuccessCircuitOutboundCellCount
- Intro2ClientSuccessCircuitOutboundCellCount
- Rend3ClientSuccessCircuitOutboundCellCount
- Intro3ClientSuccessCircuitOutboundCellCount
- Rend2Tor2WebClientSuccessCircuitOutboundCellCount
- Intro2Tor2WebClientSuccessCircuitOutboundCellCount
- Rend3Tor2WebClientSuccessCircuitOutboundCellCount
- Intro3Tor2WebClientSuccessCircuitOutboundCellCount
- Rend2MultiHopClientSuccessCircuitOutboundCellCount
- Intro2MultiHopClientSuccessCircuitOutboundCellCount
- Rend3MultiHopClientSuccessCircuitOutboundCellCount
- Intro3MultiHopClientSuccessCircuitOutboundCellCount
- ExitCircuitOutboundCellCount
- Rend2ClientCircuitOutboundCellCount
- Intro2ClientCircuitOutboundCellCount
- Rend3ClientCircuitOutboundCellCount
- Intro3ClientCircuitOutboundCellCount
- Rend2Tor2WebClientCircuitOutboundCellCount
- Intro2Tor2WebClientCircuitOutboundCellCount
- Rend3Tor2WebClientCircuitOutboundCellCount
- Intro3Tor2WebClientCircuitOutboundCellCount
- Rend2MultiHopClientCircuitOutboundCellCount
- Intro2MultiHopClientCircuitOutboundCellCount
- Rend3MultiHopClientCircuitOutboundCellCount
- Intro3MultiHopClientCircuitOutboundCellCount
- EntryCircuitOutboundCellCount
- Rend3CircuitCount
- Intro3CircuitCount
- HSDir3CircuitCount
- Rend3ServiceCircuitCount
- Intro3ServiceCircuitCount
- Intro2SingleOnionServiceCircuitCount
- Rend3SingleOnionServiceCircuitCount
- Intro3SingleOnionServiceCircuitCount
- Intro2MultiHopServiceCircuitCount
- Rend3MultiHopServiceCircuitCount
- Intro3MultiHopServiceCircuitCount
- Rend3FailureCircuitCount
- Intro3FailureCircuitCount
- Rend3ServiceFailureCircuitCount
- Intro3ServiceFailureCircuitCount
- Rend2SingleOnionServiceFailureCircuitCount
- Intro2SingleOnionServiceFailureCircuitCount
- Rend3SingleOnionServiceFailureCircuitCount
- Intro3SingleOnionServiceFailureCircuitCount
- Rend2MultiHopServiceFailureCircuitCount
- Intro2MultiHopServiceFailureCircuitCount
- Rend3MultiHopServiceFailureCircuitCount
- Intro3MultiHopServiceFailureCircuitCount
- Rend3ClientFailureCircuitCount
- Intro3ClientFailureCircuitCount
- Rend2Tor2WebClientFailureCircuitCount
- Intro2Tor2WebClientFailureCircuitCount
- Rend3Tor2WebClientFailureCircuitCount
- Intro3Tor2WebClientFailureCircuitCount
- Rend2MultiHopClientFailureCircuitCount
- Intro2MultiHopClientFailureCircuitCount
- Rend3MultiHopClientFailureCircuitCount
- Intro3MultiHopClientFailureCircuitCount
- Rend3SuccessCircuitCount
- Intro3SuccessCircuitCount
- Rend3ServiceSuccessCircuitCount
- Intro3ServiceSuccessCircuitCount
- Rend2SingleOnionServiceSuccessCircuitCount
- Intro2SingleOnionServiceSuccessCircuitCount
- Rend3SingleOnionServiceSuccessCircuitCount
- Intro3SingleOnionServiceSuccessCircuitCount
- Rend2MultiHopServiceSuccessCircuitCount
- Intro2MultiHopServiceSuccessCircuitCount
- Rend3MultiHopServiceSuccessCircuitCount
- Intro3MultiHopServiceSuccessCircuitCount
- Rend3ClientSuccessCircuitCount
- Intro3ClientSuccessCircuitCount
- Rend2Tor2WebClientSuccessCircuitCount
- Intro2Tor2WebClientSuccessCircuitCount
- Rend3Tor2WebClientSuccessCircuitCount
- Intro3Tor2WebClientSuccessCircuitCount
- Rend2MultiHopClientSuccessCircuitCount
- Intro2MultiHopClientSuccessCircuitCount
- Rend3MultiHopClientSuccessCircuitCount
- Intro3MultiHopClientSuccessCircuitCount
- Rend3ClientCircuitCount
- Intro3ClientCircuitCount
- Intro2Tor2WebClientCircuitCount
- Rend3Tor2WebClientCircuitCount
- Intro3Tor2WebClientCircuitCount
- Intro2MultiHopClientCircuitCount
- Rend3MultiHopClientCircuitCount
- Intro3MultiHopClientCircuitCount
- HSDir2ServiceCircuitInboundCellCount
- HSDir3ServiceCircuitInboundCellCount
- HSDir2SingleOnionServiceCircuitInboundCellCount
- HSDir3SingleOnionServiceCircuitInboundCellCount
- HSDir2MultiHopServiceCircuitInboundCellCount
- HSDir3MultiHopServiceCircuitInboundCellCount
- HSDir2FailureCircuitInboundCellCount
- HSDir3FailureCircuitInboundCellCount
- MidFailureCircuitInboundCellCount
- EndFailureCircuitInboundCellCount
- HSDir2ServiceFailureCircuitInboundCellCount
- HSDir3ServiceFailureCircuitInboundCellCount
- HSDir2SingleOnionServiceFailureCircuitInboundCellCount
- HSDir3SingleOnionServiceFailureCircuitInboundCellCount
- HSDir2MultiHopServiceFailureCircuitInboundCellCount
- HSDir3MultiHopServiceFailureCircuitInboundCellCount
- OriginFailureCircuitInboundCellCount
- SingleHopFailureCircuitInboundCellCount
- DirFailureCircuitInboundCellCount
- ExitFailureCircuitInboundCellCount
- HSDir2ClientFailureCircuitInboundCellCount
- HSDir3ClientFailureCircuitInboundCellCount
- HSDir2Tor2WebClientFailureCircuitInboundCellCount
- HSDir3Tor2WebClientFailureCircuitInboundCellCount
- HSDir2MultiHopClientFailureCircuitInboundCellCount
- HSDir3MultiHopClientFailureCircuitInboundCellCount
- EntryFailureCircuitInboundCellCount
- HSDir2SuccessCircuitInboundCellCount
- HSDir3SuccessCircuitInboundCellCount
- MidSuccessCircuitInboundCellCount
- EndSuccessCircuitInboundCellCount
- HSDir2ServiceSuccessCircuitInboundCellCount
- HSDir3ServiceSuccessCircuitInboundCellCount
- HSDir2SingleOnionServiceSuccessCircuitInboundCellCount
- HSDir3SingleOnionServiceSuccessCircuitInboundCellCount
- HSDir2MultiHopServiceSuccessCircuitInboundCellCount
- HSDir3MultiHopServiceSuccessCircuitInboundCellCount
- OriginSuccessCircuitInboundCellCount
- SingleHopSuccessCircuitInboundCellCount
- DirSuccessCircuitInboundCellCount
- ExitSuccessCircuitInboundCellCount
- HSDir2ClientSuccessCircuitInboundCellCount
- HSDir3ClientSuccessCircuitInboundCellCount
- HSDir2Tor2WebClientSuccessCircuitInboundCellCount
- HSDir3Tor2WebClientSuccessCircuitInboundCellCount
- HSDir2MultiHopClientSuccessCircuitInboundCellCount
- HSDir3MultiHopClientSuccessCircuitInboundCellCount
- EntrySuccessCircuitInboundCellCount
- HSDir2ClientCircuitInboundCellCount
- HSDir3ClientCircuitInboundCellCount
- HSDir2Tor2WebClientCircuitInboundCellCount
- HSDir3Tor2WebClientCircuitInboundCellCount
- HSDir2MultiHopClientCircuitInboundCellCount
- HSDir3MultiHopClientCircuitInboundCellCount
- HSDir2ServiceCircuitOutboundCellCount
- HSDir3ServiceCircuitOutboundCellCount
- HSDir2SingleOnionServiceCircuitOutboundCellCount
- HSDir3SingleOnionServiceCircuitOutboundCellCount
- HSDir2MultiHopServiceCircuitOutboundCellCount
- HSDir3MultiHopServiceCircuitOutboundCellCount
- HSDir2FailureCircuitOutboundCellCount
- HSDir3FailureCircuitOutboundCellCount
- MidFailureCircuitOutboundCellCount
- EndFailureCircuitOutboundCellCount
- HSDir2ServiceFailureCircuitOutboundCellCount
- HSDir3ServiceFailureCircuitOutboundCellCount
- HSDir2SingleOnionServiceFailureCircuitOutboundCellCount
- HSDir3SingleOnionServiceFailureCircuitOutboundCellCount
- HSDir2MultiHopServiceFailureCircuitOutboundCellCount
- HSDir3MultiHopServiceFailureCircuitOutboundCellCount
- OriginFailureCircuitOutboundCellCount
- SingleHopFailureCircuitOutboundCellCount
- DirFailureCircuitOutboundCellCount
- ExitFailureCircuitOutboundCellCount
- HSDir2ClientFailureCircuitOutboundCellCount
- HSDir3ClientFailureCircuitOutboundCellCount
- HSDir2Tor2WebClientFailureCircuitOutboundCellCount
- HSDir3Tor2WebClientFailureCircuitOutboundCellCount
- HSDir2MultiHopClientFailureCircuitOutboundCellCount
- HSDir3MultiHopClientFailureCircuitOutboundCellCount
- EntryFailureCircuitOutboundCellCount
- HSDir2SuccessCircuitOutboundCellCount
- HSDir3SuccessCircuitOutboundCellCount
- MidSuccessCircuitOutboundCellCount
- EndSuccessCircuitOutboundCellCount
- HSDir2ServiceSuccessCircuitOutboundCellCount
- HSDir3ServiceSuccessCircuitOutboundCellCount
- HSDir2SingleOnionServiceSuccessCircuitOutboundCellCount
- HSDir3SingleOnionServiceSuccessCircuitOutboundCellCount
- HSDir2MultiHopServiceSuccessCircuitOutboundCellCount
- HSDir3MultiHopServiceSuccessCircuitOutboundCellCount
- OriginSuccessCircuitOutboundCellCount
- SingleHopSuccessCircuitOutboundCellCount
- DirSuccessCircuitOutboundCellCount
- ExitSuccessCircuitOutboundCellCount
- HSDir2ClientSuccessCircuitOutboundCellCount
- HSDir3ClientSuccessCircuitOutboundCellCount
- HSDir2Tor2WebClientSuccessCircuitOutboundCellCount
- HSDir3Tor2WebClientSuccessCircuitOutboundCellCount
- HSDir2MultiHopClientSuccessCircuitOutboundCellCount
- HSDir3MultiHopClientSuccessCircuitOutboundCellCount
- EntrySuccessCircuitOutboundCellCount
- HSDir2ClientCircuitOutboundCellCount
- HSDir3ClientCircuitOutboundCellCount
- HSDir2Tor2WebClientCircuitOutboundCellCount
- HSDir3Tor2WebClientCircuitOutboundCellCount
- HSDir2MultiHopClientCircuitOutboundCellCount
- HSDir3MultiHopClientCircuitOutboundCellCount
- HSDir2ServiceCircuitCount
- HSDir3ServiceCircuitCount
- HSDir2SingleOnionServiceCircuitCount
- HSDir3SingleOnionServiceCircuitCount
- HSDir2MultiHopServiceCircuitCount
- HSDir3MultiHopServiceCircuitCount
- HSDir2FailureCircuitCount
- HSDir3FailureCircuitCount
- MidFailureCircuitCount
- EndFailureCircuitCount
- HSDir2ServiceFailureCircuitCount
- HSDir3ServiceFailureCircuitCount
- HSDir2SingleOnionServiceFailureCircuitCount
- HSDir3SingleOnionServiceFailureCircuitCount
- HSDir2MultiHopServiceFailureCircuitCount
- HSDir3MultiHopServiceFailureCircuitCount
- OriginFailureCircuitCount
- SingleHopFailureCircuitCount
- DirFailureCircuitCount
- ExitFailureCircuitCount
- HSDir2ClientFailureCircuitCount
- HSDir3ClientFailureCircuitCount
- HSDir2Tor2WebClientFailureCircuitCount
- HSDir3Tor2WebClientFailureCircuitCount
- HSDir2MultiHopClientFailureCircuitCount
- HSDir3MultiHopClientFailureCircuitCount
- EntryFailureCircuitCount
- HSDir2SuccessCircuitCount
- HSDir3SuccessCircuitCount
- MidSuccessCircuitCount
- EndSuccessCircuitCount
- HSDir2ServiceSuccessCircuitCount
- HSDir3ServiceSuccessCircuitCount
- HSDir2SingleOnionServiceSuccessCircuitCount
- HSDir3SingleOnionServiceSuccessCircuitCount
- HSDir2MultiHopServiceSuccessCircuitCount
- HSDir3MultiHopServiceSuccessCircuitCount
- OriginSuccessCircuitCount
- SingleHopSuccessCircuitCount
- DirSuccessCircuitCount
- ExitSuccessCircuitCount
- HSDir2ClientSuccessCircuitCount
- HSDir3ClientSuccessCircuitCount
- HSDir2Tor2WebClientSuccessCircuitCount
- HSDir3Tor2WebClientSuccessCircuitCount
- HSDir2MultiHopClientSuccessCircuitCount
- HSDir3MultiHopClientSuccessCircuitCount
- EntrySuccessCircuitCount
- HSDir2ClientCircuitCount
- HSDir3ClientCircuitCount
- HSDir2Tor2WebClientCircuitCount
- HSDir3Tor2WebClientCircuitCount
- HSDir2MultiHopClientCircuitCount
- HSDir3MultiHopClientCircuitCount
- Rend2CircuitInboundCellHistogram
- Intro2CircuitInboundCellHistogram
- HSDir2CircuitInboundCellHistogram
- Rend3CircuitInboundCellHistogram
- Intro3CircuitInboundCellHistogram
- HSDir3CircuitInboundCellHistogram
- MidCircuitInboundCellHistogram
- EndCircuitInboundCellHistogram
- Rend2ServiceCircuitInboundCellHistogram
- Intro2ServiceCircuitInboundCellHistogram
- HSDir2ServiceCircuitInboundCellHistogram
- Rend3ServiceCircuitInboundCellHistogram
- Intro3ServiceCircuitInboundCellHistogram
- HSDir3ServiceCircuitInboundCellHistogram
- Rend2SingleOnionServiceCircuitInboundCellHistogram
- Intro2SingleOnionServiceCircuitInboundCellHistogram
- HSDir2SingleOnionServiceCircuitInboundCellHistogram
- Rend3SingleOnionServiceCircuitInboundCellHistogram
- Intro3SingleOnionServiceCircuitInboundCellHistogram
- HSDir3SingleOnionServiceCircuitInboundCellHistogram
- Rend2MultiHopServiceCircuitInboundCellHistogram
- Intro2MultiHopServiceCircuitInboundCellHistogram
- HSDir2MultiHopServiceCircuitInboundCellHistogram
- Rend3MultiHopServiceCircuitInboundCellHistogram
- Intro3MultiHopServiceCircuitInboundCellHistogram
- HSDir3MultiHopServiceCircuitInboundCellHistogram
- Rend2FailureCircuitInboundCellHistogram
- Intro2FailureCircuitInboundCellHistogram
- HSDir2FailureCircuitInboundCellHistogram
- Rend3FailureCircuitInboundCellHistogram
- Intro3FailureCircuitInboundCellHistogram
- HSDir3FailureCircuitInboundCellHistogram
- MidFailureCircuitInboundCellHistogram
- EndFailureCircuitInboundCellHistogram
- Rend2ServiceFailureCircuitInboundCellHistogram
- Intro2ServiceFailureCircuitInboundCellHistogram
- HSDir2ServiceFailureCircuitInboundCellHistogram
- Rend3ServiceFailureCircuitInboundCellHistogram
- Intro3ServiceFailureCircuitInboundCellHistogram
- HSDir3ServiceFailureCircuitInboundCellHistogram
- Rend2SingleOnionServiceFailureCircuitInboundCellHistogram
- Intro2SingleOnionServiceFailureCircuitInboundCellHistogram
- HSDir2SingleOnionServiceFailureCircuitInboundCellHistogram
- Rend3SingleOnionServiceFailureCircuitInboundCellHistogram
- Intro3SingleOnionServiceFailureCircuitInboundCellHistogram
- HSDir3SingleOnionServiceFailureCircuitInboundCellHistogram
- Rend2MultiHopServiceFailureCircuitInboundCellHistogram
- Intro2MultiHopServiceFailureCircuitInboundCellHistogram
- HSDir2MultiHopServiceFailureCircuitInboundCellHistogram
- Rend3MultiHopServiceFailureCircuitInboundCellHistogram
- Intro3MultiHopServiceFailureCircuitInboundCellHistogram
- HSDir3MultiHopServiceFailureCircuitInboundCellHistogram
- OriginFailureCircuitInboundCellHistogram
- SingleHopFailureCircuitInboundCellHistogram
- DirFailureCircuitInboundCellHistogram
- ExitFailureCircuitInboundCellHistogram
- Rend2ClientFailureCircuitInboundCellHistogram
- Intro2ClientFailureCircuitInboundCellHistogram
- HSDir2ClientFailureCircuitInboundCellHistogram
- Rend3ClientFailureCircuitInboundCellHistogram
- Intro3ClientFailureCircuitInboundCellHistogram
- HSDir3ClientFailureCircuitInboundCellHistogram
- Rend2Tor2WebClientFailureCircuitInboundCellHistogram
- Intro2Tor2WebClientFailureCircuitInboundCellHistogram
- HSDir2Tor2WebClientFailureCircuitInboundCellHistogram
- Rend3Tor2WebClientFailureCircuitInboundCellHistogram
- Intro3Tor2WebClientFailureCircuitInboundCellHistogram
- HSDir3Tor2WebClientFailureCircuitInboundCellHistogram
- Rend2MultiHopClientFailureCircuitInboundCellHistogram
- Intro2MultiHopClientFailureCircuitInboundCellHistogram
- HSDir2MultiHopClientFailureCircuitInboundCellHistogram
- Rend3MultiHopClientFailureCircuitInboundCellHistogram
- Intro3MultiHopClientFailureCircuitInboundCellHistogram
- HSDir3MultiHopClientFailureCircuitInboundCellHistogram
- EntryFailureCircuitInboundCellHistogram
- OriginCircuitInboundCellHistogram
- SingleHopCircuitInboundCellHistogram
- DirCircuitInboundCellHistogram
- Rend2SuccessCircuitInboundCellHistogram
- Intro2SuccessCircuitInboundCellHistogram
- HSDir2SuccessCircuitInboundCellHistogram
- Rend3SuccessCircuitInboundCellHistogram
- Intro3SuccessCircuitInboundCellHistogram
- HSDir3SuccessCircuitInboundCellHistogram
- MidSuccessCircuitInboundCellHistogram
- EndSuccessCircuitInboundCellHistogram
- Rend2ServiceSuccessCircuitInboundCellHistogram
- Intro2ServiceSuccessCircuitInboundCellHistogram
- HSDir2ServiceSuccessCircuitInboundCellHistogram
- Rend3ServiceSuccessCircuitInboundCellHistogram
- Intro3ServiceSuccessCircuitInboundCellHistogram
- HSDir3ServiceSuccessCircuitInboundCellHistogram
- Rend2SingleOnionServiceSuccessCircuitInboundCellHistogram
- Intro2SingleOnionServiceSuccessCircuitInboundCellHistogram
- HSDir2SingleOnionServiceSuccessCircuitInboundCellHistogram
- Rend3SingleOnionServiceSuccessCircuitInboundCellHistogram
- Intro3SingleOnionServiceSuccessCircuitInboundCellHistogram
- HSDir3SingleOnionServiceSuccessCircuitInboundCellHistogram
- Rend2MultiHopServiceSuccessCircuitInboundCellHistogram
- Intro2MultiHopServiceSuccessCircuitInboundCellHistogram
- HSDir2MultiHopServiceSuccessCircuitInboundCellHistogram
- Rend3MultiHopServiceSuccessCircuitInboundCellHistogram
- Intro3MultiHopServiceSuccessCircuitInboundCellHistogram
- HSDir3MultiHopServiceSuccessCircuitInboundCellHistogram
- OriginSuccessCircuitInboundCellHistogram
- SingleHopSuccessCircuitInboundCellHistogram
- DirSuccessCircuitInboundCellHistogram
- ExitSuccessCircuitInboundCellHistogram
- Rend2ClientSuccessCircuitInboundCellHistogram
- Intro2ClientSuccessCircuitInboundCellHistogram
- HSDir2ClientSuccessCircuitInboundCellHistogram
- Rend3ClientSuccessCircuitInboundCellHistogram
- Intro3ClientSuccessCircuitInboundCellHistogram
- HSDir3ClientSuccessCircuitInboundCellHistogram
- Rend2Tor2WebClientSuccessCircuitInboundCellHistogram
- Intro2Tor2WebClientSuccessCircuitInboundCellHistogram
- HSDir2Tor2WebClientSuccessCircuitInboundCellHistogram
- Rend3Tor2WebClientSuccessCircuitInboundCellHistogram
- Intro3Tor2WebClientSuccessCircuitInboundCellHistogram
- HSDir3Tor2WebClientSuccessCircuitInboundCellHistogram
- Rend2MultiHopClientSuccessCircuitInboundCellHistogram
- Intro2MultiHopClientSuccessCircuitInboundCellHistogram
- HSDir2MultiHopClientSuccessCircuitInboundCellHistogram
- Rend3MultiHopClientSuccessCircuitInboundCellHistogram
- Intro3MultiHopClientSuccessCircuitInboundCellHistogram
- HSDir3MultiHopClientSuccessCircuitInboundCellHistogram
- EntrySuccessCircuitInboundCellHistogram
- ExitCircuitInboundCellHistogram
- Rend2ClientCircuitInboundCellHistogram
- Intro2ClientCircuitInboundCellHistogram
- HSDir2ClientCircuitInboundCellHistogram
- Rend3ClientCircuitInboundCellHistogram
- Intro3ClientCircuitInboundCellHistogram
- HSDir3ClientCircuitInboundCellHistogram
- Rend2Tor2WebClientCircuitInboundCellHistogram
- Intro2Tor2WebClientCircuitInboundCellHistogram
- HSDir2Tor2WebClientCircuitInboundCellHistogram
- Rend3Tor2WebClientCircuitInboundCellHistogram
- Intro3Tor2WebClientCircuitInboundCellHistogram
- HSDir3Tor2WebClientCircuitInboundCellHistogram
- Rend2MultiHopClientCircuitInboundCellHistogram
- Intro2MultiHopClientCircuitInboundCellHistogram
- HSDir2MultiHopClientCircuitInboundCellHistogram
- Rend3MultiHopClientCircuitInboundCellHistogram
- Intro3MultiHopClientCircuitInboundCellHistogram
- HSDir3MultiHopClientCircuitInboundCellHistogram
- Rend2CircuitOutboundCellHistogram
- Intro2CircuitOutboundCellHistogram
- HSDir2CircuitOutboundCellHistogram
- Rend3CircuitOutboundCellHistogram
- Intro3CircuitOutboundCellHistogram
- HSDir3CircuitOutboundCellHistogram
- MidCircuitOutboundCellHistogram
- EndCircuitOutboundCellHistogram
- Rend2ServiceCircuitOutboundCellHistogram
- Intro2ServiceCircuitOutboundCellHistogram
- HSDir2ServiceCircuitOutboundCellHistogram
- Rend3ServiceCircuitOutboundCellHistogram
- Intro3ServiceCircuitOutboundCellHistogram
- HSDir3ServiceCircuitOutboundCellHistogram
- Rend2SingleOnionServiceCircuitOutboundCellHistogram
- Intro2SingleOnionServiceCircuitOutboundCellHistogram
- HSDir2SingleOnionServiceCircuitOutboundCellHistogram
- Rend3SingleOnionServiceCircuitOutboundCellHistogram
- Intro3SingleOnionServiceCircuitOutboundCellHistogram
- HSDir3SingleOnionServiceCircuitOutboundCellHistogram
- Rend2MultiHopServiceCircuitOutboundCellHistogram
- Intro2MultiHopServiceCircuitOutboundCellHistogram
- HSDir2MultiHopServiceCircuitOutboundCellHistogram
- Rend3MultiHopServiceCircuitOutboundCellHistogram
- Intro3MultiHopServiceCircuitOutboundCellHistogram
- HSDir3MultiHopServiceCircuitOutboundCellHistogram
- Rend2FailureCircuitOutboundCellHistogram
- Intro2FailureCircuitOutboundCellHistogram
- HSDir2FailureCircuitOutboundCellHistogram
- Rend3FailureCircuitOutboundCellHistogram
- Intro3FailureCircuitOutboundCellHistogram
- HSDir3FailureCircuitOutboundCellHistogram
- MidFailureCircuitOutboundCellHistogram
- EndFailureCircuitOutboundCellHistogram
- Rend2ServiceFailureCircuitOutboundCellHistogram
- Intro2ServiceFailureCircuitOutboundCellHistogram
- HSDir2ServiceFailureCircuitOutboundCellHistogram
- Rend3ServiceFailureCircuitOutboundCellHistogram
- Intro3ServiceFailureCircuitOutboundCellHistogram
- HSDir3ServiceFailureCircuitOutboundCellHistogram
- Rend2SingleOnionServiceFailureCircuitOutboundCellHistogram
- Intro2SingleOnionServiceFailureCircuitOutboundCellHistogram
- HSDir2SingleOnionServiceFailureCircuitOutboundCellHistogram
- Rend3SingleOnionServiceFailureCircuitOutboundCellHistogram
- Intro3SingleOnionServiceFailureCircuitOutboundCellHistogram
- HSDir3SingleOnionServiceFailureCircuitOutboundCellHistogram
- Rend2MultiHopServiceFailureCircuitOutboundCellHistogram
- Intro2MultiHopServiceFailureCircuitOutboundCellHistogram
- HSDir2MultiHopServiceFailureCircuitOutboundCellHistogram
- Rend3MultiHopServiceFailureCircuitOutboundCellHistogram
- Intro3MultiHopServiceFailureCircuitOutboundCellHistogram
- HSDir3MultiHopServiceFailureCircuitOutboundCellHistogram
- OriginFailureCircuitOutboundCellHistogram
- SingleHopFailureCircuitOutboundCellHistogram
- DirFailureCircuitOutboundCellHistogram
- ExitFailureCircuitOutboundCellHistogram
- Rend2ClientFailureCircuitOutboundCellHistogram
- Intro2ClientFailureCircuitOutboundCellHistogram
- HSDir2ClientFailureCircuitOutboundCellHistogram
- Rend3ClientFailureCircuitOutboundCellHistogram
- Intro3ClientFailureCircuitOutboundCellHistogram
- HSDir3ClientFailureCircuitOutboundCellHistogram
- Rend2Tor2WebClientFailureCircuitOutboundCellHistogram
- Intro2Tor2WebClientFailureCircuitOutboundCellHistogram
- HSDir2Tor2WebClientFailureCircuitOutboundCellHistogram
- Rend3Tor2WebClientFailureCircuitOutboundCellHistogram
- Intro3Tor2WebClientFailureCircuitOutboundCellHistogram
- HSDir3Tor2WebClientFailureCircuitOutboundCellHistogram
- Rend2MultiHopClientFailureCircuitOutboundCellHistogram
- Intro2MultiHopClientFailureCircuitOutboundCellHistogram
- HSDir2MultiHopClientFailureCircuitOutboundCellHistogram
- Rend3MultiHopClientFailureCircuitOutboundCellHistogram
- Intro3MultiHopClientFailureCircuitOutboundCellHistogram
- HSDir3MultiHopClientFailureCircuitOutboundCellHistogram
- EntryFailureCircuitOutboundCellHistogram
- OriginCircuitOutboundCellHistogram
- SingleHopCircuitOutboundCellHistogram
- DirCircuitOutboundCellHistogram
- Rend2SuccessCircuitOutboundCellHistogram
- Intro2SuccessCircuitOutboundCellHistogram
- HSDir2SuccessCircuitOutboundCellHistogram
- Rend3SuccessCircuitOutboundCellHistogram
- Intro3SuccessCircuitOutboundCellHistogram
- HSDir3SuccessCircuitOutboundCellHistogram
- MidSuccessCircuitOutboundCellHistogram
- EndSuccessCircuitOutboundCellHistogram
- Rend2ServiceSuccessCircuitOutboundCellHistogram
- Intro2ServiceSuccessCircuitOutboundCellHistogram
- HSDir2ServiceSuccessCircuitOutboundCellHistogram
- Rend3ServiceSuccessCircuitOutboundCellHistogram
- Intro3ServiceSuccessCircuitOutboundCellHistogram
- HSDir3ServiceSuccessCircuitOutboundCellHistogram
- Rend2SingleOnionServiceSuccessCircuitOutboundCellHistogram
- Intro2SingleOnionServiceSuccessCircuitOutboundCellHistogram
- HSDir2SingleOnionServiceSuccessCircuitOutboundCellHistogram
- Rend3SingleOnionServiceSuccessCircuitOutboundCellHistogram
- Intro3SingleOnionServiceSuccessCircuitOutboundCellHistogram
- HSDir3SingleOnionServiceSuccessCircuitOutboundCellHistogram
- Rend2MultiHopServiceSuccessCircuitOutboundCellHistogram
- Intro2MultiHopServiceSuccessCircuitOutboundCellHistogram
- HSDir2MultiHopServiceSuccessCircuitOutboundCellHistogram
- Rend3MultiHopServiceSuccessCircuitOutboundCellHistogram
- Intro3MultiHopServiceSuccessCircuitOutboundCellHistogram
- HSDir3MultiHopServiceSuccessCircuitOutboundCellHistogram
- OriginSuccessCircuitOutboundCellHistogram
- SingleHopSuccessCircuitOutboundCellHistogram
- DirSuccessCircuitOutboundCellHistogram
- ExitSuccessCircuitOutboundCellHistogram
- Rend2ClientSuccessCircuitOutboundCellHistogram
- Intro2ClientSuccessCircuitOutboundCellHistogram
- HSDir2ClientSuccessCircuitOutboundCellHistogram
- Rend3ClientSuccessCircuitOutboundCellHistogram
- Intro3ClientSuccessCircuitOutboundCellHistogram
- HSDir3ClientSuccessCircuitOutboundCellHistogram
- Rend2Tor2WebClientSuccessCircuitOutboundCellHistogram
- Intro2Tor2WebClientSuccessCircuitOutboundCellHistogram
- HSDir2Tor2WebClientSuccessCircuitOutboundCellHistogram
- Rend3Tor2WebClientSuccessCircuitOutboundCellHistogram
- Intro3Tor2WebClientSuccessCircuitOutboundCellHistogram
- HSDir3Tor2WebClientSuccessCircuitOutboundCellHistogram
- Rend2MultiHopClientSuccessCircuitOutboundCellHistogram
- Intro2MultiHopClientSuccessCircuitOutboundCellHistogram
- HSDir2MultiHopClientSuccessCircuitOutboundCellHistogram
- Rend3MultiHopClientSuccessCircuitOutboundCellHistogram
- Intro3MultiHopClientSuccessCircuitOutboundCellHistogram
- HSDir3MultiHopClientSuccessCircuitOutboundCellHistogram
- EntrySuccessCircuitOutboundCellHistogram
- ExitCircuitOutboundCellHistogram
- Rend2ClientCircuitOutboundCellHistogram
- Intro2ClientCircuitOutboundCellHistogram
- HSDir2ClientCircuitOutboundCellHistogram
- Rend3ClientCircuitOutboundCellHistogram
- Intro3ClientCircuitOutboundCellHistogram
- HSDir3ClientCircuitOutboundCellHistogram
- Rend2Tor2WebClientCircuitOutboundCellHistogram
- Intro2Tor2WebClientCircuitOutboundCellHistogram
- HSDir2Tor2WebClientCircuitOutboundCellHistogram
- Rend3Tor2WebClientCircuitOutboundCellHistogram
- Intro3Tor2WebClientCircuitOutboundCellHistogram
- HSDir3Tor2WebClientCircuitOutboundCellHistogram
- Rend2MultiHopClientCircuitOutboundCellHistogram
- Intro2MultiHopClientCircuitOutboundCellHistogram
- HSDir2MultiHopClientCircuitOutboundCellHistogram
- Rend3MultiHopClientCircuitOutboundCellHistogram
- Intro3MultiHopClientCircuitOutboundCellHistogram
- HSDir3MultiHopClientCircuitOutboundCellHistogram
- Rend2ActiveFailureCircuitInboundCellHistogram
- Intro2ActiveFailureCircuitInboundCellHistogram
- HSDir2ActiveFailureCircuitInboundCellHistogram
- Rend3ActiveFailureCircuitInboundCellHistogram
- Intro3ActiveFailureCircuitInboundCellHistogram
- HSDir3ActiveFailureCircuitInboundCellHistogram
- MidActiveFailureCircuitInboundCellHistogram
- EndActiveFailureCircuitInboundCellHistogram
- Rend2ServiceActiveFailureCircuitInboundCellHistogram
- Intro2ServiceActiveFailureCircuitInboundCellHistogram
- HSDir2ServiceActiveFailureCircuitInboundCellHistogram
- Rend3ServiceActiveFailureCircuitInboundCellHistogram
- Intro3ServiceActiveFailureCircuitInboundCellHistogram
- HSDir3ServiceActiveFailureCircuitInboundCellHistogram
- Rend2SingleOnionServiceActiveFailureCircuitInboundCellHistogram
- Intro2SingleOnionServiceActiveFailureCircuitInboundCellHistogram
- HSDir2SingleOnionServiceActiveFailureCircuitInboundCellHistogram
- Rend3SingleOnionServiceActiveFailureCircuitInboundCellHistogram
- Intro3SingleOnionServiceActiveFailureCircuitInboundCellHistogram
- HSDir3SingleOnionServiceActiveFailureCircuitInboundCellHistogram
- Rend2MultiHopServiceActiveFailureCircuitInboundCellHistogram
- Intro2MultiHopServiceActiveFailureCircuitInboundCellHistogram
- HSDir2MultiHopServiceActiveFailureCircuitInboundCellHistogram
- Rend3MultiHopServiceActiveFailureCircuitInboundCellHistogram
- Intro3MultiHopServiceActiveFailureCircuitInboundCellHistogram
- HSDir3MultiHopServiceActiveFailureCircuitInboundCellHistogram
- OriginActiveFailureCircuitInboundCellHistogram
- SingleHopActiveFailureCircuitInboundCellHistogram
- DirActiveFailureCircuitInboundCellHistogram
- Rend2ClientActiveFailureCircuitInboundCellHistogram
- Intro2ClientActiveFailureCircuitInboundCellHistogram
- HSDir2ClientActiveFailureCircuitInboundCellHistogram
- Rend3ClientActiveFailureCircuitInboundCellHistogram
- Intro3ClientActiveFailureCircuitInboundCellHistogram
- HSDir3ClientActiveFailureCircuitInboundCellHistogram
- Rend2Tor2WebClientActiveFailureCircuitInboundCellHistogram
- Intro2Tor2WebClientActiveFailureCircuitInboundCellHistogram
- HSDir2Tor2WebClientActiveFailureCircuitInboundCellHistogram
- Rend3Tor2WebClientActiveFailureCircuitInboundCellHistogram
- Intro3Tor2WebClientActiveFailureCircuitInboundCellHistogram
- HSDir3Tor2WebClientActiveFailureCircuitInboundCellHistogram
- Rend2MultiHopClientActiveFailureCircuitInboundCellHistogram
- Intro2MultiHopClientActiveFailureCircuitInboundCellHistogram
- HSDir2MultiHopClientActiveFailureCircuitInboundCellHistogram
- Rend3MultiHopClientActiveFailureCircuitInboundCellHistogram
- Intro3MultiHopClientActiveFailureCircuitInboundCellHistogram
- HSDir3MultiHopClientActiveFailureCircuitInboundCellHistogram
- EntryActiveFailureCircuitInboundCellHistogram
- Rend2InactiveFailureCircuitInboundCellHistogram
- Intro2InactiveFailureCircuitInboundCellHistogram
- HSDir2InactiveFailureCircuitInboundCellHistogram
- Rend3InactiveFailureCircuitInboundCellHistogram
- Intro3InactiveFailureCircuitInboundCellHistogram
- HSDir3InactiveFailureCircuitInboundCellHistogram
- MidInactiveFailureCircuitInboundCellHistogram
- EndInactiveFailureCircuitInboundCellHistogram
- Rend2ServiceInactiveFailureCircuitInboundCellHistogram
- Intro2ServiceInactiveFailureCircuitInboundCellHistogram
- HSDir2ServiceInactiveFailureCircuitInboundCellHistogram
- Rend3ServiceInactiveFailureCircuitInboundCellHistogram
- Intro3ServiceInactiveFailureCircuitInboundCellHistogram
- HSDir3ServiceInactiveFailureCircuitInboundCellHistogram
- Rend2SingleOnionServiceInactiveFailureCircuitInboundCellHistogram
- Intro2SingleOnionServiceInactiveFailureCircuitInboundCellHistogram
- HSDir2SingleOnionServiceInactiveFailureCircuitInboundCellHistogram
- Rend3SingleOnionServiceInactiveFailureCircuitInboundCellHistogram
- Intro3SingleOnionServiceInactiveFailureCircuitInboundCellHistogram
- HSDir3SingleOnionServiceInactiveFailureCircuitInboundCellHistogram
- Rend2MultiHopServiceInactiveFailureCircuitInboundCellHistogram
- Intro2MultiHopServiceInactiveFailureCircuitInboundCellHistogram
- HSDir2MultiHopServiceInactiveFailureCircuitInboundCellHistogram
- Rend3MultiHopServiceInactiveFailureCircuitInboundCellHistogram
- Intro3MultiHopServiceInactiveFailureCircuitInboundCellHistogram
- HSDir3MultiHopServiceInactiveFailureCircuitInboundCellHistogram
- OriginInactiveFailureCircuitInboundCellHistogram
- SingleHopInactiveFailureCircuitInboundCellHistogram
- DirInactiveFailureCircuitInboundCellHistogram
- Rend2ClientInactiveFailureCircuitInboundCellHistogram
- Intro2ClientInactiveFailureCircuitInboundCellHistogram
- HSDir2ClientInactiveFailureCircuitInboundCellHistogram
- Rend3ClientInactiveFailureCircuitInboundCellHistogram
- Intro3ClientInactiveFailureCircuitInboundCellHistogram
- HSDir3ClientInactiveFailureCircuitInboundCellHistogram
- Rend2Tor2WebClientInactiveFailureCircuitInboundCellHistogram
- Intro2Tor2WebClientInactiveFailureCircuitInboundCellHistogram
- HSDir2Tor2WebClientInactiveFailureCircuitInboundCellHistogram
- Rend3Tor2WebClientInactiveFailureCircuitInboundCellHistogram
- Intro3Tor2WebClientInactiveFailureCircuitInboundCellHistogram
- HSDir3Tor2WebClientInactiveFailureCircuitInboundCellHistogram
- Rend2MultiHopClientInactiveFailureCircuitInboundCellHistogram
- Intro2MultiHopClientInactiveFailureCircuitInboundCellHistogram
- HSDir2MultiHopClientInactiveFailureCircuitInboundCellHistogram
- Rend3MultiHopClientInactiveFailureCircuitInboundCellHistogram
- Intro3MultiHopClientInactiveFailureCircuitInboundCellHistogram
- HSDir3MultiHopClientInactiveFailureCircuitInboundCellHistogram
- EntryInactiveFailureCircuitInboundCellHistogram
- Rend2ActiveCircuitInboundCellHistogram
- Intro2ActiveCircuitInboundCellHistogram
- HSDir2ActiveCircuitInboundCellHistogram
- Rend3ActiveCircuitInboundCellHistogram
- Intro3ActiveCircuitInboundCellHistogram
- HSDir3ActiveCircuitInboundCellHistogram
- MidActiveCircuitInboundCellHistogram
- EndActiveCircuitInboundCellHistogram
- Rend2ServiceActiveCircuitInboundCellHistogram
- Intro2ServiceActiveCircuitInboundCellHistogram
- HSDir2ServiceActiveCircuitInboundCellHistogram
- Rend3ServiceActiveCircuitInboundCellHistogram
- Intro3ServiceActiveCircuitInboundCellHistogram
- HSDir3ServiceActiveCircuitInboundCellHistogram
- Rend2SingleOnionServiceActiveCircuitInboundCellHistogram
- Intro2SingleOnionServiceActiveCircuitInboundCellHistogram
- HSDir2SingleOnionServiceActiveCircuitInboundCellHistogram
- Rend3SingleOnionServiceActiveCircuitInboundCellHistogram
- Intro3SingleOnionServiceActiveCircuitInboundCellHistogram
- HSDir3SingleOnionServiceActiveCircuitInboundCellHistogram
- Rend2MultiHopServiceActiveCircuitInboundCellHistogram
- Intro2MultiHopServiceActiveCircuitInboundCellHistogram
- HSDir2MultiHopServiceActiveCircuitInboundCellHistogram
- Rend3MultiHopServiceActiveCircuitInboundCellHistogram
- Intro3MultiHopServiceActiveCircuitInboundCellHistogram
- HSDir3MultiHopServiceActiveCircuitInboundCellHistogram
- OriginActiveCircuitInboundCellHistogram
- SingleHopActiveCircuitInboundCellHistogram
- DirActiveCircuitInboundCellHistogram
- Rend2ClientActiveCircuitInboundCellHistogram
- Intro2ClientActiveCircuitInboundCellHistogram
- HSDir2ClientActiveCircuitInboundCellHistogram
- Rend3ClientActiveCircuitInboundCellHistogram
- Intro3ClientActiveCircuitInboundCellHistogram
- HSDir3ClientActiveCircuitInboundCellHistogram
- Rend2Tor2WebClientActiveCircuitInboundCellHistogram
- Intro2Tor2WebClientActiveCircuitInboundCellHistogram
- HSDir2Tor2WebClientActiveCircuitInboundCellHistogram
- Rend3Tor2WebClientActiveCircuitInboundCellHistogram
- Intro3Tor2WebClientActiveCircuitInboundCellHistogram
- HSDir3Tor2WebClientActiveCircuitInboundCellHistogram
- Rend2MultiHopClientActiveCircuitInboundCellHistogram
- Intro2MultiHopClientActiveCircuitInboundCellHistogram
- HSDir2MultiHopClientActiveCircuitInboundCellHistogram
- Rend3MultiHopClientActiveCircuitInboundCellHistogram
- Intro3MultiHopClientActiveCircuitInboundCellHistogram
- HSDir3MultiHopClientActiveCircuitInboundCellHistogram
- EntryActiveCircuitInboundCellHistogram
- Rend2InactiveCircuitInboundCellHistogram
- Intro2InactiveCircuitInboundCellHistogram
- HSDir2InactiveCircuitInboundCellHistogram
- Rend3InactiveCircuitInboundCellHistogram
- Intro3InactiveCircuitInboundCellHistogram
- HSDir3InactiveCircuitInboundCellHistogram
- MidInactiveCircuitInboundCellHistogram
- EndInactiveCircuitInboundCellHistogram
- Rend2ServiceInactiveCircuitInboundCellHistogram
- Intro2ServiceInactiveCircuitInboundCellHistogram
- HSDir2ServiceInactiveCircuitInboundCellHistogram
- Rend3ServiceInactiveCircuitInboundCellHistogram
- Intro3ServiceInactiveCircuitInboundCellHistogram
- HSDir3ServiceInactiveCircuitInboundCellHistogram
- Rend2SingleOnionServiceInactiveCircuitInboundCellHistogram
- Intro2SingleOnionServiceInactiveCircuitInboundCellHistogram
- HSDir2SingleOnionServiceInactiveCircuitInboundCellHistogram
- Rend3SingleOnionServiceInactiveCircuitInboundCellHistogram
- Intro3SingleOnionServiceInactiveCircuitInboundCellHistogram
- HSDir3SingleOnionServiceInactiveCircuitInboundCellHistogram
- Rend2MultiHopServiceInactiveCircuitInboundCellHistogram
- Intro2MultiHopServiceInactiveCircuitInboundCellHistogram
- HSDir2MultiHopServiceInactiveCircuitInboundCellHistogram
- Rend3MultiHopServiceInactiveCircuitInboundCellHistogram
- Intro3MultiHopServiceInactiveCircuitInboundCellHistogram
- HSDir3MultiHopServiceInactiveCircuitInboundCellHistogram
- OriginInactiveCircuitInboundCellHistogram
- SingleHopInactiveCircuitInboundCellHistogram
- DirInactiveCircuitInboundCellHistogram
- Rend2ClientInactiveCircuitInboundCellHistogram
- Intro2ClientInactiveCircuitInboundCellHistogram
- HSDir2ClientInactiveCircuitInboundCellHistogram
- Rend3ClientInactiveCircuitInboundCellHistogram
- Intro3ClientInactiveCircuitInboundCellHistogram
- HSDir3ClientInactiveCircuitInboundCellHistogram
- Rend2Tor2WebClientInactiveCircuitInboundCellHistogram
- Intro2Tor2WebClientInactiveCircuitInboundCellHistogram
- HSDir2Tor2WebClientInactiveCircuitInboundCellHistogram
- Rend3Tor2WebClientInactiveCircuitInboundCellHistogram
- Intro3Tor2WebClientInactiveCircuitInboundCellHistogram
- HSDir3Tor2WebClientInactiveCircuitInboundCellHistogram
- Rend2MultiHopClientInactiveCircuitInboundCellHistogram
- Intro2MultiHopClientInactiveCircuitInboundCellHistogram
- HSDir2MultiHopClientInactiveCircuitInboundCellHistogram
- Rend3MultiHopClientInactiveCircuitInboundCellHistogram
- Intro3MultiHopClientInactiveCircuitInboundCellHistogram
- HSDir3MultiHopClientInactiveCircuitInboundCellHistogram
- EntryInactiveCircuitInboundCellHistogram
- Rend2ActiveSuccessCircuitInboundCellHistogram
- Intro2ActiveSuccessCircuitInboundCellHistogram
- HSDir2ActiveSuccessCircuitInboundCellHistogram
- Rend3ActiveSuccessCircuitInboundCellHistogram
- Intro3ActiveSuccessCircuitInboundCellHistogram
- HSDir3ActiveSuccessCircuitInboundCellHistogram
- MidActiveSuccessCircuitInboundCellHistogram
- EndActiveSuccessCircuitInboundCellHistogram
- Rend2ServiceActiveSuccessCircuitInboundCellHistogram
- Intro2ServiceActiveSuccessCircuitInboundCellHistogram
- HSDir2ServiceActiveSuccessCircuitInboundCellHistogram
- Rend3ServiceActiveSuccessCircuitInboundCellHistogram
- Intro3ServiceActiveSuccessCircuitInboundCellHistogram
- HSDir3ServiceActiveSuccessCircuitInboundCellHistogram
- Rend2SingleOnionServiceActiveSuccessCircuitInboundCellHistogram
- Intro2SingleOnionServiceActiveSuccessCircuitInboundCellHistogram
- HSDir2SingleOnionServiceActiveSuccessCircuitInboundCellHistogram
- Rend3SingleOnionServiceActiveSuccessCircuitInboundCellHistogram
- Intro3SingleOnionServiceActiveSuccessCircuitInboundCellHistogram
- HSDir3SingleOnionServiceActiveSuccessCircuitInboundCellHistogram
- Rend2MultiHopServiceActiveSuccessCircuitInboundCellHistogram
- Intro2MultiHopServiceActiveSuccessCircuitInboundCellHistogram
- HSDir2MultiHopServiceActiveSuccessCircuitInboundCellHistogram
- Rend3MultiHopServiceActiveSuccessCircuitInboundCellHistogram
- Intro3MultiHopServiceActiveSuccessCircuitInboundCellHistogram
- HSDir3MultiHopServiceActiveSuccessCircuitInboundCellHistogram
- OriginActiveSuccessCircuitInboundCellHistogram
- SingleHopActiveSuccessCircuitInboundCellHistogram
- DirActiveSuccessCircuitInboundCellHistogram
- Rend2ClientActiveSuccessCircuitInboundCellHistogram
- Intro2ClientActiveSuccessCircuitInboundCellHistogram
- HSDir2ClientActiveSuccessCircuitInboundCellHistogram
- Rend3ClientActiveSuccessCircuitInboundCellHistogram
- Intro3ClientActiveSuccessCircuitInboundCellHistogram
- HSDir3ClientActiveSuccessCircuitInboundCellHistogram
- Rend2Tor2WebClientActiveSuccessCircuitInboundCellHistogram
- Intro2Tor2WebClientActiveSuccessCircuitInboundCellHistogram
- HSDir2Tor2WebClientActiveSuccessCircuitInboundCellHistogram
- Rend3Tor2WebClientActiveSuccessCircuitInboundCellHistogram
- Intro3Tor2WebClientActiveSuccessCircuitInboundCellHistogram
- HSDir3Tor2WebClientActiveSuccessCircuitInboundCellHistogram
- Rend2MultiHopClientActiveSuccessCircuitInboundCellHistogram
- Intro2MultiHopClientActiveSuccessCircuitInboundCellHistogram
- HSDir2MultiHopClientActiveSuccessCircuitInboundCellHistogram
- Rend3MultiHopClientActiveSuccessCircuitInboundCellHistogram
- Intro3MultiHopClientActiveSuccessCircuitInboundCellHistogram
- HSDir3MultiHopClientActiveSuccessCircuitInboundCellHistogram
- EntryActiveSuccessCircuitInboundCellHistogram
- Rend2InactiveSuccessCircuitInboundCellHistogram
- Intro2InactiveSuccessCircuitInboundCellHistogram
- HSDir2InactiveSuccessCircuitInboundCellHistogram
- Rend3InactiveSuccessCircuitInboundCellHistogram
- Intro3InactiveSuccessCircuitInboundCellHistogram
- HSDir3InactiveSuccessCircuitInboundCellHistogram
- MidInactiveSuccessCircuitInboundCellHistogram
- EndInactiveSuccessCircuitInboundCellHistogram
- Rend2ServiceInactiveSuccessCircuitInboundCellHistogram
- Intro2ServiceInactiveSuccessCircuitInboundCellHistogram
- HSDir2ServiceInactiveSuccessCircuitInboundCellHistogram
- Rend3ServiceInactiveSuccessCircuitInboundCellHistogram
- Intro3ServiceInactiveSuccessCircuitInboundCellHistogram
- HSDir3ServiceInactiveSuccessCircuitInboundCellHistogram
- Rend2SingleOnionServiceInactiveSuccessCircuitInboundCellHistogram
- Intro2SingleOnionServiceInactiveSuccessCircuitInboundCellHistogram
- HSDir2SingleOnionServiceInactiveSuccessCircuitInboundCellHistogram
- Rend3SingleOnionServiceInactiveSuccessCircuitInboundCellHistogram
- Intro3SingleOnionServiceInactiveSuccessCircuitInboundCellHistogram
- HSDir3SingleOnionServiceInactiveSuccessCircuitInboundCellHistogram
- Rend2MultiHopServiceInactiveSuccessCircuitInboundCellHistogram
- Intro2MultiHopServiceInactiveSuccessCircuitInboundCellHistogram
- HSDir2MultiHopServiceInactiveSuccessCircuitInboundCellHistogram
- Rend3MultiHopServiceInactiveSuccessCircuitInboundCellHistogram
- Intro3MultiHopServiceInactiveSuccessCircuitInboundCellHistogram
- HSDir3MultiHopServiceInactiveSuccessCircuitInboundCellHistogram
- OriginInactiveSuccessCircuitInboundCellHistogram
- SingleHopInactiveSuccessCircuitInboundCellHistogram
- DirInactiveSuccessCircuitInboundCellHistogram
- Rend2ClientInactiveSuccessCircuitInboundCellHistogram
- Intro2ClientInactiveSuccessCircuitInboundCellHistogram
- HSDir2ClientInactiveSuccessCircuitInboundCellHistogram
- Rend3ClientInactiveSuccessCircuitInboundCellHistogram
- Intro3ClientInactiveSuccessCircuitInboundCellHistogram
- HSDir3ClientInactiveSuccessCircuitInboundCellHistogram
- Rend2Tor2WebClientInactiveSuccessCircuitInboundCellHistogram
- Intro2Tor2WebClientInactiveSuccessCircuitInboundCellHistogram
- HSDir2Tor2WebClientInactiveSuccessCircuitInboundCellHistogram
- Rend3Tor2WebClientInactiveSuccessCircuitInboundCellHistogram
- Intro3Tor2WebClientInactiveSuccessCircuitInboundCellHistogram
- HSDir3Tor2WebClientInactiveSuccessCircuitInboundCellHistogram
- Rend2MultiHopClientInactiveSuccessCircuitInboundCellHistogram
- Intro2MultiHopClientInactiveSuccessCircuitInboundCellHistogram
- HSDir2MultiHopClientInactiveSuccessCircuitInboundCellHistogram
- Rend3MultiHopClientInactiveSuccessCircuitInboundCellHistogram
- Intro3MultiHopClientInactiveSuccessCircuitInboundCellHistogram
- HSDir3MultiHopClientInactiveSuccessCircuitInboundCellHistogram
- EntryInactiveSuccessCircuitInboundCellHistogram
- Rend2ActiveFailureCircuitOutboundCellHistogram
- Intro2ActiveFailureCircuitOutboundCellHistogram
- HSDir2ActiveFailureCircuitOutboundCellHistogram
- Rend3ActiveFailureCircuitOutboundCellHistogram
- Intro3ActiveFailureCircuitOutboundCellHistogram
- HSDir3ActiveFailureCircuitOutboundCellHistogram
- MidActiveFailureCircuitOutboundCellHistogram
- EndActiveFailureCircuitOutboundCellHistogram
- Rend2ServiceActiveFailureCircuitOutboundCellHistogram
- Intro2ServiceActiveFailureCircuitOutboundCellHistogram
- HSDir2ServiceActiveFailureCircuitOutboundCellHistogram
- Rend3ServiceActiveFailureCircuitOutboundCellHistogram
- Intro3ServiceActiveFailureCircuitOutboundCellHistogram
- HSDir3ServiceActiveFailureCircuitOutboundCellHistogram
- Rend2SingleOnionServiceActiveFailureCircuitOutboundCellHistogram
- Intro2SingleOnionServiceActiveFailureCircuitOutboundCellHistogram
- HSDir2SingleOnionServiceActiveFailureCircuitOutboundCellHistogram
- Rend3SingleOnionServiceActiveFailureCircuitOutboundCellHistogram
- Intro3SingleOnionServiceActiveFailureCircuitOutboundCellHistogram
- HSDir3SingleOnionServiceActiveFailureCircuitOutboundCellHistogram
- Rend2MultiHopServiceActiveFailureCircuitOutboundCellHistogram
- Intro2MultiHopServiceActiveFailureCircuitOutboundCellHistogram
- HSDir2MultiHopServiceActiveFailureCircuitOutboundCellHistogram
- Rend3MultiHopServiceActiveFailureCircuitOutboundCellHistogram
- Intro3MultiHopServiceActiveFailureCircuitOutboundCellHistogram
- HSDir3MultiHopServiceActiveFailureCircuitOutboundCellHistogram
- OriginActiveFailureCircuitOutboundCellHistogram
- SingleHopActiveFailureCircuitOutboundCellHistogram
- DirActiveFailureCircuitOutboundCellHistogram
- Rend2ClientActiveFailureCircuitOutboundCellHistogram
- Intro2ClientActiveFailureCircuitOutboundCellHistogram
- HSDir2ClientActiveFailureCircuitOutboundCellHistogram
- Rend3ClientActiveFailureCircuitOutboundCellHistogram
- Intro3ClientActiveFailureCircuitOutboundCellHistogram
- HSDir3ClientActiveFailureCircuitOutboundCellHistogram
- Rend2Tor2WebClientActiveFailureCircuitOutboundCellHistogram
- Intro2Tor2WebClientActiveFailureCircuitOutboundCellHistogram
- HSDir2Tor2WebClientActiveFailureCircuitOutboundCellHistogram
- Rend3Tor2WebClientActiveFailureCircuitOutboundCellHistogram
- Intro3Tor2WebClientActiveFailureCircuitOutboundCellHistogram
- HSDir3Tor2WebClientActiveFailureCircuitOutboundCellHistogram
- Rend2MultiHopClientActiveFailureCircuitOutboundCellHistogram
- Intro2MultiHopClientActiveFailureCircuitOutboundCellHistogram
- HSDir2MultiHopClientActiveFailureCircuitOutboundCellHistogram
- Rend3MultiHopClientActiveFailureCircuitOutboundCellHistogram
- Intro3MultiHopClientActiveFailureCircuitOutboundCellHistogram
- HSDir3MultiHopClientActiveFailureCircuitOutboundCellHistogram
- EntryActiveFailureCircuitOutboundCellHistogram
- Rend2InactiveFailureCircuitOutboundCellHistogram
- Intro2InactiveFailureCircuitOutboundCellHistogram
- HSDir2InactiveFailureCircuitOutboundCellHistogram
- Rend3InactiveFailureCircuitOutboundCellHistogram
- Intro3InactiveFailureCircuitOutboundCellHistogram
- HSDir3InactiveFailureCircuitOutboundCellHistogram
- MidInactiveFailureCircuitOutboundCellHistogram
- EndInactiveFailureCircuitOutboundCellHistogram
- Rend2ServiceInactiveFailureCircuitOutboundCellHistogram
- Intro2ServiceInactiveFailureCircuitOutboundCellHistogram
- HSDir2ServiceInactiveFailureCircuitOutboundCellHistogram
- Rend3ServiceInactiveFailureCircuitOutboundCellHistogram
- Intro3ServiceInactiveFailureCircuitOutboundCellHistogram
- HSDir3ServiceInactiveFailureCircuitOutboundCellHistogram
- Rend2SingleOnionServiceInactiveFailureCircuitOutboundCellHistogram
- Intro2SingleOnionServiceInactiveFailureCircuitOutboundCellHistogram
- HSDir2SingleOnionServiceInactiveFailureCircuitOutboundCellHistogram
- Rend3SingleOnionServiceInactiveFailureCircuitOutboundCellHistogram
- Intro3SingleOnionServiceInactiveFailureCircuitOutboundCellHistogram
- HSDir3SingleOnionServiceInactiveFailureCircuitOutboundCellHistogram
- Rend2MultiHopServiceInactiveFailureCircuitOutboundCellHistogram
- Intro2MultiHopServiceInactiveFailureCircuitOutboundCellHistogram
- HSDir2MultiHopServiceInactiveFailureCircuitOutboundCellHistogram
- Rend3MultiHopServiceInactiveFailureCircuitOutboundCellHistogram
- Intro3MultiHopServiceInactiveFailureCircuitOutboundCellHistogram
- HSDir3MultiHopServiceInactiveFailureCircuitOutboundCellHistogram
- OriginInactiveFailureCircuitOutboundCellHistogram
- SingleHopInactiveFailureCircuitOutboundCellHistogram
- DirInactiveFailureCircuitOutboundCellHistogram
- Rend2ClientInactiveFailureCircuitOutboundCellHistogram
- Intro2ClientInactiveFailureCircuitOutboundCellHistogram
- HSDir2ClientInactiveFailureCircuitOutboundCellHistogram
- Rend3ClientInactiveFailureCircuitOutboundCellHistogram
- Intro3ClientInactiveFailureCircuitOutboundCellHistogram
- HSDir3ClientInactiveFailureCircuitOutboundCellHistogram
- Rend2Tor2WebClientInactiveFailureCircuitOutboundCellHistogram
- Intro2Tor2WebClientInactiveFailureCircuitOutboundCellHistogram
- HSDir2Tor2WebClientInactiveFailureCircuitOutboundCellHistogram
- Rend3Tor2WebClientInactiveFailureCircuitOutboundCellHistogram
- Intro3Tor2WebClientInactiveFailureCircuitOutboundCellHistogram
- HSDir3Tor2WebClientInactiveFailureCircuitOutboundCellHistogram
- Rend2MultiHopClientInactiveFailureCircuitOutboundCellHistogram
- Intro2MultiHopClientInactiveFailureCircuitOutboundCellHistogram
- HSDir2MultiHopClientInactiveFailureCircuitOutboundCellHistogram
- Rend3MultiHopClientInactiveFailureCircuitOutboundCellHistogram
- Intro3MultiHopClientInactiveFailureCircuitOutboundCellHistogram
- HSDir3MultiHopClientInactiveFailureCircuitOutboundCellHistogram
- EntryInactiveFailureCircuitOutboundCellHistogram
- Rend2ActiveCircuitOutboundCellHistogram
- Intro2ActiveCircuitOutboundCellHistogram
- HSDir2ActiveCircuitOutboundCellHistogram
- Rend3ActiveCircuitOutboundCellHistogram
- Intro3ActiveCircuitOutboundCellHistogram
- HSDir3ActiveCircuitOutboundCellHistogram
- MidActiveCircuitOutboundCellHistogram
- EndActiveCircuitOutboundCellHistogram
- Rend2ServiceActiveCircuitOutboundCellHistogram
- Intro2ServiceActiveCircuitOutboundCellHistogram
- HSDir2ServiceActiveCircuitOutboundCellHistogram
- Rend3ServiceActiveCircuitOutboundCellHistogram
- Intro3ServiceActiveCircuitOutboundCellHistogram
- HSDir3ServiceActiveCircuitOutboundCellHistogram
- Rend2SingleOnionServiceActiveCircuitOutboundCellHistogram
- Intro2SingleOnionServiceActiveCircuitOutboundCellHistogram
- HSDir2SingleOnionServiceActiveCircuitOutboundCellHistogram
- Rend3SingleOnionServiceActiveCircuitOutboundCellHistogram
- Intro3SingleOnionServiceActiveCircuitOutboundCellHistogram
- HSDir3SingleOnionServiceActiveCircuitOutboundCellHistogram
- Rend2MultiHopServiceActiveCircuitOutboundCellHistogram
- Intro2MultiHopServiceActiveCircuitOutboundCellHistogram
- HSDir2MultiHopServiceActiveCircuitOutboundCellHistogram
- Rend3MultiHopServiceActiveCircuitOutboundCellHistogram
- Intro3MultiHopServiceActiveCircuitOutboundCellHistogram
- HSDir3MultiHopServiceActiveCircuitOutboundCellHistogram
- OriginActiveCircuitOutboundCellHistogram
- SingleHopActiveCircuitOutboundCellHistogram
- DirActiveCircuitOutboundCellHistogram
- Rend2ClientActiveCircuitOutboundCellHistogram
- Intro2ClientActiveCircuitOutboundCellHistogram
- HSDir2ClientActiveCircuitOutboundCellHistogram
- Rend3ClientActiveCircuitOutboundCellHistogram
- Intro3ClientActiveCircuitOutboundCellHistogram
- HSDir3ClientActiveCircuitOutboundCellHistogram
- Rend2Tor2WebClientActiveCircuitOutboundCellHistogram
- Intro2Tor2WebClientActiveCircuitOutboundCellHistogram
- HSDir2Tor2WebClientActiveCircuitOutboundCellHistogram
- Rend3Tor2WebClientActiveCircuitOutboundCellHistogram
- Intro3Tor2WebClientActiveCircuitOutboundCellHistogram
- HSDir3Tor2WebClientActiveCircuitOutboundCellHistogram
- Rend2MultiHopClientActiveCircuitOutboundCellHistogram
- Intro2MultiHopClientActiveCircuitOutboundCellHistogram
- HSDir2MultiHopClientActiveCircuitOutboundCellHistogram
- Rend3MultiHopClientActiveCircuitOutboundCellHistogram
- Intro3MultiHopClientActiveCircuitOutboundCellHistogram
- HSDir3MultiHopClientActiveCircuitOutboundCellHistogram
- EntryActiveCircuitOutboundCellHistogram
- Rend2InactiveCircuitOutboundCellHistogram
- Intro2InactiveCircuitOutboundCellHistogram
- HSDir2InactiveCircuitOutboundCellHistogram
- Rend3InactiveCircuitOutboundCellHistogram
- Intro3InactiveCircuitOutboundCellHistogram
- HSDir3InactiveCircuitOutboundCellHistogram
- MidInactiveCircuitOutboundCellHistogram
- EndInactiveCircuitOutboundCellHistogram
- Rend2ServiceInactiveCircuitOutboundCellHistogram
- Intro2ServiceInactiveCircuitOutboundCellHistogram
- HSDir2ServiceInactiveCircuitOutboundCellHistogram
- Rend3ServiceInactiveCircuitOutboundCellHistogram
- Intro3ServiceInactiveCircuitOutboundCellHistogram
- HSDir3ServiceInactiveCircuitOutboundCellHistogram
- Rend2SingleOnionServiceInactiveCircuitOutboundCellHistogram
- Intro2SingleOnionServiceInactiveCircuitOutboundCellHistogram
- HSDir2SingleOnionServiceInactiveCircuitOutboundCellHistogram
- Rend3SingleOnionServiceInactiveCircuitOutboundCellHistogram
- Intro3SingleOnionServiceInactiveCircuitOutboundCellHistogram
- HSDir3SingleOnionServiceInactiveCircuitOutboundCellHistogram
- Rend2MultiHopServiceInactiveCircuitOutboundCellHistogram
- Intro2MultiHopServiceInactiveCircuitOutboundCellHistogram
- HSDir2MultiHopServiceInactiveCircuitOutboundCellHistogram
- Rend3MultiHopServiceInactiveCircuitOutboundCellHistogram
- Intro3MultiHopServiceInactiveCircuitOutboundCellHistogram
- HSDir3MultiHopServiceInactiveCircuitOutboundCellHistogram
- OriginInactiveCircuitOutboundCellHistogram
- SingleHopInactiveCircuitOutboundCellHistogram
- DirInactiveCircuitOutboundCellHistogram
- Rend2ClientInactiveCircuitOutboundCellHistogram
- Intro2ClientInactiveCircuitOutboundCellHistogram
- HSDir2ClientInactiveCircuitOutboundCellHistogram
- Rend3ClientInactiveCircuitOutboundCellHistogram
- Intro3ClientInactiveCircuitOutboundCellHistogram
- HSDir3ClientInactiveCircuitOutboundCellHistogram
- Rend2Tor2WebClientInactiveCircuitOutboundCellHistogram
- Intro2Tor2WebClientInactiveCircuitOutboundCellHistogram
- HSDir2Tor2WebClientInactiveCircuitOutboundCellHistogram
- Rend3Tor2WebClientInactiveCircuitOutboundCellHistogram
- Intro3Tor2WebClientInactiveCircuitOutboundCellHistogram
- HSDir3Tor2WebClientInactiveCircuitOutboundCellHistogram
- Rend2MultiHopClientInactiveCircuitOutboundCellHistogram
- Intro2MultiHopClientInactiveCircuitOutboundCellHistogram
- HSDir2MultiHopClientInactiveCircuitOutboundCellHistogram
- Rend3MultiHopClientInactiveCircuitOutboundCellHistogram
- Intro3MultiHopClientInactiveCircuitOutboundCellHistogram
- HSDir3MultiHopClientInactiveCircuitOutboundCellHistogram
- EntryInactiveCircuitOutboundCellHistogram
- Rend2ActiveSuccessCircuitOutboundCellHistogram
- Intro2ActiveSuccessCircuitOutboundCellHistogram
- HSDir2ActiveSuccessCircuitOutboundCellHistogram
- Rend3ActiveSuccessCircuitOutboundCellHistogram
- Intro3ActiveSuccessCircuitOutboundCellHistogram
- HSDir3ActiveSuccessCircuitOutboundCellHistogram
- MidActiveSuccessCircuitOutboundCellHistogram
- EndActiveSuccessCircuitOutboundCellHistogram
- Rend2ServiceActiveSuccessCircuitOutboundCellHistogram
- Intro2ServiceActiveSuccessCircuitOutboundCellHistogram
- HSDir2ServiceActiveSuccessCircuitOutboundCellHistogram
- Rend3ServiceActiveSuccessCircuitOutboundCellHistogram
- Intro3ServiceActiveSuccessCircuitOutboundCellHistogram
- HSDir3ServiceActiveSuccessCircuitOutboundCellHistogram
- Rend2SingleOnionServiceActiveSuccessCircuitOutboundCellHistogram
- Intro2SingleOnionServiceActiveSuccessCircuitOutboundCellHistogram
- HSDir2SingleOnionServiceActiveSuccessCircuitOutboundCellHistogram
- Rend3SingleOnionServiceActiveSuccessCircuitOutboundCellHistogram
- Intro3SingleOnionServiceActiveSuccessCircuitOutboundCellHistogram
- HSDir3SingleOnionServiceActiveSuccessCircuitOutboundCellHistogram
- Rend2MultiHopServiceActiveSuccessCircuitOutboundCellHistogram
- Intro2MultiHopServiceActiveSuccessCircuitOutboundCellHistogram
- HSDir2MultiHopServiceActiveSuccessCircuitOutboundCellHistogram
- Rend3MultiHopServiceActiveSuccessCircuitOutboundCellHistogram
- Intro3MultiHopServiceActiveSuccessCircuitOutboundCellHistogram
- HSDir3MultiHopServiceActiveSuccessCircuitOutboundCellHistogram
- OriginActiveSuccessCircuitOutboundCellHistogram
- SingleHopActiveSuccessCircuitOutboundCellHistogram
- DirActiveSuccessCircuitOutboundCellHistogram
- Rend2ClientActiveSuccessCircuitOutboundCellHistogram
- Intro2ClientActiveSuccessCircuitOutboundCellHistogram
- HSDir2ClientActiveSuccessCircuitOutboundCellHistogram
- Rend3ClientActiveSuccessCircuitOutboundCellHistogram
- Intro3ClientActiveSuccessCircuitOutboundCellHistogram
- HSDir3ClientActiveSuccessCircuitOutboundCellHistogram
- Rend2Tor2WebClientActiveSuccessCircuitOutboundCellHistogram
- Intro2Tor2WebClientActiveSuccessCircuitOutboundCellHistogram
- HSDir2Tor2WebClientActiveSuccessCircuitOutboundCellHistogram
- Rend3Tor2WebClientActiveSuccessCircuitOutboundCellHistogram
- Intro3Tor2WebClientActiveSuccessCircuitOutboundCellHistogram
- HSDir3Tor2WebClientActiveSuccessCircuitOutboundCellHistogram
- Rend2MultiHopClientActiveSuccessCircuitOutboundCellHistogram
- Intro2MultiHopClientActiveSuccessCircuitOutboundCellHistogram
- HSDir2MultiHopClientActiveSuccessCircuitOutboundCellHistogram
- Rend3MultiHopClientActiveSuccessCircuitOutboundCellHistogram
- Intro3MultiHopClientActiveSuccessCircuitOutboundCellHistogram
- HSDir3MultiHopClientActiveSuccessCircuitOutboundCellHistogram
- EntryActiveSuccessCircuitOutboundCellHistogram
- Rend2InactiveSuccessCircuitOutboundCellHistogram
- Intro2InactiveSuccessCircuitOutboundCellHistogram
- HSDir2InactiveSuccessCircuitOutboundCellHistogram
- Rend3InactiveSuccessCircuitOutboundCellHistogram
- Intro3InactiveSuccessCircuitOutboundCellHistogram
- HSDir3InactiveSuccessCircuitOutboundCellHistogram
- MidInactiveSuccessCircuitOutboundCellHistogram
- EndInactiveSuccessCircuitOutboundCellHistogram
- Rend2ServiceInactiveSuccessCircuitOutboundCellHistogram
- Intro2ServiceInactiveSuccessCircuitOutboundCellHistogram
- HSDir2ServiceInactiveSuccessCircuitOutboundCellHistogram
- Rend3ServiceInactiveSuccessCircuitOutboundCellHistogram
- Intro3ServiceInactiveSuccessCircuitOutboundCellHistogram
- HSDir3ServiceInactiveSuccessCircuitOutboundCellHistogram
- Rend2SingleOnionServiceInactiveSuccessCircuitOutboundCellHistogram
- Intro2SingleOnionServiceInactiveSuccessCircuitOutboundCellHistogram
- HSDir2SingleOnionServiceInactiveSuccessCircuitOutboundCellHistogram
- Rend3SingleOnionServiceInactiveSuccessCircuitOutboundCellHistogram
- Intro3SingleOnionServiceInactiveSuccessCircuitOutboundCellHistogram
- HSDir3SingleOnionServiceInactiveSuccessCircuitOutboundCellHistogram
- Rend2MultiHopServiceInactiveSuccessCircuitOutboundCellHistogram
- Intro2MultiHopServiceInactiveSuccessCircuitOutboundCellHistogram
- HSDir2MultiHopServiceInactiveSuccessCircuitOutboundCellHistogram
- Rend3MultiHopServiceInactiveSuccessCircuitOutboundCellHistogram
- Intro3MultiHopServiceInactiveSuccessCircuitOutboundCellHistogram
- HSDir3MultiHopServiceInactiveSuccessCircuitOutboundCellHistogram
- OriginInactiveSuccessCircuitOutboundCellHistogram
- SingleHopInactiveSuccessCircuitOutboundCellHistogram
- DirInactiveSuccessCircuitOutboundCellHistogram
- Rend2ClientInactiveSuccessCircuitOutboundCellHistogram
- Intro2ClientInactiveSuccessCircuitOutboundCellHistogram
- HSDir2ClientInactiveSuccessCircuitOutboundCellHistogram
- Rend3ClientInactiveSuccessCircuitOutboundCellHistogram
- Intro3ClientInactiveSuccessCircuitOutboundCellHistogram
- HSDir3ClientInactiveSuccessCircuitOutboundCellHistogram
- Rend2Tor2WebClientInactiveSuccessCircuitOutboundCellHistogram
- Intro2Tor2WebClientInactiveSuccessCircuitOutboundCellHistogram
- HSDir2Tor2WebClientInactiveSuccessCircuitOutboundCellHistogram
- Rend3Tor2WebClientInactiveSuccessCircuitOutboundCellHistogram
- Intro3Tor2WebClientInactiveSuccessCircuitOutboundCellHistogram
- HSDir3Tor2WebClientInactiveSuccessCircuitOutboundCellHistogram
- Rend2MultiHopClientInactiveSuccessCircuitOutboundCellHistogram
- Intro2MultiHopClientInactiveSuccessCircuitOutboundCellHistogram
- HSDir2MultiHopClientInactiveSuccessCircuitOutboundCellHistogram
- Rend3MultiHopClientInactiveSuccessCircuitOutboundCellHistogram
- Intro3MultiHopClientInactiveSuccessCircuitOutboundCellHistogram
- HSDir3MultiHopClientInactiveSuccessCircuitOutboundCellHistogram
- EntryInactiveSuccessCircuitOutboundCellHistogram
- Rend2ActiveFailureCircuitCellRatio
- Intro2ActiveFailureCircuitCellRatio
- HSDir2ActiveFailureCircuitCellRatio
- Rend3ActiveFailureCircuitCellRatio
- Intro3ActiveFailureCircuitCellRatio
- HSDir3ActiveFailureCircuitCellRatio
- MidActiveFailureCircuitCellRatio
- EndActiveFailureCircuitCellRatio
- Rend2ServiceActiveFailureCircuitCellRatio
- Intro2ServiceActiveFailureCircuitCellRatio
- HSDir2ServiceActiveFailureCircuitCellRatio
- Rend3ServiceActiveFailureCircuitCellRatio
- Intro3ServiceActiveFailureCircuitCellRatio
- HSDir3ServiceActiveFailureCircuitCellRatio
- Rend2SingleOnionServiceActiveFailureCircuitCellRatio
- Intro2SingleOnionServiceActiveFailureCircuitCellRatio
- HSDir2SingleOnionServiceActiveFailureCircuitCellRatio
- Rend3SingleOnionServiceActiveFailureCircuitCellRatio
- Intro3SingleOnionServiceActiveFailureCircuitCellRatio
- HSDir3SingleOnionServiceActiveFailureCircuitCellRatio
- Rend2MultiHopServiceActiveFailureCircuitCellRatio
- Intro2MultiHopServiceActiveFailureCircuitCellRatio
- HSDir2MultiHopServiceActiveFailureCircuitCellRatio
- Rend3MultiHopServiceActiveFailureCircuitCellRatio
- Intro3MultiHopServiceActiveFailureCircuitCellRatio
- HSDir3MultiHopServiceActiveFailureCircuitCellRatio
- OriginActiveFailureCircuitCellRatio
- SingleHopActiveFailureCircuitCellRatio
- DirActiveFailureCircuitCellRatio
- Rend2ClientActiveFailureCircuitCellRatio
- Intro2ClientActiveFailureCircuitCellRatio
- HSDir2ClientActiveFailureCircuitCellRatio
- Rend3ClientActiveFailureCircuitCellRatio
- Intro3ClientActiveFailureCircuitCellRatio
- HSDir3ClientActiveFailureCircuitCellRatio
- Rend2Tor2WebClientActiveFailureCircuitCellRatio
- Intro2Tor2WebClientActiveFailureCircuitCellRatio
- HSDir2Tor2WebClientActiveFailureCircuitCellRatio
- Rend3Tor2WebClientActiveFailureCircuitCellRatio
- Intro3Tor2WebClientActiveFailureCircuitCellRatio
- HSDir3Tor2WebClientActiveFailureCircuitCellRatio
- Rend2MultiHopClientActiveFailureCircuitCellRatio
- Intro2MultiHopClientActiveFailureCircuitCellRatio
- HSDir2MultiHopClientActiveFailureCircuitCellRatio
- Rend3MultiHopClientActiveFailureCircuitCellRatio
- Intro3MultiHopClientActiveFailureCircuitCellRatio
- HSDir3MultiHopClientActiveFailureCircuitCellRatio
- EntryActiveFailureCircuitCellRatio
- Rend2ActiveCircuitCellRatio
- Intro2ActiveCircuitCellRatio
- HSDir2ActiveCircuitCellRatio
- Rend3ActiveCircuitCellRatio
- Intro3ActiveCircuitCellRatio
- HSDir3ActiveCircuitCellRatio
- MidActiveCircuitCellRatio
- EndActiveCircuitCellRatio
- Rend2ServiceActiveCircuitCellRatio
- Intro2ServiceActiveCircuitCellRatio
- HSDir2ServiceActiveCircuitCellRatio
- Rend3ServiceActiveCircuitCellRatio
- Intro3ServiceActiveCircuitCellRatio
- HSDir3ServiceActiveCircuitCellRatio
- Rend2SingleOnionServiceActiveCircuitCellRatio
- Intro2SingleOnionServiceActiveCircuitCellRatio
- HSDir2SingleOnionServiceActiveCircuitCellRatio
- Rend3SingleOnionServiceActiveCircuitCellRatio
- Intro3SingleOnionServiceActiveCircuitCellRatio
- HSDir3SingleOnionServiceActiveCircuitCellRatio
- Rend2MultiHopServiceActiveCircuitCellRatio
- Intro2MultiHopServiceActiveCircuitCellRatio
- HSDir2MultiHopServiceActiveCircuitCellRatio
- Rend3MultiHopServiceActiveCircuitCellRatio
- Intro3MultiHopServiceActiveCircuitCellRatio
- HSDir3MultiHopServiceActiveCircuitCellRatio
- OriginActiveCircuitCellRatio
- SingleHopActiveCircuitCellRatio
- DirActiveCircuitCellRatio
- Rend2ClientActiveCircuitCellRatio
- Intro2ClientActiveCircuitCellRatio
- HSDir2ClientActiveCircuitCellRatio
- Rend3ClientActiveCircuitCellRatio
- Intro3ClientActiveCircuitCellRatio
- HSDir3ClientActiveCircuitCellRatio
- Rend2Tor2WebClientActiveCircuitCellRatio
- Intro2Tor2WebClientActiveCircuitCellRatio
- HSDir2Tor2WebClientActiveCircuitCellRatio
- Rend3Tor2WebClientActiveCircuitCellRatio
- Intro3Tor2WebClientActiveCircuitCellRatio
- HSDir3Tor2WebClientActiveCircuitCellRatio
- Rend2MultiHopClientActiveCircuitCellRatio
- Intro2MultiHopClientActiveCircuitCellRatio
- HSDir2MultiHopClientActiveCircuitCellRatio
- Rend3MultiHopClientActiveCircuitCellRatio
- Intro3MultiHopClientActiveCircuitCellRatio
- HSDir3MultiHopClientActiveCircuitCellRatio
- Rend2ActiveSuccessCircuitCellRatio
- Intro2ActiveSuccessCircuitCellRatio
- HSDir2ActiveSuccessCircuitCellRatio
- Rend3ActiveSuccessCircuitCellRatio
- Intro3ActiveSuccessCircuitCellRatio
- HSDir3ActiveSuccessCircuitCellRatio
- MidActiveSuccessCircuitCellRatio
- EndActiveSuccessCircuitCellRatio
- Rend2ServiceActiveSuccessCircuitCellRatio
- Intro2ServiceActiveSuccessCircuitCellRatio
- HSDir2ServiceActiveSuccessCircuitCellRatio
- Rend3ServiceActiveSuccessCircuitCellRatio
- Intro3ServiceActiveSuccessCircuitCellRatio
- HSDir3ServiceActiveSuccessCircuitCellRatio
- Rend2SingleOnionServiceActiveSuccessCircuitCellRatio
- Intro2SingleOnionServiceActiveSuccessCircuitCellRatio
- HSDir2SingleOnionServiceActiveSuccessCircuitCellRatio
- Rend3SingleOnionServiceActiveSuccessCircuitCellRatio
- Intro3SingleOnionServiceActiveSuccessCircuitCellRatio
- HSDir3SingleOnionServiceActiveSuccessCircuitCellRatio
- Rend2MultiHopServiceActiveSuccessCircuitCellRatio
- Intro2MultiHopServiceActiveSuccessCircuitCellRatio
- HSDir2MultiHopServiceActiveSuccessCircuitCellRatio
- Rend3MultiHopServiceActiveSuccessCircuitCellRatio
- Intro3MultiHopServiceActiveSuccessCircuitCellRatio
- HSDir3MultiHopServiceActiveSuccessCircuitCellRatio
- OriginActiveSuccessCircuitCellRatio
- SingleHopActiveSuccessCircuitCellRatio
- DirActiveSuccessCircuitCellRatio
- Rend2ClientActiveSuccessCircuitCellRatio
- Intro2ClientActiveSuccessCircuitCellRatio
- HSDir2ClientActiveSuccessCircuitCellRatio
- Rend3ClientActiveSuccessCircuitCellRatio
- Intro3ClientActiveSuccessCircuitCellRatio
- HSDir3ClientActiveSuccessCircuitCellRatio
- Rend2Tor2WebClientActiveSuccessCircuitCellRatio
- Intro2Tor2WebClientActiveSuccessCircuitCellRatio
- HSDir2Tor2WebClientActiveSuccessCircuitCellRatio
- Rend3Tor2WebClientActiveSuccessCircuitCellRatio
- Intro3Tor2WebClientActiveSuccessCircuitCellRatio
- HSDir3Tor2WebClientActiveSuccessCircuitCellRatio
- Rend2MultiHopClientActiveSuccessCircuitCellRatio
- Intro2MultiHopClientActiveSuccessCircuitCellRatio
- HSDir2MultiHopClientActiveSuccessCircuitCellRatio
- Rend3MultiHopClientActiveSuccessCircuitCellRatio
- Intro3MultiHopClientActiveSuccessCircuitCellRatio
- HSDir3MultiHopClientActiveSuccessCircuitCellRatio
- EntryActiveSuccessCircuitCellRatio
- Rend2ActiveFailureCircuitInboundCellCount
- Intro2ActiveFailureCircuitInboundCellCount
- HSDir2ActiveFailureCircuitInboundCellCount
- Rend3ActiveFailureCircuitInboundCellCount
- Intro3ActiveFailureCircuitInboundCellCount
- HSDir3ActiveFailureCircuitInboundCellCount
- MidActiveFailureCircuitInboundCellCount
- EndActiveFailureCircuitInboundCellCount
- Rend2ServiceActiveFailureCircuitInboundCellCount
- Intro2ServiceActiveFailureCircuitInboundCellCount
- HSDir2ServiceActiveFailureCircuitInboundCellCount
- Rend3ServiceActiveFailureCircuitInboundCellCount
- Intro3ServiceActiveFailureCircuitInboundCellCount
- HSDir3ServiceActiveFailureCircuitInboundCellCount
- Rend2SingleOnionServiceActiveFailureCircuitInboundCellCount
- Intro2SingleOnionServiceActiveFailureCircuitInboundCellCount
- HSDir2SingleOnionServiceActiveFailureCircuitInboundCellCount
- Rend3SingleOnionServiceActiveFailureCircuitInboundCellCount
- Intro3SingleOnionServiceActiveFailureCircuitInboundCellCount
- HSDir3SingleOnionServiceActiveFailureCircuitInboundCellCount
- Rend2MultiHopServiceActiveFailureCircuitInboundCellCount
- Intro2MultiHopServiceActiveFailureCircuitInboundCellCount
- HSDir2MultiHopServiceActiveFailureCircuitInboundCellCount
- Rend3MultiHopServiceActiveFailureCircuitInboundCellCount
- Intro3MultiHopServiceActiveFailureCircuitInboundCellCount
- HSDir3MultiHopServiceActiveFailureCircuitInboundCellCount
- OriginActiveFailureCircuitInboundCellCount
- SingleHopActiveFailureCircuitInboundCellCount
- DirActiveFailureCircuitInboundCellCount
- Rend2ClientActiveFailureCircuitInboundCellCount
- Intro2ClientActiveFailureCircuitInboundCellCount
- HSDir2ClientActiveFailureCircuitInboundCellCount
- Rend3ClientActiveFailureCircuitInboundCellCount
- Intro3ClientActiveFailureCircuitInboundCellCount
- HSDir3ClientActiveFailureCircuitInboundCellCount
- Rend2Tor2WebClientActiveFailureCircuitInboundCellCount
- Intro2Tor2WebClientActiveFailureCircuitInboundCellCount
- HSDir2Tor2WebClientActiveFailureCircuitInboundCellCount
- Rend3Tor2WebClientActiveFailureCircuitInboundCellCount
- Intro3Tor2WebClientActiveFailureCircuitInboundCellCount
- HSDir3Tor2WebClientActiveFailureCircuitInboundCellCount
- Rend2MultiHopClientActiveFailureCircuitInboundCellCount
- Intro2MultiHopClientActiveFailureCircuitInboundCellCount
- HSDir2MultiHopClientActiveFailureCircuitInboundCellCount
- Rend3MultiHopClientActiveFailureCircuitInboundCellCount
- Intro3MultiHopClientActiveFailureCircuitInboundCellCount
- HSDir3MultiHopClientActiveFailureCircuitInboundCellCount
- EntryActiveFailureCircuitInboundCellCount
- Rend2InactiveFailureCircuitInboundCellCount
- Intro2InactiveFailureCircuitInboundCellCount
- HSDir2InactiveFailureCircuitInboundCellCount
- Rend3InactiveFailureCircuitInboundCellCount
- Intro3InactiveFailureCircuitInboundCellCount
- HSDir3InactiveFailureCircuitInboundCellCount
- MidInactiveFailureCircuitInboundCellCount
- EndInactiveFailureCircuitInboundCellCount
- Rend2ServiceInactiveFailureCircuitInboundCellCount
- Intro2ServiceInactiveFailureCircuitInboundCellCount
- HSDir2ServiceInactiveFailureCircuitInboundCellCount
- Rend3ServiceInactiveFailureCircuitInboundCellCount
- Intro3ServiceInactiveFailureCircuitInboundCellCount
- HSDir3ServiceInactiveFailureCircuitInboundCellCount
- Rend2SingleOnionServiceInactiveFailureCircuitInboundCellCount
- Intro2SingleOnionServiceInactiveFailureCircuitInboundCellCount
- HSDir2SingleOnionServiceInactiveFailureCircuitInboundCellCount
- Rend3SingleOnionServiceInactiveFailureCircuitInboundCellCount
- Intro3SingleOnionServiceInactiveFailureCircuitInboundCellCount
- HSDir3SingleOnionServiceInactiveFailureCircuitInboundCellCount
- Rend2MultiHopServiceInactiveFailureCircuitInboundCellCount
- Intro2MultiHopServiceInactiveFailureCircuitInboundCellCount
- HSDir2MultiHopServiceInactiveFailureCircuitInboundCellCount
- Rend3MultiHopServiceInactiveFailureCircuitInboundCellCount
- Intro3MultiHopServiceInactiveFailureCircuitInboundCellCount
- HSDir3MultiHopServiceInactiveFailureCircuitInboundCellCount
- OriginInactiveFailureCircuitInboundCellCount
- SingleHopInactiveFailureCircuitInboundCellCount
- DirInactiveFailureCircuitInboundCellCount
- Rend2ClientInactiveFailureCircuitInboundCellCount
- Intro2ClientInactiveFailureCircuitInboundCellCount
- HSDir2ClientInactiveFailureCircuitInboundCellCount
- Rend3ClientInactiveFailureCircuitInboundCellCount
- Intro3ClientInactiveFailureCircuitInboundCellCount
- HSDir3ClientInactiveFailureCircuitInboundCellCount
- Rend2Tor2WebClientInactiveFailureCircuitInboundCellCount
- Intro2Tor2WebClientInactiveFailureCircuitInboundCellCount
- HSDir2Tor2WebClientInactiveFailureCircuitInboundCellCount
- Rend3Tor2WebClientInactiveFailureCircuitInboundCellCount
- Intro3Tor2WebClientInactiveFailureCircuitInboundCellCount
- HSDir3Tor2WebClientInactiveFailureCircuitInboundCellCount
- Rend2MultiHopClientInactiveFailureCircuitInboundCellCount
- Intro2MultiHopClientInactiveFailureCircuitInboundCellCount
- HSDir2MultiHopClientInactiveFailureCircuitInboundCellCount
- Rend3MultiHopClientInactiveFailureCircuitInboundCellCount
- Intro3MultiHopClientInactiveFailureCircuitInboundCellCount
- HSDir3MultiHopClientInactiveFailureCircuitInboundCellCount
- EntryInactiveFailureCircuitInboundCellCount
- Rend2ActiveCircuitInboundCellCount
- Intro2ActiveCircuitInboundCellCount
- HSDir2ActiveCircuitInboundCellCount
- Rend3ActiveCircuitInboundCellCount
- Intro3ActiveCircuitInboundCellCount
- HSDir3ActiveCircuitInboundCellCount
- MidActiveCircuitInboundCellCount
- EndActiveCircuitInboundCellCount
- Rend2ServiceActiveCircuitInboundCellCount
- Intro2ServiceActiveCircuitInboundCellCount
- HSDir2ServiceActiveCircuitInboundCellCount
- Rend3ServiceActiveCircuitInboundCellCount
- Intro3ServiceActiveCircuitInboundCellCount
- HSDir3ServiceActiveCircuitInboundCellCount
- Rend2SingleOnionServiceActiveCircuitInboundCellCount
- Intro2SingleOnionServiceActiveCircuitInboundCellCount
- HSDir2SingleOnionServiceActiveCircuitInboundCellCount
- Rend3SingleOnionServiceActiveCircuitInboundCellCount
- Intro3SingleOnionServiceActiveCircuitInboundCellCount
- HSDir3SingleOnionServiceActiveCircuitInboundCellCount
- Rend2MultiHopServiceActiveCircuitInboundCellCount
- Intro2MultiHopServiceActiveCircuitInboundCellCount
- HSDir2MultiHopServiceActiveCircuitInboundCellCount
- Rend3MultiHopServiceActiveCircuitInboundCellCount
- Intro3MultiHopServiceActiveCircuitInboundCellCount
- HSDir3MultiHopServiceActiveCircuitInboundCellCount
- OriginActiveCircuitInboundCellCount
- SingleHopActiveCircuitInboundCellCount
- DirActiveCircuitInboundCellCount
- Rend2ClientActiveCircuitInboundCellCount
- Intro2ClientActiveCircuitInboundCellCount
- HSDir2ClientActiveCircuitInboundCellCount
- Rend3ClientActiveCircuitInboundCellCount
- Intro3ClientActiveCircuitInboundCellCount
- HSDir3ClientActiveCircuitInboundCellCount
- Rend2Tor2WebClientActiveCircuitInboundCellCount
- Intro2Tor2WebClientActiveCircuitInboundCellCount
- HSDir2Tor2WebClientActiveCircuitInboundCellCount
- Rend3Tor2WebClientActiveCircuitInboundCellCount
- Intro3Tor2WebClientActiveCircuitInboundCellCount
- HSDir3Tor2WebClientActiveCircuitInboundCellCount
- Rend2MultiHopClientActiveCircuitInboundCellCount
- Intro2MultiHopClientActiveCircuitInboundCellCount
- HSDir2MultiHopClientActiveCircuitInboundCellCount
- Rend3MultiHopClientActiveCircuitInboundCellCount
- Intro3MultiHopClientActiveCircuitInboundCellCount
- HSDir3MultiHopClientActiveCircuitInboundCellCount
- EntryActiveCircuitInboundCellCount
- Rend2InactiveCircuitInboundCellCount
- Intro2InactiveCircuitInboundCellCount
- HSDir2InactiveCircuitInboundCellCount
- Rend3InactiveCircuitInboundCellCount
- Intro3InactiveCircuitInboundCellCount
- HSDir3InactiveCircuitInboundCellCount
- MidInactiveCircuitInboundCellCount
- EndInactiveCircuitInboundCellCount
- Rend2ServiceInactiveCircuitInboundCellCount
- Intro2ServiceInactiveCircuitInboundCellCount
- HSDir2ServiceInactiveCircuitInboundCellCount
- Rend3ServiceInactiveCircuitInboundCellCount
- Intro3ServiceInactiveCircuitInboundCellCount
- HSDir3ServiceInactiveCircuitInboundCellCount
- Rend2SingleOnionServiceInactiveCircuitInboundCellCount
- Intro2SingleOnionServiceInactiveCircuitInboundCellCount
- HSDir2SingleOnionServiceInactiveCircuitInboundCellCount
- Rend3SingleOnionServiceInactiveCircuitInboundCellCount
- Intro3SingleOnionServiceInactiveCircuitInboundCellCount
- HSDir3SingleOnionServiceInactiveCircuitInboundCellCount
- Rend2MultiHopServiceInactiveCircuitInboundCellCount
- Intro2MultiHopServiceInactiveCircuitInboundCellCount
- HSDir2MultiHopServiceInactiveCircuitInboundCellCount
- Rend3MultiHopServiceInactiveCircuitInboundCellCount
- Intro3MultiHopServiceInactiveCircuitInboundCellCount
- HSDir3MultiHopServiceInactiveCircuitInboundCellCount
- OriginInactiveCircuitInboundCellCount
- SingleHopInactiveCircuitInboundCellCount
- DirInactiveCircuitInboundCellCount
- Rend2ClientInactiveCircuitInboundCellCount
- Intro2ClientInactiveCircuitInboundCellCount
- HSDir2ClientInactiveCircuitInboundCellCount
- Rend3ClientInactiveCircuitInboundCellCount
- Intro3ClientInactiveCircuitInboundCellCount
- HSDir3ClientInactiveCircuitInboundCellCount
- Rend2Tor2WebClientInactiveCircuitInboundCellCount
- Intro2Tor2WebClientInactiveCircuitInboundCellCount
- HSDir2Tor2WebClientInactiveCircuitInboundCellCount
- Rend3Tor2WebClientInactiveCircuitInboundCellCount
- Intro3Tor2WebClientInactiveCircuitInboundCellCount
- HSDir3Tor2WebClientInactiveCircuitInboundCellCount
- Rend2MultiHopClientInactiveCircuitInboundCellCount
- Intro2MultiHopClientInactiveCircuitInboundCellCount
- HSDir2MultiHopClientInactiveCircuitInboundCellCount
- Rend3MultiHopClientInactiveCircuitInboundCellCount
- Intro3MultiHopClientInactiveCircuitInboundCellCount
- HSDir3MultiHopClientInactiveCircuitInboundCellCount
- EntryInactiveCircuitInboundCellCount
- Rend2ActiveSuccessCircuitInboundCellCount
- Intro2ActiveSuccessCircuitInboundCellCount
- HSDir2ActiveSuccessCircuitInboundCellCount
- Rend3ActiveSuccessCircuitInboundCellCount
- Intro3ActiveSuccessCircuitInboundCellCount
- HSDir3ActiveSuccessCircuitInboundCellCount
- MidActiveSuccessCircuitInboundCellCount
- EndActiveSuccessCircuitInboundCellCount
- Rend2ServiceActiveSuccessCircuitInboundCellCount
- Intro2ServiceActiveSuccessCircuitInboundCellCount
- HSDir2ServiceActiveSuccessCircuitInboundCellCount
- Rend3ServiceActiveSuccessCircuitInboundCellCount
- Intro3ServiceActiveSuccessCircuitInboundCellCount
- HSDir3ServiceActiveSuccessCircuitInboundCellCount
- Rend2SingleOnionServiceActiveSuccessCircuitInboundCellCount
- Intro2SingleOnionServiceActiveSuccessCircuitInboundCellCount
- HSDir2SingleOnionServiceActiveSuccessCircuitInboundCellCount
- Rend3SingleOnionServiceActiveSuccessCircuitInboundCellCount
- Intro3SingleOnionServiceActiveSuccessCircuitInboundCellCount
- HSDir3SingleOnionServiceActiveSuccessCircuitInboundCellCount
- Rend2MultiHopServiceActiveSuccessCircuitInboundCellCount
- Intro2MultiHopServiceActiveSuccessCircuitInboundCellCount
- HSDir2MultiHopServiceActiveSuccessCircuitInboundCellCount
- Rend3MultiHopServiceActiveSuccessCircuitInboundCellCount
- Intro3MultiHopServiceActiveSuccessCircuitInboundCellCount
- HSDir3MultiHopServiceActiveSuccessCircuitInboundCellCount
- OriginActiveSuccessCircuitInboundCellCount
- SingleHopActiveSuccessCircuitInboundCellCount
- DirActiveSuccessCircuitInboundCellCount
- Rend2ClientActiveSuccessCircuitInboundCellCount
- Intro2ClientActiveSuccessCircuitInboundCellCount
- HSDir2ClientActiveSuccessCircuitInboundCellCount
- Rend3ClientActiveSuccessCircuitInboundCellCount
- Intro3ClientActiveSuccessCircuitInboundCellCount
- HSDir3ClientActiveSuccessCircuitInboundCellCount
- Rend2Tor2WebClientActiveSuccessCircuitInboundCellCount
- Intro2Tor2WebClientActiveSuccessCircuitInboundCellCount
- HSDir2Tor2WebClientActiveSuccessCircuitInboundCellCount
- Rend3Tor2WebClientActiveSuccessCircuitInboundCellCount
- Intro3Tor2WebClientActiveSuccessCircuitInboundCellCount
- HSDir3Tor2WebClientActiveSuccessCircuitInboundCellCount
- Rend2MultiHopClientActiveSuccessCircuitInboundCellCount
- Intro2MultiHopClientActiveSuccessCircuitInboundCellCount
- HSDir2MultiHopClientActiveSuccessCircuitInboundCellCount
- Rend3MultiHopClientActiveSuccessCircuitInboundCellCount
- Intro3MultiHopClientActiveSuccessCircuitInboundCellCount
- HSDir3MultiHopClientActiveSuccessCircuitInboundCellCount
- EntryActiveSuccessCircuitInboundCellCount
- Rend2InactiveSuccessCircuitInboundCellCount
- Intro2InactiveSuccessCircuitInboundCellCount
- HSDir2InactiveSuccessCircuitInboundCellCount
- Rend3InactiveSuccessCircuitInboundCellCount
- Intro3InactiveSuccessCircuitInboundCellCount
- HSDir3InactiveSuccessCircuitInboundCellCount
- MidInactiveSuccessCircuitInboundCellCount
- EndInactiveSuccessCircuitInboundCellCount
- Rend2ServiceInactiveSuccessCircuitInboundCellCount
- Intro2ServiceInactiveSuccessCircuitInboundCellCount
- HSDir2ServiceInactiveSuccessCircuitInboundCellCount
- Rend3ServiceInactiveSuccessCircuitInboundCellCount
- Intro3ServiceInactiveSuccessCircuitInboundCellCount
- HSDir3ServiceInactiveSuccessCircuitInboundCellCount
- Rend2SingleOnionServiceInactiveSuccessCircuitInboundCellCount
- Intro2SingleOnionServiceInactiveSuccessCircuitInboundCellCount
- HSDir2SingleOnionServiceInactiveSuccessCircuitInboundCellCount
- Rend3SingleOnionServiceInactiveSuccessCircuitInboundCellCount
- Intro3SingleOnionServiceInactiveSuccessCircuitInboundCellCount
- HSDir3SingleOnionServiceInactiveSuccessCircuitInboundCellCount
- Rend2MultiHopServiceInactiveSuccessCircuitInboundCellCount
- Intro2MultiHopServiceInactiveSuccessCircuitInboundCellCount
- HSDir2MultiHopServiceInactiveSuccessCircuitInboundCellCount
- Rend3MultiHopServiceInactiveSuccessCircuitInboundCellCount
- Intro3MultiHopServiceInactiveSuccessCircuitInboundCellCount
- HSDir3MultiHopServiceInactiveSuccessCircuitInboundCellCount
- OriginInactiveSuccessCircuitInboundCellCount
- SingleHopInactiveSuccessCircuitInboundCellCount
- DirInactiveSuccessCircuitInboundCellCount
- Rend2ClientInactiveSuccessCircuitInboundCellCount
- Intro2ClientInactiveSuccessCircuitInboundCellCount
- HSDir2ClientInactiveSuccessCircuitInboundCellCount
- Rend3ClientInactiveSuccessCircuitInboundCellCount
- Intro3ClientInactiveSuccessCircuitInboundCellCount
- HSDir3ClientInactiveSuccessCircuitInboundCellCount
- Rend2Tor2WebClientInactiveSuccessCircuitInboundCellCount
- Intro2Tor2WebClientInactiveSuccessCircuitInboundCellCount
- HSDir2Tor2WebClientInactiveSuccessCircuitInboundCellCount
- Rend3Tor2WebClientInactiveSuccessCircuitInboundCellCount
- Intro3Tor2WebClientInactiveSuccessCircuitInboundCellCount
- HSDir3Tor2WebClientInactiveSuccessCircuitInboundCellCount
- Rend2MultiHopClientInactiveSuccessCircuitInboundCellCount
- Intro2MultiHopClientInactiveSuccessCircuitInboundCellCount
- HSDir2MultiHopClientInactiveSuccessCircuitInboundCellCount
- Rend3MultiHopClientInactiveSuccessCircuitInboundCellCount
- Intro3MultiHopClientInactiveSuccessCircuitInboundCellCount
- HSDir3MultiHopClientInactiveSuccessCircuitInboundCellCount
- EntryInactiveSuccessCircuitInboundCellCount
- Rend2ActiveFailureCircuitOutboundCellCount
- Intro2ActiveFailureCircuitOutboundCellCount
- HSDir2ActiveFailureCircuitOutboundCellCount
- Rend3ActiveFailureCircuitOutboundCellCount
- Intro3ActiveFailureCircuitOutboundCellCount
- HSDir3ActiveFailureCircuitOutboundCellCount
- MidActiveFailureCircuitOutboundCellCount
- EndActiveFailureCircuitOutboundCellCount
- Rend2ServiceActiveFailureCircuitOutboundCellCount
- Intro2ServiceActiveFailureCircuitOutboundCellCount
- HSDir2ServiceActiveFailureCircuitOutboundCellCount
- Rend3ServiceActiveFailureCircuitOutboundCellCount
- Intro3ServiceActiveFailureCircuitOutboundCellCount
- HSDir3ServiceActiveFailureCircuitOutboundCellCount
- Rend2SingleOnionServiceActiveFailureCircuitOutboundCellCount
- Intro2SingleOnionServiceActiveFailureCircuitOutboundCellCount
- HSDir2SingleOnionServiceActiveFailureCircuitOutboundCellCount
- Rend3SingleOnionServiceActiveFailureCircuitOutboundCellCount
- Intro3SingleOnionServiceActiveFailureCircuitOutboundCellCount
- HSDir3SingleOnionServiceActiveFailureCircuitOutboundCellCount
- Rend2MultiHopServiceActiveFailureCircuitOutboundCellCount
- Intro2MultiHopServiceActiveFailureCircuitOutboundCellCount
- HSDir2MultiHopServiceActiveFailureCircuitOutboundCellCount
- Rend3MultiHopServiceActiveFailureCircuitOutboundCellCount
- Intro3MultiHopServiceActiveFailureCircuitOutboundCellCount
- HSDir3MultiHopServiceActiveFailureCircuitOutboundCellCount
- OriginActiveFailureCircuitOutboundCellCount
- SingleHopActiveFailureCircuitOutboundCellCount
- DirActiveFailureCircuitOutboundCellCount
- Rend2ClientActiveFailureCircuitOutboundCellCount
- Intro2ClientActiveFailureCircuitOutboundCellCount
- HSDir2ClientActiveFailureCircuitOutboundCellCount
- Rend3ClientActiveFailureCircuitOutboundCellCount
- Intro3ClientActiveFailureCircuitOutboundCellCount
- HSDir3ClientActiveFailureCircuitOutboundCellCount
- Rend2Tor2WebClientActiveFailureCircuitOutboundCellCount
- Intro2Tor2WebClientActiveFailureCircuitOutboundCellCount
- HSDir2Tor2WebClientActiveFailureCircuitOutboundCellCount
- Rend3Tor2WebClientActiveFailureCircuitOutboundCellCount
- Intro3Tor2WebClientActiveFailureCircuitOutboundCellCount
- HSDir3Tor2WebClientActiveFailureCircuitOutboundCellCount
- Rend2MultiHopClientActiveFailureCircuitOutboundCellCount
- Intro2MultiHopClientActiveFailureCircuitOutboundCellCount
- HSDir2MultiHopClientActiveFailureCircuitOutboundCellCount
- Rend3MultiHopClientActiveFailureCircuitOutboundCellCount
- Intro3MultiHopClientActiveFailureCircuitOutboundCellCount
- HSDir3MultiHopClientActiveFailureCircuitOutboundCellCount
- EntryActiveFailureCircuitOutboundCellCount
- Rend2InactiveFailureCircuitOutboundCellCount
- Intro2InactiveFailureCircuitOutboundCellCount
- HSDir2InactiveFailureCircuitOutboundCellCount
- Rend3InactiveFailureCircuitOutboundCellCount
- Intro3InactiveFailureCircuitOutboundCellCount
- HSDir3InactiveFailureCircuitOutboundCellCount
- MidInactiveFailureCircuitOutboundCellCount
- EndInactiveFailureCircuitOutboundCellCount
- Rend2ServiceInactiveFailureCircuitOutboundCellCount
- Intro2ServiceInactiveFailureCircuitOutboundCellCount
- HSDir2ServiceInactiveFailureCircuitOutboundCellCount
- Rend3ServiceInactiveFailureCircuitOutboundCellCount
- Intro3ServiceInactiveFailureCircuitOutboundCellCount
- HSDir3ServiceInactiveFailureCircuitOutboundCellCount
- Rend2SingleOnionServiceInactiveFailureCircuitOutboundCellCount
- Intro2SingleOnionServiceInactiveFailureCircuitOutboundCellCount
- HSDir2SingleOnionServiceInactiveFailureCircuitOutboundCellCount
- Rend3SingleOnionServiceInactiveFailureCircuitOutboundCellCount
- Intro3SingleOnionServiceInactiveFailureCircuitOutboundCellCount
- HSDir3SingleOnionServiceInactiveFailureCircuitOutboundCellCount
- Rend2MultiHopServiceInactiveFailureCircuitOutboundCellCount
- Intro2MultiHopServiceInactiveFailureCircuitOutboundCellCount
- HSDir2MultiHopServiceInactiveFailureCircuitOutboundCellCount
- Rend3MultiHopServiceInactiveFailureCircuitOutboundCellCount
- Intro3MultiHopServiceInactiveFailureCircuitOutboundCellCount
- HSDir3MultiHopServiceInactiveFailureCircuitOutboundCellCount
- OriginInactiveFailureCircuitOutboundCellCount
- SingleHopInactiveFailureCircuitOutboundCellCount
- DirInactiveFailureCircuitOutboundCellCount
- Rend2ClientInactiveFailureCircuitOutboundCellCount
- Intro2ClientInactiveFailureCircuitOutboundCellCount
- HSDir2ClientInactiveFailureCircuitOutboundCellCount
- Rend3ClientInactiveFailureCircuitOutboundCellCount
- Intro3ClientInactiveFailureCircuitOutboundCellCount
- HSDir3ClientInactiveFailureCircuitOutboundCellCount
- Rend2Tor2WebClientInactiveFailureCircuitOutboundCellCount
- Intro2Tor2WebClientInactiveFailureCircuitOutboundCellCount
- HSDir2Tor2WebClientInactiveFailureCircuitOutboundCellCount
- Rend3Tor2WebClientInactiveFailureCircuitOutboundCellCount
- Intro3Tor2WebClientInactiveFailureCircuitOutboundCellCount
- HSDir3Tor2WebClientInactiveFailureCircuitOutboundCellCount
- Rend2MultiHopClientInactiveFailureCircuitOutboundCellCount
- Intro2MultiHopClientInactiveFailureCircuitOutboundCellCount
- HSDir2MultiHopClientInactiveFailureCircuitOutboundCellCount
- Rend3MultiHopClientInactiveFailureCircuitOutboundCellCount
- Intro3MultiHopClientInactiveFailureCircuitOutboundCellCount
- HSDir3MultiHopClientInactiveFailureCircuitOutboundCellCount
- EntryInactiveFailureCircuitOutboundCellCount
- Rend2ActiveCircuitOutboundCellCount
- Intro2ActiveCircuitOutboundCellCount
- HSDir2ActiveCircuitOutboundCellCount
- Rend3ActiveCircuitOutboundCellCount
- Intro3ActiveCircuitOutboundCellCount
- HSDir3ActiveCircuitOutboundCellCount
- MidActiveCircuitOutboundCellCount
- EndActiveCircuitOutboundCellCount
- Rend2ServiceActiveCircuitOutboundCellCount
- Intro2ServiceActiveCircuitOutboundCellCount
- HSDir2ServiceActiveCircuitOutboundCellCount
- Rend3ServiceActiveCircuitOutboundCellCount
- Intro3ServiceActiveCircuitOutboundCellCount
- HSDir3ServiceActiveCircuitOutboundCellCount
- Rend2SingleOnionServiceActiveCircuitOutboundCellCount
- Intro2SingleOnionServiceActiveCircuitOutboundCellCount
- HSDir2SingleOnionServiceActiveCircuitOutboundCellCount
- Rend3SingleOnionServiceActiveCircuitOutboundCellCount
- Intro3SingleOnionServiceActiveCircuitOutboundCellCount
- HSDir3SingleOnionServiceActiveCircuitOutboundCellCount
- Rend2MultiHopServiceActiveCircuitOutboundCellCount
- Intro2MultiHopServiceActiveCircuitOutboundCellCount
- HSDir2MultiHopServiceActiveCircuitOutboundCellCount
- Rend3MultiHopServiceActiveCircuitOutboundCellCount
- Intro3MultiHopServiceActiveCircuitOutboundCellCount
- HSDir3MultiHopServiceActiveCircuitOutboundCellCount
- OriginActiveCircuitOutboundCellCount
- SingleHopActiveCircuitOutboundCellCount
- DirActiveCircuitOutboundCellCount
- Rend2ClientActiveCircuitOutboundCellCount
- Intro2ClientActiveCircuitOutboundCellCount
- HSDir2ClientActiveCircuitOutboundCellCount
- Rend3ClientActiveCircuitOutboundCellCount
- Intro3ClientActiveCircuitOutboundCellCount
- HSDir3ClientActiveCircuitOutboundCellCount
- Rend2Tor2WebClientActiveCircuitOutboundCellCount
- Intro2Tor2WebClientActiveCircuitOutboundCellCount
- HSDir2Tor2WebClientActiveCircuitOutboundCellCount
- Rend3Tor2WebClientActiveCircuitOutboundCellCount
- Intro3Tor2WebClientActiveCircuitOutboundCellCount
- HSDir3Tor2WebClientActiveCircuitOutboundCellCount
- Rend2MultiHopClientActiveCircuitOutboundCellCount
- Intro2MultiHopClientActiveCircuitOutboundCellCount
- HSDir2MultiHopClientActiveCircuitOutboundCellCount
- Rend3MultiHopClientActiveCircuitOutboundCellCount
- Intro3MultiHopClientActiveCircuitOutboundCellCount
- HSDir3MultiHopClientActiveCircuitOutboundCellCount
- EntryActiveCircuitOutboundCellCount
- Rend2InactiveCircuitOutboundCellCount
- Intro2InactiveCircuitOutboundCellCount
- HSDir2InactiveCircuitOutboundCellCount
- Rend3InactiveCircuitOutboundCellCount
- Intro3InactiveCircuitOutboundCellCount
- HSDir3InactiveCircuitOutboundCellCount
- MidInactiveCircuitOutboundCellCount
- EndInactiveCircuitOutboundCellCount
- Rend2ServiceInactiveCircuitOutboundCellCount
- Intro2ServiceInactiveCircuitOutboundCellCount
- HSDir2ServiceInactiveCircuitOutboundCellCount
- Rend3ServiceInactiveCircuitOutboundCellCount
- Intro3ServiceInactiveCircuitOutboundCellCount
- HSDir3ServiceInactiveCircuitOutboundCellCount
- Rend2SingleOnionServiceInactiveCircuitOutboundCellCount
- Intro2SingleOnionServiceInactiveCircuitOutboundCellCount
- HSDir2SingleOnionServiceInactiveCircuitOutboundCellCount
- Rend3SingleOnionServiceInactiveCircuitOutboundCellCount
- Intro3SingleOnionServiceInactiveCircuitOutboundCellCount
- HSDir3SingleOnionServiceInactiveCircuitOutboundCellCount
- Rend2MultiHopServiceInactiveCircuitOutboundCellCount
- Intro2MultiHopServiceInactiveCircuitOutboundCellCount
- HSDir2MultiHopServiceInactiveCircuitOutboundCellCount
- Rend3MultiHopServiceInactiveCircuitOutboundCellCount
- Intro3MultiHopServiceInactiveCircuitOutboundCellCount
- HSDir3MultiHopServiceInactiveCircuitOutboundCellCount
- OriginInactiveCircuitOutboundCellCount
- SingleHopInactiveCircuitOutboundCellCount
- DirInactiveCircuitOutboundCellCount
- Rend2ClientInactiveCircuitOutboundCellCount
- Intro2ClientInactiveCircuitOutboundCellCount
- HSDir2ClientInactiveCircuitOutboundCellCount
- Rend3ClientInactiveCircuitOutboundCellCount
- Intro3ClientInactiveCircuitOutboundCellCount
- HSDir3ClientInactiveCircuitOutboundCellCount
- Rend2Tor2WebClientInactiveCircuitOutboundCellCount
- Intro2Tor2WebClientInactiveCircuitOutboundCellCount
- HSDir2Tor2WebClientInactiveCircuitOutboundCellCount
- Rend3Tor2WebClientInactiveCircuitOutboundCellCount
- Intro3Tor2WebClientInactiveCircuitOutboundCellCount
- HSDir3Tor2WebClientInactiveCircuitOutboundCellCount
- Rend2MultiHopClientInactiveCircuitOutboundCellCount
- Intro2MultiHopClientInactiveCircuitOutboundCellCount
- HSDir2MultiHopClientInactiveCircuitOutboundCellCount
- Rend3MultiHopClientInactiveCircuitOutboundCellCount
- Intro3MultiHopClientInactiveCircuitOutboundCellCount
- HSDir3MultiHopClientInactiveCircuitOutboundCellCount
- EntryInactiveCircuitOutboundCellCount
- Rend2ActiveSuccessCircuitOutboundCellCount
- Intro2ActiveSuccessCircuitOutboundCellCount
- HSDir2ActiveSuccessCircuitOutboundCellCount
- Rend3ActiveSuccessCircuitOutboundCellCount
- Intro3ActiveSuccessCircuitOutboundCellCount
- HSDir3ActiveSuccessCircuitOutboundCellCount
- MidActiveSuccessCircuitOutboundCellCount
- EndActiveSuccessCircuitOutboundCellCount
- Rend2ServiceActiveSuccessCircuitOutboundCellCount
- Intro2ServiceActiveSuccessCircuitOutboundCellCount
- HSDir2ServiceActiveSuccessCircuitOutboundCellCount
- Rend3ServiceActiveSuccessCircuitOutboundCellCount
- Intro3ServiceActiveSuccessCircuitOutboundCellCount
- HSDir3ServiceActiveSuccessCircuitOutboundCellCount
- Rend2SingleOnionServiceActiveSuccessCircuitOutboundCellCount
- Intro2SingleOnionServiceActiveSuccessCircuitOutboundCellCount
- HSDir2SingleOnionServiceActiveSuccessCircuitOutboundCellCount
- Rend3SingleOnionServiceActiveSuccessCircuitOutboundCellCount
- Intro3SingleOnionServiceActiveSuccessCircuitOutboundCellCount
- HSDir3SingleOnionServiceActiveSuccessCircuitOutboundCellCount
- Rend2MultiHopServiceActiveSuccessCircuitOutboundCellCount
- Intro2MultiHopServiceActiveSuccessCircuitOutboundCellCount
- HSDir2MultiHopServiceActiveSuccessCircuitOutboundCellCount
- Rend3MultiHopServiceActiveSuccessCircuitOutboundCellCount
- Intro3MultiHopServiceActiveSuccessCircuitOutboundCellCount
- HSDir3MultiHopServiceActiveSuccessCircuitOutboundCellCount
- OriginActiveSuccessCircuitOutboundCellCount
- SingleHopActiveSuccessCircuitOutboundCellCount
- DirActiveSuccessCircuitOutboundCellCount
- Rend2ClientActiveSuccessCircuitOutboundCellCount
- Intro2ClientActiveSuccessCircuitOutboundCellCount
- HSDir2ClientActiveSuccessCircuitOutboundCellCount
- Rend3ClientActiveSuccessCircuitOutboundCellCount
- Intro3ClientActiveSuccessCircuitOutboundCellCount
- HSDir3ClientActiveSuccessCircuitOutboundCellCount
- Rend2Tor2WebClientActiveSuccessCircuitOutboundCellCount
- Intro2Tor2WebClientActiveSuccessCircuitOutboundCellCount
- HSDir2Tor2WebClientActiveSuccessCircuitOutboundCellCount
- Rend3Tor2WebClientActiveSuccessCircuitOutboundCellCount
- Intro3Tor2WebClientActiveSuccessCircuitOutboundCellCount
- HSDir3Tor2WebClientActiveSuccessCircuitOutboundCellCount
- Rend2MultiHopClientActiveSuccessCircuitOutboundCellCount
- Intro2MultiHopClientActiveSuccessCircuitOutboundCellCount
- HSDir2MultiHopClientActiveSuccessCircuitOutboundCellCount
- Rend3MultiHopClientActiveSuccessCircuitOutboundCellCount
- Intro3MultiHopClientActiveSuccessCircuitOutboundCellCount
- HSDir3MultiHopClientActiveSuccessCircuitOutboundCellCount
- EntryActiveSuccessCircuitOutboundCellCount
- Rend2InactiveSuccessCircuitOutboundCellCount
- Intro2InactiveSuccessCircuitOutboundCellCount
- HSDir2InactiveSuccessCircuitOutboundCellCount
- Rend3InactiveSuccessCircuitOutboundCellCount
- Intro3InactiveSuccessCircuitOutboundCellCount
- HSDir3InactiveSuccessCircuitOutboundCellCount
- MidInactiveSuccessCircuitOutboundCellCount
- EndInactiveSuccessCircuitOutboundCellCount
- Rend2ServiceInactiveSuccessCircuitOutboundCellCount
- Intro2ServiceInactiveSuccessCircuitOutboundCellCount
- HSDir2ServiceInactiveSuccessCircuitOutboundCellCount
- Rend3ServiceInactiveSuccessCircuitOutboundCellCount
- Intro3ServiceInactiveSuccessCircuitOutboundCellCount
- HSDir3ServiceInactiveSuccessCircuitOutboundCellCount
- Rend2SingleOnionServiceInactiveSuccessCircuitOutboundCellCount
- Intro2SingleOnionServiceInactiveSuccessCircuitOutboundCellCount
- HSDir2SingleOnionServiceInactiveSuccessCircuitOutboundCellCount
- Rend3SingleOnionServiceInactiveSuccessCircuitOutboundCellCount
- Intro3SingleOnionServiceInactiveSuccessCircuitOutboundCellCount
- HSDir3SingleOnionServiceInactiveSuccessCircuitOutboundCellCount
- Rend2MultiHopServiceInactiveSuccessCircuitOutboundCellCount
- Intro2MultiHopServiceInactiveSuccessCircuitOutboundCellCount
- HSDir2MultiHopServiceInactiveSuccessCircuitOutboundCellCount
- Rend3MultiHopServiceInactiveSuccessCircuitOutboundCellCount
- Intro3MultiHopServiceInactiveSuccessCircuitOutboundCellCount
- HSDir3MultiHopServiceInactiveSuccessCircuitOutboundCellCount
- OriginInactiveSuccessCircuitOutboundCellCount
- SingleHopInactiveSuccessCircuitOutboundCellCount
- DirInactiveSuccessCircuitOutboundCellCount
- Rend2ClientInactiveSuccessCircuitOutboundCellCount
- Intro2ClientInactiveSuccessCircuitOutboundCellCount
- HSDir2ClientInactiveSuccessCircuitOutboundCellCount
- Rend3ClientInactiveSuccessCircuitOutboundCellCount
- Intro3ClientInactiveSuccessCircuitOutboundCellCount
- HSDir3ClientInactiveSuccessCircuitOutboundCellCount
- Rend2Tor2WebClientInactiveSuccessCircuitOutboundCellCount
- Intro2Tor2WebClientInactiveSuccessCircuitOutboundCellCount
- HSDir2Tor2WebClientInactiveSuccessCircuitOutboundCellCount
- Rend3Tor2WebClientInactiveSuccessCircuitOutboundCellCount
- Intro3Tor2WebClientInactiveSuccessCircuitOutboundCellCount
- HSDir3Tor2WebClientInactiveSuccessCircuitOutboundCellCount
- Rend2MultiHopClientInactiveSuccessCircuitOutboundCellCount
- Intro2MultiHopClientInactiveSuccessCircuitOutboundCellCount
- HSDir2MultiHopClientInactiveSuccessCircuitOutboundCellCount
- Rend3MultiHopClientInactiveSuccessCircuitOutboundCellCount
- Intro3MultiHopClientInactiveSuccessCircuitOutboundCellCount
- HSDir3MultiHopClientInactiveSuccessCircuitOutboundCellCount
- EntryInactiveSuccessCircuitOutboundCellCount
- Rend2ActiveFailureCircuitCount
- Intro2ActiveFailureCircuitCount
- HSDir2ActiveFailureCircuitCount
- Rend3ActiveFailureCircuitCount
- Intro3ActiveFailureCircuitCount
- HSDir3ActiveFailureCircuitCount
- MidActiveFailureCircuitCount
- EndActiveFailureCircuitCount
- Rend2ServiceActiveFailureCircuitCount
- Intro2ServiceActiveFailureCircuitCount
- HSDir2ServiceActiveFailureCircuitCount
- Rend3ServiceActiveFailureCircuitCount
- Intro3ServiceActiveFailureCircuitCount
- HSDir3ServiceActiveFailureCircuitCount
- Rend2SingleOnionServiceActiveFailureCircuitCount
- Intro2SingleOnionServiceActiveFailureCircuitCount
- HSDir2SingleOnionServiceActiveFailureCircuitCount
- Rend3SingleOnionServiceActiveFailureCircuitCount
- Intro3SingleOnionServiceActiveFailureCircuitCount
- HSDir3SingleOnionServiceActiveFailureCircuitCount
- Rend2MultiHopServiceActiveFailureCircuitCount
- Intro2MultiHopServiceActiveFailureCircuitCount
- HSDir2MultiHopServiceActiveFailureCircuitCount
- Rend3MultiHopServiceActiveFailureCircuitCount
- Intro3MultiHopServiceActiveFailureCircuitCount
- HSDir3MultiHopServiceActiveFailureCircuitCount
- OriginActiveFailureCircuitCount
- SingleHopActiveFailureCircuitCount
- DirActiveFailureCircuitCount
- Rend2ClientActiveFailureCircuitCount
- Intro2ClientActiveFailureCircuitCount
- HSDir2ClientActiveFailureCircuitCount
- Rend3ClientActiveFailureCircuitCount
- Intro3ClientActiveFailureCircuitCount
- HSDir3ClientActiveFailureCircuitCount
- Rend2Tor2WebClientActiveFailureCircuitCount
- Intro2Tor2WebClientActiveFailureCircuitCount
- HSDir2Tor2WebClientActiveFailureCircuitCount
- Rend3Tor2WebClientActiveFailureCircuitCount
- Intro3Tor2WebClientActiveFailureCircuitCount
- HSDir3Tor2WebClientActiveFailureCircuitCount
- Rend2MultiHopClientActiveFailureCircuitCount
- Intro2MultiHopClientActiveFailureCircuitCount
- HSDir2MultiHopClientActiveFailureCircuitCount
- Rend3MultiHopClientActiveFailureCircuitCount
- Intro3MultiHopClientActiveFailureCircuitCount
- HSDir3MultiHopClientActiveFailureCircuitCount
- EntryActiveFailureCircuitCount
- Rend2InactiveFailureCircuitCount
- Intro2InactiveFailureCircuitCount
- HSDir2InactiveFailureCircuitCount
- Rend3InactiveFailureCircuitCount
- Intro3InactiveFailureCircuitCount
- HSDir3InactiveFailureCircuitCount
- MidInactiveFailureCircuitCount
- EndInactiveFailureCircuitCount
- Rend2ServiceInactiveFailureCircuitCount
- Intro2ServiceInactiveFailureCircuitCount
- HSDir2ServiceInactiveFailureCircuitCount
- Rend3ServiceInactiveFailureCircuitCount
- Intro3ServiceInactiveFailureCircuitCount
- HSDir3ServiceInactiveFailureCircuitCount
- Rend2SingleOnionServiceInactiveFailureCircuitCount
- Intro2SingleOnionServiceInactiveFailureCircuitCount
- HSDir2SingleOnionServiceInactiveFailureCircuitCount
- Rend3SingleOnionServiceInactiveFailureCircuitCount
- Intro3SingleOnionServiceInactiveFailureCircuitCount
- HSDir3SingleOnionServiceInactiveFailureCircuitCount
- Rend2MultiHopServiceInactiveFailureCircuitCount
- Intro2MultiHopServiceInactiveFailureCircuitCount
- HSDir2MultiHopServiceInactiveFailureCircuitCount
- Rend3MultiHopServiceInactiveFailureCircuitCount
- Intro3MultiHopServiceInactiveFailureCircuitCount
- HSDir3MultiHopServiceInactiveFailureCircuitCount
- OriginInactiveFailureCircuitCount
- SingleHopInactiveFailureCircuitCount
- DirInactiveFailureCircuitCount
- Rend2ClientInactiveFailureCircuitCount
- Intro2ClientInactiveFailureCircuitCount
- HSDir2ClientInactiveFailureCircuitCount
- Rend3ClientInactiveFailureCircuitCount
- Intro3ClientInactiveFailureCircuitCount
- HSDir3ClientInactiveFailureCircuitCount
- Rend2Tor2WebClientInactiveFailureCircuitCount
- Intro2Tor2WebClientInactiveFailureCircuitCount
- HSDir2Tor2WebClientInactiveFailureCircuitCount
- Rend3Tor2WebClientInactiveFailureCircuitCount
- Intro3Tor2WebClientInactiveFailureCircuitCount
- HSDir3Tor2WebClientInactiveFailureCircuitCount
- Rend2MultiHopClientInactiveFailureCircuitCount
- Intro2MultiHopClientInactiveFailureCircuitCount
- HSDir2MultiHopClientInactiveFailureCircuitCount
- Rend3MultiHopClientInactiveFailureCircuitCount
- Intro3MultiHopClientInactiveFailureCircuitCount
- HSDir3MultiHopClientInactiveFailureCircuitCount
- EntryInactiveFailureCircuitCount
- Rend2ActiveCircuitCount
- Intro2ActiveCircuitCount
- HSDir2ActiveCircuitCount
- Rend3ActiveCircuitCount
- Intro3ActiveCircuitCount
- HSDir3ActiveCircuitCount
- MidActiveCircuitCount
- EndActiveCircuitCount
- Rend2ServiceActiveCircuitCount
- Intro2ServiceActiveCircuitCount
- HSDir2ServiceActiveCircuitCount
- Rend3ServiceActiveCircuitCount
- Intro3ServiceActiveCircuitCount
- HSDir3ServiceActiveCircuitCount
- Rend2SingleOnionServiceActiveCircuitCount
- Intro2SingleOnionServiceActiveCircuitCount
- HSDir2SingleOnionServiceActiveCircuitCount
- Rend3SingleOnionServiceActiveCircuitCount
- Intro3SingleOnionServiceActiveCircuitCount
- HSDir3SingleOnionServiceActiveCircuitCount
- Rend2MultiHopServiceActiveCircuitCount
- Intro2MultiHopServiceActiveCircuitCount
- HSDir2MultiHopServiceActiveCircuitCount
- Rend3MultiHopServiceActiveCircuitCount
- Intro3MultiHopServiceActiveCircuitCount
- HSDir3MultiHopServiceActiveCircuitCount
- OriginActiveCircuitCount
- SingleHopActiveCircuitCount
- DirActiveCircuitCount
- Rend2ClientActiveCircuitCount
- Intro2ClientActiveCircuitCount
- HSDir2ClientActiveCircuitCount
- Rend3ClientActiveCircuitCount
- Intro3ClientActiveCircuitCount
- HSDir3ClientActiveCircuitCount
- Rend2Tor2WebClientActiveCircuitCount
- Intro2Tor2WebClientActiveCircuitCount
- HSDir2Tor2WebClientActiveCircuitCount
- Rend3Tor2WebClientActiveCircuitCount
- Intro3Tor2WebClientActiveCircuitCount
- HSDir3Tor2WebClientActiveCircuitCount
- Rend2MultiHopClientActiveCircuitCount
- Intro2MultiHopClientActiveCircuitCount
- HSDir2MultiHopClientActiveCircuitCount
- Rend3MultiHopClientActiveCircuitCount
- Intro3MultiHopClientActiveCircuitCount
- HSDir3MultiHopClientActiveCircuitCount
- Rend2InactiveCircuitCount
- Intro2InactiveCircuitCount
- HSDir2InactiveCircuitCount
- Rend3InactiveCircuitCount
- Intro3InactiveCircuitCount
- HSDir3InactiveCircuitCount
- MidInactiveCircuitCount
- EndInactiveCircuitCount
- Rend2ServiceInactiveCircuitCount
- Intro2ServiceInactiveCircuitCount
- HSDir2ServiceInactiveCircuitCount
- Rend3ServiceInactiveCircuitCount
- Intro3ServiceInactiveCircuitCount
- HSDir3ServiceInactiveCircuitCount
- Rend2SingleOnionServiceInactiveCircuitCount
- Intro2SingleOnionServiceInactiveCircuitCount
- HSDir2SingleOnionServiceInactiveCircuitCount
- Rend3SingleOnionServiceInactiveCircuitCount
- Intro3SingleOnionServiceInactiveCircuitCount
- HSDir3SingleOnionServiceInactiveCircuitCount
- Rend2MultiHopServiceInactiveCircuitCount
- Intro2MultiHopServiceInactiveCircuitCount
- HSDir2MultiHopServiceInactiveCircuitCount
- Rend3MultiHopServiceInactiveCircuitCount
- Intro3MultiHopServiceInactiveCircuitCount
- HSDir3MultiHopServiceInactiveCircuitCount
- OriginInactiveCircuitCount
- SingleHopInactiveCircuitCount
- DirInactiveCircuitCount
- Rend2ClientInactiveCircuitCount
- Intro2ClientInactiveCircuitCount
- HSDir2ClientInactiveCircuitCount
- Rend3ClientInactiveCircuitCount
- Intro3ClientInactiveCircuitCount
- HSDir3ClientInactiveCircuitCount
- Rend2Tor2WebClientInactiveCircuitCount
- Intro2Tor2WebClientInactiveCircuitCount
- HSDir2Tor2WebClientInactiveCircuitCount
- Rend3Tor2WebClientInactiveCircuitCount
- Intro3Tor2WebClientInactiveCircuitCount
- HSDir3Tor2WebClientInactiveCircuitCount
- Rend2MultiHopClientInactiveCircuitCount
- Intro2MultiHopClientInactiveCircuitCount
- HSDir2MultiHopClientInactiveCircuitCount
- Rend3MultiHopClientInactiveCircuitCount
- Intro3MultiHopClientInactiveCircuitCount
- HSDir3MultiHopClientInactiveCircuitCount
- Rend2ActiveSuccessCircuitCount
- Intro2ActiveSuccessCircuitCount
- HSDir2ActiveSuccessCircuitCount
- Rend3ActiveSuccessCircuitCount
- Intro3ActiveSuccessCircuitCount
- HSDir3ActiveSuccessCircuitCount
- MidActiveSuccessCircuitCount
- EndActiveSuccessCircuitCount
- Rend2ServiceActiveSuccessCircuitCount
- Intro2ServiceActiveSuccessCircuitCount
- HSDir2ServiceActiveSuccessCircuitCount
- Rend3ServiceActiveSuccessCircuitCount
- Intro3ServiceActiveSuccessCircuitCount
- HSDir3ServiceActiveSuccessCircuitCount
- Rend2SingleOnionServiceActiveSuccessCircuitCount
- Intro2SingleOnionServiceActiveSuccessCircuitCount
- HSDir2SingleOnionServiceActiveSuccessCircuitCount
- Rend3SingleOnionServiceActiveSuccessCircuitCount
- Intro3SingleOnionServiceActiveSuccessCircuitCount
- HSDir3SingleOnionServiceActiveSuccessCircuitCount
- Rend2MultiHopServiceActiveSuccessCircuitCount
- Intro2MultiHopServiceActiveSuccessCircuitCount
- HSDir2MultiHopServiceActiveSuccessCircuitCount
- Rend3MultiHopServiceActiveSuccessCircuitCount
- Intro3MultiHopServiceActiveSuccessCircuitCount
- HSDir3MultiHopServiceActiveSuccessCircuitCount
- OriginActiveSuccessCircuitCount
- SingleHopActiveSuccessCircuitCount
- DirActiveSuccessCircuitCount
- Rend2ClientActiveSuccessCircuitCount
- Intro2ClientActiveSuccessCircuitCount
- HSDir2ClientActiveSuccessCircuitCount
- Rend3ClientActiveSuccessCircuitCount
- Intro3ClientActiveSuccessCircuitCount
- HSDir3ClientActiveSuccessCircuitCount
- Rend2Tor2WebClientActiveSuccessCircuitCount
- Intro2Tor2WebClientActiveSuccessCircuitCount
- HSDir2Tor2WebClientActiveSuccessCircuitCount
- Rend3Tor2WebClientActiveSuccessCircuitCount
- Intro3Tor2WebClientActiveSuccessCircuitCount
- HSDir3Tor2WebClientActiveSuccessCircuitCount
- Rend2MultiHopClientActiveSuccessCircuitCount
- Intro2MultiHopClientActiveSuccessCircuitCount
- HSDir2MultiHopClientActiveSuccessCircuitCount
- Rend3MultiHopClientActiveSuccessCircuitCount
- Intro3MultiHopClientActiveSuccessCircuitCount
- HSDir3MultiHopClientActiveSuccessCircuitCount
- EntryActiveSuccessCircuitCount
- Rend2InactiveSuccessCircuitCount
- Intro2InactiveSuccessCircuitCount
- HSDir2InactiveSuccessCircuitCount
- Rend3InactiveSuccessCircuitCount
- Intro3InactiveSuccessCircuitCount
- HSDir3InactiveSuccessCircuitCount
- MidInactiveSuccessCircuitCount
- EndInactiveSuccessCircuitCount
- Rend2ServiceInactiveSuccessCircuitCount
- Intro2ServiceInactiveSuccessCircuitCount
- HSDir2ServiceInactiveSuccessCircuitCount
- Rend3ServiceInactiveSuccessCircuitCount
- Intro3ServiceInactiveSuccessCircuitCount
- HSDir3ServiceInactiveSuccessCircuitCount
- Rend2SingleOnionServiceInactiveSuccessCircuitCount
- Intro2SingleOnionServiceInactiveSuccessCircuitCount
- HSDir2SingleOnionServiceInactiveSuccessCircuitCount
- Rend3SingleOnionServiceInactiveSuccessCircuitCount
- Intro3SingleOnionServiceInactiveSuccessCircuitCount
- HSDir3SingleOnionServiceInactiveSuccessCircuitCount
- Rend2MultiHopServiceInactiveSuccessCircuitCount
- Intro2MultiHopServiceInactiveSuccessCircuitCount
- HSDir2MultiHopServiceInactiveSuccessCircuitCount
- Rend3MultiHopServiceInactiveSuccessCircuitCount
- Intro3MultiHopServiceInactiveSuccessCircuitCount
- HSDir3MultiHopServiceInactiveSuccessCircuitCount
- OriginInactiveSuccessCircuitCount
- SingleHopInactiveSuccessCircuitCount
- DirInactiveSuccessCircuitCount
- Rend2ClientInactiveSuccessCircuitCount
- Intro2ClientInactiveSuccessCircuitCount
- HSDir2ClientInactiveSuccessCircuitCount
- Rend3ClientInactiveSuccessCircuitCount
- Intro3ClientInactiveSuccessCircuitCount
- HSDir3ClientInactiveSuccessCircuitCount
- Rend2Tor2WebClientInactiveSuccessCircuitCount
- Intro2Tor2WebClientInactiveSuccessCircuitCount
- HSDir2Tor2WebClientInactiveSuccessCircuitCount
- Rend3Tor2WebClientInactiveSuccessCircuitCount
- Intro3Tor2WebClientInactiveSuccessCircuitCount
- HSDir3Tor2WebClientInactiveSuccessCircuitCount
- Rend2MultiHopClientInactiveSuccessCircuitCount
- Intro2MultiHopClientInactiveSuccessCircuitCount
- HSDir2MultiHopClientInactiveSuccessCircuitCount
- Rend3MultiHopClientInactiveSuccessCircuitCount
- Intro3MultiHopClientInactiveSuccessCircuitCount
- HSDir3MultiHopClientInactiveSuccessCircuitCount
- EntryInactiveSuccessCircuitCount
