# PrivCount Counter Definitions

Each privcount counter is named after the information it collects (see
NamingCounters.markdown).

Some Tor network overheads (TorNetworkOverhead.markdown) are filtered out of
counters and counter events (TorEvents.markdown). In particular, all counters
exclude one-hop directory connections and circuits initated by the current
relay.

## Base Counts

This section describes the types of counters that are collected.

### Count

The number of Connections, Circuits, Streams, Cells, Bytes, or descriptor
Stores or Fetches seen by the relay.

Some overheads are excluded:
* Streams with zero (total read and write) or negative byte counts are ignored.
* Cell counts are not collected on Inactive Circuits.
* Byte counts for Exits exclude Tor cell overheads. Byte counts for other
  positions include Tor cell overheads, but exclude TLS, TCP, and IP overheads.

### Histogram

The number of Connections, Circuits, Streams, Cells, or Bytes seen as part of some
larger event by the relay.

### CountList

The Count of Connections, Circuits, Streams, Cells, Bytes, or descriptor
Stores seen by the relay, that match one of the lists configured on the
Tally Server.

### ClientIPCount

The number of unique Client IP addresses seen by the relay in each 10 minute
interval.

The IP addresses used in ClientIP counters are rotated every 10 minutes to
limit the number of Client IP addresses stored in memory. It takes 2
rotations for a Client IP address to be removed from memory.

### LifeTime

The number of seconds between the creation and destruction of the Connection,
Circuit, or Stream.

The precision is determined by the bins used to collect the counter. The
underlying event timestamps have microsecond precision. But the Tor event loop
only runs once per second, so sub-second bins are unlikely to be accurate or
meaningful.

### CircuitInterStreamCreationTime

The number of seconds between the creation of a Stream and the creation of the
next Stream on that Circuit. Circuits with zero or one Streams are excluded
from this counter.

See LifeTime for information about timestamp and event loop precision.

### Ratio

The base 2 log ratio of the Inbound and Outbound (see below) Cells or Bytes.
Uses the total Cells or Bytes over the life of the Circuit or Stream.

Calculated using log(Outbound/Inbound, 2), with the following boundary
conditions:
* 0.0 when Outbound equals Inbound,
* -.inf when Outbound is zero, and
* .inf when Inbound is zero.

### TrafficModelEmissionCount

The number of packets emitted by the relay.

The traffic model assumes each packet is at most 1500 bytes. Byte events are
split into packets, assuming no delay between emitted packets in the same byte
event.

### TrafficModelTransitionCount

The number of state transitions in the traffic model.

### TrafficModelLogDelayTime and TrafficModelSquaredLogDelayTime

The (squared) natural logarithm of the inter-packet delay time in microseconds.
These are derived from socket read/write timestamps, in a similar way to
InterStreamCreationTimes. Each socket read/write is then split on 1500 byte
boundaries into packets. The entire delay is assigned to the first packet in
the socket read/write.

Calculated using int(log(DelayTime, math.e)), with the following boundary
conditions:
* 0 when DelayTime is less than 1 microsecond.

For the Squared counter, the value is squared after truncation to an integer.

See LifeTime for information about timestamp and event loop precision.

### ZeroCount

A counter that is not incremented by any relay.

The aggregated value of this counter must be zero. A non-zero value indicates
that one or more Share Keepers or Data Collectors failed to provide results.

## Counter Variants and Sub-Categories

This section describes how some counters are split or filtered.

### Relay Position

This counter is only collected when the relay is in this position in the
Connection or Circuit.

Connections: Entry/NonEntry
* When Tor clients connect to the Tor network, they make an Entry Connection.
* When Tor relays connect to another relay, they make a NonEntry Connection.
  (The ends of the connection may be in the Entry, Mid or End position on
  different circuits.)

Circuits: Origin/Entry/Mid/End/SingleHop/Intro/Rend
* When Tor clients build a preemtive circuit, the client is in the Origin position, and relays
  are in the Entry, Mid, and End positions.
* When Tor clients build a non-anonymous directory circuit, the directory mirror is in
  the Entry, End, and SingleHop positions.
* When Tor relays act as a rehdezvous point, they join an IntroClient and IntroService
  circuit together, and relay cells between them.

Circuits and Streams: Exit/Dir/HSDir
* When Tor clients access a remote server, they make an Exit Stream.

Stores and Fetches: HSDir
* When Tor onion services upload a descriptor, they perform an HSDir Store.

### /Tor2Web/SingleOnion/MultiHop Client/Service

Each onion service circuit is being used by a Client or Service.

SingleHop onion service circuits are labelled as Tor2Web or SingleOnion.
MultiHop onion service circuits don't have special names.

### RelayOnAddress

An IP address can have clients (unauthenticated links) and relays
(authenticated links) on it.

EntryRelayOnAddressConnectionCount counts connections from clients that share
an address with relays.

EntryNoRelayOnAddressConnectionCount counts connections from clients that
don't share an address with relays.

### Active/Inactive

An Active Circuit is being used by a Tor client. Circuit Activity is only
checked when a Circuit ends.

The activity thresholds are:
* Origin, Entry, Mid, End, and SingleHop Circuit positions: 8 or more Cells were
                  transmitted over the Circuit. Uses the sum of Inbound and Outbound Cells.
* Intro and Rend Circuit positions: The circuit meets the 8 cell threshold, and both the
                  client and service are connected to the relay.
* Exit, Dir, and HSDir Circuits: 1 or more Streams were opened on the Circuit. Relays
                  can't distinguish between Exit and Dir circuits until a stream opens on the
                  circuit. So all Exit, Dir, and HSDir Circuits are considered active. (Use the
                  End position counters to find inactive, unused circuits.)
* Entry ClientIP counters: 1 or more active Entry Circuits closed in this rotation
                   period. If a client does not close any circuits, it is
                   not counted. If a client only closes inactive circuits, it
                   is inactive.

### Hidden Service Versions U/2/3

Intro and Rend Circuits can have Hidden Service Version 2, 3, or U (unknown).

The Hidden Service Version is always known for HSDir circuits.

### Stream Port

Stream sub-categories based on the remote port used by the Stream. A Circuit
can belong to multiple sub-categories based on its Streams: if it does,
its counters are incremented for each sub-category.

The sub-categories are:
* Interactive: ports typically used for low-latency connections
* P2P: ports typically used for bulk data transfer
* Web: ports typically used for web browsing
* OtherPort: any ports not listed in any other category
* NonWeb: all ports except Web ports

### Inbound/Outbound

The direction of Cell or Byte traffic on the Circuit or Stream.

Outbound data is sent away from the client, typically to an Exit.
Cells are read from the Exit's circuit with the client, and written as
Outbound Bytes to the Exit's edge connection. There are no Outbound Cells at
the End of a circuit.

Inbound data is sent to the client, typically from an Exit.
Bytes are read from the Exit's edge connection, and written to Inbound Cells.
There are no Inbound cells at the Origin of a circuit.

An Inbound circuit has a previous hop, which goes back to a client
(Entry/SingleHop) or relay (NonEntry/Middle/End).

An Outbound circuit has a next hop, which goes to another relay.

### Initial/Subsequent

Initial streams are the first stream on the circuit.

Subsequent streams are every other stream on the circuit.

### IPv4Literal/IPv6Literal/Hostname

The address sent by the client can be an IPv4 address, IPv6 address, or DNS
hostname.

### IPv4/IPv6

The IP address resolved by the Exit can be an IPv4 address or IPv6 address.

### Match/ExactMatch/SuffixMatch

When collecting a CountList:
* Country, AS, and Domain lists can be matched exactly (Match or ExactMatch)
* Domain lists can be matched by any suffix of the domain (SuffixMatch)

Country uses the remote IP address to look up countries in Tor's geoip files.

AS uses the remote IP address to look up AS numbers in the CAIDA IPv4 and IPv6
AS prefix databases.

Domain uses the DNS domain and does a case-insensitive (ExactMatch) or domain
component suffix match (SuffixMatch).

### Upload Delay Time

The difference between the DescriptorCreationTime, and the EventTimestamp.

The DescriptorCreationTime is truncated to the nearest hour, so this field
only captures significant delays.

### Add/Reject

Whether an onion service descriptor was added to the cache during an HSDir
Store.

The reasons that a descriptor may be added or rejected are documented in
doc/TorEvent.markdown.

### Cached/Uncached

Whether an existing onion service descriptor was present in the cache during
an HSDir Store or Fetch.

HSDir fetches treat uncached descriptors as a failure.

See the list of cache reasons in test/hsdir-*-reason.txt, or see CacheReasonString
in doc/TorEvents.markdown.

### Traffic Model Template Counters

The Traffic Model autogenerates a set of counters from counter templates.

These autogenerated Traffic Model counters are based on the static Traffic
Model counters, with a suffix containing underscore-separated state and
direction qualifiers.

The number of states and the state labels vary depending on the model.
The state labels used below are examples only.

Transition counters use these qualifiers:
* START/Thinking/Blabbing (Source State)
* Thinking/Blabbing (Destination State)

Transitions from the START state are not counted in
ExitStreamTrafficModelTransitionCount, but are counted in the
ExitStreamTrafficModelTransitionCount_START_* counters.

Emission and Delay counters use these qualifiers:
* Thinking/Blabbing/End (Current State)
* -/+/F (Direction)

The Traffic Model counters use '-' for Inbound, '+' for Outbound, and 'F' for
the End state.
