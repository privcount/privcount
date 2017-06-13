# Tor Network Overhead

The Tor network transfers TCP streams. Exits connect Client streams to
arbitrary remote Internet services, and Hidden Services connect Client streams
to a particular service, which may or may not be Internet-accessible.

The Tor network also has the following overheads:

## General Overheads

In general, PrivCount ignores some invalid events, such as DNS resolution
failures. It also ignores or has incomplete data for some events where the
relevant hooks have not yet been implemented.

In general, PrivCount counts every time a tor client attempts an action. This
may include retries if the action fails.

## Directory

Tor's directory documents are used by clients to locate relays and build
circuits.

### Relay Descriptor Uploads

Tor relays upload their descriptors to the directory authorities via a direct
HTTP POST.

### Voting and Consensus Signatures

Tor directory authorities vote and sign consensuses every hour via a direct
HTTP POST.

### Directory Downloads

Relays and clients download directory documents from directory mirrors, either
over a one-hop BEGINDIR connection, or an unencrypted HTTP GET via the DirPort.

### Bandwidth Authorities

Bandwidth authorities build 2-hop paths through a relay and an exit, and check
the speed of the connection.

## Client

### Preemptive Circuits

Clients keep a small number of circuits open to speed up application requests.

## Relay

### ORPort Self-Checks

Relays create a 2-hop path to their own ORPort, and wait until they receive
a remote connection.

### ORPort Bandwidth Checks

Relays create a 2-hop path to their own ORPort, and transfer cells to measure
their own bandwidth.

### DirPort Self-Checks

Directory mirrors create a 3-hop path to their own DirPort, and download their
own descriptor.

## Onion Routing

### Authentication

Tor sends CERTS and AUTH* cells to authenticate to relays.

### Metadata

Tor sends VERSIONS and NETINFO cells.

### Circuit Management

Tor sends CREATE* and DESTROY cells to manage circuits.

### Data Flow Management

Tor sends SENDME cells to request more data.

### Padding

Tor automatically drops [V]PADDING cells: upcoming versions of tor may send
these cells by default. Tor also drops RELAY_DROP cells.

### Data Cell Overhead

Each cell contains a variable-length header depending on the cell type.
RELAY_DATA cells typically have 16 bytes of overhead (out of 514 bytes).

## Exit

### DNS Resolution

Exits perform DNS resolution on hostnames supplied by clients. CONNECT requests
connect the stream to the remote server. RESOLVE requests return the IP address
to the client.

### Exit Mapping

Tor runs a service which connects to every exit and discovers its exit IP
addresses.
