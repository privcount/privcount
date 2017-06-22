# PrivCount Release Notes

## What is PrivCount?

PrivCount makes Tor statistics collection more secure. PrivCount produces
totals across all participating relays. Noise is added to each total to hide
typical user activity.

## Should I Run PrivCount?

Don't run PrivCount unless you enjoy running experimental code.
It has several known accuracy, security, scaling and robustness issues.

Be careful collecting and releasing PrivCount results: the configured noise
and the length of collection must protect user privacy.
(If you don't know what this means, find out before running PrivCount!)

## Are different PrivCount versions compatible?

All PrivCount versions in a major series are compatible, as long as you are
collecting counters known to all nodes. For example, you can collect the
EntryActiveCircuitCount using a mix of nodes on any PrivCount 1.*.* version.

Share Keepers on version 1.0.1 and later can store shares for any counters,
even counters introduced in subsequent Data Collector and Tally Server
versions.

Data Collectors can use any PrivCount Tor Patch that supports the events for
the counters they are collecting. For example, you can collect the
EntryActiveCircuitCount using the PrivCount Tor Patch 1.0.0 or later. The
PrivCount Tor Patch may be available for multiple tor versions: any tor version
can be used.

## Who wrote PrivCount?

Authors are listed in CONTRIBUTORS.markdown

## How can I use PrivCount?

Since PrivCount 1.0.0, PrivCount has been distributed under a modified 3-clause
BSD license. See LICENSE for details.

# Release History

Issue numbers are from:
    https://github.com/privcount/privcount/issues

## PrivCount 1.0.2

PrivCount 1.0.2 fixes a critical Data Collector security bug, where noise
was not being added to the results. It also fixes a logging bug on Data
Collectors and Tally Servers.

All PrivCount Data Collectors shoudld erase the results of collections made
with version 1.0.0 or version 1.0.1 Data Collectors, and upgrade before
running any more collections.

The versions of the PrivCount Tor Patch released with PrivCount 1.0.2 are
the same as those released with PrivCount 1.0.1. Please use the 1.0.1 tags.

Security:
* Actually add noise to counts on DCs. Bugfix on PrivCount 1.0.0 #360
* Check that secure counters have generated noise before producing results #360
* Make tally servers reject insecure Data Collector versions #360

Deployment:
* Add an example script and crontab entry for launching nodes on boot #354

Logging:
* Downgrade warnings in the git revision check to info level #353
* Add log messages on more failures, summarise other log messages #357

Testing:
* Create a directory required by the unit and integration tests #352
* Improve injector and tor shutdown behaviour in integration tests #358

Documentation:
* Minor documentation updates #340, #350

A full list of issues resolved in this release is available at:
https://github.com/privcount/privcount/milestone/6?closed=1

## PrivCount 1.0.1

PrivCount 1.0.1 fixes a Share Keeper forward-compatibility issue, and makes
other minor accuracy, compatibility and documentation fixes.

PrivCount 1.0.1 is compatible with PrivCount 1.0.0.
PrivCount 1.0.1 Share Keepers are forward-compatible with counters introduced
in later versions.

The versions of the PrivCount Tor Patch released with PrivCount 1.0.1 are:
* privcount-1.0.1-tor-0.3.0.8 (Tor stable)
* privcount-1.0.1-tor-0.2.9.11 (Tor LTS)

All PrivCount relay operators should upgrade.

These Tor versions fix:
* multiple relay connection issues
* HSDir3 descriptor upload issues (0.3.0.8 only)
* undefined behaviour parsing geoip6 files

See Tor's release announcement for details:
https://blog.torproject.org/blog/tor-0308-released-fix-hidden-services-also-are-02429-02514-02612-0278-02814-and-02911

Compatibility:
* Make Share Keepers accept blinding shares containing counters introduced in
  later PrivCount versions #340
* Make shell scripts run on systems that don't have bash in /bin #334

Accuracy:
* Count zero EntryClientIPActiveCircuitCounts and
  EntryClientIPInactiveCircuitCounts, rather than ignoring them #306
* Stop filtering BadExits from non-exit positions in the weights script #346

Documentation:
* Revise the Data Collector section in DEPLOY.markdown #339
* Document PrivCount's torrc reload behaviour in TorEvents.markdown #327
* Document minor inaccuracies in PrivCount's statistics #349, #350

A full list of issues resolved in this release is available at:
https://github.com/privcount/privcount/milestone/10?closed=1

## PrivCount 1.0.0

PrivCount 1.0.0 is a major rewrite of the PrivCount codebase, focusing on
accuracy, security, robustness, and documentation.

PrivCount 1.0.0 requires Python 2.7's automatic long integer support, and
OpenSSL 1.0.2 and cryptography >= 1.4 for encryption padded using SHA256.
For other dependencies, see INSTALL.markdown.

As of release 1.0.0, PrivCount uses Semantic Versioning. Patch versions are
compatible, and minor versions are compatible as long as no new features are
used. See http://semver.org for details.

The PrivCount Tor Patch is versioned using the PrivCount release version, and
the underlying Tor version. The versions of the PrivCount Tor Patch released
with PrivCount 1.0.0 are:
* privcount-1.0.0-tor-0.3.0.7 (Tor stable)
* privcount-1.0.0-tor-0.2.9.10 (Tor LTS)

PrivCount 1.0.0 is not compatible with PrivCount 0.1.1 or 0.1.0.

Features:
* Traffic Model Statistics: PrivCount updates the probabilities in an initial
  traffic model based on observed stream packet sizes and inter-packet delays.
  (This feature is experimental: event processing is delayed when large
  streams end. Tor will store events in RAM until processing resumes. This
  may cause out of memory errors in Tor. Expected additional RAM usage is
  150 MB - 2.5 GB per Tor process for a 1 GB stream.) #19

* Add the following counters:
  * ZeroCount #1
  * ExitStreamLifeTime #269
  * ExitCircuitLifeTime, ExitInactiveCircuitLifeTime #128
* PrivCount's counters were renamed using a consistent naming scheme #228
* PrivCount now uses Python longs for counters, rather than floats. This
  allows integer-accurate counts for values exceeding 10**15. This
  feature requires Python 2.7's automatic long support #18, #40
* Add the remote hostname and IP address to the stream end event #178
* PrivCount's event subsystem was rewritten, allowing Data Collectors to
  request only the events required for the current collection #99, #100

* The Tally Server can calculate sigma values from configured expected values
  and sensitivities #9
* The Tally Server can configure the counters and noise for each round,
  without configuration updates on Data Collectors or Share Keepers #44
* The Tally Server adds comprehensive contextual information to the round
  outcomes file #6, #81

* Unit and Integration Testing: PrivCount has an expanded and improved test
  suite. See test/README.markdown and test/run_test.sh --help for details
* A test report is available in doc/CounterTests.markdown #261
* PrivCount can now log in quiet mode (-q) as well as at info and debug levels
  #160
* PrivCount's existing documentation has been rewritten and expanded.
  See README.markdown, INSTALL.markdown, DEPLOY.markdown, and the doc
  subdirectory.

Accuracy:
* Consistently exclude overheads in cell counters, byte counters, and events
  #230
* Stop counting BEGINDIR connections, circuits, streams, cells, and bytes
   #230, #244
* Accurately identify clients, relays, and exit destinations #199, #255
* Stop overwriting remote IP addresses in circuit events #243
* Remove bias towards long-running events #305, #308
* Include Exit streams on port 1 #190
* Include zero Inbound bytes in Ratio counters #278
* The DNS Resolved event now contains a timestamp. (PrivCount does not
  request or parse this event) #249
* Document which overheads are excluded in doc/TorNetworkOverhead.markdown #191

Security:
* PrivCount Share Keepers enforce a minimum delay when noise allocations change
  between rounds. This protects a certain level of user activity #22
* Data Collectors check various counter properties before starting collection.
  See doc/CounterChecks.markdown for details #75

* PrivCount supports the following Tor Control Port features:
  * Unix Sockets #134
  * Password Authentication #140
  * Safe Cookie Authentication #140
  This allows relay operators to use more secure methods to access the control
  port.

* PrivCount samples noise values using a uniformly distributed
  cryptographically secure pseudo-random number generator (CSPRNG). This
  replaces a SHA1-based hash construction that only blinded the lower 32-bits
  of each counter #34, #37, #65
* Replace OAEP/MGF1/SHA1 with OAEP/MGF1/SHA256 in PrivCount's public key
  encryption. This requires OpenSSL 1.0.2 and cryptography >= 1.4 #46
* Use fernet symmetric encryption to encrypt and decrypt unlimited amounts of
  data. The fernet keys are encrypted using public key encryption #37, #46
* Rewrite the PrivCount handshake using a SHA256-based hash construction
  similar to the Tor Control Protocol handshake. Clients must know the shared
  key to connect to the Tally Server #53, #78
* Use a CSPRNG for the PrivCount handshake. This replaces random.random() #52

* Avoid processing untrusted YAML from the network. This prevents object
  deserialisation attacks #79

Robustness:
* Stop creating multiple protocol instances when the control connection breaks
  #327
* Stop considering clients dead when their IP address changes #318
* Make clients try to checkin multiple times #274

* Enforce a maximum line length when parsing Tor Control Port protocol
  responses #284
* Increase the maximum PrivCount protocol line length to allow for large
  Traffic Models #270

* PrivCount now logs more helpful messages when things go wrong
* Report Data Collector failures earlier and in more detail #304
* PrivCount reports the versions of the PrivCount Node, Tor Patch and Tor in
  log messages and as part of the checkin context #307
* The Tally Server warns if a Data Collector never received any events #304
* PrivCount stops when major errors occur #148

A full list of issues resolved in this release is available at:
https://github.com/privcount/privcount/milestone/1?closed=1

## PrivCount 0.1.1

PrivCount version 0.1.1 removes a compiler warning introduced in
PrivCount Tor Patch 0.1.0.

The version of the PrivCount Tor Patch released with PrivCount 0.1.1 was:
* privcount-0.1.1-tor-0.2.7.6

## PrivCount 0.1.0

PrivCount 0.1.0 is an initial, independent implementation of the PrivEx Secret
Sharing (S2) variant. See README.markdown for more details.

The major features in version 0.1.0 are:
* PrivCount can aggregate a large variety of statistical counts from Tor,
* PrivCount provides differential privacy guarantees.

The version of the PrivCount Tor Patch released with PrivCount 0.1.0 was:
* privcount-0.1.0-tor-0.2.7.6

This version was used to collect the data used in the "Safely Measuring Tor"
paper.
