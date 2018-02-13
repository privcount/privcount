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

PrivCount version 2.0.0 changes the names of some counters, and changes the
format of the stream end event. Tally Servers and Data Collectors must run
version 2.0.0 or later of PrivCount and the PrivCount Tor Patch.

All PrivCount versions in a major series are compatible, as long as you are
collecting counters known to all nodes. For example, you can collect the
EntryActiveCircuitCount using a mix of nodes on any PrivCount 2.*.* version.

Data Collectors can use any PrivCount Tor Patch that supports the events for
the counters they are collecting. For example, you can collect the
EntryActiveCircuitCount using the PrivCount Tor Patch 1.0.0 or later.

Share Keepers on version 1.1.1 and later can store shares for any counters,
even counters introduced in subsequent Data Collector and Tally Server
versions (even versions 2.0.0 and later).

Tally Servers on version 1.0.2 and later ignore Data Collectors on versions
1.0.1 and earlier, because they have a critical security issue.

The PrivCount Tor Patch may be available for multiple tor versions:
 * Tor relays on 0.3.0.8 and later are used for v3 HSDir
 * Tor relays on 0.3.0.4-alpha and later are used for v3 Intro in ed25519
   authentication mode (earlier versions are used in legacy mode)
 * Tor relays on 0.2.9.1-alpha and later are used for v3 Rend

In general, you should use the latest Tor version.

## Who wrote PrivCount?

Authors are listed in CONTRIBUTORS.markdown

## How can I use PrivCount?

Since PrivCount 1.0.0, PrivCount has been distributed under a modified 3-clause
BSD license. See LICENSE for details.

# Release History

Issue numbers are from:
    https://github.com/privcount/privcount/issues

## PrivCount 2.0.1 and 1.1.1

These bugfix versions of PrivCount:
* make ShareKeepers ignore traffic models, fixing bug #493,
* add some additional warnings when a round fails to start,
* ensure that run_test.sh installs the currently checked-out version.

## PrivCount 2.0.0

PrivCount version 2.0.0 changes the names of some counters, and changes the
format of the stream end event. Tally Servers and Data Collectors must run
version 2.0.0 or later of PrivCount and the PrivCount Tor Patch.

It also adds a dependency on pyasn.

It adds the following counters:
* Onion Service Failures,
* Exit Domain Names and Domain Suffixes,
* Client Autonomous System Numbers,
* Client Countries.

It contains important fixes for the Tally Server, Data Collectors, and the
PrivCount Tor patch. All PrivCount node operators and relay operators should
upgrade.

The version of the PrivCount Tor Patch released with PrivCount 2.0.0 is:
* privcount-2.0.0-tor-0.3.0.13-dev (Tor stable, with additional patches)

This Tor version fixes several relay security issues.
See Tor's release announcements for details:
https://blog.torproject.org/new-stable-tor-releases-security-fixes-0319-03013-02914-02817-02516

A full list of issues resolved in this release is available at:
https://github.com/privcount/privcount/milestone/2?closed=1

## PrivCount 1.1.0

PrivCount 1.1.0 adds support for Onion Service Directory Descriptor
Store events. It extends the Circuit event to support the Onion Service HSDir,
Intro and Rend positions, and the Mid and Dir positions. All Onion Service
events support versions 2 and 3, and distinguish between them where possible.

This release also allows PrivCount to sample high-volume events from Tor,
and allows multiple Data Collectors to collect from the same Tor instance.

It contains important fixes for all PrivCount node roles and the PrivCount
Tor patch. All PrivCount node operators and relay operators should upgrade.

The version of the PrivCount Tor Patch released with PrivCount 1.1.0 is:
* privcount-1.1.0-tor-0.3.0.10 (Tor stable)

These Tor versions fix the following Tor relay issues:
* an assertion failure OpenBSD relays in response to client input
* process termination by the Linux sandbox with some IPv6 configs, and
  some Data Directory configs

See Tor's release announcements for details:
https://blog.torproject.org/tor-0309-released-security-update-clients
https://blog.torproject.org/tor-03010-released

Features:
* Add the PRIVCOUNT_HSDIR_CACHE_STORE event to the PrivCount Tor Patch #336
* Add 107 HSDir{2,3}Store counters to PrivCount #336

* Add the PRIVCOUNT_CIRCUIT_CELL event to the PrivCount Tor Patch #368
* Extend the circuit termination event by adding PRIVCOUNT_CIRCUIT_CLOSE #368
* Add 19 Circuit and Cell counters to PrivCount #375
* Add byte counters for non-Exit circuits #192, #248

* Add HSDir, Intro, and Rend to the position weights script #289, #397
* Add version 3 Onion Services to the position weights script #404, #416

* Allow PrivCount to limit cell events from Tor #405, #418
* Allow multiple Data Collectors to use the same Tor instance #365
* Use tagged fields for new events #256
* Create counter variants for new counters from template strings #229

Counter Fixes:
* Actually allow Share Keepers to process unknown counters #406
  Bugfix on #340 in 1.0.1
* Distinguish Exit Circuits using BEGIN cells #384
* Allow DCs to be excluded by specifying no noise weight #415

Stability Fixes:
* Make Tor version parsing more reliable #363. Bugfix on #307 in 1.0.0.
  Likely triggered by #361 in 1.0.2
* Handle tor relays that haven't bootstrapped yet #364
  Bugfix on #361 in 1.0.2
* Distinguish between a missing nickname and an unknown nickname #366
  Bugfix on 1.0.0
* Always check if EnablePrivCount is on before starting a collection #365
* Allow Data Collectors to recover from failed rounds #407
* Allow Tally Servers to add keys to their config while running #399
* Update the default check-in period to 10 minutes #378
* Increase the maximum tor event length to 2kB #336
* Improve dummy counter handling

Logging:
* Display the last character in the string when summarising #396
* Make delay period warnings INFO-level when a safe default is used #379
* Improve config validation #376, #427

Testing:
* Check all events are tested and documented when running tests #347
* Add privcount/tools/add_counter.sh to generate test configs #336, #386
* Make run_test.sh's quiet mode much quieter

Documentation:
* Explain how to INSTALL newer OpenSSL versions #380
* Document cell and circuit events #370, #414
* Improve the release instructions in PrivCountVersion.markdown
*  Add a missing ExecStartPre line in the systemd file

A full list of issues resolved in this release is available at:
https://github.com/privcount/privcount/milestone/9?closed=1

## PrivCount 1.0.2

PrivCount 1.0.2 fixes a critical Data Collector security bug, where noise
was not being added to the results. It also fixes several logging bugs on
all node types: Tally Servers should upgrade for this fix.

All PrivCount Data Collectors shoudld erase the results of collections made
with version 1.0.0 or version 1.0.1 Data Collectors, and upgrade before
running any more collections.

PrivCount Tally Servers on 1.0.2 and later refuse to use insecure Data
Collectors with PrivCount versions 1.0.0 and 1.0.1. Share Keepers and the
PrivCount Tor Patch are not affected by this restriction.

There are no changes in the PrivCount Tor Patch for PrivCount 1.0.2.
Please use the PrivCount Tor Patch 1.0.1 with PrivCount 1.0.2 Data Collectors.

Security:
* Actually add noise to counts on DCs. Bugfix on PrivCount 1.0.0 #360
* Check that secure counters have generated noise before producing results #360
* Make tally servers reject insecure Data Collector versions #360

Deployment:
* Add an example script and crontab entry for launching nodes on boot #354

Logging:
* Downgrade warnings in the git revision check to info level #353
* Add log messages on more failures, summarise other log messages #357
* Downgrade warnings when DCs are not expecting events #361
* Add the relay flags to the results context #361

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
