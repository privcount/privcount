# PrivCount Counter Checks

PrivCount checks counter configurations when it loads counters, and before
a round starts.

## Initial Checks

PrivCount performs various counter sanity checks to guard against errors.

PrivCount checks the following counter properties:
* every time the config is loaded (Tally Server), or
* at the start of every round (Share Keeper, Data Collector).

If these checks fail, the configuration is rejected and no collection occurs.

### Counters

Each counter counts events in a set of bins.

* Each counter name must be in the list of valid counter names.  
  (This list can have counters added to it at runtime by the Traffic Model).  
  This check is only performed by the Tally Server and Data Collector.  
  Share Keepers will accept any counter names: this allows older Share Keeper  
  versions to be used with newer Tally Server and Data Collector versions.
* Counters for bins and sigmas must match

### Noise

Each counter has noise added to it when it is initialised by the data
collector.

#### Noise Weights

The noise weight reflects how much a client's activity is expected to change
the counter.

* Each noise weight is a non-negative decimal value
* The total noise weight is less than the maximum counter value

#### Sigmas

The sigma determines how much noise is added to a counter.

* Sigma counters must have a sigma element
* Each sigma is a non-negative decimal value

### Bins

The bins determine how events are aggregated in the counter.

* Bin counters must have a bins element
* Each bins element must have at least one bin
* Bins have lower and upper bounds which are decimal values  
  (including positive and negative infinity)
* The upper bound is strictly greater than the lower bound
* The bins in a counter must not overlap (but there may be gaps)

### Periods

The periods determine how often nodes communicate, and how long rounds last.

#### Collect Period

Data Collectors collect events for collect period seconds. Tor generates these
events in response to network activity, and PrivCount increments counter(s) in
response to the events it receives.

```
tally_server:
  collect_period: 86400
```

* the collect period must be a non-negative integer
* a collect period shorter than 4 seconds does not work reliably

#### Event Period

The tally server runs its main loop every event period. The main loop checks
for config file changes, responds to Data Collector and Share Keeper status
updates, and initiates or terminates rounds.

```
tally_server:
  event_period: 600
```

* the event period must be a non-negative integer
* there must be at least two event periods in each collect period
* event periods shorter than 2 seconds do not work reliably

#### Checkin Period

Data Collectors and Share Keepers connect to the Tally Server and tell it they
are still active every checkin period. These status events also contain
information about the client's state.

```
tally_server:
  checkin_period: 60
```

* the checkin period must be a non-negative integer
* the checkin period should be less than or equal to the event period  
  (checkin periods longer than the event period cause client status update
  delays)
* there must be at least two checkin periods in each collect period
* checkin periods shorter than 2 seconds do not work reliably

#### Delay Period

If the noise allocation changes, the Share Keepers enforce a delay period
between consecutive rounds.

```
tally_server:
  delay_period: 86400
data_collector:
  delay_period: 86400
share_keeper:
  delay_period: 86400
```

* the delay period must be a non-negative integer
* PrivCount warns if the delay period is very short

### Node Thresholds

The node thresholds determine when rounds are run. The Tally Server does not
start the round until both node thresholds are met: that is, the number of
ShareKeepers and Data Collectors is greater than or equal to their respective
thresholds.

### Data Collector Threshold

* the data collector threshold is an integer
* the data collector threshold must be at least 1
* the data collector threshold must not exceed a sensible maximum

### Share Keeper Threshold

* the share keeper threshold is an integer
* the share keeper threshold must be at least 1

### Round Continuation

The tally server will launch new rounds if configured to do so.

```
tally_server:
  continue: True
```

* continue must be True or False

*OR*

```
tally_server:
  continue: 10
```

* continue must be a non-negative integer

The tally server runs this many rounds (if an integer) or runs until the
config is updated (if True). If the config is updated with False, it stops
after the current round, if updated with a number, it stops after that many
rounds have run. At least one round is always run.

## Round Start Checks

PrivCount enforces a delay between rounds when the noise allocation changes.
The delay protects user activity from being revealed.

PrivCount checks the following counter properties:
* at the start of every round.

The SKs must enforce these checks for the protocol to be secure. In the
current implementation, all nodes perform these checks.

If there has been no previous round, or there is no next round, these checks
are skipped.

If these checks fail, the node enforces a delayed start for the next round.
(This is the time the round actually finished, rather than the time the tally
server requested the round stop.) The amount of delay is controlled by the
delay period config option.

A delay of *N* seconds protects that many seconds worth of user activity.
(It should be set based on average Tor usage by a single user, and the
desired amount of activity protected by differential privacy.)

### Counters

Adding or removing a counter changes the noise allocation, and requires a
delay.

* The set of counters is the same as those in the previous round

### Noise

Changing the noise allocation requires a delay.

#### Sigmas

Decreasing a sigma changes the noise allocation, and requires a delay.
(Increasing a sigma adds extra noise, and is therefore safe.)

* Each sigma is greater than or equal to the previous sigma for that counter  

A configurable sigma decrease tolerance allows for floating-point inaccuracy,
but new values are always compared with the values from the initial round, to
avoid counter creep. An enforced delay resets the initial round to the current
one.

```
tally_server:
  sigma_decrease_tolerance: 1.0e-6
data_collector:
  sigma_decrease_tolerance: 1.0e-6
share_keeper:
  sigma_decrease_tolerance: 1.0e-6
```

### Always Delaying a Round

The always_delay config option always delays the next round, regardless of the
noise allocation. It is intended for use in testing.

```
tally_server:
  always_delay: True
data_collector:
  always_delay: True
share_keeper:
  always_delay: True
```
