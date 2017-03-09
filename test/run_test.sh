#!/bin/bash

# Shell settings
# fail on failed commands or unset variables
set -e
set -u
# the exit status of a pipe is the last non-zero exit, or zero if all succeed
set -o pipefail
# report background exit statuses immediately
set -b

# Set default option values if empty (:) or unset (-)
# PrivCount itself
PRIVCOUNT_INSTALL=${PRIVCOUNT_INSTALL:-0}
PRIVCOUNT_DIRECTORY=${PRIVCOUNT_DIRECTORY:-.}
PRIVCOUNT_SOURCE=${PRIVCOUNT_SOURCE:-inject}

# Inject source
PRIVCOUNT_ROUNDS=${PRIVCOUNT_ROUNDS:-2}
PRIVCOUNT_UNIT_TESTS=${PRIVCOUNT_UNIT_TESTS:-1}

# Tor source
# use the chutney tor dir, or assume privcount-tor is beside privcount
PRIVCOUNT_TOR_DIR=${PRIVCOUNT_TOR_DIR:-${TOR_DIR:-../../tor-privcount/}}
# Don't run make by default
PRIVCOUNT_TOR_MAKE=${PRIVCOUNT_TOR_MAKE:-0}
# allow the torrc to be the empty string (which means "no torrc")
PRIVCOUNT_TORRC=${PRIVCOUNT_TORRC-torrc}
# make the data directory a new temp directory by default
PRIVCOUNT_TOR_DATADIR=${PRIVCOUNT_TOR_DATADIR:-`mktemp -d`}

# internal: not configurable via a command-line argument or the environment
# use --tor-dir instead
PRIVCOUNT_TOR_BINARY=src/or/tor
PRIVCOUNT_TOR_GENCERT_BINARY=src/tools/tor-gencert

# Chutney source
# use the chutney path, or assume chutney is beside privcount
PRIVCOUNT_CHUTNEY_PATH=${PRIVCOUNT_CHUTNEY_PATH:-${CHUTNEY_PATH:-../../chutney/}}
PRIVCOUNT_CHUTNEY_FLAVOUR=${PRIVCOUNT_CHUTNEY_FLAVOUR:-${NETWORK_FLAVOUR:-basic-min}}
# the relay control ports opened by the selected chutney flavour
# this must be manually kept in sync with PRIVCOUNT_CHUTNEY_FLAVOUR
# basic-min has 3 relays/authorities and starts at controlport_base (8000)
PRIVCOUNT_CHUTNEY_PORTS=${PRIVCOUNT_CHUTNEY_PORTS:-`seq 8000 8002`}
PRIVCOUNT_CHUTNEY_CONNECTIONS=${PRIVCOUNT_CHUTNEY_CONNECTIONS:-${CHUTNEY_CONNECTIONS:-1}}
# The chutney default is 10KB, we use 1KB to make counts easy to check
PRIVCOUNT_CHUTNEY_BYTES=${PRIVCOUNT_CHUTNEY_BYTES:-${CHUTNEY_DATA_BYTES:-1024}}
# other chutney environmental variables are listed in tools/test-network.sh

# internal: not configurable via command-line arguments
# can be set in the environment
PRIVCOUNT_CHUTNEY_LAUNCH=${PRIVCOUNT_CHUTNEY_LAUNCH:-tools/test-network.sh}
PRIVCOUNT_CHUTNEY_WARNINGS=${PRIVCOUNT_CHUTNEY_WARNINGS:-tools/warnings.sh}

# Process arguments
until [ "$#" -le 0 ]
do
  case "$1" in
    --install|-I)
      PRIVCOUNT_INSTALL=1
      ;;
    --no-unit-tests|-x)
      PRIVCOUNT_UNIT_TESTS=0
      ;;
    --rounds|-r)
      PRIVCOUNT_ROUNDS=$2
      shift
      ;;
    --source|-s)
      PRIVCOUNT_SOURCE=$2
      shift
      ;;
    --tor-dir|-t)
      PRIVCOUNT_TOR_DIR=$2
      shift
      ;;
    --make-tor|-m)
      PRIVCOUNT_TOR_MAKE=1
      ;;
    --torrc|-f)
      PRIVCOUNT_TORRC=$2
      shift
      ;;
    --tor-datadir|-d)
      PRIVCOUNT_TOR_DATADIR=$2
      shift
      ;;
    --chutney-path|-c)
      PRIVCOUNT_CHUTNEY_PATH=$2
      shift
      ;;
    --chutney-flavour|-n)
      PRIVCOUNT_CHUTNEY_FLAVOUR=$2
      shift
      ;;
    --chutney-ports|-p)
      PRIVCOUNT_CHUTNEY_PORTS=""
      while [ $# -ge 2 ] && [[ "$2" =~ [0-9]* ]]; do
        PRIVCOUNT_CHUTNEY_PORTS="$PRIVCOUNT_CHUTNEY_PORTS $2"
        shift
      done
      ;;
    --chutney-connections|-o)
      PRIVCOUNT_CHUTNEY_CONNECTIONS=$2
      shift
      ;;
    --chutney-bytes|-b)
      PRIVCOUNT_CHUTNEY_BYTES=$2
      shift
      ;;
    --help|-h)
      echo "usage: $0 [...] [<privcount-directory>] -- [<data-source-args...>]"
      echo "  -I: run 'pip install -I <privcount-directory>' before testing"
      echo "    default: $PRIVCOUNT_INSTALL (1: install, 0: don't install) "
      echo "  -x: skip unit tests"
      echo "    default: '$PRIVCOUNT_UNIT_TESTS' (1: run, 0: skip)"
      echo "  -r rounds: run this many rounds before stopping"
      echo "    default: '$PRIVCOUNT_ROUNDS' (set to 1 for tor and chutney)"
      echo "  -s source: use inject, chutney, or tor as the data source"
      echo "    default: '$PRIVCOUNT_SOURCE'"
      echo "    inject: use 'privcount inject' on test/events.txt"
      echo "    tor: use a privcount-patched tor binary"
      echo "    chutney: use a chutney network with a privcount-patched tor"
      echo "  -t tor-dir: use the privcount-patched tor binary in tor-dir/$PRIVCOUNT_TOR_BINARY"
      echo "    default: '$PRIVCOUNT_TOR_DIR'"
      echo "  -m: run make on tor-path before testing (sources: tor, chutney)"
      echo "    default: '$PRIVCOUNT_TOR_MAKE' (0: no make, 1: make)"
      echo "  -f torrc-path: launch tor with the torrc at torrc-path"
      echo "    an empty torrc path '' means 'no torrc file'"
      echo "    default: '$PRIVCOUNT_TORRC'"
      echo "  -d datadir-path: launch tor with the data directory datadir-path"
      echo "    default: a new temp directory" # $PRIVCOUNT_TOR_DATADIR
      echo "  -c chutney-path: launch chutney from chutney-path/$PRIVCOUNT_CHUTNEY_LAUNCH_SCRIPT"
      echo "    default: '$PRIVCOUNT_CHUTNEY_PATH'"
      echo "  -n chutney-flavour: launch chutney with chutney-flavour"
      echo "    default: '$PRIVCOUNT_CHUTNEY_FLAVOUR'"
      echo "  -p chutney-port ... : launch a data collector for each port"
      echo "    use: \`seq 8000 finish-port\` to generate a list"
      echo "    default: '$PRIVCOUNT_CHUTNEY_PORTS'"
      echo "  -o chutney-connections: make chutney-connections per client"
      echo "    default: '$PRIVCOUNT_CHUTNEY_BYTES'"
      echo "  -b chutney-bytes: verify chutney-bytes per client connection"
      echo "    default: '$PRIVCOUNT_CHUTNEY_BYTES'"
      echo "  <privcount-directory>: the directory privcount is in"
      echo "    default: '$PRIVCOUNT_DIRECTORY'"
      echo "  <data-source-args...>: arguments appended to the data source"
      echo "    defaults:"
      echo "      inject first round: port 20003, password auth"
      echo "      inject next rounds: unix /tmp/privcount-inject, cookie auth"
      echo "      tor single round: port 20003, cookie auth"
      echo "      chutney single round: chutney basic-min ports, cookie auth"
      echo "Relative paths are supported."
      echo "Paths with special characters or spaces are not supported."
      exit 0
      ;;
    --)
      # leave any remaining arguments for the data source
      shift
      break
      ;;
    *)
      PRIVCOUNT_DIRECTORY=$1
      ;;
  esac
  shift
done

# Data source commands

# Inject Source

# We can either test --simulate, and get partial data, or get full data
# It's better to get full data
INJECT_BASE_CMD="privcount inject --log events.txt"

# The commands for IP port connection and password authentication
INJECT_PORT_CMD="$INJECT_BASE_CMD --port 20003 --control-password keys/control_password.txt $@"

# The command for unix socket connection and safecookie authentication
# The injector automatically writes its own cookie file, just like tor
INJECT_UNIX_CMD="$INJECT_BASE_CMD --unix /tmp/privcount-inject --control-cookie-file /tmp/privcount-control-auth-cookie $@"

# logs go to standard output/error and need no special treatment
INJECT_LOG_CMD=true

# Uses the standard test config
INJECT_CONFIG=config.yaml

# Tor Source

# Find tor
PRIVCOUNT_TOR=$PRIVCOUNT_TOR_DIR/$PRIVCOUNT_TOR_BINARY

# The command to start a tor relay
# Sets the data directory to a newly created temporary directory (by default)
# Uses a torrc with the same control port as the injector (if set)
# Appends any remaining command-line arguments
TOR_CMD="$PRIVCOUNT_TOR DataDirectory $PRIVCOUNT_TOR_DATADIR ${PRIVCOUNT_TORRC+-f $PRIVCOUNT_TORRC} $@"

# logs go to standard output/error and need no special treatment
# TODO: write to file and ignore standard warnings when displaying messages?
TOR_LOG_CMD=true
#TOR_LOG_CMD="grep -v -e TODO '$TOR_LOG_PATH'"

# Uses the standard test config
# TODO: write a config with longer rounds
TOR_CONFIG=config.tor.yaml

# Chutney Source

# Give chutney the environmental variables it needs
export TOR_DIR=${PRIVCOUNT_TOR_DIR:-$TOR_DIR}
export CHUTNEY_PATH=${PRIVCOUNT_CHUTNEY_PATH:-$CHUTNEY_PATH}
export NETWORK_FLAVOUR=${PRIVCOUNT_CHUTNEY_FLAVOUR:-$NETWORK_FLAVOUR}
export CHUTNEY_CONNECTIONS=${PRIVCOUNT_CHUTNEY_CONNECTIONS:-$CHUTNEY_CONNECTIONS}
export CHUTNEY_DATA_BYTES=${PRIVCOUNT_CHUTNEY_BYTES:-$CHUTNEY_DATA_BYTES}

# The command to start a tor test network using chutney
CHUTNEY_TEST_NETWORK=$PRIVCOUNT_CHUTNEY_PATH/$PRIVCOUNT_CHUTNEY_LAUNCH
# Needs to know all the variables listed above
CHUTNEY_CMD="$CHUTNEY_TEST_NETWORK --all-warnings $@"

# Recent chutney versions log warnings automatically, but we want a summary
# at the end of the script output
CHUTNEY_LOG_CMD="$CHUTNEY_PATH/tools/warnings.sh"

# A config template: we need one config per data collector
CHUTNEY_CONFIG=config.chutney.yaml

# Now select the source command
echo "Selecting data source $PRIVCOUNT_SOURCE..."

case "$PRIVCOUNT_SOURCE" in
  inject)
    FIRST_ROUND_CMD=$INJECT_PORT_CMD
    OTHER_ROUND_CMD=$INJECT_UNIX_CMD
    LOG_CMD=$INJECT_LOG_CMD
    CONFIG=$INJECT_CONFIG
    ;;
  tor)
    FIRST_ROUND_CMD=$TOR_CMD
    # only supports 1 round, fail if we try to have more
    OTHER_ROUND_CMD=false
    LOG_CMD=$TOR_LOG_CMD
    CONFIG=$TOR_CONFIG
    PRIVCOUNT_ROUNDS=1
    ;;
  chutney)
    FIRST_ROUND_CMD=$CHUTNEY_CMD
    # only supports 1 round, fail if we try to have more
    OTHER_ROUND_CMD=false
    LOG_CMD=$CHUTNEY_LOG_CMD
    CONFIG=$CHUTNEY_CONFIG
    PRIVCOUNT_ROUNDS=1
    ;;
  *)
    echo "Source $PRIVCOUNT_SOURCE not supported."
    exit 1
    ;;
esac

# source the venv if it exists
if [ -f "$PRIVCOUNT_DIRECTORY/venv/bin/activate" ]; then
    echo "Using virtualenv in venv..."
    set +u
    . "$PRIVCOUNT_DIRECTORY/venv/bin/activate"
    set -u
fi

if [ "$PRIVCOUNT_INSTALL" -eq 1 ]; then
  # Install the latest requirements
  # Unfortunately, this doesn't work on my OS X install without sudo
  #echo "Installing requirements from '$PRIVCOUNT_DIRECTORY' ..."
  #pip install -r "$PRIVCOUNT_DIRECTORY/requirements.txt"

  # Install the latest privcount version
  echo "Installing latest version of privcount from '$PRIVCOUNT_DIRECTORY' ..."
  pip install -I "$PRIVCOUNT_DIRECTORY"
fi

if [ "$PRIVCOUNT_TOR_MAKE" -eq 1 ]; then
  # Recompile Tor, if needed
  # assume standard tor source directory structure
  TOR_MAKE_DIR=`dirname "$PRIVCOUNT_TOR"`/../..
  case "$PRIVCOUNT_SOURCE" in
    inject)
      # nothing
      ;;
    tor)
      echo "Making tor binary in '$TOR_MAKE_DIR' ..."
      make -C "$TOR_MAKE_DIR" "$PRIVCOUNT_TOR_BINARY"
      ;;
    chutney)
      # chutney needs tor-gencert as well as tor
      echo "Making tor binaries in '$TOR_MAKE_DIR' ..."
      make -C "$TOR_MAKE_DIR" "$PRIVCOUNT_TOR_BINARY" \
        "$PRIVCOUNT_TOR_GENCERT_BINARY"
      ;;
    *)
      echo "Source $PRIVCOUNT_SOURCE not supported."
      exit 1
      ;;
  esac
fi

# From this point onwards, the script assumes it's in the test directory
cd "$PRIVCOUNT_DIRECTORY/test"

if [ "$PRIVCOUNT_UNIT_TESTS" -eq 1 ]; then
  # Run the python-based unit tests
  echo "Testing time formatting:"
  python test_format_time.py
  echo ""

  echo "Testing encryption:"
  python test_encryption.py
  echo ""

  echo "Testing random numbers:"
  python test_random.py
  echo ""

  echo "Testing counters:"
  python test_counter.py
  echo ""

  echo "Testing traffic model:"
  python test_traffic_model.py
  echo ""

  echo "Testing noise:"
  python ../privcount/tools/compute_noise.py

  # Requires a local privcount-patched Tor instance
  #python test_tor_ctl_event.py
fi

# Execute this command to produce a numeric unix timestamp in seconds
TIMESTAMP_COMMAND="date +%s"
DATE_COMMAND="date"
# Record how long the tests take to run
"$DATE_COMMAND"
STARTSEC="`$TIMESTAMP_COMMAND`"

# Move aside the old result files
echo "Moving old results files to '$PRIVCOUNT_DIRECTORY/test/old' ..."
mkdir -p old
# Save the commands for re-use during multiple round tests
MOVE_JSON_COMMAND="mv privcount.*.json old/"
MOVE_PDF_COMMAND="mv privcount.*.pdf old/"
MOVE_LOG_COMMAND="mv privcount.*.log old/"
# Clean up before running the test
$MOVE_JSON_COMMAND || true
# If the plot libraries are not installed, this will always fail
$MOVE_PDF_COMMAND 2> /dev/null || true
$MOVE_LOG_COMMAND || true

# Generate a log file name
# Usage:
# > `log_file_name privcount_command timestamp` 2>&1
# 2>&1 | tee `log_file_name privcount_command timestamp`
# Takes two arguments: the privcount command (inject, ts, sk, dc) and the unix
# timestamp for the log
# Outputs a string containing the log file name
# Doesn't handle arguments with spaces
function log_file_name() {
  PRIVCOUNT_COMMAND="$1"
  FILE_TIMESTAMP="$2"
  echo "privcount.$PRIVCOUNT_COMMAND.$FILE_TIMESTAMP.log"
}

# Save a command's output in a log file
# Usage:
# privcount privcount_command args 2&>1 | \
#   `save_to_log privcount_command timestamp`
# Takes two arguments: the privcount command (inject, ts, sk, dc) and the unix
# timestamp for the log
# Outputs a command that logs the output of a command to a file, and also
# echoes it to standard output
# Doesn't handle arguments with spaces
function save_to_log() {
  SAVE_LOG_COMMAND="tee"
  PRIVCOUNT_COMMAND="$1"
  FILE_TIMESTAMP="$2"
  FILE_NAME=`log_file_name "$PRIVCOUNT_COMMAND" "$FILE_TIMESTAMP"`
  echo "$SAVE_LOG_COMMAND $FILE_NAME"
}

# Then run the ts, sk, dc, and injector
echo "Launching $PRIVCOUNT_SOURCE, tally server, share keeper, and data collector..."
# This won't match the timestamp logged by the TS, because the TS waits before
# starting the round
LOG_TIMESTAMP="$STARTSEC"
ROUNDS=1

# Launch commands
case "$PRIVCOUNT_SOURCE" in
  inject)
    # Prepare for password authentication: the data collector and injector both
    # read this file
    echo "Generating random password file for injector..."
    cat /dev/random | hexdump -e '"%x"' -n 32 -v > keys/control_password.txt
    # standard launch commands
    privcount ts "$CONFIG" 2>&1 | `save_to_log ts $LOG_TIMESTAMP` &
    privcount sk "$CONFIG" 2>&1 | `save_to_log sk $LOG_TIMESTAMP` &
    privcount dc "$CONFIG" 2>&1 | `save_to_log dc $LOG_TIMESTAMP` &
    $FIRST_ROUND_CMD 2>&1 | \
        `save_to_log $PRIVCOUNT_SOURCE.$ROUNDS $LOG_TIMESTAMP` &
    ;;
  tor)
    # standard launch commands
    privcount ts "$CONFIG" 2>&1 | `save_to_log ts $LOG_TIMESTAMP` &
    privcount sk "$CONFIG" 2>&1 | `save_to_log sk $LOG_TIMESTAMP` &
    privcount dc "$CONFIG" 2>&1 | `save_to_log dc $LOG_TIMESTAMP` &
    $FIRST_ROUND_CMD 2>&1 | \
        `save_to_log $PRIVCOUNT_SOURCE.$ROUNDS $LOG_TIMESTAMP` &
    ;;
  chutney)
    # clean up the whitespace in the port list
    PRIVCOUNT_CHUTNEY_PORTS=`echo -n $PRIVCOUNT_CHUTNEY_PORTS | xargs`
    # work out how many ports there are
    CHUTNEY_PORT_ARRAY=( $PRIVCOUNT_CHUTNEY_PORTS )
    CHUTNEY_PORT_COUNT=${#CHUTNEY_PORT_ARRAY[@]}
    TEMPLATE_CONFIG=$CONFIG
    # launch one DC per port
    for CHUTNEY_PORT in ${CHUTNEY_PORT_ARRAY[@]} ; do
      CONFIG=$TEMPLATE_CONFIG.$CHUTNEY_PORT
      echo "Generating config for chutney port $CHUTNEY_PORT..."
      cp "$TEMPLATE_CONFIG" "$CONFIG"
      sed -i "" -e "s/CHUTNEY_PORT_COUNT/$CHUTNEY_PORT_COUNT/g" "$CONFIG"
      sed -i "" -e "s/CHUTNEY_PORT/$CHUTNEY_PORT/g" "$CONFIG"
      privcount dc "$CONFIG" 2>&1 | `save_to_log dc $LOG_TIMESTAMP` &
    done
    # launch the TS expecting the right number of DCs
    # (the config number does not matter)
    privcount ts "$CONFIG" 2>&1 | `save_to_log ts $LOG_TIMESTAMP` &
    # the SK doesn't care how many DCs there are
    privcount sk "$CONFIG" 2>&1 | `save_to_log sk $LOG_TIMESTAMP` &
    # The chutney output is very verbose: don't save it to the log
    $FIRST_ROUND_CMD 2>&1
    echo -n | `save_to_log $PRIVCOUNT_SOURCE.$ROUNDS $LOG_TIMESTAMP` &
    ;;
  *)
    echo "Source $PRIVCOUNT_SOURCE not supported."
    exit 1
    ;;
esac

# Then wait for each job, terminating if any job produces an error
# Ideally, we'd want to use wait, or wait $job, but that only checks one job
# at a time, so continuing processes can cause the script to run forever
echo "Waiting for PrivCount to finish..."
JOB_STATUS=`jobs`
echo "$JOB_STATUS"
while echo "$JOB_STATUS" | grep -q "Running"; do
  # fail if any job has failed
  if echo "$JOB_STATUS" | grep -q "Exit"; then
    # and kill everything
    echo "Error: Privcount or $PRIVCOUNT_SOURCE process exited with error..."
    pkill -P $$
    exit 1
  fi
  # succeed if an outcome file is produced
  if [ -f privcount.outcome.*.json ]; then
    if [ $ROUNDS -lt $PRIVCOUNT_ROUNDS ]; then
      echo \
         "Moving round $ROUNDS results to '$PRIVCOUNT_DIRECTORY/test/old' ..."
      $MOVE_JSON_COMMAND || true
      # If the plot libraries are not installed, this will always fail
      $MOVE_PDF_COMMAND 2> /dev/null || true
      ROUNDS=$[$ROUNDS+1]
      echo "Launching $PRIVCOUNT_SOURCE for round $ROUNDS..."
      $OTHER_ROUND_CMD 2>&1 | \
        `save_to_log $PRIVCOUNT_SOURCE.$ROUNDS $LOG_TIMESTAMP` &
    else
      break
    fi
  fi
  sleep 3
  JOB_STATUS=`jobs`
  echo "$JOB_STATUS"
done

# Measure how long the actual tests took
ENDDATE="`$DATE_COMMAND`"
ENDSEC="`$TIMESTAMP_COMMAND`"

# And terminate all the privcount processes
echo "Terminating privcount and $PRIVCOUNT_SOURCE after $ROUNDS round(s)..."
pkill -P $$

# Symlink a timestamped file to a similarly-named "latest" file
# Usage:
# link_latest prefix suffix
# Takes two arguments: the prefix and the suffix, in a filename like:
# privcount.prefix.timestamp.suffix
# Doesn't handle arguments with spaces
function link_latest() {
  PREFIX="$1"
  SUFFIX="$2"
  GLOB_PATTERN=privcount.$PREFIX.*.$SUFFIX
  LATEST_NAME=privcount.$PREFIX.latest.$SUFFIX
  if [ -f $GLOB_PATTERN ]; then
    ln -s $GLOB_PATTERN $LATEST_NAME
  else
    echo "Error: No $PREFIX $SUFFIX file produced."
    exit 1
  fi
}

# If an outcome file was produced, keep a link to the latest file
link_latest outcome json

# If a traffic model file was produced, keep a link to the latest file
link_latest traffic.model json

# If a tallies file was produced, keep a link to the latest file, and plot it
link_latest tallies json
if [ -f privcount.tallies.latest.json ]; then
  echo "Plotting results..."
  # plot will fail if the optional dependencies are not installed
  # tolerate this failure, and shut down the privcount processes
  privcount plot -d privcount.tallies.latest.json data 2>&1 | \
    `save_to_log plot $LOG_TIMESTAMP` || true
fi

# If log files were produced, keep a link to the latest files
link_latest ts log
link_latest sk log
link_latest dc log
for round_number in `seq $PRIVCOUNT_ROUNDS`; do
  link_latest $PRIVCOUNT_SOURCE.$round_number log
done

# Show the differences between the latest and old latest outcome files
if [ -e privcount.outcome.latest.json -a \
     -e old/privcount.outcome.latest.json ]; then
  # there's no point in comparing the tallies JSON or results PDF
  echo "Comparing latest outcomes file with previous outcomes file..."
  # skip expected differences due to time or network jitter
  # PrivCount is entirely deterministic: if there are any other differences,
  # they are due to code changes, or are a bug, or need to be filtered out here
  diff --minimal --unified=10 \
    -I "time" -I "[Cc]lock" -I "alive" -I "rtt" -I "Start" -I "Stop" \
    -I "[Dd]elay" -I "Collect" -I "End" -I "peer" -I "fingerprint" \
    old/privcount.outcome.latest.json privcount.outcome.latest.json || true
else
  # Since we need old/latest and latest, it takes two runs to generate the
  # first outcome file comparison
  echo "Warning: Outcomes files could not be compared."
  echo "$0 must be run twice to produce the first comparison."
fi

# Show the differences between the latest and old latest traffic model files
if [ -e privcount.traffic.model.latest.json -a \
     -e old/privcount.traffic.model.latest.json ]; then
  echo "Comparing latest traffic model with previous traffic model..."
  # PrivCount is entirely deterministic: if there are any other differences,
  # they are due to code changes, or are a bug, or need to be filtered out here
  diff --minimal --unified=10 \
    old/privcount.traffic.model.latest.json \
    privcount.traffic.model.latest.json || true
else
  # Since we need old/latest and latest, it takes two runs to generate the
  # first traffic model file comparison
  echo "Warning: traffic model files could not be compared."
  echo "$0 must be run twice to produce the first comparison."
fi

# Grep the warnings out of the log files
# $LOG_CMD displays warnings from all logs produced by the chutney data source
# We don't diff the previous log files with the latest log files, because many
# of the timestamps and other irrelevant details are different
echo "Extracting warnings from privcount and $PRIVCOUNT_SOURCE output..."
grep -v -e NOTICE -e INFO -e DEBUG \
  -e "seconds of user activity" -e "delay_period not specified" \
  -e notice \
  -e "Path for PidFile" -e "Your log may contain" \
  privcount.*.latest.log \
  || true
# Log any source-specific warnings
# Summarise unexpected chutney warnings
CHUTNEY_WARNINGS_IGNORE_EXPECTED=true CHUTNEY_WARNINGS_SUMMARY=true $LOG_CMD

# Show how long it took
echo "$ENDDATE"
ELAPSEDSEC=$[ $ENDSEC - $STARTSEC ]
echo "Seconds Elapsed: $ELAPSEDSEC for $ROUNDS round(s)"
