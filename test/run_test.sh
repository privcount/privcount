#!/bin/bash
# See LICENSE for licensing information

# Shell settings
# fail on failed commands or unset variables
set -e
set -u
# the exit status of a pipe is the last non-zero exit, or zero if all succeed
set -o pipefail
# report background exit statuses immediately
set -b

# Set default option values if empty (:) or unset (-)

# OpenSSL
PRIVCOUNT_OPENSSL=${PRIVCOUNT_OPENSSL:-openssl}

# PrivCount itself
PRIVCOUNT_INSTALL=${PRIVCOUNT_INSTALL:-0}
TEST_DIR=`dirname "$0"`
export PRIVCOUNT_DIRECTORY=${PRIVCOUNT_DIRECTORY:-`dirname "$TEST_DIR"`}
PRIVCOUNT_SOURCE=${PRIVCOUNT_SOURCE:-inject}
PRIVCOUNT_SHARE_KEEPERS=${PRIVCOUNT_SHARE_KEEPERS:-1}
PRIVCOUNT_UNIT_TESTS=${PRIVCOUNT_UNIT_TESTS:-1}
PRIVCOUNT_PLOT=${PRIVCOUNT_PLOT:-1}
PRIVCOUNT_LOG=${PRIVCOUNT_LOG:-""}
# The default is to echo info and warning messages
I="echo"
W="echo"

# Inject source
PRIVCOUNT_ROUNDS=${PRIVCOUNT_ROUNDS:-2}

# Tor source
# use the chutney tor dir, or assume privcount-tor is beside privcount
PRIVCOUNT_TOR_DIR=${PRIVCOUNT_TOR_DIR:-${TOR_DIR:-`dirname "$0"`/../../tor-privcount/}}
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
PRIVCOUNT_CHUTNEY_PATH=${PRIVCOUNT_CHUTNEY_PATH:-${CHUTNEY_PATH:-`dirname "$0"`/../../chutney/}}
PRIVCOUNT_CHUTNEY_FLAVOUR=${PRIVCOUNT_CHUTNEY_FLAVOUR:-${NETWORK_FLAVOUR:-basic-min}}
# the relay control ports opened by the selected chutney flavour
# this must be manually kept in sync with PRIVCOUNT_CHUTNEY_FLAVOUR
# basic-min has 3 relays/authorities and starts at controlport_base (8000)
PRIVCOUNT_CHUTNEY_PORTS=${PRIVCOUNT_CHUTNEY_PORTS:-`seq 8000 8002 | tr '\n' ' '`}
# Connections are simultaneous, rounds are sequential
PRIVCOUNT_CHUTNEY_CONNECTIONS=${PRIVCOUNT_CHUTNEY_CONNECTIONS:-${CHUTNEY_CONNECTIONS:-1}}
PRIVCOUNT_CHUTNEY_ROUNDS=${PRIVCOUNT_CHUTNEY_ROUNDS:-${CHUTNEY_ROUNDS:-1}}
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
    --no-plot|-z)
      PRIVCOUNT_PLOT=0
      ;;
    --debug|-v)
      PRIVCOUNT_LOG="-v"
      ;;
    --warn|--warning|-q)
      PRIVCOUNT_LOG="-q"
      ;;
    --rounds|-r)
      PRIVCOUNT_ROUNDS=$2
      shift
      ;;
    --source|-s)
      PRIVCOUNT_SOURCE=$2
      shift
      ;;
    --share-keepers|-k)
      PRIVCOUNT_SHARE_KEEPERS=$2
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
      while [ $# -ge 2 ] && [[ "$2" =~ [0-9][0-9]* ]]; do
        PRIVCOUNT_CHUTNEY_PORTS="$PRIVCOUNT_CHUTNEY_PORTS $2"
        shift
      done
      ;;
    --chutney-connections|-o)
      PRIVCOUNT_CHUTNEY_CONNECTIONS=$2
      shift
      ;;
    --chutney-rounds|-u)
      PRIVCOUNT_CHUTNEY_ROUNDS=$2
      shift
      ;;
    --chutney-bytes|-b)
      PRIVCOUNT_CHUTNEY_BYTES=$2
      shift
      ;;
    --help|-h)
      "$W" "usage: $0 [...] [<privcount-directory>] -- [<data-source-args...>]"
      "$W" "  -I: run 'pip install -I <privcount-directory>' before testing"
      "$I" "    default: $PRIVCOUNT_INSTALL (1: install, 0: don't install) "
      "$W" "  -x: skip unit tests"
      "$I" "    default: '$PRIVCOUNT_UNIT_TESTS' (1: run, 0: skip)"
      "$W" "  -z: skip plot"
      "$I" "    default: '$PRIVCOUNT_PLOT' (1: run, 0: skip)"
      "$W" "  -v: verbose logging"
      "$W" "  -q: quiet logging"
      "$I" "    default: '$PRIVCOUNT_LOG' ('': standard (info) level logging)"
      "$W" "  -r rounds: run this many rounds before stopping"
      "$I" "    default: '$PRIVCOUNT_ROUNDS' (1 for tor and chutney)"
      "$W" "  -s source: use inject, chutney, or tor as the data source"
      "$I" "    default: '$PRIVCOUNT_SOURCE'"
      "$I" "    inject: use 'privcount inject' on test/events.txt"
      "$I" "    tor: use a privcount-patched tor binary"
      "$I" "    chutney: use a chutney network with a privcount-patched tor"
      "$W" "  -k sks: run this many share keepers"
      "$I" "    default: '$PRIVCOUNT_SHARE_KEEPERS'"
      "$W" "  -t tor-dir: use the privcount-patched tor binary in tor-dir/$PRIVCOUNT_TOR_BINARY"
      "$I" "    default: '$PRIVCOUNT_TOR_DIR'"
      "$W" "  -m: run make on tor-path before testing (sources: tor, chutney)"
      "$I" "    default: '$PRIVCOUNT_TOR_MAKE' (0: no make, 1: make)"
      "$W" "  -f torrc-path: launch tor with the torrc at torrc-path"
      "$I" "    an empty torrc path '' means 'no torrc file'"
      "$I" "    default: '$PRIVCOUNT_TORRC'"
      "$W" "  -d datadir-path: launch tor with the data directory datadir-path"
      "$I" "    default: a new temp directory" # $PRIVCOUNT_TOR_DATADIR
      "$W" "  -c chutney-path: launch chutney from chutney-path/chutney"
      "$I" "    default: '$PRIVCOUNT_CHUTNEY_PATH'"
      "$W" "  -n chutney-flavour: launch chutney with chutney-flavour"
      "$I" "    default: '$PRIVCOUNT_CHUTNEY_FLAVOUR'"
      "$W" "  -p chutney-port ... : launch a data collector for each port"
      "$I" "    use: \`seq 8000 finish-port\` to generate a list"
      "$I" "    default: '$PRIVCOUNT_CHUTNEY_PORTS'"
      "$W" "  -o chutney-connections: make chutney-connections per client"
      "$I" "    Each connection to the chutney data source uses one stream."
      "$I" "    Chutney opens these streams simultanously."
      "$I" "    default: '$PRIVCOUNT_CHUTNEY_CONNECTIONS'"
      "$W" "  -u chutney-rounds: run chutney-rounds verification rounds"
      "$I" "    Chutney runs rounds sequentially.."
      "$I" "    default: '$PRIVCOUNT_CHUTNEY_ROUNDS'"
      "$W" "  -b chutney-bytes: verify chutney-bytes per client connection"
      "$I" "    default: '$PRIVCOUNT_CHUTNEY_BYTES'"
      "$W" "  <privcount-directory>: the directory privcount is in"
      "$I" "    default: '$PRIVCOUNT_DIRECTORY'"
      "$W" "  <data-source-args...>: arguments appended to the data source"
      "$I" "    defaults:"
      "$I" "      inject first round: port 20003, password auth"
      "$I" "      inject next rounds: unix /tmp/privcount-inject, cookie auth"
      "$I" "      tor single round: port 20003, cookie auth"
      "$I" "      chutney single round: chutney basic-min ports, cookie auth"
      "$I" "Relative paths are supported."
      "$W" "Paths with special characters or spaces are not supported."
      exit 0
      ;;
    --)
      # leave any remaining arguments for the data source
      shift
      break
      ;;
    *)
      export PRIVCOUNT_DIRECTORY=$1
      ;;
  esac
  shift
done

# Set subdirectory paths
TEST_DIR="$PRIVCOUNT_DIRECTORY/test"
TOOLS_DIR="$PRIVCOUNT_DIRECTORY/privcount/tools"

# The logging option for this script itself
case "$PRIVCOUNT_LOG" in
  -q)
    I="true"
    ;;
  "")
    # do nothing by default
    ;;
  -v)
    # do nothing, it's already pretty verbose
    ;;
  *)
    "$W" "Logging level $PRIVCOUNT_LOG not supported."
    exit 1
    ;;
esac

# Data source commands

# Inject Source

# We can either test --simulate, and get partial data, or get full data
# It's better to get full data
INJECT_BASE_CMD="privcount $PRIVCOUNT_LOG inject --log $TEST_DIR/events.txt"

# The commands for IP port connection and password authentication
INJECT_PORT_CMD="$INJECT_BASE_CMD --port 20003 --control-password $TEST_DIR/keys/control_password.txt $@"

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

# the default is Log notice stderr
TOR_LOG=""
# The logging option for tor
case "$PRIVCOUNT_LOG" in
  -q)
    TOR_LOG="--hush"
    ;;
  "")
    # do nothing by default
    ;;
  -v)
    # we want info, not debug
    TOR_LOG="--Log 'info stderr'"
    ;;
  *)
    "$W" "Logging level $PRIVCOUNT_LOG not supported."
    exit 1
    ;;
esac

# The command to start a tor relay
# Sets the data directory to a newly created temporary directory (by default)
# Uses a torrc with the same control port as the injector (if set)
# Appends any remaining command-line arguments
TOR_CMD="$PRIVCOUNT_TOR DataDirectory $PRIVCOUNT_TOR_DATADIR ${PRIVCOUNT_TORRC+-f $TEST_DIR/$PRIVCOUNT_TORRC} $TOR_LOG $@"

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
export CHUTNEY_ROUNDS=${PRIVCOUNT_CHUTNEY_ROUNDS:-$CHUTNEY_ROUNDS}
export CHUTNEY_DATA_BYTES=${PRIVCOUNT_CHUTNEY_BYTES:-$CHUTNEY_DATA_BYTES}

# The command to start a tor test network using chutney
CHUTNEY_TEST_NETWORK=$PRIVCOUNT_CHUTNEY_PATH/$PRIVCOUNT_CHUTNEY_LAUNCH

# when running, we make chutney log all warnings
CHUTNEY_LOG_DURING="--all-warnings"
# at the end, we use chutney's default unexpected warning mode
CHUTNEY_LOG_END=""
# The logging option for chutney
case "$PRIVCOUNT_LOG" in
  -q)
    # defaults to summarising unexpected warnings
    CHUTNEY_LOG_DURING="--quiet"
    # don't duplicate the warnings at the end 
    CHUTNEY_LOG_END="--quiet --no-warnings"
    ;;
  "")
    # do nothing by default
    ;;
  -v)
    CHUTNEY_LOG_DURING="--debug --all-warnings"
    CHUTNEY_LOG_END="--all-warnings"
    ;;
  *)
    "$W" "Logging level $PRIVCOUNT_LOG not supported."
    exit 1
    ;;
esac

# Needs to know all the variables listed above
CHUTNEY_CMD="$CHUTNEY_TEST_NETWORK $CHUTNEY_LOG_DURING $@"

# Recent chutney versions log warnings automatically, but we want a summary
# at the end of the script output
CHUTNEY_LOG_CMD="$CHUTNEY_TEST_NETWORK --only-warnings $CHUTNEY_LOG_END"

# A config template: we need one config per data collector
CHUTNEY_CONFIG=config.chutney.yaml

# Now select the source command
"$I" "Selecting data source $PRIVCOUNT_SOURCE..."

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
    PRIVCOUNT_ROUNDS=1
    LOG_CMD=$TOR_LOG_CMD
    CONFIG=$TOR_CONFIG
    ;;
  chutney)
    FIRST_ROUND_CMD=$CHUTNEY_CMD
    # only supports 1 round, fail if we try to have more
    OTHER_ROUND_CMD=false
    PRIVCOUNT_ROUNDS=1
    LOG_CMD=$CHUTNEY_LOG_CMD
    CONFIG=$CHUTNEY_CONFIG
    ;;
  *)
    "$W" "Source $PRIVCOUNT_SOURCE not supported."
    exit 1
    ;;
esac

# source the venv if it exists
if [ -f "$PRIVCOUNT_DIRECTORY/venv/bin/activate" ]; then
    "$I" "Using virtualenv in venv..."
    set +u
    . "$PRIVCOUNT_DIRECTORY/venv/bin/activate"
    set -u
fi

if [ "$PRIVCOUNT_INSTALL" -eq 1 ]; then
  # Install the latest requirements
  # Unfortunately, this doesn't work on my OS X install without sudo
  #"$I" "Installing requirements from '$PRIVCOUNT_DIRECTORY' ..."
  #pip install -r "$PRIVCOUNT_DIRECTORY/requirements.txt"

  # Install the latest privcount version
  "$I" "Installing latest version of privcount from '$PRIVCOUNT_DIRECTORY' ..."
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
      "$I" "Making tor binary in '$TOR_MAKE_DIR' ..."
      make -C "$TOR_MAKE_DIR" "$PRIVCOUNT_TOR_BINARY"
      ;;
    chutney)
      # chutney needs tor-gencert as well as tor
      "$I" "Making tor binaries in '$TOR_MAKE_DIR' ..."
      make -C "$TOR_MAKE_DIR" "$PRIVCOUNT_TOR_BINARY" \
        "$PRIVCOUNT_TOR_GENCERT_BINARY"
      ;;
    *)
      "$W" "Source $PRIVCOUNT_SOURCE not supported."
      exit 1
      ;;
  esac
fi

# Run the counter matching checks
"$I" "Checking that all counters have events, increments, and tests:"
"$TEST_DIR/test_counter_match.sh"
"$I" ""

if [ "$PRIVCOUNT_UNIT_TESTS" -eq 1 ]; then
  # Run the python-based unit tests
  "$I" "Testing time formatting:"
  python "$TEST_DIR/test_format_time.py"
  "$I" ""

  "$I" "Testing encryption:"
  # Generate a 4096-bit RSA key for testing
  TEST_KEY_PATH="$TEST_DIR/keys/test.pem"
  TEST_CERT_PATH="$TEST_DIR/keys/test.cert"
  if [ ! -e "$TEST_KEY_PATH" ]; then
    "$PRIVCOUNT_OPENSSL" genrsa -out "$TEST_KEY_PATH" 4096
  fi
  if [ ! -e "$TEST_CERT_PATH" ]; then
    "$PRIVCOUNT_OPENSSL" rsa -pubout < "$TEST_KEY_PATH" > "$TEST_CERT_PATH"
  fi
  python "$TEST_DIR/test_encryption.py"
  "$I" ""

  "$I" "Testing random numbers:"
  python "$TEST_DIR/test_random.py"
  "$I" ""

  "$I" "Testing counters:"
  python "$TEST_DIR/test_counter.py"
  "$I" ""

  "$I" "Testing traffic model:"
  python "$TEST_DIR/test_traffic_model.py"
  "$I" ""

  "$I" "Testing noise:"
  python "$TOOLS_DIR/compute_noise.py"

  # Requires a local privcount-patched Tor instance
  #python "$TEST_DIR/test_tor_ctl_event.py"
fi

# Execute this command to produce a numeric unix timestamp in seconds
TIMESTAMP_COMMAND="date +%s"
DATE_COMMAND="date"
# Record how long the tests take to run
"$DATE_COMMAND"
STARTSEC="`$TIMESTAMP_COMMAND`"

OLD_DIR="$TEST_DIR/old"
# Move aside the old result files
"$I" "Moving old results files to '$OLD_DIR' ..."
mkdir -p "$OLD_DIR"
# Save the commands for re-use during multiple round tests
MOVE_JSON_COMMAND="mv $TEST_DIR/privcount.*.json $OLD_DIR/"
MOVE_PDF_COMMAND="mv $TEST_DIR/privcount.*.pdf $OLD_DIR/"
MOVE_LOG_COMMAND="mv $TEST_DIR/privcount.*.log $OLD_DIR/"
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
  LOG_DIR="$1"
  PRIVCOUNT_COMMAND="$2"
  FILE_TIMESTAMP="$3"
  echo "$LOG_DIR/privcount.$PRIVCOUNT_COMMAND.$FILE_TIMESTAMP.log"
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
  LOG_DIR="$1"
  PRIVCOUNT_COMMAND="$2"
  FILE_TIMESTAMP="$3"
  FILE_NAME=`log_file_name "$LOG_DIR" "$PRIVCOUNT_COMMAND" "$FILE_TIMESTAMP"`
  echo "$SAVE_LOG_COMMAND $FILE_NAME"
}

# Then run the ts, sk, dc, and injector
"$I" "Launching $PRIVCOUNT_SOURCE, tally server, share keeper, and data collector..."
# This won't match the timestamp logged by the TS, because the TS waits before
# starting the round
LOG_TIMESTAMP="$STARTSEC"
ROUNDS=1

# Set some defaults
DATA_COLLECTOR_COUNT=1
CHUTNEY_PORT_ARRAY=( 0 )
DC_SOURCE_PORT=0
SK_NUM=0

SK_LIST_FILE="keys/sk.sha256.list"
rm "$TEST_DIR/$SK_LIST_FILE" || true
touch "$TEST_DIR/$SK_LIST_FILE"

# Prepare for launch
case "$PRIVCOUNT_SOURCE" in
  inject)
    # Prepare for password authentication: the data collector and injector both
    # read this file
    "$I" "Generating random password file for injector..."
    # sometimes cat /dev/{random,urandom,zero} exits with error 141
    # even though the file is actually written out
    if [ ! -e "$TEST_DIR/keys/control_password.txt" ]; then
      cat /dev/random | hexdump -e '"%x"' -n 32 -v \
          > "$TEST_DIR/keys/control_password.txt" || true
    fi
    ;;
  tor)
    # we don't need to do anything here
    ;;
  chutney)
    # clean up the whitespace in the port list
    PRIVCOUNT_CHUTNEY_PORTS=`echo -n $PRIVCOUNT_CHUTNEY_PORTS | xargs`
    # work out how many ports there are
    CHUTNEY_PORT_ARRAY=( $PRIVCOUNT_CHUTNEY_PORTS )
    DATA_COLLECTOR_COUNT=${#CHUTNEY_PORT_ARRAY[@]}
    ;;
  *)
    "$W" "Source $PRIVCOUNT_SOURCE not supported."
    exit 1
    ;;
esac

# the privcount test configs expect to be in the test directory
pushd "$TEST_DIR"
TEMPLATE_CONFIG=$CONFIG

# Turn $TEMPLATE_CONFIG into $CONFIG using replacement parameters
# Usage:
# template_to_config
# Takes no arguments, but expects the following variables to be set:
#  TEMPLATE_CONFIG: the file to copy the template from
#  CONFIG: the output file name
# Template variables must be supplied, but their values are only used in files
# that contain the template string (which is the same as the variable name).
# The following variables are template variables:
# Tally Server:
#  PRIVCOUNT_SHARE_KEEPERS: the total number of share keepers
#  DATA_COLLECTOR_COUNT: the total number of data collectors
#    (whether using chutney or not)
# Share Keeper:
#  SK_NUM: a unique identifier for this share keeper
# Data Collector:
#  DC_SOURCE_PORT: the data source port for this data collector
#  SK_LIST_FILE: the path to a file containing a list of share keeper
#    fingerprints, as a list of quoted JSON strings
# Creates a file at $CONFIG
function template_to_config() {
  cp "$TEMPLATE_CONFIG" "$CONFIG"
  
  # This code must be kept in sync with the DC code
  # TS values
  sed -i"" -e "s/PRIVCOUNT_SHARE_KEEPERS/$PRIVCOUNT_SHARE_KEEPERS/g" \
      "$CONFIG"
  sed -i"" -e "s/DATA_COLLECTOR_COUNT/$DATA_COLLECTOR_COUNT/g" "$CONFIG"
  
  # SK values
  sed -i"" -e "s/SK_NUM/$SK_NUM/g" "$CONFIG"

  # DC stub values
  sed -i"" -e "s/DC_SOURCE_PORT/$DC_SOURCE_PORT/g" "$CONFIG"
  sed -i"" -e "/- SK_LIST/r $SK_LIST_FILE" "$CONFIG"
  sed -i"" -e "/- SK_LIST/d" "$CONFIG"
}

# this config makes the TS expect the right number of DCs and SKs
CONFIG="$TEMPLATE_CONFIG.ts"
"$I" "Generating TS config from $TEMPLATE_CONFIG in $CONFIG..."
template_to_config

# launch the TS
privcount $PRIVCOUNT_LOG ts "$CONFIG" 2>&1 \
    | `save_to_log . ts "$LOG_TIMESTAMP"` &

# launch enough SKs
for SK_NUM in `seq "$PRIVCOUNT_SHARE_KEEPERS"`; do
  CONFIG="$TEMPLATE_CONFIG.sk.$SK_NUM"
  "$I" "Generating SK config $SK_NUM from $TEMPLATE_CONFIG in $CONFIG..."
  template_to_config

  # Launch an SK with this config
  privcount $PRIVCOUNT_LOG --log-id ".$SK_NUM" sk "$CONFIG" 2>&1 \
      | `save_to_log . "sk.$SK_NUM" "$LOG_TIMESTAMP"` &
done

# find the SK fingerprints
for SK_NUM in `seq "$PRIVCOUNT_SHARE_KEEPERS"`; do
  SK_KEY_PATH="keys/sk.$SK_NUM.pem"
  "$I" -n "Generating SK fingerprint for $SK_KEY_PATH"
  echo -n "        - '" >> "$SK_LIST_FILE"
  # Let the SKs finish launching
  while [ ! -e "$SK_KEY_PATH" ]; do
    "$I" -n "."
    sleep 1
  done
  "$I" ""
  # Some versions of openssl dgst use (stdin)= before the hash, others don't
  "$PRIVCOUNT_OPENSSL" rsa -pubout < "$SK_KEY_PATH" \
    | "$PRIVCOUNT_OPENSSL" dgst -sha256 | cut -d" " -f2 | tr -d '\r\n' \
    >> "$SK_LIST_FILE"
  echo "'" >> "$SK_LIST_FILE"
done

# sort the sk fingerprints so they match the order reported by DCs
# Is there any need to remove duplicates here?
sort "$SK_LIST_FILE" -o "$SK_LIST_FILE"

# Clear the previous value
SK_NUM=0

# launch one DC per port
# for inject and tor, there is one placeholder port in the array
for DC_SOURCE_PORT in ${CHUTNEY_PORT_ARRAY[@]} ; do
  CONFIG="$TEMPLATE_CONFIG.dc.$DC_SOURCE_PORT"
  "$I" "Generating DC config $DC_SOURCE_PORT from $TEMPLATE_CONFIG in $CONFIG..."
  template_to_config

  # Launch a DC with this config
  privcount $PRIVCOUNT_LOG --log-id ".$DC_SOURCE_PORT" dc "$CONFIG" 2>&1 \
      | `save_to_log . "dc.$DC_SOURCE_PORT" "$LOG_TIMESTAMP"` &
done

popd

# Launch the data source
case "$PRIVCOUNT_SOURCE" in
  inject|tor)
    $FIRST_ROUND_CMD 2>&1 | \
        `save_to_log "$TEST_DIR" $PRIVCOUNT_SOURCE.$ROUNDS $LOG_TIMESTAMP` &
    ;;
  chutney)
    # The chutney output is very verbose: don't save it to the log
    "$I" "For full chutney logs run $CHUTNEY_LOG_CMD" | \
        `save_to_log "$TEST_DIR" $PRIVCOUNT_SOURCE.$ROUNDS $LOG_TIMESTAMP`
    $FIRST_ROUND_CMD 2>&1 &
    ;;
  *)
    "$W" "Source $PRIVCOUNT_SOURCE not supported."
    exit 1
    ;;
esac

# Then wait for each job, terminating if any job produces an error
# Ideally, we'd want to use wait, or wait $job, but that only checks one job
# at a time, so continuing processes can cause the script to run forever
"$I" "Waiting for PrivCount to finish..."
JOB_STATUS=`jobs`
"$I" "$JOB_STATUS"
while echo "$JOB_STATUS" | grep -q "Running"; do
  # fail if any job has failed
  # sometimes this doesn't work, and the script just loops, see #316
  if echo "$JOB_STATUS" | grep -q "Exit"; then
    # and kill everything
    "$W" "Error: Privcount or $PRIVCOUNT_SOURCE process exited with error..."
    pkill -P $$
    exit 1
  fi
  # succeed if an outcome file is produced
  if [ -f "$TEST_DIR/"privcount.outcome.*.json ]; then
    if [ $ROUNDS -lt $PRIVCOUNT_ROUNDS ]; then
      "$I" "Moving round $ROUNDS results to '$OLD_DIR' ..."
      $MOVE_JSON_COMMAND || true
      # If the plot libraries are not installed, this will always fail
      $MOVE_PDF_COMMAND 2> /dev/null || true
      ROUNDS=$[$ROUNDS+1]
      "$I" "Launching $PRIVCOUNT_SOURCE for round $ROUNDS..."
      $OTHER_ROUND_CMD 2>&1 | \
        `save_to_log "$TEST_DIR" $PRIVCOUNT_SOURCE.$ROUNDS $LOG_TIMESTAMP` &
    else
      break
    fi
  fi
  sleep 3
  JOB_STATUS=`jobs`
  "$I" "$JOB_STATUS"
done

# Measure how long the actual tests took
ENDDATE="`$DATE_COMMAND`"
ENDSEC="`$TIMESTAMP_COMMAND`"

# And terminate all the privcount processes
"$I" "Terminating privcount and $PRIVCOUNT_SOURCE after $ROUNDS round(s)..."
pkill -P $$
wait

# Symlink a timestamped file to a similarly-named "latest" file
# Usage:
# link_latest prefix suffix [is_mandatory]
# Takes three arguments: the prefix and the suffix, in a filename like:
#     privcount.prefix.timestamp.suffix
# and is_mandatory: if a file is mandatory, this function exits the script
# if it is not found. is_mandatory defaults to true if not provided.
# Doesn't handle arguments with spaces
function link_latest() {
  PREFIX="$1"
  SUFFIX="$2"
  IS_MANDATORY="${3:-1}"
  GLOB_PATTERN=privcount.$PREFIX.*.$SUFFIX
  LATEST_NAME=privcount.$PREFIX.latest.$SUFFIX
  pushd "$TEST_DIR" > /dev/null
  if [ -f $GLOB_PATTERN ]; then
    ln -s $GLOB_PATTERN "$LATEST_NAME"
  elif [ "$IS_MANDATORY" -eq 1 ]; then
    "$W" "Error: No $PREFIX $SUFFIX file produced."
    exit 1
  else
    "$W" "Warning: No $PREFIX $SUFFIX file produced."
  fi
  popd > /dev/null
}

# If an outcome file was produced, link to the latest file
link_latest outcome json

# If the optional traffic model file was produced, link to the latest file
link_latest traffic.model json 0

# If a tallies file was produced, link to the latest file, and plot it
link_latest tallies json
if [ -f "$TEST_DIR/privcount.tallies.latest.json" -a \
    "$PRIVCOUNT_PLOT" -eq 1 ]; then
  "$I" "Plotting results..."
  # plot will fail if the optional dependencies are not installed
  # tolerate this failure
  privcount plot -d "$TEST_DIR/privcount.tallies.latest.json" data 2>&1 | \
    `save_to_log "$TEST_DIR" plot $LOG_TIMESTAMP` || \
    "$W" "Plot failed. Install the dependencies in requirements-plot.txt to run plot."
fi

# If log files were produced, link to the latest files
link_latest ts log

for SK_NUM in `seq "$PRIVCOUNT_SHARE_KEEPERS"`; do
  link_latest "sk.$SK_NUM" log
done

for DC_SOURCE_PORT in ${CHUTNEY_PORT_ARRAY[@]} ; do
  link_latest "dc.$DC_SOURCE_PORT" log
done

for round_number in `seq $PRIVCOUNT_ROUNDS`; do
  link_latest $PRIVCOUNT_SOURCE.$round_number log
done

# Don't do diffs in quiet mode
if [ "$PRIVCOUNT_LOG" != "-q" ]; then

  # Show the differences between the latest and old latest outcome files
  if [ -e "$TEST_DIR/privcount.outcome.latest.json" -a \
      -e "$OLD_DIR/privcount.outcome.latest.json" ]; then
    # there's no point in comparing the tallies JSON or results PDF
    "$I" "Comparing latest outcomes file with previous outcomes file..."
    # skip expected differences due to time or network jitter
    # PrivCount is entirely deterministic: if there are any other differences,
    # they are due to code changes, or are a bug, or need to be filtered out
    # here
    diff --minimal --unified=10 \
      -I "time" -I "[Cc]lock" -I "alive" -I "rtt" -I "Start" -I "Stop" \
      -I "[Dd]elay" -I "Collect" -I "End" -I "peer" -I "fingerprint" \
      "$OLD_DIR/privcount.outcome.latest.json" \
      "$TEST_DIR/privcount.outcome.latest.json" || true
  else
    # Since we need old/latest and latest, it takes two runs to generate the
    # first outcome file comparison
    "$W" "Warning: Outcomes files could not be compared."
    "$W" "$0 must be run twice to produce the first comparison."
  fi

  # Show the differences between the latest and old latest traffic model files
  if [ -e "$TEST_DIR/privcount.traffic.model.latest.json" -a \
       -e "$OLD_DIR/privcount.traffic.model.latest.json" ]; then
    "$I" "Comparing latest traffic model with previous traffic model..."
    # PrivCount is entirely deterministic: if there are any other differences,
    # they are due to code changes, or are a bug, or need to be filtered out
    # here
    diff --minimal --unified=10 \
      "$OLD_DIR/privcount.traffic.model.latest.json" \
      "$TEST_DIR/privcount.traffic.model.latest.json" || true
  else
    # Since we need old/latest and latest, it takes two runs to generate the
    # first traffic model file comparison
    "$W" "Warning: traffic model files could not be compared."
    "$W" "$0 must be run twice to produce the first comparison."
  fi

fi

# Grep the warnings out of the log files
# $LOG_CMD displays warnings from all logs produced by the chutney data source
# We don't diff the previous log files with the latest log files, because many
# of the timestamps and other irrelevant details are different
"$I" "Extracting warnings from privcount and $PRIVCOUNT_SOURCE output..."
grep -v -e NOTICE -e INFO -e DEBUG \
  -e "seconds of user activity" -e "delay_period not specified" \
  -e notice \
  -e "Path for PidFile" -e "Your log may contain" \
  -e "no nameservers" -e "any working nameservers" \
  "$TEST_DIR/"privcount.*.latest.log \
  || true
# Log any source-specific warnings
# Summarise unexpected chutney warnings
CHUTNEY_WARNINGS_IGNORE_EXPECTED=true CHUTNEY_WARNINGS_SUMMARY=true $LOG_CMD

# Show how long it took
"$I" "$ENDDATE"
ELAPSEDSEC=$[ $ENDSEC - $STARTSEC ]
"$I" "Seconds Elapsed: $ELAPSEDSEC for $ROUNDS round(s)"
