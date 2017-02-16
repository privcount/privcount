#!/bin/bash

set -e
set -u

# Default option values
PRIVCOUNT_INSTALL=0
PRIVCOUNT_DIRECTORY=.
PRIVCOUNT_ROUNDS=2
PRIVCOUNT_UNIT_TESTS=1

# Process arguments
until [ "$#" -le 0 ]
do
  case "$1" in
    --install|-I)
      PRIVCOUNT_INSTALL=1
      ;;
    --rounds|-r)
      PRIVCOUNT_ROUNDS=$2
      shift
      ;;
    --no-unit-tests|-x)
      PRIVCOUNT_UNIT_TESTS=0
      ;;
    --help|-h)
      echo "usage: $0 [...] [<privcount-directory>] -- [<data-source-args...>]"
      echo "  -I: run 'pip install -I <privcount-directory>' before testing"
      echo "    default: $PRIVCOUNT_INSTALL (1: install, 0: don't install) "
      echo "  -r rounds: run this many rounds before stopping"
      echo "  -x: skip unit tests"
      echo "    default: '$PRIVCOUNT_UNIT_TESTS' (1: run, 0: skip)"
      echo "  <privcount-directory>: the directory privcount is in"
      echo "    default: '$PRIVCOUNT_DIRECTORY'"
      echo "  <data-source-args...>: arguments appended to the data source"
      echo "    default first round: port 20003, password auth"
      echo "    default next rounds: unix /tmp/privcount-inject, cookie auth"
      # we've done what they asked
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

# Injector commands for re-use
# We can either test --simulate, and get partial data, or get full data
# It's better to get full data
INJECTOR_BASE_CMD="privcount inject --log events.txt"

# Prepare for password authentication: the data collector and injector both
# read this file
echo "Generating random password file..."
cat /dev/random | hexdump -e '"%x"' -n 32 -v > keys/control_password.txt
# The command for password authentication
INJECTOR_PORT_CMD="$INJECTOR_BASE_CMD --port 20003 --control-password keys/control_password.txt $@"

# The command for safecookie authentication
# The injector automatically writes its own cookie file, just like tor
INJECTOR_UNIX_CMD="$INJECTOR_BASE_CMD --unix /tmp/privcount-inject --control-cookie-file /tmp/privcount-control-auth-cookie $@"

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
# privcount privcount_command args 2&>1 | `save_to_log privcount_command timestamp`
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
echo "Launching injector (IP), tally server, share keeper, and data collector..."
# This won't match the timestamp logged by the TS, because the TS waits before
# starting the round
LOG_TIMESTAMP="$STARTSEC"
privcount ts config.yaml 2>&1 | `save_to_log ts $LOG_TIMESTAMP` &
privcount sk config.yaml 2>&1 | `save_to_log sk $LOG_TIMESTAMP` &
privcount dc config.yaml 2>&1 | `save_to_log dc $LOG_TIMESTAMP` &
ROUNDS=1
$INJECTOR_PORT_CMD 2>&1 | `save_to_log inject.$ROUNDS $LOG_TIMESTAMP` &

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
    echo "Error: Privcount process exited with an error..."
    pkill -P $$
    exit 1
  fi
  # succeed if an outcome file is produced
  if [ -f privcount.outcome.*.json ]; then
    if [ $ROUNDS -lt $PRIVCOUNT_ROUNDS ]; then
      echo "Moving round $ROUNDS results files to '$PRIVCOUNT_DIRECTORY/test/old' ..."
      $MOVE_JSON_COMMAND || true
      # If the plot libraries are not installed, this will always fail
      $MOVE_PDF_COMMAND 2> /dev/null || true
      ROUNDS=$[$ROUNDS+1]
      echo "Restarting injector (unix path) for round $ROUNDS..."
      $INJECTOR_UNIX_CMD 2>&1 | `save_to_log inject.$ROUNDS $LOG_TIMESTAMP` &
    else
      break
    fi
  fi
  sleep 2
  JOB_STATUS=`jobs`
  echo "$JOB_STATUS"
done

# Measure how long the actual tests took
ENDDATE="`$DATE_COMMAND`"
ENDSEC="`$TIMESTAMP_COMMAND`"

# And terminate all the privcount processes
echo "Terminating privcount after $ROUNDS round(s)..."
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
  privcount plot -d privcount.tallies.latest.json data 2>&1 | `save_to_log plot $LOG_TIMESTAMP` || true
fi

# If log files were produced, keep a link to the latest files
link_latest ts log
link_latest sk log
link_latest dc log
for round_number in `seq $PRIVCOUNT_ROUNDS`; do
  link_latest inject.$round_number log
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
    -I "[Dd]elay" -I "Collect" -I "End" -I "peer" \
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
  echo "Comparing latest traffic model file with previous traffic model file..."
  # PrivCount is entirely deterministic: if there are any other differences,
  # they are due to code changes, or are a bug, or need to be filtered out here
  diff --minimal --unified=10 \
    old/privcount.traffic.model.latest.json privcount.traffic.model.latest.json || true
else
  # Since we need old/latest and latest, it takes two runs to generate the
  # first traffic model file comparison
  echo "Warning: traffic model files could not be compared."
  echo "$0 must be run twice to produce the first comparison."
fi

# Grep the warnings out of the log files
# We don't diff the previous log files with the latest log files, because many
# of the timestamps and other irrelevant details are different
echo "Extracting warnings from privcount output..."
grep -v -e NOTICE -e INFO -e DEBUG \
  -e "seconds of user activity" -e "delay_period not specified" \
  privcount.*.latest.log \
  || true

# Show how long it took
echo "$ENDDATE"
ELAPSEDSEC=$[ $ENDSEC - $STARTSEC ]
echo "Seconds Elapsed: $ELAPSEDSEC for $ROUNDS round(s)"
