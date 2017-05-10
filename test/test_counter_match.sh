#!/bin/bash
# See LICENSE for licensing information

# Check if the counters in the code, test, and doc files are the same

# Shell settings
# fail on failed commands or unset variables
set -e
set -u
# the exit status of a pipe is the last non-zero exit, or zero if all succeed
set -o pipefail
# report background exit statuses immediately
set -b

TEST_DIR=${TEST_DIR:-`dirname "$0"`}
NAME_REGEX="[a-z0-9]*"

echo "Checking counter consistency:"

# Clean up after last time
rm "$TEST_DIR"/*.names || true
rm "$TEST_DIR"/*.names.unsorted || true
rm "$TEST_DIR"/*.names.extra || true

echo "Processing $TEST_DIR/traffic.noise.yaml:"
grep -i "^ *$NAME_REGEX:$" "$TEST_DIR/traffic.noise.yaml" \
    | grep -v -e 'counters:' \
    | tr -d " \t:" > "$TEST_DIR/traffic.noise.yaml.names.extra"

# Process the test counter files
for counters in "$TEST_DIR"/counters.{bins,noise,sigmas}.yaml; do
    echo "Processing $counters:"
    grep -i "$NAME_REGEX:$" "$counters" \
        | grep -v -e '^#' -e 'bins:' -e 'privacy:' -e 'counters:' \
        | tr -d " \t:" > "$counters.names.unsorted"
    # The traffic model bins are automatic, and they don't support sigmas
    # So add them to each file
    cat "$TEST_DIR/traffic.noise.yaml.names.extra" \
        >> "$counters.names.unsorted"
    # And sort
    cat "$counters.names.unsorted" | sort > "$counters.names"
done

echo "Processing $TEST_DIR/../privcount/traffic_model.py:"
grep -i "'$NAME_REGEX'[],]" "$TEST_DIR/../privcount/traffic_model.py" \
    | grep -v -e 'counters' -e 'states' \
    | cut -d"'" -f 2 > "$TEST_DIR/traffic_model.py.names.extra"

echo "Processing $TEST_DIR/../privcount/statistics_noise.py:"
grep -i "DEFAULT_DUMMY_COUNTER_NAME *= *'$NAME_REGEX'" \
    "$TEST_DIR/../privcount/statistics_noise.py" \
    | cut -d"'" -f 2 > "$TEST_DIR/statistics_noise.py.names.extra"

# Process the code files
for code in "$TEST_DIR"/../privcount/{counter,data_collector}.py; do
    echo "Processing $code:"
    OUT_PATH="$TEST_DIR"/`basename "$code"`
    grep -i "'$NAME_REGEX'[, ][: ]" "$code" | cut -d"'" -f 2 \
        | grep -v -e 'bins' -e 'DOCUMENT' -e 'type' \
        > "$OUT_PATH.names.unsorted"
    # Add the traffic model bins to the data_collector file only
    if [ `basename "$code"` = 'data_collector.py' ]; then
        cat "$TEST_DIR/traffic_model.py.names.extra" \
            >> "$OUT_PATH.names.unsorted"
    fi
    # Add the ZeroCount counter (it has no events and no increments)
    cat "$TEST_DIR/statistics_noise.py.names.extra" \
        >> "$OUT_PATH.names.unsorted"
    # And sort
    cat "$OUT_PATH.names.unsorted" | sort > "$OUT_PATH.names"
done

# Process the doc files
doc="$TEST_DIR/../doc/CounterTests.markdown"
OUT_PATH="$TEST_DIR/CounterTests.markdown"
# the trailing colon is optional: it is used to delimit a test expression
# we ignore the template counters
grep -i "^- $NAME_REGEX" "$doc" \
    | cut -d' ' -f 2 | cut -d':' -f 1 | grep -v '_' \
    | sort > "$OUT_PATH.names"

echo "Number of counters:"
wc -l "$TEST_DIR"/*.py.names "$TEST_DIR"/*.yaml.names \
    "$TEST_DIR"/*.markdown.names "$TEST_DIR"/*.names.extra \
    | grep -v total

echo "Differences between counters in code, test, and docs, and counter.py:"
diff -u "$TEST_DIR"/*.names \
    --to-file="$TEST_DIR/counter.py.names"
