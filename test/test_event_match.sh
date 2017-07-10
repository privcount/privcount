#!/usr/bin/env bash
# See LICENSE for licensing information

# Check if all events are in the PrivCount code, test and doc files, and the
# PrivCount Tor Patch

# Shell settings
# fail on failed commands or unset variables
set -e
set -u
# the exit status of a pipe is the last non-zero exit, or zero if all succeed
set -o pipefail
# report background exit statuses immediately
set -b

TEST_DIR=${TEST_DIR:-`dirname "$0"`}
NAME_REGEX="PRIVCOUNT_[A-Z0-9_]*"
PY_DIR="$TEST_DIR"/../privcount
TOR_DIR=${TOR_DIR:-"$TEST_DIR"/../../tor-privcount}

echo "Checking event consistency:"

# Clean up after last time
rm "$TEST_DIR"/*.event_names || true

# Process the PrivCount Tor Patch files
if [ -d "$TOR_DIR" ]; then
    for code in "$TOR_DIR"/src/or/control.{c,h}; do
        #echo "Processing $code:"
        OUT_PATH="$TEST_DIR"/`basename "$code"`
        grep -i "^[^*]*EVENT_$NAME_REGEX[ ,]" "$code" \
            | cut -d"(" -f 2 | cut -d"_" -f 2- \
            | cut -d"," -f 1 | cut -d" " -f 1 \
            | sort -u > "$OUT_PATH.event_names"
    done
fi

# Process the PrivCount python code files
for code in "$PY_DIR"/{counter,data_collector,inject}.py; do
    #echo "Processing $code:"
    OUT_PATH="$TEST_DIR"/`basename "$code"`
    grep -i "'$NAME_REGEX'" "$code" \
        | cut -d"'" -f 2 \
        | grep -v 'privcount_version' \
        | sort -u > "$OUT_PATH.event_names"
done

# Process the test event files
for events in "$TEST_DIR"/events.txt; do
    #echo "Processing $events:"
    grep -i "$NAME_REGEX " "$events" | cut -d" " -f1 \
        | sort -u > "$events.event_names"
done

# Process the doc files
doc="$TEST_DIR/../doc/TorEvents.markdown"
OUT_PATH="$TEST_DIR/TorEvents.markdown"
grep -i "### $NAME_REGEX" "$doc" \
    | cut -d' ' -f 2 \
    | sort > "$OUT_PATH.event_names"

echo "Number of events:"
wc -l "$TEST_DIR"/*.{c,h,py,txt,markdown}.event_names \
    | grep -v total

echo "Differences between events in code, test, docs, and Tor Patch, and counter.py:"
# We don't use the PRIVCOUNT_DNS_RESOLVED event
diff -u "$TEST_DIR"/*.event_names \
    -I "PRIVCOUNT_DNS_RESOLVED" \
    --to-file="$TEST_DIR/counter.py.event_names"
