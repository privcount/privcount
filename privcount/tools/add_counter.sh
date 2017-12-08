#!/usr/bin/env bash
# See LICENSE for licensing information

# Make the counters in the code, test, and doc files the same
# Adds extra counters in privcount/counter.py to the other files

# Shell settings
# fail on failed commands or unset variables
set -e
set -u
# the exit status of a pipe is the last non-zero exit, or zero if all succeed
set -o pipefail
# report background exit statuses immediately
set -b

BASE_DIR=${BASE_DIR:-`dirname "$0"`/../..}
TEST_DIR=${TEST_DIR:-"$BASE_DIR"/test}
DOC_DIR=${DOC_DIR:-"$BASE_DIR"/doc}

# Clean up after last time
rm "$BASE_DIR"/missing_counters || true

echo "Finding missing counters:"
# sort by reversed counter name, to sort similar suffixes together
"$TEST_DIR"/test_counter_match.sh | grep "^+" | cut -d+ -f2 | grep -v "^$" \
    | rev | sort -u | rev \
    > "$BASE_DIR"/missing_counters && echo "No missing counters." && exit 0

echo "Adding missing counters to CounterTests.markdown:"
for counter in `cat "$BASE_DIR"/missing_counters`; do
    echo "- $counter" >> "$DOC_DIR"/CounterTests.markdown
done

echo "Adding missing counters to counters.noise.yaml:"
for counter in `cat "$BASE_DIR"/missing_counters`; do
    echo "    $counter:" >> "$TEST_DIR"/counters.noise.yaml
    echo "        estimated_value: 0.0" >> "$TEST_DIR"/counters.noise.yaml
    echo "        sensitivity: 0.0" >> "$TEST_DIR"/counters.noise.yaml
done

echo "Adding missing counters to counters.sigmas.yaml:"
for counter in `cat "$BASE_DIR"/missing_counters`; do
    echo "    $counter:" >> "$TEST_DIR"/counters.sigmas.yaml
    echo "        sigma: 0.0" >> "$TEST_DIR"/counters.sigmas.yaml
done

echo "Adding missing counters to counters.sigmas_large.yaml:"
for counter in `cat "$BASE_DIR"/missing_counters`; do
    echo "    $counter:" >> "$TEST_DIR"/counters.sigmas_large.yaml
    echo "        sigma: 1.0e+12" >> "$TEST_DIR"/counters.sigmas_large.yaml
done

echo "Adding missing counters to counters.bins.yaml:"
for counter in `cat "$BASE_DIR"/missing_counters`; do
     echo "    $counter:" >> "$TEST_DIR"/counters.bins.yaml
     echo "        bins:" >> "$TEST_DIR"/counters.bins.yaml
     echo "        - [-.inf, .inf]" >> "$TEST_DIR"/counters.bins.yaml
done
echo "You must manually add bins to multi-bin counters (Histograms)."

"$TEST_DIR"/test_counter_match.sh
