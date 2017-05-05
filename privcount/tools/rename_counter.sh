#!/bin/bash

# Rename a counter throughout the PrivCount code base

# Shell settings
# fail on failed commands or unset variables
set -e
set -u
# the exit status of a pipe is the last non-zero exit, or zero if all succeed
set -o pipefail
# report background exit statuses immediately
set -b

if [ $# -ne 2 ]; then
    echo "usage: $0: OldCounterName NewCounterName"
fi

OLD_NAME="$1"
NEW_NAME="$2"
NAME_CHAR="A-Za-z0-9"

TOOLS_DIR=`dirname "$0"`
PRIVCOUNT_DIR=${PRIVCOUNT_DIR:-"$TOOLS_DIR/../.."}

# Don't rename counters unless they already match
"$PRIVCOUNT_DIR/test/test_counter_match.sh"

echo "Renaming $OLD_NAME to $NEW_NAME in $PRIVCOUNT_DIR:"

for file in `find "$PRIVCOUNT_DIR" | \
    grep -e '.py$' -e '.sh$' -e '.markdown$' -e '.yaml$' | \
    grep -v -e old -e venv -e .git`; do

    MATCH_COUNT=`grep -c "$OLD_NAME[^$NAME_CHAR]" "$file"` || true
    # skip files with no characters in them, outputting a match count
    if [ "0$MATCH_COUNT" -gt 0 ]; then
        echo "Replacing $MATCH_COUNT names in $file:"
        # In PrivCount 0.1.0, some counter names were prefixes of other names
        # This regex matches names, without matching prefixes in longer names
        # Since the traffic model templates use extra characters, they *will*
        # be renamed along with their non-template counterparts
        sed -i .bak "s/$OLD_NAME\([^$NAME_CHAR]\)/$NEW_NAME\1/g" "$file"
    fi
done

# Exit with an error if the counter names do not match after the rename
"$PRIVCOUNT_DIR/test/test_counter_match.sh"
