#!/bin/sh

# Starts privcount in the background, logging to privcount.log
# Use this script by itself, or with crontab.privcount

SCRIPT_DIR=`dirname "$0"`/..

cd "$SCRIPT_DIR"
if [ -e venv/bin/activate ]; then
    . venv/bin/activate
    privcount "$@" 2>&1 >> privcount.log &
elif [ -x privcount/tools/privcount ]; then
    privcount/tools/privcount "$@" 2>&1 >> privcount.log &
else
    echo "Can't find privcount"
    exit 1
fi

echo "Started privcount, to see logs, use:"
echo "tail -f privcount.log"
