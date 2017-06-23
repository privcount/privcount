#!/bin/sh

# Starts privcount in the background, logging to privcount.log
# Use this script by itself, or with crontab.privcount

SCRIPT_DIR=`dirname "$0"`/..

cd "$SCRIPT_DIR"
if [ -e venv/bin/activate ]; then
    . venv/bin/activate
    privcount "$@" >> privcount.log 2>&1 &
elif [ -x privcount/tools/privcount ]; then
    privcount/tools/privcount "$@" >> privcount.log 2>&1 &
else
    echo "Can't find privcount"
    exit 1
fi

sleep 1
head privcount.log
echo "Started privcount, to see logs, use:"
echo "tail -f $SCRIPT_DIR/privcount.log"
