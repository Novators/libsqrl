#!/bin/bash

CNT=0
"$@"
while [ $? -eq 0 ]; do
    CNT=$((${CNT} + 1))
    if [ ${CNT} -gt 50 ]; then
        echo "Timeout -- All 50 Passed"
        exit
    fi
    "$@"
done