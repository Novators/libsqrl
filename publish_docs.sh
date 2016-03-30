#!/bin/bash

WEBPATH=/srv/www/sqrlid.com/libsqrl
SRV=adam@novators.net

make doc
cd doc/html

$ERRORSTRING="Error. Please make sure you've indicated correct parameters"
if [ $# -eq 0 ]
    then
        echo $ERRORSTRING;
fi

if [[ -z $1 ]]
    then
        echo "Running dry-run"
        rsync --dry-run -az --force --delete --progress -e "ssh -p22" ./ ${SRV}:${WEBPATH}
        echo
        echo Repeat with option \"go\" to deploy.
elif [ $1 == "go" ]
    then
        echo "Running actual deploy"
        rsync -az --force --delete --progress -e "ssh -p22" ./ ${SRV}:${WEBPATH}
else
    echo $ERRORSTRING;
fi