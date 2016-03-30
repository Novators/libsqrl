#!/bin/bash

if [ -e "Makefile" ]
then
	exit 0
fi

cmake -DCMAKE_INSTALL_PREFIX:PATH=$2 .
cd $1
cmake -DCMAKE_INSTALL_PREFIX:PATH=$2 ..

