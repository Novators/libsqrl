#!/bin/bash

if [ -e "Makefile" ]
then
	exit 0
fi

if [ -e "configure" ]
then
	./configure --prefix=$1
else
	./autogen.sh && ./configure --prefix=$1
fi