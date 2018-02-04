#!/usr/bin/env python

import datetime
import fileinput
import sys
import os

os.chdir( sys.path[0] )
print sys.path[0]

infile = open( "../VERSION" )
s = infile.read()
infile.close()

parts = s.split(".")

vMajor = parts[0]
vMinor = parts[1]
vBuild = int(parts[2])

increment = True

today = datetime.datetime.utcnow()
nMajor = str(today.year)[2:]
nMinor = str(today.month).zfill(2)
nBuild = 1

if( vMajor != nMajor ):
    increment = False

if( increment and vMinor != nMinor ):
    increment = False

if( increment ):
    nBuild = vBuild + 1

nBuild = str(nBuild).zfill(4)

nString = nMajor + "." + nMinor + "." + nBuild
print "Bumping to version: " + nString

outfile = open( "../VERSION", 'w' )
outfile.write( nString )
outfile.close()

for line in fileinput.input( "../README.md", inplace=True ):
    if fileinput.filelineno() == 1:
        print "# libsqrl " + nString
    else:
        print line.rstrip()

for line in fileinput.input( "../CMakeLists.txt", inplace=True ):
    if line.startswith( "set(sqrl_version_major " ):
        print "set(sqrl_version_major " + nMajor + ")"
    elif line.startswith( "set(sqrl_version_minor " ):
        print "set(sqrl_version_minor " + nMinor + ")"
    elif line.startswith( "set(sqrl_build " ):
        print "set(sqrl_build " + nBuild + ")"
    else:
        print line.rstrip()

print "Please run cmake to update project!"
