import datetime
import fileinput
import sys
import os

os.chdir( sys.path[0] )
print sys.path[0]

infile = open("../VERSION")

s = infile.read()
infile.close()
parts = s.split(".")

vMajor = parts[0]
vMinor = parts[1]
ovDate = parts[2]
ovBuild = int(parts[3])

today = datetime.datetime.utcnow()
nvDate = str(today.year)[2:] + str(today.timetuple().tm_yday).zfill(3)

if ovDate == nvDate:
    nvBuild = str(ovBuild + 1)
else:
    nvBuild = str(1)

nvString = vMajor + "." + vMinor + "." + nvDate + "." + nvBuild

outfile = open( "../VERSION", 'w' )
outfile.write(nvString)
outfile.close()
print nvString

for line in fileinput.input("../README.md", inplace=True):
    if fileinput.filelineno() == 1:
        print "# libsqrl " + nvString
    else:
        print line.strip()

for line in fileinput.input("../src/version.h", inplace=True):
    if line.startswith( "#define SQRL_LIB_VERSION_MAJOR" ):
        print "#define SQRL_LIB_VERSION_MAJOR " + vMajor
    elif line.startswith( "#define SQRL_LIB_VERSION_MINOR" ):
        print "#define SQRL_LIB_VERSION_MINOR " + vMinor
    elif line.startswith( "#define SQRL_LIB_VERSION_BUILD_DATE" ):
        print "#define SQRL_LIB_VERSION_BUILD_DATE " + nvDate
    elif line.startswith( "#define SQRL_LIB_VERSION_REVISION" ):
        print "#define SQRL_LIB_VERSION_REVISION " + nvBuild
    elif line.startswith( "#define SQRL_LIB_VERSION" ):
        print '#define SQRL_LIB_VERSION "' + nvString + '"'
    else:
        print line.strip()
    
