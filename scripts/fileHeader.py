import fileinput
import sys
import os

pth = sys.path[0] + '\..\src'
print pth
os.chdir( pth )

header = """@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/
"""

fn = "SqrlAction.h"
ftag = fn.replace( '.', '_' ).upper()

needsClosingTag = False

for line in fileinput.input( "SqrlAction.h", inplace = True ):
    if fileinput.filelineno() == 1 and line.startswith( '#pragma once' ):
        print "/** @file " + fn
        print header
        print '#ifndef ' + ftag
        print '#define ' + ftag
        needsClosingTag = True
    else:
        print line.strip()
if needsClosingTag:
    with open( fn, "a" ) as myfile:
        myfile.write( '#endif // ' + ftag + "\n" )

