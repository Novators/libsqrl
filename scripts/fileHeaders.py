import fileinput
import sys
import os

pth = sys.path[0] + '\..\src'
print pth
os.chdir( pth )

header = """ *
 * \\author Adam Comley
 * 
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/
"""

for fn in os.listdir( pth ):
    if fn.endswith( ".h" ):
        ftag = fn.replace( '.', '_' ).upper()
        needsClosingTag = False

        for line in fileinput.input( fn, inplace = True ):
            if fileinput.filelineno() == 1:
                if line.startswith( '#pragma once' ):
                    print "/** \\file " + fn
                    print header
                    print '#ifndef ' + ftag
                    print '#define ' + ftag
                    needsClosingTag = True
                elif line.startswith( '/**' ):
                    print line.rstrip()
                else:
                    print "/** \\file " + fn
                    print header
                    print line.rstrip()
            elif line.startswith( '#pragma once' ):
                print '#ifndef ' + ftag
                print '#define ' + ftag
                needsClosingTag = True
            else:
                print line.rstrip()
        if needsClosingTag:
            with open( fn, "a" ) as myfile:
                myfile.write( '#endif // ' + ftag + "\n" )
    elif fn.endswith( ".cpp" ):
        for line in fileinput.input( fn, inplace = True ):
            if fileinput.filelineno() == 1:
                if line.startswith( '/**' ):
                    print line.rstrip()
                else:
                    print "/** \\file " + fn
                    print header
                    print line.rstrip()
            else:
                print line.rstrip()

