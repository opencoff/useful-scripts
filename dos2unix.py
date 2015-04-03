#! /usr/bin/env python

import os, sys, os.path
from os.path import join

Z = os.path.basename(sys.argv[0])

def die(fmt, *args):

    sfmt = "%s: %s" % (Z, fmt)

    if args:
        sfmt = sfmt % args

    sfmt += "\n"
    sys.stdout.flush()
    sys.stderr.write(sfmt)
    sys.stderr.flush()

    sys.exit(1)


def transcode(fn, verbose=False):
    """Fixup file fn"""

    tmp = fn + '.tmp'
    fd  = open(fn, 'rb', 1048576)
    out = open(tmp, 'wb', 1048576)
    mod = False
    for line in fd:
        i = line.rfind("\r\n")
        if i >= 0:
            line = line[:i] + "\n"
            mod  = True

        out.write(line)

    out.close()
    fd.close()

    if mod:
        if verbose:
            print "%s" % fn

        bak = fn + '.orig'
        os.rename(fn, bak)
        os.rename(tmp, fn)
    else:
        os.unlink(tmp)

        
    return mod



def fixup(dn, verbose=False):
    """Walk directory 'dn' and fixup all files recursively"""


    if not os.path.isdir(dn):
        return 0

    n = 0
    for root, dirs, files in os.walk(dn, 1):
        for f in files:
            fn = join(root, f)
            mod = transcode(fn, verbose)
            if mod:
                n += 1

    return n


for f in sys.argv[1:]:
    if os.path.isfile(f):
        transcode(f, True)
    elif os.path.isdir(f):
        fixup(f, True)
    else:
        print "Hmm. %s is not a file or dir" % f
