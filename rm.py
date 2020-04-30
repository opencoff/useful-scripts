#! /usr/bin/env python

# rm(1) replacement that asks for permission
#
# (c) 2010 Sudhi Herle <sudhi@herle.net>
# License: GPLv2
#
import sys, os, os.path, signal, re
from os.path import isfile, islink

Z = os.path.basename(sys.argv[0])
Dry_run   = False

Usage = """Remove a file or files.

%s file [file ..]

%s is a pythonic replacement for rm(1).
Its default behavior is akin to 'rm -i' - except the user
doesn't have to press <Return> after every response.

In all cases, the user is presented with an interactive prompt
before removing the file.
""" % (Z, Z)



def error(doex, fmt, *args):
    """Show error message and die if doex > 0"""
    sfmt = "%s: %s" % (Z, fmt)
    if args:
        sfmt = sfmt % args

    if not sfmt.endswith('\n'):
        sfmt += '\n'

    sys.stdout.flush()
    sys.stderr.write(sfmt)
    sys.stderr.flush()
    if doex > 0:
        sys.exit(doex)


# Raw character input
Getch = None
if sys.platform in ('win32', 'win64', 'cygwin'):
    import msvcrt

    class _GetchWindows:
        def __init__(self):
            pass

        def __call__(self):
            return msvcrt.getch()


    Getch = _GetchWindows()

else:
    import tty, termios

    class _GetchUnix:
        def __init__(self):
            pass

        def __call__(self):
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                ch = sys.stdin.read(1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            return ch


    Getch = _GetchUnix()




def prompt(s):
    """Show prompt 's' and return the response"""
    global Getch

    sys.stdout.write(s)
    sys.stdout.flush()
    v = Getch()
    r = 0
    if v == 'y' or v == 'Y':
        r = 1
    elif v == 'q' or v == 'Q':
        r = -1
    #sys.stdout.write('\n')
    return r


def main(argv):

    if len(argv) == 1 or argv[1] == '-h':
        print("Usage: %s FILE [FILE..]" % argv[0]) 
        sys.exit(1)

    for f in argv[1:]:
        if not isfile(f) and not islink(f):
            continue

        s = "%-50s [y/N]? " % f
        r = prompt(s)
        if r < 0:
            sys.stdout.write('\n')
            sys.exit(0)

        elif r > 0:
            try:
            os.unlink(f)
            except Exception as ex:
                s = str(ex)
                sys.stdout.write(" %s\n" % s)
        sys.stdout.write('\n')

main(sys.argv)

# vim: notextmode:sw=4:ts=4:tw=128:expandtab:
