#! /usr/bin/env python

#
# Parallel directory walker - non recursive edition.
#
# We illustrate use of multi-processing to do a simple version of
# "du".
#
# (c) 2014, 2015 Sudhi Herle <sw-at-herle.net>
# License: GPLv2
#
#
import os, os.path, sys
import argparse
import stat, time
import signal
import multiprocessing as m

from os.path    import join, basename
from stat       import S_ISDIR, S_ISREG, S_ISLNK
from functools  import partial

Z        = basename(sys.argv[0])
__doc__  = "%s - Parallelized, simplified, sorted du replacement" % Z

KB = 1024L
MB = 1024L * KB
GB = 1024L * MB
TB = 1024L * GB
PB = 1024L * TB
EB = 1024L * PB

# Arranged in strictly descending order!
Divisors = [
    ('EB', EB),
    ('PB', PB),
    ('TB', TB),
    ('GB', GB),
    ('MB', MB),
    ('kB', KB),
    ]


def human(n):
    """Return human readable size for n bytes"""
    global Divisors
    for nm, sz in Divisors:
        if n > sz:
            s = "%8.2f %s" % (float(n) / sz, nm)
            return s

    return "%lu" % n

def warn(fmt, *args):
    s = "%s: %s" % (Z, fmt)
    if args:                 s  = s % args
    if not s.endswith('\n'): s += '\n'

    sys.stdout.flush()
    sys.stderr.write(s)
    sys.stderr.flush()

def die(fmt, *args):
    warn(fmt, *args)
    sys.exit(1)

def block_sigs():
    """Block signals in the worker process"""
    signal.signal(signal.SIGINT,  signal.SIG_IGN)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    signal.signal(signal.SIGHUP,  signal.SIG_IGN)

def listdir(dn, xstat, xdev):
    """Scan a directory and classify entries into files, dirs,
    etc.

    Returns a 3 tuple: errors, dirs, files, dir-size

    Where dir-size is a tuple: dirname, size; and 'size' is the
    cumulative size of all the files in that directory.

    files is an array of tuples 'size, name'
    """

    errs  = []
    dirs  = []
    files = []

    fsz   = 0L
    try:
        dc = os.listdir(dn)
    except Exception, ex:
        errs.append((dn, ex))
        return errs, dirs, files, (dn, fsz)

    for x in dc:
        nm = join(dn, x)
        try:
            st = xstat(nm)
        except Exception, ex:
            errs.append((nm, ex))
            continue

        if S_ISDIR(st.st_mode):
            if xdev == 0 or xdev == st.st_dev:
                dirs.append((nm, st, xdev))
        elif S_ISREG(st.st_mode):
            fsz += size(st)
            files.append((st.st_size, nm))

    return errs, dirs, files, (dn, fsz)


def parwalk(dn, mp, xstat, xdev):
    """Parallel dirwalk.

    Returns an async-result
    """

    ld = partial(listdir, xstat=xstat, xdev=xdev)
    a  = mp.apply_async(ld, args=(dn,))
    return a


def size(st):
    """Return disk size occupied by this file"""
    return st.st_blocks * 512


def null_units(n):
    return "%u" % n

def kilobytes(n):
    z = float(n) / 1024
    return "%8.2f kB" % z


def sighandler(a, b):
    #warn("** Keyboard interrupt. Exiting ..")
    sys.exit(1)

def main():
    global __doc__, Z

    signal.signal(signal.SIGINT, sighandler)

    ap = argparse.ArgumentParser(description=__doc__, conflict_handler='resolve')
    g  = ap.add_mutually_exclusive_group()
    g.add_argument("-b", "--bytes", action="store_true",
                    dest="abytes",   default=False,
                    help="Show exact byte count for utilization [False]")

    g.add_argument("-k", "--kilo-bytes", action="store_true",
                    dest="kilobytes",    default=False,
                    help="Show utilization in units of kilo bytes (1024) [False]")

    g.add_argument("-h", "--human", action="store_true",
                    dest="human",   default=True,
                    help="Show utilization in human readable units [DEFAULT]")

    ap.add_argument("-L", "--follow-symlinks", action="store_true",
                      dest="followlinks",      default=False,
                      help="Dereference symlinks and follow them [False]")

    ap.add_argument("-x", "--one-file-system", action="store_true",
                      dest="onefilesys",       default=False,
                      help="Don't descend mountpoints [False]")

    g  = ap.add_mutually_exclusive_group()
    g.add_argument("-a", "--all", action="store_true",
                    dest="all",   default=False,
                    help="Show all files, not just directories [False]")

    g.add_argument("-s", "--summarize", action="store_true",
                    dest="summary",     default=True,
                    help="Show summary for each argument [True]")

    ap.add_argument("-t", "--totals", action="store_true",
                    dest="totals",     default=False,
                    help="Show a grand total of all entries [False]")

    ap.add_argument("args", nargs="+", metavar="E",
            help="One or more files or directories")

    # Number of sets to keep
    a    = ap.parse_args()
    args = a.args

    # Config parameter
    xstat = os.stat if a.followlinks else os.lstat
    if a.abytes:
        units = null_units
    elif a.kilobytes:
        units = kilobytes
    else:
        units = human

    mp = m.Pool(processes=None, initializer=block_sigs)

    ee, ff, ww = [], [], []
    sizes = {}

    # Prime the pump
    for dn in args:
        sizes.setdefault(dn, 0L)
        try:
            st = xstat(dn)
        except Exception, ex:
            ee.append((dn, ex))
            continue

        if S_ISDIR(st.st_mode):
            dev = st.st_dev if a.onefilesys else 0
            w   = parwalk(dn, mp, xstat=xstat, xdev=dev)
            ww.append(w)
        elif S_ISREG(st.st_mode):
            sizes[dn] += size(st)


    # Reap jobs and feed the monster
    for w in ww:
        rr  = w.get()
        dd  = rr[1]
        ee += rr[0]

        if a.all: ff += rr[2]

        for d, st, dev in dd:
            x = parwalk(d, mp, xstat, xdev=dev)
            ww.append(x)

        # This is the rolled-up size of some subdirectory.
        # We try to apportion it to the right bucket.
        dn, dsz = rr[3]
        for nm in args:
            if dn.startswith(nm):
                sizes[nm] += dsz

    # Finish all jobs
    mp.close()
    for w in ww:
        w.wait()

    ev = [ str(ex) for nm, ex in ee ]
    es = "\n".join(ev)
    if len(ev) > 0:
        warn(es)

    # Now, print the final output - in decreasing utilization of space.
    tot = 0L
    vals = []
    for x in args:
        vals.append((sizes[x], x))
        tot += sizes[x]

    vals.sort(reverse=True)
    gg = ( "%8s %s" % (units(sz), nm) for sz, nm in vals )
    print '\n'.join(gg)

    if a.all:
        ff.sort(reverse=True)
        gg = ( "%8s %s" % (units(sz), nm) for sz, nm in ff )
        print '\n'.join(gg)

    if a.totals:
        print "%8s TOTAL" % units(tot)


main()
# EOF
