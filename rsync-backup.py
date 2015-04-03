#! /usr/bin/env python

#
# Simple script to backup things via rsync and keep the last N
# full backups. Uses hard links in the file system to efficiently
# store ENTIRE files.
#
# Sudhi Herle <sudhi@herle.net>
# License: GPLv2
# March 07, 2011
#
# Essential rsync invocation:
#   rsync -azH --link-dest=$PREV_BACKUP $SRC $DEST
#
# Usage:
#   $0  [options] daily|weekly|monthly SRC DEST
#

import os, sys, os.path
import subprocess, random
from os.path import dirname, basename, join, isdir
from shutil import rmtree
from optparse import OptionParser


# File extensions that shouldn't be compressed
No_compress = [
    ".zip",
    ".bz2",
    ".z",
    ".gz",
    ".iso",
    ".mp3",
    ".m4a",
    ".mp4",
    ".flv",
    ".wma",
    ".wmv",
    ".img",
    ".jpg",
    ".jpeg",
    ".JPG",
    ".PNG",
    ".png",
    ".pdf",
  ]


# Global vars
Z       = basename(sys.argv[0])
Dry_run = False
Skip_compress = '/tmp/.rsync_skip_compress%d' % random.randint(1000, 10000000)

def error(ex, fmt, *args):
    global Z

    sfmt = args and fmt % args or fmt
    print >>sys.stderr, "%s: %s" % (Z, sfmt)
    if ex:
        sys.exit(ex)


class actions(object):
    """Abstract class to capture a set of actions performed"""

    def __init__(self):
        pass

    def run(self, argv):
        """Run a command and exit if it fails"""

        try:
            r = subprocess.call(argv)
            if r > 0 or r < 0:
                error(r, "Subprocess '%s' failed: %d",
                        ' '.join(argv), r)
        except OSError, e:
                error(e.errno, "Subprocess '%s' failed: %s",
                        ' '.join(argv), e.strerror)


    def rename(self, old, new):
        os.rename(old, new)

    def mkdir(self, dn, mod=0755):
        os.makedirs(dn, mod)


class dry_run_actions(actions):
    """Abstract class that overrides basic actions to just print the
    actions."""

    def run(self, argv):
        print ' '.join(argv)

    def rename(self, old, new):
        print "mv %s %s" % (old, new)

    def mkdir(self, dn, mod=0755):
        print 'mkdir -p %s %#o' % (dn, mod)


def rotate_dir(act, dn, n):
    """Rotate a dir 'dn' by keeping only last 'n' dirs.
    
    Directory 'dn' is expected to be of the form NAME.NN where NN is
    a number.
    e.g., if we are rotating through 5 backups:

        0->1, 1->2, 2->3, 3->4, 4->5
        rm 5; 4->5, 3->4, 2->3, 1->2, 0->1
    """

    while n > 0:
        prev = n - 1
        nm   = "%s.%d" % (dn, n)
        p_nm = "%s.%d" % (dn, prev)

        if isdir(nm):
            act.run(['rm', '-rf', nm])

        if isdir(p_nm):
            act.rename(p_nm, nm)

        n = prev

    # At the end of the loop, DIR.0 is available
    i     = 1
    p_dir = None
    while  i < nbackups:
        nm = dn + ".%d" % i
        if isdir(nm):
            p_dir = dnm
            break
        i += 1

    return p_dir


def dpkg(act, dst, opt):
    """Run a dpkg --get-selections command either locally or remotely
    and fetch the output to be stored in the backup dir.
    
    Here, dst is the final backup dir.
    """
    dtmp = '/tmp/.dpkg_%d' % random.randint(10000, 1000000)


def rsync(act, src, dst, opt, linkdir=None):
    """Run rsync with --link-dest option and other options."""

    global Skip_compress

    rsync = [ 'rsync', '-azH', '--skip-compress=%s' % Skip_compress ]

    if opt.use_ssh or opt.ssh_key:
        ssh  = opt.ssh_key and " -i %s" % opt.ssh_key or ""
        if opt.ssh_user:
            ssh += " -l %s" % opt.ssh_user

        rsync += [ "--rsh=ssh%s" % ssh ]

    if linkdir:
        rsync += [ "--link-dest=%s" % linkdir ]

    if opt.verbose:
        rsync += [ "-v" ]

    rsync += [src, dst]

    act.run(rsync)



# main()
usage  = """%s - Reliable daily/weekly/monthly FULL backup using
rsync.

Usage: %s [options] daily|weekly|monthly  SRC DEST.

    SRC is passed intact to rsync
    DEST is augmented with daily/monthly etc. info to form a proper
    path before passing to rsync.
""" % (Z, Z)

parser = OptionParser(usage)
parser.add_option("-s", "--ssh", dest="use_ssh",
        action="store_true", default=False,
        help="Use rsync over SSH [%default]")
parser.add_option("-k", "--key", dest="ssh_key", type="string",
        action="store", default=None, metavar="K",
        help="Use key K as the SSH key for rsync over ssh [%default]")
parser.add_option("-u", "--ssh-user", dest="ssh_user", type="string",
        action="store", default='root', metavar="U",
        help="Use user U as the SSH user for rsync over ssh [%default]")
parser.add_option("-n", "--dry-run", dest="dry_run",
        action="store_true", default=False,
        help="Work in dry-run (don't act) mode [%default]")
parser.add_option("-N", "--backups", dest="nbackups", type="int",
        action="store", default=10, metavar="N",
        help="Keep the last N backups [%default]")
parser.add_option("-v", "--verbose", dest="verbose",
        action="store_true", default=False,
        help="Be verbose about all the actions [%default]")

opt, args = parser.parse_args()

if len(args) < 3:
    error(1, "Insufficient arguments. Try '%s --help'", Z)


actor = opt.dry_run and dry_run_actions() or actions()

typ = args[0]
src = args[1]
dst = args[2]


if not os.path.isabs(dst):
    error(1, "Destination path %s must be absolute path", dst)

if os.path.exists(dst) and not os.path.isdir(dst):
    error(1, "Destination path %s already exists, but is not a directory", dst)

backup_dir = join(dst, typ)
nbackups   = opt.nbackups
linkdir    = rotate_dir(actor, backup_dir, nbackups)

# make the skip-compress list
fd = file(Skip_compress, 'w')
fd.write('\n'.join(No_compress))
fd.close()

# Find a suitable linking directory


# Final backup dir
backup_dir += '.0'

# Keep with rsync conventions.
if not src.endswith('/'):
    src += '/'

rsync(actor, src, backup_dir, opt, linkdir)

os.unlink(Skip_compress)

# vim: expandtab:sw=4:ts=4:tw=72:
