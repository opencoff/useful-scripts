#! /usr/bin/env python

# pkill(1) and kill(1) replacement in python
#
# (c) 2010 Sudhi Herle <sudhi@herle.net>
# License: GPLv2
#
import sys, os, os.path, signal, re

Z = os.path.basename(sys.argv[0])
Verbose   = False
Dry_run   = False
Use_regex = False

Usage = """Kill or Terminate a process.

%s [options] NAME|PID [NAME|PID ..]

%s -SIGNAME NAME|PID [NAME|PID ..]
%s -SIGNAME NAME|PID [NAME|PID ..] -SIGNAME2 NAME|PID [NAME|PID ...]
%s -SIGNUM  NAME|PID [NAME|PID ..]
%s -SIGNUM  NAME|PID [NAME|PID ..] -SIGNUM2  NAME|PID [NAME|PID ...]

%s is a pythonic replacement for kill(1) and pkill(1) that is agnostic to
PIDs or Process Names. Its default behavior is akin to 'kill -i'.

It takes as mandatory arguments the PID of the process to be killed
or the name of the process to be killed. If a given NAME maps to multiple
processes, then all processes matching that name are killed.

In all cases, the user is presented with an interactive prompt
before killing the process.

The default signal is SIGTERM.

Options:
 -n, --dry-run   Do not kill any process, only show what will be done [False]
 -r, --regex     For processes that are named, use regex matching [False]
 -h, --help      Show this help message and quit
""" % (Z, Z, Z, Z, Z, Z)



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



class process(object):
    """Abstraction of a process"""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.parent = None
        self.children = []


    def kill(self, sig=signal.SIGTERM):
        os.kill(self.pid, sig)

    def killchildren(self, sig=signal.SIGTERM):
        pass

    def killgroup(self, sig=signal.SIGTERM):
        pass

    def __str__(self):
        return "%s(%d)" % (self.command, self.pid)

def ps_output(pscmd, n):
    """Open the ps command 'ps' and yield each line as a tuple.
    Join everything after 'n' th argument as a string.
    """
    fd = os.popen(pscmd, 'r')
    l  = fd.readline()  # first line has the titles
    for l in fd:
        l = l.strip()
        v = l.split()
        if len(v) > n:
            x = v[n:]
            v = v[:n]
            v.append(' '.join(x))

        #print '|'.join(v)
        yield v

    fd.close()


def _common_darwin_linux_pslist(psfmt):
    """Common processing block for Darwin & Linux for grokking "ps -auxw" output."""

    plist = []
    mypid = os.getpid()
    for v in ps_output(psfmt, 10):
        cmd = v[10]
        d = {'user': v[0],
             'uid':     int(v[1]),
             'pid':     int(v[2]),
             'gid':     int(v[3]),
             'pgid':    int(v[4]),
             'ppid':    int(v[5]),
             'ruser':   v[6],
             'ruid':    int(v[7]),
             'rgid':    int(v[8]),
             'state':   v[9],
             'command': cmd,
             'name':    os.path.basename(cmd),
            }

        if mypid != d['pid']:
            #print "%s - %d" % (d['name'], d['pid'])
            plist.append(d)

    return plist


def Darwin_pslist():
    """PS List for Darwin returned as an array of dicts"""

    psfmt = "ps -axww -o 'user,uid,pid,gid,pgid,ppid,ruser,ruid,rgid,state,comm'"
    return _common_darwin_linux_pslist(psfmt)

def Linux_pslist():
    """PS List for Darwin returned as an array of dicts"""

    psfmt = "ps axww -o 'user,uid,pid,gid,pgid,ppid,ruser,ruid,rgid,state,args'"
    return _common_darwin_linux_pslist(psfmt)


def cygwin_pslist():
    """ps that uses cygwin's implementation.

    """
    psfmt = "ps -W -l"
    plist = []
    mypid = os.getpid()
    for v in ps_output(psfmt, 7):
        cmd = v[6]
        d = {'pid':     int(v[0]),
             'ppid':    int(v[1]),
             'pgid':    int(v[2]),
             'winpid':  int(v[3]),
             'uid':     int(v[5]),
             'gid':     0,
             'ruid':    0,
             'rgid':    0,
             'state':   0,
             'command': cmd,
             'name':    os.path.basename(cmd),
            }
        if mypid != d['pid']:
            plist.append(d)

    return plist


class process_list(object):
    """Abstraction of system specific process listing.

    This is meant to be a singleton object.

    """

    PS = {
          'Darwin': Darwin_pslist,
          'darwin': Darwin_pslist,
          'Linux':  Linux_pslist,
          'cygwin': cygwin_pslist,
          'CYGWIN_NT-5.1': cygwin_pslist,
         }

    def __init__(self):
        self.by_pid  = {}
        self.by_name = {}

        #uname = os.uname()[0]
        uname = sys.platform
        psgrok = self.PS.get(uname, None)
        assert psgrok is not None, "Can't find ps(1) specification for '%s'" % uname

        plist = psgrok()

        for d in plist:
            d['plist'] = self
            p = process(**d)

            self.by_pid[p.pid] = p
            self.by_name.setdefault(p.name, []).append(p)

        # Create reverse mappings of parents <-> children
        for p in self.by_pid.values():
            parent = self.by_pid.get(p.ppid, None)
            if not parent:
                continue

            parent.children.append(p)
            p.parent = parent


    def pid(self, p):
        """Return process with the given pid"""
        return self.by_pid.get(p, None)

    def pgid(self, pgid):
        """Return processes with the given pgid"""

        x = []
        for v in os.by_pid.values():
            if v.pgid == pgid:
                x.append(v)

        return x

    def named(self, name):
        """Return all processes with the given name in a case insensitive way"""
        pn = name.lower()
        rr = []
        for nm, pv in self.by_name.items():
            ll = nm.lower()
            if ll == pn or ll.startswith(pn):
                rr += pv # Flatten and append

        return rr
        #return self.by_name.get(name, [])

    def match_rx(self, pat):
        """Return list of processes matching the regex 'pat'"""

        ret = []
        p2  = re.escape(pat)
        rx  = re.compile(p2, re.IGNORECASE)
        for pid, proc in self.by_pid.items():
            #print proc
            if rx.search(proc.command):
                ret.append(proc)

        return ret

def show_help():
    print Usage


def map_name(a, proclist):
    """Given a name or pid, map it into a process object or a list
    of process objects.

    Note that a given 'name' can map to more than one process
    objects.
    """

    procs  = []
    retval = 0
    try:
        pid = int(a)
        if pid < 0:
            pid = -pid
            procs.append(proclist.pgid(pid))
        else:
            p = proclist.pid(pid)
            if p:
                procs.append(p)
            else:
                error(0, "Can't find pid %s", a)
                retval += 1

    except  ValueError, e:
        if Use_regex:
            p = proclist.match_rx(a)
        else:
            p = proclist.named(a)

        if len(p) == 0:
            retval += 1
            error(0, "Can't find Process '%s'", a)
        else:
            procs += p

    return procs, retval


def parse_args(argv):
    """Clever command line parser that understands signal names or
    signal numbers.

    It builds a system specific list of signals and their
    corresponding names."""

    global Verbose, Dry_run, Use_regex

    # First build a mapping of signal names to signum. Also turn it
    # into easily testable commandline option.
    sigs = {}
    for d in dir(signal):
        if d.startswith('SIG'):
            nm  = d[3:]
            num = eval('signal.%s' % d)
            sigs[nm]          = num
            sigs[num]         = num
            sigs['-%s' % nm]  = num
            sigs['-%d' % num] = num


    # Now process the command line args
    proclist = process_list()
    sig      = signal.SIGTERM
    procs    = {}
    errs     = 0
    for a in argv:
        if a == '-n' or a == "--dry-run":
            Dry_run = True
            continue

        if a == "-h" or a == "--help":
            show_help()
            sys.exit(0)
        
        if a == "-r" or a == "--regex":
            Use_regex = True
            continue

        if a.startswith('-'):
            sig = sigs.get(a, None)
            if sig is None:
                # XXX How do we grok pgid? especially if the pgid
                # happens to be the same _value_ as a signal!
                error(1, "Unknown option '%s'", a)
        else:
            killable, retval = map_name(a, proclist)
            if retval == 0:
                x = procs.setdefault(sig, [])
                x += killable

            errs += retval


    return procs, errs


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
    sys.stdout.write('\n')
    return r


def main(argv):
    global Z, Verbose, Dry_run

    procs, errs = parse_args(argv[1:])

    for k, v in procs.items():
        # k is the signal number, v is a list of process objects

        if not Dry_run:
            for p in v:
                s = "kill -%d %7d '%s'? [y/N]? " % (k, p.pid, p.command)
                r = prompt(s)
                if r > 0:
                    os.kill(p.pid, k)
                elif r < 0:
                    sys.exit(1)
        else:
            x = '\n'.join(['kill -%d %7d %s' % (k, z.pid, z.command) for z in v])
            print x


main(sys.argv)

# vim: notextmode:sw=4:ts=4:tw=128:expandtab:
