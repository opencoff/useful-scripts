#! /usr/bin/env python

# pkill(1) and kill(1) replacement in python
#
# (c) 2010 Sudhi Herle <sudhi@herle.net>
# License: GPLv2
#
import sys, os, os.path, signal, re
from os.path import basename

Z           = basename(sys.argv[0])
Verbose   = False
Dry_run   = False
Use_regex = False
Ignore_case = False
# Raw character input
Getch       = None

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
 -i, --ignore-case Ignore case when matching names [False]
 -h, --help      Show this help message and quit
""" % (Z, Z, Z, Z, Z, Z)

def main(argv):
    global Z, Verbose, Dry_run

    procs, errs = parse_args(argv[1:])

    for k, v in procs.items():
        # k is the signal number, v is a list of process objects

        if Dry_run:
            x = '\n'.join(['kill -%d %7d %s' % (k, z.pid, z.name) for z in v])
            print(x)
            continue

        for p in v:
            x = ' '.join(p.command)
            s = "kill -%d %7d '%s'? [y/N]? " % (k, p.pid, x)
            r = prompt(s)
            if r < 0:
                sys.stdout.write('\n')
                sys.exit(0)

            if r > 0:
                os.kill(p.pid, k)
            sys.stdout.write('\n')


class process(object):
    """Abstraction of a process"""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.parent = None
        self.children = []

    def __str__(self):
        return "%d: %s" % (self.pid, self.name)

def ps_output(pscmd, n):
    """Open the ps command 'ps' and yield each line as a tuple.
    Join everything after 'n' th argument as a string.
    """
    fd = os.popen(pscmd, 'r')
    l  = fd.readline()  # first line has the titles
    for l in fd:
        l = l.strip()
        v = l.split(None, n-1)
        #print "%d: %s" % (len(v), v)
        yield v

    fd.close()


def _common_darwin_linux_pslist(psfmt):
    """Common processing block for Darwin & Linux for grokking "ps -axww" output."""

    plist = {}
    mypid = os.getpid()
    for v in ps_output(psfmt, 10):
        d = process(user=v[0],
               uid=int(v[1]),
               pid=int(v[2]),
               gid=int(v[3]),
               pgid=int(v[4]),
               ppid=int(v[5]),
               ruser=v[6],
               ruid=int(v[7]),
               rgid=int(v[8]),
               command=[v[9]],   # this is a list!
              )

        d.name = basename(d.command[0])


        if mypid != d.pid:
            #print "%s - %d" % (d['name'], d['pid'])
            plist[d.pid] = d

    return plist


# BSD, Linux ps commands are all same.
Psfmt = "ps axww -o 'user,uid,pid,gid,pgid,ppid,ruser,ruid,rgid,comm'"

def Darwin_pslist():
    """PS List for Darwin returned as an array of dicts"""

    return _common_darwin_linux_pslist(Psfmt)

def OpenBSD6_pslist():
    """PS List for OpenBSD returned as an array of dicts"""

    return _common_darwin_linux_pslist(Psfmt)

def Linux_pslist():
    """PS List for Darwin returned as an array of dicts"""

    return _common_darwin_linux_pslist(Psfmt)


def cygwin_pslist():
    """ps that uses cygwin's implementation.

    """
    psfmt = "ps -W -l"
    plist = {}
    mypid = os.getpid()
    for v in ps_output(psfmt, 7):
        cmd = v[6]
        d = bundle(pid=int(v[0]),
             ppid=int(v[1]),
             pgid=int(v[2]),
             winpid=int(v[3]),
             uid=int(v[5]),
             gid=0,
             ruid=0,
             rgid=0,
             state=0,
             command=cmd,
             name=os.path.basename(cmd)
            )
        if mypid != d.pid:
            plist[d.pid] = d

    return plist


class process_list(object):
    """Abstraction of system specific process listing.

    This is meant to be a singleton object.

    """

    PS = {
          'Darwin': Darwin_pslist,
          'darwin': Darwin_pslist,
          'Linux':  Linux_pslist,
          'linux':    Linux_pslist,
          'linux2':  Linux_pslist,
          'cygwin': cygwin_pslist,
          'openbsd6': OpenBSD6_pslist,
          'CYGWIN_NT-5.1': cygwin_pslist,
         }

    def __init__(self):
        self.by_pid  = {}
        self.by_name = {}

        #uname = os.uname()[0]
        uname = sys.platform
        psgrok = self.PS.get(uname, None)
        if psgrok is None:
            error(1, "don't know how to parse ps(1) on %s", uname)

        self.by_pid = psgrok()

        # Create reverse mappings of parents <-> children
        for p in self.by_pid.values():
            self.by_name.setdefault(p.name, []).append(p)
            parent = self.by_pid.get(p.ppid, None)
            if not parent:
                continue

            parent.children.append(p)
            p.parent = parent
            #print str(p)



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
        """Return all processes with the given name"""
        global Ignore_case

        pn = name.lower() if Ignore_case else name
        rr = []
        for nm, pv in self.by_name.items():
            ll = nm.lower() if Ignore_case else nm
            if ll == pn or ll.startswith(pn):
                rr += pv # Flatten and append

        return rr
        #return self.by_name.get(name, [])

    def match_rx(self, pat):
        """Return list of processes matching the regex 'pat'"""
        global Ignore_case

        ret = []
        rx  = re.compile(pat, re.IGNORECASE if Ignore_case else 0)
        for pid, proc in self.by_pid.items():
            #print proc
            if rx.search(proc.name):
                ret.append(proc)

        return ret

    def find_all(self, a):
        """Given a name or pid 'a', map it into a process object or a list
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
                procs.append += self.pgid(pid)
        else:
                p = self.pid(pid)
            if p:
                procs.append(p)
            else:
                error(0, "Can't find pid %s", a)
                retval += 1

        except  ValueError as e:
        if Use_regex:
                p = self.match_rx(a)
        else:
                p = self.named(a)

        if len(p) == 0:
            error(0, "Can't find Process '%s'", a)
                retval += 1
        else:
            procs += p

    return procs, retval

def show_help():
    print(Usage)



def parse_args(argv):
    """Clever command line parser that understands signal names or
    signal numbers.

    It builds a system specific list of signals and their
    corresponding names."""

    global Verbose, Dry_run, Use_regex, Ignore_case

    # First build a mapping of signal names to signum. Also turn it
    # into easily testable commandline option.
    sigs = {}
    for d in dir(signal):
        if d.startswith('SIG') and not d.startswith('SIG_'):
            nm  = d[3:]
            num = getattr(signal, d)
            sigs[d]           = num
            sigs[nm]          = num
            sigs[num]         = num
            sigs['-%s' % nm]  = num
            sigs['-%s' % d]   = num
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

        if a == "-i" or a == "--ignore-case" or a == "--ignore":
            Ignore_case = True
            continue

        if a.startswith('-'):
            sig = sigs.get(a, None)
            if sig is None:
                # XXX How do we grok pgid? especially if the pgid
                # happens to be the same _value_ as a signal!
                error(1, "Unknown option '%s'", a)
        else:
            killable, retval = proclist.find_all(a)
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
    return r


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



# global setup before main()
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


main(sys.argv)

# vim: notextmode:sw=4:ts=4:tw=128:expandtab:
