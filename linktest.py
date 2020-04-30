#! /usr/bin/env python

# Utility to verify link status of one or more interfaces
#
# Author: Sudhi Herle <sudhi@herle.net>
#
import os, sys, os.path
import re
#import paramiko

from optparse import Option, OptionParser, OptionValueError

__version__ = '0.1.1'

Z = os.path.basename(sys.argv[0])
Verbose = False

# Regexps to parse output of mii-tool
speed_rx = re.compile(r'negotiated\s+(\d+)base..-(..)')
link_rx  = re.compile(r'link\s+(\w+)')

# Help string
__doc__ = """%s - Simple link checking utility.

Usage: %s [options] interface [interface ..]

Where interface is an ethernet interface on the machine. e.g.,
    %s eth0 eth1

In verbose mode, this script writes logs to stderr.""" % (Z, Z, Z)


def verbose(fmt, *args):
    """Print a verbose message to syslog"""
    if not Verbose:
        return

    s = (fmt % args) if args else fmt
    print(s, file=sys.stderr)
    sys.stderr.flush()
    

def error(doex, fmt, *args):
    """Show error message and die if doex > 0"""
    sfmt = "%s: %s" % (Z, fmt)
    s = (fmt % args) if args else fmt
    print(s, file=sys.stderr)
    if doex > 0:
        sys.exit(doex)


class command:
    """Abstract class for command execution pattern"""
    def __init__(self, **kwargs):
        pass

    def run(self, cmd):
        pass

class remote_command(command):
    """Class to encapsulate remotely executed command"""
    def __init__(self, **kwargs):
        paramiko.util.log_to_file('/dev/null')
        self.ssh = paramiko.SSHClient()
        self.ssh.load_system_host_keys()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh_user = SSH_user

        try:
            verbose("Connecting to %s:%d as %s [%s] ...", SSH_peer, SSH_port,
                     SSH_user, SSH_identity)
            self.ssh.connect(hostname=SSH_peer, port=SSH_port,
                             username=SSH_user, key_filename=SSH_identity)
            self.connected = True
            verbose("Connected to %s:%d for remote ping", SSH_peer, SSH_port)
        except:
            error(1, "Unable to connect to %s:%d via SSH", SSH_peer, SSH_port)


    def run(self, cmd):
        verbose("remote cmd=%s", cmd)
        fdin, fdout, fderr = self.ssh.exec_command(cmd)
        return fdin, fdout, fderr

    def run_sudo(self, cmd):
        if self.ssh_user != 'root':
            cmd = "sudo %s" % cmd

        return self.run(cmd)

class local_command(command):
    """Class to encapsulate locally executed command"""
    def __init__(self, **kwargs):
        self.nossh = True

    def run(self, cmd):
        verbose("local cmd=%s", cmd)
        fdin, fdout, fderr = os.popen3(cmd)
        return fdin, fdout, fderr

    def run_sudo(self, cmd):
        cmd = "sudo %s" % cmd
        return self.run(cmd)


# mapping fields from ethtool output to simple names
field_map = { 'Supported ports': 'ports',
    'Supported link modes': 'sup_link_modes',
    'Supports auto-negotiation': 'sup_autoneg',
    'Advertised link modes':  'adv_link_modes',
    'Advertised auto-negotiation': 'adv_autoneg',
    'Speed': 'speed',
    'Duplex': 'duplex',
    'Port': 'port',
    'Auto-negotiation': 'autoneg',
    'Link detected': 'link',
}


def parse_miitool_output(fd):
    """parse output of mii-tool"""

    duplex_map = {'FD': 'full',
                  'HD': 'half',
                 }
    fields = {'speed':  "-",
              'link':   "-",
              'duplex': "-",
             }
    line = fd.readline().strip()
    if len(line) == 0:
        return fields

    verbose("   line=|%s|", line)
    r     = line.find(':')
    iface = line[:r].strip()
    rest  = line[r+1:].strip()

    if rest == "no link":
        fields['link'] = 'no'
        return fields

    speed  = "-"
    duplex = "-"
    link   = '-'

    rest  = map(lambda x: x.strip(), rest.split(','))
    verbose("iface=%s rest=%s", iface, repr(rest))
    m = speed_rx.match(rest[0])
    if m is not None:
        speed  = m.group(1)
        duplex = m.group(2)
        if speed.startswith('1000'):
            speed = '1Gb/s'
        elif speed.startswith('100'):
            speed = '100Mb/s'
        else:
            speed = '10Mb/s'

        duplex = duplex_map[duplex]

    if len(rest) > 1:
        m = link_rx.match(rest[1])
        if m is not None:
            link = m.group(1)

    if link == 'ok':
        link = 'yes'
    else:
        link = 'no'

    fields['link']   = link
    fields['speed']  = speed
    fields['duplex'] = duplex
    return fields

def parse_ethtool_output(fd):
    """parse ethtool output"""

    # Skip first line
    fd.readline()
    fields = {}
    field  = ""
    fields['speed']  = "-"
    fields['link']   = "-"
    fields['duplex'] = '-'
    for line in fd:
        line = line.rstrip()
        r    = line.find(':')
        #verbose("       line=|%s|", line)
        if r > 0:
            field = line[:r].strip()
            if field not in field_map:
                continue
            field = field_map[field]
            data  = line[r+1:].strip()
            fields[field] = data
            verbose("  %s=%s", field, data)
        else:
            if len(field) > 0:
                fields[field] +=  ' ' + line.strip()

    #print fields
    return fields

def lowerize(fields, t):
    """Change some dict values to lower case. The keys are in tuple 't'"""
    
    for f in t:
        val = fields[f]
        fields[f] = val.lower()


def run_miitool(iface):
    """run mii-tool and return dict of interesting fields"""
    fdin, fdout, fderr = cmdobj.run_sudo("mii-tool %s" % iface)
    fields = parse_miitool_output(fdout)
    fdout.close()
    fdin.close()
    fderr.close()
    return fields


def run_ethtool(iface):
    """run ethtool and return dict of interesting fields"""
    fdin, fdout, fderr = cmdobj.run_sudo("ethtool %s" % iface)
    fields = parse_ethtool_output(fdout)
    fdout.close()
    fdin.close()
    fderr.close()
    lowerize(fields, ('link', 'duplex'))
    return fields


def link_test(cmdobj, iface):
    """Run link test command on interface 'iface'"""

    # First try mii-tool
    fields = run_miitool(iface)
    if fields['link'] == '-':
        fields = run_ethtool(iface)

    result = "OK"
    if fields['link'] != 'yes':
        result = "NOPE"

    print("%s %s link=%s speed=%s duplex=%s" % (result, iface, fields['link'],
            fields['speed'], fields['duplex']))


# -- main() --
parser = OptionParser(__doc__)
parser.add_option("-v", "--verbose", dest='verbose', action="store_true",
                  default=False,
                  help="Be verbose about actions [False]")

#pv = paramiko.__version_info__
#if pv[0] < 1 and pv[1] < 6:
#    error(1, "python-paramiko on this platform is not suitable; need at least v1.6.0")

(opt, args) = parser.parse_args()
argc = len(args)
if argc < 1:
    error(1, "Usage: %s [options] interface [interface ..]", Z)


Verbose = opt.verbose
cmdobj  = local_command()
for a in args:
    if not os.path.isdir('/sys/class/net/%s' % a):
        print("ERR %s No such interface" % a)
        continue

    link_test(cmdobj, a)

# vim: tw=82:sw=4:ts=4:expandtab:notextmode:
