#!/usr/bin/env python

"""pingsubnet.py
 
 Ping one or more subnets and return the results.

 Original ICMP Ping code:
 Copyright (C) 2004 - Lars Strand <lars strand at gnist org>

 Subnet pinging code:
 Copyright (c) 2014-2015 - Sudhi Herle <sudhi at herle net>

 License
 =======
 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

 Note
 ====
 Must be running as root, or write a suid-wrapper. Since newer *nix
 variants, the kernel ignores the set[ug]id flags on #! scripts for
 security reasons.
"""

import sys, os, os.path, select
import struct, array
import time, math
import socket, string
import argparse
from binascii import hexlify
from datetime import datetime
from operator import attrgetter

# total size of data (payload)
ICMP_DATA_SIZE = 56  

ICMP_TYPE = 8
ICMP_CODE = 0
IPPROTO_ICMP = 1
Z         = os.path.basename(sys.argv[0])
__doc__   = """%s - Ping all the hosts in one or more subnets and return
the result.

Usage: %s [options] SUBNET [SUBNET..]
""" % (Z, Z)

Debug = 0

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-w", "--wait", dest='wait', action="store", type=float,
                      default=1.0, metavar="T",
                      help="Wait T seconds to conclude a host dead [1.0]")
    parser.add_argument("-n", "--max-packets", dest='maxpkt', action="store",
                      type=int, default=3, metavar="N",
                      help="Send 'N' ICMP_ECHO packets [%(default)d]")
    parser.add_argument("-s", "--size", dest='size', action="store",
                      type=int, default=ICMP_DATA_SIZE, metavar="N",
                      help="Send 'N' bytes of data in the ping packet [%(default)d]")
    parser.add_argument("-b", "--brief",  dest='brief', action="store_true",
                      default=False,
                      help="Show only IP addresses [False]")

    g = parser.add_mutually_exclusive_group()
    g.add_argument("--all", dest='all', action="store_true",
                      help="Show all hosts and responses [False]")
    g.add_argument("-d", "--dead", dest='dead', action="store_true",
                      help="Show all hosts that are non-response [False]")
    g.add_argument("-a", "--alive", dest='alive', action="store_true",
                      help="Show all hosts that are responsive [True]")

    parser.add_argument("subnets", nargs="+", type=ipv4, help="SUBNET [SUBNET..]")

    args = parser.parse_args()

    h = {}
    maxpkt = args.maxpkt

    size = 0
    for sn in args.subnets:
        for a in sn:
            s = a.addrstr()
            h[s] = ping(a, maxpkt)


    simulping(h, args)
    
    if args.all:
        z = h.values()
    elif args.dead:
        z = deadhosts(h)
    else:
        z = livehosts(h)

    zs = sorted(z, key=attrgetter('ipaddr'))
    if args.brief:
        zp = ( v.addr for v in zs )
    else:
        zp = ( "%15s: %s" % (v.addr, v.summary()) for v in zs )

    print('\n'.join(zp))

def simulping(h, args):
    """Ping concurrently"""

    fd      = sockv4()
    timeout = args.wait
    size    = args.maxpkt
    rem     = pending(h)

    debug("%d total hosts ..", len(rem))

    # Prime the pump
    for a, p in h.items():

        # Send the first packet to each of the hosts
        pkt = p.next_packet()
        try:
            fd.sendto(pkt, (a, 1))
        except Exception as ex:
            debug("tx %s: %s", a, str(ex))
            pass

    # Now, wait for things to come back
    while len(rem) > 0:
        debug("%d pending .. \r" % len(rem))

        rfd = []
        while True:
            rfd, wfd, xfd = select.select([fd], [], [], timeout)
            break

        # Notify everyone that we lost a bloody packet.
        if not rfd:
            debug("Timeout; rem %d", len(rem))
            z = []
            for v in rem:
                v.lostpkt()
                pkt = v.next_packet()
                if pkt:
                    try:
                        z.append(v)
                        fd.sendto(pkt, (v.addr, 1))
                    except Exception as ex:
                        debug("tx2 %s: %s", v.addr, str(ex))
                        pass

            # Restart the wait loop
            rem = z
            continue

        endtime = now()
        pkt, tup = fd.recvfrom(size+48)
        addr = tup[0]
        debug("%s: RX %d bytes", addr, len(pkt))
        v = h.get(addr, None)
        if not v:
            #warn("%s: Wha?", addr)
            continue

        v.reply_in(pkt, endtime)

        pkt = v.next_packet()
        if pkt:
            fd.sendto(pkt, (addr, 1))

        #rem = pending(h)



def sockv4():
    """Return an IPv4 socket."""
    # can not create a raw socket if not root or setuid to root
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, \
                                   socket.getprotobyname("icmp"))
    except socket.error as e:
        die("You must be root (%s uses raw sockets)" % os.path.basename(sys.argv[0]))

    return sock


class ipv4:
    """A Useful IPv4 address class.

    IPv4 Addresses can be constructed like so:

        >>> ipv4("128.99.33.43")
        >>> ipv4("128.99.33.43/18")
        >>> ipv4("128.99.33.43/255.255.255.248")

    Once constructed, the individual methods can be used to do a variety
    of operations:

        - Return CIDR address representation
        - Return range of addresses (an iterator)
        - Return netmask in standard (dotted-quad) or CIDR notation
        - Return first and last addresses of range
        - Return network encapsulating the address
        - Return number of addresses in range
    
    """

    _max = 32

    def _parse(self, st="0.0.0.0"):
        """Parse an ipv4 address string"""

        if type(st) == int:
            if st > 0xffffffff:
                raise ValueError, "Malformed IP address '%l'" % st

            return st & 0xffffffffL

        try:
            x = int(st)
            if x > 0xffffffff:
                raise ValueError, "Malformed IP address '%s'" % st
            return x & 0xffffffffL
        except:
            pass

        v = st.split('.')
        if len(v) != 4:
            raise ValueError, "Malformed IP address '%s'" % st

        try:
            vi = map(int, v)
        except:
            raise ValueError, "Malformed IP address '%s'" % st

        z = 0
        for x in vi:
            if x > 255 or x < 0:
                raise ValueError, "Malformed IP address '%s'" % st
            z = (z << 8) | x

        return z & 0xffffffff

    def _parse_mask(self, st):
        """Intelligently grok a netmask"""

        if type(st) == int:

            if st > self._max:
                return st
            else:
                return prefix_to_ipv4(st)

        if st.find('.') < 0:
            try:
                v = int(st)
            except:
                raise ValueError, "Malformed netmask '%s'" % st

            if v > self._max:
                raise ValueError, "Too many bits in netmask '%s'" % st

            return prefix_to_ipv4(v)
        else:
            return self._parse(st)

    @classmethod
    def tostr(cls, v):
        return _tostr(v)


    def _masklen(self, v):
        """Return cidr mask - number of set bits """

        return ipv4_to_prefix(v)


    def __init__(self, addr, mask=None):
        """Construct an IPv4 address"""

        if type(addr) != type(""):
            addr = repr(addr)

        if mask is None:
            str = addr
            i = str.find('/')
            if i < 0:
                self._addr = self._parse(str)
                self._mask = self._parse_mask("32")
            else:
                self._addr = self._parse(str[0:i])
                self._mask = self._parse_mask(str[i+1:])
        else:
            self._addr = self._parse(addr)
            self._mask = self._parse_mask(mask)

        self._cidr = self._masklen(self._mask)
        #print "addr=%lx mask=%lx cidrbits=%d" % (self._addr,
                #self._mask, self._cidr)


    def __repr__(self):
        return "%s/%d" % (_tostr(self._addr), self._cidr)

    def __str__(self):
        return self.__repr__()


    def __eq__(a, b):
        return a._addr == b._addr

    def __lt__(a, b):
        return a._addr < b._addr
    def __le__(a, b):
        return a._addr <= b._addr

    def __gt__(a, b):
        return a._addr > b._addr
    def __ge__(a, b):
        return a._addr >= b._addr

    def __ne__(a, b):
        return a._addr != b._addr

    def __hash__(self):
        """Return int usable as a key to dict"""
        return int(self._addr & 0x7fffffffL)

    def __iter__(self):
        """Return iterator for range represented by this CIDR"""
        return _ipv4iter(self)

    def __len__(self):
        """Return number of hosts spanned by this address range"""
        n = self._max - self._cidr
        return int(1 << n)

    # Accessor methods
    def cidr(self):
        return self.__repr__()

    def first(self):
        """Return the first IP address of the range"""
        net = 0xffffffff & (self._addr & self._mask)
        return ipv4(net, self._mask)

    def count(self):
        """Count number of addresses in the range"""
        f = self._addr
        l = 0xffffffff & (self._addr | ~self._mask)
        return l - f

    def last(self):
        """Return the last IP address of the range"""
        l = 0xffffffff & (self._addr | ~self._mask)
        return ipv4(l, self._mask)

    def standard(self):
        return "%s/%s" % (_tostr(self._addr), _tostr(self._mask))

    def addr(self):
        return self._addr

    def netmask(self):
        return self._mask

    def netmask_cidr(self):
        return self._masklen(self._mask)


    def addrstr(self):
        return _tostr(self._addr)

    def maskstr(self):
        return _tostr(self._mask)

    def net(self):
        """Return network number of this address+mask"""
        return 0xffffffff & (self._addr & self._mask)


    def is_member_of(self, net):
        """Return true if IP is member of network 'net'"""
        fp = getattr(net, "netmask_cidr", None)
        if fp is None:
            net = ipv4(net)

        mynet    = self._addr & net._mask;
        theirnet = net._addr  & net._mask;
        return mynet == theirnet

    def network(self):
        net = 0xffffffff & (self._addr & self._mask)
        return "%s/%s" % (_tostr(net), _tostr(self._mask))

    def network_cidr(self):
        net = 0xffffffff & (self._addr & self._mask)
        return "%s/%d" % (_tostr(net), self._cidr)

    tostr = classmethod(tostr)


def ipv4_to_prefix(n):
    """Convert IPv4 address 'a' (in integer representation) into prefix format."""

    if n == 0xffffffff: return 32
    if n == 0:          return 0

    for i in range(32):
        if n & 1: return 32-i
        n >>= 1


def prefix_to_ipv4(n):
    """Convert a 32-bit network prefix length into a IPv4 address"""
    ones = 0xffffffff
    return ones ^ (ones >> n)

def _tostr(v):
    """Convert IPv4 to dotted quad string"""
    v0 =  v & 0xff
    v1 = (v >> 8)  & 0xff
    v2 = (v >> 16) & 0xff
    v3 = (v >> 24) & 0xff
    return "%s.%s.%s.%s" % (v3, v2, v1, v0)


class _ipv4iter(object):
    """An IPv4 address iterator"""
    def __init__(self, addr):
        self.mask = addr.netmask()
        self.last = addr.net()
        self.cur  = addr.addr()

    def __iter__(self):
        return self

    def next(self):
        """Return the next address after self.cur"""

        m = 0xffffffff & (self.cur & self.mask)
        if m != self.last:
            raise StopIteration

        n = self.cur
        self.cur +=  1
        return ipv4(n, self.mask)


def icmpv4(pktid, seq, size, ipv6):
    """Constructs a ICMP echo packet of variable size
    """

    if size < 16: die("packet size too small, must be at least 16")

    header = struct.pack('BBHHH', ICMP_TYPE, ICMP_CODE, 0, pktid, seq)
    body   = string.printable
    size  -= struct.calcsize("Q")
    rest = ""
    while size > 0:
        n = size if len(body) > size else len(body)
        rest += body[:n]
        size -= n

    ts       = now()
    data     = struct.pack("Q", ts) + rest
    checksum = _in_cksum(header+data)
    header   = struct.pack('BBHHH', ICMP_TYPE, ICMP_CODE, checksum, pktid, seq)

    return header + data 

class ping(object):
    """Abstraction of a ping request and a response for a given host.
    """
    def __init__(self, addr, maxpkts, pktid=os.getpid(), ipv6=False, size=ICMP_DATA_SIZE):
        # size must be big enough to contain time sent
        if size < int(struct.calcsize("d")):
            die("packetsize to small, must be at least %d" % int(struct.calcsize("d")))

        self.ipaddr = addr
        self.addr   = addr.addrstr()
        self.pktid  = pktid
        self.ipv6   = ipv6
        self.size   = size
        self.seq    = 1; 
        self.mint   = 999 * 1000
        self.maxt   = 0.0
        self.avg    = 0.0
        self.lost   = 0
        self.tsum   = 0
        self.tsumsq = 0.0
        self.rxpkt  = 0
        self.txpkt  = 0

        self.lastpkt = self.seq + maxpkts


    def next_packet(self):
        """Return the next packet to be sent out.

        Returns a fully formed IP packet ready for transmission.
        """
        if self.seq >= self.lastpkt:
            return None

        pkt = icmpv4(self.pktid, self.seq, self.size, self.ipv6)
        self.seq += 1
        self.txpkt += 1

        # a perfectly formatted ICMP echo packet
        return pkt

    def lostpkt(self):
        self.lost += 1

    def reply_in(self, pkt, endtime):
        """Record a reply for this host.
        Updates the stats for this host.
        """

        # examine packet
        # fetch TTL from IP header
        if self.ipv6:
            # since IPv6 header and any extension header are never passed
            # to a raw socket, we can *not* get hoplimit field..
            # I hoped that a socket option would help, but it's not
            # supported:
            #   pingSocket.setsockopt(IPPROTO_IPV6, IPV6_RECVHOPLIMIT, 1)
            # so we can't fetch hoplimit..

            # fetch hoplimit
            #rawPongHop = struct.unpack("c", pkt[7])[0]

            # fetch pkt header
            typ, code, cksum, pktid, seq = struct.unpack("bbHHh", pkt[0:8])

            # fetch starttime from pkt
            starttime = struct.unpack("d", pkt[8:16])[0]

        # IPv4
        else:
            # XXX We assume no IP extension headers are present.
            # B B: V+IHL, DSCP+ESCN
            # H: Total Len
            # H: id
            # H: flags + fragoff
            # B B: TTL, Proto
            # H: Header cksum
            # I, I: Srcaddr, destaddr
            pv = struct.unpack("BBHHHBBHII", pkt[0:20])

            proto = pv[6]
            if proto != IPPROTO_ICMP: return

            orig = pkt
            pkt  = pkt[20:36]
            typ, code, cksum, pktid, seq = struct.unpack("BBHHH", pkt[0:8])

            # fetch starttime from pkt
            starttime = struct.unpack("Q", pkt[8:])[0]
            if pktid != self.pktid: return


        if seq >= self.seq: return

            self.rxpkt += 1
        triptime     = endtime - starttime
        self.tsum   += triptime
        self.tsumsq += triptime * triptime

            # compute statistic
        self.maxt = max(triptime, self.maxt)
        self.mint = min(triptime, self.mint)


    def done(self):
        """Return True if we are done with this host"""
        return self.seq >= self.lastpkt

    def dead(self):
        return self.rxpkt == 0

    def summary(self, verb=False):
        """Show a summary for this host"""

        # UGH. Some Dell Printers reply too many times!
        if self.rxpkt > self.txpkt:
            self.rxpkt = self.txpkt

        # compute and print som stats
        lost   = self.txpkt - self.rxpkt
        plost = 100.0 * (float(lost) / float(self.txpkt))

        s1 = "%d TX, %d RX, %d%% loss"  % \
              (self.txpkt, self.rxpkt, plost)

        s2 = ""
        if self.rxpkt > 0:
            # stddev computation based on ping.c from FreeBSD
            avg  = (float(self.tsum) / self.rxpkt)
            vari = abs((float(self.tsumsq) / self.rxpkt) - (avg * avg))
                s2 = " RTT min %.3f ms avg %.3f ms max %.3f ms stddev %.3f" % \
                       (self.mint/1000.0, avg/1000.0, self.maxt/1000.0, math.sqrt(vari)/1000.0)
        return s1+s2



def now():
    """Return time in microseconds as uint64 """
    n = datetime.utcnow()
    s = 0 + (((n.hour * 60) + n.minute) * 60) + n.second
    s = n.microsecond + (s * 1000000)
    return s

def pending(z):
    """Walk the dict and return pending items"""
    return [ v for v in z.values() if not v.done() ]

def deadhosts(z):
    return [v for v in z.values() if v.dead() ]

def livehosts(z):
    return [v for v in z.values() if not v.dead() ]


def die(fmt, *args):
    """Exit if running standalone, else raise an exception
    """
    warn(fmt, *args)
    sys.exit(1)

def warn(fmt, *args):
    sfmt = "%s: %s" % (Z, fmt)
    if len(args) > 0:
        sfmt = sfmt % args

    if not sfmt.endswith('\n'):
        sfmt += '\n'
    sys.stderr.write(sfmt)
    sys.stderr.flush()

def debug(fmt, *args):
    global Debug
    if not Debug:
        return

    z = fmt % args if len(args) > 0 else fmt
    if not z.endswith('\n'): z += '\n'

    sys.stderr.write(z)
    sys.stderr.flush()


def _in_cksum(packet):
    """THE RFC792 states: 'The 16 bit one's complement of
    the one's complement sum of all 16 bit words in the header.'

    Generates a checksum of a (ICMP) packet. Based on in_chksum found
    in ping.c on FreeBSD.
    """
            
    # add byte if not dividable by 2
    if len(packet) & 1:
        packet = packet + '\0'

    # split into 16-bit word and insert into a binary array
    words = array.array('h', packet)
    s = 0

    # perform ones complement arithmetic on 16-bit words
    for word in words:
        s += (word & 0xffff)

    hi = s >> 16
    lo = s & 0xffff
    s = hi + lo
    s = s + (s >> 16)

    return (~s) & 0xffff # return ones complement
    
def hexdump(src, stride=16, sep='.'):
    chrtab = [(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)]
    lines  = []
    for c in xrange(0, len(src), stride):
        chars = src[c:c+stride]
        hexb  = ' '.join(["%02x" % ord(x) for x in chars])
        if len(hexb) > 24:
            hexb = "%s %s" % (hexb[:24], hexb[24:])
        pr = ''.join(["%s" % chrtab[ord(x)] for x in chars])
        lines.append("%08x:  %-*s  |%s|" % (c, stride*3, hexb, pr))

    return '\n'.join(lines)

main()

# vim: notextmode:sw=4:ts=4:expandtab:tw=82:
