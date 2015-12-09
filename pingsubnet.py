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

# total size of data (payload)
ICMP_DATA_SIZE = 56  

ICMP_TYPE = 8
ICMP_CODE = 0
PID       = 0xffff & os.getpid()
Z         = os.path.basename(sys.argv[0])
__doc__   = """%s - Ping all the hosts in one or more subnets and return
the result.

Usage: %s [options] SUBNET [SUBNET..]
""" % (Z, Z)

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



def sockv4():
    """Return an IPv4 socket."""
    # can not create a raw socket if not root or setuid to root
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, \
                                   socket.getprotobyname("icmp"))
    except socket.error, e:
        die("You must be root (%s uses raw sockets)" % os.path.basename(sys.argv[0]))

    return sock


class ipv4(object):
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

    def _parse(self, st="0.0.0.0"):
        """Parse an ipv4 address string"""

        if type(st) == long:
            if st > 0xffffffffL:
                raise ValueError, "Malformed IP address '%l'" % st

            return st & 0xffffffffL

        try:
            x = long(st)
            if x > 0xffffffffL:
                raise ValueError, "Malformed IP address '%s'" % st
            return x & 0xffffffffL
        except:
            pass

        v = st.split('.')
        if len(v) != 4:
            raise ValueError, "Malformed IP address '%s'" % st

        try:
            vi = map(long, v)
        except:
            raise ValueError, "Malformed IP address '%s'" % st

        for x in vi:
            if x > 255 or x < 0:
                raise ValueError, "Malformed IP address '%s'" % st

        x = (vi[0] << 24) | (vi[1]  << 16) | (vi[2] << 8)  | vi[3]
        return x & 0xffffffffL

    def _parse_mask(self, st):
        """Intelligently grok a netmask"""

        if type(st) == long or type(st) == int:

            if st > self._max:
                return st

            else:
                return 0xffffffffL & (((2L << (st - 1)) - 1) << (32 - st))

        if st.find('.') < 0:
            try:
                v = long(st)
            except:
                raise ValueError, "Malformed netmask '%s'" % st

            if v > self._max:
                raise ValueError, "Too many bits in netmask '%s'" % st

            return 0xffffffffL & (((2L << (v - 1)) - 1) << (32 - v))
        else:
            return self._parse(st)

    @classmethod
    def tostr(cls, v):
        #v  = a._addr & 0xffffffffL;
        v0 =  v & 0xff
        v1 = (v >> 8)  & 0xff
        v2 = (v >> 16) & 0xff
        v3 = (v >> 24) & 0xff
        return "%s.%s.%s.%s" % (v3, v2, v1, v0)

    def _tostr(self, v):
        """Convert 'v' to string quad"""
        return ipv4.tostr(v)


    def _masklen(self, v):
        """Return cidr mask - number of set bits """

        # We actually cheat and count zero bits from the left and
        # subtract it from the max
        nz = 0L
        while v > 0:
            if v & 1:
                break

            nz += 1
            v >>= 1

        return self._max - nz


    def __init__(self, addr, mask=None):
        """Construct an IPv4 address"""
        self._max  = 32L

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
        return "%s/%d" % (self._tostr(self._addr), self._cidr)


    def __cmp__(self, other):
        """Return -1 if self < other; 0 if self == other; 1 if self > other"""
        a = self._addr
        b = other._addr
        x = a - b
        if x < 0:
            y = -1
        elif x > 0:
            y = +1
        else:
            y = 0
        return y

    def __hash__(self):
        """Return int usable as a key to dict"""
        return int(self._addr & 0x7fffffffL)

    # Accessor methods
    def cidr(self):
        return self.__repr__()

    def first(self):
        """Return the first IP address of the range"""
        net = 0xffffffffL & (self._addr & self._mask)
        return ipv4(net, self._mask)

    def __iter__(self):
        """Return iterator for range of addresses represented by this
        class"""
        return _ipv4iter(self)

    def count(self):
        """Count number of addresses in the range"""
        f = self._addr
        l = 0xffffffffL & (self._addr | ~self._mask)
        return l - f

    def last(self):
        """Return the last IP address of the range"""
        l = 0xffffffffL & (self._addr | ~self._mask)
        return ipv4(l, self._mask)

    def standard(self):
        return "%s/%s" % (self._tostr(self._addr), self._tostr(self._mask))

    def addr(self):
        return self._addr

    def addrstr(self):
        return ipv4.tostr(self._addr)

    def netmask(self):
        return self._mask

    def netmask_cidr(self):
        return self._masklen(self._mask)


    def net(self):
        """Return network number of this address+mask"""
        return 0xffffffffL & (self._addr & self._mask)


    def is_member_of(self, net):
        """Return true if IP is member of network 'net'"""
        try:
            v = net.netmask_cidr
        except:
            net = ipv4(net)

        mynet    = self._addr & net._mask;
        theirnet = net._addr  & net._mask;
        return mynet == theirnet

    def network(self):
        net = 0xffffffffL & (self._addr & self._mask)
        return "%s/%s" % (self._tostr(net), self._tostr(self._mask))

    def network_cidr(self):
        net = 0xffffffffL & (self._addr & self._mask)
        return "%s/%d" % (self._tostr(net), self._cidr)


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

        m = 0xffffffffL & (self.cur & self.mask)
        if m != self.last:
            raise StopIteration

        n = self.cur
        self.cur +=  1
        return ipv4(n, self.mask)

def icmpv4(idz, size, ipv6):
    """Constructs a ICMP echo packet of variable size
    """

    if size < int(struct.calcsize("d")):
        die("packet size too small, must be at least %d", int(struct.calcsize("d")))
    
    header = struct.pack('bbHHh', ICMP_TYPE, ICMP_CODE, 0, \
                         PID, idz)

    # if size big enough, embed this payload
    load = "--PING-PONG KING-KONG PING-KING-PONG-KONG!--"
    
    # space for time
    size -= struct.calcsize("d")

    # construct payload based on size, may be omitted :)
    rest = ""
    if size > len(load):
        rest = load
        size -= len(load)

    # pad the rest of payload
    rest += size * "X"

    # pack
    data     = struct.pack("d", time.time()) + rest
    checksum = _in_cksum(header+data)    # make checksum

    # Redo the header with the right checksum
    header   = struct.pack('bbHHh', ICMP_TYPE, ICMP_CODE, checksum, PID, \
                         idz)

    # ping packet *with* checksum
    return header + data 

class ping(object):
    """Abstraction of a ping request and a response for a given host.
    """
    def __init__(self, addr, maxpkts, ipv6=False, size=ICMP_DATA_SIZE):
        # size must be big enough to contain time sent
        if size < int(struct.calcsize("d")):
            die("packetsize to small, must be at least %d" % int(struct.calcsize("d")))

        self.addr   = addr
        self.ipv6   = ipv6
        self.size   = size
        self.seq    = 1; 
        self.mint   = 999
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

        pkt = icmpv4(self.seq, self.size, self.ipv6)
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
            pktHeader = pkt[0:8]
            pktType, pktCode, pktChksum, pktID, pktSeqnr = \
                      struct.unpack("bbHHh", pktHeader)

            # fetch starttime from pkt
            starttime = struct.unpack("d", pkt[8:16])[0]

        # IPv4
        else:
            # time to live
            rawPongHop = struct.unpack("s", pkt[8])[0]

            # convert TTL from 8 bit to 16 bit integer
            pktHop = int(hexlify(str(rawPongHop)), 16)

            # fetch pkt header
            pktHeader = pkt[20:28]
            pktType, pktCode, pktChksum, pktID, pktSeqnr = \
                      struct.unpack("bbHHh", pktHeader)

            # fetch starttime from pkt
            starttime = struct.unpack("d", pkt[28:36])[0]

        # valid ping packet received?
        #print >>sys.stderr, "%s: start=%d, rx=%d" % (self.addr, self.seq, pktSeqnr)
        if pktSeqnr < self.seq:
            self.rxpkt += 1
            triptime  = endtime - starttime # compute RRT
            self.tsum   += triptime            # triptime for all packets (stddev)
            self.tsumsq += triptime * triptime # triptime^2  for all packets (stddev)

            # compute statistic
            self.maxt = max ((triptime, self.maxt))
            self.mint = min ((triptime, self.mint))


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
        # stddev computation based on ping.c from FreeBSD
        lost   = self.txpkt - self.rxpkt
        avg    = self.tsum / self.rxpkt
        vari   = abs((self.tsumsq / self.rxpkt) - (avg * avg))
        # %-packet lost
        plost = 100.0 * (float(lost) / float(self.txpkt))

        s1 = "%d TX, %d RX, %d%% loss"  % \
              (self.txpkt, self.rxpkt, plost)

        s2 = ""
        if self.rxpkt > 0:
            try:
                s2 = " RTT min %.3f ms avg %.3f ms max %.3f ms stddev %.3f" % \
                      (self.mint*1000, avg*1000, self.maxt*1000, math.sqrt(vari)*1000)
            except Exception, ex:
                warn("%s: %s\n avg %.3f vari %.3f", self.addr, str(ex), avg, vari)

        return s1+s2


def pending(z):
    """Walk the dict and return pending items"""
    return [ v for v in z.values() if not v.done() ]

def deadhosts(z):
    return [v for v in z.values() if v.dead() ]

def livehosts(z):
    return [v for v in z.values() if not v.dead() ]


def simulping(h, args):
    fd      = sockv4()
    timeout = args.wait
    size    = args.maxpkt
    rem     = pending(h)

    #warn("%d total hosts ..", len(rem))

    # Prime the pump
    for a, p in h.items():

        # Send the first packet to each of the hosts
        pkt = p.next_packet()
        try:
            fd.sendto(pkt, (a, 1))
        except Exception, ex:
            #warn("%s: %s", a, str(ex))
            pass

    # Now, wait for things to come back
    while len(rem) > 0:
        #sys.stdout.write("%d pending .. \r" % len(rem))
        #sys.stdout.flush()
        #print "%d pending" % len(rem)

        rfd = []
        while True:
            rfd, wfd, xfd = select.select([fd], [], [], timeout)
            break

        # Notify everyone that we lost a bloody packet.
        if not rfd:
            #warn("Timeout; rem %d", len(rem))
            z = []
            for v in rem:
                v.lostpkt()
                pkt = v.next_packet()
                if pkt:
                    try:
                        z.append(v)
                        fd.sendto(pkt, (v.addr, 1))
                    except Exception, ex:
                        #warn("%s: %s", v.addr, str(ex))
                        pass

            # Restart the wait loop
            rem = z
            continue

        endtime = time.time()  # time packet received
        pkt, tup = fd.recvfrom(size+48)
        addr = tup[0]
        #warn("%s: RX %d bytes", addr, len(pkt))
        #print >>sys.stderr, "RX %d bytes from %s" % (len(pkt), addr)
        v = h.get(addr, None)
        if not v:
            #warn("%s: Wha?", addr)
            continue
        
        v.reply_in(pkt, endtime)

        pkt = v.next_packet()
        if pkt:
            fd.sendto(pkt, (addr, 1))

        #rem = pending(h)

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
    parser.add_argument("-v", "--verbose", dest='verbose', action="store_true",
                      default=False,
                      help="Show verbose ping summary [False]")

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
        for i in sn:
            a = i.addrstr()
            p = ping(a, maxpkt)
            h[a] = p
            

    if args.verbose:
        print "# %d total hosts" % len(h)

    simulping(h, args)

    if args.all:
        z =  h.values()
    elif args.dead:
        z = deadhosts(h)
    else:
        z = livehosts(h)

    # ipv4 objects can be naturally compared!
    zs = sorted(z)
    zp = []
    if args.verbose:
        zp = ( "%15s: %s" % (v.addr, v.summary()) for v in zs )
    else:
        zp = ( v.addr for v in zs )
    
    print '\n'.join(zp)


main()

# vim: notextmode:sw=4:ts=4:expandtab:tw=82:
