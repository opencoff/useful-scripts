#! /usr/bin/env python
#
#
# Portable file encrypt/decrypt using AES
# 
# (c) 2012 Sudhi Herle <sw at herle.net>
# License: GPLv2
#
# Notes:
#  - Does not seek the input or output streams. Thus, this script can
#    be used in a traditional pipe e.g.,
#      tar cf - somedir otherdir | gzip -9 | PW=foo encrypt.py -e -k PW -o backup.tar.gz.e
#  - Handles in-place encryption/decryption - i.e., if same file name is used as
#    the output file, the program does the "right thing"
#
#  - Uses PBKDF2 to derive two keys (one for hmac and one for cipher)
#  - AES in CTR mode
#  - Calc HMAC of encrypted bytes on the fly
#  - Salts, keylen, KDF rounds written as header (using struct.pack)
#  - HMAC written as trailer of encrypted stream
#  - Important information is captured in the header of the encrypted stream.
#    Thus, as long as header format stays same, future versions of the program
#    can still decrypt files encrypted with older version of script.
#
#  - Things that are parametrized are in ALL CAPS at the beginning of the file.
#
# Limitations:
#  - We only support AES-256, SHA-256 and PBKDF2 algorithms
#  - HMAC verification is NOT done before decrypting the data. This is
#    by design to enable stream mode processing (via pipes).
#

import os, sys, stat, string
import argparse, random, getpass
import binascii, struct

from stat                 import S_ISREG, S_IFIFO, S_IFSOCK, S_IWUSR
from struct               import pack, unpack
from os.path              import dirname, abspath, normpath
from Crypto.Cipher        import AES, Blowfish
from Crypto.Hash          import SHA256, SHA512, HMAC
from Crypto.Util          import Counter
from Crypto.Protocol.KDF  import PBKDF2
from Crypto.Random.random import StrongRandom


# -- Parameters that are tunable --

SALTLEN    = 16
KEYLEN     = 32     # AES-256
BUF_SIZE   = 65536  # I/O Bufsize

KEY_ROUNDS = 10000  # PBKDF2 rounds.
CIPHER     = AES
MAC        = SHA256

BLKSIZE    = CIPHER.block_size
MACSIZE    = MAC.digest_size


# Fixed identifiers for now
AES_id    = 0x0
SHA256_id = 0x0
PBKDF2_id = 0x0



# Fixed length header: ENCALGO, HASHALGO, KDFALGO, KEYLEN, SALTLEN, KEY_ROUNDS
F_HDRFMT   = "> B B B x H H I"
F_HDRLEN   = 2 + 2 + 4

# Variable length header: SALT1, SALT2
V_HDRFMT   = "> %ds %ds" % (SALTLEN, SALTLEN)
V_HDRLEN   = SALTLEN + SALTLEN

# --- --- ---

def warn(fmt, *args):
    if args:
        sf = fmt % args
    else:
        sf = fmt

    if not sf.endswith('\n'):
        sf += '\n'

    sys.stderr.write(sf)
    sys.stderr.flush()

def die(fmt, *args):
    warn(fmt, *args)
    sys.exit(1)

def randbytes(n):
    """Get a random string of n bytes length"""
    return os.urandom(n)


charset = list(string.letters + string.digits)
def randchars(n):
    """Get a random string of n printable chars"""
    global charset

    random.shuffle(charset)
    x = random.sample(charset, n)

    return ''.join(x)

def dump(fmt, *args):
    """Dump one or more variables containing binary data"""
    if args:
        v = ( binascii.hexlify(a) for a in args )
        x = fmt % tuple(v)
    else:
        x = fmt

    if not x.endswith('\n'):
        x += '\n'

    sys.stderr.write(x)
    sys.stderr.flush()

def hashem(pw):
    """hash the password once; expands shorter passwords"""
    h = SHA512.new()
    h.update(pw)
    return h.digest()


def get_pass(env=None):
    """Read password from console or environment var"""

    if env:
        return hashem(os.environ.get(env, None))

    n = 0
    while True:
        n += 1
        pw1 = getpass.getpass("Enter password: ", sys.stderr)
        pw2 = getpass.getpass("Re-enter password: ", sys.stderr)
        if pw1 == pw2:
            return hashem(pw1)

        if n > 3:
            print >>sys.stderr, "Too many mistakes. Bye!"
            sys.exit(1)
        else:
            print >>sys.stderr, "Passwords don't match. Try again.."


class cipher:
    """Abstraction of an encrypt/decrypt operation

    XXX We only support AES-256+SHA256+PBKDF2
    """

    def __init__(self, encalgo, hashalgo, kdfalgo, keylen, saltlen, rounds):
        #warn("enc=|%s| hash=|%s| kdf=|%s|, keylen=%d, saltlen=%d rounds=%d",
        #        encalgo, hashalgo, kdfalgo, keylen, saltlen, rounds)
        assert encalgo  == 'AES',    ("Encryption algorithm %s is unsupported" % encalgo)
        assert hashalgo == 'SHA256', ("Hash algorithm %s is unsupported" % hashalgo)
        assert kdfalgo  == 'PBKDF2', ("KDF algorithm %s is unsupported" % kdfalgo)

        self.kdf     = PBKDF2
        self.cipher  = AES
        self.shash   = SHA256
        self.keylen  = keylen
        self.saltlen = saltlen
        self.rounds  = rounds


    def makekeys(self, pw, salt1=None, salt2=None):
        blksize = self.cipher.block_size

        s1  = salt1 if salt1 else randbytes(self.saltlen)
        s2  = salt2 if salt2 else randbytes(self.saltlen)

        k1  = self.kdf(pw, s1, self.keylen, self.rounds)
        k2  = self.kdf(pw, s2, self.keylen, self.rounds)
        vf  = "> %ds %ds" % (self.saltlen, self.saltlen)
        h1  = pack(F_HDRFMT, 0x0, 0x0, 0x0, self.keylen, self.saltlen, self.rounds)
        h2  = pack(vf, s1, s2)

        ctr = Counter.new(8 * blksize)

        self.H  = HMAC.new(k1, digestmod=self.shash)
        self.C  = self.cipher.new(k2, self.cipher.MODE_CTR, counter=ctr)
        self.hdr = h1 + h2


    @classmethod
    def decbegin(klass, infd, pw):
        """Initialize decryption by reading from 'infd'.
        """

        hdr = infd.read(12) # fixed size header
        if len(hdr) < 12:
            raise Exception("Header incomplete, expected at least 12 bytes, saw %d bytes" % len(hdr))

        vv  = unpack(F_HDRFMT, hdr)
        ea  = vv[0]
        ha  = vv[1]
        ka  = vv[2]

        if ea != 0 or ha != 0 or ka != 0:
            raise Exception("Unsupported algorithms in the header")

        kl  = vv[3]
        sl  = vv[4]
        rr  = vv[5]

    
        hdr1 = hdr[:]
        sln  = sl + sl
        hdr  = infd.read(sln)
        if len(hdr) < sln:
            raise Exception("Header incomplete, expected %d bytes, saw %d bytes" % (sln, len(hdr)))

        vf  = "> %ds %ds" % (sl, sl)
        vv  = unpack(vf, hdr)
        cf  = cipher('AES', 'SHA256', 'PBKDF2', kl, sl, rr)

        cf.makekeys(pw, vv[0], vv[1])

        hdr = hdr1 + hdr
        lb  = pack(">I", len(hdr))
        cf.H.update(lb)
        cf.H.update(hdr)

        return cf

    def encbegin(self, pw, outfd):
        """Initialize operation"""

        self.makekeys(pw)

        lb = pack(">I", len(self.hdr))
        self.H.update(lb)
        self.H.update(self.hdr)
        outfd.write(self.hdr)


    def enc(self, infd, outfd):
        """Encrypt by reading the input fd and writing to outfd"""

        n = 0L
        while True:
            buf = infd.read(BUF_SIZE)
            if not buf:
                break

            eb = self.C.encrypt(buf)
            self.H.update(eb)
            outfd.write(eb)
            n += len(eb)

        z = pack(">Q", n)
        self.H.update(z)
        outfd.write(self.H.digest())


    def dec(self, infd, outfd):
        """Decrypt by reading the input and writing to outfd"""

        n    = 0L
        prev = infd.read(BUF_SIZE)
        while len(prev) == BUF_SIZE:
            buf = infd.read(BUF_SIZE)
            if not buf:
                break

            n += len(prev)
            self.H.update(prev)
            dbuf = self.C.decrypt(prev)
            outfd.write(dbuf)

            prev = buf

        # Last block has the mac. Remove it before decrypting the rest of the content
        if len(prev) < MACSIZE:
            raise Exception("File corrupt? Last block too small (%d bytes)" % len(prev))

        file_mac = prev[-MACSIZE:]
        ebuf     = prev[:-MACSIZE]

        n += len(ebuf)
        self.H.update(ebuf)

        z = pack(">Q", n)
        self.H.update(z)
        mac  = self.H.digest()

        if file_mac != mac:
            raise Exception("File corrupt? MAC mismatch")

        dbuf = self.C.decrypt(ebuf)
        outfd.write(dbuf)


def regfile(a):
    """Return if st_mode info in 'a' points to a file or file like filesystem
    object"""

    return S_ISREG(a) or S_IFIFO(a) or S_IFSOCK(a)

def samefile(a, b):
    """Return True if a and b are the same file and dirname(a) is writable.

    Return False otherwise."""

    if not a: return False
    if not b: return False

    try:
        sta = os.stat(a)
    except Exception, ex:
        die("%s: %s", a, str(ex))

    try:
        stb = os.stat(b)
    except:
        return False

    if not regfile(sta.st_mode):
        die("%s is not a file like entry?", a)

    if not regfile(stb.st_mode):
        die("%s is not a file like entry?", b)

    if sta.st_ino  != stb.st_ino:   return False
    if sta.st_dev  != stb.st_dev:   return False
    if sta.st_rdev != stb.st_rdev:  return False

    # Now, make sure the parent dir of 'a' is writable.
    adir = dirname(a)
    std  = os.stat(adir)
    if S_IWUSR != (S_IWUSR & std.st_mode):
        die("Directory %s is not writable for inplace operation.", adir)

    return True

def main():
    ap = argparse.ArgumentParser(description="""Portable encryption/decryption of file.
            Encryption uses AES-256. The user supplied passphrase is used to
            derive encryption and HMAC keys using the PBKDF2 function. Encrypted data is
            authenticated with HMAC-SHA-256.

            If both input and output file names are identical, then the script
            assumes in-place transformation and uses temporary files for the
            operation.
            """)

    ap.add_argument("-o", "--output", type=str, default=None, metavar='F',
                    help="Write output to file 'F' [Stdout]")
    ap.add_argument("-k", "--env-pass", type=str, default=None, metavar='E',
                    help="Read password from environment variable 'E' []")

    g = ap.add_mutually_exclusive_group()
    g.add_argument("-e", "--encrypt", action="store_true",
                    dest="encrypt", default=True,
                    help="Run in encrypt mode [DEFAULT]")
    g.add_argument("-d", "--decrypt", action="store_false",
                    dest="encrypt", default=False,
                    help="Run in decrypt mode")

    ap.add_argument("infile", nargs='?', help="Input file to encrypt [Stdin]")

    args = ap.parse_args()

    pwd = get_pass(args.env_pass)

    #print "PASS=%s ENV=%s" % (pwd, args.env_pass)

    infd  = sys.stdin
    outfd = sys.stdout

    # Verify for in place operation
    inplace = False
    if samefile(args.infile, args.output):
        inplace     = True
        args.infile = abspath(normpath(args.infile))
        args.output = args.infile + randchars(8)

    if args.infile:
        infd = open(args.infile, 'rb', BUF_SIZE)

    if args.output:
        outfd = open(args.output, 'wb', BUF_SIZE)

    if args.encrypt:
        cf  = cipher('AES', 'SHA256', 'PBKDF2', KEYLEN, SALTLEN, KEY_ROUNDS)
        cf.encbegin(pwd, outfd)
        cf.enc(infd, outfd)
    else:
        cf = cipher.decbegin(infd, pwd)
        cf.dec(infd, outfd)

    if inplace:
        outfd.close()
        infd.close()

        tmp = args.infile + randchars(8)

        # Save the orig file temporarily
        try:
            os.rename(args.infile, tmp)
        except:
            os.unlink(args.output)
            die("Operation failed; Unable to create temporary restore point")

        try:
            os.rename(args.output, args.infile)
        except:
            os.rename(tmp, args.infile)
            os.unlink(args.output)
            die("Operation failed; unable to rename transformed file back to original")
        else:
            os.unlink(tmp)

    else:
        if args.infile:
            infd.close()

        if args.output:
            outfd.close()


main()

# vim: tw=82:notextmode:expandtab:sw=4:ts=4:
