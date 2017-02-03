#! /usr/bin/env python
#
#
# Portable file encrypt/decrypt using AES.
# Tested on:
#  - Python 2.7
#  - Python 3.4
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
import struct
import string

from binascii             import hexlify
from stat                 import S_ISREG, S_ISFIFO, S_ISSOCK, S_IWUSR, S_ISCHR
from struct               import pack, unpack
from os.path              import dirname, abspath, normpath
from Crypto.Cipher        import AES, Blowfish
from Crypto.Hash          import SHA256, SHA512, HMAC
from Crypto.Util          import Counter
from Crypto.Protocol.KDF  import PBKDF2

PY3K    = sys.version_info >= (3, 0)
CHARSET = list('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')

# Program version
# Increment with every change.
VERSION = '%(prog)s - 0.9'


# -- Parameters that are tunable --

SALTLEN    = 32
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

# Variable length header: SALT1, SALT2
V_HDRFMT   = "> %ds %ds" % (SALTLEN, SALTLEN)

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

def randchars(n):
    """Get a random string of n printable chars"""
    global CHARSET

    random.shuffle(CHARSET)
    x = random.sample(CHARSET, n)

    return ''.join(x)

def dump(fmt, *args):
    """Dump one or more variables containing binary data"""
    if args:
        v = ( hexlify(a) for a in args )
        x = fmt % tuple(v)
    else:
        x = fmt

    if not x.endswith('\n'):
        x += '\n'

    sys.stderr.write(x)
    sys.stderr.flush()

def hashem(pw):
    """hash the password once; expands shorter passwords"""
    h  = SHA512.new()
    lb = pack("> I", len(pw))
    h.update(lb)
    h.update(pw)
    return h.digest()

def get_pass(env=None, tries=1):
    """Read password from console or environment var"""
    global PY3K

    if PY3K:
        pwenc = lambda x: x.encode('utf-8')
    else:
        pwenc = lambda x: x

    if env:
        pw = os.environ.get(env, None)
        if not pw:
            die("Environment var %s is empty?", pw)

        return hashem(pwenc(pw))

    if tries == 1:
        pw = getpass.getpass("Enter password: ", sys.stderr)
        return hashem(pwenc(pw))

    n = 0
    while True:
        n  += 1
        pw1 = getpass.getpass("Enter password: ", sys.stderr)
        pw2 = getpass.getpass("Re-enter password: ", sys.stderr)
        if pw1 == pw2:
            return hashem(pwenc(pw1))

        if n < 3:
            warn("Passwords don't match. Try again..")
        else:
            die("Too many mistakes. Bye!")


def kdfprf(p, s):
    """Pseudo-random-function used by PBKDF2. We use HMAC-SHA512."""

    h0 = HMAC.new(p, digestmod=SHA512)
    h0.update(s)
    return h0.digest()


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
        self.infd    = None
        self.outfd   = None


    def makekeys(self, pw, salt1=None, salt2=None):
        blksize = self.cipher.block_size

        s1  = salt1 if salt1 else randbytes(self.saltlen)
        s2  = salt2 if salt2 else randbytes(self.saltlen)

        k1  = self.kdf(pw, s1, self.keylen, self.rounds, kdfprf)
        k2  = self.kdf(pw, s2, self.keylen, self.rounds, kdfprf)
        vf  = "> %ds %ds" % (self.saltlen, self.saltlen)
        h1  = pack(F_HDRFMT, 0x0, 0x0, 0x0, self.keylen, self.saltlen, self.rounds)
        h2  = pack(vf, s1, s2)

        # initial counter is derived from the salts above.
        iv0 = hashem(s1 + s2)[:16]
        iv  = int(hexlify(iv0), 16)

        ctr = Counter.new(8 * blksize, initial_value=iv)

        self.H   = HMAC.new(k1, digestmod=self.shash)
        self.C   = self.cipher.new(k2, self.cipher.MODE_CTR, counter=ctr)
        self.hdr = h1 + h2


    @classmethod
    def decbegin(klass, infd, pw):
        """Initialize decryption by reading from 'infd'.
        """

        hdr = infd.read(12) # fixed size header
        if len(hdr) < 12:
            die("Header incomplete, expected at least 12 bytes, saw %d bytes" % len(hdr))

        vv  = unpack(F_HDRFMT, hdr)
        ea  = vv[0]
        ha  = vv[1]
        ka  = vv[2]

        if ea != 0 or ha != 0 or ka != 0:
            die("Unsupported algorithms in the header")

        kl  = vv[3]
        sl  = vv[4]
        rr  = vv[5]

    
        hdr1 = hdr[:]
        sln  = sl + sl
        hdr  = infd.read(sln)
        if len(hdr) < sln:
            die("Header incomplete, expected %d bytes, saw %d bytes" % (sln, len(hdr)))

        vf  = "> %ds %ds" % (sl, sl)
        vv  = unpack(vf, hdr)
        cf  = cipher('AES', 'SHA256', 'PBKDF2', kl, sl, rr)

        cf.makekeys(pw, vv[0], vv[1])

        hdr = hdr1 + hdr
        lb  = pack(">I", len(hdr))
        cf.H.update(lb)
        cf.H.update(hdr)
        cf.infd = infd

        return cf

    def encbegin(self, pw, outfd):
        """Initialize operation"""

        self.makekeys(pw)

        lb = pack(">I", len(self.hdr))
        self.H.update(lb)
        self.H.update(self.hdr)
        outfd.write(self.hdr)
        self.outfd = outfd


    def enc(self, infd):
        """Encrypt by reading the input fd and writing to outfd"""

        n = 0
        outfd = self.outfd
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


    def dec(self, outfd):
        """Decrypt by reading the input and writing to outfd"""

        n    = 0
        infd = self.infd
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
            die("File corrupt? Last block too small (%d bytes)" % len(prev))

        file_mac = prev[-MACSIZE:]
        ebuf     = prev[:-MACSIZE]

        n += len(ebuf)
        self.H.update(ebuf)

        z = pack(">Q", n)
        self.H.update(z)
        mac  = self.H.digest()

        if file_mac != mac:
            die("File corrupt? MAC mismatch")

        dbuf = self.C.decrypt(ebuf)
        outfd.write(dbuf)


def regfile(a):
    """Return if st_mode info in 'a' points to a file or file like filesystem
    object"""

    return S_ISREG(a) or S_ISFIFO(a) or S_ISSOCK(a) or S_ISCHR(a)

def samefile(a, b):
    """Return True if a and b are the same file and dirname(a) is writable.

    Return False otherwise."""

    if not a: return False
    if not b: return False

    try:
        sta = os.stat(a)
    except Exception as ex:
        die("%s: %s", a, str(ex))

    # It is NOT an error for the output file to NOT exist!
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

def openif(nm, fd, mod):
    """Open 'nm' if non-null else, fdopen 'fd'"""

    return open(nm, mod, BUF_SIZE) if nm else os.fdopen(fd.fileno(), mod)

def main():
    global VERSION 

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
    ap.add_argument('-V', "--version", action='version', version=VERSION)


    g = ap.add_mutually_exclusive_group()
    g.add_argument("-e", "--encrypt", action="store_true",
                    dest="encrypt", default=True,
                    help="Run in encrypt mode [DEFAULT]")
    g.add_argument("-d", "--decrypt", action="store_false",
                    dest="encrypt", default=False,
                    help="Run in decrypt mode")

    ap.add_argument("infile", nargs='?', help="Input file to encrypt [Stdin]")

    args = ap.parse_args()

    # Don't ask for password twice if we are decrypting.
    pwd = get_pass(args.env_pass, tries=2 if args.encrypt else 1)

    #print "PASS=%s ENV=%s" % (pwd, args.env_pass)

    # Verify for in place operation
    inplace = False
    if samefile(args.infile, args.output):
        inplace     = True
        args.infile = abspath(normpath(args.infile))
        args.output = args.infile + randchars(8)


    infd  = openif(args.infile, sys.stdin,  'rb')
    outfd = openif(args.output, sys.stdout, 'wb')

    if args.encrypt:
        cf = cipher('AES', 'SHA256', 'PBKDF2', KEYLEN, SALTLEN, KEY_ROUNDS)
        cf.encbegin(pwd, outfd)
        cf.enc(infd)
    else:
        cf = cipher.decbegin(infd, pwd)
        cf.dec(outfd)

    outfd.close()
    infd.close()

    if inplace:
        tmp = args.infile + randchars(8)

        # Save the orig file temporarily
        try:
            os.rename(args.infile, tmp)
        except Exception as ex:
            os.unlink(args.output)
            die("Operation failed; Unable to create temporary restore point\n\t%s", str(ex))

        try:
            os.rename(args.output, args.infile)
        except Exception as ex:
            os.rename(tmp, args.infile)
            os.unlink(args.output)
            die("Operation failed; unable to rename transformed file back to original\n\t%s", str(ex))
        else:
            os.unlink(tmp)



main()

# vim: tw=82:notextmode:expandtab:sw=4:ts=4:
