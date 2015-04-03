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
#  - Cipher algorithm, HMAC algorithm are not captured in the header.
#  - HMAC verification is NOT done before decrypting the data. This is
#    by design to enable stream mode processing (via pipes)
#

import os, sys, stat, string
import argparse, random, getpass
import binascii, struct

from os.path              import dirname, abspath, normpath
from Crypto.Cipher        import AES, Blowfish
from Crypto.Hash          import SHA256, HMAC
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


# Fixed length header: KEYLEN, SALTLEN, KEY_ROUNDS
F_HDRFMT   = "> H H I"
F_HDRLEN   = 2 + 2 + 4

# Variable length header: SALT1, SALT2
V_HDRFMT   = "> %ds %ds" % (SALTLEN, SALTLEN)
V_HDRLEN   = SALTLEN + SALTLEN

# --- --- ---

def die(fmt, *args):
    if args:
        sfmt = fmt % args
    else:
        sfmt = fmt

    if not sfmt.endswith('\n'):
        sfmt += '\n'

    sys.stderr.write(sfmt)
    sys.stderr.flush()
    sys.exit(1)

def randbytes(n):
    """Get a random string of n bytes length"""
    rand  = StrongRandom()
    rbits = rand.getrandbits(8 * n)
    v     = ( chr(0xff & (rbits >> (i*8))) for i in range(n) )
    return ''.join(v)


charset = list(string.letters + string.digits)
def randchars(n):
    """Get a random string of n printable chars"""
    global charset

    random.shuffle(charset)
    x = random.sample(charset, n)
    random.shuffle(charset)

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

def nodump(fmt, *args):
    pass

def kdf(pw, klen=KEYLEN, rounds=KEY_ROUNDS):
    """Derive a key from the pass phrase.

    Return salt and key as a tuple"""

    salt = randbytes(SALTLEN)
    key  = PBKDF2(pw, salt, klen, rounds)

    return salt, key


def get_pass(env=None):
    """Read password from console or environment var"""

    if env:
        return os.environ.get(env, None)

    n = 0
    while True:
        n += 1
        pw1 = getpass.getpass("Enter password: ", sys.stderr)
        pw2 = getpass.getpass("Re-enter password: ", sys.stderr)
        if pw1 == pw2:
            return pw1

        if n > 3:
            print >>sys.stderr, "Too many mistakes. Bye!"
            sys.exit(1)
        else:
            print >>sys.stderr, "Passwords don't match. Try again.."



def encrypt(src, dest, pw, debugdump):
    """Encrypt input stream 'src' using password 'pw' and write encrypted data to
    output stream 'dest'
    """

    s1, k1 = kdf(pw, KEYLEN)
    s2, k2 = kdf(pw, KEYLEN)

    hmac   = HMAC.new(k1, digestmod=MAC)
    ctr    = Counter.new(8 * BLKSIZE)
    aes    = CIPHER.new(k2, CIPHER.MODE_CTR, counter=ctr)

    st1    = struct.Struct(F_HDRFMT)
    st2    = struct.Struct(V_HDRFMT)

    p1     = st1.pack(KEYLEN, SALTLEN, KEY_ROUNDS)
    p2     = st2.pack(s1, s2)

    hmac.update(p1)
    hmac.update(p2)

    dest.write(p1)
    dest.write(p2)


    debugdump("S1: %s  K1: %s", s1, k1)
    debugdump("S2: %s  K2: %s", s2, k2)
    debugdump("Header: %s %s", p1, p2)

    sz   = len(p1) + len(p2)

    while True:
        buf = src.read(BUF_SIZE)
        if not buf:
            break

        ebuf = aes.encrypt(buf)
        hmac.update(ebuf)
        dest.write(ebuf)
        sz += len(ebuf)

    mac = hmac.digest()
    dest.write(mac)

    debugdump("MAC: %s", mac)

    return sz + len(mac)


def decrypt(src, dest, pw, debugdump):
    """Decrypt input stream 'src' using password 'pw' and write decrypted data to
    output stream 'dest'.
    """

    buf1 = src.read(F_HDRLEN)
    if len(buf1) < F_HDRLEN:
        raise Exception("Header incomplete. Decryption impossible!")

    debugdump("Header-1: %s", buf1)

    st1  = struct.Struct(F_HDRFMT)
    keylen, saltlen, rounds = st1.unpack(buf1)

    # We can't calculate HMAC until we have k1.
    # i.e., we need to read the full header and derive keys etc.

    # Now, read the salt
    n    = 2 * saltlen
    fmt  = "> %ds %ds" % (saltlen, saltlen)
    st2  = struct.Struct(fmt)

    buf2 = src.read(n)
    if len(buf2) < n:
        raise Exception("Header incomplete. Decryption impossible!")

    s1, s2 = st2.unpack(buf2)

    k1  = PBKDF2(pw, s1, keylen, rounds)
    k2  = PBKDF2(pw, s2, keylen, rounds)

    debugdump("Header-2: %s", buf2)
    debugdump("S1: %s  K1: %s", s1, k1)
    debugdump("S2: %s  K2: %s", s2, k2)

    hmac = HMAC.new(k1, digestmod=MAC)
    ctr  = Counter.new(8 * BLKSIZE)
    aes  = CIPHER.new(k2, CIPHER.MODE_CTR, counter=ctr)

    hmac.update(buf1)
    hmac.update(buf2)

    sz   = 0
    prev = src.read(BUF_SIZE)
    while len(prev) == BUF_SIZE:
        buf = src.read(BUF_SIZE)
        if not buf:
            break

        hmac.update(prev)
        dbuf = aes.decrypt(prev)
        dest.write(dbuf)

        sz  += len(dbuf)
        prev = buf

    # Last block has the mac. Remove it before decrypting the rest of the content
    if len(prev) < MACSIZE:
        raise Exception("File corrupt? Last block too small (%d bytes)" % len(prev))

    file_mac = prev[-MACSIZE:]
    ebuf     = prev[:-MACSIZE]

    hmac.update(ebuf)
    mac  = hmac.digest()

    debugdump("filemac: %s", file_mac)
    debugdump("mac    : %s", mac)

    if file_mac != mac:
        raise Exception("File corrupt? MAC mismatch")

    dbuf = aes.decrypt(ebuf)
    dest.write(dbuf)
    sz += len(dbuf)
    return sz



def main():
    ap = argparse.ArgumentParser(description="""Portable encryption/decryption of file.
            Encryption uses AES-256. The user supplied passphrase is used to
            derive encryption and HMAC keys using the PBKDF2 function. Encrypted data is
            authenticated with HMAC-SHA-256.

            If both input and output file names are identical, then the script
            assumes in-place transformation and uses temporary files for the
            operation.
            """)

    g = ap.add_mutually_exclusive_group()
    g.add_argument("-e", "--encrypt", action="store_true",
                    dest="encrypt", default=True,
                    help="Run in encrypt mode [DEFAULT]")
    g.add_argument("-d", "--decrypt", action="store_false",
                    dest="encrypt", default=False,
                    help="Run in decrypt mode")

    ap.add_argument("--debug", action="store_true", dest="debug",
                    default=False,
                    help="Dump debug data to stderr [False]")
    ap.add_argument("-o", "--output", type=str, default=None, metavar='F',
                    help="Write output to file 'F' [Stdout]")
    ap.add_argument("-k", "--env-pass", type=str, default=None, metavar='E',
                    help="Read password from environment variable 'E' []")

    ap.add_argument("infile", nargs='?', help="Input file to encrypt [Stdin]")

    args = ap.parse_args()

    pwd = get_pass(args.env_pass)

    #print "PASS=%s ENV=%s" % (pwd, args.env_pass)

    infd  = sys.stdin
    outfd = sys.stdout

    # Verify for in place operation
    inplace = False
    if args.infile and args.output and args.output == args.infile:
        args.infile = abspath(normpath(args.infile))
        inplace = True
        indir   = dirname(args.infile)
        st      = os.stat(indir)
        if stat.S_IWUSR != (stat.S_IWUSR & st.st_mode):
            die("Directory %s is not writable for inplace operation.", indir)

        args.output = args.infile + randchars(8)

    if args.infile:
        infd = open(args.infile, 'rb', BUF_SIZE)

    if args.output:
        outfd = open(args.output, 'wb', BUF_SIZE)

    if args.debug:
        dbg = dump
    else:
        dbg = nodump

    if args.encrypt:
        encrypt(infd, outfd, pwd, dbg)
    else:
        decrypt(infd, outfd, pwd, dbg)

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
