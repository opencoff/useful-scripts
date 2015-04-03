#! /usr/bin/env python

#
# Simple tool to manage SSL PKI infrastructure
#
# This script helps manage local CA, server certs, client certs, CRLs
# etc.
#
# Author: Sudhi Herle <sw @ herle.net>
# (c) Sudhi Herle
# License: GPLv2 http://www.gnu.org/licenses/old-licenses/gpl-2.0.html

import os, sys, signal, glob
import string, textwrap, cStringIO
import shutil, ConfigParser, random
import subprocess, re, zipfile
from os.path import basename, dirname, abspath, normpath, join
from optparse import Option, OptionParser, OptionValueError
from datetime import datetime
import smtplib, random
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders

# GLobal vars
Z         = basename(sys.argv[0])
Quit_Loop = False
Debug     = False
Verbose   = False
DB        = None
Prompt    = "(cert-tool) "


__version__ = "1.0"
__author__  = "Sudhi Herle <sw @ herle.net>"
__license__ = "GPLv2 [http://www.gnu.org/licenses/old-licenses/gpl-2.0.html]"



def sighandler(sig,frm):
    """Trivial signal handler"""
    global Quit_Loop
    Quit_Loop = True


def _exit(rc):
    """Wrapper around sys.exit() to close the user database"""
    sys.exit(rc)

def error(doexit, fmt, *args):
    """Clone of the glibc error() function"""
    sfmt = "%s: %s" % (Z, fmt)
    sys.stdout.flush()
    print >>sys.stderr, sfmt % args
    sys.stderr.flush()
    if doexit:
        _exit(1)

def debug(fmt, *args):
    """Print a debug message"""
    global Debug
    if not Debug:
        return

    sfmt = "# %s" % fmt
    print sfmt % args
    sys.stdout.flush()


def progress(fmt, *args):
    """Print a progress message"""
    global Verbose
    if not Verbose:
        return

    print fmt % args
    sys.stdout.flush()


def today():
    """Return today's time in string form"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")
    return now


def randnum(n=4):
    """Return a 'n' decimal digit random number"""

    l = 10L ** (n - 1)
    #print "%ld <= x < %ld" % (l, l *10)
    v = random.randint(l, (l * 10) - 1)
    return v
    #return "%ld" % v


def randpass(n):
    """Generate password n bytes long chosen from chars in
    sampleset"""

    sampleset = list(string.letters + string.digits)
    random.shuffle(sampleset)

    x = []
    size = len(sampleset)
    while n > 0:
        if n > size:
            s = size
        else:
            s = n

        x += random.sample(sampleset, s)
        n -= s

    return ''.join(x)


def randenv():
    """Generate a random environment var name"""

    a = randpass(8)
    if a[0] in string.digits:
        a = "x" + a

    return a


class ex(Exception):
    """Our exception"""
    def __init__(self, str, *args):
        self.str = str % args
        Exception.__init__(self, self.str)

    def __repr__(self):
        return self.str

    __str__ = __repr__


def abbrev(wordlist):
    """abbrev - a simple function to generate an abbreviation table of
       unambiguous words from an input wordlist.

       Originally from perl4/perl5 sources.

       Converted to Python by Sudhi Herle <gnu@herle.net>

       Copyright (C) 2004-2005 Free Software Foundation
       Python code (C) 2005-2008 Sudhi Herle <sudhi@herle.net>

       Licensed under the terms of Aritistic License (Perl) or GNU GPLv2.

        Synopsis::

            import abbrev

            table = abbrev.abbrev(wordlist)

        Stores all unambiguous truncations of each element of
        `wordlist` as keys in a table. The values in the table are
        the original list elements.

        Example::

            wordlist = [ "help", "hello", "sync", "show" ]
            table = abbrev.abbrev(wordlist)

            print table

            # Read short-form from stdin
            short_form = sys.stdin.readline().strip()

            # Now, given an abbreviation of one of the words in
            # 'wordlist', you can check if the abbreviation
            # is unique like so:
            if short_form not in table:
                print "No unique abbreviation available"

        This will print::

            {'sy': 'sync', 'help': 'help', 'show': 'show',
             'sync': 'sync', 'syn': 'sync', 'sh': 'show',
             'hell': 'hello', 'hello': 'hello', 'sho': 'show'}

        (The order of the keys may differ depending on your
        platform)

    """

    abbrev_seen = {}
    table = {}
    for word in wordlist:
        table[word] = word[:]
        l = len(word)-1
        while l > 0:
            ab = word[0:l]
            if ab in abbrev_seen:
                abbrev_seen[ab] = abbrev_seen[ab] + 1
            else:
                abbrev_seen[ab] = 0
            ntimes = abbrev_seen[ab]
            if ntimes == 0:     # first time we're seeing this abbrev
                table[ab] = word
            elif ntimes == 1:
                # This is the second time. So, 'ab' is ambiguous.
                # And thus, can't be used in the final dict.
                del table[ab]
            else:
                break
            l = l - 1


    return table   


def rename(a, b):
    """Rename a -> b.
    
    On Win32, os.rename() fails for destination files that exist.
    """

    if os.path.exists(b):
        if os.path.isfile(b):
            os.unlink(b)
        elif os.path.isdir(b):
            rmtree(b)
        else:
            raise ex("Unknown file type for '%s'; can't rename!" % b)

    os.rename(a, b)


def openssl(cmd, argv, additional_env={}, use_config=True):
    """Convenient wrapper around the openssl command. It sets up some
    standard environment variables and also changes directory to the
    certificate db dir.

    If additional_env is present, it is appended to the sub-processes'
    environment.

    If use_config is false, then the "-config $CONFIG_FILE" option won't
    be passed on the openssl command line.
    """

    global DB, Verbose

    db   = DB
    pwd  = os.getcwd()

    args = ['openssl', cmd, ] +  argv
    if use_config:
        args += [ '-config', DB.sslconf ]

    if Verbose:
        args += [ '-verbose' ]

    #os.chdir(db.crtdir)

    env = os.environ.copy()
    env.update(DB.config_file().ssl_env())
    env.update(additional_env)

    debug("PWD: %s", os.getcwd())
    debug("OpenSSL: %s", ' '.join(args))
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

    err = p.stderr.readlines()
    ex  = p.wait()
    if ex < 0:
        error(0, "Process 'openssl %s' caught signal %d and died!",
               cmd, -ex)
        if len(err) > 0:
            error(1, ''.join(err))
        else:
            _exit(1)
    elif ex > 0:
        error(0, "Process 'openssl %s' exited abnormally (code %d); error follows..", cmd, ex)
        if len(err) > 0:
            error(1, ''.join(err))
        else:
            _exit(1)

    debug("OpenSSL %s: OK", cmd)
    #os.chdir(pwd)


def edit_file(filename):
    """Fork an editor and edit the file 'filename'"""


    print """
        Starting Editor for
           %s

        Please edit the file and update the various fields appropriately
        before using this tool to create new certificates.

        Starting editor ..
        """ % filename

    dn  = dirname(filename)
    tmp = filename + '.tmp_%d' % os.getpid()
    shutil.copy2(filename, tmp)

    ed  = None
    for k in [ 'EDITOR', 'VISUAL', ]:
        ed = os.environ.get(k, None)
        if ed is not None:
            break
    if ed is None:
        error(0, "Can't find usable editor to edit %s", filename)
        raise ex("Please set environment var EDITOR appropriately")

    argv = [ ed, tmp ]
    debug("Calling '%s' ..", ' '.join(argv))
    rc = subprocess.call(argv)
    if rc < 0:
        error(1, "Process '%s' caught signal %d and died!",
               ed, -rc)
    elif rc > 0:
        error(1, "Process '%s' exited abnormally (code %d)", ed, rc)

    rename(tmp, filename)

    # Remove any stale temporaries
    for f in glob.iglob(tmp + "*"):
        os.unlink(f)


def create_file(fn, s):
    """Create file 'fn' with the contents from string 's'"""
    tmp = fn + '.tmp'
    fd = open(tmp, 'w')
    fd.write(s)
    fd.close()

    debug("Created file %s..", fn)
    rename(tmp, fn)


def rmfiles(*files):
    """Remove one or more files"""
    debug("# rm -f %s", ' '.join(files))
    for f in files:
        os.unlink(f)

def rmtree(dn):
    """pythonic rm -rf"""

    debug("# rm -rf %s .." % dn)
    shutil.rmtree(dn, ignore_errors=True)


def _xxxpath(p):
    """Simplify the path by stripping out leading string of DBDIR"""
    global DB
    if p.startswith(DB.dbdir):
        n = len(DB.dbdir)
        return "DBDIR" + p[n:]
    return p



class opt_parser(OptionParser):
    """Wrapper around option parser to override the meaning of
    "exit()". In our case, we return StopIteration to break out of
    the call chain and resume the main loop."""
    def exit(self, status=0, msg=None):
        if msg:
            sys.stderr.write(msg)

        # This exception
        raise StopIteration


class config(object):
    """Abstraction of a DB config.

    We make it easy to set just one variable the base-dir for the cert
    storage. And, the __getattr__ override provides suitable instance
    variables for all other paths that are within the base-dir tree.
    """

    _sslconf  = 'openssl.cnf'
    _toolconf = 'ssltool.conf'
    _crtdir   = 'certs'
    _crldir   = 'crl'
    _crlfile  = join('crl', 'crl.pem')
    _serial   = 'serial'
    _index    = 'index.txt'

    def __init__(self, dbdir):
        self.__dict__['dbdir']  = dbdir
        self.__dict__['tooldb'] = None
        debug("Using %s as the DB dir ..", dbdir)

    def __getattr__(self, arg):

        names = [arg]
        if not arg.startswith('_'):
            names.append('_' + arg)

        # Order of lookups of dicts. We first look in the class instance
        # and then the class itself.
        dicts = [ self.__dict__, self.__class__.__dict__ ]

        v = None
        for n, d in [ (x,y) for x in names for y in dicts ]:
            if n in d:
                v = d[n]
                break

        if v is None:
            raise AttributeError, arg

        #debug("%s?  => %s/%s", arg, self.dbdir, v)
        return normpath(join(self.dbdir, v))

    def __setattr__(self, arg, val):
        raise NotImplementedError, "Can't set %s=%s; This class is Read-Only" % (arg, val)

    @staticmethod
    def split_cn(s):
        """Split a string of the form 
    /C=US/ST=TX/L=Richardson/O=Snakeoil Industries Inc/CN=snake@snakeoil.com/emailAddress=snake@snakeoil.com/OU=snake@snakeoil.com

        into constituent parts"""
        v   = s.split('/')
        tbl = {}
        for i in v:
            if i.find('=') < 0:
                continue

            x = i.split('=')
            debug("CN %s => %s", s, repr(x))
            key = string.lower(x[0])
            tbl[key] = x[1]

        attr = bundle(tbl)
        return attr



    def config_file(self, force=False):
        """Return an instance of a parsed tool conf file"""

        if force or self.tooldb is None:
            cnf = self.toolconf

            debug("Reading config file '%s' ...", cnf)
            self.__dict__['tooldb'] = config_file(cnf)
            self.tooldb.dump()


        return self.tooldb

    def section(self, arg):
        """Handy alias for config_file.section"""
        return self.tooldb.section(arg)


    def crldb(self):
        """Parse and return CRL entries"""

        crl_file = self.crlfile

        if not os.path.isfile(crl_file):
            error(0, "No CRL or CRL is empty. Nothing to show")
            return []

        certdb = self.certdb()

        # now, read the CRL and process the data
        list_crl_exe = 'openssl crl -text -noout -in %s' % crl_file
        crls = os.popen(list_crl_exe, 'r')
        revoked = {}
        for x in crls:
            x = x.strip()

            if not x.startswith('Serial Number:'):
                continue

            debug("Revoked %s", x)

            serial = int(x.split(':')[1].strip())
            if serial not in certdb:
                error(0, 'Serial# %s is not in the certificate DB', serial)
                continue

            else:
                d = certdb[serial]
                if d.status != 'R':
                    error(0, "Serial# %s is not revoked?! ** Consistency error**!", serial)
                else:
                    revoked[serial] = d
                    #d.serial = serial
                    #revoked.append(d)
                    #print '%s: %s' % (serial, d.cn)

        crls.close()
        return revoked


    def certdb(self):
        """Parse index.txt"""

        #global DB

        #idx = DB.index
        idx = self.index
        fd  = open(idx, 'rb')
        db  = {}
        for x in fd:
            v = x.strip().split()

            status = v[0]

            if status == 'V':
                rest   = ' '.join(v[4:])
                serial = int(v[2])
            else:
                serial = int(v[3])
                rest   = ' '.join(v[5:])

            details = self.split_cn(rest)
            details.status = v[0]
            details.serial = serial
            db[serial] = details
            debug("index: serial=%d/%x, rest=%s", serial, serial, details)

        fd.close()
        return db


class bundle:
    """Simplistic class to make it easy for referring to instance
    attributes (sort of like 'C struct')."""

    def __init__(self, kwargs):
        self.__dict__.update(kwargs)

    def update(self, kwargs):
        self.__dict__.update(kwargs)

    def __setattr__(self, key, val):
        self.__dict__[key] = val

    def __repr__(self):
        """Print string representation"""
        s = ""
        for k, v in self.__dict__.items():
            if not k.startswith('_'):
                s += "%s=%s|" % (k, v)
        return s

class command(object):
    """Abstraction of a command"""
    def __init__(self):
        self.name = "NONE"
        self.cmd_aliases = []

    def run(self, args):
        """Run the command"""
        pass

    def name(self):
        return self.name

    def help(self):
        """Display the doc string in a nicely formatted fashion"""

        d = self.__doc__
        if d is None:
            return ""

        x = cStringIO.StringIO(d)
        h = x.readline()
        h = x.readline().strip()
        if len(h) == 0:
            rest = ""
        else:
            rest = h + "\n"
        for line in x:
            rest += line
        x.close()
        return textwrap.dedent(rest)

    def usage(self):
        """Construct the optparse help string and return it"""

        if hasattr(self, "parser"):
            usage = self.parser.format_help()
        else:
            usage = self.help()

        return usage

    def brief_help(self):
        """Return first line of the doc string"""
        d = self.__doc__
        if d is None:
            return "*NONE*"

        x = cStringIO.StringIO(d)
        h = x.readline().strip()
        x.close()
        return h

    def aliases(self):
        """Return the command and its aliases"""

        a = [ self.name ]
        if hasattr(self, "cmd_aliases"):
            a += self.cmd_aliases
        return a

class init(command):
    """Initialize a SSL PKI Certificate DB

    init [options] [DBDIR]

    If DBDIR is not given, the default from the command line is
    used.
    """

    def __init__(self):
        super(init, self).__init__()
        self.name = 'init'
        self.parser = opt_parser(usage=self.help())
        self.parser.add_option("", "--overwrite",
                dest="overwrite", action="store_true", default=False,
                help="Overwrite previous config and re-initialize DB")
        self.parser.add_option("-p", "--passwd",
                dest="passwd", action="store", type="string",
                default=None, metavar="P",
                help="Use password 'P' for encrypting the CA private key")
        

    def cleanup(self, dn):
        """Cleanup a previous installation of DB dir"""

        progress("Cleaning up existing install in %s", dn)
        tmp = dn + '.tmp'
        rename(dn, tmp)
        rmtree(tmp)


    def create_dirs(self, db):
        """Make required directories in the DB dir"""

        progress("Initializing DB dir %s ..", db.dbdir)
        dirs = [db.dbdir, db.crtdir, db.crldir]
        for d in dirs:
            if not os.path.exists(d):
                os.makedirs(d, 0700)

    def run(self, args):
        global DB
        global SSL_conf_template, CA_Template
        global Tool_conf_template

        opt, argv = self.parser.parse_args(args=args[1:])

        if len(argv) > 0:
            DB = config(argv[0])


        # Don't set this vars unless db-dir is updated correctly
        # above
        ssl = DB.sslconf
        cnf = DB.toolconf

        #print ssl, cnf

        if os.path.isfile(cnf) and os.path.isfile(ssl):
            if opt.overwrite:
                self.cleanup(DB.dbdir)
            else:
                raise ex("Can't initialize in existing directory %s" % DB.dbdir)

        # Now, create the files from local templates
        self.create_dirs(DB)

        # There can be no subst's in this file - since it is the one
        # containing all the useful info.
        create_file(cnf, Tool_conf_template)

        # Fork an editor from here and let user update the file.
        edit_file(cnf)

        # Read the config file now and populate global dir.
        db = DB.config_file(force=True)

        # standard substitutions
        subst = { 'Z': Z,
                  'date':    today(),
                  #'ca_name': db['openssl.company'] + " Trust Authority",
                  'ca_name': 'Root_CA',
                  'ca_cert': 'ca.crt',
                  'ca_key':  'ca.key',
                  'dbdir':   DB.dbdir,
                }

        subst.update(db.section('openssl'))
        subst.update(db.section('general'))

        debug("subst:\n%s\n", "".join(["  %s=%s\n" % (a, b) for a, b in subst.items()]))

        ssl_cnf = (SSL_conf_template + CA_Template) % subst

        progress("Generating config files %s ..", ssl)
        create_file(ssl, ssl_cnf)

        e = db.ssl_env()
        create_file(DB.serial, e['KEY_SERIAL'])
        create_file(DB.index, "")

        self.make_ca()

    def make_ca(self):
        """create CA certs, DH keys etc."""
        global DB

        db = DB
        cf = db.config_file()

        env = cf.ssl_env()
        co  = cf['openssl.company']
        xtra_env = {
            'KEY_OU': co + ' SSL Certificates Division',
            'KEY_CN': co + ' Root CA'
        }


        # For the root CA, we will do 20 year life time.
        # Should be sufficient for most use cases.

        env['KEY_DAYS'] = "%d" % int(20 * 365.25)

        progress("Generating CA certificates ..")
        openssl('genrsa', ['-out', join(db.crtdir, 'ca.key'), env['KEY_SIZE']])
        openssl('req', ['-batch', '-days', env['KEY_DAYS'],
                    '-set_serial', env['KEY_CA_SERIAL'], '-new',
                    '-x509', '-key', join(db.crtdir, 'ca.key'),
                    '-out', join(db.crtdir, 'ca.crt'),
                    '-extensions', 'v3_ca'],
                    xtra_env)




class generic_cert_command(command):
    """Base class for generating any kind of certificate.

    There will be three derived instances:
       - server cert
       - client cert
       - intermediate CA cert
    """

    # Need to set:
    #   KEY_OU="$KEY_CN client certificate"
    #   KEY_CN="user@domain.name"

    def __init__(self):
        super(generic_cert_command, self).__init__()
        self.parser = opt_parser(usage=self.help())
        self.parser.add_option("-p", "--passwd",
                dest="passwd", action="store", type="string",
                default=None, metavar="P",
                help="Use password 'P' for encrypting the certificate private key [%default]")

        self.parser.add_option("-r", "--random",
                dest="random", action="store_true",
                default=False,
                help="Generate random password(s) for encrypting the certificate private key [%default]")

        self.parser.add_option("-i", "--inter",
                dest="inter", type="string",
                default=None, metavar='F',
                help="Use intermediate CA 'F' to sign the certificate [%default]")

        self.parser.add_option("-e", "--expiry",
                dest="expiry", type="string",
                default="+1Y", metavar='T',
                help="Set the certificate to expire on date 'T' (can be relative \
                    date like +1Y, +1M, +1D etc.) [%default]")



    def make_cert(self, user, passwd=None, def_config=True, xtra_ca_args=[]):
        """Add one user to the system"""
        global DB

        debug("Making new cert %s (%s) '%s' extension", user, passwd if passwd else ":NOPASS:", self.extension)

        db = DB
        cf = db.config_file()


        if self.fqdn:
            user  = cf.fqdn(user)
            email = 'certadmin@' + user
        else:
            user  = cf.email(user)
            email = user

        xtra_env = {
            'KEY_OU': cf.ou(),
            'KEY_CN': user,
            'KEY_EMAIL': email,
        }

        crt  = join(DB.crtdir, user + '.crt')
        key  = join(DB.crtdir, user + '.key')
        csr  = join(DB.crtdir, user + '.csr')

        args = ['-batch', '-days', "%d" % cf.expiry(), ]

        rsa_args = []
        csr_args = args + ['-new', '-key', key, '-out', csr, '-extensions', self.extension]
        ca_args  = args + ['-out', crt, '-in', csr , '-extensions', self.extension]

        if passwd is not None:
            passenv = randenv()
            xtra_env[passenv] = passwd
            rsa_args += ['-des3', '-passout', 'env:%s' % passenv ]

        rsa_args += ['-out', key, "%d" % cf.keysize() ]


        # Generate key & CSR
        openssl('genrsa', rsa_args, xtra_env)
        openssl('req', csr_args, xtra_env)

        # Now, sign the CSR by the CA key
        openssl('ca', ca_args + xtra_ca_args, xtra_env, use_config=def_config)


    def run(self, args):
        global DB

        db = DB
        cf = db.config_file()

        opt, argv = self.parser.parse_args(args=args[1:])

        if len(argv) < 1:
            raise ex("Insufficient arguments. Try '%s --help'", self.name)

        if opt.inter:
            if opt.inter.find('.') < 0:
                inter = cf.fqdn(opt.inter)
            else:
                inter = opt.inter

            cnf = join(db.dbdir, inter + '.cnf')
            if not os.path.isfile(cnf):
                raise ex("Can't find intermediate CA config %s", cnf)

            ca_crt = join(db.crtdir, inter + '.crt')
            ca_key = join(db.crtdir, inter + '.key')

            if not os.path.isfile(ca_crt):
                raise ex("Can't find intermediate CA certificate %s", ca_crt)
            if not os.path.isfile(ca_key):
                raise ex("Can't find intermediate CA key %s", ca_key)

            xtra_ca_args = ['-name', inter, '-config', cnf ]
            def_config   = False
            caname       = inter
        else:
            def_config   = True
            xtra_ca_args = ['-name', 'Root_CA',]
            caname       = 'ROOT_CA'

        for v in argv:
            crt = join(db.crtdir, v + '.crt')
            if os.path.isfile(crt):
                error(0, "Certificate %s' already exists!", v)
                continue

            if opt.random:
                p = randpass(8)
                print "Password for %s: %s" % (v, p)
            elif opt.passwd is not None:
                p = opt.passwd
            else:
                p = None

            progress("Generating certificate  %s and signing with %s", v, caname)
            self.make_cert(v, p, def_config=def_config, xtra_ca_args=xtra_ca_args)

            # Call hook function if one exists
            self.cert_done_hook(v)


    def cert_done_hook(self, nm):
        pass


class client(generic_cert_command):
    """Generate one or more client certificates and private key.

       client [options] name [name...]

       'name' should preferably be of the form 'user@domain.com' -
       e.g., like an email address.

       If multiple names are specified and "--password" option is
       chosen, then the same password is assigned to all the names.
    """

    extension = 'usr_cert'

    def __init__(self):
        super(client, self).__init__()
        self.name = 'client'
        self.fqdn = False
        self.cmd_aliases = []

class server(generic_cert_command):
    """Generate one or more server certificates and private key.

       server [options] name [name...]

       'name' should preferably be of the form 'sub.domain.com'
       e.g., a fully qualified domain name.

       If multiple names are specified and "--password" option is
       chosen, then the same password is assigned to all the private
       keys.
    """

    extension = 'server_cert'

    def __init__(self):
        super(server, self).__init__()
        self.name = 'server'
        self.fqdn = True
        self.cmd_aliases = []


class inter(generic_cert_command):
    """Generate one or more intermediate CA certificates.

       inter [options] name [name...]

       'name' will be something to use in future 'server' and/or
       'client' commands.
    """

    extension = 'v3_ca'

    def __init__(self):
        super(inter, self).__init__()
        self.name = 'inter'
        self.fqdn = True
        self.cmd_aliases = ['intermediate_ca']


    def cert_done_hook(self, nm):
        global DB, CA_Template

        db = DB
        cf = db.config_file()

        if nm.find('.') < 0:
            nm = cf.fqdn(nm)

        cnf = join(db.dbdir,  nm + '.cnf')

        # Now, generate a separate cnf file for the intermediate CA
        subst = { 'Z': Z,
                  'date': today(),
                  'ca_name': nm,
                  'ca_cert': nm + '.crt',
                  'ca_key':  nm + '.key',
                  'dbdir':   db.dbdir,
                }

        subst.update(db.section('openssl'))
        subst.update(db.section('general'))

        progress("Creating an intermediate CA config %s ..", cnf)
        create_file(cnf, CA_Template % subst)


# To build an intermediate CA:
#   - build a req and sign with v3_ca extension
#   - generate a new $inter.cnf file
#     This file is a copy of default_ca but with the ca and key
#     directives pointing to $inter.{crt,key}
# 
# To sign with an intermediate CA:
#   - use "-name" of ca to point to the section in $inter.cnf
#   - point the 'ca' command to the $inter.cnf conf file:
#      * -extfile $inter.crt
#      * -extension inter_ca -- this should be in the extfile
#      * - 



class passwd(command):
    """Change password on a given certificate private key

       passwd [options] cert-name

       If the "-p" option is not used to specify a new password, the
       existing password will be reset. i.e., the certificate private
       key will be without a password.
    """

    def __init__(self):
        super(passwd, self).__init__()
        self.name = 'passwd'
        self.parser = opt_parser(usage=self.help())
        self.parser.add_option("-p", "--passwd",
                dest="passwd", action="store", type="string",
                default=None, metavar="P",
                help="Use password 'P' for encrypting the client certificate private key")

        self.parser.add_option("-r", "--random",
                dest="random", action="store_true",
                default=False,
                help="Generate random password(s) for encrypting the client certificate private key")


    def run(self, args):
        global DB

        opt, argv = self.parser.parse_args(args=args[1:])

        rxstr = ".*"
        if len(argv) < 1:
            raise ex("Insufficient arguments. Try 'passwd --help'")


        uid = argv[0]
        user_key = join(DB.crtdir,  + '.key')
        if not os.path.isfile(user_key):
            raise ex("Can't find private key %s", user_key)

        oldpass = None
        if opt.random:
            newpass = randpass(8)
            print "New password is %s" % newpass
        else:
            newpass = opt.passwd

        inpass   = randenv()
        outpass  = randenv()

        xtra_env = { inpass: oldpass }
        args     = [ '-in', user_key, '-out', user_key,
                     '-passin', 'env:%s' % inpass, ]

        if newpass is not None:
            args += [ '-des3', '-passout', 'env:%s' % outpass]
            xtra_env[outpass] = newpass

        # Finally, update the passwd in the key file
        openssl('rsa', args, xtra_env, use_config=False)

        progress("Password for %s successfully changed", uid)


class revoke(command):
    """Remove one or more users from the system.

    revoke cert-name [cert-name...]

    This command removes users from the system by revoking their client
    certificates and generating a CRL. The CRL must then be pushed to
    the appropriate server and the server must be restarted.
    """

    def __init__(self):
        super(revoke, self).__init__()
        self.name = 'revoke'
        self.cmd_aliases = ['remove', 'delete']
        self.parser = opt_parser(usage=self.help())

    def run(self, args):
        global DB

        opt, argv = self.parser.parse_args(args=args[1:])

        if len(argv) < 1:
            raise ex("Insufficient arguments. Try 'revoke --help'")

        for u in argv:
            self.revoke_user(u)

        self.make_crl()

    def revoke_user(self, uid):
        """Revoke one user"""
        global DB

        db = DB
        cf = db.config_file()

        user_crt = join(db.crtdir, uid + '.crt')
        user_csr = join(db.crtdir, uid + '.csr')
        user_key = join(db.crtdir, uid + '.key')

        if not os.path.isfile(user_crt):
            raise ex("Consistency error! User %s is in user DB but private key not found!", uid)

        xtra_env = {
            'KEY_OU': cf.ou(),
            'KEY_CN': uid,
            'KEY_EMAIL': cf.email(uid),
        }
        args = ['-revoke', user_crt ]
        openssl('ca', args, xtra_env)

        rmfiles(user_crt, user_key, user_csr)
        progress("Removed user %s", uid)

    def make_crl(self):
        """Make a new CRL"""
        global DB

        xtra_env = {
            'KEY_OU': 'SSL Certificates Division',
            'KEY_CN': "foo",
            'KEY_EMAIL': "foo",
        }
        openssl('ca', ['-gencrl', '-out', DB.crlfile], xtra_env)
        progress("Generated new CRL in %s" % DB.crlfile)



class listcrt(command):
    """Show all valid certificates in the system

    listcrt [options] [pattern]

    If 'pattern' is specified, look for specified CN; 'pattern' is a
    regex.
    """

    def __init__(self):
        super(listcrt, self).__init__()
        self.name = 'listcrt'
        self.cmd_aliases = [ 'list', 'ls', ]
        self.parser = opt_parser(usage=self.help())
        #self.parser.add_option("-p", "--show-password",
        #        dest="show_passwd", action="store_true", default=False,
        #        help="Show passwords for each user [False]")


    def parse_cert(self, crt, attr):
        """Run some openssl commands and figure out some more attributes
        for the 'crt'.
        """

        # Run the following command
        #
        # openssl x509 -in foo.bar.com.crt -text -certopt no_header,no_version,no_serial,no_signame,no_subject,no_issuer,no_pubkey,no_sigdump -noout 
        
        args = ['-in', crt, '-text', '-noout', '-certopt',
             'no_header,no_version,no_serial,no_signame,no_subject,no_issuer,no_pubkey,no_sigdump'
            ]

        cmd = 'openssl x509 ' + ' '.join(args)
        fd  = os.popen(cmd, 'r')
        d   = {}
        for l in fd.readlines():
            l = l.strip()
            if len(l) == 0:
                continue

            if l.find(':') > 0:
                a, b = l.split(':', 1)
            else:
                a = l
                b = ""

            #print "%s => %s" % (a, b)
            d[a.strip()] = b.strip()

        fd.close()

        ca_s = d.get('CA', "FALSE")

        attr.expires   = d['Not After']
        attr.is_server = 'SSL Server' in d
        attr.is_ca     = ca_s == "TRUE"

        return attr

    def run(self, args):
        global DB

        db = DB
        opt, argv = self.parser.parse_args(args=args[1:])

        rxstr = ".*"
        if len(argv) > 0:
            rxstr = argv[0]

        try:
            rxpat = re.compile(rxstr)
        except:
            raise ex("Can't compile regex pattern '%s'", rxstr)

        r   = db.certdb()
        for k, v in r.items():
            if v.status != 'V':
                continue

            if not rxpat.search(v.cn):
                continue

            crt = join(db.crtdir, v.cn + '.crt')
            v   = self.parse_cert(crt, v)
            if v.is_ca:
                typ = "[CA]"
            else:
                typ = "[S] " if v.is_server else "[C] "

            print "%s %-30s %8d/%#8.8x %s" % (typ, v.cn, v.serial,
                    v.serial,  v.expires)


class listcrl(command):
    """Show certificates that are revoked.

    lscrl [options] [pattern]

    If 'pattern' is specified, look for specified CN in the CRL list.
    """

    def __init__(self):
        super(listcrl, self).__init__()
        self.name = 'listcrl'
        self.cmd_aliases = [ 'lscrl' ]
        self.parser = opt_parser(usage=self.help())
        self.parser.add_option("-p", "--show-path",
                dest="show_path", action="store_true", default=False,
                help="Show path to the CRL file [False]")
        self.parser.add_option("-s", "--show-serial",
                dest="show_serial", action="store_true", default=False,
                help="Show user's certificate serial number  [False]")


    def run(self, args):
        global DB

        opt, argv = self.parser.parse_args(args=args[1:])

        rxstr = ".*"
        if len(argv) > 0:
            rxstr = argv[0]

        try:
            rxpat = re.compile(rxstr)
        except:
            raise ex("Can't compile regex pattern '%s'", rxstr)

        if opt.show_path:
            print "CRL is   '%s'" % DB.crlfile

        r = DB.crldb()
        for k, x  in r.items():
            if not rxpat.search(x.cn):
                continue

            if opt.show_serial:
                s = "%-15s [%d/%#8.8x]" % (x.cn, k, k)
            else:
                s = "%-15s" % x.cn
            print s



class quit(command):
    """Quit the interactive SSL-tool session"""
    def __init__(self):
        super(quit, self).__init__()
        self.name = 'quit'
        self.cmd_aliases = ['exit']

    def run(self, args):
        _exit(0)


class helpcmd(command):
    """Show help on one or more commands.

    Usage: help [command]

    If 'command' is omitted, brief help for every command is
    displayed. If 'command' is used, detailed help for that command
    is displayed.
    """

    def __init__(self, dispatch):
        super(helpcmd, self).__init__()
        self.name = 'help'
        self.disp = dispatch
        self.cmds = dispatch.cmdlist()

    def cmdlist(self, indent="   "):
        """Return a list of commands and their brief usage"""
        str = ""
        for k, v in self.cmds.items():
            a    = v.aliases()
            str += indent
            if len(a) > 1:
                str += ', '.join(a)
            else:
                str += k

            str += ":\n%s    %s\n" % (indent, v.brief_help())
        return str

    def run(self, args):
        args = args[1:]
        if len(args) == 0:
            print "List of available commands:\n%s" % self.cmdlist()
        else:
            name = args[0]
            #c    = self.cmds.get(name, None)
            c = self.disp.find(name)
            if c is None:
                raise ex("Invalid command %s" % name)

            print "%s: %s" % (c.name, c.brief_help())
            a = c.aliases()
            if len(a) > 1:
                print  "Aliases: %s" % ', '.join(a)
            print "\n", c.usage()


class config_file(object):
    """Abstraction representing a .ini style config file for
    cert-tool.
    
    Instances of this class can be used to query different sections of
    the config file like so:

        c = config_file()
        print c['section.keyword']

    """

    # Mapping of config file keywords in the 'openssl' section to
    # environment vars that will be used when openssl is run.
    ssl_mapping = { 'country':  'KEY_COUNTRY',
                    'city':     'KEY_CITY',
                    'company':  'KEY_ORG',
                    'comment':  'NS_COMMENT',
                    'validity': 'KEY_DAYS',
                    'keysize':  'KEY_SIZE',
                    'state':    'KEY_PROVINCE',
        }


    def __init__(self, fn):
        self.filename = fn
        self.cp = ConfigParser.ConfigParser()

        if not os.path.isfile(self.filename):
            error(0, "Warning: Can't find config file %s", self.filename)
        else:
            debug("Processing config file %s ..", self.filename)
            self.cp.read(self.filename)


    def dump(self):
        """Debug print the config file"""
        for s in self.cp.sections():
            for k, v in self.cp.items(s):
                debug("%s.%s = %s", s, k, v)


    def section(self, s):
        """Return contents of section 's' as a dict"""
        if self.cp.has_section(s):
            return dict(self.cp.items(s))

        return {}

    def ssl_env(self):
        """Return config elements as suitable environment vars"""

        env = {}
        admin = self.cp.get('general', 'admin')
        keysz = self.cp.get('openssl', 'keysize')
        env['KEY_EMAIL'] = admin
        for k, v in self.ssl_mapping.items():
            e = self.cp.get('openssl', k)
            if e is None:
                continue

            if k == 'validity':
                expiry  = int(e) * 365
                env[v] = "%d" % expiry
            else:
                env[v] = e

        r = randnum(4)
        env.setdefault('KEY_SIZE', keysz)
        env.setdefault('KEY_CA_SERIAL', "%d" % (r-1))
        env.setdefault('KEY_SERIAL', "%d" % r)
        return env


    def __getitem__(self, k):
        """Make config-file behave like a dict"""
        v = k.split('.')
        if len(v) != 2:
            raise ex("Malformed attribute request in config_file.__getattr__('%s')" % k)

        s, t = v
        try:
            e = self.cp.get(s, t)
        except NoSectionError, e:
            raise ex("Unknown section '%s' in config_file.__getattr__('%s')" % s)

        return e

    def email(self, cn):
        """Given a CN, return an email address"""
        if cn.find('@') < 0:
            if cn.find('.') < 0:
                do = self.cp.get('general', 'domain')
                em = cn + '@' + do
            else:
                em = 'cert@' + cn
        else:
            em = cn

        return em

    def ou(self):
        """Return a valid OU"""
        co = self.cp.get('openssl', 'company')
        return co + ' Certificates Division'


    def fqdn(self, nm):
        if nm.find('.') < 0:
            dom =  self.cp.get('general', 'domain')
            return nm + '.' + dom

        return nm


    def expiry(self):
        """Return default expiry in days"""
        e = self.cp.get('openssl', 'validity')
        return int(e) * 365

    def keysize(self):
        return int(self.cp.get('openssl', 'keysize'))



class dispatcher(object):
    """Command dispatch abstraction.
    
    This class will be a singleton.
    """
    instance = None

    def __init__(self, commands):
        if self.instance is not None:
            raise ex("dispatcher is a singleton.")

        self.instance = self
        self.cmddb    = {}
        for c in commands:
            cmd = c()
            self.add(cmd)

        self._rebuild()

    def _verify(self, cmd):
        if cmd.name in self.cmddb:
            raise ex("Duplicate command '%s'" % cmd.name)

        for a in cmd.aliases():
            if a in self.cmddb:
                raise ex("Alias '%s' for command '%s' is a duplicate of another command" % (a, cmd.name))

    def add(self, cmd):
        self._verify(cmd)
        self.cmddb[cmd.name] = cmd
        self._rebuild()

    def cmdlist(self):
        """Return list of command instances registered with the
        dispatcher"""
        return self.cmddb

    def _rebuild(self):
        """Rebuild abbreviation list and other internal data
        structures"""

        # List of commands that will need unique abbreviations.
        ablist   = []

        cmd_aliases = {}
        for cmd in self.cmddb.values():
            a   = cmd.aliases()
            ablist += a
            for x in a:
                cmd_aliases[x] = cmd.name

        self.cmd_aliases = cmd_aliases
        self.abtab       = abbrev(ablist)

    def find(self, cmdname):
        """Find the commmand 'cmdname' and return instance that handles
        it."""
        s = self.abtab.get(cmdname, None)
        if s is not None:
            s = self.cmd_aliases.get(s, s)
            s = self.cmddb.get(s, None)

        return s

    def _run(self, args):
        """Wrapper around cmd::run() that also throws an exception"""
        cmdname = args[0]
        cmd     = self.find(cmdname)
        if cmd is None:
            raise ex("Invalid or partial command %s" % cmdname)

        cmd.run(args)

    def run_one(self, args, exitcode=1):
        """Run one instance of command line"""
        try:
            self._run(args)
        except ex, e:
            error(exitcode, e)
        except os.error, e:
            error(exitcode, e)
        except StopIteration:
            pass
        except:
            raise

    def run_loop(self, prompt=Prompt):
        """Run loop - read from stdin and process each command typed on
        a line."""
        global Quit_Loop

        while True:
            if Quit_Loop:
                break

            print prompt,
            cmd = sys.stdin.readline()
            if cmd is None:
                break

            cmd = cmd.strip()
            if len(cmd) > 0:
                args = cmd.split()
                self.run_one(args, 0)






# Install signal handlers to gracefully exit
signal.signal(signal.SIGINT, sighandler)
signal.signal(signal.SIGTERM, sighandler)
if sys.platform not in ("cygwin", "win232", "win64"):
    signal.signal(signal.SIGHUP, sighandler)

# List of commands
commands = [ init, client, server, inter, revoke, listcrl, listcrt, quit ]
disp     = dispatcher(commands)

# Instantiate the help command to include info about the other commands
H = helpcmd(disp)

# Now, add the help command to the dispatcher.
disp.add(H)

def main():
    """The start of the program"""

    global Debug, Verbose
    global DB
    global __version__, __author__, __license__
    global Z, H, disp

    dd  = { 'Z': Z, 'cmds': H.cmdlist(),
            'auth': __author__,
            'ver': __version__,
            'lic': __license__,
           }
    doc = """%(Z)s [options] -- [command] [command options..]

%(Z)s - A simple tool for managing SSL PKI infrastructure - i.e., generate
and manage client, server, intermediate-ca, CRLs.

If no command is specified on the command line, the tool enters
interactive mode ("command line mode").

The Database Directory ("DB dir") is a directory where the tool
maintains its configuration files, certificates etc.

The tool has the following commands:

%(cmds)s

Detailed help for each command can be obtained as follows:

   %(Z)s CMD --help

Version: %(ver)s
Author: %(auth)s
License: %(lic)s""" % dd


    parser = OptionParser(usage=doc,
                          version="%s - v%s %s" % (Z, __version__, __author__))
    parser.add_option("-D", "--db-dir", dest="dbdir", action="store",
                      type="string", default='.', metavar="D",
                      help="Use 'D' as the database directory [%default]")

    parser.add_option("-d", "--debug", dest="debug", action="store_true",
                      default=False,
                      help="Run in debug mode [%default]")

    parser.add_option("-v", "--verbose", dest="verbose", action="store_true",
                      default=False,
                      help="Run in verbose mode [%default]")

    parser.disable_interspersed_args()
    (opt, args) = parser.parse_args()


    # Setting debug => verbose output as well
    if opt.debug:
        Debug       = True
        opt.verbose = True

    if opt.verbose:
        Verbose = True

    have_args = len(args) > 0

    if have_args and args[0] == 'help':
        disp.run_one(args, 1)
        _exit(0)


    # All other commands needs a DBdir to be set.

    if opt.dbdir is None:
        error(1, "DB directory is not set. Please use '-D' global option")

    opt.dbdir = abspath(normpath(opt.dbdir))

    # Now, process the DB dir
    try:
        DB  = config(opt.dbdir)
        DB.config_file()
    except os.error, e:
        error(1, e)

    if have_args:
        disp.run_one(args, 1)
    else:
        disp.run_loop()

    _exit(0)

# Builtin templates for openssl.cnf and other things
SSL_conf_template = """

# Automatically Generated. DO NOT EDIT!
# Generated by %(Z)s on: %(date)s
#

# This definition stops the following lines choking if HOME isn't
# defined.
HOME            = $ENV::HOME
RANDFILE        = $ENV::HOME/.rnd

# Extra OBJECT IDENTIFIER info:
#oid_file       = $ENV::HOME/.oid
oid_section     = new_oids

# To use this configuration file with the "-extfile" option of the
# "openssl x509" utility, name here the section containing the
# X.509v3 extensions to use:
# extensions        = 
# (Alternatively, use a configuration file that has only
# X.509v3 extensions in its main [= default] section.)

[ new_oids ]

# We can add new OIDs in here for use by 'ca' and 'req'.
# Add a simple OID like this:
# testoid1=1.2.3.4
# Or use config file substitution like this:
# testoid2=${testoid1}.5.6


# For the CA policy
[ policy_match ]
countryName     = match
stateOrProvinceName = match
organizationName    = match
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional


# For the 'anything' policy
# At this point in time, you must list all acceptable 'object'
# types.
[ policy_anything ]
countryName     = optional
stateOrProvinceName = optional
localityName        = optional
organizationName    = optional
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional

####################################################################
[ req ]
default_bits        = $ENV::KEY_SIZE
default_keyfile     = privkey.pem
distinguished_name  = req_distinguished_name
attributes      = req_attributes
x509_extensions = v3_ca # The extentions to add to the self signed cert

string_mask = nombstr

# req_extensions = v3_req # The extensions to add to a certificate request

[ req_distinguished_name ]
countryName             = Country Name (2 letter code)
countryName_default     = $ENV::KEY_COUNTRY
countryName_min         = 2
countryName_max         = 2

stateOrProvinceName         = State or Province Name (full name)
stateOrProvinceName_default = $ENV::KEY_PROVINCE

localityName            = Locality Name (eg, city)
localityName_default    = $ENV::KEY_CITY

0.organizationName      = Organization Name (eg, company)
0.organizationName_default  = $ENV::KEY_ORG

organizationalUnitName          = Organizational Unit Name (eg, section)
organizationalUnitName_default  = $ENV::KEY_OU

commonName          = Common Name (eg, your name or your server\'s hostname)
commonName_default  = $ENV::KEY_CN
commonName_max          = 64

emailAddress            = Email Address
emailAddress_default    = $ENV::KEY_EMAIL
emailAddress_max        = 40

# SET-ex3           = SET extension number 3

[ req_attributes ]
challengePassword       = A challenge password
challengePassword_min   = 4
challengePassword_max   = 20

unstructuredName        = An optional company name


[ v3_req ]

# Extensions to add to a certificate request

nsCertType       = client
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment, keyAgreement

# Extension for signing a CA cert.
[ v3_ca ]

subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = critical,CA:true
keyUsage = cRLSign, keyCertSign
nsCertType = sslCA, emailCA
subjectAltName=email:copy
issuerAltName=issuer:copy

[ crl_ext ]

# CRL extensions.
# Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.

# issuerAltName=issuer:copy
authorityKeyIdentifier=keyid:always,issuer:always
"""


# This template will be instantiated for the default CA and appended to
# openssl.cnf.
# And, for every intermediate CA, it will be instantiated once.
CA_Template = """

# Automatically Generated. DO NOT EDIT!
# Generated by %(Z)s on: %(date)s

[%(ca_name)s]

dir         = %(dbdir)s # where everything is ketp
certs       = $dir/certs        # Where the issued certs are kept
crl_dir     = $dir/crl          # Where the issued crl are kept
new_certs_dir = $certs          # default place for new certs.
database    = $dir/index.txt    # database index file.
serial      = $dir/serial       # The current serial number
crl         = $crl_dir/crl.pem    # The current CRL
RANDFILE    = $dir/.rand          # private random number file

certificate = $certs/%(ca_cert)s  # The CA certificate
private_key = $certs/%(ca_key)s   # The private key

x509_extensions = usr_cert      # The extentions to add to the cert

# Extensions to add to a CRL. Note: Netscape communicator chokes on V2 CRLs
# so this is commented out by default to leave a V1 CRL.
# crl_extensions    = crl_ext

default_days = 365           # how long to certify for
default_crl_days= 30            # how long before next CRL
default_md  = sha1              # which md to use.
preserve    = no                # keep passed DN ordering

# A few difference way of specifying how similar the request should look
# For type CA, the listed attributes must be the same, and the optional
# and supplied fields are just that :-)
policy      = policy_supplied


[ policy_supplied ]
countryName         = supplied
stateOrProvinceName = supplied
localityName        = supplied
organizationName    = supplied
commonName          = supplied
emailAddress        = supplied

# Extension for signing a CA cert.
[ v3_ca ]

subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = critical,CA:true
keyUsage = cRLSign, keyCertSign
nsCertType = sslCA, emailCA
subjectAltName=email:copy
issuerAltName=issuer:copy

[ usr_cert ]

# These extensions are added when 'ca' signs a request.
nsCertType = client, email
extendedKeyUsage=clientAuth
keyUsage = nonRepudiation,digitalSignature,keyEncipherment,dataEncipherment, keyAgreement

basicConstraints=CA:FALSE
nsComment           = $ENV::NS_COMMENT
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
subjectAltName=email:copy
issuerAltName=dirName:issuer_ca,issuer:copy

[ server_cert ]
nsCertType          = server
extendedKeyUsage=serverAuth
keyUsage = nonRepudiation,digitalSignature,keyEncipherment,dataEncipherment,keyAgreement


basicConstraints=CA:FALSE
nsComment           = $ENV::NS_COMMENT
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
subjectAltName=email:copy,DNS:$ENV::KEY_CN
issuerAltName=dirName:issuer_ca,issuer:copy

# Section to record the issuer's info
[issuer_ca]
C = %(country)s
ST = %(state)s
L = %(city)s
O = %(company)s
#OU = %(ca_name)s CA of %(company)s
CN = %(ca_name)s.%(domain)s



"""

Tool_conf_template = """
# Config file for ssl-tool
#

[general]
# SSL Cert Admin. Will also be used in the From field of the SMTP
# Envelope.
admin   = ssladmin@company.com
domain  = company.com

# Config block for openssl
[openssl]
# Size of private key in bits. Making this larger than 1024 will
# mean extra security at the cost of more work on the part of
# server and client.
keysize = 2048

country = US
city    = Dallas
state   = TX
company = Snakeoil Peddlers Inc.
comment = Certificate issued by Snakeoil CA

# Name to be used in the CN of CA
ca = Snakeoil Trust Authority


# Number of years client certificate is valid
validity = 3


# vim: expandtab:sw=4:ts=4:tw=72:ft=ini
"""



main()

# vim: expandtab:sw=4:ts=4:tw=72:notextmode:
