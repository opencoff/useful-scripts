#! /usr/bin/env python

#
# Comprehensive Tool to manage OpenVPN PKI infrastructure, config files
# and client certificates for users.
#
# Author: Sudhi Herle <sw+ovpntool@herle.net>
# Date: October 2007
# License: GPLv2 http://www.gnu.org/licenses/old-licenses/gpl-2.0.html

import os, sys, signal
import string, textwrap, cStringIO
import shutil, ConfigParser, random
import subprocess, re, zipfile, itertools
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
Prompt    = "(ovpn-tool) "

Tool_conf_db = {}
User_db      = None


__version__ = "0.9.5"
__author__  = "Sudhi Herle <sudhi@herle.net>"
__license__ = "GPLv2 [http://www.gnu.org/licenses/old-licenses/gpl-2.0.html]"



def sighandler(sig,frm):
    """Trivial signal handler"""
    global Quit_Loop
    Quit_Loop = True


def _exit(rc):
    """Wrapper around sys.exit() to close the user database"""
    if User_db is not None:
        User_db.finalize()
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


class randpass_gen(object):
    """Generate random, human readable passwords.
    
       Clever algorithm is due to Herman Schaaf.
    """

    initial_consonants = (set(string.ascii_lowercase) - set('aeiou')
                          # remove those easily confused with others
                          - set('qxc')
                          # add some crunchy clusters
                          | set(['bl', 'br', 'cl', 'cr', 'dr', 'fl',
                                 'fr', 'gl', 'gr', 'pl', 'pr', 'sk',
                                 'sl', 'sm', 'sn', 'sp', 'st', 'str',
                                 'sw', 'tr'])
                          )

    final_consonants = (set(string.ascii_lowercase) - set('aeiou')
                        # confusable
                        - set('qxcsj')
                        # crunchy clusters
                        | set(['ct', 'ft', 'mp', 'nd', 'ng', 'nk', 'nt',
                               'pt', 'sk', 'sp', 'ss', 'st'])
                        )

    vowels = 'aeiou' # we'll keep this simple


    def __init__(self, wordcount=2, spaces=False, capital=False):
        # each syllable is consonant-vowel-consonant "pronounceable"
        self.syllables = map(''.join, itertools.product(self.initial_consonants, 
                                                   self.vowels, 
                                                   self.final_consonants))
        self.words   = wordcount
        self.spaces  = spaces
        self.capital = capital

        random.shuffle(self.syllables)

    def password(self, n=1):
        """Generate and return a list of passwords"""

        random.shuffle(self.syllables)

        x = []
        sep = ' ' if self.spaces else ''

        #print self.syllables
        #print self.__class__.syllables
        while n > 0:
            n -= 1
            g = random.sample(self.syllables, self.words)
            if self.capital:
                g = [ a.capitalize() for a in g ]

            x.append(sep.join(g))

        return x


# Keep a single global instance for now
RP = randpass_gen(wordcount=3, capital=True)

def randpass():
    """Generate password n bytes long chosen from chars in
    sampleset"""

    global RP

    x = RP.password(1)
    return x[0]
    

def randenv():
    """Generate a random environment var name"""

    sampleset = list(string.letters + string.digits)
    random.shuffle(sampleset)

    x = []
    n = 10
    size = len(sampleset)
    while n > 0:
        if n > size:
            s = size
        else:
            s = n

        x += random.sample(sampleset, s)
        n -= s

    a = ''.join(x)
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
        # end of while len > 0

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
            raise ex, "Unknown file type for '%s'; can't rename!" % b

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

    global DB

    pwd  = os.getcwd()

    args = ['openssl', cmd, ] +  argv
    if use_config:
        args += [ '-config', DB.sslconf ]

    os.chdir(DB.crtdir)

    env = os.environ.copy()
    env.update(Tool_conf_db.ssl_env())
    env.update(additional_env)
    env['KEY_DIR'] = DB.dbdir

    debug("OpenSSL: %s", ' '.join(args))
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

    err = ''
    while p.poll() is None:
        o = p.stdout.readline()
        e = p.stderr.readline()
        if o:
            sys.stdout.write(o)
            sys.stdout.flush()
        if e:
            err += e
            sys.stderr.write(e)
            sys.stdout.flush()

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
    os.chdir(pwd)


def edit_file(filename):
    """Fork an editor and edit the file 'filename'"""

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
        raise ex, "Please set environment var EDITOR appropriately"

    argv = [ ed, tmp ]
    debug("Calling '%s' ..", ' '.join(argv))
    rc = subprocess.call(argv)
    if rc < 0:
        error(1, "Process '%s' caught signal %d and died!",
               ed, -rc)
    elif rc > 0:
        error(1, "Process '%s' exited abnormally (code %d)", ed, rc)

    rename(tmp, filename)

def create_file(fn, str, subst=None):
    """Create file 'fn' with the contents from string 'str'"""
    tmp = fn + '.tmp'
    fd = open(tmp, 'w')
    if subst is not None:
        fd.write(str % subst)
    else:
        fd.write(str)
    fd.close()
    rename(tmp, fn)


def rmfiles(*files):
    """Remove one or more files"""
    for f in files:
        os.unlink(f)

def rmtree(dir):
    """pythonic rm -rf"""

    for root, dirs, files in os.walk(dir, 0):
        for f in files:
            here  = join(root, f)
            os.unlink(here)

        for d in dirs:
            here  = join(root, d)
            os.rmdir(here)

    os.rmdir(dir)


def make_ovpn_secret(of, bits=2048):
    """Make a 2048 bit shared secret key for OpenVPN.

    This secret key will prevent a majority of DoS attacks on the UDP
    version of OpenVPN.

    We are going to generate this key based on V1 of the OpenVPN tool.
    """
    r  = random.Random()
    bb = bits / 8
    v  = []
    n  = 0
    while bb > 0:
        x = "%02x" % r.randint(0,255)
        if (n % 16) == 0:
            v.append('\n')

        n += 1
        bb -= 1
        v.append(x)

    fd = open(of, 'wb')
    fd.write("""#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----%s
-----END OpenVPN Static key V1-----
""" % ''.join(v))

    fd.close()


def read_db_file(a, *args):
    """Join one or more path components and read the contents of the file"""
    fn = a
    if args:
        fn = os.path.join(a, *args)

    fd = open(fn)
    buf = fd.read()
    fd.close()
    return buf

def make_conf(zf, u):
    """Make a .ovpn config file named 'zf' for user 'u'."""
    global Client_config_template
    global DB
    global Tool_conf_db


    progress("Creating conf file %s for user %s ..", zf, u)
    db  = Tool_conf_db
    srv = db.vpn_server()
    #z   = zipfile.ZipFile(zf, 'w', zipfile.ZIP_DEFLATED)
    crt = "%s.crt" % u
    key = "%s.key" % u

    d = { 'today':     today(),
          'username':  u,
          'client':    u,
          'vpnserver': srv,
          'proto':     db['openvpn.proto'],
          'vpnport':   db.vpn_server_port(),
          'ca_cert':   read_db_file(DB.crtdir, 'ca.crt'),
          'user_key':  read_db_file(DB.crtdir, key),
          'user_cert': read_db_file(DB.crtdir, crt),
          'tls_secret': read_db_file(DB.secret)
        }

    
    #debug("user dict = \n%s\n", str(d))
    cfg = Client_config_template % d
    fd  = open(zf, "w", 0600)
    fd.write(cfg)
    fd.close()


def _path(p):
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
    _userdb   = 'passwd'
    _crtdir   = 'certs'
    _crldir   = 'crl'
    _crlfile  = join('crl', 'crl.pem')
    _confdir  = 'conf'
    _serial   = 'serial'
    _index    = 'index.txt'
    _email    = 'email.txt'
    _secret   = 'server_secret.key'
    _serverconf = 'server.conf'

    def __init__(self, dbdir):
        self.__dict__['dbdir'] = dbdir
        debug("Using %s as the DB dir ..", dbdir)

    def __getattr__(self, arg):
        priv = "_" + arg
        v    = getattr(self, priv)
        if v is None:
            raise AttributeError, arg
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
            val = x[1]
            tbl[key] = val

        attr = bundle(tbl)
        return attr

    def parse_index(self):
        """Parse index.txt"""

        idx = DB.index
        fd  = open(idx, 'rb')
        certdb = {}
        for x in fd:
            v = x.strip().split()

            status = v[0]

            if status == 'V':
                rest   = ' '.join(v[4:])
                serial = v[2]
            else:
                serial = v[3]
                rest   = ' '.join(v[5:])

            details = self.split_cn(rest)
            details.status = v[0]
            details.serial = serial
            certdb[serial] = details
            debug("index: serial=%s, rest=%s", serial, details)

        fd.close()
        return certdb


class bundle:
    """Simplistic class to make it easy for referring to instance
    attributes (sort of like 'C struct')."""

    def __init__(self, kwargs):
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
    """Initialize a SSL Certificate DB for OpenVPN

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
                help="Use password 'P' for encrypting the private key")
        

    def cleanup(self, dn):
        """Cleanup a previous installation of DB dir"""

        progress("Cleaning up existing install in %s", dn)
        tmp = dn + '.tmp'
        rename(dn, tmp)
        rmtree(tmp)

    def create_dirs(self, db):
        """Make required directories in the DB dir"""

        os.makedirs(db.dbdir,  0700)
        os.makedirs(db.crtdir, 0700)
        os.makedirs(db.confdir, 0700)
        os.makedirs(db.crldir, 0700)

    def run(self, args):
        global DB
        global SSL_conf_template
        global Tool_conf_template
        global Email_template

        opt, argv = self.parser.parse_args(args=args[1:])

        if len(argv) > 0:
            DB = config(argv[0])

        # Don't set this vars unless db-dir is updated correctly
        # above
        ssl = DB.sslconf
        cnf = DB.toolconf

        if os.path.isfile(cnf) and os.path.isfile(ssl):
            if opt.overwrite:
                self.cleanup(DB.dbdir)
            else:
                raise ex, "Can't initialize in existing directory %s" % DB.dbdir

        # Now, create the files from local templates
        self.create_dirs(DB)
        create_file(ssl, SSL_conf_template)
        create_file(cnf, Tool_conf_template)
        create_file(DB.email, Email_template)
        create_file(DB.serial, "14")
        create_file(DB.index, "")

        print """
            Starting Editor for
               %s

            Please edit the file and update the various fields appropriately
            before using this tool to create new certificates.

            Starting editor ..
            """ % cnf

        # Fork an editor from here and let user update the file.
        edit_file(cnf)

        # Read the config file now and populate global dir.
        read_config()

        self.make_ca()
        self.generate_server_cert(opt.passwd)
        self.make_server_conf()

    def make_ca(self):
        """create CA certs, DH keys etc."""
        global Tool_conf_db

        db = Tool_conf_db

        env = db.ssl_env()
        co  = db['openssl.company']
        xtra_env = {
            'KEY_OU': co + ' SSL Certificates Division',
            'KEY_CN': co + ' CA Certificate',
        }


        progress("Generating CA certificates ..")
        openssl('req', ['-batch', '-days', env['KEY_DAYS'],
                    '-nodes', '-set_serial', "13", '-new', '-x509',
                    '-keyout', 'ca.key', '-out', 'ca.crt'],
                    xtra_env)

        progress("Generating DH param (%s bits) ..", env['KEY_SIZE'])
        openssl('dhparam', ['-out', 'dh%s.pem' % env['KEY_SIZE'],
                    env['KEY_SIZE']], xtra_env, use_config=False)


    def generate_server_cert(self, passwd):
        """Generate the OpenVPN Server certificate"""

        global DB, Tool_conf_db

        db          = Tool_conf_db

        # XXX OpenSSL 0.9.8e cannot handle time larger than 2038!
        # It seems that OpenSSL 0.9.8e doesn't support the ASN.1
        # "generalizedTime" format of time representation.
        exp_yrs     = 10
        exp_days    = exp_yrs * 365
        server_name = db.vpn_server()

        env      = db.ssl_env()
        xtra_env = {
            'KEY_OU':    db['openssl.company'] + ' SSL Certificates Division',
            'KEY_CN':    server_name,
            'KEY_EMAIL': db['general.admin'],
        }

        crt  = server_name + '.crt'
        key  = server_name + '.key'
        csr  = server_name + '.csr'

        debug("OpenVPN server: %s", server_name)

        args = ['-batch', '-days', "%d" % exp_days,
                '-extensions', 'server', ]

        csr_args = args + ['-new', '-keyout', key, '-out', csr, ]
        ca_args  = args + ['-out', crt, '-in', csr ]

        if passwd is not None:
            passenv = randenv()
            xtra_env[passenv] = passwd
            csr_args += ['-passout', 'env:%s' % passenv ]
        else:
            csr_args += [ '-nodes' ]

        progress("Generating OpenVPN Server certificate ..")

        # Generate CSR
        openssl('req', csr_args, xtra_env)
        # Now, sign the CSR by the CA key
        openssl('ca', ca_args, xtra_env)

        progress("OpenVPN server certificate is in %s.crt", server_name)

    def make_server_conf(self):
        """Generate a usable OpenVPN server config file"""
        
        global DB, Server_conf_template
        global Tool_conf_db

        db  = Tool_conf_db
        env = db.vpn_env()

        server_name = db.vpn_server()
        dhparam     = 'dh%s.pem' % db['openssl.keysize']

        # Add additional substitutions
        env['vpnserver'] = server_name
        env['vpnport']   = db.vpn_server_port()
        env['today']     = today()
        env['proto']     = db['openvpn.proto']
        env['dhparam']   = dhparam

        progress("Generating OpenVPN server config and zip file ..")

        create_file(DB.serverconf, Server_conf_template, env)

        make_ovpn_secret(DB.secret)


        # Now, create a ZIP file containing the latest server config
        # stuff.
        files = [ server_name + '.crt', server_name + '.key',
                 'ca.crt', dhparam ]

        zfname = join(DB.confdir, server_name + '.zip')
        zf     = zipfile.ZipFile(zfname, 'w', zipfile.ZIP_DEFLATED)
        zf.write(DB.serverconf, server_name + '.conf')
        zf.write(DB.secret, server_name + '.secret')
        for f in files:
            zf.write(join(DB.crtdir, f), f)

        readme = """Congratulations!

        Your OpenVPN server config is ready for use.

        Please pick up a zipfile containing all the necessary files for
        OpenVPN server here:
            %s
         
        Expand the contents of this file into the OpenVPN server
        directory config - e.g., /etc/openvpn on Linux systems.
        It is important to keep the permissions of the '.key' file very
        strict. e.g., on Unix systems, do
           chmod 0600 %s.key
           chmod 0600 %s.secret

    
        If required, please edit
            %s
        This template will be used for
        sending out automated emails to your users with the appropriate
        OpenVPN client config whenever a new user is added.

        """ % (normpath(zfname), server_name, server_name, DB.email)

        zf.writestr('README.txt', readme)
        zf.close()
        print readme



class client(command):
    """Generate one or more client certificates and private key.

       client [options] user-id [user-id...]

       'user-id' should preferably be of the form 'user@domain.com' -
       e.g., like an email address.

       If multiple users are specified and "--password" option is
       chosen, then the same password is assigned to all the users.
       Thus, it is recommended that "--random" option be chosen when
       multiple users are specified on the command line.
    """

    # Need to set:
    #   KEY_OU="$KEY_CN client certificate"
    #   KEY_CN="user@domain.name"

    def __init__(self):
        super(client, self).__init__()
        self.name = 'client'
        self.cmd_aliases = [ 'adduser', 'newuser' ]
        self.parser = opt_parser(usage=self.help())
        self.parser.add_option("-p", "--passwd",
                dest="passwd", action="store", type="string",
                default=None, metavar="P",
                help="Use password 'P' for encrypting the client certificate private key")

        self.parser.add_option("-r", "--random",
                dest="random", action="store_true",
                default=False,
                help="Generate random password(s) for encrypting the client certificate private key")



    def adduser(self, user, passwd):
        """Add one user to the system"""
        global DB, Tool_conf_db, User_db

        debug("Adding user=%s pass=%s", user, passwd)

        db  = Tool_conf_db
        env = db.ssl_env()
        co  = db['openssl.company']
        xtra_env = {
            'KEY_OU': co + ' SSL Certificates Division',
            'KEY_CN': user,
            'KEY_EMAIL': user,
        }


        exp      = int(db['openssl.validity'])
        exp_days = 365 * exp

        crt  = user + '.crt'
        key  = user + '.key'
        csr  = user + '.csr'

        args = ['-batch', '-days', "%d" % exp_days, ]

        csr_args = args + ['-new', '-keyout', key, '-out', csr, ]
        ca_args  = args + ['-out', crt, '-in', csr ]
        ca_args += ['-notext']

        if passwd is not None:
            passenv = randenv()
            xtra_env[passenv] = passwd
            csr_args += ['-passout', 'env:%s' % passenv ]
        else:
            csr_args += [ '-nodes' ]

        # Generate CSR
        openssl('req', csr_args, xtra_env)

        # Now, sign the CSR by the CA key
        openssl('ca', ca_args, xtra_env)

        # add to the user db
        User_db[user] = passwd

        # Make a zipfile out of the client's certs
        db = Tool_conf_db
        zf = join(DB.confdir, '%s.ovpn' % user)
        if not os.path.exists(zf):
            make_conf(zf, user)


    def run(self, args):
        global DB
        global Tool_conf_db

        opt, argv = self.parser.parse_args(args=args[1:])

        if len(argv) < 1:
            raise ex("Insufficient arguments. Try 'client --help'")

        for v in argv:
            crt = join(DB.crtdir, v + '.crt')
            if os.path.isfile(crt):
                error(0, "User '%s' already exists!", v)
                continue

            if opt.random:
                p = randpass()
            elif opt.passwd is not None:
                p = opt.passwd
            else:
                p = None

            self.adduser(v, p)

class passwd(command):
    """Change password on a given certificate.

       passwd [options] user-id

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
        global DB, User_db

        opt, argv = self.parser.parse_args(args=args[1:])

        rxstr = ".*"
        if len(argv) < 1:
            raise ex("Insufficient arguments. Try 'passwd --help'")

        uid = argv[0]
        udb = User_db
        if uid not in udb:
            raise ex("User '%s' not found in the user DB", uid)

        user_key = join(DB.crtdir, uid + '.key')
        if not os.path.isfile(user_key):
            raise ex("Consistency error! User %s is in user DB but private key not found!", uid)

        oldpass = udb[uid]

        if opt.random:
            newpass = randpass()
        else:
            newpass = opt.passwd

        inpass  = randenv()
        outpass = randenv()

        xtra_env = { inpass: oldpass }
        args     = [ '-in', user_key, '-out', user_key,
                     '-passin', 'env:%s' % inpass, ]

        if newpass is not None:
            args += [ '-des3', '-passout', 'env:%s' % outpass]
            xtra_env[outpass] = newpass

        openssl('rsa', args, xtra_env, use_config=False)

        # Finally, change the user db with new password
        udb[uid] = newpass
        progress("Password for %s successfully changed", uid)


class revoke(command):
    """Remove one or more users from the system.

    revoke user-id [user-id...]

    This command removes users from the system by revoking their client
    certificates and generating a CRL. The CRL must then be pushed to
    the OpenVPN server and the server must be restarted.
    """

    def __init__(self):
        super(revoke, self).__init__()
        self.name = 'revoke'
        self.cmd_aliases = ['remove', 'delete']
        self.parser = opt_parser(usage=self.help())

    def run(self, args):
        global DB
        global User_db

        opt, argv = self.parser.parse_args(args=args[1:])

        if len(argv) < 1:
            raise ex("Insufficient arguments. Try 'revoke --help'")

        udb = User_db
        for u in argv:
            if u not in udb:
                raise ex("User '%s' not found in the user DB", u)

            self.revoke_user(u)

        self.make_crl()

    def revoke_user(self, uid):
        """Revoke one user"""
        global DB, User_db

        user_crt = join(DB.crtdir, uid + '.crt')
        user_csr = join(DB.crtdir, uid + '.csr')
        user_key = join(DB.crtdir, uid + '.key')

        if not os.path.isfile(user_crt):
            raise ex("Consistency error! User %s is in user DB but private key not found!", uid)

        xtra_env = {
            'KEY_OU': 'SSL Certificates Division',
            'KEY_CN': uid,
            'KEY_EMAIL': uid,
        }
        args = ['-revoke', user_crt ]
        openssl('ca', args, xtra_env)

        del User_db[uid]

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



class mkconf(command):
    """Create a zip file containing user's certificate, private key & config files.

    conf [options] user-id [user-id...]

    This command creates or overwrites the per-user .ovpn conf file and stores them
    in the $DBDIR/zip directory.
    """

    def __init__(self):
        super(mkconf, self).__init__()
        #self.cmd_aliases = ['remove', 'delete']
        self.name = 'conf'
        self.parser = opt_parser(usage=self.help())
        self.parser.add_option("-f", "--force-overwrite",
                dest="force", action="store_true",
                default=False,
                help="Forcibly overwrite the destination files [%default]")

    def run(self, args):
        global DB
        global User_db
        global Tool_conf_db

        db        = Tool_conf_db
        opt, argv = self.parser.parse_args(args=args[1:])

        if len(argv) < 1:
            raise ex("Insufficient arguments. Try 'zip --help'")

        udb = User_db
        for u in argv:
            if u not in udb:
                warn("Unknown user '%s'", u)
                continue
            zf = join(DB.confdir, '%s.ovpn' % u)
            if opt.force or not os.path.exists(zf):
                make_conf(zf, u)
            else:
                error(0, "Not overwriting %s", _path(zf))



class email(command):
    """Send client config & password to user via email.

    email [options] user-id [user-id...]

    This command emails users a ready to use .ovpn config file and any
    private key password.

    The outbound SMTP server and envelope From address are both read
    from the config file.
    """

    def __init__(self):
        super(email, self).__init__()
        self.name = 'email'
        self.parser = opt_parser(usage=self.help())
        self.parser.add_option("-s", "--smtp-server",
                dest="smtp_server", action="store", type="string",
                default=None, metavar="S",
                help="Use server 'S' as the outbound SMTP server [default from config file]")
        self.parser.add_option("-f", "--from",
                dest="envelope_from", action="store", type="string",
                default=None, metavar="S",
                help="Use 'S' as the envelope sender address [default from config file]")
        self.parser.add_option("-n", "--dry-run",
                dest="dryrun", action="store_true",
                default=False,
                help="Do a dry-run; don't really send the email [False]")

    def run(self, args):
        global DB
        global User_db
        global Tool_conf_db

        db        = Tool_conf_db
        opt, argv = self.parser.parse_args(args=args[1:])

        if len(argv) < 1:
            raise ex("Insufficient arguments. Try 'revoke --help'")

        smtp_srv  = db['general.smtp']
        smtp_from = db['general.admin']

        if opt.smtp_server is not None:
            smtp_srv = opt.smtp_server

        if opt.envelope_from is not None:
            smtp_from = opt.envelop_from

        udb = User_db
        for u in argv:
            passwd = udb.get(u, None)
            ovpn   = join(DB.confdir, '%s.ovpn' % u)
            if not passwd and not os.path.exists(ovpn):
                raise ex("Can't find user '%s' or their config file", u)

            self.send_email(u, passwd, smtp_srv, smtp_from, opt.dryrun)


    def send_email(self, u, passwd, smtp_server, smtp_from, dryrun):
        """Email credentials for user 'u'

       Borrowed with kind permission and grateful thanks to:
            http://www.bigbold.com/snippets/posts/show/757
        """
        
        global DB
        global Tool_conf_db

        db = Tool_conf_db
        zf = join(DB.confdir, '%s.ovpn' % u)

        d = { 'today': today(),
              'username': u,
              'password': passwd,
              'vpnserver': db.vpn_server(),
              'vpnport':   db.vpn_server_port(),
              'proto':     db['openvpn.proto'],
            }

        fd  = open(DB.email, 'r')
        txt = fd.read(-1) % d
        fd.close()

        to    = [ u ]
        files = [ zf ]
        msg   = MIMEMultipart()

        msg['From']    = smtp_from
        msg['To']      = COMMASPACE.join(to)
        msg['Date']    = formatdate(localtime=True)
        msg['Subject'] = "IMPORTANT: OpenVPN Configuration and password"

        msg.attach( MIMEText(txt) )

        for x in files:
            base = os.path.basename(x)
            part = MIMEBase('application', "octet-stream")
            part.set_payload( open(x, "rb").read() )
            Encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="%s"' % base)
            msg.attach(part)

        debug("Sending email for %s/%s [via %s] as %s", u, passwd,
              smtp_server, smtp_from)

        if not dryrun:
            progress("Sending email for %s [via %s] ..", u, smtp_server)
            smtp = smtplib.SMTP(smtp_server)
            smtp.sendmail(smtp_from, to, msg.as_string() )
            smtp.close()
        else:
            progress("DRYRUN: Sending email for %s [via %s] ..", u, smtp_server)
            debug("Email Text:\n%s\n\n", txt)


class listusers(command):
    """Show all valid users in the system

    listusers [options] [pattern]

    If 'pattern' is specified, look for specified user in the user DB.
    """

    def __init__(self):
        super(listusers, self).__init__()
        self.name = 'listusers'
        self.cmd_aliases = [ 'list', 'lsusers', ]
        self.parser = opt_parser(usage=self.help())
        self.parser.add_option("-p", "--show-password",
                dest="show_passwd", action="store_true", default=False,
                help="Show passwords for each user [False]")


    def run(self, args):
        global DB, User_db
        global Tool_conf_db

        db = Tool_conf_db
        opt, argv = self.parser.parse_args(args=args[1:])

        rxstr = ".*"
        if len(argv) > 0:
            rxstr = argv[0]

        try:
            rxpat = re.compile(rxstr)
        except:
            raise ex("Can't compile regex pattern '%s'", rxstr)

        udb = User_db
        r   = DB.parse_index()
        vs  = db.vpn_server()
        for k, v in r.items():
            if v.status != 'V':
                continue

            if v.cn == vs:
                continue

            if v.cn not in udb:
                error(0, "Consistency error; user %s is in the cert DB but not user db!", v.cn)
                continue

            if not rxpat.search(v.cn):
                continue

            if opt.show_passwd:
                print "%-33s   %s" % (v.cn, udb[v.cn])
            else:
                print "%s" % v.cn


class showcrl(command):
    """Show Users that have been revoked.

    showcrl [options] [pattern]

    If 'pattern' is specified, look for specified user in the CRL list.
    """

    def __init__(self):
        super(showcrl, self).__init__()
        self.name = 'showcrl'
        self.cmd_aliases = [ 'listcrl', 'lscrl' ]
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

        r = self.grab_revoked()
        for x in r:
            if not rxpat.search(x.cn):
                continue
            s = "%-15s" % x.cn
            if opt.show_serial:
                s += " [%s]" % x.serial
            print s



    @staticmethod
    def grab_revoked():
        """Make a list of all revoked certs"""

        global DB

        crl_file = join(DB.crldir, 'crl.pem')

        if not os.path.isfile(crl_file):
            error(0, "No CRL or CRL is empty. Nothing to show")
            return []

        certdb = DB.parse_index()

        # now, read the CRL and process the data
        list_crl_exe = 'openssl crl -text -noout -in %s' % crl_file
        crls = os.popen(list_crl_exe, 'r')
        revoked = []
        for x in crls:
            x = x.strip()

            if not x.startswith('Serial Number:'):
                continue

            serial = x.split(':')[1].strip()
            if serial not in certdb:
                error(0, 'Serial# %s is not in the certificate DB', serial)
                continue

            else:
                d = certdb[serial]
                if d.status != 'R':
                    error(0, "Serial# %s is not revoked?! ** Consistency error**!", serial)
                else:
                    d.serial = serial
                    revoked.append(d)
                    #print '%s: %s' % (serial, d.cn)

        crls.close()
        return revoked

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
                raise ex, "Invalid command %s" % name

            print "%s: %s" % (c.name, c.brief_help())
            a = c.aliases()
            if len(a) > 1:
                print  "Aliases: %s" % ', '.join(a)
            print "\n", c.usage()


class config_file(object):
    """Abstraction representing a .ini style config file for
    ssl-tool.
    
    Instances of this class can be used to query different sections of
    the config file like so:

        c = config_file()
        print c['section.keyword']

    """

    # Mapping of config file keywords in the 'openssl' section to
    # environment vars that will be used when openssl is run.
    ssl_mapping = { 'country': 'KEY_COUNTRY',
                    'city': 'KEY_CITY',
                    'company': 'KEY_ORG',
                    'comment': 'NS_COMMENT',
                    'validity': 'KEY_DAYS',
                    'keysize':  'KEY_SIZE',
                    'state':    'KEY_PROVINCE',
        }


    # Mapping of config file keywords in the 'openvpn' section to
    # substitution dictionary variables
    ovpn_mapping = { 'server': 'vpnserver',
                     'proto': 'proto',
                     'ip-range': 'iprange',
        }

    def __init__(self, fn):
        self.filename = fn

        if not os.path.isfile(self.filename):
            return

        debug("Processing config file %s ..", self.filename)
        self.cp = ConfigParser.ConfigParser()
        self.cp.read(self.filename)


    def ssl_env(self):
        """Return config elements as suitable environment vars"""

        vars = {}
        admin = self.cp.get('general', 'admin')
        vars['KEY_EMAIL'] = admin
        for k, v in self.ssl_mapping.items():
            e = self.cp.get('openssl', k)
            if e is None:
                continue

            if k == 'validity':
                expiry  = int(e) * 365
                vars[v] = "%d" % expiry
            else:
                vars[v] = e
        return vars

    def vpn_env(self):
        """Return dict containing mapping from config file to
        substitution dictionary."""

        vars = {}
        for k, v in self.ovpn_mapping.items():
            e = self.cp.get('openvpn', k)
            if e is None:
                continue

            vars[v] = e

        return vars

    def vpn_server(self):
        """Return the VPN server hostname or IP"""
        c = self.cp.get('openvpn', 'server')
        if c is None:
            return ""

        i = c.find(':')
        if i > 0:
            c = c[:i]

        return c

    def vpn_server_port(self):
        """Return the VPN server port"""

        c = self.cp.get('openvpn', 'server')
        if c is None:
            c = "1194"
        else:
            i = c.find(':')
            if i > 0:
                c = c[i+1:]
            elif i < 0:
                c = "1194"

        return c

    def __getitem__(self, k):
        """Make config-file behave like a dict"""
        v = k.split('.')
        if len(v) != 2:
            raise ex, "Malformed attribute request in config_file.__getattr__('%s')" % k

        s, t = v
        try:
            e = self.cp.get(s, t)
        except NoSectionError, e:
            raise ex, "Unknown section '%s' in config_file.__getattr__('%s')" % s

        return e


class userdb(object):
    """Abstraction of user's passwd database.
    
    It behaves as a dict(), except it is persistent.

    If python had true destructors, we could've flushed the userdb to
    disk in the dtor. Since it doesn't exist, we have to use the
    finalize() method below.
    """

    def __init__(self, dbname):
        self.filename = dbname
        self.db       = {}
        self.modified = False

        if not os.path.exists(dbname):
            return

        debug("Processing user passwd db %s ...", dbname)
        fd = open(dbname, 'r')
        n  = 0
        for line in fd:
            n += 1
            
            a = line.strip().split(':')
            if len(a) == 2:
                k, v = a[0], a[1]
                self.db[k] = v
            else:
                raise ex("%s:%d: Malformed record", dbname, n)
        fd.close()
        debug("User db %s: %d records", dbname, n)

    def finalize(self):
        if not self.modified:
            return

        tmp = self.filename + '.tmp'
        fd  = open(tmp, 'wb')
        for k, v in self.db.items():
            fd.write("%s:%s\n" % (k, v))
        fd.close()
        rename(tmp, self.filename)

    def __getitem__(self, key):
        return self.db[key]

    def __setitem__(self, key, val):
        if val is None:
            val = ""
        self.db[key]  = val
        self.modified = True

    def __delitem__(self, key):
        self.modified = True
        del self.db[key]

    def __contains__(self, key):
        return key in self.db

    def __len__(self):
        return len(self.db)

def read_config():
    """Read the config file in dbdir"""
    global DB
    global Tool_conf_db, User_db

    cnf = DB.toolconf

    debug("Reading config file '%s' ...", cnf)
    Tool_conf_db = config_file(cnf)

    debug("Reading user db '%s' ...", DB.userdb)
    User_db  = userdb(DB.userdb)



# XXX This is incomplete. Do NOT use it.
class dispatcher(object):
    """Command dispatch abstraction.
    
    This class will be a singleton.
    """
    instance = None

    def __init__(self, commands):
        if self.instance is not None:
            raise ex, "dispatcher is a singleton. "

        self.instance = self
        self.cmddb    = {}
        for c in commands:
            cmd = c()
            self.add(cmd)

        self._rebuild()

    def _verify(self, cmd):
        if cmd.name in self.cmddb:
            raise ex, "Duplicate command '%s'" % cmd.name

        for a in cmd.aliases():
            if a in self.cmddb:
                raise ex, "Alias '%s' for command '%s' is a duplicate of another command" % (a, cmd.name)

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
            raise ex, "Invalid or partial command %s" % cmdname

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

    def run_loop(self):
        """Run loop - read from stdin and process each command typed on
        a line."""
        global Quit_Loop, Prompt

        while True:
            if Quit_Loop:
                break

            print Prompt,
            cmd  = sys.stdin.readline().strip()
            if cmd is None:
                break

            if len(cmd) == 0:
                continue

            args = cmd.split()
            self.run_one(args, 0)


# Install signal handlers to gracefully exit
signal.signal(signal.SIGINT, sighandler)
signal.signal(signal.SIGTERM, sighandler)
if not sys.platform.startswith('win'):
    signal.signal(signal.SIGHUP, sighandler)

# List of commands
commands = [ init, client, passwd, mkconf, revoke, showcrl, listusers, email, quit ]
disp     = dispatcher(commands)

# Instantiate the help command to include info about the other commands
H = helpcmd(disp)

# Now, add the help command to the dispatcher.
disp.add(H)

def main():
    """The start of the program"""

    global Debug, Verbose
    global DB
    global __desc__, __version__, __author__
    global Z, H, disp

    doc = """%s [options] -- [command] [command options..]

%s - A comprehensive tool for managing OpenVPN Client & Server certificates in
PKI mode. The tool also generates appropriate client and server
configuration files.

Every remote user of OpenVPN will use a SSL Client Certificate. The
Common Name on the certificate will be the user name.

The tool provides the following commands:

%s

If no command is specified on the command line, the tool enters
interactive mode ("command line mode").

The Database Directory ("DB dir") is a directory where the tool
maintains its configuration files, etc. This is a mandatory argument for
all commands.

Detailed help for each command can be obtained as follows:

   %s -D . CMDNAME --help

Version: %s
Author: %s
License: %s""" % (Z, Z, H.cmdlist(), Z, __version__, __author__, __license__)


    parser = OptionParser(usage=doc,
                          version="%s - v%s %s" % (Z, __version__, __author__))
    parser.add_option("-D", "--db-dir", dest="dbdir", action="store",
                      type="string", default=None, metavar="D",
                      help="Use 'D' as the database directory")

    parser.add_option("-d", "--debug", dest="debug", action="store_true",
                      default=False,
                      help="Run in debug mode [False]")

    parser.add_option("-V", "--verbose", dest="verbose", action="store_true",
                      default=False,
                      help="Run in verbose mode [False]")

    parser.disable_interspersed_args()
    (opt, args) = parser.parse_args()


    # Setting debug => verbose output as well
    if opt.debug:
        Debug       = True
        opt.verbose = True

    if opt.verbose:
        Verbose = True

    if opt.dbdir is None:
        error(1, "DB directory is not set. Please use '-D' global option")

    opt.dbdir = abspath(normpath(opt.dbdir))
    # Now, process the DB dir
    try:
        DB  = config(opt.dbdir)
        read_config()
    except os.error, e:
        error(1, e)

    if len(args) > 0:
        disp.run_one(args, 1)
    else:
        disp.run_loop()

    _exit(0)

# Builtin templates for openssl.cnf and other things
SSL_conf_template = """
#
# OpenSSL example configuration file.
# This is mostly being used for generation of certificate requests.
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

####################################################################
[ ca ]
default_ca  = CA_default        # The default ca section

####################################################################
[ CA_default ]

dir         = $ENV::KEY_DIR     # Where everything is kept
certs       = $dir/certs        # Where the issued certs are kept
crl_dir     = $dir/crl          # Where the issued crl are kept
new_certs_dir = $certs          # default place for new certs.

database    = $dir/index.txt    # database index file.
serial      = $dir/serial       # The current serial number

certificate = $certs/ca.crt       # The CA certificate
crl         = $crl_dir/crl.pem    # The current CRL
private_key = $certs/ca.key       # The private key
RANDFILE    = $dir/.rand          # private random number file

x509_extensions = usr_cert      # The extentions to add to the cert

# Extensions to add to a CRL. Note: Netscape communicator chokes on V2 CRLs
# so this is commented out by default to leave a V1 CRL.
# crl_extensions    = crl_ext

default_days    = 365           # how long to certify for
default_crl_days= 30            # how long before next CRL
default_md  = sha1              # which md to use.
preserve    = no                # keep passed DN ordering

# A few difference way of specifying how similar the request should look
# For type CA, the listed attributes must be the same, and the optional
# and supplied fields are just that :-)
policy      = policy_supplied

# For the CA policy
[ policy_match ]
countryName     = match
stateOrProvinceName = match
organizationName    = match
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional

[ policy_supplied ]
countryName         = supplied
stateOrProvinceName = supplied
localityName        = supplied
organizationName    = supplied
commonName          = supplied
emailAddress        = supplied
organizationalUnitName  = supplied


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

# Passwords for private keys if not present they will be prompted for
# input_password = secret
# output_password = secret

# This sets a mask for permitted string types. There are several options. 
# default: PrintableString, T61String, BMPString.
# pkix   : PrintableString, BMPString.
# utf8only: only UTF8Strings.
# nombstr : PrintableString, T61String (no BMPStrings or UTF8Strings).
# MASK:XXXX a literal mask value.
# WARNING: current versions of Netscape crash on BMPStrings or UTF8Strings
# so use this option with caution!
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

# we can do this but it is not needed normally :-)
#1.organizationName     = Second Organization Name (eg, company)
#1.organizationName_default = World Wide Web Pty Ltd

organizationalUnitName          = Organizational Unit Name (eg, section)
organizationalUnitName_default  = $ENV::KEY_OU

commonName          = Common Name (eg, your name or your server\'s hostname)
commonName_default  = $ENV::KEY_CN
commonName_max          = 64

emailAddress            = Email Address
emailAddress_default    = $ENV::KEY_EMAIL
emailAddress_max        = 40
# JY -- added for batch mode
#organizationalUnitName_default = $ENV::KEY_OU
#commonName_default = $ENV::KEY_CN

# SET-ex3           = SET extension number 3

[ req_attributes ]
challengePassword       = A challenge password
challengePassword_min   = 4
challengePassword_max   = 20

unstructuredName        = An optional company name

[ usr_cert ]

# These extensions are added when 'ca' signs a request.

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
# nsCertType            = server

# For an object signing certificate this would be used.
# nsCertType = objsign

# For normal client use this is typical
# nsCertType = client, email

# and for everything including object signing:
# nsCertType = client, email, objsign

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment           = $ENV::NS_COMMENT

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
# subjectAltName=email:copy

# Copy subject details
# issuerAltName=issuer:copy

#nsCaRevocationUrl      = http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName

[ server ]

# JY ADDED -- Make a cert with nsCertType set to "server"
basicConstraints=CA:FALSE
nsCertType          = server
nsComment           = $ENV::NS_COMMENT
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always
extendedKeyUsage=serverAuth
keyUsage = digitalSignature, keyEncipherment

[ v3_req ]

# Extensions to add to a certificate request

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[ v3_ca ]


# Extensions for a typical CA


# PKIX recommendation.

subjectKeyIdentifier=hash

authorityKeyIdentifier=keyid:always,issuer:always

# This is what PKIX recommends but some broken software chokes on critical
# extensions.
#basicConstraints = critical,CA:true
# So we do this instead.
basicConstraints = CA:true

# Key usage: this is typical for a CA certificate. However since it will
# prevent it being used as an test self-signed certificate it is best
# left out by default.
# keyUsage = cRLSign, keyCertSign

# Some might want this also
# nsCertType = sslCA, emailCA

# Include email address in subject alt name: another PKIX recommendation
# subjectAltName=email:copy
# Copy issuer details
# issuerAltName=issuer:copy

# DER hex encoding of an extension: beware experts only!
# obj=DER:02:03
# Where 'obj' is a standard or added object
# You can even override a supported extension:
# basicConstraints= critical, DER:30:03:01:01:FF

[ crl_ext ]

# CRL extensions.
# Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.

# issuerAltName=issuer:copy
authorityKeyIdentifier=keyid:always,issuer:always
"""

Tool_conf_template = """
# Config file for ssl-tool
#

[general]

# SMTP server for sending email
smtp = 127.0.0.1

# SSL Cert Admin. Will also be used in the From field of the SMTP
# Envelope.
admin   = ssladmin@company.com

# Section for Ovpn
[openvpn]

# server can be one of the following forms:
#    IP:port
#    FQDN:port
#    IP
#    FQDN
# In the last two cases, the default port of 1194 is used.
server = IP:port

# Use tcp or udp for proto field
# Preferred is udp
proto  = udp

# IP Range for the server
# This should be in the same format as expected by OpenVPN server
ip-range = 1.0.1.0 255.255.255.0


# Config block for openssl
[openssl]
# Size of private key in bits. Making this larger than 1024 will
# mean extra security at the cost of more work on the part of
# server and client.
keysize = 1024

country = US
city    = Dallas
state   = TX
company = Snakeoil Peddlers Inc.
comment = Certificate issued by Snakeoil CA


# Number of years client certificate is valid
validity = 3


# vim: expandtab:sw=4:ts=4:tw=72:ft=ini
"""

Server_conf_template = """
#################################################
# Sample OpenVPN 2.0 config file for multi-client server.
#
# This file is for the server side of a many-clients <-> one-server
# OpenVPN configuration.
#
# Comments are preceded with '#' or ';'
#################################################

# Which local IP address should OpenVPN listen on? (optional)
local %(vpnserver)s

# Which TCP/UDP port should OpenVPN listen on?
# If you want to run multiple OpenVPN instances on the same machine, use
# a different port number for each one. You will need to open up this
# port on your firewall.
port %(vpnport)s

proto %(proto)s

# "dev tun" will create a routed IP tunnel, If you want to control
# access policies over the VPN, you must create firewall rules for the
# the TUN interface. On non-Windows systems, you can give an explicit
# unit number, such as tun0. On most systems, the VPN will not function
# unless you partially or fully disable the firewall for the TUN
# interface.
dev tun


# SSL/TLS root certificate (ca), certificate (cert), and private key (key).
# Each client and the server must have their own cert and key file.
# The server and all clients will use the same ca file.
#
# See the "easy-rsa" directory for a series of scripts for generating
# RSA certificates # and private keys. Remember to use a unique Common
# Name for the server and each of the client certificates.
#
# Any X509 key management system can be used.  OpenVPN can also
# use a PKCS #12 formatted key file (see "pkcs12" directive in man
# page).
ca ca.crt
cert %(vpnserver)s.crt

# On Unix systems, make sure you chmod 0600 on this file.
key %(vpnserver)s.key

# Diffie hellman parameters.
# Generate your own with:
#   openssl dhparam -out dh1024.pem 1024
# Substitute 2048 for 1024 if you are using
# 2048 bit keys.
dh %(dhparam)s

# TLS Shared secret
tls-auth %(vpnserver)s.secret 0

# Configure server mode and supply a VPN subnet for OpenVPN to draw
# client addresses from. The server will take 1.99.99.1 for itself, the
# rest will be made available to clients. Each client will be able to
# reach the server on 1.99.99.1. See the man page for more info. This
# virtual IP address range should be a private range which is currently
# unused on your network
server %(iprange)s


# Maintain a record of client <-> virtual IP address associations in
# this file. If OpenVPN goes down or is restarted, reconnecting clients
# can be assigned the same virtual IP address from the pool that was
# previously assigned.
ifconfig-pool-persist /var/lib/openvpn/ipp.txt


# Push routes to the client to allow it to reach other private
# subnets behind the server.
# engineering net
#push "route 192.168.15.0 255.255.255.0"
#push "route 192.168.16.0 255.255.255.0"
#push "route 192.168.64.0 255.255.192.0"
#XXX Maybe add routes to all US Nets as well?

# VPN server is the default gw for all traffic
push "redirect-gateway"

# To assign specific IP addresses to specific clients or if a connecting
# client has a private subnet behind it that should also have VPN
# access, use the subdirectory "ccd" for client-specific configuration
# files (see man page for more info).
client-config-dir ccd

# If the client having the certificate common name
# dbenjamin also has a small subnet behind his client openvpn machine,
# such as 192.168.211.0/255.255.255.0. and you want machines on that
# network to be able to talk to the server openvpn, then
# you need to let openvpn know to route to that network.
#route 192.168.211.0 255.255.255.0
# Then create a file ccd/dbenjamin with this line:
#   iroute 192.168.211.0 255.255.255.0
# This will allow dbenjamin private subnet to access the VPN. This
# example will only work if you are routing, not bridging, i.e. you are
# using "dev tun" and "server" directives.


# The keepalive directive causes ping-like messages to be sent back
# and forth over the link so that each side knows when the other
# side has gone down.  Ping every 10 seconds, assume that remote
# peer is down if no ping received during a 120 second time period.
keepalive 10 120

# Enable compression on the VPN link.  If you enable it here, you
# must also enable it in the client config file.
comp-lzo

# The maximum number of concurrently connected clients we want to
# allow.
#max-clients 10

# It's a good idea to reduce the OpenVPN daemon's privileges after
# initialization.
user nobody
group nobody

# The persist options will try to avoid accessing certain resources
# on restart that may no longer be accessible because of the
# privilege downgrade.
persist-key
persist-tun

# Output a short status file showing current connections, truncated
# and rewritten every minute.
status /tmp/openvpn-status.log

# By default, log messages will go to the syslog.
# Use log or log-append to override this default.
# "log" will truncate the log file on OpenVPN startup, while
# "log-append" will append to it.  Use one or the other (but not
# both).
#;log         openvpn.log
#;log-append  openvpn.log

# Set the appropriate level of log
# file verbosity.
#
# 0 is silent, except for fatal errors
# 4 is reasonable for general usage
# 5 and 6 can help to debug connection problems
# 9 is extremely verbose
verb 3

# Silence repeating messages.  At most 20 sequential messages of the
# same message category will be output to the log.
#;mute 20

# Management console
# mgmt.passwd is the name of the password file in /etc/openvpn
# This file must contain the password on a single line
#management 127.0.0.1 11940 mgmt.passwd

"""

Client_config_template = """
#
# OpenVPN client configuration for connecting to %(vpnserver)s
#    user  %(client)s 
#
# Generated on %(today)s
# 

client
tls-client
dev tun
proto %(proto)s
remote %(vpnserver)s %(vpnport)s
resolv-retry infinite
nobind
topology subnet
comp-lzo
verb 3
passtos
route-delay 4
script-security 2

<ca>
%(ca_cert)s
</ca>
<cert>
%(user_cert)s
</cert>
<key>
%(user_key)s
</key>
<tls-auth>
%(tls_secret)s
</tls-auth>
"""

Email_template = """Greetings %(username)s,

This email explains how to setup VPN client for your organization on
your Linux, Windows PC, iOS or Android device(s).

If your configuration is locked with a password, you will find it below:

    %(password)s

Attached to this email is your OpenVPN client configuration file.

Instructions for Mobile Users
=============================
If you are on iOS:
    
    - press and hold down the ovpn config file ("long press")
    - When presented with a choice, open the config file in the OpenVPN
      app. This will import the config file into your iOS device.


If you are on Android:

    - Save this config file onto SDCard
    - Open the OpenVPN app and select "import configuration"
    - Navigate to the folder where you stored the config file
    - open it.

Instructions for Windows Users
==============================
1. Make sure you are logged into an account with administrative
  rights

2. Fetch the OpenVPN Windows Client from:
     http://www.openvpn.se/download.html

3. Install the package with the following options selected:

    * Install GUI
    * Add OpenVPN GUI to Startup folder

4. Save the attached .ovpn config file and then double click to install
it in the correct directory/app.

   Make sure that the files all end up in the subdirectory
   "config".

5. Start OpenVPN-GUI (if not already started)

6. Right click on the task-bar button for OpenVPN and select
   "Connect". A dialog box should show the progress and successful
   connection status.

Instructions for Unix Users
===========================
1. Install OpenVPN according to the conventions of your
   distribution (e.g., apt-get install openvpn)

2. As root, expand the contents of the attached zip-file into
   /etc/openvpn. Then, run the following commands:

    cd /etc/openvpn
    mv config/*.ovpn .
    rmdir config

3. Start OpenVPN. On GNU/Linux systems, the following will suffice:

     /etc/init.d/openvpn start %(username)s


Testing the VPN
===============
To test connectivity of the VPN, try pinging to one of the well known
servers inside your network.

Important Note
==============
If you use the *same* credentials (contents of the zipfile) on two or
more computers, you will find that your connections will be randomly
terminated and re-established frequently. This is a security
feature. The only solution is to get a separate set of credentials for
each device that needs to connect.

Thanking the Right People
=========================
Undoubtedly, over time you will find that OpenVPN is very useful and
is much better than other (inferior) VPN clients you have used in
the past. If such is the case, please direct your grateful thanks
to the author of OpenVPN - http://www.openvpn.net/donate.html

Colophon
========
If you have difficulty, please contact your local Unix admin or
your local Linux/Unix guru.

Cheers,
--
Your Friendly OpenVPN Administrator
%(today)s

P.S. Do Not reply to this email. The address does not exist.
"""

main()

# vim: expandtab:sw=4:ts=4:tw=72:notextmode:
