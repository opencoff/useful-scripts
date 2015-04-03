Sudhi's Script Hacks
====================
These are some of the scripts I wrote to make my life interesting.
I contribute it to the world so that others may enjoy.


Most of the scripts come with some sort of help message
(``--help``). If not, the use of the script ought to be evident.

License
=======
Most of the scripts are GPLv2. Some are with a more liberal (BSD)
license. Don't ask - its just my preference.

Brief Blurb about Each
======================
::

    abspath           when you need command line access to os.path.abspath()
    isabs             when you need command line access to os.path.isabs()
    realpath          when you need command line access to os.path.realpath()
    aes.py            AES encrypt a file in CTR mode with random salt
    cert-tool.py      Tool to make you into a light weight X.509 CA
    comic2pdf         If you have bunch of CBRs and want PDFs instead
    deadlinks         Show me symlinks that point to non existent files
    dos2unix.py       Turn CRLF into LF
    finddup           If you have identical files strewn around in your file system
    hexlify           hexlificate your stdin

    kill.py           Cross platform PID/name based kill utility with interactive prompts.
                      alias kill=kill.py  works very nicely.

    make-tunnel.py    Create IPSec tunnels with preshared keys (site-to-site VPN). Tested on Linux,
                      easy to adapt to other OSes.

    mk-raw-vmware.py  The name says it all; make a raw disk with no holes
    pingsubnet.py     Ping multiple addresses in a subnet and get results back
    randmac           Print a semi-random mac address
    randpass          Experiments in generating random passwords
    rename            Rename files based on regex. Yes, its Perl.
    rotatedir         Rotate a directory with newest name ending in .0 suffix
    rsync-backup.py   Backup using rsync and hardlinks
    tolower           Play with file names and their case. Try 'tolower --help'
    xdump             I forget how to use hexdump. Hence this short alias

    server-backup     Script I use to backup remote machines via SSH. Customize it for your use
                      case.

ovpn-tool.py      
------------
So, you want to run your own OpenVPN server. And then you decide to get adventerous and offer it to
your friends and family. Now, you have to worry about authentication and mobile devices. This
utility is designed to make your life easy to manage a small OpenVPN server and generate client
certs, client configs etc. The generated ``.ovpn`` file is also usable on iOS and Android.

Comes with builtin help ``ovpn-tool.py  --help``.

OS X Tools
----------
These are some OS X specific tools that make your life interesting.::

    mkdmg.sh          Make OS X compressed disk image from a source directory
    gone.sh           Nuke your OS X root/boot disk. Use with care :-)

The next set of utilities work with ``launchd(8)`` to make their behavior persistent across boots.
You can run them in one-shot mode on the command line or use the ``install`` option to relegate it
to launchd control.::

    osx-ipfw.sh       Enable ipfw(8) with a default set of secure rules
    osx-noatime.sh    Enable noatime mounts on all disks
    osx-ramfs.sh      Put /tmp and /var/run under a RAMFS
    osx-randmac.sh    Randomize your MAC address at every boot. Designed to auto-detect your wifi
                      interface and use it with that.
    osx-tuntap.sh     Make your tun-tap driver persistent.


Linux Specific Tools
--------------------
::

    find-usb-disk     List USB disks - for those of us who dislike systemd
    linktest.py       Test link status of ethernet interface(s)

kern-build
~~~~~~~~~~
If you are in the embedded systems world - building and using custom linux kernels, then you'll love
this utility. It allows you to build multiple kernel images from a single source directory. It
took life during the reign of 2.6.12. I've kept it more or less up-to-date through modern 3.x
kernels. Haven't tried it on 4.x yet.

I used it regularly to build kernels for UML, x86 and mips. If you add other Arch's and their
aliases, send me patches.

openbsd-randmac.sh 
------------------
This script is incomplete - it generates a random mac address and sets it on the interface. But, one
needs a place from whence to call this. Haven't figured out exactly where to do that. Patches
welcome.

disablecaps.inf
---------------
A long time ago, I used to do a lot of work on Windows - especially writing ARM instruction set
emulators. And, I wanted a way to disable CapsLock permanently. I figured out this hack to make it
happen. I haven't tested in on a more recent Windows 7/8/10. If you find this useful, drop me a
note.



--

Sudhi
