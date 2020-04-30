#! /bin/ksh

#
# Randomize OpenBSD interface mac addresses
#
# (c) 2014, 2015 Sudhi Herle <sudhi-at-herle-net>
# License: Same as OpenBSD kernel (BSD)
#
# Installation for OpenBSD:
#    - put this script as /bin/randmac
#    - This script is meant to be called from hostname.if(5)
#      As the very first line of the hostname.if(5) file, add the
#      following invocation:
#       !randmac $if
#
#    - Add the lines you normally would after this line. Now, whenever
#      the interface in question is brought up, it will get a random mac
#      address.
#
# This should work on all the BSDs and OS X. But, I haven't tried it
# on any of them.

PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/bin
export PATH

# Other OUIs:
# D-Link 1c:af:f7
# HTC    1c:b0:94 38:e7:d8 64:a7:69 7c:61:93 84:7a:88

_rand4() {
    typeset x=$(dd if=/dev/urandom bs=64 count=1 2>/dev/null | md5sum)
    echo ${x:0:2} ${x:2:2} ${x:4:2} ${x:6:2}
    return 0
}

_hexrand() {
    typeset rr=$(hexdump -e '32/1 "%02x " "\n"' -n 8 /dev/urandom)
    echo $rr
    return 0
}

# Generate a random mac address
_randmac() {
    # These are VMware, Xen and Parallels OUIs
    set -A vendors "00:05:69" "00:0c:29" "00:1c:14" "00:50:56" \
                   "00:1c:42" "00:16:3e" "00:bb:3a" "e0:cb:1d"
    typeset n=${#vendors[@]}

    typeset rr=$(_rand4)

    set -A rand -- $rr

    typeset a1=${rand[0]}
    typeset a2=${rand[1]}
    typeset a3=${rand[2]}
    typeset a4=$(( 0 + 0x${rand[3]} ))   # We want this to be an integer

    # pick a random prefix from the list
    typeset pref=${vendors[$a4 % $n]}

    echo "$pref:$a1:$a2:$a3"
}

if [ "x$1" = "x" ]; then
    echo "Usage: $0 IFACE" 1>&2
    exit 1
fi

iface=$1

# When run as a normal user, just print the command that would've
# been executed
me=$(id -u)
if [ $me != 0 ]; then
    e=echo
fi

$e ifconfig $iface lladdr $(_randmac)
