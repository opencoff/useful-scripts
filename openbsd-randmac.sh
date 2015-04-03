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

# Generate a random mac address
_randmac() {
    # These are VMware, Xen and Parallels OUIs
    set -A vendors "00:05:69" "00:0c:29" "00:1c:14" "00:50:56" \
                   "00:1c:42" "00:16:3e"
    typeset n=${#vendors[@]}

    set -A rand -- $(dd if=/dev/urandom bs=4 count=1 2>/dev/null| od -t xC)

    # rand[0] and rand[5] are offsets; we can ignore them.
    typeset a1=${rand[1]}
    typeset a2=${rand[2]}
    typeset a3=${rand[3]}
    typeset a4=$(( 0 + 0x${rand[4]} ))   # We want this to be an integer

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

$e ifconfig $iface ether $(_randmac)
