#! /bin/ksh

#
# Setup OS X with a random mac address for WiFi or a specific
# interface. The MAC address on the specified iface is randomized
# every day (24 hours). This script uses a systemwide LaunchAgent to
# trigger the periodic MAC refresh.
#
# Author: Sudhi Herle <sudhi-at-herle-net>
# (c) Sudhi Herle 2013-2016
# License: GPLv2
#
# Order of doing things
#  - disassociate from any network
#  - update airport interface with random mac address
#  - restart network


# name for launchd
FNAME=net.spoof.mac
airport=/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport
net=/usr/sbin/networksetup
ipconfig=/usr/sbin/ipconfig
Z=`basename $0`
DATE=/bin/date
STAT=/usr/bin/stat
TOUCH=/usr/bin/touch
PROG=$0
Me=`id -u`

# Debug hook
#e=echo

Installdir=/Library/LaunchDaemons
Bindir=/usr/local/bin

PATH=/sbin:/usr/sbin:/bin:/usr/bin:$PATH
export PATH


function die {
    echo "$Z: $@" 1>&2
    exit 1
}


if [ $Me -ne 0 ]; then
    echo "$Z: Need root privilege to run; switching to dry-run mode .."
    Installdir=/tmp/LaunchAgents
    Bindir=/tmp/bin
    e=echo

    mkdir -p $Installdir $Bindir
fi


#set -x

# First dump existing config to stderr
#ifconfig -a 1>&2

function usage {
    cat 1>&2 <<EOF1
$Z - Randomize MAC address of OS X WiFi (or any given interface).

Usage: $Z start|update|stop|restart|install [IFACE]

If no interface is specified, the script automatically detects and
uses the WiFi interface. Description of actions:

start, update: Update MAC Address
stop:    No Op
restart: No op
install: Creates a launchd file in /Library/LaunchDaemons
EOF1

    exit 1
}

uname=`uname`
case $uname in
    Darwin);;

    *) die "This script is meant for Mac OS X only."
       ;;
esac

action=$1
test -n "$action" || usage
shift

function writelog {
    #$e logger -p "daemon.notice" -t "${FNAME}" "$@"
    echo "`date`: $@" >> /tmp/mac.log
}


function grok_wifi_darwin {
    typeset iface=$1

    if [ -n "$iface" ]; then
        n=$(ifconfig $iface 2>/dev/null | wc -l)
        test $n -gt 0 || die "$iface is not a network interface?"
    else
        # grok the wifi interface

        # Run scutil to get interface state which has AirPort in it
        typeset xx=`echo list | scutil | grep State: | grep -i AirPort | cut -d= -f2`

        if [ -z "$xx" ]; then
            echo list | scutil 1>&2
            die "Whoa. Can't find any WiFi interface!"
        fi

        typeset dx=`dirname $xx`
        iface=`basename $dx`
        test -n "$iface" || die "Can't grok WiFi Interface. Are you connected via WiFi?"
    fi

    # Now, lets make sure this is really a wireless interface
    xx=`$net -getairportnetwork $iface`
    test $? -eq 0 || die "$iface doesn't look like a WiFi interface.."

    echo $iface
}


# Ugly hack to wait for an interface to come up
# The problem seems to have started with Yosemite!
function wait_wifi_darwin {
    typeset max=10
    typeset i=0
    typeset iface=


    while [ $i -lt 10 ]; do
        i=$(( i + 1 ))

        # Run scutil to get interface state which has AirPort in it
        typeset xx=`echo list | scutil | grep State: | grep -i AirPort | cut -d= -f2`

        if [ -z "$xx" ]; then
            sleep 2
            continue
        fi

        typeset dx=`dirname $xx`
        iface=`basename $dx`
        if [ -z "$iface" ]; then
            sleep 2
            continue
        fi

        # Now, lets make sure this is really a wireless interface
        xx=`$net -getairportnetwork $iface`
        test $? -eq 0 || die "$iface doesn't look like a WiFi interface.."

        echo $iface
        return 0
        
    done

    die "Can't grok WiFi interface after 10 tries!"
}


# Verify that a given interface is really a wifi interface.
function verify_wifi_Darwin {
    typeset iface=$1
    typeset x=`echo list | scutil | grep "State:/Network/Interface/$iface/AirPort"`

    test -n "$x" || die "$iface is not a WiFi interface"
    $e ifconfig $iface down
    return 0
}


# Generate a random mac address
function _randmac {
    # Generate random bytes
    typeset randstr=$(dd if=/dev/urandom bs=4 count=1 2>/dev/null| od -t xC)

    # These are VMware, Xen and Parallels OUIs
    typeset -a vendors=("00:05:69" "00:0c:29" "00:1c:14" "00:50:56" \
                        "00:1c:42" "00:16:3e" "00:bb:3a" "e0:cb:1d")
    typeset -a rand=($randstr)

    # Number of vendors (length of array)
    typeset n=${#vendors[@]}

    # rand[0] and rand[5] are offsets; we can ignore them.
    typeset a1=${rand[1]}
    typeset a2=${rand[2]}
    typeset a3=${rand[3]}
    typeset a4=$(( 0 + 0x${rand[4]} ))   # We want this to be an integer

    # pick a random prefix from the list
    typeset pref=${vendors[$a4 % $n]}

    echo "$pref:$a1:$a2:$a3"
}


function update_mac {
    typeset iface=$1
    typeset mac=$2

    # Updating MAC requires us to turn on the WiFi iface


    # First disassociate from any connected WiFi
    #$e $ipconfig set $iface NONE

    $e $airport -z || return $?

    $e ifconfig $iface down

    #$e $net -setairportpower $iface off; sleep 2;
    $e $net -setairportpower $iface on
    $e ifconfig $iface ether $mac up || return $?

    $e $net -detectnewhardware

    #writelog "$iface: MAC updated to $mac"
    writelog "$iface: $mac"

    return 0
}


# Installs a startup service
function install_service {
    typeset iface=$1
    typeset fname=${2}.$iface
    typeset bn=`basename $Z`
    typeset prog=$Bindir/$bn

    typeset file=$Installdir/${fname}.plist

    cat > $file <<EOF2
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$fname</string>

    <key>Disabled</key>
    <false/>

    <key>UserName</key>
    <string>root</string>

    <key>GroupName</key>
    <string>wheel</string>

    <key>KeepAlive</key>
    <false/>

    <key>Debug</key>
    <false/>

    <key>RunAtLoad</key>
    <true/>

    <key>AbandonProcessGroup</key>
    <true/>

    <!-- Randomize the MAC at 0600 every day -->

    <key>StartCalendarInterval</key>
    <dict>
        <key>Minute</key>
        <integer>0</integer>

        <key>Hour</key>
        <integer>6</integer>
    </dict>

    <key>ProgramArguments</key>
    <array>
        <string>$prog</string>
        <string>update</string>
        <string>$iface</string>
    </array>
</dict>
</plist>
EOF2

    test -d $Bindir || $e mkdir -p $Bindir
    $e cp $PROG $prog
    $e chmod a+rx,og-w $prog

    $e launchctl load $file
    $e launchctl enable system/$fname

    echo "Installed to $file and $prog .."

    return 0
}

# -- start of main() --

iface=$1
if [ -z "$iface" ]; then
    iface=`wait_wifi_darwin`
    test -n "$iface" || die "Can't figure out the WiFi interface. Aborting..."
else
    verify_wifi_Darwin $iface
    test $? -eq 0 || exit 1
fi

mac=$2
if [ -z "$mac" ]; then
    mac=$(_randmac)
fi


r=0
case $action in
    start|update)
        update_mac $iface $mac
        r=$?
        ;;

    install)
        install_service ${iface} ${FNAME}
        r=$?
        ;;

    stop|restart)
        ;;

    help|*)
        usage
        ;;
esac
exit $r

# EOF
