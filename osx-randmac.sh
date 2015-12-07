#! /bin/ksh

#
# Setup OS X with a random mac address for WiFi or a specific
# interface.
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

PATH=/sbin:/usr/sbin:/bin:/usr/bin:$PATH
export PATH

#set -x

# First dump existing config to stderr
#ifconfig -a 1>&2

function usage {
    cat 1>&2 <<EOF1
$Z - Randomize MAC address of OS X WiFi (or any given interface).

Usage: $Z start|update|stop|restartinstall [IFACE]

If no interface is specified, the script automatically detects and
uses the WiFi interface. Description of actions:

start, update: Update MAC Address
stop:    No Op
restart: No op
install: Creates a system startup file in /System/Library/LaunchDaemons/$FNAME.plist
EOF1

    exit 1
}

uname=`uname`
case $uname in
    Darwin);;

    *) echo "$0: This script is meant for Mac OS X only." 1>&2
       exit 1
       ;;
esac

action=$1
if [ -z "$action" ]; then
    usage
    exit 1
fi
shift

# Ideally, this should be installed at the system wide level.
# If you install it on a per-user basis, make sure you tie it to laptop lid-wake events.
# sleepwatcher is your friend.
systemwide=1

if [ -n "$systemwide" ]; then
    installdir=/System/Library/LaunchDaemons
    bindir=/usr/sbin
else
    installdir=/Library/LaunchDaemons
    bindir=/etc
fi



me=`id -u`
if [ $me -ne 0 ]; then
    echo "$Z: Need root privilege to run; switching to dry-run mode .."
    e=echo
fi

#set -x

function grok_wifi_darwin {
    typeset iface=$1

    if [ -n "$iface" ]; then
        n=$(ifconfig $iface 2>/dev/null | wc -l)
        if [ $n -eq 0 ]; then
            echo "$Z: $iface is not a network interface?" 1>&2
            exit 2
        fi
    else
        # grok the wifi interface

        # Run scutil to get interface state which has AirPort in it
        typeset xx=`echo list | scutil | grep State: | grep -i AirPort | cut -d= -f2`

        if [ -z "$xx" ]; then
            echo list | scutil 1>&2
            echo "$Z: Whoa. Can't find any WiFi interface!" 1>&2
            exit 1
        fi

        typeset dx=`dirname $xx`
        iface=`basename $dx`

        if [ -z "$iface" ]; then
            echo "$Z: Can't grok WiFi Interface. Are you connected via WiFi?" 1>&2
            exit 1
        fi
    fi

    # Now, lets make sure this is really a wireless interface
    xx=`$net -getairportnetwork $iface`
    if [ $? -ne 0 ]; then
        echo "$Z: $iface doesn't look like a WiFi interface.." 1>&2
        exit 1
    fi

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
        if [ $? -ne 0 ]; then
            echo "$Z: $iface doesn't look like a WiFi interface.." 1>&2
            exit 1
        fi

        echo $iface
        return 0
        
    done

    echo "$Z: Can't grok WiFi interface after 10 tries!" 1>&2
    exit 1
}


# Verify that a given interface is really a wifi interface.
function verify_wifi_Darwin {
    typeset iface=$1
    typeset x=`echo list | scutil | grep "State:/Network/Interface/$iface/AirPort"`

    if [ -z "$x" ]; then
        echo "$Z: $iface is not a WiFi interface" 1>&2
        return 1
    fi
    $e ifconfig $iface down
    return 0
}


# Generate a random mac address
function _randmac {
    # Generate random bytes
    typeset randstr=$(dd if=/dev/urandom bs=4 count=1 2>/dev/null| od -t xC)

    # These are VMware, Xen and Parallels OUIs
    typeset -a vendors=("00:05:69" "00:0c:29" "00:1c:14" "00:50:56" \
                        "00:1c:42" "00:16:3e")
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
    typeset mac=$(_randmac)

    # Updating MAC requires us to turn on the WiFi iface


    # First disassociate from any connected WiFi
    #$e $ipconfig set $iface NONE

    $e $airport -z || return $?

    $e ifconfig $iface down

    #$e $net -setairportpower $iface off; sleep 2;
    $e $net -setairportpower $iface on
    $e ifconfig $iface ether $mac up || return $?

    $e $net -detectnewhardware

    return 0
}


# Installs a startup service
function install_service {
    typeset bn=`basename $Z`
    typeset prog=$bindir/$bn

    if [ $me -ne 0 ]; then
        installdir=/tmp
    fi

    typeset file=$installdir/${FNAME}.plist

    cat > $file <<EOF2
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$FNAME</string>

    <key>Disabled</key>
    <false/>

    <key>UserName</key>
    <string>root</string>

    <key>GroupName</key>
    <string>wheel</string>

    <key>KeepAlive</key>
    <false/>

    <key>RunAtLoad</key>
    <true/>

    <key>ProgramArguments</key>
    <array>
        <string>$prog</string>
        <string>start</string>
        <string>$iface</string>
    </array>

</dict>
</plist>
EOF2

    $e cp $0 $prog
    $e chmod a+rx,og-w $prog

    echo "Installed to $file and $prog .."

    return 0
}


iface=$1
if [ -z "$iface" ]; then
    iface=`wait_wifi_darwin`

    if [ -z "$iface" ]; then
      echo "$Z: Can't figure out the WiFi interface. Aborting..." 1>&2
      exit 1
    fi
else
    verify_wifi_Darwin $iface
    if [ $? -ne 0 ]; then
        exit 1
    fi
fi
FNAME=${FNAME}.$iface

$e ifconfig $iface down

case $action in
    start|update)
        #echo "Setting MAC Address for $iface .."
        update_mac $iface
        ;;

    install)
        install_service
        ;;

    stop|restart)
        ;;

    help|*)
        usage
        ;;
esac

# EOF
