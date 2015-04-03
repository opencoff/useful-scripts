#! /bin/bash

#
# Setup IPFW for OS X 
#
# (c) 2012, 2013 Sudhi Herle <sw at herle.net>
# License: GPLv2
#

# Theory:
#   - OS X uses the in kernel ipfw(8) firewall & traffic shaper
#   - Setup rules in /etc/ipfw.conf
#   - Run those rules at startup once using LaunchDaemons
#
# Notes:
#   - '$0 install' will turn this into a LaunchDaemon
#

# Name for launchd 
FNAME=net.herle.ipfw

me=`id -u`
if [ $me -ne 0 ]; then
    echo "$0: Need root privilege to run; switching to dry-run mode .."
    e=echo
fi

#set -x

usage() {
    cat 1>&2 <<EOF1
Usage: $0 start|stop|restartinstall

start: Start the firewall
stop: Stop the firewall
restart: Flush the rules and restart the firewall
install: Creates a system startup file in /Library/LaunchDaemons/$FNAME.plist
EOF1

    exit 1

}

make_config() {
    local conf=$1
    local now=`date`

    cat > $conf <<EOF3

# Ruleset created by $0
# 
# If you change this file, do the following:
#   sudo ipfw -f flush
#   sudo ipfw -q /etc/ipfw.conf
#
#

######################################################################
# Localhost Settings
######################################################################

# Allow everything on the localhost (127.0.0.1)
add 00100 set 0 allow ip from any to any via lo*    

# Prevent spoofing attacks via localhost
add 00200 set 0 deny log all from 127.0.0.0/8 to any in
add 00201 set 0 deny log all from any to 127.0.0.0/8 in
add 00202 set 0 deny log ip from 224.0.0.0/3 to any in
add 00203 set 0 deny log tcp from any to 224.0.0.0/3 in
    
######################################################################
# ip-options
# (per FreeBSD Security Advisory: FreeBSD-SA-00:23.ip-options)
######################################################################

add 00250 set 0 deny log ip from any to any ipoptions ssrr,lsrr,ts,rr
    
######################################################################
# Allow outbound TCP, UDP & ICMP  keep-state
######################################################################

add 00300 set 1 check-state
add 00301 set 1 deny log all from any to any frag in 
add 00302 set 1 allow log tcp from any to any established
add 00303 set 1 allow tcp from me to any out setup keep-state
add 00304 set 1 allow udp from me to any out keep-state
add 00305 set 1 allow icmp from any to any out keep-state 

# Allow traceroute out for diagnostics
add 00307 set 1 allow udp from me to any 33434-33525 out keep-state
add 00308 set 1 allow log udp from any to any 33434-33525 in keep-state

# Prevent spoofing attacks
add 00309 set 1 deny ip from me to me in keep-state

# Deny Inbound NetBios traffic which just clogs up the logs
add 00311 set 1 deny tcp from any to any 137,138,139 in setup keep-state
add 00312 set 1 deny udp from any to any 137,138,139 in keep-state

# Prevent ident requests
add 00313 set 1 deny log tcp from any to me 113 in setup keep-state

# Attempt to prevent os fingerprinting, port 0 is commonly used for fingerprinting purposes
add 00314 set 1 deny log tcp from any to any 0 in setup keep-state
add 00315 set 1 deny log udp from any to any 0 in keep-state

######################################################################
# DNS, Rendevouz, DHCP & NTP Services
######################################################################
    
# Allow DNS 
add 00400 set 2 allow tcp from me to any 53 out setup keep-state
add 00401 set 2 allow udp from me to any 53 out keep-state

#Allow Rendezvous packets (mDNS Responder)
#add 00402 set 2 allow udp from any 5353 to any in keep-state
add 00402 set 2 allow udp from any to any 5353 keep-state
#Multicast packet required by Rendezvous
add 00404 set 2 allow ip from any to 224.0.0.251 out keep-state

# Allow DHCP 
add 00500 set 2 allow udp from any 67,68 to any 67,68 in keep-state
add 00501 set 2 allow udp from any 67,68 to any 67,68 out keep-state

# Allow NTP
add 00600 set 2 allow udp from any to any 123 out keep-state
add 00601 set 2 allow tcp from any to any 123 out setup keep-state

######################################################################
# Services Inbound
######################################################################

# Allow SSH and rsync inbound
add 00700 set 3 allow tcp from any to me dst-port 22 in setup keep-state
add 00701 set 3 allow tcp from 105.1.80.0/24 to me dst-port 873 in setup keep-state
add 00702 set 3 allow tcp from any to me dst-port 2222 in setup keep-state

add 00712 set 3 allow tcp from any to me dst-port 80 in setup keep-state
add 00713 set 3 allow tcp from any to me dst-port 443 in setup keep-state
add 00714 set 3 allow tcp from any to me dst-port 8000 in setup keep-state

# Deny any TCP setup requests from the outside world
add 00800 set 3 deny log tcp from any to any setup in keep-state

######################################################################
# ICMP
######################################################################

# Allow pings
add 00900 set 4 allow icmp from any to any icmptypes 0,3,8,11

# Deny ICMP
add 00905 set 4 deny icmp from any to me in icmptypes 4,12

# Deny external ICMP redirect requests
add 00908 set 4 deny icmp from any to any icmptype 5 in keep-state

# Silent block on router advertisements
add 00910 set 4 deny icmp from any to any icmptypes 9
    
# Drop all other ICMP
add 00911 set 4 deny icmp from any to any
    
######################################################################
# Cleanup
######################################################################

# Default deny rule
add 10000 set 5 deny log logamount 500 all from any to any
#
# vim: tw=180:expandtab:sw=4:ts=4:
EOF3

}


# Installs a startup service
install_service() {
    local idir=/Library/LaunchDaemons
    local bn=`basename $0`
    local prog=/etc/$bn

    if [ $me -ne 0 ]; then
        idir=/tmp/ramfs
    fi

    local file=$idir/${FNAME}.plist

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

    <key>Debug</key>
    <false/>

    <key>KeepAlive</key>
    <false/>

    <key>RunAtLoad</key>
    <true/>

    <key>ProgramArguments</key>
    <array>
        <string>$prog</string>
        <string>start</string>
    </array>

</dict>
</plist>
EOF2

    local tmp=/tmp/ipfw.conf
    local conf=/etc/ipfw.conf

    make_config $tmp
    if [ -f $conf ]; then
        $e mv $conf ${conf}.sav
    fi

    $e cp $tmp $conf
    $e cp $0 $prog
    $e chmod a+rx,og-w $prog
    $e chmod 0644 $file
    $e chmod 0600 $conf
    $e rm -f $tmp

    return 0
}


if [ -z "$1" ]; then
    usage
    exit 1
fi


conf=/etc/ipfw.conf
sysctl=/usr/sbin/sysctl
ipfw=/sbin/ipfw

case $1 in
    start)
        echo "Starting firewall .."
        if [ ! -f $conf ]; then
            echo "Making $conf .."

            tx=/tmp/ipfw.conf
            make_config $tx
            $e cp $tx $conf
            $e rm -f $tx
        else
            echo "Using $conf .."
        fi

        # Wait for interface to get at least _one_ IP address
        #ipconfig waitall

        $e $sysctl -w net.inet.ip.fw.verbose=2
        $e $sysctl -w net.inet.ip.fw.verbose_limit=100
        $e $sysctl -w net.inet.tcp.blackhole=2
        $e $sysctl -w net.inet.udp.blackhole=1
        $e $sysctl -w net.inet.ip.forwarding=1

        $e $ipfw -f flush
        $e $ipfw -q $conf
        ;;

    stop)
        echo "Stopping firewall .."
        $e $ipfw -f flush
        ;;

    restart)
        echo "Restarting firewall .."
        $0 stop; sleep 3
        $0 start
        ;;

    install)
        install_service
        ;;

    *)
        usage
        exit 1
        ;;
esac


# vim: expandtab:sw=4:ts=4:tw=72:notextmode:
