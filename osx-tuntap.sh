#! /bin/bash

#
# Load tun/tap OSX drivers
#
# For some bizarre reason, org.macports.tuntaposx fails to start on
# Lion. Thus, this script was born.
#
# (c) 2012, 2013 Sudhi Herle <sw at herle.net>
# License: GPLv2
#



# Name for launchd 
FNAME=net.herle.tuntaposx

me=`id -u`
if [ $me -ne 0 ]; then
    echo "$0: Need root privilege to run; switching to dry-run mode .."
    e=echo
fi

#set -x

usage() {
    cat 1>&2 <<EOF1
Usage: $0 start|stop|install

start: Loads the tun/tap kext module
stop: Unloads the tun/tap kext module
install: Creates a system startup file in /System/Library/LaunchDaemons/$FNAME.plist
EOF1

    exit 1

}


maybe_load() {
    local mod=$1
    local bn=`basename $mod .kext`
    local z=`kextstat | egrep "\.$bn " | wc -l`
    if [  $z -eq 0 ]; then
        $e kextload $mod
    else
        echo "$bn already loaded!"
    fi
    return 0
}

kload() {

    maybe_load /opt/local/Library/Extensions/tun.kext
    maybe_load /opt/local/Library/Extensions/tap.kext
    return 0
}

kunload() {
	$e kextunload /opt/local/Library/Extensions/tap.kext
    $e kextunload /opt/local/Library/Extensions/tun.kext
    return 0
}



# Installs a startup service
install_service() {
    local idir=/System/Library/LaunchDaemons
    local bn=`basename $0`
    local prog=/usr/sbin/$bn

    if [ $me -ne 0 ]; then
        idir=/tmp/$bn
        mkdir -p $idir
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

    $e cp $0 $prog
    $e chmod a+rx,og-w $prog
    $e chmod 0644 $file

    echo "Installed to $file and $prog .."

    # Now, manually load the service - so that launchctl knows about
    # this
    # $e launchctl load -F $file
    return 0
}


if [ -z "$1" ]; then
    usage
    exit 1
fi


case $1 in
    start)
        echo "Loading tun/tap OS X drivers .."

        kload;

        ;;

    stop)
        echo "Unloading tun/tap OS X drivers .."
        kunload;
        ;;

    restart)
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
