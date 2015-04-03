#! /bin/bash

#
# Tweak OS X to not have atime updates on its file systems.
# (c) 2012, 2013 Sudhi Herle <sw at herle.net>
# License: GPLv2
#

# Notes:
#   - Running this script once sets the noatime option on /
#   - When invoked as "$0 install", it will set itself up
#     as a system startup item to set this at every boot

FNAME=net.herle.noatime

me=`id -u`
if [ $me -ne 0 ]; then
    echo "$0: Need root privilege to run; switching to dry-run mode .."
    e=echo
fi

#set -x

usage() {
    cat 1>&2 <<EOF1
Usage: $0 start|install

start:   Set noatime on /
install: Creates a system startup file in /Library/LaunchDaemons/$FNAME.plist
EOF1

    exit 1

}


# Installs a startup service
install_service() {
    local rdir=/Library/LaunchDaemons

    if [ $me -ne 0 ]; then
        rdir=/tmp
    fi

    local file=$rdir/${FNAME}.plist
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

    <!-- We only mount / with the noatime option -->
    <key>ProgramArguments</key>
    <array>
        <string>mount</string>
        <string>-uvw</string>
        <string>-o</string>
        <string>noatime</string>
        <string>/</string>
    </array>

</dict>
</plist>
EOF2

    $e chmod 0644 $file

    return 0
}


if [ -z "$1" ]; then
    usage
    exit 1
fi


case $1 in
    start)
        echo "Setting noatime on /"
        $e mount -uvw -o noatime /

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
