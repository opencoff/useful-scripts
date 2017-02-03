#! /bin/ksh

#
# Create and mount a ramfs disk for OS X
# (c) 2012, 2013 Sudhi Herle <sw at herle.net>
# License: GPLv2
#

# Theory:
#   - OS X has a light weight, in kernel disk image mounting tool
#   - Use this to create an in-kernel disk image in RAM
#   - man hdik, man newfs
#   - make a newfs on this disk image
#   - use union mount to overlay this on top of the mount point
#
# Notes:
#   - '$0 install' will turn this into a LaunchDaemon
#

#set -x

PATH=/sbin:/usr/sbin:/bin:/usr/bin:$PATH
export PATH

# >>>  Tunables <<<
# size of /tmp in MB
TMP_SIZE=1024

# size of /var/run in MB
VAR_RUN_SIZE=8


# Name for launchd 
FNAME=net.herle.ramfs

me=`id -u`
if [ $me -ne 0 ]; then
    echo "$0: Need root privilege to run; switching to dry-run mode .."
    e=echo
fi


usage() {
    cat 1>&2 <<EOF1
Usage: $0 start|install

start: Creates and mounts the ramfs
stop, restart: No op
install: Creates a system startup file in /Library/LaunchDaemons/$FNAME.plist
EOF1

    exit 1

}

mount_ramdisk() {
    typeset sz=$1     # Size is in MB
    typeset dest=$2

    # OS X likes sectors
    # sects = (MB * 1024 * 1024) / 512
    typeset sects=$(( $sz * 1024 * 2 ))

    typeset dev

    if [ $me -eq 0 ]; then
        dev=`hdik -drivekey system-image=yes -nomount ram://$sects`
        if [ $? -ne 0 ]; then
            return $?
        fi
    else
        $e hdik -drivekey system-image=yes -nomount ram://$sects
        dev=/dev/DRYRUN
    fi

    # We don't care about the journal.
    $e newfs_hfs -v "RAMFS_${sz}MB" $dev    || return 1

    # Grok the original perms and mode on the mountpoint
    eval `stat -s $dest`

    $e mount -t hfs -o noatime,nobrowse,union $dev $dest    || return 1

    # Replicate it on the new mount point
    $e chown $st_uid:$st_gid $dest
    $e chmod $st_mode $dest

    echo "Mounted $dev at $dest ($sz MB)"
    return 0
}


# Installs a startup service
install_service() {
    typeset idir=/Library/LaunchDaemons
    typeset bn=`basename $0`
    typeset prog=/etc/$bn

    if [ $me -ne 0 ]; then
        idir=/tmp/ramfs
        mkdir -p $idir
    fi

    typeset file=$idir/${FNAME}.plist

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

    <!-- Yosemite unmounts shit once the script completes. WTF. -->
    <key>KeepAlive</key>
    <dict>
        <key>PathState</key>
        <dict>
            <key>/private/tmp</key>
            <false/>

            <key>/var/run</key>
            <false/>
        </dict>
    </dict>

    <key>RunAtLoad</key>
    <true/>

    <key>ProgramArguments</key>
    <array>
        <string>$prog</string>
        <string>start</string>
    </array>

    <key>StandardErrorPath</key>
    <string>/var/log/$FNAME-err.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/$FNAME-out.log</string>

</dict>
</plist>
EOF2

    $e cp $0 $prog
    $e chmod a+rx,og-w $prog
    $e chmod 0644 $file

    echo "Installed to $file and $prog .."

    return 0
}


if [ -z "$1" ]; then
    usage
    exit 1
fi


case $1 in
    start)
        echo "Initializing RAM disk for /tmp and /var/run .."
        sleep 5
        mount_ramdisk $TMP_SIZE /private/tmp
        mount_ramdisk $VAR_RUN_SIZE   /var/run
        mount
        df -h
        ;;

    stop|restart)
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
