#!/bin/sh
#
# Creates a disk image (dmg) on Mac OS X from the command line.
#
# Sudhi Herle <sudhi-at-herle-net>
# License: BSD
#
# usage:
#    mkdmg <volname> <vers> <srcdir>
#
# Where <volname> is the name to use for the mounted image, <vers> is the version
# number of the volume and <srcdir> is where the contents to put on the dmg are.
#
# The result will be a file called <volname>-<vers>.dmg

if [ $# != 3 ]; then
 echo "usage: mkdmg.sh volname vers srcdir"
 exit 0
fi

VOL="$1"
VER="$2"
FILES="$3"

DMG="tmp-$VOL.dmg"

# create temporary disk image and format, ejecting when done
SIZE=`du -sk ${FILES} | sed -n '/^[0-9]*/s/([0-9]*).*/1/p'`
SIZE=$((${SIZE}/1000+1))
hdiutil create "$DMG" -megabytes ${SIZE} -ov -type UDIF
DISK=`hdid "$DMG" | sed -ne ' /Apple_partition_scheme/ s|^/dev/([^ ]*).*$|1|p'`
newfs_hfs -v "$VOL" /dev/r${DISK}s2
hdiutil eject $DISK

# mount and copy files onto volume
hdid "$DMG"
cp -R "${FILES}"/* "/Volumes/$VOL"
hdiutil eject $DISK

# convert to compressed image, delete temp image
rm -f "${VOL}-${VER}.dmg"
hdiutil convert "$DMG" -format UDZO -o "${VOL}-${VER}.dmg"
rm -f "$DMG"

