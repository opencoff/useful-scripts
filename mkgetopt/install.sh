#! /bin/sh

#
# Simple installer for Unix-like systems.
#

Z=`basename $0`
os=`uname`
me=`id -u`

warn() {
    echo "$Z: $@" 1>&2
}

die() {
    echo "$Z: $@" 1>&2
    exit 1
}

e=
if [ $me -ne 0 ]; then
    warn "Not root; running in dry-run mode .."
    e=echo
fi


dest=
case $os in
    Darwin)
        for d in /opt/local /usr/local; do
            if [ -d $d ]; then
                dest=$d
                break
            fi
        done
        ;;

    *BSD)
        dest=/usr/local
        ;;

    Linux*)
        dest=/usr/local
        ;;

    *)
        die "I don't know what to do on $os"
        ;;
esac
if [ "x$dest" = "x" ]; then
    die "Dest dir not known for $os"
fi
   
$e mkdir -p $dest/bin $dest/man/man1

$e cp mkgetopt.py $dest/bin/
gzip -9 -c  mkgetopt.1  > /tmp/a.gz
$e cp /tmp/a.gz $dest/man/man1/mkgetopt.py.1.gz
rm -f /tmp/a.gz
