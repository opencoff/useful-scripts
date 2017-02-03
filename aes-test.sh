#! /usr/bin/env bash

# Self tests for aes.py
# Author: Sudhi Herle
# License: Public Domain

AES=./aes.py
#AES='python3.4 ./aes.py'

uname=`uname`
case $uname in
    Linux) MD5=md5sum ;;
    Darwin|OpenBSD) MD5='md5 -q'    ;;

    *) echo "$0: Don't know how to do md5 on $uname" 1>&2
       exit 1
       ;;
esac

begin() {
    echo -n "$@"
}

end() {
    echo "$@"
}

xverify() {
    local inf=$1
    local dec=$2

    local a=`$MD5 $inf| awk '{print $1}'`
    local b=`$MD5 $dec| awk '{print $1}'`
    if [ $a != $b ]; then
        end "Fail"
    else
        end "OK"
    fi
    return 0
}

testsz() {
    local sz=$1; shift

    local inf=/tmp/in$sz
    local enc=/tmp/enc$sz
    local dec=/tmp/dec$sz

    if [ $sz -gt 0 ]; then
        dd if=/dev/urandom of=$inf bs=$sz count=1 2>/dev/null
    else
        touch $inf
    fi

    begin "Testing file $sz .."
    FX=abcdef $AES -e -k FX $inf -o $enc || exit 1
    FX=abcdef $AES -d -k FX $enc -o $dec || exit 1
    xverify $inf $dec || exit 1

    begin "Testing inplace $sz .."
    cp $inf $enc
    FX=abcdef $AES -e -k FX $enc -o $enc || exit 1

    cp $enc $dec
    FX=abcdef $AES -d -k FX $dec -o $dec || exit 1
    xverify $inf $dec || exit 1


    begin "Testing stdio $sz .."
    FX=abcdef $AES -e -k FX < $inf > $enc || exit 1
    FX=abcdef $AES -d -k FX < $enc > $dec || exit 1
    xverify $inf $dec || exit 1


    rm -f $inf $enc $dec
}

# Generate random ints between [100, 100000)
randsz() {
    local x=101
    local y=100000
    local r=$(( $y - $x + 1))
    local n=0

    while true; do
        n=$(( $RANDOM * $RANDOM ))
        n=$(( $n % $r ))
        n=$(( $x + $n ))
        if [ $n -gt 0 ]; then
            echo $n
            return 0
        fi
    done
}


trap 'exit 0' INT TERM QUIT

# Test various sizes
for s in 0 1 2 3 4 8 16 128 512 4096 16384 1048576
do
    testsz $s
done

# Test random sizes
n=8
while [ $n -gt 0 ]; do
    n=$(( $n - 1 ))
    testsz $(randsz)
done

