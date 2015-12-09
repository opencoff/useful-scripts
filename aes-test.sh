#! /bin/bash

# Self tests for aes.py
# Author: Sudhi Herle
# License: Public Domain

AES=./aes.py

begin() {
    echo -n "$@"
}

end() {
    echo "$@"
}

xverify() {
    local inf=$1
    local dec=$2

    local a=`md5sum $inf| awk '{print $1}'`
    local b=`md5sum $dec| awk '{print $1}'`
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
    FX=abcdef $AES -e -k FX $inf -o $enc
    FX=abcdef $AES -d -k FX $enc -o $dec
    xverify $inf $dec

    begin "Testing inplace $sz .."
    cp $inf $enc
    FX=abcdef $AES -e -k FX $enc -o $enc

    cp $enc $dec
    FX=abcdef $AES -d -k FX $dec -o $dec
    xverify $inf $dec


    begin "Testing stdio $sz .."
    FX=abcdef $AES -e -k FX < $inf > $enc
    FX=abcdef $AES -d -k FX < $enc > $dec
    xverify $inf $dec


    rm -f $inf $enc $dec
}



# Test various sizes
for s in 0 1 2 3 4 8 16 128 512 4096 16384 1048576
do
    testsz $s
done


