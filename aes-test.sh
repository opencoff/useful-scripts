#! /usr/bin/env bash

# Self tests for aes.py
# Author: Sudhi Herle
# License: Public Domain

TMP=$HOME/tmp/aes
AES=./aes.py
[ -n "$PYTHON" ] && AES="$PYTHON $AES"
#AES='python3.4 ./aes.py'

mkdir -p $TMP || exit 1

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
    #set -x
    local sz=$1; shift
    local bsiz=$1; shift

    [ -n "$bsiz" ] && bsiz="-B $bsiz"

    local inf=${TMP}/in$sz
    local enc=${TMP}/enc$sz
    local dec=${TMP}/dec$sz

    if [ $sz -gt 0 ]; then
        dd if=/dev/urandom of=$inf bs=$sz count=1 2>/dev/null
    else
        touch $inf
    fi

    echo "File size $sz:"

    begin "  regular file I/O ..."
    FX=abcdef $AES -k FX $bsiz encrypt $inf -o $enc || exit 1
    FX=abcdef $AES -k FX $bsiz test    $enc         || exit 1
    FX=abcdef $AES -k FX $bsiz decrypt $enc -o $dec || exit 1
    xverify $inf $dec || exit 1

    begin "  streaming I/O ..."
    cat $inf | FX=abcdef $AES -k FX $bsiz encrypt | cat > $enc
    [ $? -ne 0 ] && end Fail && exit 1

    cat $enc | FX=abcdef $AES -k FX $bsiz decrypt | cat > $dec
    [ $? -ne 0 ] && end Fail && exit 1
    xverify $inf $dec || exit 1

    begin "  inplace ..."
    cp $inf $enc
    FX=abcdef $AES -k FX $bsiz encrypt $enc -o $enc || exit 1

    cp $enc $dec
    FX=abcdef $AES -k FX $bsiz decrypt $dec -o $dec || exit 1
    xverify $inf $dec || exit 1


    rm -f $inf $enc $dec
}

# Full suite of functional tests
basic() {
    #set -x
    local sz=$(randsz)
    local inf=${TMP}/in$sz
    local enc=${TMP}/enc$sz
    local dec=${TMP}/dec$sz
    local enc2=${enc}.2
    local szskip=$(( $sz / 2 ))
    local badcount=$(( $sz / 4 ))
    local bsize=$(( $sz / 2 ))

    dd if=/dev/urandom of=$inf bs=$sz count=1 2>/dev/null || exit 1

    echo "Basic tests with size $sz .."
    begin "  basic functions ..."
    FX=abcdef $AES -k FX encrypt $inf -o $enc || exit 1
    FX=abcdef $AES -k FX test    $enc         || exit 1
    FX=abcdef $AES -k FX decrypt $enc -o $dec || exit 1
    xverify $inf $dec || exit 1

    begin "  basic functions (bufsize $bsize) ..."
    FX=abcdef $AES -k FX -B $bsize encrypt $inf -o $enc || exit 1
    FX=abcdef $AES -k FX -B $bsize test    $enc         || exit 1
    FX=abcdef $AES -k FX -B $bsize decrypt $enc -o $dec || exit 1
    xverify $inf $dec || exit 1

    # Bad password should fail
    FX=abcxyz $AES -k FX test    $enc         2>/dev/null && end Fail && exit 1

    # Corrupted enc file should fail
    cp $enc $enc2 || exit 1
    dd if=/dev/urandom of=$enc2 count=1 bs=$(($szskip * 2)) \
        seek=$szskip conv=notrunc 2>/dev/null  || exit 1
    FX=abcdef $AES -k FX test    $enc2          2>/dev/null && end Fail && exit 1

    begin "  inplace ..."
    cp $inf $enc
    FX=abcdef $AES -k FX encrypt $enc -o $enc || exit 1

    cp $enc $dec
    FX=abcdef $AES -k FX decrypt $dec -o $dec || exit 1
    xverify $inf $dec || exit 1

    begin "  stream input and output ..."
    cat $inf | FX=abcdef $AES -k FX encrypt | cat > $enc
    [ $? -ne 0 ] && end Fail && exit 1

    cat $enc | FX=abcdef $AES -k FX decrypt | cat > $dec
    [ $? -ne 0 ] && end Fail && exit 1
    xverify $inf $dec || exit 1

    rm -f $inf $enc $dec $enc2

}

# Generate random ints between x and y
randsz() {
    local x=78329
    local y=900000
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


trap "rm -rf $TMP; exit 0" INT TERM QUIT

echo "Testing $AES .."
basic

# Test various sizes
for s in 0 1 2 3 4 8 16 128 512 4096 16384 1048576
do
    testsz $s
done

# Test random sizes
n=8
while [ $n -gt 0 ]; do
    n=$(( $n - 1 ))
    sz=$(randsz)
    testsz $sz $(( $sz / 8 ))
done

