#! /bin/bash

me=`id -u`
if [ $me -ne 0 ]; then
    exec sudo $0
fi
#e=echo

$e dd if=/dev/urandom of=/dev/rdisk0 bs=1024 count=1048576
