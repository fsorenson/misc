#!/bin/bash

count=$1
let i=0
cd /var/tmp/test
while (( $i < $count ))
do
        ./testprogram &
        let i=i+1
done
