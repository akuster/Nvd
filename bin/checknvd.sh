#!/bin/bash

year=2002
end=2011

echo "Begin" > cve.lst
while [ $year -le  $end ]
	do
		echo "Checking $year"
		nvdcve -o vendor=linux -o prod=kernel -o start=2.6.10 -o yr=$year -w >> cve.lst
		year=$(($year +1))
done
