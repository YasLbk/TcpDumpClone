#!/bin/bash
for filename in *.pcap; do
    echo log1_$filename
    ../analyseur -v1 -o $filename > alog1_$filename
    ../analyseur -v2 -o $filename > alog2_$filename
    ../analyseur -v3 -o $filename > alog3_$filename

done