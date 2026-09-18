#!/bin/bash
/home/brego/Documents/Uni/Tesi/industryTargetsAlpha/coredns_1.14.3_linux_amd64/coredns -conf /home/brego/Documents/Uni/Tesi/industryTargetsAlpha/coredns_1.14.3_linux_amd64/Corefile &
PID=$!
sleep 1
dnsperf -s 127.0.0.1 -p 1053 -d /home/brego/Documents/Uni/Tesi/industryTargetsAlpha/coredns_1.14.3_linux_amd64/queries.txt -c 100 -n 50000 > dnsperf.out
kill $PID
cat dnsperf.out
