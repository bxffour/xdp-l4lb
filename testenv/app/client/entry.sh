#!/bin/bash

ethtool -K eth0 tx off 
while echo "ping" | socat -t 1 udp4:172.30.0.10:7000 - > out 2>&1; do sleep 1; done
