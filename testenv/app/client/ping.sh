#!/bin/bash

while echo "ping" | socat -t 1 udp4:172.20.0.10:7000 - > out 2>&1; do sleep 1; done