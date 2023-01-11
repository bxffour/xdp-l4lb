#!/bin/bash

ip addr add 172.30.0.10/24 brd + dev eth0
/app/xdplb start --ingress eth0 --egress eth0 -c /app/config.yml --section xdp.decap -m skb &
/app/ping-server 
