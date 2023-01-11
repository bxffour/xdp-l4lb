#!/bin/sh

ethtool -K eth0 tx off
ip addr add 172.20.0.10 dev eth0
tcpdump -w /pcap/lb.pcap -i eth0 -vv 'net 172.20.0.0/24' &
/app/xdplb start -dev eth0 --egress eth1 -c /app/config.yml --section xdp.loadbalancer --arp /app/arp -m skb