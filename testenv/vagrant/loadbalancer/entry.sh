#!/bin/bash

/vagrant/xdplb start --dev eth2 --egress eth1 -c /vagrant/config.yml --section xdp.loadbalancer -m skb > /tmp/out 2>&1 &
# tcpdump -i eth2 -nn -s 0 -w /vagrant/pcap/eth2.pcap -vv 'net 172.20.0.0/24' > /tmp/eth2dump 2>&1 &
# tcpdump -i eth1 -nn -s 0 -w /vagrant/pcap/eth2.pcap -vv 'net 172.20.0.0/24' > /tmp/eth1dump 2>&1 &
# tcpdump -i eth0 -nn -s 0 -w /vagrant/pcap/eth0.pcap -vv  > /tmp/eth0dump 2>&1 &
