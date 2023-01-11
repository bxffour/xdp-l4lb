#!/bin/sh

echo_stderr ()
{
	echo "$@" >&2
}

SERVER_NAME=$1

if [[ -z $SERVER_NAME ]]
then
	echo_stderr "USAGE $0 <fname.log>"
	exit 1
fi

/vagrant/server > /vagrant/$SERVER_NAME.log 2>&1 &
# tcpdump -i eth1 -s 0 -w /vagrant/pcap/$SERVER_NAME.pcap -vv 'net 172.20.0.0/24' &
