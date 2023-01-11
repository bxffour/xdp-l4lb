# syntax=docker/dockerfile:1

FROM rockylinux:9-minimal

RUN microdnf -y update
RUN microdnf -y install lsof
RUN microdnf -y install tcpdump
RUN microdnf -y install socat
RUN microdnf -y install nmap
RUN microdnf -y install iproute
RUN microdnf -y install iputils
RUN microdnf -y install net-tools
RUN microdnf -y install perf
RUN microdnf -y install procps-ng
RUN microdnf -y install traceroute
RUN microdnf -y install ethtool