#include <linux/in.h>
#include <linux/ip.h>
#include <stdbool.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "csum_helpers.h"

__attribute__((__always_inline__)) static inline
void rewrite_ip4hdr(
		struct iphdr *iph,
		__be32 saddr,
		__be32 daddr)
{
	__u64 csum = 0;
	iph->check = 0;
	iph->saddr = saddr;
	iph->daddr = daddr;
	
	ipv4_csum(iph, sizeof(struct iphdr), &csum);
	iph->check = csum;
}

__attribute__((__always_inline__)) static inline
void rewrite_tcphdr(
		struct tcphdr* tcp,
		__u16 sport,
		__u16 dport)
{
	__u64 csum = 0;
	tcp->source = sport;
	tcp->dest = dport;
}