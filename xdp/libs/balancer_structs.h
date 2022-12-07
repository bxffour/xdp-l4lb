#ifndef BALANCER_STRUCTS_H
#define BALANCER_STRUCTS_H

#include <linux/types.h>
#include <linux/if_ether.h>

#ifndef  memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#undef bpf_printk
#define bpf_printk(fmt, ...)                  \
({                                            \
   static const char ____fmt[] = fmt;         \
   bpf_trace_printk(____fmt, sizeof(____fmt), \
                ##__VA_ARGS__);               \
})

#define SET_BIT(BF, N) BF |= ((__u8)0x01 << N)
#define CLR_BIT(BF, N) BF &= ~((__u8)0x01 << N)
#define IS_BIT_SET(BF, N) ((BF, N) & 0x01)

#define BE_ETH_P_IP 8
#define BE_ETH_P_IPV6 56710

#undef  AF_INET
#define AF_INET 2

#undef  AF_INET6
#define AF_INET6 10

#define VLAN_MAX_DEPTH 2

#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)

#define PCKT_FRAGMENTED 65343

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#define CONN_MAX 10
#define BACKENDS_MAX 10

#define F_IPV6 (1<<0)
#define F_ICMP (1<<1)

struct loadbalancer {
    __be32   ip;
    unsigned char mac[ETH_ALEN];
    __u32    index;
}__attribute__((__packed__));

struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

struct backend {
    __be32 ipv4;
    unsigned char mac[ETH_ALEN];
}__attribute__((__packed__));

struct flow {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8  proto;
    __u8  flags;
    unsigned char smac[ETH_ALEN];
};

struct flow_key {
    __be32 backend_addr;
    __u16  port; // sport egress, dport ingress
    __u8   protocol;
};
#endif
