#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/bpf.h> 
#include <bpf/bpf_endian.h>
#include <stdbool.h>

#include "balancer_structs.h"
#include "encap.h"
#include "maps.h"

__attribute__((__always_inline__)) static inline bool mac_is_equal(
        unsigned char recv_mac[ETH_ALEN],
        unsigned char lb_mac[ETH_ALEN])
{
    int i;
    
    for (i = 0; i < ETH_ALEN; i++) {
        if (recv_mac[i] != lb_mac[i]) {
            return false;
        } 
    }
    
    return true;
}

__attribute__((__always_inline__)) static inline
void process_mac(
    struct ethhdr* eth, 
    unsigned char smac[ETH_ALEN],
    unsigned char dmac[ETH_ALEN],
    struct flow* flow)
{
    memcpy(flow->smac, eth->h_source, ETH_ALEN);
    
    memcpy(eth->h_source, smac, ETH_ALEN);
    memcpy(eth->h_dest, dmac, ETH_ALEN);
}

__attribute__((__always_inline__)) static inline
void process_ip(
    struct iphdr* iph,
    __be32 saddr,
    __be32 daddr,
    struct flow* flow)
{
    flow->daddr = iph->daddr;
    flow->saddr = iph->saddr;
    flow->proto = iph->protocol;
    
    rewrite_ip4hdr(iph, saddr, daddr);   
}

__attribute__((__always_inline__)) static inline
void process_tcp(
    struct tcphdr* tcp,
    __u16 sport,
    __u16 dport,
    struct flow* flow)
{
    flow->sport = tcp->source;
    flow->dport = tcp->dest;
    
    tcp->source = sport;
    tcp->dest   = dport;
}

__attribute__((__always_inline__)) static inline
void process_udp(
    struct udphdr* udp,
    __u16 sport,
    __u16 dport,
    struct flow* flow)
{
    flow->sport = udp->source;
    flow->dport = udp->dest;
    
    udp->source = sport;
    udp->dest   = dport;
}

__attribute__((__always_inline__)) static inline
bool get_backend(struct backend** backend_ptr)
{
    __u32 backend_key = 0;
    struct backend* backend;

    backend = bpf_map_lookup_elem(&backend_map, &backend_key);
    if (!backend) {
        return false;
    }
    
    *backend_ptr = backend;
    
    return true;
}

__attribute__((__always_inline__)) static inline
bool get_loadbalancer(struct loadbalancer** lb_ptr)
{
    __u32 lb_key = 0;
    struct loadbalancer *lb;

    lb = bpf_map_lookup_elem(&lb_metadata, &lb_key);
    if (!lb) {
        return false;
    }

    *lb_ptr = lb;

    return true;
}

__attribute__((__always_inline__)) static inline
bool store_flow_metadata(struct flow_key* f_key, struct flow* flow)
{
    void* val;
    val = bpf_map_lookup_elem(&packet_flow_map, f_key);
    if (!val){
        if (0 > bpf_map_update_elem(&packet_flow_map, f_key, flow, BPF_NOEXIST)) {
            return false;
        }
    }
    
    return true;
}

__attribute__((__always_inline__)) static inline
int process_ingress_traffic(void* data, void* data_end)
{   
    struct ethhdr* eth = data;
    struct iphdr*  iph;
    struct udphdr* udp;
    struct tcphdr* tcp;
        
    struct flow flow = {};
    struct flow_key f_key = {};
    
    __u64 off;
    off = sizeof(struct ethhdr);
    if (data + off > data_end) {
        return XDP_ABORTED;
    }

    struct loadbalancer* lb;
    if (!get_loadbalancer(&lb)) {
        return XDP_ABORTED;
    }
    
    struct backend* backend;
    if (!get_backend(&backend)) {
        return XDP_ABORTED;
    }
    
    if (!mac_is_equal(eth->h_dest, lb->mac)) {
        return XDP_ABORTED;
    }
    
    process_mac(eth, lb->mac, backend->mac, &flow);
    
    iph = data + off;
    if (iph + 1 > data_end) {
        return XDP_ABORTED;
    }
    
    if (iph->daddr != lb->ip) {
        return XDP_ABORTED;
    }
    
    process_ip(iph, lb->ip, backend->ipv4, &flow);
        
    __u16 sport = bpf_htons(4004);
    __u16 dport = bpf_htons(5005);
    
    off += sizeof(struct iphdr);
    if (iph->protocol == IPPROTO_TCP) {
        tcp = data + off;
        if (tcp + 1 > data_end) {
            return XDP_ABORTED;
        }
        
        process_tcp(tcp, sport, dport, &flow);
        f_key.port = tcp->source;
    } else if (iph->protocol == IPPROTO_UDP) {
        udp = data + off;
        if (udp + 1 > data_end) {
            return XDP_ABORTED;
        }
        
        process_udp(udp, sport, dport, &flow);
        f_key.port = udp->source;
    } else {
        return XDP_DROP;
    }
    
    f_key.backend_addr = backend->ipv4;
    f_key.protocol = iph->protocol;
    
    if (!store_flow_metadata(&f_key, &flow)) {
        return XDP_DROP;
    }
    
    return XDP_TX;
}