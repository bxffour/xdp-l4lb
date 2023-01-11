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

__attribute__((__always_inline__)) static inline void print_mac(
        unsigned char mac[ETH_ALEN])
{
    int i;
    
    for (i = 0; i < ETH_ALEN; i++) {
        __bpf_printk("%x", mac[i]);
    }
}

__attribute__((__always_inline__)) static inline
void process_mac(
    struct ethhdr* eth, 
    unsigned char smac[ETH_ALEN],
    unsigned char dmac[ETH_ALEN],
    struct flow* flow)
{
    // memcpy(flow->smac, eth->h_source, ETH_ALEN);
    
    memcpy(eth->h_source, smac, ETH_ALEN);
    memcpy(eth->h_dest, dmac, ETH_ALEN);
}

__attribute__((__always_inline__)) static inline
bool get_egress(struct egress** egress_ptr)
{
    __u32 egress_key = 0;
    struct egress* egress;

    egress = bpf_map_lookup_elem(&egress_metadata, &egress_key);
    if (!egress) {
        return false;
    }

    *egress_ptr = egress;
    return true;
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
bool decap(struct xdp_md* xdp, void** data_end, void** data) {
    struct ethhdr* old_eth;
    struct ethhdr* new_eth;

    old_eth = *data;
    new_eth = *data + sizeof(struct iphdr);

    memcpy(new_eth->h_source, old_eth->h_source, ETH_ALEN);
    memcpy(new_eth->h_dest, old_eth->h_dest, ETH_ALEN);
    new_eth->h_proto = BE_ETH_P_IP;

    if (bpf_xdp_adjust_head(xdp, (int)sizeof(struct iphdr))) {
        return false;
    }

    *data = (void*)(long)xdp->data;
    *data_end = (void*)(long)xdp->data_end;
    return true;
}

__attribute__((__always_inline__)) static inline
void set_ethhdr(struct ethhdr* new_eth, __u8 mac[ETH_ALEN], struct backend* be, __u16 h_proto)
{
   memcpy(new_eth->h_source, mac, ETH_ALEN);
   memcpy(new_eth->h_dest, be->mac, ETH_ALEN);
   new_eth->h_proto = h_proto;
}
