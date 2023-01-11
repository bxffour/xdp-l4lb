#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/udp.h>
#include <linux/perf_event.h>

#include "libs/balancer_structs.h"
#include "libs/balancer_helpers.h"
#include "libs/csum_helpers.h"
#include "libs/lb_stats.h"
#include "libs/maps.h"

__attribute__((__always_inline__)) static inline
__u32 process_packet(struct xdp_md* xdp, __u64 off)
{
   void* data     = (void*)(long)xdp->data;
   void* data_end = (void*)(long)xdp->data_end;

   struct ethhdr* old_eth;
   struct ethhdr* new_eth;
   struct iphdr*  iph;
   struct iphdr   be_tnl;
   struct udphdr* udp;

   struct flow flow = {};
   struct backend* backend;
   struct loadbalancer* lb;
   struct egress* eg;

   __u16 payload_len;
   __u16* next_iph_u16;
   __u32 csum = 0;
   
   iph = data + off;
   if (iph + 1 > data_end) {
      return XDP_ABORTED;
   }

   if (iph->ihl != 5) {
      return XDP_ABORTED;
   }
   
   if (iph->protocol != IPPROTO_UDP) {
      return XDP_PASS;
   }

   payload_len = bpf_ntohs(iph->tot_len);
   off += sizeof(*iph);

   if (iph->frag_off & PCKT_FRAGMENTED) {
      return XDP_ABORTED;
   }

   flow.saddr = iph->saddr;

   udp = data + off;
   if (udp + 1 > data_end) {
      return XDP_ABORTED;
   }

   flow.port16[0] = udp->source;
   flow.port16[1] = udp->dest;

   if (udp->dest != bpf_htons(7000)) {
      return XDP_PASS;
   }

   if (!get_backend(&backend)) {
      return XDP_ABORTED;
   }

   if (!get_loadbalancer(&lb)) {
      return XDP_ABORTED;
   }

   if (!get_egress(&eg)) {
      return XDP_ABORTED;
   }

   if (iph->saddr == lb->ip) {
      return XDP_PASS;
   }

   if (bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct iphdr))) {
      return XDP_ABORTED;
   }

   data = (void*)(long)xdp->data;
   data_end = (void*)(long)xdp->data_end;

   new_eth = data;
   old_eth = data + sizeof(*iph);

   if (new_eth + 1 > data_end || old_eth + 1 > data_end || iph + 1 > data_end) {
      return XDP_ABORTED;
   }

   set_ethhdr(new_eth, eg->mac, backend, BE_ETH_P_IP);

   be_tnl.version = 4;
   be_tnl.ihl = sizeof(*iph) >> 2;
   be_tnl.frag_off = 0;
   be_tnl.protocol = IPPROTO_IPIP;
   be_tnl.check = 0;
   be_tnl.id = 0;
   be_tnl.tos = 0;
   be_tnl.tot_len = bpf_htons(payload_len + sizeof(*iph));
   be_tnl.saddr = eg->ip;
   be_tnl.daddr = backend->ipv4;
   be_tnl.ttl = 8;

   next_iph_u16 = (__u16*)&be_tnl;
   #pragma clang loop unroll(full)
   for (int i = 0; i < (int)sizeof(*iph) >> 1; i++) {
      csum += *next_iph_u16++;
   }
   be_tnl.check = ~((csum & 0xffff) + (csum >> 16));

   iph = data + sizeof(*new_eth);
   *iph = be_tnl;

   __bpf_printk("dest mac -> %x:%x:%x", new_eth->h_dest[3], new_eth->h_dest[4], new_eth->h_dest[5]);
   return bpf_redirect(eg->index, 0);   
}

__attribute__((__always_inline__)) static inline
__u32 handle_ipip(struct xdp_md* xdp, void** data, void** data_end)
{
   if (*data + sizeof(struct iphdr) + sizeof(struct ethhdr) > *data_end) {
      return XDP_ABORTED;
   }

   if (!decap(xdp, data_end, data)) {
      return XDP_ABORTED;
   }
   __bpf_printk("decapped the hell outta this bitch");
   return XDP_PASS;
}

SEC("xdp.pass")
int xdp_pass(struct xdp_md* xdp)
{
   __u32 action  = XDP_PASS;

out:
   return xdp_stats_record_action(xdp, action);
}

SEC("xdp.loadbalance")
int xdp_loadbalancer(struct xdp_md *xdp)
{
   void* data = (void*)(long)xdp->data;
   void* data_end = (void*)(long)xdp->data_end;
   struct ethhdr* eth = data;
   __u16 eth_proto;
   __u64 offset;

   __u32 action = XDP_PASS;

   offset = sizeof(struct ethhdr);
   if (data + offset > data_end) {
      action = XDP_ABORTED;
      goto out;
   }

   eth_proto = eth->h_proto;
   if (eth_proto == BE_ETH_P_IP) {
      action = process_packet(xdp, offset);
   }
   
out:
   return xdp_stats_record_action(xdp, action);
}

SEC("xdp.decapip")
int xdp_decap(struct xdp_md* xdp)
{
   void* data = (void*)(long)xdp->data;
   void* data_end = (void*)(long)xdp->data_end;

   struct ethhdr* eth = data;
   struct iphdr*  iph;

   __u64 off = sizeof(*eth);
   __u16 eth_proto;
   __u8  ip_proto;

   __u32 action = XDP_PASS;
   
   if (data + off > data_end) {
      action = XDP_ABORTED;
      goto out;
   }

   eth_proto = eth->h_proto;
   if (eth_proto != BE_ETH_P_IP) {
      action = XDP_PASS;
      goto out;
   }

   iph = data + off;
   if (iph + 1 > data_end) {
      action = XDP_ABORTED;
      goto out;
   }

   if (iph->protocol == IPPROTO_IPIP) {
      action = handle_ipip(xdp, &data, &data_end);
   }

out:
   return xdp_stats_record_action(xdp, action);
}

SEC("xdp.test")
int xdp_test(struct xdp_md *xdp)
{
   __u32 action = XDP_PASS;

   struct egress* val;
   __u32 key = 0;

   val = bpf_map_lookup_elem(&egress_metadata, &key);
   if (!val) {
      action = XDP_ABORTED;
      goto out;
   }

   __be32 ip = val->ip;

   __bpf_printk("egress Mac => %x:%x:%x", val->mac[3], val->mac[4], val->mac[5]);
   __bpf_printk("egress IP => %pI4", &ip);
   __bpf_printk("egress index => %d", val->index);
out:
   return xdp_stats_record_action(xdp, action);
}


char _license[] SEC("license") = "GPL";