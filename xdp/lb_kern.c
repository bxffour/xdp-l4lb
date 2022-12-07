#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "libs/balancer_structs.h"
#include "libs/balancer_helpers.h"
#include "libs/lb_stats.h"
#include "libs/maps.h"


SEC("xdp.pass")
int xdp_pass(struct xdp_md *ctx)
{  
   return xdp_stats_record_action(ctx, XDP_PASS);
}

SEC("xdp.drop")
int xdp_drop(struct xdp_md *ctx)
{
   return xdp_stats_record_action(ctx, XDP_DROP);
}

SEC("xdp.abort")
int xdp_abort(struct xdp_md *ctx) {
   return xdp_stats_record_action(ctx, XDP_ABORTED);
}

SEC("xdp.loadbalance")
int xdp_loadbalancer(struct xdp_md *ctx)
{
   void* data = (void*)(long)ctx->data;
   void* data_end = (void*)(long)ctx->data_end;

   __u32 action;
   action = process_ingress_traffic(data, data_end);
         
out:
   return xdp_stats_record_action(ctx, action);
}

SEC("xdp.compare")
int xdp_compare(struct xdp_md *xdp)
{
   void *data = (void *)(long)xdp->data;
   void *data_end = (void *)(long)xdp->data_end;

   struct ethhdr* eth = data;
   // struct iphdr* iph;
   __u32 action = XDP_PASS;
   
   __u64 off = sizeof(struct ethhdr);
   if ((void*)eth + off > data_end) {
      action = XDP_ABORTED;
      goto out;
   }
   
   __u32 key = 0;
   struct loadbalancer* val;
   
   val = bpf_map_lookup_elem(&lb_metadata, &key);
   if (!val) {
      action = XDP_ABORTED;
      goto out;
   }
      
   if (!mac_is_equal(eth->h_dest, val->mac)) {
      action = XDP_DROP;
      goto out;
   }
         
out:
   return xdp_stats_record_action(xdp, action);
}


char _license[] SEC("license") = "GPL";