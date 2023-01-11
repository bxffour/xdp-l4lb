#include <linux/types.h>
#include <linux/ip.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "balancer_structs.h"

__attribute__((__always_inline__)) static inline
__u16 csum_fold_helper(__u64 csum)
{
  int i;
#pragma unroll
  for(i = 0; i < 4; i++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }

  return ~csum; 
}

__attribute__((__always_inline__)) static inline
__u16 iphdr_csum(struct iphdr* iph)
{
  iph->check = 0;
  __u64 csum = bpf_csum_diff(0, 0, (__be32*)iph, sizeof(struct iphdr), 0);
  return csum_fold_helper(csum);
}

__attribute__((__always_inline__)) static inline
void update_csum(__u64* csum, __be32 old_addr, __be32 new_addr)
{
  *csum = ~*csum;
  *csum = *csum & 0xffff;

  __u32 tmp;
  tmp = ~old_addr;
  *csum += tmp;

  *csum += new_addr;

  *csum = csum_fold_helper(*csum);
}