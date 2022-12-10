#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

__attribute__((__always_inline__)) static inline 
__u16 csum_fold_helper(__u64 csum)
{
  int i;
  #pragma unroll
  for (i = 0; i < 4; i++) {
    if (csum >> 16) 
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

__attribute__((__always_inline__)) static inline void
ipv4_csum(void* data_start, int data_size, __u64* csum)
{
  *csum = bpf_csum_diff(0, 0, (__be32*)data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__)) static inline void
ipv4_csum_inline(void* iph, __u64*csum)
{
  __u16* next_iph_u16 = (__u16*)iph;
  
  #pragma clang loop unroll(full)
  for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
    *csum = *next_iph_u16++;
  }
  
  *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__)) static inline 
__u16 tcph_csum_diff(__u16 seed, struct tcphdr* tcph_new, struct tcphdr* tcph_old)
{
  __u32 csum, size = sizeof(struct tcphdr);
  
  csum = bpf_csum_diff((__be32*)tcph_old, size, (__be32*)tcph_new, size, seed);
  return csum_fold_helper(csum);
}

__attribute__((__always_inline__)) static inline 
__u16 udph_csum_diff(__u16 seed, struct udphdr* udph_new, struct udphdr* udph_old)
{
  __u32 csum, size = sizeof(struct udphdr);
  
  csum = bpf_csum_diff((__be32*)udph_old, size, (__be32*)udph_new, size, seed);
  return csum_fold_helper(csum);
}
