#ifndef MAPS_H
#define MAPS_H

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

#include "balancer_structs.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct datarec));
    __uint(max_entries, XDP_ACTION_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct backend);
    __uint(max_entries, 5);
} backend_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, __u8);
    __uint(max_entries, BACKENDS_MAX);  
} ip_to_index_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow);
    __uint(max_entries, CONN_MAX);
} packet_flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct loadbalancer));
    __uint(max_entries, 1);
} lb_metadata SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct egress));
    __uint(max_entries, 2);
} egress_metadata SEC(".maps");

#endif