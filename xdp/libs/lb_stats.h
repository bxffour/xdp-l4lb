#ifndef LB_STATS_H
#define LB_STATS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "maps.h"

static __always_inline __u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
    // validate action
    if (action >= XDP_ACTION_MAX) {
        return XDP_ABORTED;
    }

    // lookup action in map
    struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
    if (!rec) {
        return XDP_ABORTED;
    }

    // increase packets and bytes
    rec->rx_packets += 1;
    rec->rx_bytes += (ctx->data_end - ctx->data);

    return action;
}

#endif