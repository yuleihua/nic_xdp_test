#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") net_xdp_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 64,  /* Assume netdev has no more than 64 queues */
};

struct bpf_map_def SEC("maps") net_xdp_stats_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = 64,
};

struct bpf_map_def SEC("maps") net_xdp_nq_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(unsigned int),
  .value_size = sizeof(__u16),
  .max_entries = 1,
};

SEC("proto_net_xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	unsigned int offset = 0;
    __u32 *pkt_count = 0;
    __u16 *num_queues = 0;

    num_queues = bpf_map_lookup_elem(&net_xdp_nq_map, &offset);
    if (!num_queues) {
        return XDP_PASS;
    } else {
        offset = ctx->rx_queue_index % *num_queues;
    }

//    pkt_count = bpf_map_lookup_elem(&net_xdp_stats_map, &offset);
//    (*pkt_count)++;

    return bpf_redirect_map(&net_xdp_map, offset, 0);
}

char _license[] SEC("license") = "GPL";
