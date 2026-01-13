// xdp_counter_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct datarec));
    __uint(max_entries, 1);
} xdp_stats_map SEC(".maps");

SEC("xdp")
int xdp_counter(struct xdp_md *ctx)
{
    __u32 key = 0;
    struct datarec *rec;

    rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if (!rec)
        return XDP_PASS;

    rec->rx_packets++;
    rec->rx_bytes += ctx->data_end - ctx->data;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
