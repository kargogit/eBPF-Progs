// cgroup_skb_counter_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "cgroup_skb_counter.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct datarec);
} counts SEC(".maps");

#define INGRESS_KEY 0
#define EGRESS_KEY  1

SEC("cgroup_skb/ingress")
int count_ingress(struct __sk_buff *skb)
{
    __u32 key = INGRESS_KEY;
    struct datarec *rec = bpf_map_lookup_elem(&counts, &key);
    if (rec) {
        rec->packets++;
        rec->bytes += skb->len;
    }
    return 1;
}

SEC("cgroup_skb/egress")
int count_egress(struct __sk_buff *skb)
{
    __u32 key = EGRESS_KEY;
    struct datarec *rec = bpf_map_lookup_elem(&counts, &key);
    if (rec) {
        rec->packets++;
        rec->bytes += skb->len;
    }
    return 1;
}

char _license[] SEC("license") = "GPL";
