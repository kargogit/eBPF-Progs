// write_counter_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Minimal context for sys_enter_* tracepoints */
struct trace_event_raw_sys_enter {
    unsigned long args[6];
};

/* Per-CPU stats (one entry, indexed by key=0) */
struct datarec {
    __u64 calls;   // Number of sys_write entries
    __u64 bytes;   // Sum of requested bytes (args[2])
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct datarec));
    __uint(max_entries, 1);
} stats_map SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int write_counter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    struct datarec *rec;

    rec = bpf_map_lookup_elem(&stats_map, &key);
    if (!rec)
        return 0;

    rec->calls++;
    rec->bytes += ctx->args[2];  // args[2] = count parameter (requested bytes)

    return 0;
}

char _license[] SEC("license") = "GPL";
