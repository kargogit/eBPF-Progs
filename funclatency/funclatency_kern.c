// funclatency_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_SLOT 34  // Covers up to ~17 billion µs (enough for any practical function)

// Helper functions to replace __builtin_clzll
static __always_inline int fls32(__u32 x)
{
    int r = 32;

    if (!x)
        return 0;
    if (!(x & 0xffff0000u)) {
        x <<= 16;
        r -= 16;
    }
    if (!(x & 0xff000000u)) {
        x <<= 8;
        r -= 8;
    }
    if (!(x & 0xf0000000u)) {
        x <<= 4;
        r -= 4;
    }
    if (!(x & 0xc0000000u)) {
        x <<= 2;
        r -= 2;
    }
    if (!(x & 0x80000000u)) {
        x <<= 1;
        r -= 1;
    }
    return r;
}

static __always_inline int fls64(__u64 x)
{
    __u32 h = x >> 32;
    if (h)
        return fls32(h) + 32;
    return fls32(x);
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} execs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_SLOT + 1);
    __type(key, __u32);
    __type(value, __u64);
} hist SEC(".maps");

SEC("kprobe")
int trace_entry(struct pt_regs *ctx)
{
    __u32 tid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe")
int trace_ret(struct pt_regs *ctx)
{
    __u32 tid = bpf_get_current_pid_tgid();
    __u64 *tsp = bpf_map_lookup_elem(&start, &tid);
    if (!tsp)
        return 0;

    __u64 delta_ns = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start, &tid);

    // Increment total execution count
    __u32 zero = 0;
    __u64 *totalp = bpf_map_lookup_elem(&execs, &zero);
    if (totalp)
        *totalp += 1;

    // Compute histogram slot
    __u32 slot = 0;
    if (delta_ns >= 1000) {
        __u64 delta_us = delta_ns / 1000;

        // REPLACED LINE: slot = 63 - __builtin_clzll(delta_us) + 1;
        // fls64 returns the position of the most significant bit (1-based),
        // which is equivalent to log2(x) + 1.
        slot = fls64(delta_us);

        if (slot > MAX_SLOT)
            slot = MAX_SLOT;
    }

    // Increment histogram slot
    __u64 *slotp = bpf_map_lookup_elem(&hist, &slot);
    if (slotp)
        *slotp += 1;

    return 0;
}

char _license[] SEC("license") = "GPL";
