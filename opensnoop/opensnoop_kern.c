// opensnoop_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/* Minimal tracepoint context - only what we need */
struct trace_event_raw_sys_enter {
    __u64 common_preamble;   // Usually 8 bytes
    int __unused_syscall_nr; // Usually 4-8 bytes depending on arch
    unsigned long args[6];   // Actual arguments start after the preamble
};

/* Map to hold the target PID (0 = trace all, >0 = filter to that PID) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} filter_pid SEC(".maps");

/* Common body used by both tracepoints */
#define COMMON_FILTER_AND_INFO \
    __u64 id = bpf_get_current_pid_tgid(); \
    __u32 pid = id >> 32; \
    __u32 key = 0; \
    __u32 *targ_pid = bpf_map_lookup_elem(&filter_pid, &key); \
    if (targ_pid && *targ_pid != 0 && pid != *targ_pid) \
        return 0; \
    char comm[TASK_COMM_LEN]; \
    bpf_get_current_comm(&comm, sizeof(comm));

SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    COMMON_FILTER_AND_INFO

    char filename[256];
    long ret = bpf_probe_read_user_str(filename, sizeof(filename),
                                        (void *)ctx->args[1]);
    if (ret <= 0)
        return 0;

    bpf_printk("OPEN PID=%u COMM=%s FILE=%s\n", pid, comm, filename);
    return 0;
}

SEC("tp/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
    COMMON_FILTER_AND_INFO

    char filename[256];
    long ret = bpf_probe_read_user_str(filename, sizeof(filename),
                                        (void *)ctx->args[0]);
    if (ret <= 0)
        return 0;

    bpf_printk("OPEN PID=%u COMM=%s FILE=%s\n", pid, comm, filename);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
