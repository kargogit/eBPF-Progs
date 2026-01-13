// execsnoop_kern.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_ARGS 10
#define MAX_ARG_LEN 128

SEC("kprobe/__x64_sys_execve")
int execsnoop(struct pt_regs *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    __u32 pid = BPF_CORE_READ(task, tgid);
    __u32 ppid = 0;
    struct task_struct *parent;
    if (bpf_core_read(&parent, sizeof(parent), &task->real_parent) == 0) {
        bpf_core_read(&ppid, sizeof(ppid), &parent->tgid);
    }

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    __u32 uid = (__u32)bpf_get_current_uid_gid();

    // Filename (user-space pointer)
    const char *filename_ptr = (const char *)PT_REGS_PARM1_CORE(ctx);
    char filename[256];
    bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr);

    bpf_printk("EXEC PID=%u PPID=%u UID=%u COMM=%s FILE=%s", pid, ppid, uid, comm, filename);

    // argv (user-space pointer to array of pointers)
    __u64 argv_ptr = PT_REGS_PARM2_CORE(ctx);
    char arg[MAX_ARG_LEN];

    #pragma clang loop unroll(full)
    for (int i = 0; i < MAX_ARGS; i++) {
        __u64 arg_ptr = 0;
        // Read the i-th argument pointer from user-space argv array
        if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), (void *)(argv_ptr + i * sizeof(void *))))
            break;
        if (arg_ptr == 0)
            break;

        // Read the argument string
        int len = bpf_probe_read_user_str(arg, sizeof(arg), (void *)arg_ptr);
        if (len <= 0)
            break;

        bpf_printk(" %s", arg);
    }

    bpf_printk("\n");

    return 0;
}

char _license[] SEC("license") = "GPL";
