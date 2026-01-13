// hello_kern.c
#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* Minimal tracepoint struct containing only what we need */
struct trace_event_raw_sys_enter {
    unsigned long args[6];
};

// This is our first eBPF program. It will be called every time
// a process calls the sys_openat system call (opening a file).

// SEC() macro tells the loader where this program should attach
// "tp/syscalls/sys_enter_openat" means: tracepoint, syscall entry,
// specifically the openat syscall entrance
SEC("tp/syscalls/sys_enter_openat")
int hello_world(struct trace_event_raw_sys_enter *ctx)
{
    // trace_event_raw_sys_enter contains information about the syscall
    // The 'args' array contains the syscall parameters.
    // For openat, args[0] is the directory file descriptor,
    // args[1] is a pointer to the filename string.

    char filename[256];
    // bpf_probe_read_kernel_str safely reads a NUL-terminated filename
    // from user/kernel memory. This is safer than bpf_probe_read_kernel
    // for strings because it guarantees termination.
    bpf_probe_read_kernel_str(filename, sizeof(filename), (const void *)ctx->args[1]);

    // bpf_printk() is the simplest way to output debug info
    // It works like printf() but has limitations (3 arguments max, %s %d %x only)
    bpf_printk("eBPF Hello World: opening %s\\n", filename);

    // Return 0 means "don't filter this packet/event"
    // For tracing programs, the return value is usually ignored
    return 0;
}

// Every eBPF program needs a license and version
// The license must be GPL-compatible to use certain helper functions
char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;
