// xdp_dropper_user.c
// User-space loader that loads the XDP program and attaches it to a specified network interface.

#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp_dropper_kern.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level >= LIBBPF_WARN)
        return vfprintf(stderr, format, args);
    return 0;
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK\n");
    }
}

int main(int argc, char **argv)
{
    struct xdp_dropper_kern *skel;
    int err, prog_fd;
    __u32 xdp_flags = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
    char *ifname;
    int ifindex;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        fprintf(stderr, "Example: %s eth0\n", argv[0]);
        return 1;
    }

    ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    // Open the BPF skeleton
    skel = xdp_dropper_kern__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Load and verify the program
    err = xdp_dropper_kern__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %d\n", err);
        goto cleanup;
    }

    // Get the program file descriptor
    prog_fd = bpf_program__fd(skel->progs.xdp_dropper);

    // Attach the XDP program to the interface (generic/SKB mode for maximum compatibility)
    err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program to %s: %d\n", ifname, err);
        fprintf(stderr, "Hint: you may need to first run 'sudo ip link set %s xdp off'\n", ifname);
        goto cleanup;
    }

    printf("XDP dropper successfully attached to %s\n", ifname);
    printf("All incoming packets on this interface will now be dropped.\n");
    printf("To see logs: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");
    printf("Press Ctrl+C to stop and unload the program.\n");

    // Keep running until interrupted
    while (1) {
        sleep(1);
    }

cleanup:
    xdp_dropper_kern__destroy(skel);
    return err != 0;
}
