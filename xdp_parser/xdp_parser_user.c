// xdp_parser_user.c
//
// User-space loader that:
// 1. Loads the XDP parser program into the kernel
// 2. Attaches it to a specified network interface
// 3. Populates the rules map with IP addresses to drop
// 4. Keeps running until Ctrl+C

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include "xdp_parser_kern.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level > LIBBPF_WARN)
        return 0;
    return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK\n");
}

// Add a drop rule to the kernel map
static int add_drop_rule(int map_fd, const char *ip_str)
{
    __u32 ip_key;
    __u8 action = 1; // 1 = DROP

    // Convert IP string to network byte order integer
    if (inet_pton(AF_INET, ip_str, &ip_key) != 1) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", ip_str);
        return -1;
    }

    // Update kernel map: this IP should be dropped
    if (bpf_map_update_elem(map_fd, &ip_key, &action, BPF_ANY) != 0) {
        perror("Failed to add rule to map");
        return -1;
    }

    printf("  - DROP %s\n", ip_str);
    return 0;
}

int main(int argc, char **argv)
{
    struct xdp_parser_kern *skel;
    int err, prog_fd, map_fd;
    __u32 xdp_flags = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
    char *ifname;
    int ifindex;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <ip_to_drop> [more_ips...]\n", argv[0]);
        fprintf(stderr, "Example: %s eth0 192.168.1.100 10.0.0.5\n", argv[0]);
        return 1;
    }

    ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        perror("Invalid interface name");
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    // Open, load, and attach eBPF program
    skel = xdp_parser_kern__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = xdp_parser_kern__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %d\n", err);
        goto cleanup;
    }

    prog_fd = bpf_program__fd(skel->progs.xdp_parser);
    err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program: %d\n", err);
        fprintf(stderr, "Hint: run 'sudo ip link set %s xdp off' first\n", ifname);
        goto cleanup;
    }

    // Populate rules map from command-line arguments
    map_fd = bpf_map__fd(skel->maps.rules_map);
    printf("\nAdding drop rules to kernel map:\n");
    for (int i = 2; i < argc; i++) {
        add_drop_rule(map_fd, argv[i]);
    }

    printf("\nXDP packet parser ACTIVE on %s\n", ifname);
    printf("Dropping packets to %d IP address(es)\n", argc - 2);
    printf("All other packets will be logged and passed through\n\n");
    printf("View logs: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");
    printf("Press Ctrl+C to exit and detach\n");

    // Keep program running
    while (1) {
        sleep(1);
    }

cleanup:
    xdp_parser_kern__destroy(skel);
    return err != 0;
}
