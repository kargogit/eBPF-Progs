// xdp_counter_user.c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp_counter_kern.skel.h"

struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level >= LIBBPF_WARN)
        return vfprintf(stderr, format, args);
    return 0;
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK\n");
}

int main(int argc, char **argv)
{
    struct xdp_counter_kern *skel = NULL;
    int err = 0;
    int prog_fd, map_fd;
    int ifindex = 0;
    char *ifname = NULL;
    __u32 xdp_flags = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
    bool attached = false;

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

    skel = xdp_counter_kern__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = xdp_counter_kern__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %d\n", err);
        goto cleanup;
    }

    prog_fd = bpf_program__fd(skel->progs.xdp_counter);
    err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program to %s: %d\n", ifname, err);
        fprintf(stderr, "Hint: try 'sudo ip link set %s xdp off' first\n", ifname);
        goto cleanup;
    }
    attached = true;

    map_fd = bpf_map__fd(skel->maps.xdp_stats_map);
    int cpus = libbpf_num_possible_cpus();
    if (cpus < 0) {
        fprintf(stderr, "Failed to get CPU count\n");
        goto cleanup;
    }

    struct datarec *samples = calloc(cpus, sizeof(struct datarec));
    if (!samples) {
        fprintf(stderr, "Failed to allocate memory\n");
        goto cleanup;
    }

    __u32 key = 0;
    __u64 prev_packets = 0, prev_bytes = 0;

    /* Initial read */
    if (bpf_map_lookup_elem(map_fd, &key, samples) == 0) {
        for (int i = 0; i < cpus; i++) {
            prev_packets += samples[i].rx_packets;
            prev_bytes += samples[i].rx_bytes;
        }
    }

    printf("XDP packet counter attached to %s\n", ifname);
    printf("   pkt/s        bit/s\n");

    while (1) {
        sleep(1);

        __u64 packets = 0, bytes = 0;
        if (bpf_map_lookup_elem(map_fd, &key, samples)) {
            continue;
        }

        for (int i = 0; i < cpus; i++) {
            packets += samples[i].rx_packets;
            bytes += samples[i].rx_bytes;
        }

        __u64 pps = packets - prev_packets;
        __u64 bps = (bytes - prev_bytes) * 8;

        printf("%10llu  %12llu\n", pps, bps);

        prev_packets = packets;
        prev_bytes = bytes;
    }

cleanup:
    if (attached)
        bpf_xdp_attach(ifindex, -1, xdp_flags, NULL);
    if (skel)
        xdp_counter_kern__destroy(skel);
    return err != 0;
}
