// cgroup_skb_counter_user.c
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cgroup_skb_counter.h"
#include "cgroup_skb_counter_kern.skel.h"


static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level >= LIBBPF_WARN)
        return vfprintf(stderr, format, args);
    return 0;
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);
}

int main(int argc, char **argv)
{
    struct cgroup_skb_counter_kern *skel = NULL;
    struct bpf_link *ingress_link = NULL;
    struct bpf_link *egress_link = NULL;
    int cgroup_fd = -1;
    int map_fd = -1;
    int err = 0;
    int cpus;
    struct datarec *samples = NULL;
    __u64 prev_ing_packets = 0, prev_ing_bytes = 0;
    __u64 prev_eg_packets = 0, prev_eg_bytes = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <cgroup_path>\n", argv[0]);
        fprintf(stderr, "Example: %s /sys/fs/cgroup/my-test-group\n", argv[0]);
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();
    signal(SIGINT, sig_handler);

    cgroup_fd = open(argv[1], O_RDONLY);
    if (cgroup_fd < 0) {
        perror("Failed to open cgroup directory");
        return 1;
    }

    skel = cgroup_skb_counter_kern__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        err = 1;
        goto cleanup;
    }

    err = cgroup_skb_counter_kern__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %d\n", err);
        goto cleanup;
    }

    ingress_link = bpf_program__attach_cgroup(skel->progs.count_ingress, cgroup_fd);
    if (!ingress_link) {
        err = -errno;
        fprintf(stderr, "Failed to attach ingress program: %s\n", strerror(-err));
        goto cleanup;
    }

    egress_link = bpf_program__attach_cgroup(skel->progs.count_egress, cgroup_fd);
    if (!egress_link) {
        err = -errno;
        fprintf(stderr, "Failed to attach egress program: %s\n", strerror(-err));
        goto cleanup;
    }

    map_fd = bpf_map__fd(skel->maps.counts);
    cpus = libbpf_num_possible_cpus();
    if (cpus < 0) {
        fprintf(stderr, "Failed to get CPU count\n");
        err = 1;
        goto cleanup;
    }

    samples = calloc(cpus, sizeof(struct datarec));
    if (!samples) {
        fprintf(stderr, "Failed to allocate memory for samples\n");
        err = 1;
        goto cleanup;
    }

    /* Initial read to initialize previous values */
    __u32 key;
    key = INGRESS_KEY;
    if (bpf_map_lookup_elem(map_fd, &key, samples) == 0) {
        for (int i = 0; i < cpus; i++) {
            prev_ing_packets += samples[i].packets;
            prev_ing_bytes += samples[i].bytes;
        }
    }
    key = EGRESS_KEY;
    if (bpf_map_lookup_elem(map_fd, &key, samples) == 0) {
        for (int i = 0; i < cpus; i++) {
            prev_eg_packets += samples[i].packets;
            prev_eg_bytes += samples[i].bytes;
        }
    }

    printf("Packet counter attached to cgroup %s\n", argv[1]);
    printf("Monitoring network traffic for processes in this cgroup.\n\n");
    printf("%-10s %12s %15s\n", "", "pkt/s", "bit/s");
    printf("-----------------------------------------\n");

    while (!exiting) {
        sleep(1);

        __u64 ing_packets = 0, ing_bytes = 0;
        __u64 eg_packets = 0, eg_bytes = 0;

        key = INGRESS_KEY;
        if (bpf_map_lookup_elem(map_fd, &key, samples) == 0) {
            for (int i = 0; i < cpus; i++) {
                ing_packets += samples[i].packets;
                ing_bytes += samples[i].bytes;
            }
        }

        key = EGRESS_KEY;
        if (bpf_map_lookup_elem(map_fd, &key, samples) == 0) {
            for (int i = 0; i < cpus; i++) {
                eg_packets += samples[i].packets;
                eg_bytes += samples[i].bytes;
            }
        }

        __u64 ing_pps = ing_packets - prev_ing_packets;
        __u64 ing_bps = (ing_bytes - prev_ing_bytes) * 8;
        __u64 eg_pps = eg_packets - prev_eg_packets;
        __u64 eg_bps = (eg_bytes - prev_eg_bytes) * 8;

        printf("%-10s %12llu %15llu\n", "Ingress:", ing_pps, ing_bps);
        printf("%-10s %12llu %15llu\n", "Egress:", eg_pps, eg_bps);

        prev_ing_packets = ing_packets;
        prev_ing_bytes = ing_bytes;
        prev_eg_packets = eg_packets;
        prev_eg_bytes = eg_bytes;
    }

cleanup:
    if (ingress_link)
        bpf_link__destroy(ingress_link);
    if (egress_link)
        bpf_link__destroy(egress_link);
    if (cgroup_fd >= 0)
        close(cgroup_fd);
    if (skel)
        cgroup_skb_counter_kern__destroy(skel);
    free(samples);
    return err != 0;
}
