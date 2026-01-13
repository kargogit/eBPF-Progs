// write_counter_user.c
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "write_counter_kern.skel.h"

struct datarec {
    __u64 calls;
    __u64 bytes;
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
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK\n");
}

int main(int argc, char **argv)
{
    struct write_counter_kern *skel = NULL;
    int err = 0;
    int map_fd;
    int cpus;
    struct datarec *samples = NULL;

    __u64 prev_calls = 0, prev_bytes = 0;

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    skel = write_counter_kern__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = write_counter_kern__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %d\n", err);
        goto cleanup;
    }

    err = write_counter_kern__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        goto cleanup;
    }

    map_fd = bpf_map__fd(skel->maps.stats_map);
    cpus = libbpf_num_possible_cpus();
    if (cpus < 0) {
        fprintf(stderr, "Failed to get CPU count\n");
        goto cleanup;
    }

    samples = calloc(cpus, sizeof(struct datarec));
    if (!samples) {
        fprintf(stderr, "Failed to allocate memory\n");
        goto cleanup;
    }

    /* Initial read to initialize prev values */
    __u32 key = 0;
    if (bpf_map_lookup_elem(map_fd, &key, samples) == 0) {
        for (int i = 0; i < cpus; i++) {
            prev_calls += samples[i].calls;
            prev_bytes += samples[i].bytes;
        }
    }

    printf("Syscall counter attached (tracing sys_write)\n");
    printf("  writes/s      bytes/s\n");

    while (1) {
        sleep(1);

        __u64 calls = 0, bytes = 0;
        if (bpf_map_lookup_elem(map_fd, &key, samples) != 0)
            continue;

        for (int i = 0; i < cpus; i++) {
            calls += samples[i].calls;
            bytes += samples[i].bytes;
        }

        __u64 wps = calls - prev_calls;
        __u64 bps = bytes - prev_bytes;

        printf("%12llu %14llu\n", wps, bps);

        prev_calls = calls;
        prev_bytes = bytes;
    }

cleanup:
    if (skel)
        write_counter_kern__destroy(skel);
    free(samples);
    return err != 0;
}
