// opensnoop_user.c
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "opensnoop_kern.skel.h"

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
    struct opensnoop_kern *skel;
    int err;
    __u32 target_pid = 0;  /* 0 = trace all */

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [PID]\n", argv[0]);
        return 1;
    }
    if (argc == 2) {
        target_pid = strtol(argv[1], NULL, 10);
        if (target_pid == 0) {
            printf("PID 0 given → tracing all processes\n");
        }
    }

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    skel = opensnoop_kern__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = opensnoop_kern__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %d\n", err);
        goto cleanup;
    }

    err = opensnoop_kern__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        goto cleanup;
    }

    /* Set the filter PID (default 0 = all) */
    int map_fd = bpf_map__fd(skel->maps.filter_pid);
    __u32 key = 0;
    bpf_map_update_elem(map_fd, &key, &target_pid, BPF_ANY);

    printf("opensnoop started. Tracing file open attempts");
    if (target_pid == 0)
        printf(" (all processes)\n");
    else
        printf(" (PID %u only)\n", target_pid);

    printf("→ View output with: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");
    printf("Press Ctrl+C to stop.\n");

    while (1) sleep(1);

cleanup:
    opensnoop_kern__destroy(skel);
    return err != 0;
}
