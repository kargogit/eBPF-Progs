// funclatency_user.c
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "funclatency_kern.skel.h"

#define MAX_SLOT 34
#define PRINT_INTERVAL 5  // seconds

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
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
    struct funclatency_kern *skel = NULL;
    struct bpf_link *entry_link = NULL, *ret_link = NULL;
    int err = 0, hist_fd, execs_fd, cpus;
    __u64 *percpu_buf = NULL;
    const char *func_name;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <kernel_function_name>\n", argv[0]);
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  %s vfs_read               # file read latency\n", argv[0]);
        fprintf(stderr, "  %s __x64_sys_nanosleep   # nanosleep syscall latency\n", argv[0]);
        return 1;
    }
    func_name = argv[1];

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();
    signal(SIGINT, sig_handler);

    skel = funclatency_kern__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = funclatency_kern__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %d\n", err);
        goto cleanup;
    }

    entry_link = bpf_program__attach_kprobe(skel->progs.trace_entry, false, func_name);
    if (!entry_link) {
        fprintf(stderr, "Failed to attach entry kprobe to %s: %s\n",
                func_name, strerror(errno));
        goto cleanup;
    }

    ret_link = bpf_program__attach_kprobe(skel->progs.trace_ret, true, func_name);
    if (!ret_link) {
        fprintf(stderr, "Failed to attach retprobe to %s: %s\n",
                func_name, strerror(errno));
        goto cleanup;
    }

    hist_fd = bpf_map__fd(skel->maps.hist);
    execs_fd = bpf_map__fd(skel->maps.execs);
    cpus = libbpf_num_possible_cpus();
    if (cpus < 0) {
        fprintf(stderr, "Failed to get CPU count\n");
        goto cleanup;
    }

    percpu_buf = calloc(cpus, sizeof(__u64));
    if (!percpu_buf) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

    printf("Successfully attached to function: %s\n", func_name);
    printf("Tracing latency... Output every %d seconds. Ctrl+C to stop.\n", PRINT_INTERVAL);

    while (!exiting) {
        sleep(PRINT_INTERVAL);

        __u64 dist[MAX_SLOT + 1] = {0};
        __u64 total_events = 0;
        __u64 max_count = 0;

        // Read total events
        __u32 key = 0;
        if (bpf_map_lookup_elem(execs_fd, &key, percpu_buf) == 0) {
            for (int i = 0; i < cpus; i++)
                total_events += percpu_buf[i];
        }

        // Read histogram
        for (__u32 s = 0; s <= MAX_SLOT; s++) {
            key = s;
            if (bpf_map_lookup_elem(hist_fd, &key, percpu_buf) == 0) {
                __u64 count = 0;
                for (int i = 0; i < cpus; i++)
                    count += percpu_buf[i];
                dist[s] = count;
                if (count > max_count)
                    max_count = count;
            }
        }

        if (total_events == 0) {
            printf("No calls to %s observed yet.\n", func_name);
            continue;
        }

        printf("\n[%s] Total calls: %llu\n", func_name, total_events);
        printf("%-20s %10s   %s\n", "usecs range", "count", "distribution");

        for (__u32 s = 0; s <= MAX_SLOT; s++) {
            __u64 count = dist[s];
            if (count == 0)
                continue;

            char range[64];
            if (s == 0)
                snprintf(range, sizeof(range), "0 -> <1");
            else if (s == MAX_SLOT)
                snprintf(range, sizeof(range), ">=%llu", 1ULL << (MAX_SLOT - 1));
            else
                snprintf(range, sizeof(range), "%llu -> %llu",
                         1ULL << (s - 1), (1ULL << s) - 1);

            int bar_width = max_count ? (count * 50 / max_count) : 0;
            printf("%-20s %10llu   |", range, count);
            for (int i = 0; i < bar_width; i++)
                putchar('*');
            printf("|\n");
        }
    }

cleanup:
    funclatency_kern__destroy(skel);
    free(percpu_buf);
    return err != 0;
}
