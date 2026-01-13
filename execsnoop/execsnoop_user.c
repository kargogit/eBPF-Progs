// execsnoop_user.c
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "execsnoop_kern.skel.h"

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
    setrlimit(RLIMIT_MEMLOCK, &rlim);
}

int main(int argc, char **argv)
{
    struct execsnoop_kern *skel;
    int err;

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    skel = execsnoop_kern__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = execsnoop_kern__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %d\n", err);
        goto cleanup;
    }

    err = execsnoop_kern__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        goto cleanup;
    }

    printf("execsnoop started. Tracing execve system calls...\n");
    printf("View output with: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");
    printf("Run programs (ls, cat, bash scripts, etc.) to see events.\n");
    printf("Press Ctrl+C to stop.\n");

    while (1) sleep(1);

cleanup:
    execsnoop_kern__destroy(skel);
    return err != 0;
}
