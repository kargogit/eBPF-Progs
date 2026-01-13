// exitsnoop_user.c
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "exitsnoop.h"
#include "exitsnoop_kern.skel.h"

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
    struct rlimit rlim = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct event *e = data;
    printf("EXIT PID=%u COMM=%s EXIT_CODE=%d\n",
           e->pid, e->comm, e->exit_code);
    return 0;
}

int main(int argc, char **argv)
{
    struct exitsnoop_kern *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = exitsnoop_kern__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = exitsnoop_kern__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %d\n", err);
        goto cleanup;
    }

    err = exitsnoop_kern__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("Process exit monitor started (using ring buffer for efficient streaming).\n");
    printf("Waiting for process terminations...\n");
    printf("Run commands or kill processes to generate events.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    exitsnoop_kern__destroy(skel);
    return err < 0 ? -err : 0;
}
