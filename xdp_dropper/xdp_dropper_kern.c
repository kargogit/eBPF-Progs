// xdp_dropper_kern.c
// Minimal XDP program that drops every incoming packet (XDP_DROP).
// It also logs a message for each packet via bpf_printk() so you can verify it is running.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Section name "xdp" marks this as an XDP program
SEC("xdp")
int xdp_dropper(struct xdp_md *ctx)
{
    // Calculate packet length and log it along with the interface index
    __u32 packet_len = ctx->data_end - ctx->data;
    bpf_printk("XDP dropper: dropping packet on ifindex %u, length %u\n",
               ctx->ingress_ifindex, packet_len);

    // 1 == XDP_DROP
    return 1;
}

// Required GPL license (needed for bpf_printk and many BPF helpers)
char _license[] SEC("license") = "GPL";
