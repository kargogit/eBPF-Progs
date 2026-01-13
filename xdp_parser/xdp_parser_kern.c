// xdp_parser_kern.c
//
// Minimal XDP packet parser that safely inspects Ethernet and IPv4 headers.
// Demonstrates boundary checks required by the eBPF verifier.
// Applies filtering rules from a userspace-controlled map.
//
// Key concepts:
// - Uses data/data_end pointers for safe memory access
// - Parses Ethernet header and checks ethertype
// - Parses IPv4 header with proper length validation
// - Looks up destination IP in a rules map to decide PASS/DROP
// - Logs packet info via bpf_printk for debugging

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>

// Map for filtering rules: key = IPv4 address, value = action (0=PASS, 1=DROP)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 1024);
} rules_map SEC(".maps");

SEC("xdp")
int xdp_parser(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct iphdr *ip;
    __u8 *action;

    // --- Ethernet Header Parsing ---
    // Cast data pointer and verify it fits within packet bounds
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS; // Packet too small, let it pass

    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // --- IP Header Parsing ---
    // Move pointer past Ethernet header and verify bounds
    ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS; // Packet too small for IP header

    // --- Rule Lookup and Action ---
    // Check if we have a rule for this destination IP
    action = bpf_map_lookup_elem(&rules_map, &ip->daddr);
    if (action && *action == 1) {
        bpf_printk("XDP Parser: DROPPING packet to %pI4\n", &ip->daddr);
        return XDP_DROP;
    }

    // --- Logging ---
    // Log all passed packets for visibility
    // %pI4 is a kernel format specifier for IPv4 addresses
    bpf_printk("XDP Parser: PASS packet from %pI4 to %pI4, proto %d\n",
               &ip->saddr, &ip->daddr, ip->protocol);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
