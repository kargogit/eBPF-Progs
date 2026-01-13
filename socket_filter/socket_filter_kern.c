// socket_filter_kern.c
//
// This is a minimal eBPF socket filter program.
//
// Purpose:
// - Demonstrate attaching an eBPF program to a raw packet socket (PF_PACKET, SOCK_RAW).
// - The program runs on every packet received on that socket.
// - It logs the packet length via bpf_printk() for debugging visibility.
// - It returns the full packet length, meaning "accept the entire packet" (no filtering/drop).
//
// Key concepts:
// - Socket filter programs use BPF_PROG_TYPE_SOCKET_FILTER.
// - They receive a struct __sk_buff *skb context (historical name; modern is struct sk_buff).
// - Return value semantics:
//   - 0                  → drop the packet
//   - > 0 (up to skb->len) → accept that many bytes
//   - skb->len           → accept the whole packet (what we do here)
// - bpf_printk() is the primary debugging tool; output appears in
//   /sys/kernel/debug/tracing/trace_pipe.
//
// This program does not perform any actual filtering — it is essentially a
// packet logger that accepts everything.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* SEC("socket") declares this as a socket filter program.
 * The loader (libbpf) will set the program type to BPF_PROG_TYPE_SOCKET_FILTER
 * and expect it to be attached via setsockopt(SO_ATTACH_BPF).
 */
SEC("socket")
int socket_filter(struct __sk_buff *skb)
{
    /* Log the total packet length (including link-layer header for raw sockets).
     * Output can be viewed in real time with:
     *   sudo cat /sys/kernel/debug/tracing/trace_pipe
     */
    bpf_printk("Packet length: %d\n", skb->len);

    /* Accept the entire packet. If we wanted to drop packets we could return 0.
     * We could also truncate by returning a smaller value.
     */
    return skb->len;
}

/* Required GPL license to allow use of certain BPF helpers (including bpf_printk).
 * Some helpers are restricted to GPL-compatible programs.
 */
char _license[] SEC("license") = "GPL";
