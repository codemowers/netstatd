// SPDX-License-Identifier: GPL-2.0
// Simple TCP connection tracker - open and close events only

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// TCP states we care about
#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7

// Event structure
struct conn_event {
    __u32 pid;
    __u32 tgid;    // Thread group ID (task ID)
    __u16 family;  // AF_INET or AF_INET6
    __u16 sport;
    __u16 dport;
    __u32 state;
    __u8 protocol;  // 6 for TCP, 17 for UDP
    __u64 sock_cookie; // Unique socket identifier for matching CLOSE events
    union {
        struct {
            __u32 saddr;
            __u32 daddr;
        } ipv4;
        struct {
            __u8 saddr[16];
            __u8 daddr[16];
        } ipv6;
    };
};

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Define in6_addr first before using it
struct in6_addr {
    union {
        __u8 u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    } in6_u;
} __attribute__((preserve_access_index));

// Minimal sock structure for BPF_CORE_READ
struct sock_common {
    unsigned short skc_family;
    unsigned char skc_state;
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    __be16 skc_dport;
    __u16 skc_num;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

// Tracepoint for TCP state changes using raw tracepoint with BTF
// For tp_btf, the function signature is: void inet_sock_set_state(struct sock *sk, int oldstate, int newstate)
// The context is a pointer to the first argument
SEC("tp_btf/inet_sock_set_state")
int trace_inet_sock_set_state(__u64 *ctx)
{
    // Arguments are passed as an array of __u64
    const struct sock *sk = (const struct sock *)ctx[0];
    int newstate = (int)ctx[2];

    // Read family using BPF_CORE_READ
    __u16 family;
    bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    // Only care about IPv4 and IPv6 TCP
    if (family != 2 && family != 10) // AF_INET=2, AF_INET6=10
        return 0;

    // Only send events for ESTABLISHED (connection opened) and CLOSE (connection closed)
    if (newstate != TCP_ESTABLISHED && newstate != TCP_CLOSE)
        return 0;

    // Reserve space in ring buffer
    struct conn_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // Fill event - get PID and TGID from current task
    // Note: For connections initiated by the kernel (e.g., in softirq context),
    // this may return 0. This is expected behavior for kernel-initiated connections.
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->tgid = pid_tgid & 0xFFFFFFFF;
    e->family = family;
    e->state = newstate;
    e->protocol = 6; // TCP

    // Get socket cookie for stable connection tracking
    // This allows matching CLOSE events even when sport=0
    e->sock_cookie = bpf_get_socket_cookie((struct sock *)sk);

    // Read ports
    __u16 sport, dport;
    bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    e->sport = sport;
    e->dport = __builtin_bswap16(dport); // dport is in network byte order

    // Read addresses based on family
    if (family == 2) {
        // IPv4
        bpf_core_read(&e->ipv4.saddr, sizeof(e->ipv4.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_core_read(&e->ipv4.daddr, sizeof(e->ipv4.daddr), &sk->__sk_common.skc_daddr);
    } else if (family == 10) {
        // IPv6
        bpf_core_read(&e->ipv6.saddr, sizeof(e->ipv6.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        bpf_core_read(&e->ipv6.daddr, sizeof(e->ipv6.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }

    // Submit event
    bpf_ringbuf_submit(e, 0);

    return 0;
}


// Kprobe for UDP send
SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs *ctx)
{
    // The first argument is struct sock *sk
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    if (!sk)
        return 0;

    // Read family
    __u16 family;
    bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    if (family != 2 && family != 10)
        return 0;

    // Reserve space in ring buffer
    struct conn_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // Fill event
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->tgid = pid_tgid & 0xFFFFFFFF;
    e->family = family;
    e->state = 0; // UDP has no state
    e->protocol = 17; // UDP

    // Get socket cookie (0 for UDP since kprobes don't have reliable access)
    e->sock_cookie = 0;

    // Read ports
    __u16 sport, dport;
    bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    e->sport = sport;
    e->dport = __builtin_bswap16(dport);

    // Read addresses
    if (family == 2) {
        bpf_core_read(&e->ipv4.saddr, sizeof(e->ipv4.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_core_read(&e->ipv4.daddr, sizeof(e->ipv4.daddr), &sk->__sk_common.skc_daddr);
    } else if (family == 10) {
        bpf_core_read(&e->ipv6.saddr, sizeof(e->ipv6.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        bpf_core_read(&e->ipv6.daddr, sizeof(e->ipv6.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Kprobe for UDP receive
SEC("kprobe/udp_recvmsg")
int trace_udp_recvmsg(struct pt_regs *ctx)
{
    // The first argument is struct sock *sk
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    if (!sk)
        return 0;

    // Read family
    __u16 family;
    bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    if (family != 2 && family != 10)
        return 0;

    // Reserve space in ring buffer
    struct conn_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // Fill event
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->tgid = pid_tgid & 0xFFFFFFFF;
    e->family = family;
    e->state = 0; // UDP has no state
    e->protocol = 17; // UDP

    // Get socket cookie (0 for UDP since kprobes don't have reliable access)
    e->sock_cookie = 0;

    // Read ports
    __u16 sport, dport;
    bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    e->sport = sport;
    e->dport = __builtin_bswap16(dport);

    // Read addresses
    if (family == 2) {
        bpf_core_read(&e->ipv4.saddr, sizeof(e->ipv4.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_core_read(&e->ipv4.daddr, sizeof(e->ipv4.daddr), &sk->__sk_common.skc_daddr);
    } else if (family == 10) {
        bpf_core_read(&e->ipv6.saddr, sizeof(e->ipv6.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        bpf_core_read(&e->ipv6.daddr, sizeof(e->ipv6.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
