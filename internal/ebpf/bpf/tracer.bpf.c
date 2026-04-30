// SPDX-License-Identifier: GPL-2.0
// TCP tracepoint and UDP kprobe connection tracker.

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Event structure - carefully aligned to minimize padding
struct conn_event {
    __u64 sock_cookie; // Unique socket identifier (8 bytes, offset 0)
    __u32 pid;         // Process ID (4 bytes, offset 8)
    __u32 _pad;        // Explicit padding; keeps state 4-byte aligned (offset 12)
    __u32 state;       // Current TCP state (4 bytes, offset 16)
    __u16 family;      // AF_INET or AF_INET6 (2 bytes, offset 20)
    __u16 sport;       // Source port (2 bytes, offset 22)
    __u16 dport;       // Destination port (2 bytes, offset 24)
    __u8 protocol;     // 6 for TCP, 17 for UDP (1 byte, offset 26)
    __u8 event_type;   // Raw event source (1 byte, offset 27)
    __u8 saddr[16];    // Source address - always 16 bytes (offset 28)
    __u8 daddr[16];    // Destination address - always 16 bytes (offset 44)
} __attribute__((packed));

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Configuration map for runtime settings
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

// Config flags bitmap
#define CONFIG_DISABLE_TCP 0x1  // 1 << 0
#define CONFIG_DISABLE_UDP 0x2  // 1 << 1

#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_SYN_RECV 3
#define TCP_CLOSE 7
#define TCP_LISTEN 10

#define EVENT_TCP_STATE 1
#define EVENT_LISTEN_SYSCALL 2
#define EVENT_TCP_ACCEPT 3
#define EVENT_UDP_SEND 4
#define EVENT_UDP_RECV 5

// Minimal socket structures used by TCP tp_btf and UDP kprobes.
struct in6_addr {
    union {
        __u8 u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    } in6_u;
} __attribute__((preserve_access_index));

struct sock_common {
    unsigned short skc_family;
    unsigned char skc_state;
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    __be16 skc_dport;
    __u16 skc_num;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
    int skc_bound_dev_if;  // Network interface index
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(trace_inet_sock_set_state, struct sock *sk, int oldstate, int newstate)
{
    if (!sk)
        return 0;

    __u16 family;
    bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    // Only care about IPv4 and IPv6 TCP.
    if (family != 2 && family != 10) // AF_INET=2, AF_INET6=10
        return 0;

    // Always filter loopback traffic
    // For IPv4: 127.0.0.0/8
    // For IPv6: ::1 (0x00000000000000000000000000000001)
    if (family == 2) {
        __u32 saddr, daddr;
        bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
        if ((saddr & 0xFF) == 0x7F || (daddr & 0xFF) == 0x7F) {
            return 0;  // Skip loopback traffic
        }
    } else if (family == 10) {
        __u32 saddr[4], daddr[4];
        bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        if ((saddr[0] == 0 && saddr[1] == 0 && saddr[2] == 0 && saddr[3] == 0x01000000) ||
            (daddr[0] == 0 && daddr[1] == 0 && daddr[2] == 0 && daddr[3] == 0x01000000)) {
            return 0;  // Skip loopback traffic
        }
    }

    // Skip SYN_RECV state (3) to reduce noise.
    if (newstate == TCP_SYN_RECV) {
        return 0;
    }

    // Reserve space in ring buffer
    struct conn_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->sock_cookie = bpf_get_socket_cookie(sk);

    e->pid = 0;
    e->_pad = 0;

    e->state = newstate;
    e->family = family;
    e->protocol = 6; // TCP
    e->event_type = EVENT_TCP_STATE;

    __u16 sport, dport;
    bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    e->sport = sport;
    e->dport = __builtin_bswap16(dport);

    // Read addresses - always store as 16 bytes (IPv4 uses IPv4-mapped IPv6)
    if (family == 2) {
        __u32 saddr, daddr;
        bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

        __builtin_memset(e->saddr, 0, 16);
        __builtin_memset(e->daddr, 0, 16);

        // Set IPv4-mapped IPv6 prefix (::ffff:0:0/96)
        e->saddr[10] = 0xff;
        e->saddr[11] = 0xff;
        e->daddr[10] = 0xff;
        e->daddr[11] = 0xff;

        __builtin_memcpy(&e->saddr[12], &saddr, 4);
        __builtin_memcpy(&e->daddr[12], &daddr, 4);
    } else if (family == 10) {
        bpf_core_read(e->saddr, 16, &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        bpf_core_read(e->daddr, 16, &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }

    // Submit event
    bpf_ringbuf_submit(e, 0);

    return 0;
}

struct sys_exit_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;

    long id;
    long ret;
};

SEC("tracepoint/syscalls/sys_exit_listen")
int trace_sys_exit_listen(struct sys_exit_ctx *ctx)
{
    if (ctx->ret != 0)
        return 0;

    struct conn_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->state = TCP_LISTEN;
    e->family = 2; // AF_INET; address and port are intentionally absent.
    e->protocol = 6; // TCP
    e->event_type = EVENT_LISTEN_SYSCALL;

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("kretprobe/inet_csk_accept")
int trace_inet_csk_accept_ret(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk)
        return 0;

    __u16 family;
    bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != 2 && family != 10)
        return 0;

    if (family == 2) {
        __u32 saddr, daddr;
        bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
        if ((saddr & 0xFF) == 0x7F || (daddr & 0xFF) == 0x7F)
            return 0;
    } else if (family == 10) {
        __u32 saddr[4], daddr[4];
        bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        if ((saddr[0] == 0 && saddr[1] == 0 && saddr[2] == 0 && saddr[3] == 0x01000000) ||
            (daddr[0] == 0 && daddr[1] == 0 && daddr[2] == 0 && daddr[3] == 0x01000000))
            return 0;
    }

    struct conn_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->sock_cookie = 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->state = TCP_ESTABLISHED;
    e->family = family;
    e->protocol = 6; // TCP
    e->event_type = EVENT_TCP_ACCEPT;

    __u16 sport, dport;
    bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    e->sport = sport;
    e->dport = __builtin_bswap16(dport);

    if (family == 2) {
        __u32 saddr, daddr;
        bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

        e->saddr[10] = 0xff;
        e->saddr[11] = 0xff;
        e->daddr[10] = 0xff;
        e->daddr[11] = 0xff;

        __builtin_memcpy(&e->saddr[12], &saddr, 4);
        __builtin_memcpy(&e->daddr[12], &daddr, 4);
    } else if (family == 10) {
        bpf_core_read(e->saddr, 16, &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        bpf_core_read(e->daddr, 16, &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }

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

    // Always filter loopback traffic
    if (family == 2) {
        // IPv4: read addresses
        __u32 saddr, daddr;
        bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

        // Check if either address is in 127.0.0.0/8
        // First octet is in the lowest byte
        if ((saddr & 0xFF) == 0x7F || (daddr & 0xFF) == 0x7F) {
            return 0;  // Skip loopback traffic
        }
    } else if (family == 10) {
        // IPv6: read addresses as 32-bit words for simpler comparison
        __u32 saddr[4], daddr[4];
        bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

        // Check if either address is ::1 (0x00000000 0x00000000 0x00000000 0x01000000 in little-endian)
        if ((saddr[0] == 0 && saddr[1] == 0 && saddr[2] == 0 && saddr[3] == 0x01000000) ||
            (daddr[0] == 0 && daddr[1] == 0 && daddr[2] == 0 && daddr[3] == 0x01000000)) {
            return 0;  // Skip loopback traffic
        }
    }

    // Reserve space in ring buffer
    struct conn_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->sock_cookie = 0;

    // Fill event
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->_pad = 0;

    e->state = 0; // UDP has no state
    e->family = family;
    e->protocol = 17; // UDP
    e->event_type = EVENT_UDP_SEND;

    // Read ports
    __u16 sport, dport;
    bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    e->sport = sport;
    e->dport = __builtin_bswap16(dport);

    // Read addresses - always store as 16 bytes
    if (family == 2) {
        // IPv4 - store as IPv4-mapped IPv6
        __u32 saddr, daddr;
        bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

        __builtin_memset(e->saddr, 0, 16);
        __builtin_memset(e->daddr, 0, 16);

        e->saddr[10] = 0xff;
        e->saddr[11] = 0xff;
        e->daddr[10] = 0xff;
        e->daddr[11] = 0xff;

        __builtin_memcpy(&e->saddr[12], &saddr, 4);
        __builtin_memcpy(&e->daddr[12], &daddr, 4);
    } else if (family == 10) {
        // IPv6 - copy directly
        bpf_core_read(e->saddr, 16, &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        bpf_core_read(e->daddr, 16, &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
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

    // Always filter loopback traffic
    if (family == 2) {
        // IPv4: read addresses
        __u32 saddr, daddr;
        bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

        // Check if either address is in 127.0.0.0/8
        // First octet is in the lowest byte
        if ((saddr & 0xFF) == 0x7F || (daddr & 0xFF) == 0x7F) {
            return 0;  // Skip loopback traffic
        }
    } else if (family == 10) {
        // IPv6: read addresses as 32-bit words for simpler comparison
        __u32 saddr[4], daddr[4];
        bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

        // Check if either address is ::1 (0x00000000 0x00000000 0x00000000 0x01000000 in little-endian)
        if ((saddr[0] == 0 && saddr[1] == 0 && saddr[2] == 0 && saddr[3] == 0x01000000) ||
            (daddr[0] == 0 && daddr[1] == 0 && daddr[2] == 0 && daddr[3] == 0x01000000)) {
            return 0;  // Skip loopback traffic
        }
    }

    // Reserve space in ring buffer
    struct conn_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->sock_cookie = 0;

    // Fill event
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->_pad = 0;

    e->state = 0; // UDP has no state
    e->family = family;
    e->protocol = 17; // UDP
    e->event_type = EVENT_UDP_RECV;

    // Read ports
    __u16 sport, dport;
    bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    e->sport = sport;
    e->dport = __builtin_bswap16(dport);

    // Read addresses - always store as 16 bytes
    if (family == 2) {
        // IPv4 - store as IPv4-mapped IPv6
        __u32 saddr, daddr;
        bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

        __builtin_memset(e->saddr, 0, 16);
        __builtin_memset(e->daddr, 0, 16);

        e->saddr[10] = 0xff;
        e->saddr[11] = 0xff;
        e->daddr[10] = 0xff;
        e->daddr[11] = 0xff;

        __builtin_memcpy(&e->saddr[12], &saddr, 4);
        __builtin_memcpy(&e->daddr[12], &daddr, 4);
    } else if (family == 10) {
        // IPv6 - copy directly
        bpf_core_read(e->saddr, 16, &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        bpf_core_read(e->daddr, 16, &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
