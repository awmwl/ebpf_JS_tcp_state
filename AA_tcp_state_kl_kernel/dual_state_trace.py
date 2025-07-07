from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
import ctypes

prog = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct trace_key_t {
    u16 oldstate;
    u16 newstate;
};

BPF_HASH(kprobe_counts, struct trace_key_t, u64);
BPF_PERF_OUTPUT(events);

// kprobe: tcp_set_state
int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    u16 oldstate = sk->__sk_common.skc_state;
    u16 newstate = state;

    struct trace_key_t key = {
        .oldstate = oldstate,
        .newstate = newstate,
    };

    u64 zero = 0, *val;
    val = kprobe_counts.lookup_or_init(&key, &zero);
    (*val)++;

    return 0;
}

// tracepoint: sock:inet_sock_set_state
struct trace_event_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u16 oldstate;
    u16 newstate;
};

TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    struct trace_event_t ev = {};

    u16 family = args->family;
    if (family != AF_INET) return 0;  // 忽略 IPv6

    __u32 saddr = 0, daddr = 0;
    __builtin_memcpy(&saddr, args->saddr, sizeof(saddr));
    __builtin_memcpy(&daddr, args->daddr, sizeof(daddr));

    ev.saddr = bpf_ntohl(saddr);
    ev.daddr = bpf_ntohl(daddr);

    ev.sport = ntohs(args->sport);
    ev.dport = ntohs(args->dport);
    ev.oldstate = args->oldstate;
    ev.newstate = args->newstate;

    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""

class Event(ctypes.Structure):
    _fields_ = [
        ("saddr", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("oldstate", ctypes.c_uint16),
        ("newstate", ctypes.c_uint16),
    ]

def inet_ntoa(addr):
    return inet_ntop(AF_INET, addr.to_bytes(4, byteorder='big'))

b = BPF(text=prog)

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    print("[Tracepoint] %s:%d -> %s:%d | %d → %d" % (
        inet_ntoa(event.saddr),
        event.sport,
        inet_ntoa(event.daddr),
        event.dport,
        event.oldstate,
        event.newstate
    ))

b["events"].open_perf_buffer(print_event)

print("Tracing both kprobe (tcp_set_state) and tracepoint (inet_sock_set_state)... Ctrl+C to stop.")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nDone. State transitions (kprobe):")
    counts = b.get_table("kprobe_counts")
    for k, v in sorted(counts.items(), key=lambda x: (x[0].oldstate, x[0].newstate)):
        print("  %d → %d: %d" % (k.oldstate, k.newstate, v.value))
