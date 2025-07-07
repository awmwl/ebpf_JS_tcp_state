// kl_detector.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "shared.h"
#include "log_table.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";


// 基准概率表（用于 KL 散度计算）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STATE_MAX * STATE_MAX);
    __type(key, __u32);
    __type(value, __u64); // Q32.32, always >= 0
} baseline_map SEC(".maps");

// log(x) 查找表（近似 ln(x) 的 Q32.32 值）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, LOG_LOOKUP_SIZE);
    __type(key, __u32);
    __type(value, __s64);  // Q32.32 signed log value
} log_table_map SEC(".maps");

// 状态转移统计（每个连接）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct conn_id);
    __type(value, struct state_count);
} state_counter_map SEC(".maps");

// KL 值告警
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} alert_map SEC(".maps");


// 你内核态 log_lookup 函数示例
static __always_inline __s64 log_lookup(__u32 x) {
    if (x == 0) x = 1;
    __u32 idx = x >> (32 - 9);  // 假设 LOG_LOOKUP_SIZE = 512 -> 9位索引
    if (idx >= LOG_LOOKUP_SIZE) idx = LOG_LOOKUP_SIZE - 1;
    return log_table[idx]; // signed Q32.32int64_t 值，可能为负，所以log_lookup() 返回值应为 __s64 类型
}



SEC("tracepoint/sock/inet_sock_set_state")
int trace_tcp_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    struct conn_id id = {};
    struct state_count *sc;

    bpf_probe_read_kernel(&id.saddr, sizeof(id.saddr), &ctx->saddr);
    bpf_probe_read_kernel(&id.daddr, sizeof(id.daddr), &ctx->daddr);
    id.dport = bpf_ntohs(ctx->dport);
    id.family = ctx->family;

    sc = bpf_map_lookup_elem(&state_counter_map, &id);
    if (!sc) {
        struct state_count init = {};
        bpf_map_update_elem(&state_counter_map, &id, &init, BPF_NOEXIST);
        sc = &init;
    }

    // __u32 newstate = ctx->newstate;
    // if (newstate >= STATE_MAX)
    //     return 0;  // 不合法
    // __sync_fetch_and_add(&sc->count[newstate], 1);
    // verfier NO PASS
    __u32 newstate = ctx->newstate;
    if (newstate >= STATE_MAX)
        return 0;

    if (sc) {
        switch (newstate) {
            case 0: __sync_fetch_and_add(&sc->count[0], 1); break;
            case 1: __sync_fetch_and_add(&sc->count[1], 1); break;
            case 2: __sync_fetch_and_add(&sc->count[2], 1); break;
            case 3: __sync_fetch_and_add(&sc->count[3], 1); break;
            case 4: __sync_fetch_and_add(&sc->count[4], 1); break;
            case 5: __sync_fetch_and_add(&sc->count[5], 1); break;
            case 6: __sync_fetch_and_add(&sc->count[6], 1); break;
            case 7: __sync_fetch_and_add(&sc->count[7], 1); break;
            case 8: __sync_fetch_and_add(&sc->count[8], 1); break;
            case 9: __sync_fetch_and_add(&sc->count[9], 1); break;
            case 10: __sync_fetch_and_add(&sc->count[10], 1); break;
            default: break;
        }
    }



    // if (ctx->newstate < STATE_MAX)
    //     __sync_fetch_and_add(&sc->count[ctx->newstate], 1);



    // 触发条件检测（例如观察到5次以上状态转移）
    __u64 total = 0;
    for (int i = 0; i < STATE_MAX; i++) total += sc->count[i];
    if (total < MIN_OBSERVE_THRESHOLD) return 0;

    // KL 散度计算：D(P || Q)
    __u64 P[STATE_MAX] = {};
    for (int i = 0; i < STATE_MAX; i++) P[i] = sc->count[i];

    __s64 kl_q32 = 0;
    __u64 sum_p = 0;

    for (int i = 0; i < STATE_MAX; i++) sum_p += P[i];
    if (sum_p == 0) return 0;

    for (int i = 0; i < STATE_MAX; i++) {
        if (P[i] == 0) continue;
        __u32 k = (__u32)(ctx->newstate * STATE_MAX + i);
        __u32 *Q_ptr = bpf_map_lookup_elem(&baseline_map, &k);
        if (!Q_ptr || *Q_ptr == 0) continue;

        __u64 p_q32 = (P[i] << 32) / sum_p;  // 整数->Q32.32
        __u64 q_q32 = *Q_ptr;
        __u64 ratio = (p_q32 << 32) / q_q32; // Q32.32->Q64.64

        __s64 log_r = log_lookup((__u32)(ratio >> 32));  // Q64.64->Q32.32  

        kl_q32 += (__s64)((p_q32 >> 16) * (log_r >> 16));  // 保持有符号.近似
    }

    if (kl_q32 > KL_THRESHOLD_Q32){
        struct alert_key *alert;
        alert = bpf_ringbuf_reserve(&alert_map, sizeof(*alert), 0);
        if (alert) {
            __builtin_memcpy(&alert->conn, &id, sizeof(id));
            alert->kl_q32 = kl_q32;
            bpf_ringbuf_submit(alert, 0);
        }
    }

    return 0;
}
