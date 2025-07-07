// shared.h
#ifndef __SHARED_H__
#define __SHARED_H__

#define STATE_MAX 11
#define LOG_INDEX_BITS 10
#define MIN_OBSERVE_THRESHOLD 6000

// KL 阈值（Q32.32 格式）
#define KL_THRESHOLD_Q32 0x80000000UL  // 0.5 in Q32.32 format

struct conn_id {
    __u32 saddr;
    __u32 daddr;
    __u16 dport;
    __u16 family;
};

struct state_count {
    __u64 count[STATE_MAX];
};

struct alert_key {
    struct conn_id conn;
    __s64 kl_q32;
};

#endif // __SHARED_H__
