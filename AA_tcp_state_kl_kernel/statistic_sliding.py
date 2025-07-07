from bcc import BPF
import time
import ctypes
from collections import deque
import json
import signal
import sys
from datetime import datetime

prog = """
#include <uapi/linux/ptrace.h>
#include <net/tcp.h>

struct key_t {
    u16 old_state;
    u16 new_state;
};

BPF_HASH(state_trans_count, struct key_t, u64);

int kprobe__tcp_set_state(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 old_state = sk->__sk_common.skc_state;
    u16 new_state = (u16)PT_REGS_PARM2(ctx);

    struct key_t key = {};
    key.old_state = old_state;
    key.new_state = new_state;

    u64 zero = 0, *val;
    val = state_trans_count.lookup_or_init(&key, &zero);
    (*val)++;

    return 0;
}
"""

class Key(ctypes.Structure):
    _fields_ = [("old_state", ctypes.c_uint16),
                ("new_state", ctypes.c_uint16)]

b = BPF(text=prog)

WINDOW_SIZE = 6
SAMPLE_INTERVAL = 10
window = deque(maxlen=WINDOW_SIZE)

def calc_prob_distribution(counts):
    totals = {}
    for (old, new), count in counts.items():
        totals[old] = totals.get(old, 0) + count
    probs = {}
    for (old, new), count in counts.items():
        total = totals[old]
        if total > 0:
            probs[(old, new)] = count / total
        else:
            probs[(old, new)] = 0.0
    return probs

def print_probs(probs, duration_sec):
    print(f"Smoothed baseline probability distribution over last {duration_sec} seconds:")
    states = sorted(set(k[0] for k in probs.keys()))
    for old in states:
        print(f"From state {old}:")
        for new in range(11):
            p = probs.get((old, new), 0.0)
            print(f"  to {new}: {p:.4f}")
    print("-" * 60)

def save_probs_json(probs, duration_sec):
    # JSON 结构：{ "duration_sec": xxx, "probabilities": { "old-new": prob, ... } }
    json_data = {
        "duration_sec": duration_sec,
        "probabilities": { f"{old}-{new}": p for (old,new), p in probs.items() }
    }
    filename = f"baseline__probs_sliding{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(json_data, f, indent=4)
    print(f"Baseline saved to {filename}")

def signal_handler(sig, frame):
    # Ctrl+C 触发，保存并退出
    if len(window) == 0:
        print("No data collected.")
        sys.exit(0)
    count_samples = len(window)
    avg_probs = {}
    for sample in window:
        for key, p in sample.items():
            avg_probs[key] = avg_probs.get(key, 0.0) + p
    for key in avg_probs:
        avg_probs[key] /= count_samples
    duration_sec = count_samples * SAMPLE_INTERVAL
    print_probs(avg_probs, duration_sec)
    save_probs_json(avg_probs, duration_sec)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

print("Starting baseline collection, press Ctrl+C to stop and save.")

try:
    while True:
        time.sleep(SAMPLE_INTERVAL)
        counts = {}
        state_map = b.get_table("state_trans_count")
        for k, v in state_map.items():
            counts[(k.old_state, k.new_state)] = v.value

        current_probs = calc_prob_distribution(counts)
        window.append(current_probs)

        # 每次也打印当前平滑概率
        count_samples = len(window)
        avg_probs = {}
        for sample in window:
            for key, p in sample.items():
                avg_probs[key] = avg_probs.get(key, 0.0) + p
        for key in avg_probs:
            avg_probs[key] /= count_samples

        print_probs(avg_probs, count_samples * SAMPLE_INTERVAL)

except Exception as e:
    print(f"Error: {e}")
