from datetime import datetime
from bcc import BPF
import time
import ctypes
import json
from collections import deque

SAMPLE_INTERVAL = 10  # 每次采样间隔（秒）
WINDOW_SIZE = 6       # 总共采样次数

prog = """
#include <uapi/linux/ptrace.h>
#include <net/tcp_states.h>

struct key_t {
    u16 old_state;
    u16 new_state;
};

BPF_HASH(state_counts, struct key_t, u64);

int kprobe__tcp_set_state(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 old = sk->__sk_common.skc_state;
    u16 new = (u16)PT_REGS_PARM2(ctx);

    struct key_t key = {};
    key.old_state = old;
    key.new_state = new;

    u64 zero = 0, *val;
    val = state_counts.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
}
"""

class Key(ctypes.Structure):
    _fields_ = [("old_state", ctypes.c_uint16),
                ("new_state", ctypes.c_uint16)]

b = BPF(text=prog)

def calc_prob_distribution(counts):
    total_by_old = {}
    for (old, new), cnt in counts.items():
        total_by_old[old] = total_by_old.get(old, 0) + cnt
    probs = {}
    for (old, new), cnt in counts.items():
        total = total_by_old[old]
        if total > 0:
            probs[f"{old}-{new}"] = cnt / total
    return probs

window = deque(maxlen=WINDOW_SIZE)

print("🚩 Begin short-term baseline sampling...")

for i in range(WINDOW_SIZE):
    time.sleep(SAMPLE_INTERVAL)

    raw_counts = {}
    state_map = b.get_table("state_counts")
    for k, v in state_map.items():
        key = (k.old_state, k.new_state)
        raw_counts[key] = raw_counts.get(key, 0) + v.value
    b["state_counts"].clear()  # 清空 map，避免累加

    prob_dist = calc_prob_distribution(raw_counts)
    window.append(prob_dist)

    print(f"✅ Sample {i+1}/{WINDOW_SIZE} collected.")

# （1）平均分布
avg_probs = {}
for sample in window:
    for key, p in sample.items():
        avg_probs[key] = avg_probs.get(key, 0.0) + p
for key in avg_probs:
    avg_probs[key] /= len(window)

# 保存到 JSON
output = {
    "duration_sec": SAMPLE_INTERVAL * WINDOW_SIZE,
    "probabilities": avg_probs
}


# （1）归一化平均分布
# step 1: 累加窗口内概率
prob_matrix = {}
total_by_old = {}

for sample in window:
    for key, prob in sample.items():
        old, new = map(int, key.split('-'))
        prob_matrix[(old, new)] = prob_matrix.get((old, new), 0.0) + prob

# step 2: 对每个 old_state 求平均
for (old, new) in prob_matrix:
    prob_matrix[(old, new)] /= len(window)

# step 3: 按 old_state 归一化，得到最终概率分布
final_probs = {}
row_sums = {}

for (old, new), p in prob_matrix.items():
    row_sums[old] = row_sums.get(old, 0.0) + p

for (old, new), p in prob_matrix.items():
    if row_sums[old] > 0:
        final_probs[f"{old}-{new}"] = p / row_sums[old]

# 保存到 JSON
output = {
    "duration_sec": SAMPLE_INTERVAL * WINDOW_SIZE,
    "probabilities": final_probs
}


filename = f"baseline_short{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
with open(filename, "w") as f:
    json.dump(output, f, indent=4)

print("✅ Short-term baseline saved to baseline_short.json")
