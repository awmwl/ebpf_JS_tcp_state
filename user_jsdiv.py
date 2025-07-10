from collections import deque
import json
from bcc import BPF
import ctypes
import time
import math
import signal
import sys
import psutil


# 这里补充你的BPF程序代码，示例中map名字是state_counts，需要和你bpf代码保持一致
prog = """
#include <uapi/linux/ptrace.h>
#include <net/tcp.h>

struct key_t {
    u16 old_state;
    u16 new_state;
};

BPF_HASH(state_counts, struct key_t, u64);

int kprobe__tcp_set_state(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 old_state = sk->__sk_common.skc_state;
    u16 new_state = (u16)PT_REGS_PARM2(ctx);

    struct key_t key = {};
    key.old_state = old_state;
    key.new_state = new_state;

    u64 zero = 0, *val;
    val = state_counts.lookup_or_init(&key, &zero);
    (*val)++;

    return 0;
}
"""

b = BPF(text=prog)

class StateKey(ctypes.Structure):
    _fields_ = [
        ("old_state", ctypes.c_uint16),
        ("new_state", ctypes.c_uint16),
    ]

# 全局变量
baseline_probs = {}
SAMPLE_INTERVAL = 10  # 采样间隔秒数
WINDOW_SIZE = 6       # 滑动窗口长度，单位采样次数
js_threshold_alert = 0.6  # 瞬时JS散度阈值，超出立即预警
js_threshold_confirm = 0.8  # 平滑JS散度连续超标阈值
consecutive_exceed_needed = 1  # 连续超标次数判定攻击

window = deque(maxlen=WINDOW_SIZE)
consecutive_exceed_count = 0
js_plot = []

process = psutil.Process()

cpu_usage_list = []
mem_usage_list = []
timestamp_list = []
detection_result_list = []


def load_baseline(path="baseline.json"):
    global baseline_probs
    with open(path) as f:
        data = json.load(f)
    ref = data.get("probabilities", data.get("reference", {}))
    baseline_probs.clear()
    for key, val in ref.items():
        baseline_probs[key] = val

def calc_current_probs(counts):
    total_by_old = {}
    for (old, new), cnt in counts.items():
        total_by_old[old] = total_by_old.get(old, 0) + cnt
    probs = {}
    for (old, new), cnt in counts.items():
        total = total_by_old[old]
        if total > 0:
            probs[f"{old}-{new}"] = cnt / total
    return probs

def js_divergence(p, q, epsilon=1e-6):
    keys = set(p.keys()).union(q.keys())
    m = {k: 0.5 * (p.get(k, 0.0) + q.get(k, 0.0)) for k in keys}
    kl_pm = sum(p.get(k, 0.0) * math.log(p.get(k, 0.0) / max(m[k], epsilon)) for k in keys if p.get(k, 0.0) > 0)
    kl_qm = sum(q.get(k, 0.0) * math.log(q.get(k, 0.0) / max(m[k], epsilon)) for k in keys if q.get(k, 0.0) > 0)
    return 0.5 * (kl_pm + kl_qm)

def print_probs(probs):
    print("Current Probability Distribution:")
    for k, p in sorted(probs.items()):
        print(f"  P({k}) = {p:.4f}")

def signal_handler(sig, frame):
    print("\nExiting and saving state...")
    # 保存 JS 值列表到文件
    with open("js_plot.json", "w") as f:
        json.dump(js_plot, f)
    print(f"Saved JS instanted values to js_plot.json")
    # 保存资源消耗
    with open("resource_usage.csv", "w") as f:
        f.write("timestamp,cpu_percent,rss_mib\n")
        for t, c, m in zip(timestamp_list, cpu_usage_list, mem_usage_list):
            f.write(f"{t:.2f},{c:.2f},{m:.2f}\n")
    print(f"Saved resource usage to resource_usage.csv")
    with open("js_detection_output.json", "w") as f:
        json.dump(detection_result_list, f, indent=4)
    print(f"Saved Detection Result to js_detection_output.json")
 
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# 载入基准分布
load_baseline("baseline.json")
print("Baseline loaded. Starting monitoring...")

# 推荐：JS 值滑动窗口
js_window = deque(maxlen=WINDOW_SIZE)


while True:
    time.sleep(SAMPLE_INTERVAL)

    state_map = b.get_table("state_counts")
    raw_counts = {}

    for k, v in state_map.items():
        key = (k.old_state, k.new_state)
        raw_counts[key] = raw_counts.get(key, 0) + v.value

    current_probs = calc_current_probs(raw_counts)
    if len(current_probs) == 0:
        print("No state transitions captured in this interval.")
        continue

    # 计算瞬时JS散度
    instant_js = js_divergence(current_probs, baseline_probs)
    state_map.clear()

    js_window.append(instant_js)
    js_plot.append(instant_js)
    # smoothed_js = sum(js_window) / len(js_window)

    print(f"📊 Instant JS: {instant_js:.6f}")
    # print(f"📊 Smoothed JS (last {len(js_window)}): {smoothed_js:.6f}")

    # if instant_js > js_threshold_alert:
    #     print("[ALERT] Instant JS divergence spike detected!")

    if instant_js > js_threshold_confirm:
        print("[ALERT] Instant JS divergence spike detected!")
        consecutive_exceed_count += 1
        print(f"[WARNING] Smoothed JS divergence over threshold ({consecutive_exceed_count}/{consecutive_exceed_needed})")
        if consecutive_exceed_count >= consecutive_exceed_needed:
            print("[ATTACK DETECTED] TCP state transitions deviate significantly from baseline!")
            # 可加入后续响应策略
    else:
        consecutive_exceed_count = 0


    
    detection_result = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "js_divergence": instant_js,
        "threshold": js_threshold_confirm,
        "alert": instant_js > js_threshold_confirm,
        "top_diff_states": sorted(current_probs, key=lambda k: abs(current_probs.get(k, 0.0) - baseline_probs.get(k, 0.0)), reverse=True)[:3]
    }
    detection_result_list.append(detection_result)

    # 记录资源消耗
    cpu = process.cpu_percent(interval=None)  # 上一个采样点以来的平均CPU占用（百分比）
    mem = process.memory_info().rss / (1024 * 1024)  # 常驻内存，单位 MiB
    ts = time.time()

    cpu_usage_list.append(cpu)
    mem_usage_list.append(mem)
    timestamp_list.append(ts)


    # print_probs(current_probs)
    

