import json
import math

STATE_MAX = 11  # 根据你实际状态数调整

LOG_LOOKUP_SIZE = 512  # 可调节大小，推荐 >= 256
FIXED_POINT_SHIFT = 32

RATIO_MIN = 0.01
RATIO_MAX = 100.0

def float_to_q32_32(x):
    return int(x * (1 << FIXED_POINT_SHIFT) + 0.5)

# 用的是 Q32.32 格式，它的底层表示是 int64_t 或 uint64_t 类型的整数。
# 原理：浮点 → Q32.32 定点数
# （1）用 uint64_t 表示的定点格式；
# （2）实数 x → 转换为：int(x * 2^32)；
# （3）用来避免内核态 eBPF 不能使用浮点的问题。
# 转换公式：uint64_t fixed = (uint64_t)(float_val * 4294967296.0 + 0.5);

def load_kl():
    with open("baseline.json") as f:
        data = json.load(f)

    ref = data["reference"]

    baseline = [0] * (STATE_MAX * STATE_MAX)

    for key, val in ref.items():
        from_s, to_s = key.split("-")
        from_i = int(from_s)
        to_i = int(to_s)
        idx = from_i * STATE_MAX + to_i
        if idx >= len(baseline):
            print(f"Error: idx {idx} out of range for key {key}")
            continue
        baseline[idx] = float_to_q32_32(val)

    with open("baseline.h", "w") as f:
        f.write("// Generated baseline_probs array (Q32.32 fixed point)\n")
        f.write("#pragma once\n\n")
        f.write(f"#define STATE_MAX {STATE_MAX}\n\n")
        f.write("#include <stdint.h>\n\n")
        f.write("static const int64_t baseline_probs[STATE_MAX * STATE_MAX] = {\n")
        for i in range(STATE_MAX):
            row = baseline[i*STATE_MAX:(i+1)*STATE_MAX]
            f.write("    " + ", ".join(str(v) + "LL" for v in row) + ",\n")
        f.write("};\n")

def generate_log_table():
    table = []

    # log_min = math.log(RATIO_MIN)
    # log_max = math.log(RATIO_MAX)
    log_min = math.log(0.01)
    log_max = math.log(100)


    for i in range(LOG_LOOKUP_SIZE):
        # 在 log-space 中均匀采样
        log_x = log_min + (log_max - log_min) * i / (LOG_LOOKUP_SIZE - 1)
        x = math.exp(log_x)  # 恢复到 x 值（比例）
        log_val = math.log(x)  # 实际就是 log_x
        table.append(float_to_q32_32(log_val))

    return table



def generate_log_table2():
    LOG_LOOKUP_SIZE = 512
    x_min = RATIO_MIN
    x_max = RATIO_MAX

    table = []
    for i in range(LOG_LOOKUP_SIZE):
        x = x_min + (x_max - x_min) * i / (LOG_LOOKUP_SIZE - 1)
        log_val = math.log(x)
        table.append(float_to_q32_32(log_val))
    return table


def write_header(table, filename="log_table.h"):
    with open(filename, "w") as f:
        f.write("// Generated log_table where x ∈ [0.01, 100.0]\n")
        f.write("#pragma once\n\n")
        f.write(f"#define LOG_LOOKUP_SIZE {LOG_LOOKUP_SIZE}\n\n")
        f.write("#include <stdint.h>\n\n")
        f.write("static const int64_t log_table[LOG_LOOKUP_SIZE] = {\n")  # 改为 int64_t
        for i in range(0, len(table), 8):
            row = table[i:i+8]
            f.write("    " + ", ".join(f"{v}LL" for v in row) + ",\n")  # 改为 LL 后缀

        f.write("};\n")

if __name__ == "__main__":
    load_kl()
    print(f"✅ baseline.h generated\n")
    table = generate_log_table2()
    write_header(table)
    print(f"✅ log_table.h generated with range log(x) for x ∈ [{RATIO_MIN}, {RATIO_MAX}]")
