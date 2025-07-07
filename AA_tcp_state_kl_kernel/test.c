// #include "log_table.h"
// #include <stdio.h>
// #include <stdint.h>  // for int64_t, etc.

// #define LOG_LOOKUP_SIZE 512  // 如果你在 log_table.h 中未定义，确保补上

// // log_lookup 返回 Q32.32 的定点数结果
// static int64_t log_lookup(uint32_t x) {
//     if (x == 0)
//         x = 1;
//     int idx = x >> (32 - 9);  // 512-entry 表 -> 取 x 的高 9 位作为索引
//     if (idx >= LOG_LOOKUP_SIZE)
//         idx = LOG_LOOKUP_SIZE - 1;
//     return log_table[idx];  // Q32.32 格式的 log(x)
// }

// // 传入的是 Q32.32 格式的定点数
// static int64_t log_lookup_q32(uint64_t x_q32) {
//     if (x_q32 == 0)
//         x_q32 = 1;

//     // 取高 9 位，索引表
//     int idx = x_q32 >> (32 + 32 - 9);  // 即 >> 55
//     if (idx >= LOG_LOOKUP_SIZE)
//         idx = LOG_LOOKUP_SIZE - 1;

//     return log_table[idx];  // Q32.32 格式 log(x)
// }


// int main2() {

//     // 表示 3.0 的 Q64.64 定点数形式
//     uint64_t ratio_q64 = 3ULL << 32;

//     int64_t log_val_1 = log_lookup(ratio_q64 >> 32);

//     printf("log_val(3) ≈ %ld\n", log_val_1);

//     double log_val1 = (double)log_val_1 / (1LL << 32);

//     printf("log_lookup(3.0) ≈ %.6f\n", log_val1);






//     int64_t log_val_q32 = log_lookup_q32(ratio_q64);

//     printf("log_val_q32(3) ≈ %ld\n", log_val_q32);

//     double log_val2 = (double)log_val_q32 / (1LL << 32);

//     printf("log_lookup(3.0) ≈ %.6f\n", log_val2);


//     return 0;
// }



#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <stdlib.h>

#include "log_table.h"

#define RATIO_MIN 0.01
#define RATIO_MAX 100.0

int main() {
    double test_vals[] = {0.01, 0.1, 1.0, 10.0, 100.0};

    for (int i = 0; i < sizeof(test_vals)/sizeof(test_vals[0]); i++) {
        double x = test_vals[i];

        // 计算 log_table 的索引（与 Python 表一致）
        int idx = (int)(((x - RATIO_MIN) / (RATIO_MAX - RATIO_MIN)) * (LOG_LOOKUP_SIZE - 1) + 0.5);
        if (idx < 0) idx = 0;
        if (idx >= LOG_LOOKUP_SIZE) idx = LOG_LOOKUP_SIZE - 1;

        int64_t log_fixed = log_table[idx];
        double log_float = (double)log_fixed / (1LL << 32);
        double expected = log(x);

        printf("x = %.4f | log(x) = %.6f | lookup = %.6f | error = %.6f\n",
               x, expected, log_float, fabs(expected - log_float));
    }

    return 0;
}
