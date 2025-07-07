TARGET = tcp_state_entropy
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CLANG ?= clang
# 设置 build 目录
BUILD_DIR ?= $(abspath ../.build)

# libbpf 和 bpftool 的路径
LIBBPF_INCLUDE ?= $(abspath $(BUILD_DIR)/libbpf/usr/include)
LIBBPF_UAPI ?= $(abspath $(BUILD_DIR)/libbpf/usr/include/uapi)
LIBBPF_LINUX ?= $(abspath $(BUILD_DIR)/libbpf/usr/include/linux)
LIBBPF_OBJ ?= $(abspath $(BUILD_DIR)/libbpf)
LIBBPF_SRC ?= $(abspath ../libbpf/src)
BPFTOOL ?= $(abspath $(BUILD_DIR)/bpftool/bpftool)
# BPFTOOL_INCLUDE ?= $(abspath $(BUILD_DIR)/bpftool/libbpf/include)

# 静态库路径（请根据实际路径调整）
LIBBPF_A := $(LIBBPF_OBJ)/libbpf.a
LIBELF_A := /usr/lib/x86_64-linux-gnu/libelf.a
LIBZ_A   := /usr/lib/x86_64-linux-gnu/libz.a
LIBZSTD_A := /usr/lib/x86_64-linux-gnu/libzstd.a

# PROM_A := /usr/local/lib/libprom.a
# PROMHTTP_A := /usr/local/lib/libpromhttp.a

# 添加标准库路径
STDINC_PATH = /usr/include /usr/local/include


INCLUDES = -I$(LIBBPF_INCLUDE) -I$(LIBBPF_SRC) -I$(LIBBPF_LINUX)
LDFLAGS_STATIC = -static $(LIBBPF_A) $(LIBELF_A) $(LIBZ_A) $(LIBZSTD_A)
PROM_STATIC = $(PROM_A) $(PROMHTTP_A)

# 包含路径
# INCLUDES = -I$(LIBBPF_INCLUDE) -I$(LIBBPF_SRC) 
# LDFLAGS = -L$(LIBBPF_OBJ) -lbpf -I$(LIBBPF_UAPI)

# 用户程序源文件
BPF_C = $(TARGET).bpf.c
BPF_O = $(TARGET).bpf.o
USER_C = $(TARGET).c
USER_SKEL = $(TARGET).skel.h
SHARED_H = shared.h
BASELINE_H = baseline.h
LOG_TABLE_H = log_table.h
VMLINUX_H = vmlinux.h  # 不放在 BUILD_DIR 目录，保留在源目录


COMMON_H = $(SHARED_H)  $(BASELINE-H)  $(LOG_TABLE_H)


# 新增：单独构建用户态程序
.PHONY: all clean user
all: $(VMLINUX_H) $(BPF_O) $(USER_SKEL) $(TARGET)
user: $(TARGET)

$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# 编译内核态程序
$(BPF_O): $(BPF_C) $(VMLINUX_H) $(COMMON_H)
	$(CLANG) -O2 -g -Wall -target bpf \
	    -D __TARGET_ARCH_$(ARCH) \
		$(INCLUDES) \
	    -c $< -o $@
	llvm-strip -g $@

# 生成 skeleton
$(USER_SKEL): $(BPF_O)
	$(BPFTOOL) gen skeleton $< > $@

# 编译用户态程序
$(TARGET): $(USER_C) $(USER_SKEL) $(COMMON_H)
	gcc -g -O2 -Wall -o $(TARGET) $(USER_C)\
		$(INCLUDES) \
		$(LDFLAGS_STATIC) \
		$(PROM_STATIC)

# 清理构建产物
clean:
	-rm -f $(TARGET)
	-rm -f $(BPF_O)
	-rm -f $(USER_SKEL)
	-rm -f $(VMLINUX_H)