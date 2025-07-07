// user.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h> // for ntohl

#include "baseline.h"   
#include "shared.h"
#include "tcp_state_entropy.skel.h"

extern int64_t baseline[STATE_MAX * STATE_MAX];

static volatile bool running = true;

static void handle_signal(int sig) {
    running = false;
}


void load_baseline_map(int map_fd) {
    for (int i = 0; i < STATE_MAX * STATE_MAX; i++) {
        uint32_t key = i;
        int64_t val = baseline_probs[i];
        if (val == 0) continue; // 可选

        int err = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to update baseline_map at key %d: %d\n", key, err);
        }
    }
    printf("Baseline map loaded successfully.\n");
}


static int print_alert(void *ctx, void *data, size_t len) {
    struct alert_key *a = data;
    printf("\n[ALERT] KL divergence = %.6f\n", (double)a->kl_q32 / (1ULL << 32));

    uint32_t saddr = ntohl(a->conn.saddr);
    uint32_t daddr = ntohl(a->conn.daddr);

    printf("  Src: %u.%u.%u.%u\n",
        (saddr >> 24) & 0xFF,
        (saddr >> 16) & 0xFF,
        (saddr >> 8) & 0xFF,
        saddr & 0xFF);
    printf("  Dst: %u.%u.%u.%u:%u\n",
        (daddr >> 24) & 0xFF,
        (daddr >> 16) & 0xFF,
        (daddr >> 8) & 0xFF,
        daddr & 0xFF,
        a->conn.dport);
    return 0;
}

int main(int argc, char **argv) {
    struct tcp_state_entropy_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = tcp_state_entropy_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open skeleton\n");
        return 1;
    }

    err = tcp_state_entropy_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load skeleton: %d\n", err);
        return 1;
    }

    err = tcp_state_entropy_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach skeleton: %d\n", err);
        return 1;
    }

    int baseline_map_fd = bpf_map__fd(skel->maps.baseline_map);
    if (baseline_map_fd < 0) {
        fprintf(stderr, "Failed to get baseline_map fd\n");
        return 1;
    }

    load_baseline_map(baseline_map_fd);

    int alert_map_fd = bpf_map__fd(skel->maps.alert_map);
    rb = ring_buffer__new(alert_map_fd, print_alert, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("KL divergence detector started. Press Ctrl+C to exit...\n");

    while (running) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err == -EINTR)
            break;
    }

    ring_buffer__free(rb);
    tcp_state_entropy_bpf__destroy(skel);
    return 0;
}
