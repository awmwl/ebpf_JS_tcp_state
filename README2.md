### 🔍 `tcp_states_entropy.py`

* Lightweight user-space monitoring tool for TCP state transition analysis.
* Attaches to kernel function `tcp_set_state` via eBPF (`kprobe`) and tracks all TCP state changes.
* Computes **Shannon entropy** of the state distribution in a configurable time window (default: 5 seconds).
* Designed to detect anomalous TCP behavior (e.g., state retention under slow-rate DoS attacks).

#### ✅ Features:

* Real-time monitoring of all 12 Linux TCP states
* Periodic entropy calculation to reflect distribution uniformity
* Windowed count resetting and verification (ensures fresh stats)
* Terminal-friendly output with percentage bars for each state
* Built-in signal handling and safe exit

#### 🧠 What It Detects:

This script is particularly useful for identifying:

* 🐌 **Slow HTTP-based DoS attacks** (e.g., Slowloris)
* ⚖️ **TCP state imbalance**, such as `CLOSE_WAIT` accumulation
* 📉 **Entropy drops**, indicating anomalous or sustained retention in certain states

#### 💾 Collected Data (per window):

* **Total transitions**
* **Entropy value**
* **Per-state count and percentage**
* Optional map-reset verification for reliability

#### 🛠 How It Works:

* Uses `BCC` to compile and inject a small eBPF program that hooks `tcp_set_state()`
* Every 5 seconds (configurable), it reads counts from the eBPF map
* Computes entropy:

  $$
  H = -\sum_{i=1}^{n} p_i \log_2(p_i)
  $$
* Then resets the counters to start a new window cleanly

#### 📦 Dependencies:

* `bcc` (Python bindings)
* Linux kernel with eBPF support (v4.9+ recommended)
* `sudo` privileges

#### 🚀 Run:

```bash
sudo python3 tcp_states_entropy.py
```
![image](https://github.com/user-attachments/assets/74a914b7-385a-4d3b-837b-b55c4b530af8)

---

