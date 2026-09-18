import json
import glob
import os

configs = [
    "coredns_intensive",
    "etcd_intensive",
    "etcd_data_heavy",
    "geth_evm_heavy",
    "geth_evm_refined"
]

def load_metrics(profile):
    base_path = f"/home/brego/Documents/Uni/Tesi/goste/benchmark/results/{profile}"
    res = {}
    for mode in ["baseline", "trace", "enforce"]:
        try:
            with open(f"{base_path}_{mode}_metrics.json", "r") as f:
                res[mode] = json.load(f)
        except Exception:
            pass
    return res

def format_num(val, metric):
    if metric == "p50_latency_ms":
        return f"{val:.2f}"
    else:
        return f"{round(val):,}"

metrics_to_print = [
    ("cpu_user_ms", "CPU User"),
    ("cpu_sys_ms", "CPU Sys"),
    ("vol_ctx_switches", "Vol Ctx"),
    ("invol_ctx_switches", "Invol Ctx"),
    ("wall_time_ms", "Wall Time"),
    ("throughput_req_per_sec", "Throughput"),
    ("p50_latency_ms", "P50 Latency")
]

for cfg in configs:
    data = load_metrics(cfg)
    if not data: continue
    
    print(f"\n--- {cfg.upper()} ---")
    for key, name in metrics_to_print:
        try:
            b = data["baseline"][key]
            t = data["trace"][key]
            e = data["enforce"][key]
            print(f"{name}: Baseline {format_num(b, key)} | Trace {format_num(t, key)} | Enforce {format_num(e, key)}")
        except KeyError:
            pass
