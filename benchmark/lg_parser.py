import re
from typing import Dict, Any, List

def parse_load_generator_output(binary: str, stdout_text: str) -> Dict[str, Any]:
    """
    Parses standard output from a load generator and extracts:
      - lg_throughput (requests/sec)
      - lg_latency_p50 (median latency in ms)
      - lg_latency_p99 (99th percentile latency in ms)
      - lg_latency_dist (dictionary of percentile -> latency in ms)
    """
    metrics = {
        "lg_throughput": None,
        "lg_latency_p50": None,
        "lg_latency_p99": None,
        "lg_latency_dist": {}
    }
    
    if not stdout_text:
        return metrics

    binary = binary.lower()
    
    if "hey" in binary:
        # Throughput
        m = re.search(r"Requests/sec:\s+([\d\.]+)", stdout_text)
        if m:
            metrics["lg_throughput"] = float(m.group(1))
            
        # Latency distribution (hey outputs seconds)
        # e.g., "  50% in 0.0123 secs"
        dist_matches = re.findall(r"(\d+)%\s+in\s+([\d\.]+)\s+secs", stdout_text)
        dist = {}
        for pct_str, val_str in dist_matches:
            pct = int(pct_str)
            val_ms = float(val_str) * 1000.0
            dist[pct] = val_ms
            if pct == 50:
                metrics["lg_latency_p50"] = val_ms
            elif pct == 99:
                metrics["lg_latency_p99"] = val_ms
        metrics["lg_latency_dist"] = dist

    elif "dnsperf" in binary:
        # Throughput
        m = re.search(r"Queries per second:\s+([\d\.]+)", stdout_text)
        if m:
            metrics["lg_throughput"] = float(m.group(1))
            
        avg_m = re.search(r"Average Latency \(s\):\s+([\d\.]+)", stdout_text)
        if avg_m:
            # We set p50 to avg if median missing, but we will calculate it precisely below
            metrics["lg_latency_p50"] = float(avg_m.group(1)) * 1000.0 
        
        # Parse latency histogram to compute percentiles
        hist_matches = re.findall(r"([\d\.]+)\s+-\s+([\d\.]+):\s+(\d+)", stdout_text)
        if hist_matches:
            buckets = []
            total_count = 0
            for start_s, end_s, count_str in hist_matches:
                mid_ms = (float(start_s) + float(end_s)) / 2.0 * 1000.0
                count = int(count_str)
                if count > 0:
                    buckets.append((mid_ms, count))
                    total_count += count
            
            if total_count > 0:
                buckets.sort(key=lambda x: x[0])
                percentiles_to_calc = [10, 25, 50, 75, 90, 95, 99, 99.9]
                dist = {}
                running_count = 0
                pct_idx = 0
                
                for mid_ms, count in buckets:
                    running_count += count
                    while pct_idx < len(percentiles_to_calc):
                        target_pct = percentiles_to_calc[pct_idx]
                        target_count = (target_pct / 100.0) * total_count
                        if running_count >= target_count:
                            if target_pct.is_integer():
                                dist[int(target_pct)] = mid_ms
                            else:
                                dist[target_pct] = mid_ms
                            
                            if target_pct == 50:
                                metrics["lg_latency_p50"] = mid_ms
                            elif target_pct == 99:
                                metrics["lg_latency_p99"] = mid_ms
                            pct_idx += 1
                        else:
                            break
                    if pct_idx >= len(percentiles_to_calc):
                        break
                
                metrics["lg_latency_dist"] = dist

    elif "benchmark-etcd" in binary or "etcd" in binary:
        # etcd benchmark outputs CSV-like or summary
        # Requests/sec: 1234.56
        m = re.search(r"Requests/sec:\s+([\d\.]+)", stdout_text)
        if m:
            metrics["lg_throughput"] = float(m.group(1))
            
        # Latency percentiles might be like:
        # "  50% in 0.0001 secs."
        # "  99.9% in 0.0032 secs."
        dist_matches = re.findall(r"([\d\.]+)%\s+in\s+([\d\.]+)\s+secs", stdout_text)
        dist = {}
        for pct_str, val_str in dist_matches:
            pct_val = float(pct_str)
            pct = int(pct_val) if pct_val.is_integer() else pct_val
            val_ms = float(val_str) * 1000.0
            dist[pct] = val_ms
            if pct == 50:
                metrics["lg_latency_p50"] = val_ms
            elif pct == 99:
                metrics["lg_latency_p99"] = val_ms
        metrics["lg_latency_dist"] = dist
        
    return metrics
