"""
report.py – Generate benchmark reports from raw result data.

Produces two outputs in the results/ directory:
  • report.csv  – one row per run, all raw metric columns
  • report.txt  – human-readable summary with averages, std-dev and
                  overhead percentages relative to baseline
"""

from __future__ import annotations

import csv
import json
import math
import os
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Column ordering in the CSV ─────────────────────────────────────────────────
_METRIC_COLS = [
    "cpu_user_ms",
    "cpu_sys_ms",
    "cpu_total_ms",
    "rss_mb_peak",
    "rss_mb_avg",
    "voluntary_ctx",
    "involuntary_ctx",
    "threads_peak",
    "wall_time_ms",
    "samples",
]

_GOSTE_METRIC_COLS = [f"goste_{c}" for c in _METRIC_COLS]

_CSV_HEADER = (
    ["target", "mode", "run"]
    + _METRIC_COLS
    + _GOSTE_METRIC_COLS
)


# ── CSV ────────────────────────────────────────────────────────────────────────

def write_csv(results: List[Dict[str, Any]], output_path: str) -> None:
    """
    Write a flat CSV file where each row corresponds to one run.

    Parameters
    ----------
    results:
        List of run-result dicts as returned by the harness.
    output_path:
        Destination file path.
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_HEADER, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            target_metrics = r.get("target_metrics") or {}
            goste_metrics  = r.get("goste_metrics")  or {}
            row: Dict[str, Any] = {
                "target": r["target"],
                "mode":   r["mode"],
                "run":    r["run"],
            }
            for col in _METRIC_COLS:
                row[col] = _fmt(target_metrics.get(col))
            for col in _METRIC_COLS:
                row[f"goste_{col}"] = _fmt(goste_metrics.get(col))
            writer.writerow(row)


def _fmt(v: Optional[float]) -> str:
    if v is None:
        return ""
    if isinstance(v, float):
        return f"{v:.3f}"
    return str(v)


# ── Human-readable summary ────────────────────────────────────────────────────

def write_summary(results: List[Dict[str, Any]], output_path: str) -> None:
    """
    Write a formatted text report with per-target tables showing averages,
    std-devs and overhead percentages relative to the baseline mode.
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    lines: List[str] = []

    lines.append("=" * 88)
    lines.append("  GoSTE Benchmark Report")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 88)
    lines.append("")

    # Group results by target
    targets: Dict[str, List[Dict]] = {}
    for r in results:
        targets.setdefault(r["target"], []).append(r)

    for tname, runs in targets.items():
        # Group runs by mode
        by_mode: Dict[str, List[Dict]] = {}
        for r in runs:
            by_mode.setdefault(r["mode"], []).append(r)

        num_runs = max(len(v) for v in by_mode.values())
        lines.append(f"Target: {tname}   |   Runs per mode: {num_runs}")
        lines.append("-" * 88)

        # Compute averages per mode
        mode_stats: Dict[str, Dict[str, float]] = {}
        for mode, mode_runs in by_mode.items():
            stats: Dict[str, float] = {}
            for col in _METRIC_COLS:
                vals = [
                    r["target_metrics"][col]
                    for r in mode_runs
                    if r.get("target_metrics") and col in r["target_metrics"]
                ]
                if vals:
                    stats[f"{col}_mean"] = statistics.mean(vals)
                    stats[f"{col}_stdev"] = statistics.stdev(vals) if len(vals) > 1 else 0.0
            mode_stats[mode] = stats

        baseline = mode_stats.get("baseline", {})

        # Print table
        col_w = 20
        modes = ["baseline", "tracing", "enforcement"]
        modes_present = [m for m in modes if m in mode_stats]

        # Header
        hdr = f"{'Metric':<22}" + "".join(f"{m:>{col_w}}" for m in modes_present)
        lines.append(hdr)
        lines.append("  " + "─" * (22 + col_w * len(modes_present) - 2))

        # Rows
        interesting_cols = [
            ("cpu_user_ms",     "CPU user (ms)"),
            ("cpu_sys_ms",      "CPU sys  (ms)"),
            ("cpu_total_ms",    "CPU total (ms)"),
            ("rss_mb_peak",     "RSS peak (MB)"),
            ("voluntary_ctx",   "Vol. ctx-sw"),
            ("involuntary_ctx", "Invol. ctx-sw"),
            ("threads_peak",    "Peak threads"),
            ("wall_time_ms",    "Wall time (ms)"),
        ]

        for col, label in interesting_cols:
            key = f"{col}_mean"
            row = f"{label:<22}"
            base_val = baseline.get(key)
            for mode in modes_present:
                val = mode_stats[mode].get(key)
                if val is None:
                    row += f"{'N/A':>{col_w}}"
                    continue
                cell = _human(col, val)
                if mode != "baseline" and base_val and base_val > 0:
                    pct = (val - base_val) / base_val * 100
                    sign = "+" if pct >= 0 else ""
                    cell = f"{cell} ({sign}{pct:.0f}%)"
                row += f"{cell:>{col_w}}"
            lines.append(row)

        # GoSTE overhead section: real overhead = delta between baseline and tracing/enforcement
        # Note: GoSTE eBPF code runs in the context of the target process, so its cost
        # appears in the target's cpu_sys_ms, not in the GoSTE wrapper process metrics.
        goste_modes = [m for m in modes_present if m != "baseline"]
        if goste_modes and baseline:
            lines.append("")
            lines.append("  GoSTE overhead (delta over baseline):")
            for mode in goste_modes:
                ms = mode_stats.get(mode, {})
                d_cpu_sys  = ms.get("cpu_sys_ms_mean",  0) - baseline.get("cpu_sys_ms_mean",  0)
                d_cpu_user = ms.get("cpu_user_ms_mean", 0) - baseline.get("cpu_user_ms_mean", 0)
                d_wall     = ms.get("wall_time_ms_mean", 0) - baseline.get("wall_time_ms_mean", 0)
                base_wall  = baseline.get("wall_time_ms_mean", 1)
                pct_wall   = d_wall / base_wall * 100 if base_wall else 0
                goste_rss_vals = [
                    r["goste_metrics"]["rss_mb_peak"]
                    for r in by_mode.get(mode, [])
                    if r.get("goste_metrics") and "rss_mb_peak" in r["goste_metrics"]
                ]
                goste_rss = statistics.mean(goste_rss_vals) if goste_rss_vals else 0.0
                lines.append(
                    f"    {mode:<14}  "
                    f"Δcpu_sys={d_cpu_sys:>+8.0f} ms   "
                    f"Δcpu_user={d_cpu_user:>+8.0f} ms   "
                    f"Δwall={d_wall:>+7.0f} ms ({pct_wall:>+.1f}%)   "
                    f"goste_rss={goste_rss:>5.1f} MB"
                )

        lines.append("")

    lines.append("=" * 88)
    lines.append("  End of Report")
    lines.append("=" * 88)

    with open(output_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_report(
    results: List[Dict[str, Any]],
    results_dir: str = "results",
) -> None:
    """
    Generate both report.csv and report.txt in *results_dir*.

    Parameters
    ----------
    results:
        Full list of run-result dicts.
    results_dir:
        Directory where reports are written.
    """
    csv_path = os.path.join(results_dir, "report.csv")
    txt_path = os.path.join(results_dir, "report.txt")

    write_csv(results, csv_path)
    print(f"[report] CSV written → {csv_path}")

    write_summary(results, txt_path)
    print(f"[report] Summary written → {txt_path}")


# ── Formatting helpers ────────────────────────────────────────────────────────

def _human(col: str, val: float) -> str:
    """Format a metric value into a concise human-readable string."""
    if "ms" in col:
        return f"{val:,.0f}"
    if "mb" in col.lower():
        return f"{val:.1f}"
    if "ctx" in col or "threads" in col or "samples" in col:
        return f"{val:,.0f}"
    return f"{val:.2f}"


# ── CLI convenience ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python report.py <raw_results.json> [results_dir]")
        sys.exit(1)

    raw_file = sys.argv[1]
    out_dir  = sys.argv[2] if len(sys.argv) > 2 else "results"

    with open(raw_file) as fh:
        data = json.load(fh)

    generate_report(data, out_dir)
