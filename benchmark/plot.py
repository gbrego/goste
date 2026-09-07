#!/usr/bin/env python3
"""
GoSTE Macrobenchmark Visualization
Generates publication-ready PDF figures for the thesis.
Restructured to output graphs per application/workload.
"""

import os
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import matplotlib.ticker as ticker

# ── Academic styling ─────────────────────────────────────────────────────────
plt.style.use('default')
plt.rcParams.update({
    'font.size': 12,
    'font.family': 'serif',
    'axes.labelsize': 14,
    'axes.titlesize': 16,
    'axes.titleweight': 'bold',
    'xtick.labelsize': 12,
    'ytick.labelsize': 12,
    'legend.fontsize': 10,
    'legend.framealpha': 0.9,
    'figure.dpi': 300,
    'savefig.dpi': 300,
})

COLORS = {
    'baseline':      '#4E79A7',
    'tracing':       '#59A14F',
    'enforcement':   '#E15759',
}

HATCHES = {
    'baseline':      '',
    'tracing':       '//',
    'enforcement':   '\\\\',
}

MODES = ['baseline', 'tracing', 'enforcement']

def load_data():
    csv_path = 'results/report.csv'
    if not os.path.exists(csv_path):
        print(f"Error: {csv_path} not found.")
        return None, None
    df = pd.read_csv(csv_path)
    
    json_path = 'results/raw_results.json'
    raw_data = []
    if os.path.exists(json_path):
        with open(json_path, 'r') as f:
            raw_data = json.load(f)
            
    return df, raw_data

def get_app_profile(target_str):
    if '_' not in target_str:
        return target_str, 'default'
    parts = target_str.split('_', 1)
    return parts[0], parts[1]

def plot_single_metric(df_target, metric, ylabel, title, out_path):
    # df_target contains data for one target (e.g., etcd_light) across runs and modes
    if metric not in df_target.columns or df_target[metric].dropna().empty:
        return
        
    agg = df_target.groupby('mode')[metric].agg(['mean', 'std'])
    
    modes_present = [m for m in MODES if m in agg.index]
    if not modes_present:
        return
        
    means = [agg.loc[m, 'mean'] for m in modes_present]
    errs = [agg.loc[m, 'std'] for m in modes_present]
    colors = [COLORS[m] for m in modes_present]
    hatches = [HATCHES[m] for m in modes_present]
    
    fig, ax = plt.subplots(figsize=(5, 5))
    x = np.arange(len(modes_present))
    
    bars = ax.bar(x, means, yerr=errs, capsize=6, edgecolor='black', color=colors, width=0.75)
    for bar, hatch in zip(bars, hatches):
        bar.set_hatch(hatch)
        
    max_val = max(means) if means else 1
    baseline_val = means[modes_present.index('baseline')] if 'baseline' in modes_present else None
    
    for i, bar in enumerate(bars):
        h = bar.get_height()
        err = errs[i] if pd.notnull(errs[i]) else 0
        if h > 0:
            fmt = f'{h:,.0f}' if h >= 10 else f'{h:,.1f}'
            
            mode = modes_present[i]
            if mode != 'baseline' and baseline_val is not None and baseline_val > 0:
                diff = h - baseline_val
                pct = (diff / baseline_val) * 100
                sign = '+' if pct > 0 else ''
                fmt += f'\n({sign}{pct:.1f}%)'
                
            ax.text(bar.get_x() + bar.get_width()/2,
                    h + err + max_val * 0.02, fmt,
                    ha='center', va='bottom', fontsize=10,
                    fontweight='bold')
        
    current_ylim = ax.get_ylim()
    ax.set_ylim(current_ylim[0], current_ylim[1] * 1.15)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_xticklabels([m.capitalize() for m in modes_present])
    ax.grid(False)
    
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)

def plot_cpu_stacked(df_target, title, out_path):
    if 'cpu_user_ms' not in df_target.columns or 'cpu_sys_ms' not in df_target.columns:
        return
        
    agg_user = df_target.groupby('mode')['cpu_user_ms'].agg(['mean'])
    agg_sys = df_target.groupby('mode')['cpu_sys_ms'].agg(['mean'])
    
    modes_present = [m for m in MODES if m in agg_user.index and m in agg_sys.index]
    if not modes_present:
        return
        
    user_means = [agg_user.loc[m, 'mean'] for m in modes_present]
    sys_means = [agg_sys.loc[m, 'mean'] for m in modes_present]
    
    fig, ax = plt.subplots(figsize=(5, 5))
    x = np.arange(len(modes_present))
    
    user_color = '#F28E2B'
    sys_color = '#76B7B2'
    
    # Bottom bar (Sys)
    bars_sys = ax.bar(x, sys_means, label='System CPU', edgecolor='black', color=sys_color, width=0.75)
    # Top bar (User)
    bars_user = ax.bar(x, user_means, bottom=sys_means, label='User CPU', edgecolor='black', color=user_color, width=0.75)
    
    # We can also add a hatch to distinguish modes if we want, but since x-axis is already modes, it's clear
    totals = [u + s for u, s in zip(user_means, sys_means)]
    max_val = max(totals) if totals else 1
    baseline_val = totals[modes_present.index('baseline')] if 'baseline' in modes_present else None
    
    for i, bar in enumerate(bars_user):
        tot = totals[i]
        if tot > 0:
            fmt = f'{tot:,.0f}' if tot >= 10 else f'{tot:,.1f}'
            
            mode = modes_present[i]
            if mode != 'baseline' and baseline_val is not None and baseline_val > 0:
                diff = tot - baseline_val
                pct = (diff / baseline_val) * 100
                sign = '+' if pct > 0 else ''
                fmt += f'\n({sign}{pct:.1f}%)'
                
            ax.text(bar.get_x() + bar.get_width()/2,
                    tot + max_val * 0.02, fmt,
                    ha='center', va='bottom', fontsize=10,
                    fontweight='bold')
                    
    current_ylim = ax.get_ylim()
    ax.set_ylim(current_ylim[0], current_ylim[1] * 1.15)
    ax.set_ylabel('CPU Time (ms)')
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_xticklabels([m.capitalize() for m in modes_present])
    ax.grid(False)
    ax.legend()
    
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)

def generate_latency_dist_for_target(target, dist_list, out_path):
    # dist_list is a dict of mode -> list of dists
    fig, ax = plt.subplots(figsize=(8, 5))
    
    plotted = False
    for mode in MODES:
        if mode not in dist_list:
            continue
            
        all_pcts = {}
        for dist in dist_list[mode]:
            for p, v in dist.items():
                p = float(p)
                all_pcts.setdefault(p, []).append(v)
                
        avg_dist = {p: np.mean(v) for p, v in all_pcts.items()}
        if not avg_dist:
            continue
            
        percentiles = sorted(avg_dist.keys())
        values = [avg_dist[p] for p in percentiles]
        min_val = min(v for v in values if v > 0) if any(v > 0 for v in values) else 1e-3
        log_values = np.log10([max(v, min_val) for v in values])
        
        uniform_samples = np.linspace(min(percentiles), max(percentiles), 10000)
        try:
            from scipy.interpolate import PchipInterpolator
            interp = PchipInterpolator(percentiles, log_values)
            synthetic_log_values = interp(uniform_samples)
        except ImportError:
            synthetic_log_values = np.interp(uniform_samples, percentiles, log_values)
            
        try:
            from scipy.stats import gaussian_kde
            kde = gaussian_kde(synthetic_log_values, bw_method='scott')
            range_span = max(log_values) - min(log_values)
            if range_span == 0: range_span = 1.0
            log_x_min = min(log_values) - range_span * 0.2
            log_x_max = max(log_values) + range_span * 0.2
            log_x_eval = np.linspace(log_x_min, log_x_max, 500)
            y_eval = kde(log_x_eval)
        except ImportError:
            n = len(synthetic_log_values)
            std_dev = np.std(synthetic_log_values)
            bw = (n ** (-1/5.0)) * std_dev * 1.5
            if bw == 0: bw = 0.1
            range_span = max(log_values) - min(log_values)
            if range_span == 0: range_span = 1.0
            log_x_min = min(log_values) - range_span * 0.2
            log_x_max = max(log_values) + range_span * 0.2
            log_x_eval = np.linspace(log_x_min, log_x_max, 500)
            diff = log_x_eval[:, None] - synthetic_log_values[None, :]
            y_eval = np.exp(-0.5 * (diff / bw) ** 2).sum(axis=1)
            y_eval /= (bw * np.sqrt(2 * np.pi) * n)
        x_eval = 10 ** log_x_eval
        
        ax.plot(x_eval, y_eval, label=mode.capitalize(), color=COLORS[mode], linewidth=2)
        ax.fill_between(x_eval, y_eval, alpha=0.2, color=COLORS[mode])
        plotted = True
        
        # Log scale formatting
        ax.set_xscale('log')
        from matplotlib.ticker import LogLocator, FuncFormatter
        if target in ['etcd_data_heavy', 'etcd_intensive', 'geth_cgo']:
            subs = (1.0, 2.0, 5.0)
        elif range_span < 1.5:
            subs = (1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0)
        elif range_span < 3.0:
            subs = (1.0, 2.0, 5.0)
        else:
            subs = (1.0,)
        ax.xaxis.set_major_locator(LogLocator(base=10.0, subs=subs))
        ax.xaxis.set_major_formatter(FuncFormatter(lambda x, pos: f"{x:g}"))
        ax.xaxis.set_minor_locator(ticker.NullLocator())
        ax.grid(False)

    if plotted:
        ax.set_xlabel('Latency (ms)')
        ax.set_ylabel('Density')
        ax.set_title(f'Latency Distribution')
        ax.legend()
        fig.tight_layout()
        fig.savefig(out_path)
    plt.close(fig)

def main():
    print("Generating Workload-specific Benchmark Plots...")
    df, raw_data = load_data()
    if df is None:
        return
        
    # Organize raw_data by target -> mode -> list of distributions
    dist_data = {}
    if raw_data:
        for r in raw_data:
            t = r.get('target')
            m = r.get('mode')
            lg = r.get('lg_metrics')
            if not t or not m or not lg or not lg.get('lg_latency_dist'): continue
            dist = lg['lg_latency_dist']
            dist_data.setdefault(t, {}).setdefault(m, []).append(dist)

    targets = df['target'].unique()
    
    for target in targets:
        app, profile = get_app_profile(target)
        out_dir = os.path.join('results', app, profile)
        os.makedirs(out_dir, exist_ok=True)
        
        df_target = df[df['target'] == target]
        
        # 1. Throughput
        plot_single_metric(df_target, 'lg_throughput', 'Requests / sec', 'Throughput', os.path.join(out_dir, 'throughput.pdf'))
        
        # 2. Walltime
        plot_single_metric(df_target, 'wall_time_ms', 'Time (ms)', 'Wall Time', os.path.join(out_dir, 'walltime.pdf'))
        
        # 3. CPU Stacked
        plot_cpu_stacked(df_target, 'CPU Usage', os.path.join(out_dir, 'cpu.pdf'))
        
        # 4. Latency Distribution
        if target in dist_data:
            generate_latency_dist_for_target(target, dist_data[target], os.path.join(out_dir, 'latency_dist.pdf'))
            
        print(f"  ✓ {app}/{profile}")

if __name__ == '__main__':
    main()
