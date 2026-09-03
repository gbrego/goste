#!/usr/bin/env python3
"""
GoSTE Microbenchmark Visualization
Generates publication-ready PDF figures for thesis inclusion.
"""

import os
import matplotlib.pyplot as plt
import numpy as np

# ── Academic styling ─────────────────────────────────────────────────────────
plt.style.use('seaborn-v0_8-whitegrid')
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

# Color palette — Tableau 10 (academic standard for data visualization)
COLORS = {
    'Baseline':      '#4E79A7',   # Tableau blue
    'Tracing':       '#59A14F',   # Tableau green
    'Enf. (Log)':    '#E15759',   # Tableau red
    'Enf. (Errno)':  '#8172B2',   # dark violet
}

HATCHES = {
    'Baseline':      '',
    'Tracing':       '//',
    'Enf. (Log)':    '\\\\',
    'Enf. (Errno)':  'xx',
}

# ── Data parsing ─────────────────────────────────────────────────────────────
FILES = {
    'Baseline':      'baseline.txt',
    'Tracing':       'tracing.txt',
    'Enf. (Log)':    'enforce_log.txt',
    'Enf. (Errno)':  'enforce_errno.txt',
}

def parse_benchmarks(filename):
    results = {}
    if not os.path.exists(filename):
        return results
    with open(filename) as f:
        for line in f:
            if not line.strip().startswith('Benchmark'):
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[-1] == 'ns/op':
                name = parts[0].split('-')[0].replace('Benchmark', '')
                val = float(parts[-2])
                results.setdefault(name, []).append(val)
    return {k: np.mean(v) for k, v in results.items()}

data = {}
for mode, fname in FILES.items():
    parsed = parse_benchmarks(fname)
    if parsed:
        data[mode] = parsed

if not data:
    print("No data found to plot. Exiting.")
    exit(0)

modes = [m for m in FILES if m in data]

def get(bench, mode):
    return data.get(mode, {}).get(bench, 0)


def annotate_bar(ax, x, val, baseline, max_val, fontsize=9):
    """Annotate a bar with value and overhead percentage."""
    if val <= 0:
        return
    overhead = val - baseline
    if abs(overhead) < 0.5:
        txt = f'{val:.1f} ns' if val < 10 else f'{val:.0f} ns'
    else:
        pct = (overhead / baseline) * 100 if baseline > 0 else 0
        if pct > 1:
            txt = f'{val:.0f} ns\n(+{pct:.0f}%)'
        else:
            txt = f'{val:.0f} ns\n(+{overhead:.1f})'
    ax.text(x, val + max_val * 0.03, txt,
            ha='center', va='bottom', fontsize=fontsize, fontweight='bold')


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 1 — Syscall Interception Overhead
# ══════════════════════════════════════════════════════════════════════════════
fig1, ax1 = plt.subplots(figsize=(7.5, 5))

bench = 'SyscallClose'
vals = [get(bench, m) for m in modes]
baseline_val = get(bench, 'Baseline')
x = np.arange(len(modes))

bars = ax1.bar(x, vals, width=0.55, edgecolor='black', linewidth=0.8,
               color=[COLORS[m] for m in modes],
               hatch=[HATCHES[m] for m in modes])

ax1.axhline(y=baseline_val, color=COLORS['Baseline'], linestyle='--',
            linewidth=1.2, alpha=0.7, label=f'Baseline ({baseline_val:.0f} ns)')

for i, (m, v) in enumerate(zip(modes, vals)):
    annotate_bar(ax1, i, v, baseline_val, max(vals))

ax1.set_ylabel('Latency (ns/op)')
ax1.set_title('Syscall Interception Overhead — close(-1)')
ax1.set_xticks(x)
ax1.set_xticklabels(modes)
ax1.set_ylim(0, max(vals) * 1.35)
ax1.legend(loc='upper left')
fig1.tight_layout()
fig1.savefig('fig_syscall_overhead.pdf', format='pdf', bbox_inches='tight')
plt.close(fig1)
print("  ✓ fig_syscall_overhead.pdf")


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 2 — State Transition (Uprobe) Overhead
# ══════════════════════════════════════════════════════════════════════════════
fig2, ax2 = plt.subplots(figsize=(7.5, 5))

bench = 'StateTransition'
vals = [get(bench, m) for m in modes]
baseline_val = get(bench, 'Baseline')
x = np.arange(len(modes))

bars = ax2.bar(x, vals, width=0.55, edgecolor='black', linewidth=0.8,
               color=[COLORS[m] for m in modes],
               hatch=[HATCHES[m] for m in modes])

for i, (m, v) in enumerate(zip(modes, vals)):
    annotate_bar(ax2, i, v, baseline_val, max(vals))

ax2.set_ylabel('Latency (ns/op)')
ax2.set_title('State Transition Overhead — Uprobe on StateTransitionTrigger()')
ax2.set_xticks(x)
ax2.set_xticklabels(modes)
ax2.set_ylim(0, max(vals) * 1.25)
fig2.tight_layout()
fig2.savefig('fig_state_transition.pdf', format='pdf', bbox_inches='tight')
plt.close(fig2)
print("  ✓ fig_state_transition.pdf")


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 3 — Goroutine Creation Overhead
# ══════════════════════════════════════════════════════════════════════════════
fig3, ax3 = plt.subplots(figsize=(7.5, 5))

bench = 'GoroutineCreation'
vals = [get(bench, m) for m in modes]
baseline_val = get(bench, 'Baseline')
x = np.arange(len(modes))

bars = ax3.bar(x, vals, width=0.55, edgecolor='black', linewidth=0.8,
               color=[COLORS[m] for m in modes],
               hatch=[HATCHES[m] for m in modes])

ax3.axhline(y=baseline_val, color=COLORS['Baseline'], linestyle='--',
            linewidth=1.2, alpha=0.7, label=f'Baseline ({baseline_val:.0f} ns)')

for i, (m, v) in enumerate(zip(modes, vals)):
    annotate_bar(ax3, i, v, baseline_val, max(vals), fontsize=8)

ax3.set_ylabel('Latency (ns/op)')
ax3.set_title('Goroutine Creation Overhead — runtime.newproc + runtime.runqput')
ax3.set_xticks(x)
ax3.set_xticklabels(modes)
ax3.set_ylim(0, max(vals) * 1.3)
ax3.legend(loc='upper left')
fig3.tight_layout()
fig3.savefig('fig_goroutine_creation.pdf', format='pdf', bbox_inches='tight')
plt.close(fig3)
print("  ✓ fig_goroutine_creation.pdf")


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 4 — Multi-Core Scalability
# ══════════════════════════════════════════════════════════════════════════════
pairs = [
    ('SyscallClose',    'ParallelSyscallClose',    'Syscall (close)'),
    ('StateTransition', 'ParallelStateTransition', 'State Transition'),
]

valid_pairs = [(s, p, l) for s, p, l in pairs
               if any(s in data.get(m, {}) and p in data.get(m, {}) for m in modes)]

if valid_pairs:
    fig4, axes = plt.subplots(1, len(valid_pairs),
                              figsize=(5.5 * len(valid_pairs), 5))
    if len(valid_pairs) == 1:
        axes = [axes]

    for ax, (seq_b, par_b, title) in zip(axes, valid_pairs):
        bar_w = 0.35
        x = np.arange(len(modes))

        seq_vals = [get(seq_b, m) for m in modes]
        par_vals = [get(par_b, m) for m in modes]

        bars1 = ax.bar(x - bar_w/2, seq_vals, bar_w, label='Sequential',
                       color='#4E79A7', edgecolor='black', linewidth=0.8)
        bars2 = ax.bar(x + bar_w/2, par_vals, bar_w, label='Parallel (16 threads)',
                       color='#F28E2B', edgecolor='black', linewidth=0.8, hatch='//')

        max_val = max(max(seq_vals), max(par_vals))
        for bar_group in [bars1, bars2]:
            for bar in bar_group:
                h = bar.get_height()
                if h > 0:
                    fmt = f'{h:.0f}' if h >= 10 else f'{h:.1f}'
                    ax.text(bar.get_x() + bar.get_width()/2,
                            h + max_val * 0.02, fmt,
                            ha='center', va='bottom', fontsize=8,
                            fontweight='bold')

        ax.set_ylabel('Latency (ns/op)')
        ax.set_title(title)
        ax.set_xticks(x)
        ax.set_xticklabels(modes)
        ax.set_ylim(0, max_val * 1.25)
        ax.legend(loc='upper left', fontsize=9)

    fig4.suptitle('Multi-Core Scalability: Sequential vs Parallel (16 threads)',
                  fontsize=14, fontweight='bold', y=1.02)
    fig4.tight_layout()
    fig4.savefig('fig_scalability.pdf', format='pdf', bbox_inches='tight')
    plt.close(fig4)
    print("  ✓ fig_scalability.pdf")


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 5 — Overhead Breakdown (horizontal bars, legend below)
# ══════════════════════════════════════════════════════════════════════════════
fig5, ax5 = plt.subplots(figsize=(8, 5))

benchmarks = ['SyscallClose', 'StateTransition', 'GoroutineCreation']
bench_labels = ['Syscall\n(close)', 'State\nTransition', 'Goroutine\nCreation']
overhead_modes = [m for m in modes if m != 'Baseline']

y = np.arange(len(benchmarks))
bar_h = 0.28
max_ov = 0

# Thinner hatches for horizontal bars (vertical lines look thicker at this scale)
THIN_HATCHES = {'Tracing': '//', 'Enf. (Log)': '\\\\', 'Enf. (Errno)': 'xx'}
prev_hatch_lw = plt.rcParams.get('hatch.linewidth', 1.0)
plt.rcParams['hatch.linewidth'] = 0.5

for j, m in enumerate(overhead_modes):
    overheads = []
    for b in benchmarks:
        base = get(b, 'Baseline')
        val = get(b, m)
        overheads.append(max(val - base, 0))
    max_ov = max(max_ov, max(overheads))

    bars = ax5.barh(y + j * bar_h, overheads, bar_h,
                    label=m, color=COLORS[m], edgecolor='black',
                    linewidth=0.8, hatch=THIN_HATCHES.get(m, ''))

    for bar, ov, b in zip(bars, overheads, benchmarks):
        if ov > 0:
            base = get(b, 'Baseline')
            pct = (ov / base) * 100 if base > 0 else 0
            lbl = f'+{ov:.0f} ns ({pct:.0f}%)'
            ax5.text(bar.get_width() + max_ov * 0.02,
                     bar.get_y() + bar.get_height() / 2,
                     lbl, va='center', fontsize=9, fontweight='bold')

ax5.set_xlabel('Overhead vs Baseline (ns/op)')
ax5.set_title('GoSTE Overhead Breakdown by Primitive')
ax5.set_yticks(y + bar_h)
ax5.set_yticklabels(bench_labels)
ax5.legend(loc='upper right', ncol=1, frameon=True, fancybox=True)
ax5.invert_yaxis()
ax5.set_xlim(0, max_ov * 1.45)
fig5.tight_layout()
fig5.savefig('fig_overhead_summary.pdf', format='pdf', bbox_inches='tight')
plt.close(fig5)
plt.rcParams['hatch.linewidth'] = prev_hatch_lw
print("  ✓ fig_overhead_summary.pdf")


print("\nAll figures generated successfully.")
