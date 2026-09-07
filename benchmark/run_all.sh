#!/bin/bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# GoSTE Macrobenchmark Automation Script
# Runs all specified targets across all modes (baseline, tracing, enforcement).
# ─────────────────────────────────────────────────────────────────────────────

# List of targets to run
TARGETS=(
    "etcd_light"
    "etcd_intensive"
    "etcd_logic_heavy"
    "etcd_data_heavy"
    "coredns_intensive"
    "geth_intensive"
    "geth_evm_heavy"
    "geth_evm_refined"
    "geth_no_overhead"
    "geth_cgo"
)

# Optional config file parameter
CONFIG_FILE=${1:-config.yaml}

echo "============================================================"
echo " Starting GoSTE Macrobenchmarks (Config: $CONFIG_FILE)"
echo "============================================================"

# Ensure script is run as root, as GoSTE needs it
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (or use sudo)."
  exit 1
fi

# Determine script directory to run commands from the right path
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

# Join targets with multiple -t flags so harness runs once and collects everything
TARGET_ARGS=""
for TARGET in "${TARGETS[@]}"; do
    TARGET_ARGS="$TARGET_ARGS -t $TARGET"
done

echo ""
echo ">>> Benchmarking All Targets: ${TARGETS[*]} <<<"
python3 harness.py $TARGET_ARGS -c "$CONFIG_FILE"

echo ""
echo "============================================================"
echo " Benchmarking Complete."
echo " Generating Plots..."
echo "============================================================"

python3 plot.py

echo " Done! Check the benchmark/results/ directory for PDFs."
