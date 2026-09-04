#!/bin/bash
set -e

# Change directory to the script's location
cd "$(dirname "$0")"

echo "============================================="
echo "   GoSTE Microbenchmarks Automation Script   "
echo "============================================="

if ! command -v benchstat &> /dev/null; then
    echo ""
    echo "Warning: benchstat is not installed."
    echo "You can install it with: go install golang.org/x/perf/cmd/benchstat@latest"
    echo "Continuing anyway... results will be in raw text format."
    echo ""
fi

echo "[1/4] Building Microbenchmarks..."
go test -c -o micro.test
echo "Built micro.test"

# Find the exact symbol name for StateTransitionTrigger
SYMBOL=$(nm micro.test | awk '$3 ~ /StateTransitionTrigger/ {print $3}' | head -n 1)
if [ -z "$SYMBOL" ]; then
    echo "Error: Could not find StateTransitionTrigger symbol in micro.test"
    exit 1
fi
echo "Found State transition symbol: $SYMBOL"

# Ensure goste is built
echo ""
echo "[2/4] Building goste (in root directory)..."
pushd ../../ > /dev/null
make build
popd > /dev/null

BENCH_COUNT=1
BENCH_TIME="1s"

echo ""
echo "============================================="
echo "Running Benchmarks (this may take a few minutes)"
echo "Note: sudo may prompt for your password for tracing."
echo "============================================="

echo ""
echo "--- Running Baseline ---"
./micro.test -test.run=^$ -test.bench . -test.benchtime ${BENCH_TIME} -test.count ${BENCH_COUNT} > baseline.txt
echo "Baseline completed."

echo ""
echo "--- Generating Enforcement Policy ---"
# Run benchmarks briefly under goste trace to capture all syscalls (close, clone, futex, etc.)
sudo ../../goste trace -s "$SYMBOL" -o micro_policy.json -- ./micro.test -test.run=^$ -test.bench . -test.benchtime 1s -test.count 1 > /dev/null
echo "Policy generated: micro_policy.json"

echo ""
echo "--- Running Tracing Mode ---"
sudo ../../goste trace -s "$SYMBOL" -- ./micro.test -test.run=^$ -test.bench . -test.benchtime ${BENCH_TIME} -test.count ${BENCH_COUNT} > tracing.txt
echo "Tracing completed."

echo ""
echo "--- Running Enforcement Mode (Log) ---"
sudo ../../goste enforce -a log micro_policy.json ./micro.test -test.run=^$ -test.bench . -test.benchtime ${BENCH_TIME} -test.count ${BENCH_COUNT} > enforce_log.txt
echo "Enforcement (Log) completed."

echo ""
echo "--- Running Enforcement Mode (Errno) ---"
sudo ../../goste enforce -a errno micro_policy.json ./micro.test -test.run=^$ -test.bench . -test.benchtime ${BENCH_TIME} -test.count ${BENCH_COUNT} > enforce_errno.txt
echo "Enforcement (Errno) completed."

echo ""
echo "--- Running Collateral Mode (Non-traced process, GoSTE active) ---"
sudo ../../goste enforce -a log micro_policy.json ./micro.test -test.run=TestSleep > collateral_goste.log 2>&1 &
GOSTE_PID=$!
sleep 2 # Let it initialize
if ! kill -0 $GOSTE_PID 2>/dev/null; then
    echo "WARNING: goste died prematurely! Check collateral_goste.log"
fi
./micro.test -test.run=^$ -test.bench . -test.benchtime ${BENCH_TIME} -test.count ${BENCH_COUNT} > collateral.txt
sudo kill $GOSTE_PID || true
wait $GOSTE_PID 2>/dev/null || true
echo "Collateral Mode completed."

echo ""
echo "============================================="
echo "                 Results                     "
echo "============================================="
if command -v benchstat &> /dev/null; then
    # We grep the lines containing Benchmark from the output because goste prints its own stdout
    grep "Benchmark" baseline.txt > baseline_clean.txt || true
    grep "Benchmark" tracing.txt > tracing_clean.txt || true
    grep "Benchmark" enforce_log.txt > enforce_log_clean.txt || true
    grep "Benchmark" enforce_errno.txt > enforce_errno_clean.txt || true
    grep "Benchmark" collateral.txt > collateral_clean.txt || true
    
    benchstat baseline_clean.txt tracing_clean.txt enforce_log_clean.txt enforce_errno_clean.txt collateral_clean.txt
else
    echo "Install benchstat to see the statistical comparison."
    echo "Raw results are saved in baseline.txt, tracing.txt, enforce_log.txt, enforce_errno.txt, collateral.txt"
fi

echo ""
echo "============================================="
echo "             Generating Graphs               "
echo "============================================="
if command -v python3 &> /dev/null; then
    python3 plot.py
else
    echo "Python3 not found. Skipping graph generation."
fi
