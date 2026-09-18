#!/bin/bash
set -e

echo "============================================================"
echo " Running CoreDNS Benchmark (Isolated)"
echo "============================================================"
echo "This script will run the CoreDNS intensive benchmark"
echo "and save all results to a dedicated directory so it"
echo "does not overwrite the existing etcd/geth results."
echo "============================================================"

RESULTS_DIR="results_coredns_new"

sudo python3 harness.py -t coredns_intensive --results-dir "$RESULTS_DIR"

echo "Benchmark complete. Generating CoreDNS graphs..."
python3 plot.py "$RESULTS_DIR"

echo "Done! Check $RESULTS_DIR for the new CSV, TXT, and PDF graphs."
