#!/usr/bin/env python3
"""
harness.py – GoSTE Benchmark Harness
=====================================
Measures the overhead introduced by GoSTE tracing / enforcement on real
Go target applications.

Each target is exercised in three modes:
  baseline    – target runs standalone, without GoSTE
  tracing     – target is a GoSTE child process (goste trace …)
  enforcement – target is a GoSTE child process (goste enforce …)

Usage
-----
    sudo python3 harness.py [options]

    -c / --config      path to config.yaml  (default: config.yaml)
    -t / --target      only benchmark this target (may be repeated)
    -m / --mode        only run this mode: baseline / tracing / enforcement
    --dry-run          print commands without executing anything
    --no-report        skip report generation (only save raw JSON)
    --results-dir      where to write output  (default: results/)

Requirements
------------
  • Python 3.8+
  • PyYAML  (pip install pyyaml)
  • GoSTE binary compiled and accessible at the path in config.yaml
  • Must be run as root (eBPF requires CAP_BPF / CAP_SYS_ADMIN)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# Local modules
sys.path.insert(0, str(Path(__file__).parent))
from metrics import MetricsCollector
from report import generate_report
from targets import load_adapter

# ─── Logging setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("harness")

# ─── Constants ────────────────────────────────────────────────────────────────
MODES = ("baseline", "tracing", "enforcement")
POLICY_GENERATE_TIMEOUT = 90   # seconds for the policy-generation tracing run
CHILD_FIND_TIMEOUT      = 15   # seconds to wait for GoSTE's child PID to appear
PROC_TERMINATE_TIMEOUT  = 10   # seconds to wait for clean shutdown


# ─── Process helpers ──────────────────────────────────────────────────────────

def _find_child_pid(parent_pid: int, timeout: float = CHILD_FIND_TIMEOUT) -> Optional[int]:
    """
    Scan /proc and return the first direct child PID of *parent_pid*.
    Polls every 200 ms until *timeout* seconds elapse.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            for entry in os.scandir("/proc"):
                if not entry.name.isdigit():
                    continue
                pid = int(entry.name)
                if pid == parent_pid:
                    continue
                try:
                    with open(f"/proc/{pid}/stat") as fh:
                        raw = fh.read()
                    rp = raw.rfind(")")
                    fields = raw[rp + 2:].split()
                    ppid = int(fields[1])  # field index 3 - 2 (after stripping comm)
                    if ppid == parent_pid:
                        return pid
                except (FileNotFoundError, ValueError, IndexError):
                    continue
        except FileNotFoundError:
            pass
        time.sleep(0.2)
    return None


def _terminate(proc: subprocess.Popen, label: str) -> None:
    """Send SIGTERM to *proc* and wait for it to exit cleanly."""
    if proc.poll() is not None:
        return  # already exited
    log.debug("[%s] Sending SIGTERM to PID %d", label, proc.pid)
    proc.terminate()
    try:
        proc.wait(timeout=PROC_TERMINATE_TIMEOUT)
    except subprocess.TimeoutExpired:
        log.warning("[%s] PID %d did not exit; sending SIGKILL", label, proc.pid)
        proc.kill()
        proc.wait()


def _is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


# ─── Command builders ─────────────────────────────────────────────────────────

def _build_baseline_cmd(adapter) -> List[str]:
    return adapter.start_command()


def _build_trace_cmd(
    goste_bin: str,
    adapter,
    policy_out: str,
) -> List[str]:
    cmd = [goste_bin, "trace", "--skip-privilege-drop"]
    for sym in adapter.cfg.get("state_symbols", []):
        cmd += ["-s", sym]
    cmd += ["-o", policy_out]
    cmd += adapter.start_command()
    return cmd


def _build_enforce_cmd(
    goste_bin: str,
    adapter,
    policy_path: str,
    action: str = "log",
) -> List[str]:
    cmd = [goste_bin, "enforce", "--skip-privilege-drop", "-a", action]
    cmd += [policy_path]
    cmd += adapter.start_command()
    return cmd


# ─── Policy generation ────────────────────────────────────────────────────────

def generate_policy(
    goste_bin: str,
    adapter,
    policy_out: str,
    duration: float,
    dry_run: bool = False,
) -> bool:
    """
    Run a short, unmeasured tracing session to collect a policy.
    Returns True if the policy file was successfully written.
    """
    cmd = _build_trace_cmd(goste_bin, adapter, policy_out)
    log.info("[policy-gen] %s → %s", adapter.name, policy_out)
    log.info("[policy-gen] Command: %s", " ".join(cmd))

    if dry_run:
        log.info("[policy-gen] DRY-RUN: skipping execution")
        return True

    Path(policy_out).parent.mkdir(parents=True, exist_ok=True)

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    except FileNotFoundError as exc:
        log.error("[policy-gen] Failed to start GoSTE: %s", exc)
        return False

    # Find the child (target) PID so we can do ready-check
    child_pid = _find_child_pid(proc.pid)
    if child_pid:
        log.info("[policy-gen] Target child PID: %d", child_pid)
        adapter.ready_check(timeout=30)
    else:
        log.warning("[policy-gen] Could not identify child PID; waiting 5 s")
        time.sleep(5)

    log.info("[policy-gen] Running for %.0f s to gather syscall coverage…", duration)
    time.sleep(duration)

    _terminate(proc, "policy-gen")

    # Give GoSTE a moment to flush the policy file
    time.sleep(1.5)

    if Path(policy_out).exists():
        log.info("[policy-gen] Policy saved → %s", policy_out)
        return True
    else:
        log.error("[policy-gen] Policy file not found after run: %s", policy_out)
        return False


# ─── Single run execution ─────────────────────────────────────────────────────

def execute_run(
    *,
    mode: str,
    run_idx: int,
    adapter,
    global_cfg: Dict[str, Any],
    goste_bin: str,
    policy_path: Optional[str],
    results_dir: str,
    dry_run: bool,
) -> Dict[str, Any]:
    """
    Execute one benchmark run and return a result dict.

    Two load-generator types are supported (set via load_generator.type in yaml):

    continuous (default)
        The load generator runs for the entire measurement window.
        Flow: start target → ready-check → warmup → [start collectors]
              → start load-gen → sleep(duration_secs) → stop load-gen
              → [stop collectors] → stop target

    oneshot
        The load generator is a finite job (e.g. etcd benchmark PUT 100k).
        The measurement window is exactly the job's runtime.
        Flow: start target → ready-check → warmup → [start collectors]
              → start load-gen → wait for load-gen to exit
              → [stop collectors] → stop target
        duration_secs acts as a safety timeout for the job.
    """
    warmup_s   = global_cfg["warmup_secs"]
    duration_s = global_cfg["duration_secs"]
    cooldown_s = global_cfg["cooldown_secs"]

    # Determine load-generator type
    lg_cfg = adapter.cfg.get("load_generator") or {}
    lg_oneshot = str(lg_cfg.get("type", "continuous")).lower() == "oneshot"

    # Build process command
    if mode == "baseline":
        cmd = _build_baseline_cmd(adapter)
        uses_goste = False
    elif mode == "tracing":
        auto_policy = os.path.join(results_dir, f"{adapter.name}_policy.json")
        cmd = _build_trace_cmd(goste_bin, adapter, policy_path or auto_policy)
        uses_goste = True
    elif mode == "enforcement":
        if not policy_path:
            log.error("[%s] No policy available for enforcement run – skipping", adapter.name)
            return _empty_run(adapter.name, mode, run_idx + 1, error="no_policy")
        cmd = _build_enforce_cmd(goste_bin, adapter, policy_path)
        uses_goste = True
    else:
        raise ValueError(f"Unknown mode: {mode}")

    lg_type_label = "oneshot" if lg_oneshot else "continuous"
    log.info(
        "  ┌─ %s | %s | run %d/%d  [load-gen: %s]",
        adapter.name, mode.upper(), run_idx + 1, global_cfg["runs"], lg_type_label,
    )
    log.info("  │  Command: %s", " ".join(cmd))

    if dry_run:
        lg_cmd = adapter.load_generator_command()
        if lg_cmd:
            log.info("  │  LoadGen (%s): %s", lg_type_label, " ".join(lg_cmd))
        log.info("  └─ DRY-RUN: skipping execution")
        return _empty_run(adapter.name, mode, run_idx + 1, error="dry_run")

    # ── Start target process ──────────────────────────────────────────────────
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,   # isolate signal groups
        )
    except FileNotFoundError as exc:
        log.error("  │  Failed to start process: %s", exc)
        return _empty_run(adapter.name, mode, run_idx + 1, error=str(exc))

    goste_pid  = proc.pid if uses_goste else None
    target_pid = proc.pid

    if uses_goste:
        log.info("  │  GoSTE PID: %d – waiting for target child…", goste_pid)
        child = _find_child_pid(goste_pid)
        if child:
            target_pid = child
            log.info("  │  Target child PID: %d", target_pid)
        else:
            log.warning("  │  Could not find child PID; monitoring GoSTE process")

    # ── Ready check ───────────────────────────────────────────────────────────
    log.info("  │  Waiting for target to be ready…")
    adapter.ready_check(timeout=30)

    # ── Warmup (before load gen – let the target stabilise) ───────────────────
    if warmup_s > 0:
        log.info("  │  Warmup %.0f s…", warmup_s)
        time.sleep(warmup_s)

    # ── Start collectors ──────────────────────────────────────────────────────
    # For oneshot load generators the window may be very short (≤1 s); use a
    # small interval so we collect enough samples for meaningful deltas.
    sample_interval = 0.1 if lg_oneshot else 0.5
    target_collector = MetricsCollector(target_pid, interval=sample_interval)
    goste_collector  = MetricsCollector(goste_pid,  interval=sample_interval) if goste_pid else None

    target_collector.start()
    if goste_collector:
        goste_collector.start()

    # ── Load generator + measurement window ───────────────────────────────────
    lg_cmd = adapter.load_generator_command()
    lg_proc: Optional[subprocess.Popen] = None
    lg_stderr_file = None   # temp file capturing load gen stderr for diagnostics
    actual_duration_s: float = duration_s
    lg_returncode: Optional[int] = None

    if lg_cmd:
        log.info("  │  Starting load generator (%s): %s", lg_type_label, " ".join(lg_cmd))
        try:
            # Always capture stderr so we can diagnose failures.
            # stdout is discarded (we don't need throughput numbers here).
            lg_stderr_file = tempfile.TemporaryFile(mode="w+", suffix="_lg_stderr")
            lg_proc = subprocess.Popen(
                lg_cmd,
                stdout=subprocess.DEVNULL,
                stderr=lg_stderr_file,
            )
        except FileNotFoundError as exc:
            log.warning("  │  Load generator not found: %s", exc)
            lg_proc = None

    t_start = time.monotonic()

    if lg_oneshot and lg_proc is not None:
        # Measurement window = exactly the load gen's runtime.
        # duration_secs is a safety upper bound.
        log.info("  │  Waiting for one-shot load gen to complete (timeout %.0f s)…", duration_s)
        try:
            lg_proc.wait(timeout=duration_s)
            actual_duration_s = time.monotonic() - t_start
            lg_returncode = lg_proc.returncode
            log.info(
                "  │  Load gen finished in %.2f s  (exit code: %d)",
                actual_duration_s, lg_returncode,
            )
        except subprocess.TimeoutExpired:
            log.warning(
                "  │  One-shot load gen exceeded %.0f s – terminating it", duration_s
            )
            _terminate(lg_proc, "load-gen")
            lg_returncode = lg_proc.returncode
            actual_duration_s = duration_s
    else:
        # Fixed measurement window (continuous load gen or no load gen)
        log.info("  │  Measuring %.0f s…", duration_s)
        time.sleep(duration_s)
        actual_duration_s = time.monotonic() - t_start
        if lg_proc and lg_proc.poll() is None:
            log.debug("  │  Stopping load generator (PID %d)", lg_proc.pid)
            _terminate(lg_proc, "load-gen")
        if lg_proc:
            lg_returncode = lg_proc.returncode

    # ── Log load gen diagnostics ─────────────────────────────────────────────
    if lg_stderr_file is not None:
        lg_stderr_file.seek(0)
        lg_stderr_text = lg_stderr_file.read().strip()
        lg_stderr_file.close()
        if lg_returncode != 0:
            log.warning(
                "  │  Load gen exited with code %s. stderr:\n%s",
                lg_returncode,
                lg_stderr_text if lg_stderr_text else "(empty)",
            )
        elif lg_stderr_text:
            log.debug("  │  Load gen stderr:\n%s", lg_stderr_text)

    # ── Stop collectors ───────────────────────────────────────────────────────
    target_collector.stop()
    if goste_collector:
        goste_collector.stop()

    target_metrics = target_collector.compute()
    goste_metrics  = goste_collector.compute() if goste_collector else None

    # Attach actual wall time to metrics (overrides the /proc-derived value
    # when the load gen determines the window length)
    if target_metrics:
        target_metrics["wall_time_ms"] = actual_duration_s * 1000

    # ── Shutdown target ───────────────────────────────────────────────────────
    log.debug("  │  Stopping target (PID %d)", proc.pid)
    _terminate(proc, mode)

    # When running in tracing mode, wait briefly so GoSTE can write the policy
    if mode == "tracing":
        time.sleep(1.5)

    log.info(
        "  │  target cpu_sys=%.0f ms  rss_peak=%.1f MB  invol_ctx=%s  wall=%.1f s",
        target_metrics.get("cpu_sys_ms", 0),
        target_metrics.get("rss_mb_peak", 0),
        target_metrics.get("involuntary_ctx", "?"),
        actual_duration_s,
    )
    if goste_metrics:
        log.info(
            "  │  goste  cpu_sys=%.0f ms  rss_peak=%.1f MB",
            goste_metrics.get("cpu_sys_ms", 0),
            goste_metrics.get("rss_mb_peak", 0),
        )
    log.info("  └─ Done.  Cooldown %.0f s…", cooldown_s)
    time.sleep(cooldown_s)

    return {
        "target":           adapter.name,
        "mode":             mode,
        "run":              run_idx + 1,
        "target_pid":       target_pid,
        "goste_pid":        goste_pid,
        "actual_duration_s": actual_duration_s,
        "target_metrics":   target_metrics,
        "goste_metrics":    goste_metrics,
        "error":            None,
    }


def _empty_run(target: str, mode: str, run: int, error: str) -> Dict[str, Any]:
    return {
        "target":         target,
        "mode":           mode,
        "run":            run,
        "target_pid":     None,
        "goste_pid":      None,
        "target_metrics": {},
        "goste_metrics":  None,
        "error":          error,
    }


# ─── Target orchestration ─────────────────────────────────────────────────────

def benchmark_target(
    target_name: str,
    target_cfg: Dict[str, Any],
    global_cfg: Dict[str, Any],
    goste_bin: str,
    results_dir: str,
    modes: List[str],
    dry_run: bool,
) -> List[Dict[str, Any]]:
    """
    Run all selected modes × N runs for a single target.
    Returns a flat list of run-result dicts.
    """
    adapter = load_adapter(target_name, target_cfg)
    binary  = target_cfg.get("binary", "")
    num_runs = global_cfg["runs"]

    # Verify binary exists
    if not dry_run and binary and not Path(binary).exists():
        log.error("[%s] Binary not found: %s – skipping target", target_name, binary)
        return []

    log.info("")
    log.info("━━━ Target: %s ━━━", target_name.upper())

    all_results: List[Dict[str, Any]] = []

    # ── Determine / generate policy ───────────────────────────────────────────
    # Policy is only needed if enforcement mode is requested.
    policy_path: Optional[str] = None
    auto_policy  = os.path.join(results_dir, f"{target_name}_policy.json")

    if "enforcement" in modes:
        cfg_policy = target_cfg.get("policy")

        if cfg_policy and Path(cfg_policy).exists():
            policy_path = cfg_policy
            log.info("[%s] Using pre-built policy: %s", target_name, policy_path)

        elif cfg_policy and not Path(cfg_policy).exists():
            log.warning(
                "[%s] Policy file '%s' not found – will auto-generate",
                target_name, cfg_policy,
            )
            # fall through to auto-generate

        if not policy_path:
            # Auto-generate only if tracing mode is NOT already in the run list
            # (if it is, the policy will be produced by the first tracing run)
            if "tracing" not in modes:
                log.info(
                    "[%s] Auto-generating policy (tracing warmup run)…", target_name
                )
                ok = generate_policy(
                    goste_bin=goste_bin,
                    adapter=adapter,
                    policy_out=auto_policy,
                    duration=global_cfg.get("warmup_secs", 15) + 10,
                    dry_run=dry_run,
                )
                if ok:
                    policy_path = auto_policy
                else:
                    log.error(
                        "[%s] Policy generation failed – enforcement mode skipped",
                        target_name,
                    )
                    modes = [m for m in modes if m != "enforcement"]
            # else: policy will be set after tracing runs complete

    # ── Run modes in order ────────────────────────────────────────────────────
    for mode in MODES:
        if mode not in modes:
            continue

        log.info("[%s] Mode: %s (%d runs)", target_name, mode.upper(), num_runs)

        # For enforcement mode, if we rely on auto-generated policy from tracing
        # runs, verify it exists now.
        if mode == "enforcement" and not policy_path:
            if Path(auto_policy).exists():
                policy_path = auto_policy
                log.info("[%s] Using auto-generated policy: %s", target_name, policy_path)
            else:
                log.error(
                    "[%s] No policy available for enforcement – skipping mode",
                    target_name,
                )
                continue

        for run_idx in range(num_runs):
            # Allow adapter to perform per-run setup (e.g. clean data dirs)
            if not dry_run:
                adapter.pre_run_hook()

            result = execute_run(
                mode=mode,
                run_idx=run_idx,
                adapter=adapter,
                global_cfg=global_cfg,
                goste_bin=goste_bin,
                policy_path=policy_path if mode in ("tracing", "enforcement") else None,
                results_dir=results_dir,
                dry_run=dry_run,
            )
            all_results.append(result)

            if not dry_run:
                adapter.post_run_hook()

        # After the first successful tracing run, the policy file may now exist
        if mode == "tracing" and not policy_path:
            if Path(auto_policy).exists():
                policy_path = auto_policy
                log.info(
                    "[%s] Policy produced by tracing run → %s",
                    target_name, policy_path,
                )

    return all_results


# ─── Entry point ─────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="GoSTE benchmark harness – measure eBPF tracing/enforcement overhead",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to config.yaml (default: config.yaml)",
    )
    parser.add_argument(
        "-t", "--target",
        action="append",
        dest="targets",
        metavar="NAME",
        help="Only benchmark this target (repeat for multiple). Default: all enabled.",
    )
    parser.add_argument(
        "-m", "--mode",
        action="append",
        dest="modes",
        choices=list(MODES),
        metavar="MODE",
        help="Only run this mode (baseline/tracing/enforcement). Default: all.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without executing anything.",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip report generation; only save raw JSON.",
    )
    parser.add_argument(
        "--results-dir",
        default="results",
        help="Directory for output files (default: results/)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # ── Privilege check ───────────────────────────────────────────────────────
    if not args.dry_run and os.geteuid() != 0:
        log.error("GoSTE requires root privileges. Re-run with sudo.")
        sys.exit(1)

    # ── Load config ───────────────────────────────────────────────────────────
    config_path = Path(args.config)
    if not config_path.exists():
        log.error("Config file not found: %s", config_path)
        sys.exit(1)

    with config_path.open() as fh:
        cfg = yaml.safe_load(fh)

    goste_bin = cfg.get("goste_binary", "../goste")
    # Resolve relative to the config file's directory
    if not Path(goste_bin).is_absolute():
        goste_bin = str((config_path.parent / goste_bin).resolve())

    if not args.dry_run and not Path(goste_bin).exists():
        log.error("GoSTE binary not found: %s", goste_bin)
        sys.exit(1)

    global_cfg = {
        "runs":          cfg.get("runs", 3),
        "warmup_secs":   cfg.get("warmup_secs", 10),
        "duration_secs": cfg.get("duration_secs", 60),
        "cooldown_secs": cfg.get("cooldown_secs", 5),
    }

    results_dir = args.results_dir
    Path(results_dir).mkdir(parents=True, exist_ok=True)

    selected_modes  = args.modes  or list(MODES)
    selected_targets = args.targets or None   # None = all enabled

    # ── Run benchmarks ────────────────────────────────────────────────────────
    all_results: List[Dict[str, Any]] = []

    targets_cfg: Dict[str, Any] = cfg.get("targets", {})
    for tname, tcfg in targets_cfg.items():
        if not tcfg.get("enabled", True):
            log.info("Skipping disabled target: %s", tname)
            continue
        if selected_targets and tname not in selected_targets:
            continue

        try:
            results = benchmark_target(
                target_name=tname,
                target_cfg=tcfg,
                global_cfg=global_cfg,
                goste_bin=goste_bin,
                results_dir=results_dir,
                modes=list(selected_modes),
                dry_run=args.dry_run,
            )
            all_results.extend(results)
        except KeyboardInterrupt:
            log.warning("Interrupted by user – saving partial results…")
            break
        except Exception as exc:
            log.exception("Unexpected error benchmarking %s: %s", tname, exc)

    # ── Save raw results ──────────────────────────────────────────────────────
    if all_results:
        raw_path = os.path.join(results_dir, "raw_results.json")
        with open(raw_path, "w") as fh:
            json.dump(all_results, fh, indent=2)
        log.info("\nRaw results saved → %s", raw_path)

        if not args.no_report:
            generate_report(all_results, results_dir)
    else:
        log.warning("No results collected.")

    log.info("Done.")


if __name__ == "__main__":
    main()
