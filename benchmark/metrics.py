"""
metrics.py – Lightweight /proc-based process metrics collector.

Collects CPU time, RSS, context switches and thread count from the Linux
/proc filesystem.  No external dependencies are required.

Usage
-----
    collector = MetricsCollector(pid, interval=1.0)
    collector.start()
    time.sleep(60)
    collector.stop()
    data = collector.compute()   # dict with aggregated metrics
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional

# Number of clock ticks per second (usually 100 on modern Linux)
_CLK_TCK: int = os.sysconf("SC_CLK_TCK")
_PAGE_SIZE_KB: int = os.sysconf("SC_PAGE_SIZE") // 1024


# ─── Low-level snapshot ───────────────────────────────────────────────────────

@dataclass
class _Snapshot:
    """A single point-in-time reading from /proc/<pid>."""
    timestamp: float = 0.0
    utime_ticks: int = 0          # user-mode CPU time
    stime_ticks: int = 0          # kernel-mode CPU time
    rss_kb: int = 0               # resident set size
    voluntary_ctx: int = 0        # voluntary context switches
    nonvoluntary_ctx: int = 0     # non-voluntary context switches
    threads: int = 0
    alive: bool = True            # False if the process was gone when sampled


def _read_snapshot(pid: int) -> _Snapshot:
    """Read a single snapshot for *pid* from /proc.  Returns a zeroed
    snapshot with alive=False if the process no longer exists."""
    snap = _Snapshot(timestamp=time.monotonic())

    # /proc/<pid>/stat  ─────────────────────────────────────────────────────
    # Field indices (0-based, after the comm field workaround):
    #   13 → utime, 14 → stime, 23 → vsize (bytes), 24 → rss (pages)
    try:
        with open(f"/proc/{pid}/stat") as fh:
            raw = fh.read()
        # The comm field (2nd token) may contain spaces and parentheses; we
        # strip it by finding the last ')' to avoid mis-parsing.
        rp = raw.rfind(")")
        fields = raw[rp + 2:].split()
        snap.utime_ticks = int(fields[11])   # utime  (relative to rp+2: field 13-2=11)
        snap.stime_ticks = int(fields[12])   # stime
    except (FileNotFoundError, ProcessLookupError):
        snap.alive = False
        return snap
    except (ValueError, IndexError):
        pass

    # /proc/<pid>/status ────────────────────────────────────────────────────
    try:
        with open(f"/proc/{pid}/status") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                rest = rest.strip()
                if key == "VmRSS":
                    snap.rss_kb = int(rest.split()[0])
                elif key == "voluntary_ctxt_switches":
                    snap.voluntary_ctx = int(rest)
                elif key == "nonvoluntary_ctxt_switches":
                    snap.nonvoluntary_ctx = int(rest)
                elif key == "Threads":
                    snap.threads = int(rest)
    except (FileNotFoundError, ProcessLookupError):
        snap.alive = False
    except (ValueError, IndexError):
        pass

    return snap


# ─── Metrics collector ────────────────────────────────────────────────────────

class MetricsCollector:
    """
    Periodically samples /proc/<pid> and computes aggregate metrics over
    the entire measurement window.

    Parameters
    ----------
    pid:
        PID to monitor.
    interval:
        Sampling interval in seconds (default 1.0).
    """

    def __init__(self, pid: int, interval: float = 1.0) -> None:
        self.pid = pid
        self.interval = interval
        self._snapshots: List[_Snapshot] = []
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start background sampling thread."""
        self._stop.clear()
        self._snapshots.clear()
        self._thread = threading.Thread(
            target=self._loop, name=f"metrics-{self.pid}", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop background sampling thread and wait for it to finish."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval * 3)

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self._snapshots.append(_read_snapshot(self.pid))

    # ── result computation ────────────────────────────────────────────────────

    def compute(self) -> dict:
        """
        Return a dict with aggregated metrics over the measurement window.
        The delta between the *first* and *last* alive snapshots is used for
        cumulative counters; peak values are taken across all snapshots.

        Returns an empty dict if fewer than 2 snapshots were collected.
        """
        alive = [s for s in self._snapshots if s.alive]
        if len(alive) < 2:
            return {}

        first = alive[0]
        last = alive[-1]
        wall_s = last.timestamp - first.timestamp

        du = last.utime_ticks - first.utime_ticks
        ds = last.stime_ticks - first.stime_ticks

        return {
            "cpu_user_ms":      max(0, du / _CLK_TCK * 1000),
            "cpu_sys_ms":       max(0, ds / _CLK_TCK * 1000),
            "cpu_total_ms":     max(0, (du + ds) / _CLK_TCK * 1000),
            "rss_mb_peak":      max((s.rss_kb for s in alive), default=0) / 1024,
            "rss_mb_avg":       sum(s.rss_kb for s in alive) / len(alive) / 1024,
            "voluntary_ctx":    max(0, last.voluntary_ctx   - first.voluntary_ctx),
            "involuntary_ctx":  max(0, last.nonvoluntary_ctx - first.nonvoluntary_ctx),
            "threads_peak":     max((s.threads for s in alive), default=0),
            "wall_time_ms":     wall_s * 1000,
            "samples":          len(alive),
        }

    def raw_snapshots(self) -> List[_Snapshot]:
        """Return all collected snapshots (for debugging)."""
        return list(self._snapshots)
