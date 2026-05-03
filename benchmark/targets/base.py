"""
targets/base.py – Abstract base class for benchmark target adapters.

Every concrete target (etcd, CoreDNS, geth, frp …) must subclass
TargetAdapter and implement at minimum `start_command()`.

The `ready_check()` default polls a TCP port; override it for targets
whose readiness cannot be detected via a simple connection.
"""

from __future__ import annotations

import abc
import socket
import time
import logging
from typing import Dict, Any, List, Optional, Tuple

log = logging.getLogger(__name__)


class TargetAdapter(abc.ABC):
    """
    Abstract adapter that encapsulates target-specific knowledge:
    how to build the command line, how to detect readiness, and how to
    build the load-generator command.

    Parameters
    ----------
    name:
        Human-readable target name (e.g. "etcd").
    cfg:
        The target's sub-dict from config.yaml.
    """

    def __init__(self, name: str, cfg: Dict[str, Any]) -> None:
        self.name = name
        self.cfg = cfg

    # ── required ──────────────────────────────────────────────────────────────

    @abc.abstractmethod
    def start_command(self) -> List[str]:
        """Return the argv list to launch the target process."""

    # ── optional overrides ────────────────────────────────────────────────────

    def ready_host_port(self) -> Optional[Tuple[str, int]]:
        """
        Return (host, port) to poll for readiness, or None to use a
        fixed wait instead.
        """
        return None

    def ready_check(self, timeout: float = 30.0) -> bool:
        """
        Block until the target reports ready, or until *timeout* seconds
        elapse.  Returns True if ready, False if timed out.
        """
        hp = self.ready_host_port()
        if hp is None:
            log.debug("[%s] No readiness port configured; waiting 3 s", self.name)
            time.sleep(3)
            return True

        host, port = hp
        deadline = time.monotonic() + timeout
        log.debug("[%s] Waiting for %s:%d …", self.name, host, port)
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=1.0):
                    log.debug("[%s] Port %d is open – target is ready", self.name, port)
                    return True
            except OSError:
                time.sleep(0.4)

        log.warning("[%s] Ready-check timed out after %.0f s", self.name, timeout)
        return False

    def load_generator_command(self) -> Optional[List[str]]:
        """
        Return the argv list for the load generator, or None if no load
        generator is configured for this target.
        """
        lg = self.cfg.get("load_generator")
        if not lg:
            return None
        binary = lg.get("binary")
        if not binary:
            return None
        return [binary] + [str(a) for a in lg.get("args", [])]

    def pre_run_hook(self) -> None:
        """
        Called by the harness immediately before each run starts.
        Override to perform per-run setup (e.g. clean a data directory).
        Default implementation does nothing.
        """

    def post_run_hook(self) -> None:
        """
        Called by the harness immediately after each run ends (after cooldown).
        Override to perform per-run teardown.
        Default implementation does nothing.
        """

    # ── helpers ───────────────────────────────────────────────────────────────

    def binary(self) -> str:
        return self.cfg["binary"]

    def extra_args(self) -> List[str]:
        return [str(a) for a in self.cfg.get("args", [])]
