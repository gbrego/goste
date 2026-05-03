"""targets/etcd.py – Adapter for etcd."""

from __future__ import annotations

import logging
import shutil
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from .base import TargetAdapter

log = logging.getLogger(__name__)


class EtcdAdapter(TargetAdapter):
    """
    etcd v3 adapter.

    Ready check: TCP connection to the client port (default 2379).
    Load generator: standalone benchmark tool (go.etcd.io/etcd/tools/benchmark).

    Between runs the etcd data directory is wiped so that WAL size does not
    accumulate across runs and artificially inflate RSS measurements.
    """

    DEFAULT_CLIENT_PORT = 2379
    DEFAULT_DATA_DIR    = "default.etcd"

    def start_command(self) -> List[str]:
        return [self.binary()] + self.extra_args()

    def ready_host_port(self) -> Tuple[str, int]:
        # Detect port from args if --listen-client-urls is present
        args = self.extra_args()
        for i, arg in enumerate(args):
            if arg.startswith("--listen-client-urls="):
                url = arg.split("=", 1)[1].split(",")[0]
                port = int(url.rsplit(":", 1)[-1].rstrip("/"))
                return ("127.0.0.1", port)
            if arg in ("--listen-client-urls", "-listen-client-urls"):
                if i + 1 < len(args):
                    url = args[i + 1].split(",")[0]
                    port = int(url.rsplit(":", 1)[-1].rstrip("/"))
                    return ("127.0.0.1", port)
        return ("127.0.0.1", self.DEFAULT_CLIENT_PORT)

    def ready_check(self, timeout: float = 30.0) -> bool:
        """Wait for TCP port, then add an extra settling delay for gRPC init."""
        ok = super().ready_check(timeout=timeout)
        if ok:
            # etcd opens the TCP port slightly before the gRPC server is ready;
            # a short extra wait avoids transient "connection refused" errors
            # from the benchmark client on the very first request.
            time.sleep(1.0)
        return ok

    def pre_run_hook(self) -> None:
        """
        Remove the etcd data directory before each run.

        Without this, each successive run loads an increasingly large WAL into
        memory, inflating RSS and distorting the comparison across modes.
        """
        self._cleanup_data_dir()

    def post_run_hook(self) -> None:
        """
        Remove the etcd data directory after each run to leave the system clean.
        """
        self._cleanup_data_dir()

    def _cleanup_data_dir(self) -> None:
        data_dir = self._resolve_data_dir()
        if Path(data_dir).exists():
            log.info("[%s] Cleaning up etcd data dir: %s", self.name, data_dir)
            shutil.rmtree(data_dir, ignore_errors=True)
        else:
            log.debug("[%s] etcd data dir not found, nothing to clean: %s", self.name, data_dir)

    def _resolve_data_dir(self) -> str:
        args = self.extra_args()
        for i, arg in enumerate(args):
            if arg.startswith("--data-dir="):
                return arg.split("=", 1)[1]
            if arg in ("--data-dir", "-data-dir"):
                if i + 1 < len(args):
                    return args[i + 1]
        # Also check config
        data_dir = self.cfg.get("data_dir")
        if data_dir:
            return data_dir
        return self.DEFAULT_DATA_DIR

