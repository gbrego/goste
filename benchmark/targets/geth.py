"""targets/geth.py – Adapter for go-ethereum (geth)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Any, List, Tuple

from .base import TargetAdapter

log = logging.getLogger(__name__)


class GethAdapter(TargetAdapter):
    """
    go-ethereum (geth) adapter.

    Ready check: HTTP JSON-RPC port (default 8545).
    Cleanup: removes stale IPC socket before each run to prevent
    "bind: address already in use" errors.
    """

    DEFAULT_RPC_PORT = 8545
    DEFAULT_IPC_PATH = "/tmp/geth.ipc"

    def start_command(self) -> List[str]:
        return [self.binary()] + self.extra_args()

    def ready_host_port(self) -> Tuple[str, int]:
        args = self.extra_args()
        for i, arg in enumerate(args):
            if arg.startswith("--http.port="):
                return ("127.0.0.1", int(arg.split("=", 1)[1]))
            if arg == "--http.port" and i + 1 < len(args):
                return ("127.0.0.1", int(args[i + 1]))
        return ("127.0.0.1", self.DEFAULT_RPC_PORT)

    def pre_run_hook(self) -> None:
        """Remove stale geth IPC socket before each run."""
        ipc_path = self._resolve_ipc_path()
        p = Path(ipc_path)
        if p.exists():
            log.info("[%s] Removing stale IPC socket: %s", self.name, ipc_path)
            p.unlink()

    def _resolve_ipc_path(self) -> str:
        """Detect --ipcpath from args, fallback to default /tmp/geth.ipc."""
        args = self.extra_args()
        for i, arg in enumerate(args):
            if arg.startswith("--ipcpath="):
                return arg.split("=", 1)[1]
            if arg == "--ipcpath" and i + 1 < len(args):
                return args[i + 1]
        return self.DEFAULT_IPC_PATH
