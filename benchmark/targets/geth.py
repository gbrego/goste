"""targets/geth.py – Adapter for go-ethereum (geth)."""

from __future__ import annotations
from typing import Dict, Any, List, Tuple
from .base import TargetAdapter


class GethAdapter(TargetAdapter):
    """
    go-ethereum (geth) adapter.

    Ready check: HTTP JSON-RPC port (default 8545).
    """

    DEFAULT_RPC_PORT = 8545

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
