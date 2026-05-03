"""targets/frp.py – Adapter for frp (Fast Reverse Proxy) server."""

from __future__ import annotations
from typing import Dict, Any, List, Tuple
from .base import TargetAdapter


class FrpAdapter(TargetAdapter):
    """
    frp server (frps) adapter.

    Ready check: TCP connection to the frp bind_port (default 7000).
    """

    DEFAULT_BIND_PORT = 7000

    def start_command(self) -> List[str]:
        return [self.binary()] + self.extra_args()

    def ready_host_port(self) -> Tuple[str, int]:
        return ("127.0.0.1", self.DEFAULT_BIND_PORT)
