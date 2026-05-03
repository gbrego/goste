"""targets/coredns.py – Adapter for CoreDNS."""

from __future__ import annotations
from typing import Dict, Any, List, Tuple, Optional
from .base import TargetAdapter


class CoreDNSAdapter(TargetAdapter):
    """
    CoreDNS adapter.

    Ready check: UDP/TCP connection to port 53 (or whatever is configured).
    Load generator: dnsperf (or dnsbench / flamethrower).
    """

    DEFAULT_DNS_PORT = 53

    def start_command(self) -> List[str]:
        return [self.binary()] + self.extra_args()

    def ready_host_port(self) -> Tuple[str, int]:
        return ("127.0.0.1", self.DEFAULT_DNS_PORT)
