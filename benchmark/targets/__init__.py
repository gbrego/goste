"""
targets/__init__.py – Adapter registry.

Maps target names (as they appear in config.yaml) to their adapter classes
and exposes `load_adapter()` as the single entry point used by the harness.
"""

from __future__ import annotations

from typing import Dict, Any, Type

from .base import TargetAdapter
from .etcd import EtcdAdapter
from .coredns import CoreDNSAdapter
from .geth import GethAdapter
from .frp import FrpAdapter

_REGISTRY: Dict[str, Type[TargetAdapter]] = {
    "etcd":    EtcdAdapter,
    "coredns": CoreDNSAdapter,
    "geth":    GethAdapter,
    "frp":     FrpAdapter,
}


def load_adapter(name: str, cfg: Dict[str, Any]) -> TargetAdapter:
    """
    Instantiate and return the adapter for the named target.

    It first checks for an explicit 'type' field in cfg.
    If not present, it tries to match the 'name' directly against the registry.
    If still not found, it tries to match the prefix (e.g. 'etcd' for 'etcd_light').
    """
    # 1. Explicit type override
    target_type = cfg.get("type")

    # 2. Direct name match
    if not target_type and name in _REGISTRY:
        target_type = name

    # 3. Prefix match (e.g. 'etcd_intensive' -> 'etcd')
    if not target_type:
        for known_type in _REGISTRY:
            if name.startswith(f"{known_type}_"):
                target_type = known_type
                break

    cls = _REGISTRY.get(target_type) if target_type else None

    if cls is None:
        raise ValueError(
            f"No adapter registered for target '{name}' (detected type: '{target_type}'). "
            f"Known types: {sorted(_REGISTRY)}"
        )
    return cls(name, cfg)


__all__ = ["TargetAdapter", "load_adapter"]
