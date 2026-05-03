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

    Parameters
    ----------
    name:
        Target name as defined in config.yaml (e.g. "etcd").
    cfg:
        The target's configuration sub-dict.

    Raises
    ------
    ValueError:
        If no adapter is registered for *name*.
    """
    cls = _REGISTRY.get(name)
    if cls is None:
        raise ValueError(
            f"No adapter registered for target '{name}'. "
            f"Known targets: {sorted(_REGISTRY)}"
        )
    return cls(name, cfg)


__all__ = ["TargetAdapter", "load_adapter"]
