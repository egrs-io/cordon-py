"""Cordon — runtime security layer for AI agents.

Public API:
    cordon.init(policy, audit, mode, on_error)
    cordon.uninstall()
    cordon.CordonDenied
"""

from cordon._core import (
    CordonDenied,
    CordonError,
    init,
    uninstall,
)

__all__ = [
    "CordonDenied",
    "CordonError",
    "init",
    "uninstall",
]

__version__ = "0.1.0"
