"""Cordon — runtime security layer for AI agents.

Public API:
    cordon.init(policy, audit, sinks, mode, on_error)
    cordon.uninstall()
    cordon.api_url() / cordon.api_key()
    cordon.CordonDenied
    cordon.Sink (protocol for pluggable audit destinations)
"""

from cordon._core import (
    CordonDenied,
    CordonError,
    api_key,
    api_url,
    init,
    uninstall,
)
from cordon.sinks import Sink

__all__ = [
    "CordonDenied",
    "CordonError",
    "Sink",
    "api_key",
    "api_url",
    "init",
    "uninstall",
]

__version__ = "0.1.0"
