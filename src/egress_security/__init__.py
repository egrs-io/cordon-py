"""Egress Security — runtime security layer for AI agents.

Public API:
    egress_security.init(policy, audit, mode, on_error)
    egress_security.uninstall()
    egress_security.EgressSecurityDenied
"""

from egress_security._core import (
    EgressSecurityDenied,
    EgressSecurityError,
    init,
    uninstall,
)

__all__ = [
    "EgressSecurityDenied",
    "EgressSecurityError",
    "init",
    "uninstall",
]

__version__ = "0.1.0"
