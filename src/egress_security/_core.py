"""Core orchestration: global config, public init/uninstall, exceptions.

Stub for the scaffolding step. The real implementation is built in step 4 of
the build order — see CLAUDE.md.
"""

from __future__ import annotations

PACKAGE_NAME = "egress-security"


class EgressSecurityError(Exception):
    """Base exception for egress-security."""


class EgressSecurityDenied(EgressSecurityError):
    """Raised when an outbound call is denied by policy in enforce mode."""

    def __init__(
        self,
        *,
        vendor: str,
        operation: str | None = None,
        rule_id: str | None = None,
        reason: str | None = None,
    ) -> None:
        self.vendor = vendor
        self.operation = operation
        self.rule_id = rule_id
        self.reason = reason
        parts = [f"egress-security denied {vendor}"]
        if operation:
            parts.append(f"::{operation}")
        if rule_id:
            parts.append(f" (rule={rule_id})")
        if reason:
            parts.append(f": {reason}")
        super().__init__("".join(parts))


def init(*args, **kwargs):  # pragma: no cover - replaced in step 4
    raise NotImplementedError("egress_security.init is built in step 4 of the build order.")


def uninstall() -> None:  # pragma: no cover - replaced in step 4
    return None
