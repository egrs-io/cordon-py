"""Global config, orchestration, public init/uninstall, exceptions.

Shims call `govern(canonical)` to run a single intercepted call through
the policy and the audit log. A thread-local reentrancy guard lets
vendor-specific shims claim a call so catch-all shims (requests/httpx)
don't double-evaluate it.
"""

from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from cordon.audit import AuditLogger
from cordon.canonical import CanonicalRequest
from cordon.policy import Policy, load_policy

_log = logging.getLogger("cordon")

PACKAGE_NAME = "cordon-sdk"


class CordonError(Exception):
    """Base exception for cordon-sdk."""


class CordonDenied(CordonError):
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
        parts = [f"cordon-sdk denied {vendor}"]
        if operation:
            parts.append(f"::{operation}")
        if rule_id:
            parts.append(f" (rule={rule_id})")
        if reason:
            parts.append(f": {reason}")
        super().__init__("".join(parts))


class _State(threading.local):
    depth: int = 0
    vendor_specific_active: bool = False


_state = _State()


class _Config:
    def __init__(self) -> None:
        self.policy: Policy | None = None
        self.audit: AuditLogger | None = None
        self.mode: str = "enforce"
        self.on_error: str = "open"
        self.uninstallers: list[Callable[[], None]] = []


_config: _Config | None = None


def init(
    *,
    policy: Any = "policies/agent-default.yaml",
    audit: str | None = "egress-audit.jsonl",
    audit_stdout: bool = False,
    mode: str = "enforce",
    on_error: str = "open",
) -> None:
    """Activate cordon-sdk.

    Args:
        policy: path to a YAML policy file, or an in-memory policy dict.
        audit: file path for the JSONL audit log. None disables the file sink.
        audit_stdout: also write each audit line to stdout.
        mode: "enforce" blocks denied calls; "monitor" audits without blocking.
        on_error: "open" swallows internal errors so the host app never breaks;
                  "closed" surfaces them.
    """
    global _config
    if mode not in ("enforce", "monitor"):
        raise ValueError(f"mode must be 'enforce' or 'monitor', got {mode!r}")
    if on_error not in ("open", "closed"):
        raise ValueError(f"on_error must be 'open' or 'closed', got {on_error!r}")
    if _config is not None:
        uninstall()
    cfg = _Config()
    cfg.policy = load_policy(policy)
    cfg.audit = AuditLogger(path=audit, stdout=audit_stdout)
    cfg.mode = mode
    cfg.on_error = on_error
    _config = cfg
    from cordon.shims._registry import install_all

    cfg.uninstallers = install_all()


def uninstall() -> None:
    """Remove all patches and close the audit log. Safe to call when inactive."""
    global _config
    if _config is None:
        return
    for fn in _config.uninstallers:
        try:
            fn()
        except Exception:
            _log.exception("shim uninstall failed")
    if _config.audit is not None:
        _config.audit.close()
    _config = None


def is_active() -> bool:
    return _config is not None


@contextmanager
def vendor_scope() -> Iterator[None]:
    """Vendor-specific shims wrap the inner SDK call in this so catch-alls back off."""
    _state.depth = getattr(_state, "depth", 0) + 1
    _state.vendor_specific_active = True
    try:
        yield
    finally:
        _state.depth -= 1
        if _state.depth <= 0:
            _state.depth = 0
            _state.vendor_specific_active = False


def govern(canonical: CanonicalRequest, *, is_catch_all: bool = False) -> None:
    """Evaluate, audit, and raise on deny.

    For catch-all shims (requests / httpx): if a vendor-specific shim is already
    governing this call further up the stack, return immediately without
    re-evaluating or re-auditing.
    """
    cfg = _config
    if cfg is None:
        return
    if is_catch_all and getattr(_state, "vendor_specific_active", False):
        return
    try:
        decision = cfg.policy.evaluate(canonical.to_dict())
    except Exception:
        _handle_internal_error("policy evaluation failed", canonical)
        return
    try:
        cfg.audit.record(
            vendor=canonical.vendor,
            operation=canonical.describe(),
            decision=decision.action,
            reason=decision.reason,
            rule_id=decision.rule_id,
            args=canonical.params if canonical.params is not None else canonical.body,
        )
    except Exception:
        _handle_internal_error("audit write failed", canonical)
    if decision.action == "deny" and cfg.mode == "enforce":
        raise CordonDenied(
            vendor=canonical.vendor,
            operation=canonical.describe(),
            rule_id=decision.rule_id,
            reason=decision.reason,
        )


def _handle_internal_error(message: str, canonical: CanonicalRequest) -> None:
    cfg = _config
    _log.warning("cordon-sdk internal error: %s (vendor=%s)", message, canonical.vendor)
    if cfg is not None and cfg.on_error == "closed":
        raise CordonError(f"internal error: {message}")
