"""boto3 / botocore shim.

Wraps the single chokepoint `botocore.client.BaseClient._make_api_call`.
All AWS SDK calls — high-level resource methods, paginators, waiters —
ultimately go through this method, so wrapping it is sufficient.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

import wrapt

from egress_security import _core
from egress_security.canonical import CanonicalRequest

_log = logging.getLogger("egress_security.shims.boto3")

_installed = False
_original: Any = None


def install() -> Callable[[], None] | None:
    """Patch botocore. Returns the uninstaller, or None if the SDK is absent."""
    global _installed, _original
    try:
        import botocore.client  # noqa: F401
    except ImportError:
        return None
    if _installed:
        return uninstall
    try:
        _original = botocore.client.BaseClient._make_api_call
        wrapt.wrap_function_wrapper(
            "botocore.client", "BaseClient._make_api_call", _wrapper
        )
    except (AttributeError, ImportError) as e:
        _log.warning(
            "boto3_shim: chokepoint signature appears to have changed (%s); "
            "leaving botocore unpatched",
            e,
        )
        return None
    _installed = True
    return uninstall


def uninstall() -> None:
    global _installed, _original
    if not _installed:
        return
    try:
        import botocore.client

        if _original is not None:
            botocore.client.BaseClient._make_api_call = _original
    except Exception:
        _log.warning("boto3_shim: uninstall failed", exc_info=True)
    _original = None
    _installed = False


def _wrapper(wrapped, instance, args, kwargs):
    operation_name = args[0] if args else kwargs.get("operation_name")
    api_params = args[1] if len(args) > 1 else kwargs.get("api_params")
    try:
        service_name = instance.meta.service_model.service_name
    except AttributeError:
        service_name = "unknown"
    canonical = CanonicalRequest(
        vendor=f"aws:{service_name}",
        operation=operation_name,
        params=api_params,
        raw={"service_name": service_name},
    )
    _core.govern(canonical)
    with _core.vendor_scope():
        return wrapped(*args, **kwargs)
