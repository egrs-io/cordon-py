"""requests shim — catch-all for outbound HTTP via the `requests` library.

This is a catch-all: when a vendor-specific shim (github_shim, etc.) is
already governing the call further up the stack, govern() returns early
so we don't double-evaluate. See `_core.vendor_scope()`.
"""

from __future__ import annotations

import logging
from typing import Any, Callable
from urllib.parse import urlparse

import wrapt

from egress_security import _core
from egress_security.canonical import CanonicalRequest

_log = logging.getLogger("egress_security.shims.requests")

_installed = False
_original: Any = None


def install() -> Callable[[], None] | None:
    global _installed, _original
    try:
        import requests.sessions  # noqa: F401
    except ImportError:
        return None
    if _installed:
        return uninstall
    try:
        _original = requests.sessions.Session.request
        wrapt.wrap_function_wrapper(
            "requests.sessions", "Session.request", _wrapper
        )
    except (AttributeError, ImportError) as e:
        _log.warning("requests_shim: chokepoint signature changed (%s)", e)
        return None
    _installed = True
    return uninstall


def uninstall() -> None:
    global _installed, _original
    if not _installed:
        return
    try:
        import requests.sessions

        if _original is not None:
            requests.sessions.Session.request = _original
    except Exception:
        _log.warning("requests_shim: uninstall failed", exc_info=True)
    _original = None
    _installed = False


def _wrapper(wrapped, instance, args, kwargs):
    method = args[0] if args else kwargs.get("method")
    url = args[1] if len(args) > 1 else kwargs.get("url")
    parsed = urlparse(url) if isinstance(url, str) else None
    host = parsed.hostname if parsed else None
    path = parsed.path if parsed else None
    body = kwargs.get("data")
    if body is None:
        body = kwargs.get("json")
    canonical = CanonicalRequest(
        vendor="http",
        method=method.upper() if isinstance(method, str) else method,
        path=path,
        host=host,
        body=body,
        raw={"url": url},
    )
    _core.govern(canonical, is_catch_all=True)
    return wrapped(*args, **kwargs)
