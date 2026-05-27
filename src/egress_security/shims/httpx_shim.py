"""httpx shim — catch-all for outbound HTTP via the `httpx` library.

Wraps both `httpx.Client.send` (sync) and `httpx.AsyncClient.send` (async).
Like `requests_shim`, this is a catch-all and defers to whichever
vendor-specific shim is already governing the call further up the stack.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

import wrapt

from egress_security import _core
from egress_security.canonical import CanonicalRequest

_log = logging.getLogger("egress_security.shims.httpx")

_installed = False
_originals: dict[str, Any] = {}


def install() -> Callable[[], None] | None:
    global _installed, _originals
    try:
        import httpx  # noqa: F401
    except ImportError:
        return None
    if _installed:
        return uninstall
    try:
        _originals["Client.send"] = httpx.Client.send
        _originals["AsyncClient.send"] = httpx.AsyncClient.send
        wrapt.wrap_function_wrapper("httpx", "Client.send", _wrapper)
        wrapt.wrap_function_wrapper("httpx", "AsyncClient.send", _wrapper)
    except (AttributeError, ImportError) as e:
        _log.warning("httpx_shim: chokepoint signature changed (%s)", e)
        return None
    _installed = True
    return uninstall


def uninstall() -> None:
    global _installed, _originals
    if not _installed:
        return
    try:
        import httpx

        if "Client.send" in _originals:
            httpx.Client.send = _originals["Client.send"]
        if "AsyncClient.send" in _originals:
            httpx.AsyncClient.send = _originals["AsyncClient.send"]
    except Exception:
        _log.warning("httpx_shim: uninstall failed", exc_info=True)
    _originals = {}
    _installed = False


def _wrapper(wrapped, instance, args, kwargs):
    request = args[0] if args else kwargs.get("request")
    canonical = _build_canonical(request)
    _core.govern(canonical, is_catch_all=True)
    # For sync, this returns a Response; for async, this returns a coroutine
    # that the caller awaits — the sync `_core.govern` raise still propagates
    # correctly since it fires before we hand back the coroutine.
    return wrapped(*args, **kwargs)


def _build_canonical(request: Any) -> CanonicalRequest:
    method = getattr(request, "method", None)
    url = getattr(request, "url", None)
    host: str | None = None
    path: str | None = None
    url_str: str | None = None
    if url is not None:
        try:
            host = url.host
        except AttributeError:
            host = None
        try:
            path = url.path
        except AttributeError:
            path = None
        url_str = str(url)
    body = getattr(request, "content", None)
    return CanonicalRequest(
        vendor="http",
        method=method.upper() if isinstance(method, str) else method,
        path=path,
        host=host,
        body=body,
        raw={"url": url_str},
    )
