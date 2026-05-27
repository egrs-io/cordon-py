"""PyGithub shim.

Wraps `github.Requester.Requester.requestJsonAndCheck` — the single
chokepoint for every PyGithub API call. The wrapper extracts the HTTP
verb and URL path, runs the policy, and either calls through or raises.
"""

from __future__ import annotations

import logging
from typing import Any, Callable
from urllib.parse import urlparse

import wrapt

from egress_security import _core
from egress_security.canonical import CanonicalRequest

_log = logging.getLogger("egress_security.shims.github")

_installed = False
_original: Any = None


def install() -> Callable[[], None] | None:
    global _installed, _original
    try:
        import github.Requester  # noqa: F401
    except ImportError:
        return None
    if _installed:
        return uninstall
    try:
        _original = github.Requester.Requester.requestJsonAndCheck
        wrapt.wrap_function_wrapper(
            "github.Requester", "Requester.requestJsonAndCheck", _wrapper
        )
    except (AttributeError, ImportError) as e:
        _log.warning("github_shim: chokepoint signature changed (%s)", e)
        return None
    _installed = True
    return uninstall


def uninstall() -> None:
    global _installed, _original
    if not _installed:
        return
    try:
        import github.Requester

        if _original is not None:
            github.Requester.Requester.requestJsonAndCheck = _original
    except Exception:
        _log.warning("github_shim: uninstall failed", exc_info=True)
    _original = None
    _installed = False


def _extract_body(args: tuple, kwargs: dict) -> Any:
    if "input" in kwargs:
        return kwargs["input"]
    if len(args) >= 5:
        return args[4]
    return None


def _wrapper(wrapped, instance, args, kwargs):
    verb = args[0] if args else kwargs.get("verb")
    url = args[1] if len(args) > 1 else kwargs.get("url")
    parsed = urlparse(url) if isinstance(url, str) else None
    path = parsed.path if parsed and parsed.path else (url if isinstance(url, str) else "")
    host = parsed.hostname if parsed else None
    canonical = CanonicalRequest(
        vendor="github",
        method=verb,
        path=path,
        host=host,
        body=_extract_body(args, kwargs),
        raw={"url": url},
    )
    _core.govern(canonical)
    with _core.vendor_scope():
        return wrapped(*args, **kwargs)
