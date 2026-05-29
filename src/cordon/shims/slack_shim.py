"""slack_sdk shim.

Wraps `slack_sdk.web.base_client.BaseClient.api_call` — the chokepoint
for every method on `WebClient` (chat_postMessage, files_upload, etc.).
Canonical: vendor=slack, operation=<api_method>, params merged from
the data/json/params/files kwargs.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

import wrapt

from cordon import _core
from cordon.canonical import CanonicalRequest

_log = logging.getLogger("cordon.shims.slack")

_installed = False
_original: Any = None


def install() -> Callable[[], None] | None:
    global _installed, _original
    try:
        import slack_sdk.web.base_client  # noqa: F401
    except ImportError:
        return None
    if _installed:
        return uninstall
    try:
        _original = slack_sdk.web.base_client.BaseClient.api_call
        wrapt.wrap_function_wrapper(
            "slack_sdk.web.base_client", "BaseClient.api_call", _wrapper
        )
    except (AttributeError, ImportError) as e:
        _log.warning("slack_shim: chokepoint signature changed (%s)", e)
        return None
    _installed = True
    return uninstall


def uninstall() -> None:
    global _installed, _original
    if not _installed:
        return
    try:
        import slack_sdk.web.base_client

        if _original is not None:
            slack_sdk.web.base_client.BaseClient.api_call = _original
    except Exception:
        _log.warning("slack_shim: uninstall failed", exc_info=True)
    _original = None
    _installed = False


def _wrapper(wrapped, instance, args, kwargs):
    api_method = args[0] if args else kwargs.get("api_method")
    http_verb = kwargs.get("http_verb", "POST")
    params = {
        k: kwargs[k]
        for k in ("data", "params", "json", "files")
        if kwargs.get(k) is not None
    }
    canonical = CanonicalRequest(
        vendor="slack",
        operation=api_method,
        method=http_verb,
        params=params or None,
        raw={"http_verb": http_verb},
    )
    _core.govern(canonical)
    with _core.vendor_scope():
        return wrapped(*args, **kwargs)
