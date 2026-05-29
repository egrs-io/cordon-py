"""Discover installed SDKs and apply available shims.

Each shim module exposes `install() -> Callable[[], None]` which patches its
chokepoint and returns an uninstaller. A shim that can't apply itself (SDK
absent, or chokepoint signature has changed) returns a no-op uninstaller
and logs a warning — `init()` must never fail because one SDK is missing.
"""

from __future__ import annotations

import importlib
import logging
from typing import Callable

_log = logging.getLogger("cordon.shims")

# Each entry: (module name to import, "install" attribute to call)
_SHIM_MODULES = (
    "cordon.shims.boto3_shim",
    "cordon.shims.github_shim",
    "cordon.shims.slack_shim",
    "cordon.shims.subprocess_shim",
    "cordon.shims.requests_shim",
    "cordon.shims.httpx_shim",
)


def install_all() -> list[Callable[[], None]]:
    """Try to install every shim. Return list of uninstaller callables."""
    uninstallers: list[Callable[[], None]] = []
    for mod_name in _SHIM_MODULES:
        try:
            mod = importlib.import_module(mod_name)
        except ImportError:
            _log.debug("shim module not found: %s", mod_name)
            continue
        install = getattr(mod, "install", None)
        if install is None:
            _log.warning("shim module %s missing install()", mod_name)
            continue
        try:
            uninstaller = install()
        except Exception:
            _log.warning("shim %s failed to install", mod_name, exc_info=True)
            continue
        if uninstaller is not None:
            uninstallers.append(uninstaller)
    return uninstallers
