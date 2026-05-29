"""Pluggable audit sinks.

Cordon's built-in audit log writes a JSONL file (and optionally stdout).
This module defines the `Sink` protocol that lets any package — including
commercial integrations like `cordon-cloud-py` — receive the same event
stream and ship it elsewhere (an HTTP API, a queue, a SIEM connector).

Sinks are discovered two ways:

  1. **Explicit**: pass ``sinks=[MySink(...)]`` to ``cordon.init()``.
  2. **Entry points**: a package can register itself in the
     ``cordon.sinks`` entry-point group; ``init()`` discovers and
     instantiates each automatically. Example, in another package's
     ``pyproject.toml``::

         [project.entry-points."cordon.sinks"]
         cloud = "cordon_cloud:CloudSink"

Sinks read ``cordon.api_url()`` and ``cordon.api_key()`` at construction
time to pick up the ``CORDON_API_URL`` / ``CORDON_API_KEY`` env vars
that ``init()`` loaded. Cordon itself never makes a network call — the
networking lives in whatever sink package the user installs.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

_log = logging.getLogger("cordon.sinks")


@runtime_checkable
class Sink(Protocol):
    """A destination that receives every audited event.

    Implementations should swallow their own errors (and log a warning)
    so a misbehaving sink never breaks the host application. Cordon will
    log a warning around any exception that escapes ``record()`` but
    will not re-raise it.
    """

    def record(self, event: dict) -> None:
        """Receive one audit event.

        The event dict has the same shape as a line in the local JSONL
        audit log: ``ts``, ``session_id``, ``vendor``, ``operation``,
        ``decision``, ``reason``, ``rule_id``, ``args``. Additional
        fields may be added in future schema versions; sinks should
        tolerate unknown keys.
        """

    def close(self) -> None:
        """Flush buffered state and release resources. Called by
        ``cordon.uninstall()``. May be a no-op for stateless sinks."""


def discover_sinks() -> list[Sink]:
    """Find sinks registered via the ``cordon.sinks`` entry-point group.

    Each entry point must point at a zero-argument callable (typically a
    class) that returns a :class:`Sink`. Failures to load any single
    entry are logged and skipped so one broken package can't take down
    every other sink."""
    try:
        import importlib.metadata as metadata
    except ImportError:  # pragma: no cover - python <3.8 unsupported
        return []

    discovered: list[Sink] = []
    try:
        eps = metadata.entry_points(group="cordon.sinks")
    except TypeError:
        # Older importlib.metadata API (Python 3.9): returns a dict-like
        eps = metadata.entry_points().get("cordon.sinks", [])  # type: ignore[attr-defined]
    for ep in eps:
        try:
            factory = ep.load()
            sink = factory()
            discovered.append(sink)
            _log.info("cordon: registered sink %r from entry point", ep.name)
        except Exception:
            _log.warning(
                "cordon: failed to load sink entry point %r", ep.name, exc_info=True
            )
    return discovered


def safe_record(sink: Sink, event: dict) -> None:
    """Call sink.record(event) with exception swallowing + logging."""
    try:
        sink.record(event)
    except Exception:
        _log.warning(
            "cordon: sink %s.record() raised; event dropped",
            type(sink).__name__,
            exc_info=True,
        )


def safe_close(sink: Sink) -> None:
    try:
        sink.close()
    except Exception:
        _log.warning(
            "cordon: sink %s.close() raised", type(sink).__name__, exc_info=True
        )
