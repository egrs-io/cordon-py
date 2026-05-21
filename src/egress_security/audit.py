"""JSONL audit log with secret redaction.

One JSON object per line, written to a file (default `egress-audit.jsonl`)
and/or stdout. Anything matching a known secret pattern in the recorded
args is replaced with `***` before serialization.
"""

from __future__ import annotations

import json
import re
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any, Mapping

SECRET_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        r"AKIA[0-9A-Z]{16}",
        r"ghp_[A-Za-z0-9]{36}",
        r"github_pat_[A-Za-z0-9_]{20,}",
        r"sk-ant-[A-Za-z0-9-]{20,}",
        r"sk-[A-Za-z0-9]{20,}",
    )
)


def redact(value: Any) -> Any:
    """Recursively replace anything matching SECRET_PATTERNS with '***'."""
    if isinstance(value, str):
        out = value
        for pat in SECRET_PATTERNS:
            out = pat.sub("***", out)
        return out
    if isinstance(value, bytes):
        try:
            return redact(value.decode("utf-8"))
        except UnicodeDecodeError:
            return "<bytes>"
    if isinstance(value, Mapping):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact(v) for v in value)
    return value


class AuditLogger:
    """Append-one-JSON-object-per-line audit log."""

    def __init__(
        self,
        *,
        path: str | Path | None = "egress-audit.jsonl",
        stdout: bool = False,
        session_id: str | None = None,
    ) -> None:
        self.path: Path | None = Path(path) if path is not None else None
        self.stdout = stdout
        self.session_id = session_id or uuid.uuid4().hex[:12]
        self._lock = threading.Lock()
        self._file: IO[str] | None = None
        if self.path is not None:
            self._file = self.path.open("a", encoding="utf-8")

    def record(
        self,
        *,
        vendor: str,
        operation: str | None,
        decision: str,
        reason: str | None = None,
        rule_id: str | None = None,
        args: Any = None,
    ) -> dict[str, Any]:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "session_id": self.session_id,
            "vendor": vendor,
            "operation": operation,
            "decision": decision,
            "reason": reason,
            "rule_id": rule_id,
            "args": redact(args),
        }
        line = json.dumps(entry, default=str)
        with self._lock:
            if self._file is not None:
                self._file.write(line + "\n")
                self._file.flush()
            if self.stdout:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
        return entry

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                self._file.close()
                self._file = None

    def __enter__(self) -> "AuditLogger":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()
