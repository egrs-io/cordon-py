"""Canonical request representation.

Every shim normalizes its intercepted call into a `CanonicalRequest`
before handing it to the policy engine. The engine only ever sees this
shape — never raw SDK objects — which keeps `policy.py` independent of
the SDKs it governs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CanonicalRequest:
    vendor: str
    operation: str | None = None
    method: str | None = None
    path: str | None = None
    host: str | None = None
    params: Any = None
    body: Any = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Plain dict view — what the policy engine consumes."""
        return asdict(self)

    def describe(self) -> str:
        """One-line human description, used in audit `operation` fields."""
        if self.operation:
            return self.operation
        if self.method and self.path:
            return f"{self.method} {self.path}"
        if self.method:
            return self.method
        return self.vendor
