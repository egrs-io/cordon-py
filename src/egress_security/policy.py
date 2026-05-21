"""YAML policy loader and matcher.

A policy is a list of rules; deny rules win; the default is configurable
(`allow` by default). A rule matches when **all** of its predicates match
the canonical request. Regex predicates use `re.search`, so anchor them
explicitly (``^...$``) if you want exact matches.

Supported predicates (`when:`):
    vendor, method, operation, path, host    -- regex over the canonical string
    body_matches                              -- regex over the serialized body/params
    host_not_in                               -- list of host patterns (fnmatch wildcards
                                                 like ``*.amazonaws.com``); the predicate
                                                 matches if the host is NOT in the list.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

_REGEX_PREDICATES = ("vendor", "method", "operation", "path", "host", "body_matches")
_ALL_PREDICATES = set(_REGEX_PREDICATES) | {"host_not_in"}


class PolicyError(Exception):
    """Raised when a policy file is malformed."""


@dataclass(frozen=True)
class Decision:
    action: str  # "allow" or "deny"
    reason: str | None = None
    rule_id: str | None = None


class _Rule:
    __slots__ = ("id", "action", "reason", "_patterns", "_host_not_in")

    def __init__(self, raw: Mapping[str, Any]) -> None:
        if not isinstance(raw, Mapping):
            raise PolicyError(f"rule must be a mapping, got {type(raw).__name__}")
        self.id: str = str(raw.get("id") or "<unnamed>")

        action = raw.get("action")
        if action not in ("allow", "deny"):
            raise PolicyError(f"rule {self.id!r}: action must be 'allow' or 'deny'")
        self.action: str = action
        self.reason: str | None = raw.get("reason")

        when = raw.get("when") or {}
        if not isinstance(when, Mapping):
            raise PolicyError(f"rule {self.id!r}: when must be a mapping")
        unknown = set(when) - _ALL_PREDICATES
        if unknown:
            raise PolicyError(
                f"rule {self.id!r}: unknown predicate(s): {sorted(unknown)}"
            )

        self._patterns: dict[str, re.Pattern[str]] = {}
        for key in _REGEX_PREDICATES:
            v = when.get(key)
            if v is None:
                continue
            if not isinstance(v, str):
                raise PolicyError(f"rule {self.id!r}: {key} must be a string")
            try:
                self._patterns[key] = re.compile(v)
            except re.error as e:
                raise PolicyError(f"rule {self.id!r}: invalid regex for {key}: {e}")

        host_not_in = when.get("host_not_in")
        if host_not_in is None:
            self._host_not_in: list[str] | None = None
        else:
            if not isinstance(host_not_in, list) or not all(
                isinstance(x, str) for x in host_not_in
            ):
                raise PolicyError(
                    f"rule {self.id!r}: host_not_in must be a list of strings"
                )
            self._host_not_in = list(host_not_in)

        if not self._patterns and self._host_not_in is None:
            raise PolicyError(
                f"rule {self.id!r}: when must specify at least one predicate"
            )

    def matches(self, canonical: Mapping[str, Any]) -> bool:
        for key, pat in self._patterns.items():
            if key == "body_matches":
                text = _stringify_for_match(
                    canonical.get("body", canonical.get("params"))
                )
                if not pat.search(text):
                    return False
                continue
            value = canonical.get(key)
            if not isinstance(value, str) or not pat.search(value):
                return False

        if self._host_not_in is not None:
            host = canonical.get("host")
            if not isinstance(host, str):
                return False
            if _host_matches_any(host, self._host_not_in):
                return False
        return True


def _stringify_for_match(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return str(value)


def _host_matches_any(host: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(host, p) for p in patterns)


class Policy:
    """A loaded, validated policy. Construct via `load_policy()`."""

    def __init__(self, raw: Mapping[str, Any]) -> None:
        if not isinstance(raw, Mapping):
            raise PolicyError(f"policy must be a mapping, got {type(raw).__name__}")
        version = raw.get("version", 1)
        if version != 1:
            raise PolicyError(f"unsupported policy version: {version}")
        default = raw.get("default", "allow")
        if default not in ("allow", "deny"):
            raise PolicyError(f"default must be 'allow' or 'deny', got {default!r}")
        self.default: str = default
        rules_raw = raw.get("rules") or []
        if not isinstance(rules_raw, list):
            raise PolicyError("rules must be a list")
        self.rules: list[_Rule] = [_Rule(r) for r in rules_raw]

    def evaluate(self, canonical: Mapping[str, Any]) -> Decision:
        first_allow: _Rule | None = None
        for rule in self.rules:
            if not rule.matches(canonical):
                continue
            if rule.action == "deny":
                return Decision(
                    action="deny", reason=rule.reason, rule_id=rule.id
                )
            if first_allow is None:
                first_allow = rule
        if first_allow is not None:
            return Decision(
                action="allow", reason=first_allow.reason, rule_id=first_allow.id
            )
        return Decision(action=self.default)


def load_policy(source: str | Path | Mapping[str, Any]) -> Policy:
    """Load a policy from a YAML file path or an in-memory mapping."""
    if isinstance(source, Mapping):
        return Policy(source)
    path = Path(source)
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, Mapping):
        raise PolicyError(f"policy file {path} did not contain a YAML mapping")
    return Policy(data)
