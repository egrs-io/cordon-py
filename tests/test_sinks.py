"""Tests for the pluggable Sink interface."""

import os

import pytest

import cordon
from cordon import Sink
from cordon._core import _config
from cordon.canonical import CanonicalRequest


_PASSTHROUGH_POLICY = {
    "version": 1,
    "default": "allow",
    "rules": [
        {
            "id": "block-x",
            "when": {"vendor": "github", "method": "DELETE"},
            "action": "deny",
            "reason": "no",
        }
    ],
}


class _CollectingSink:
    """Test sink that just stashes every event in a list."""

    def __init__(self) -> None:
        self.events: list[dict] = []
        self.closed = False

    def record(self, event: dict) -> None:
        self.events.append(event)

    def close(self) -> None:
        self.closed = True


class _ExplodingSink:
    """Sink whose record() always raises; used to verify error containment."""

    def __init__(self) -> None:
        self.attempts = 0

    def record(self, event: dict) -> None:
        self.attempts += 1
        raise RuntimeError("simulated sink failure")

    def close(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    monkeypatch.delenv("CORDON_API_URL", raising=False)
    monkeypatch.delenv("CORDON_API_KEY", raising=False)
    yield
    cordon.uninstall()


def _govern(name: str = "github", method: str = "GET") -> None:
    from cordon._core import govern

    govern(CanonicalRequest(vendor=name, method=method, path="/x"))


def test_sink_protocol_recognizes_collecting_sink():
    """A class with record() + close() satisfies the protocol via runtime_checkable."""
    assert isinstance(_CollectingSink(), Sink)


def test_explicit_sink_receives_every_event(tmp_path):
    sink = _CollectingSink()
    cordon.init(
        policy=_PASSTHROUGH_POLICY,
        audit=str(tmp_path / "a.jsonl"),
        sinks=[sink],
    )
    _govern()
    _govern()
    assert len(sink.events) == 2
    assert sink.events[0]["vendor"] == "github"
    assert sink.events[0]["decision"] == "allow"


def test_multiple_sinks_all_called(tmp_path):
    a, b = _CollectingSink(), _CollectingSink()
    cordon.init(
        policy=_PASSTHROUGH_POLICY,
        audit=str(tmp_path / "a.jsonl"),
        sinks=[a, b],
    )
    _govern()
    assert len(a.events) == 1
    assert len(b.events) == 1


def test_sink_receives_deny_decisions_too(tmp_path):
    sink = _CollectingSink()
    cordon.init(
        policy=_PASSTHROUGH_POLICY,
        audit=str(tmp_path / "a.jsonl"),
        sinks=[sink],
        mode="monitor",
    )
    _govern(method="DELETE")
    assert len(sink.events) == 1
    assert sink.events[0]["decision"] == "deny"


def test_failing_sink_does_not_break_govern(tmp_path):
    exploding = _ExplodingSink()
    good = _CollectingSink()
    cordon.init(
        policy=_PASSTHROUGH_POLICY,
        audit=str(tmp_path / "a.jsonl"),
        sinks=[exploding, good],
    )
    _govern()
    _govern()
    # Exploding sink was called both times, but the good sink also received both.
    assert exploding.attempts == 2
    assert len(good.events) == 2


def test_uninstall_closes_all_sinks(tmp_path):
    sink = _CollectingSink()
    cordon.init(
        policy=_PASSTHROUGH_POLICY,
        audit=str(tmp_path / "a.jsonl"),
        sinks=[sink],
    )
    assert sink.closed is False
    cordon.uninstall()
    assert sink.closed is True


def test_api_url_and_api_key_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CORDON_API_URL", "https://api.egrs.io/v1/events")
    monkeypatch.setenv("CORDON_API_KEY", "ck_acme_abc123")
    cordon.init(policy=_PASSTHROUGH_POLICY, audit=str(tmp_path / "a.jsonl"))
    assert cordon.api_url() == "https://api.egrs.io/v1/events"
    assert cordon.api_key() == "ck_acme_abc123"


def test_api_url_and_api_key_none_when_unset(tmp_path):
    cordon.init(policy=_PASSTHROUGH_POLICY, audit=str(tmp_path / "a.jsonl"))
    assert cordon.api_url() is None
    assert cordon.api_key() is None


def test_api_url_and_api_key_none_before_init():
    assert cordon.api_url() is None
    assert cordon.api_key() is None


def test_empty_env_var_is_treated_as_unset(monkeypatch, tmp_path):
    monkeypatch.setenv("CORDON_API_URL", "   ")  # whitespace only
    cordon.init(policy=_PASSTHROUGH_POLICY, audit=str(tmp_path / "a.jsonl"))
    assert cordon.api_url() is None


def test_discover_sinks_returns_empty_when_no_entry_points():
    # We haven't registered any entry points in this test env so this just
    # confirms it returns a list (possibly empty) and doesn't raise.
    from cordon.sinks import discover_sinks

    result = discover_sinks()
    assert isinstance(result, list)
