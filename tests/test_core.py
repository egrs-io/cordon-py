import json

import pytest

import cordon
from cordon import _core
from cordon.canonical import CanonicalRequest


@pytest.fixture(autouse=True)
def _clean_state():
    yield
    cordon.uninstall()


_BLOCK_DELETE_POLICY = {
    "version": 1,
    "default": "allow",
    "rules": [
        {
            "id": "block-delete",
            "when": {"vendor": "github", "method": "DELETE"},
            "action": "deny",
            "reason": "destructive",
        }
    ],
}


def _init(tmp_path, **overrides):
    kwargs = {
        "policy": _BLOCK_DELETE_POLICY,
        "audit": str(tmp_path / "audit.jsonl"),
        "mode": "enforce",
        "on_error": "open",
    }
    kwargs.update(overrides)
    cordon.init(**kwargs)


def test_init_then_govern_allow(tmp_path):
    _init(tmp_path)
    req = CanonicalRequest(vendor="github", method="GET", path="/repos/a/b")
    _core.govern(req)  # should not raise


def test_init_then_govern_deny_raises_in_enforce(tmp_path):
    _init(tmp_path)
    req = CanonicalRequest(vendor="github", method="DELETE", path="/repos/a/b")
    with pytest.raises(cordon.CordonDenied) as exc:
        _core.govern(req)
    assert exc.value.vendor == "github"
    assert exc.value.rule_id == "block-delete"
    assert exc.value.reason == "destructive"


def test_monitor_mode_audits_without_blocking(tmp_path):
    _init(tmp_path, mode="monitor")
    req = CanonicalRequest(vendor="github", method="DELETE", path="/repos/a/b")
    _core.govern(req)  # must not raise
    line = (tmp_path / "audit.jsonl").read_text().strip()
    entry = json.loads(line)
    assert entry["decision"] == "deny"  # decision still recorded


def test_no_config_is_passthrough(tmp_path):
    # Without init(), govern is a no-op.
    req = CanonicalRequest(vendor="github", method="DELETE", path="/repos/a/b")
    _core.govern(req)  # no raise


def test_catch_all_suppressed_inside_vendor_scope(tmp_path):
    _init(tmp_path)
    req = CanonicalRequest(vendor="github", method="DELETE", path="/repos/a/b")
    # Outer vendor-specific scope; an inner catch-all call should be suppressed
    # even though the policy would deny it.
    with _core.vendor_scope():
        _core.govern(req, is_catch_all=True)  # suppressed — must not raise
    # Outside the scope, the same catch-all call should be evaluated again
    # (and in this case, the policy would deny the github DELETE — but a
    # catch-all wouldn't actually pass vendor=github; using http here.)
    req2 = CanonicalRequest(vendor="http", method="GET", host="api.github.com")
    _core.govern(req2, is_catch_all=True)  # not denied; default allow


def test_init_writes_audit_line(tmp_path):
    _init(tmp_path)
    req = CanonicalRequest(vendor="github", method="GET", path="/repos/a/b")
    _core.govern(req)
    entry = json.loads((tmp_path / "audit.jsonl").read_text().strip())
    assert entry["decision"] == "allow"
    assert entry["vendor"] == "github"
    assert entry["operation"] == "GET /repos/a/b"


def test_uninstall_closes_audit_and_clears_config(tmp_path):
    _init(tmp_path)
    assert _core.is_active() is True
    cordon.uninstall()
    assert _core.is_active() is False
    # govern is now a no-op
    _core.govern(CanonicalRequest(vendor="github", method="DELETE"))


def test_uninstall_safe_when_not_active():
    cordon.uninstall()  # no raise


def test_re_init_replaces_previous(tmp_path):
    _init(tmp_path)
    _init(tmp_path, audit=str(tmp_path / "audit2.jsonl"))
    req = CanonicalRequest(vendor="github", method="GET", path="/x")
    _core.govern(req)
    # Only the second file should have entries
    assert (tmp_path / "audit2.jsonl").read_text().strip()


def test_invalid_mode_raises():
    with pytest.raises(ValueError):
        cordon.init(policy=_BLOCK_DELETE_POLICY, audit=None, mode="warn")


def test_invalid_on_error_raises():
    with pytest.raises(ValueError):
        cordon.init(
            policy=_BLOCK_DELETE_POLICY, audit=None, on_error="maybe"
        )


def test_denied_message_includes_vendor_operation_rule_reason(tmp_path):
    _init(tmp_path)
    req = CanonicalRequest(vendor="github", method="DELETE", path="/repos/a/b")
    with pytest.raises(cordon.CordonDenied) as exc:
        _core.govern(req)
    msg = str(exc.value)
    assert "github" in msg
    assert "DELETE" in msg
    assert "block-delete" in msg
    assert "destructive" in msg
