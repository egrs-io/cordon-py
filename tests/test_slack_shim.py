import json

import pytest

import egress_security
from egress_security import EgressSecurityDenied

slack_sdk = pytest.importorskip("slack_sdk")


POLICY = {
    "version": 1,
    "default": "allow",
    "rules": [
        {
            "id": "block-chat-write",
            "when": {"vendor": "slack", "operation": "^chat\\."},
            "action": "deny",
            "reason": "no chat writes in this test",
        }
    ],
}


@pytest.fixture(autouse=True)
def _clean():
    yield
    egress_security.uninstall()


def test_chat_postmessage_denied(tmp_path):
    egress_security.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    client = slack_sdk.WebClient(token="xoxb-fake")
    with pytest.raises(EgressSecurityDenied) as exc:
        client.chat_postMessage(channel="#general", text="hi")
    assert exc.value.vendor == "slack"
    assert exc.value.operation == "chat.postMessage"
    assert exc.value.rule_id == "block-chat-write"
    entry = json.loads((tmp_path / "a.jsonl").read_text().strip())
    assert entry["decision"] == "deny"
    assert entry["operation"] == "chat.postMessage"


def test_allowed_call_passes_through(tmp_path, monkeypatch):
    egress_security.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    # Mock the lowest-level network method below the chokepoint so the
    # wrapper's call-through actually returns without hitting Slack.
    from slack_sdk.web.base_client import BaseClient

    def fake_perform(self, *_a, **_kw):
        return {"status": 200, "body": '{"ok": true}', "headers": {}}

    monkeypatch.setattr(BaseClient, "_perform_urllib_http_request", fake_perform)

    client = slack_sdk.WebClient(token="xoxb-fake")
    resp = client.users_info(user="U123")
    assert resp["ok"] is True
    entry = json.loads((tmp_path / "a.jsonl").read_text().strip())
    assert entry["decision"] == "allow"
    assert entry["vendor"] == "slack"
    assert entry["operation"] == "users.info"


def test_install_idempotent(tmp_path):
    egress_security.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    from egress_security.shims import slack_shim

    slack_shim.install()
    client = slack_sdk.WebClient(token="xoxb-fake")
    with pytest.raises(EgressSecurityDenied):
        client.chat_postMessage(channel="#x", text="y")


def test_uninstall_removes_patch(tmp_path):
    egress_security.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    egress_security.uninstall()
    from egress_security.shims import slack_shim

    assert slack_shim._installed is False
