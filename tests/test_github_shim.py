import json

import pytest

import egress_security
from egress_security import EgressSecurityDenied

github = pytest.importorskip("github")
responses = pytest.importorskip("responses")


POLICY = {
    "version": 1,
    "default": "allow",
    "rules": [
        {
            "id": "block-repo-delete",
            "when": {
                "vendor": "github",
                "method": "DELETE",
                "path": "^/repos/[^/]+/[^/]+$",
            },
            "action": "deny",
            "reason": "destructive",
        }
    ],
}


@pytest.fixture(autouse=True)
def _clean():
    yield
    egress_security.uninstall()


def _requester():
    from github.Auth import Token
    from github.Requester import Requester

    return Requester(
        auth=Token("fake-token"),
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


def test_delete_repo_denied_before_network(tmp_path):
    egress_security.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    req = _requester()
    with pytest.raises(EgressSecurityDenied) as exc:
        req.requestJsonAndCheck("DELETE", "/repos/acme/widget")
    assert exc.value.vendor == "github"
    assert "DELETE" in exc.value.operation
    assert exc.value.rule_id == "block-repo-delete"
    entry = json.loads((tmp_path / "a.jsonl").read_text().strip())
    assert entry["decision"] == "deny"
    assert entry["operation"] == "DELETE /repos/acme/widget"


@responses.activate
def test_get_repo_allowed_and_audited(tmp_path):
    egress_security.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    responses.add(
        responses.GET,
        "https://api.github.com:443/repos/acme/widget",
        json={"id": 1, "full_name": "acme/widget"},
        status=200,
    )
    req = _requester()
    headers, data = req.requestJsonAndCheck("GET", "/repos/acme/widget")
    assert data["full_name"] == "acme/widget"
    entry = json.loads((tmp_path / "a.jsonl").read_text().strip())
    assert entry["vendor"] == "github"
    assert entry["decision"] == "allow"
    assert entry["operation"] == "GET /repos/acme/widget"


def test_install_idempotent(tmp_path):
    egress_security.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    from egress_security.shims import github_shim

    github_shim.install()
    req = _requester()
    with pytest.raises(EgressSecurityDenied):
        req.requestJsonAndCheck("DELETE", "/repos/acme/widget")


@responses.activate
def test_uninstall_removes_patch(tmp_path):
    egress_security.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    egress_security.uninstall()
    responses.add(
        responses.DELETE,
        "https://api.github.com:443/repos/acme/widget",
        status=204,
    )
    req = _requester()
    # After uninstall the call should pass through (no EgressSecurityDenied)
    req.requestJsonAndCheck("DELETE", "/repos/acme/widget")
