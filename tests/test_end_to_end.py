"""End-to-end smoke tests against the real `policies/agent-default.yaml`.

Verifies the default policy pack actually blocks the destructive calls
it claims to and lets benign calls through, across every shim.
"""

import json
from pathlib import Path

import pytest

import cordon
from cordon import CordonDenied

DEFAULT_POLICY = (
    Path(__file__).resolve().parent.parent / "policies" / "agent-default.yaml"
)


@pytest.fixture(autouse=True)
def _isolated(tmp_path):
    cordon.init(
        policy=str(DEFAULT_POLICY),
        audit=str(tmp_path / "audit.jsonl"),
    )
    yield tmp_path
    cordon.uninstall()


def _audit_lines(tmp_path):
    p = tmp_path / "audit.jsonl"
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text().strip().splitlines() if l]


# ---------------------------------------------------------------- github

def _gh_requester():
    from github.Auth import Token
    from github.Requester import Requester

    return Requester(
        auth=Token("fake"),
        base_url="https://api.github.com",
        timeout=15,
        user_agent="e2e",
        per_page=30,
        verify=True,
        retry=None,
        pool_size=None,
        seconds_between_requests=0,
        seconds_between_writes=0,
    )


def test_default_blocks_github_repo_delete(_isolated):
    with pytest.raises(CordonDenied) as exc:
        _gh_requester().requestJsonAndCheck("DELETE", "/repos/acme/widget")
    assert exc.value.rule_id == "block-github-repo-delete"


def test_default_blocks_github_ref_rewrite(_isolated):
    with pytest.raises(CordonDenied) as exc:
        _gh_requester().requestJsonAndCheck(
            "PATCH", "/repos/acme/widget/git/refs/heads/main"
        )
    assert exc.value.rule_id == "block-github-ref-rewrite"


# ---------------------------------------------------------------- aws / boto3

def _aws_client(service):
    import boto3

    return boto3.client(
        service,
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def test_default_blocks_ec2_terminate(_isolated):
    with pytest.raises(CordonDenied) as exc:
        _aws_client("ec2").terminate_instances(InstanceIds=["i-abc"])
    assert exc.value.rule_id == "block-aws-terminate"


def test_default_blocks_s3_delete_bucket(_isolated):
    with pytest.raises(CordonDenied) as exc:
        _aws_client("s3").delete_bucket(Bucket="b")
    # Could match block-aws-terminate (no) or block-aws-deletes (yes) -- deny wins
    assert exc.value.rule_id == "block-aws-deletes"


def test_default_blocks_iam_create_role(_isolated):
    with pytest.raises(CordonDenied) as exc:
        _aws_client("iam").create_role(
            RoleName="x", AssumeRolePolicyDocument="{}"
        )
    assert exc.value.rule_id == "block-aws-iam-writes"


def test_default_allows_benign_aws_call(_isolated):
    from botocore.stub import Stubber

    client = _aws_client("s3")
    stubber = Stubber(client)
    stubber.add_response("list_buckets", {"Buckets": []})
    stubber.activate()
    client.list_buckets()
    lines = _audit_lines(_isolated)
    assert any(
        e["vendor"] == "aws:s3"
        and e["operation"] == "ListBuckets"
        and e["decision"] == "allow"
        for e in lines
    )


# ---------------------------------------------------------------- http catch-all

def test_default_blocks_secret_exfil_over_requests(_isolated):
    import requests

    with pytest.raises(CordonDenied) as exc:
        # Allowed host, but body contains an AWS key — secret rule fires.
        requests.post(
            "https://api.github.com/leak",
            json={"creds": "AKIAIOSFODNN7EXAMPLE"},
        )
    assert exc.value.rule_id == "block-secret-exfiltration"


def test_default_blocks_unknown_host_over_requests(_isolated):
    import requests

    with pytest.raises(CordonDenied) as exc:
        requests.get("https://evil.example/x")
    assert exc.value.rule_id == "block-unknown-egress"


def test_default_blocks_secret_exfil_over_httpx(_isolated):
    import httpx

    with pytest.raises(CordonDenied) as exc:
        with httpx.Client() as c:
            c.post(
                "https://api.github.com/leak",
                json={"key": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            )
    assert exc.value.rule_id == "block-secret-exfiltration"


def test_default_allows_known_host_without_secrets(_isolated):
    import responses
    import requests

    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            "https://api.github.com/repos/a/b",
            json={"ok": True},
            status=200,
        )
        # Calling api.github.com via requests goes through the github_shim
        # chokepoint only if it's PyGithub; plain requests.get hits the
        # http catch-all and should be allowed (host on the allowlist).
        r = requests.get("https://api.github.com/repos/a/b")
        assert r.status_code == 200
    lines = _audit_lines(_isolated)
    assert any(
        e["vendor"] == "http"
        and e["decision"] == "allow"
        and e["operation"] == "GET /repos/a/b"
        for e in lines
    )


# ---------------------------------------------------------------- subprocess

def test_default_blocks_curl_shellout(_isolated):
    import subprocess

    with pytest.raises(CordonDenied) as exc:
        subprocess.run(["curl", "https://example.com"])
    assert exc.value.rule_id == "block-network-cli-shellout"


def test_default_blocks_git_push_shellout(_isolated):
    import subprocess

    with pytest.raises(CordonDenied) as exc:
        subprocess.run(["git", "push", "origin", "main"])
    assert exc.value.rule_id == "block-git-network-shellout"


def test_default_blocks_docker_pull_shellout(_isolated):
    import subprocess

    with pytest.raises(CordonDenied) as exc:
        subprocess.run(["docker", "pull", "alpine"])
    assert exc.value.rule_id == "block-docker-network-shellout"


def test_default_allows_local_subprocess(_isolated):
    import subprocess

    # `true` is local, no network, and not in any deny rule.
    assert subprocess.run(["true"]).returncode == 0
