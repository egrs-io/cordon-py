import json

import pytest

import egress_security
from egress_security import EgressSecurityDenied

boto3 = pytest.importorskip("boto3")
botocore = pytest.importorskip("botocore")
from botocore.stub import Stubber  # noqa: E402

POLICY = {
    "version": 1,
    "default": "allow",
    "rules": [
        {
            "id": "block-aws-deletes",
            "when": {"vendor": "^aws:", "operation": "^Delete"},
            "action": "deny",
            "reason": "destructive",
        },
        {
            "id": "block-ec2-terminate",
            "when": {"vendor": "aws:ec2", "operation": "^TerminateInstances$"},
            "action": "deny",
            "reason": "terminating ec2 is destructive",
        },
    ],
}


@pytest.fixture(autouse=True)
def _clean():
    yield
    egress_security.uninstall()


def _s3_client():
    return boto3.client(
        "s3",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def _ec2_client():
    return boto3.client(
        "ec2",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def test_allowed_call_passes_through(tmp_path):
    egress_security.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    client = _s3_client()
    stubber = Stubber(client)
    stubber.add_response("list_buckets", {"Buckets": []})
    stubber.activate()
    resp = client.list_buckets()
    assert "Buckets" in resp
    # audit line written for the allowed call
    lines = (tmp_path / "a.jsonl").read_text().strip().splitlines()
    entry = json.loads(lines[0])
    assert entry["vendor"] == "aws:s3"
    assert entry["operation"] == "ListBuckets"
    assert entry["decision"] == "allow"


def test_destructive_s3_delete_denied(tmp_path):
    egress_security.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    client = _s3_client()
    with pytest.raises(EgressSecurityDenied) as exc:
        client.delete_bucket(Bucket="my-bucket")
    assert exc.value.vendor == "aws:s3"
    assert exc.value.operation == "DeleteBucket"
    assert exc.value.rule_id == "block-aws-deletes"
    entry = json.loads((tmp_path / "a.jsonl").read_text().strip())
    assert entry["decision"] == "deny"
    assert entry["vendor"] == "aws:s3"
    assert entry["args"] == {"Bucket": "my-bucket"}


def test_ec2_terminate_denied(tmp_path):
    egress_security.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    client = _ec2_client()
    with pytest.raises(EgressSecurityDenied) as exc:
        client.terminate_instances(InstanceIds=["i-abc"])
    assert exc.value.vendor == "aws:ec2"
    assert exc.value.operation == "TerminateInstances"
    assert exc.value.rule_id == "block-ec2-terminate"


def test_install_is_idempotent(tmp_path):
    egress_security.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    from egress_security.shims import boto3_shim

    # Calling install a second time should not double-patch.
    boto3_shim.install()
    client = _ec2_client()
    with pytest.raises(EgressSecurityDenied):
        client.terminate_instances(InstanceIds=["i-abc"])


def test_uninstall_removes_patch(tmp_path):
    egress_security.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    egress_security.uninstall()
    # After uninstall, the destructive call should be governed no more.
    client = _s3_client()
    stubber = Stubber(client)
    stubber.add_response("delete_bucket", {})
    stubber.activate()
    client.delete_bucket(Bucket="my-bucket")  # no raise
