import json

import pytest

from cordon.audit import AuditLogger, redact


def test_redact_replaces_aws_access_key():
    assert redact("key=AKIAIOSFODNN7EXAMPLE end") == "key=*** end"


def test_redact_replaces_github_pat():
    s = "token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 trailing"
    assert "***" in redact(s)
    assert "ghp_" not in redact(s)


def test_redact_replaces_anthropic_key():
    s = "auth=sk-ant-abc123XYZdef456ghi789jkl"
    assert "sk-ant-" not in redact(s)


def test_redact_replaces_openai_key():
    s = "auth=sk-aabbccddeeff112233445566"
    assert "sk-" not in redact(s)


def test_redact_recurses_into_dicts_and_lists():
    payload = {
        "headers": {"Authorization": "Bearer sk-1234567890abcdefghij"},
        "body": ["AKIAIOSFODNN7EXAMPLE", "harmless"],
    }
    out = redact(payload)
    assert out["headers"]["Authorization"] == "Bearer ***"
    assert out["body"][0] == "***"
    assert out["body"][1] == "harmless"


def test_redact_handles_bytes():
    assert redact(b"key=AKIAIOSFODNN7EXAMPLE") == "key=***"


def test_redact_handles_tuple():
    out = redact(("AKIAIOSFODNN7EXAMPLE", 42))
    assert out == ("***", 42)


def test_redact_passes_through_other_types():
    assert redact(42) == 42
    assert redact(None) is None
    assert redact(True) is True


def test_record_writes_one_line_per_call(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    with AuditLogger(path=log_path, session_id="sess-test") as al:
        al.record(
            vendor="github",
            operation="DELETE /repos/a/b",
            decision="deny",
            reason="destructive",
            rule_id="r1",
            args={"verb": "DELETE", "url": "/repos/a/b"},
        )
        al.record(
            vendor="aws:s3",
            operation="GetObject",
            decision="allow",
        )
    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 2
    entries = [json.loads(line) for line in lines]
    assert entries[0]["vendor"] == "github"
    assert entries[0]["decision"] == "deny"
    assert entries[0]["rule_id"] == "r1"
    assert entries[0]["reason"] == "destructive"
    assert entries[0]["session_id"] == "sess-test"
    assert entries[0]["ts"].endswith("Z")
    assert entries[1]["vendor"] == "aws:s3"


def test_record_redacts_args(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    with AuditLogger(path=log_path) as al:
        al.record(
            vendor="http",
            operation="POST /v1/messages",
            decision="deny",
            args={"body": "key=AKIAIOSFODNN7EXAMPLE secret"},
        )
    entry = json.loads(log_path.read_text().strip())
    assert "AKIA" not in json.dumps(entry)
    assert "***" in entry["args"]["body"]


def test_record_stdout_only(capsys, tmp_path):
    with AuditLogger(path=None, stdout=True, session_id="s") as al:
        al.record(vendor="github", operation="DELETE", decision="deny")
    out = capsys.readouterr().out.strip()
    assert out
    entry = json.loads(out)
    assert entry["vendor"] == "github"
    assert entry["session_id"] == "s"


def test_session_id_auto_generated():
    with AuditLogger(path=None) as al:
        assert isinstance(al.session_id, str)
        assert len(al.session_id) >= 8


def test_close_is_idempotent(tmp_path):
    al = AuditLogger(path=tmp_path / "a.jsonl")
    al.close()
    al.close()  # should not raise
