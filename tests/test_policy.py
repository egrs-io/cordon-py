import pytest

from egress_security.policy import Policy, PolicyError, load_policy


def _policy(rules, *, default="allow"):
    return Policy({"version": 1, "default": default, "rules": rules})


def test_default_allow_when_no_rules_match():
    p = _policy([])
    d = p.evaluate({"vendor": "aws:ec2", "operation": "DescribeInstances"})
    assert d.action == "allow"
    assert d.rule_id is None
    assert d.reason is None


def test_default_deny():
    p = _policy([], default="deny")
    assert p.evaluate({"vendor": "anything"}).action == "deny"


def test_deny_rule_matches_carries_reason_and_id():
    p = _policy(
        [
            {
                "id": "block-delete",
                "when": {"vendor": "github", "method": "DELETE"},
                "action": "deny",
                "reason": "no deletes",
            }
        ]
    )
    d = p.evaluate({"vendor": "github", "method": "DELETE", "path": "/repos/a/b"})
    assert d.action == "deny"
    assert d.rule_id == "block-delete"
    assert d.reason == "no deletes"


def test_deny_wins_over_earlier_allow():
    p = _policy(
        [
            {"id": "allow-1", "when": {"vendor": "github"}, "action": "allow"},
            {
                "id": "deny-1",
                "when": {"vendor": "github", "method": "DELETE"},
                "action": "deny",
                "reason": "destructive",
            },
        ]
    )
    d = p.evaluate({"vendor": "github", "method": "DELETE", "path": "/repos/a/b"})
    assert d.action == "deny"
    assert d.rule_id == "deny-1"


def test_regex_path_anchoring():
    p = _policy(
        [
            {
                "id": "rdel",
                "when": {
                    "vendor": "github",
                    "method": "DELETE",
                    "path": "^/repos/[^/]+/[^/]+$",
                },
                "action": "deny",
            }
        ]
    )
    assert (
        p.evaluate({"vendor": "github", "method": "DELETE", "path": "/repos/a/b"}).action
        == "deny"
    )
    # path with extra segments must NOT match the anchored regex
    assert (
        p.evaluate(
            {"vendor": "github", "method": "DELETE", "path": "/repos/a/b/issues/1"}
        ).action
        == "allow"
    )


def test_aws_prefix_regex():
    p = _policy(
        [
            {
                "id": "aws-del",
                "when": {"vendor": "^aws:", "operation": "^Delete"},
                "action": "deny",
            }
        ]
    )
    assert (
        p.evaluate({"vendor": "aws:s3", "operation": "DeleteBucket"}).action == "deny"
    )
    assert (
        p.evaluate({"vendor": "aws:s3", "operation": "GetObject"}).action == "allow"
    )
    assert p.evaluate({"vendor": "github", "method": "DELETE"}).action == "allow"


def test_body_matches_credential_in_string():
    p = _policy(
        [
            {
                "id": "secret",
                "when": {"vendor": "http", "body_matches": "AKIA[0-9A-Z]{16}"},
                "action": "deny",
            }
        ]
    )
    assert (
        p.evaluate({"vendor": "http", "body": "key=AKIAIOSFODNN7EXAMPLE"}).action
        == "deny"
    )
    assert p.evaluate({"vendor": "http", "body": "nothing"}).action == "allow"


def test_body_matches_handles_dict_and_bytes():
    p = _policy(
        [
            {
                "id": "secret",
                "when": {"vendor": "http", "body_matches": "AKIA[0-9A-Z]{16}"},
                "action": "deny",
            }
        ]
    )
    assert (
        p.evaluate(
            {"vendor": "http", "body": {"creds": "AKIAIOSFODNN7EXAMPLE"}}
        ).action
        == "deny"
    )
    assert (
        p.evaluate({"vendor": "http", "body": b"key=AKIAIOSFODNN7EXAMPLE"}).action
        == "deny"
    )


def test_host_not_in_blocks_unknown_with_wildcard():
    p = _policy(
        [
            {
                "id": "egress",
                "when": {
                    "vendor": "http",
                    "host_not_in": ["api.github.com", "*.amazonaws.com"],
                },
                "action": "deny",
            }
        ]
    )
    assert (
        p.evaluate({"vendor": "http", "host": "evil.example.com"}).action == "deny"
    )
    assert (
        p.evaluate({"vendor": "http", "host": "api.github.com"}).action == "allow"
    )
    assert (
        p.evaluate({"vendor": "http", "host": "s3.amazonaws.com"}).action == "allow"
    )


def test_load_policy_from_path(tmp_path):
    src = """
version: 1
default: allow
rules:
  - id: rule-1
    when: { vendor: 'aws:s3', operation: '^DeleteBucket$' }
    action: deny
    reason: nope
"""
    p_file = tmp_path / "policy.yaml"
    p_file.write_text(src)
    policy = load_policy(p_file)
    d = policy.evaluate({"vendor": "aws:s3", "operation": "DeleteBucket"})
    assert d.action == "deny"
    assert d.rule_id == "rule-1"
    assert d.reason == "nope"


def test_load_policy_from_dict():
    p = load_policy({"version": 1, "default": "allow", "rules": []})
    assert p.evaluate({"vendor": "anything"}).action == "allow"


def test_invalid_action_raises():
    with pytest.raises(PolicyError):
        Policy(
            {
                "version": 1,
                "default": "allow",
                "rules": [
                    {"id": "x", "when": {"vendor": "y"}, "action": "block"}
                ],
            }
        )


def test_unknown_predicate_raises():
    with pytest.raises(PolicyError):
        Policy(
            {
                "version": 1,
                "default": "allow",
                "rules": [{"id": "x", "when": {"foo": "bar"}, "action": "deny"}],
            }
        )


def test_unsupported_version_raises():
    with pytest.raises(PolicyError):
        Policy({"version": 99, "default": "allow", "rules": []})


def test_empty_when_raises():
    with pytest.raises(PolicyError):
        Policy(
            {
                "version": 1,
                "default": "allow",
                "rules": [{"id": "x", "when": {}, "action": "deny"}],
            }
        )


def test_invalid_regex_raises():
    with pytest.raises(PolicyError):
        Policy(
            {
                "version": 1,
                "default": "allow",
                "rules": [
                    {
                        "id": "x",
                        "when": {"vendor": "[unclosed"},
                        "action": "deny",
                    }
                ],
            }
        )


def test_bad_default_raises():
    with pytest.raises(PolicyError):
        Policy({"version": 1, "default": "maybe", "rules": []})


def test_missing_host_does_not_match_host_not_in_rule():
    # A canonical without a host string should not be matched by an HTTP
    # host_not_in rule — the rule simply does not apply.
    p = _policy(
        [
            {
                "id": "egress",
                "when": {"vendor": "http", "host_not_in": ["api.github.com"]},
                "action": "deny",
            }
        ]
    )
    assert (
        p.evaluate({"vendor": "aws:s3", "operation": "GetObject"}).action == "allow"
    )
