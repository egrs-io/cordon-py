from egress_security.canonical import CanonicalRequest


def test_minimal_construction():
    req = CanonicalRequest(vendor="github")
    assert req.vendor == "github"
    assert req.operation is None
    assert req.method is None
    assert req.raw == {}


def test_to_dict_includes_all_fields():
    req = CanonicalRequest(
        vendor="aws:s3",
        operation="DeleteBucket",
        params={"Bucket": "x"},
    )
    d = req.to_dict()
    assert d["vendor"] == "aws:s3"
    assert d["operation"] == "DeleteBucket"
    assert d["params"] == {"Bucket": "x"}
    # absent fields are present as None so the policy matcher sees them as missing
    assert d["method"] is None
    assert d["path"] is None


def test_describe_prefers_operation():
    req = CanonicalRequest(vendor="aws:s3", operation="DeleteBucket")
    assert req.describe() == "DeleteBucket"


def test_describe_falls_back_to_method_and_path():
    req = CanonicalRequest(vendor="github", method="DELETE", path="/repos/a/b")
    assert req.describe() == "DELETE /repos/a/b"


def test_describe_falls_back_to_vendor():
    req = CanonicalRequest(vendor="github")
    assert req.describe() == "github"


def test_canonical_is_consumable_by_policy_engine():
    from egress_security.policy import Policy

    p = Policy(
        {
            "version": 1,
            "default": "allow",
            "rules": [
                {
                    "id": "x",
                    "when": {"vendor": "^aws:", "operation": "^Delete"},
                    "action": "deny",
                }
            ],
        }
    )
    req = CanonicalRequest(vendor="aws:s3", operation="DeleteBucket")
    assert p.evaluate(req.to_dict()).action == "deny"
