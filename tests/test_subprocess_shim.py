import subprocess

import pytest

import egress_security
from egress_security import EgressSecurityDenied

POLICY = {
    "version": 1,
    "default": "allow",
    "rules": [
        {
            "id": "block-curl",
            "when": {"vendor": "subprocess", "operation": "^curl$"},
            "action": "deny",
            "reason": "no shell-out to curl",
        },
        {
            "id": "block-git-push",
            "when": {
                "vendor": "subprocess",
                "operation": "^git$",
                "body_matches": r"\bpush\b",
            },
            "action": "deny",
            "reason": "no git push via subprocess",
        },
    ],
}


@pytest.fixture(autouse=True)
def _clean(tmp_path):
    egress_security.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    yield
    egress_security.uninstall()


def test_allowed_command_runs():
    # `true` is universal on Unix and returns 0 with no output / side effects.
    assert subprocess.run(["true"]).returncode == 0


def test_curl_blocked_by_basename():
    with pytest.raises(EgressSecurityDenied) as exc:
        subprocess.run(["curl", "https://example.com"])
    assert exc.value.rule_id == "block-curl"
    assert exc.value.operation == "curl"


def test_curl_blocked_via_full_path():
    with pytest.raises(EgressSecurityDenied) as exc:
        subprocess.run(["/usr/bin/curl", "https://example.com"])
    assert exc.value.rule_id == "block-curl"  # operation is basename(argv[0])


def test_shell_true_string_is_parsed():
    # When shell=True and the command is a string, we tokenize it so the
    # policy sees the actual binary, not "/bin/sh".
    with pytest.raises(EgressSecurityDenied) as exc:
        subprocess.run("curl https://example.com", shell=True)
    assert exc.value.rule_id == "block-curl"


def test_git_push_blocked_via_body_match():
    with pytest.raises(EgressSecurityDenied) as exc:
        subprocess.run(["git", "push", "origin", "main"])
    assert exc.value.rule_id == "block-git-push"


def test_git_non_push_subcommand_not_blocked():
    # `git --version` is local; the push rule should not fire.
    try:
        subprocess.run(["git", "--version"], capture_output=True, timeout=5)
    except FileNotFoundError:
        pytest.skip("git not installed")
    # If we got here, no EgressSecurityDenied was raised. Test passes.


def test_install_is_idempotent():
    from egress_security.shims import subprocess_shim

    subprocess_shim.install()  # second call should be a no-op
    with pytest.raises(EgressSecurityDenied):
        subprocess.run(["curl", "x"])


def test_uninstall_removes_patch():
    egress_security.uninstall()
    from egress_security.shims import subprocess_shim

    assert subprocess_shim._installed is False
