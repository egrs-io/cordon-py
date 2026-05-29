"""Integration tests for the cordon-mcp proxy.

Spawns the proxy as a subprocess with a stub MCP child server, pipes
JSON-RPC over stdio, and verifies that tools/call is governed by the
shared policy engine while everything else passes through untouched.
"""

import json
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _write_stub_child(path: Path) -> None:
    """A tiny stub 'MCP server' that echoes any line it receives back as a
    JSON-RPC response (so we can tell what the proxy forwarded)."""
    path.write_text(
        textwrap.dedent(
            """
            import sys, json
            for line in sys.stdin:
                try:
                    msg = json.loads(line)
                except Exception:
                    continue
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg.get("id"),
                    "result": {"echoed_method": msg.get("method"), "echoed_params": msg.get("params")},
                }
                sys.stdout.write(json.dumps(resp) + "\\n")
                sys.stdout.flush()
            """
        ).strip()
    )


def _start_proxy(tmp_path: Path, policy: dict, audit_path: Path) -> subprocess.Popen:
    import yaml

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    child_path = tmp_path / "child.py"
    _write_stub_child(child_path)

    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "cordon_mcp",
            "--policy",
            str(policy_path),
            "--audit",
            str(audit_path),
            "--",
            sys.executable,
            str(child_path),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(REPO_ROOT),
    )


def _send(proxy: subprocess.Popen, msg: dict) -> dict:
    proxy.stdin.write((json.dumps(msg) + "\n").encode())
    proxy.stdin.flush()
    # Wait briefly for the response line
    for _ in range(50):
        line = proxy.stdout.readline()
        if line:
            return json.loads(line)
        time.sleep(0.02)
    raise AssertionError("no response from proxy within timeout")


POLICY = {
    "version": 1,
    "default": "allow",
    "rules": [
        {
            "id": "block-delete-tool",
            "when": {"vendor": "mcp", "operation": "^delete_"},
            "action": "deny",
            "reason": "destructive tool",
        }
    ],
}


def test_denied_tools_call_returns_error_and_does_not_reach_child(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    proxy = _start_proxy(tmp_path, POLICY, audit_path)
    try:
        resp = _send(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "delete_repo",
                    "arguments": {"owner": "a", "repo": "b"},
                },
            },
        )
        assert "error" in resp
        assert "cordon-sdk denied" in resp["error"]["message"]
        assert resp["error"]["data"]["rule_id"] == "block-delete-tool"
        # The stub child would have echoed back `result.echoed_method` -- the
        # absence of that field confirms the request was blocked at the proxy.
        assert "result" not in resp
    finally:
        proxy.stdin.close()
        proxy.wait(timeout=5)

    entry = json.loads(audit_path.read_text().strip())
    assert entry["vendor"] == "mcp"
    assert entry["operation"] == "delete_repo"
    assert entry["decision"] == "deny"


def test_allowed_tools_call_is_forwarded(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    proxy = _start_proxy(tmp_path, POLICY, audit_path)
    try:
        resp = _send(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "list_issues",
                    "arguments": {"repo": "a/b"},
                },
            },
        )
        # Child stub echoes the method back in result.echoed_method.
        assert resp["result"]["echoed_method"] == "tools/call"
        assert resp["result"]["echoed_params"]["name"] == "list_issues"
    finally:
        proxy.stdin.close()
        proxy.wait(timeout=5)

    entry = json.loads(audit_path.read_text().strip())
    assert entry["operation"] == "list_issues"
    assert entry["decision"] == "allow"


def test_non_tools_call_passes_through(tmp_path):
    """Initialize, tools/list, ping, etc. must NOT be intercepted -- only
    tools/call goes through policy."""
    audit_path = tmp_path / "audit.jsonl"
    proxy = _start_proxy(tmp_path, POLICY, audit_path)
    try:
        resp = _send(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/list",
                "params": {},
            },
        )
        assert resp["result"]["echoed_method"] == "tools/list"
    finally:
        proxy.stdin.close()
        proxy.wait(timeout=5)

    # No audit line for non-tools/call traffic.
    assert not audit_path.exists() or not audit_path.read_text().strip()
