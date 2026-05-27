"""Egress-MCP proxy.

A wrapping MCP server that sits between an agent's MCP client and a real
MCP server. We spawn the real server as a child process, pass JSON-RPC
messages through over stdio, and govern every `tools/call` against the
same policy engine `egress-security` uses for SDK interception.

Reuses `egress_security.policy`, `egress_security.canonical`, and
`egress_security.audit` directly — no duplicated logic.

Usage:
    egress-mcp --policy policies/agent-default.yaml -- python -m my_real_mcp_server

Or as a Python module:
    python -m egress_mcp --policy ./p.yaml -- <real-server-cmd> [args...]
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import threading
from typing import IO, Any

from egress_security.audit import AuditLogger
from egress_security.canonical import CanonicalRequest
from egress_security.policy import Policy, load_policy

_log = logging.getLogger("egress_mcp")

# JSON-RPC error code for "Internal error" -- closest match for a policy block.
_DENY_ERROR_CODE = -32603


def _deny_response(request_id: Any, reason: str | None, rule_id: str | None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": _DENY_ERROR_CODE,
            "message": f"egress-security denied: {reason or 'policy violation'}",
            "data": {"rule_id": rule_id} if rule_id else {},
        },
    }


def _govern_tools_call(
    msg: dict, policy: Policy, audit: AuditLogger
) -> dict | None:
    """Return a JSON-RPC deny response if blocked, or None to forward."""
    params = msg.get("params") or {}
    name = params.get("name")
    arguments = params.get("arguments") or {}
    canonical = CanonicalRequest(
        vendor="mcp",
        operation=name,
        params=arguments,
        raw={"jsonrpc_id": msg.get("id")},
    )
    decision = policy.evaluate(canonical.to_dict())
    audit.record(
        vendor="mcp",
        operation=name,
        decision=decision.action,
        reason=decision.reason,
        rule_id=decision.rule_id,
        args=arguments,
    )
    if decision.action == "deny":
        return _deny_response(msg.get("id"), decision.reason, decision.rule_id)
    return None


def _pump_client_to_server(
    client_in: IO[bytes],
    server_in: IO[bytes],
    client_out: IO[bytes],
    policy: Policy,
    audit: AuditLogger,
) -> None:
    for raw in client_in:
        forward = True
        deny_payload: dict | None = None
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            msg = None
        if isinstance(msg, dict) and msg.get("method") == "tools/call":
            deny_payload = _govern_tools_call(msg, policy, audit)
            if deny_payload is not None:
                forward = False
        if forward:
            line = raw if raw.endswith(b"\n") else raw + b"\n"
            server_in.write(line)
            server_in.flush()
        else:
            client_out.write((json.dumps(deny_payload) + "\n").encode())
            client_out.flush()


def _pump_server_to_client(
    server_out: IO[bytes], client_out: IO[bytes]
) -> None:
    for raw in server_out:
        client_out.write(raw)
        client_out.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="egress-mcp",
        description=(
            "Wrap an MCP server with egress-security policy enforcement. "
            "All stdio JSON-RPC traffic is passed through; tools/call "
            "requests are evaluated against the policy before being forwarded."
        ),
    )
    parser.add_argument(
        "--policy", required=True, help="Path to YAML policy file."
    )
    parser.add_argument(
        "--audit",
        default="egress-mcp-audit.jsonl",
        help="Path to JSONL audit log (default: egress-mcp-audit.jsonl).",
    )
    parser.add_argument(
        "server_command",
        nargs=argparse.REMAINDER,
        help="-- followed by the real MCP server command to spawn.",
    )
    args = parser.parse_args(argv)

    server_cmd = [a for a in args.server_command if a != "--"]
    if not server_cmd:
        parser.error("missing server command after --")

    policy = load_policy(args.policy)
    audit = AuditLogger(path=args.audit)

    proc = subprocess.Popen(
        server_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        bufsize=0,
    )

    s2c = threading.Thread(
        target=_pump_server_to_client,
        args=(proc.stdout, sys.stdout.buffer),
        daemon=True,
    )
    s2c.start()
    try:
        _pump_client_to_server(
            sys.stdin.buffer, proc.stdin, sys.stdout.buffer, policy, audit
        )
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        audit.close()
    return proc.returncode or 0


if __name__ == "__main__":
    sys.exit(main())
