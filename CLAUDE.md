# Notes for future Claude sessions

This is **Egress Security v0.1** — a Python runtime security layer for AI agents. It monkey-patches popular SDKs at a single chokepoint per SDK, evaluates each intercepted call against a YAML policy, audits the decision, and blocks (raises `EgressSecurityDenied`) or calls through.

The package name (`egress-security`) is provisional; the import name is `egress_security` and the constant `egress_security._core.PACKAGE_NAME` holds it for easy rename.

## v0.1 north star

One compelling before/after demo (the "toxic chain"): an AI agent reads a GitHub issue containing a hidden malicious instruction, then either deletes the repo or is blocked.

## Architecture in one paragraph

`shims/*` each wrap a single chokepoint in one SDK using `wrapt.wrap_function_wrapper` (the OpenTelemetry pattern). The wrapper builds a **canonical request** (`canonical.py`) — vendor, operation/method, path, host, params/body — and hands it to `policy.evaluate()`. The decision is written to the JSONL audit log (`audit.py`) and either passes through (`allow`) or raises `EgressSecurityDenied` (`deny`). All shims must: degrade gracefully (silently skip if the SDK is absent or the chokepoint signature has changed), be idempotent, and honor a thread-local reentrancy guard so one logical call (e.g. PyGithub → requests) is only evaluated once.

The `subprocess` shim is the bypass guard. SDK shims only matter if every path *out* of the process is covered; an agent that can `subprocess.run(["curl", ...])` walks around them. The default policy denies shell-out to known network binaries (curl, wget, gh, aws, gcloud, kubectl, ssh, ...) and the network subcommands of git/docker. The premise: agents should use the SDK or an MCP server.

## Build order (demo-driven)

1. `policy.py` + tests
2. `audit.py` + tests
3. `canonical.py`
4. `_core.py` + `__init__.py` (public API, reentrancy guard)
5. `boto3_shim.py` + tests
6. `github_shim.py` + tests
7. **Demo working end-to-end — STOP for review**
8. `slack_shim.py`, `requests_shim.py` + tests
9. `policies/agent-default.yaml` + `test_end_to_end.py`
10. README, CI workflow
11. `egress-mcp`

## Decisions made (v0.1)

- **Demo agent loop**: deterministic scripted stand-in only — no Anthropic dep for v0.1. The before/after lands without an LLM in the loop.
- **No in-process transport mocks**: the demo issues calls that *would* be real. Protected run blocks before anything leaves the process; unprotected run lets the call leave and prints "destructive call left the process — egress-security was not active to stop it." Live validation uses disposable GitHub repos.
- **Reentrancy guard**: thread-local "shim in flight" flag. Vendor-specific shims set it; catch-all shims (requests/httpx) skip evaluation when it's set. Prevents double-audit when PyGithub → requests.
- **Fail behavior**: `on_error="open"` default — internal errors in egress-security log a warning and call through, so the host app never breaks. `monitor` mode never blocks.

## Constraints

- Python 3.10+. Runtime deps only `wrapt` and `PyYAML`; all SDKs are optional extras.
- `import egress_security` must succeed with zero SDKs installed.
- Apache-2.0.
