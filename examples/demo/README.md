# Egress Security demo — the toxic chain

This is the canonical before/after for egress-security v0.1.

## What it shows

An AI agent reads a GitHub issue. The issue's body contains a hidden
prompt-injection telling the agent to:

1. delete the repository `acme/widget`, and
2. email the AWS_ACCESS_KEY_ID to an external mailbox.

We run that scenario twice:

| Run            | egress-security | Outcome                                         |
| -------------- | --------------- | ----------------------------------------------- |
| Unprotected    | not initialized | destructive calls leave the process             |
| Protected      | active          | destructive calls are blocked **before** egress |

The "agent" is a deterministic scripted stand-in — no Anthropic API key
required, no model drift between runs. The destructive tools execute
through real, patched SDKs (`PyGithub` for the DELETE, `requests` for the
HTTP POST), so egress-security actually intercepts them.

## How to run

From the repo root, after `pip install -e ".[dev]"`:

```bash
python examples/demo/run_demo.py
```

The script writes a JSONL audit log to
`examples/demo/demo-audit.jsonl` during the protected run and prints
both runs side-by-side.

## What "leave the process" means here

Per the project's v0.1 scoping decision, this demo does **not** mock the
transport layer below the chokepoint. In the unprotected run, the calls
will actually attempt to reach `api.github.com` and the fake email host —
they will likely fail at the network or auth layer, but **the security
boundary inside the process has already been lost**: an egress-security
deployment would have stopped those calls before they left.

In the protected run, the calls never leave: the policy denies them at
the chokepoint and `EgressSecurityDenied` is raised before any HTTP
request is made.

## What's in the policy

`demo_policy.yaml` declares three rules:

- `block-github-repo-delete` — `DELETE /repos/:owner/:repo` is denied.
- `block-secret-exfiltration` — any outbound HTTP body matching a known
  credential pattern (`AKIA…`, `ghp_…`, `sk-…`, etc.) is denied.
- `block-unknown-egress` — outbound HTTP to a host not on the allowlist
  is denied (catches `evil.example` and similar).
