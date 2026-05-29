# Cordon demo — the toxic chain

The canonical before/after for cordon-sdk.

## The scenario

An AI agent reads a GitHub issue whose body contains a hidden
prompt-injection (`malicious_issue.md`). The agent follows it and tries
to:

1. delete a GitHub repository, and
2. exfiltrate an AWS access key to a Slack channel.

We run that scenario twice:

| Run            | cordon-sdk | Outcome                                         |
| -------------- | --------------- | ----------------------------------------------- |
| Unprotected    | not initialized | destructive calls leave the process             |
| Protected      | active          | destructive calls are blocked **before** egress |

The "agent" is a deterministic scripted stand-in — no Anthropic API key
required, no model drift between runs. The destructive tools execute
through real, patched SDKs (`PyGithub` for the DELETE, `requests` for
the Slack POST), so cordon-sdk actually intercepts them.

## Two modes

### Fake (default — safe to run anywhere)

```bash
python examples/demo/run_unprotected.py
python examples/demo/run_protected.py
python examples/demo/show_audit.py
```

Targets are placeholders (`acme/widget`, a fake Slack webhook). Calls
"leave the process" in the unprotected run and fail at the network
because nothing is reachable — but the policy decisions (BLOCK / SENT)
are identical to live mode, because the policy looks at the shape of
the call, not whether the target exists.

### Live (real GitHub repo, real Slack message)

This is the version to use in front of an audience that can verify with
their own eyes: refresh `github.com/<your-user>/egress-demo-...` and
watch it 404, watch the message land in your Slack channel.

```bash
# one-time setup
cp examples/demo/.env.example .env
$EDITOR .env          # paste your GitHub PAT and Slack webhook URL
source .env

# the three demo beats
python examples/demo/run_unprotected.py --live    # creates a disposable repo, deletes it, posts to Slack
python examples/demo/run_protected.py --live      # same LOG shape, BLOCKED before any of that happens
python examples/demo/show_audit.py                # the JSONL audit trail
```

`run_unprotected.py --live` auto-creates a fresh `egress-demo-<epoch>`
repo via `setup_repo.sh` before each run, so you never touch GitHub
manually. `run_protected.py --live` does NOT create a repo (the policy
blocks before any call goes out) — it just uses your env vars to render
the same LOG line as the unprotected run.

### Between sessions

`run_protected.py --live` leaves behind the disposable repo it would
have targeted... actually no, it doesn't create one — only the
unprotected runs do, and each unprotected run destroys its own target.
So in practice nothing accumulates. But if anything ever fails halfway
through, you can sweep:

```bash
./examples/demo/cleanup_repos.sh --dry-run    # show what would be deleted
./examples/demo/cleanup_repos.sh              # actually delete egress-demo-* older than 1h
```

By default `cleanup_repos.sh` only touches repos whose name starts with
`egress-demo-` AND are older than one hour. Override the age with
`MIN_AGE_HOURS=0 ./examples/demo/cleanup_repos.sh`.

## What's in the policy

`demo_policy.yaml` declares three rules:

- `block-github-repo-delete` — `DELETE /repos/:owner/:repo` is denied.
- `block-secret-exfiltration` — any outbound HTTP body matching a known
  credential pattern (`AKIA…`, `ghp_…`, `sk-…`, etc.) is denied.
- `block-unknown-egress` — outbound HTTP to a host not on the allowlist
  is denied. `hooks.slack.com` IS on the allowlist; the Slack post in
  live mode is blocked because of the credential pattern in the body,
  not because of the host. That's the right framing: the destination is
  legitimate, the *content* is what's dangerous.

## Audit log

`examples/demo/demo-audit.jsonl` (gitignored) is written by the
protected run. Each line is one JSON object recording vendor, operation,
decision, rule_id, and a redacted copy of the args. Known credential
patterns are replaced with `***` before serialization.

> **Live-mode note:** the *URL* of the Slack webhook (which contains a
> secret) is recorded in the audit log under `args.raw.url`. That's
> faithful — real audit pipelines need to see what was attempted — but
> if you ran the demo with `--live` against a webhook you care about,
> rotate the webhook afterwards.
