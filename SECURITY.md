# Security Policy

Cordon is a security tool. If you find a vulnerability in Cordon itself,
or a way to bypass an enforced policy, please report it privately so we
can fix it before disclosure.

## Reporting a vulnerability

**Preferred channel:** GitHub Private Vulnerability Reporting.

  → <https://github.com/egrs-io/cordon-py/security/advisories/new>

This creates a private advisory only maintainers can see. Please do not
open a public issue or pull request for vulnerabilities.

If GitHub PVR is not available to you, email `security@egrs.io` instead.

## What to include

  - A clear description of the issue and its impact.
  - The minimum reproduction (a small Python snippet plus the policy YAML
    that demonstrates the bypass or unexpected behavior).
  - Affected version (`cordon-sdk` version + Python version + the SDK or
    runtime involved, e.g. `boto3 1.34.x`).

## What to expect

  - **Acknowledgment within 72 hours** of receipt.
  - We will work with you to understand and reproduce the issue.
  - A coordinated disclosure timeline — typically 90 days from the
    acknowledgment, shorter for critical issues, with the option to
    extend by mutual agreement if a fix is in progress.
  - Public credit in the advisory and changelog unless you prefer
    otherwise.

## Scope

In scope:
  - Policy bypass: a shim that does not actually intercept the SDK call
    it claims to govern.
  - Predicate evasion: a `when:` rule that fails to match a request that
    should match it (or vice versa).
  - Audit log tampering or unintended secret leakage in audit records.
  - Issues in `cordon-mcp`'s tools/call proxying.

Out of scope (please report through normal issues instead):
  - General feature requests.
  - Policy authoring mistakes (a policy that allows what its author
    intended to block).
  - Issues in the third-party SDKs themselves (report those upstream).

## Supported versions

Until 1.0, only the latest tagged release on `master` receives security
fixes. After 1.0 we will document a longer-term support policy.
