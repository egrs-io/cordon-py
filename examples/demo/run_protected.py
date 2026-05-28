"""Run the agent WITH egress-security active.

Use this in a live demo as the "after" half of the before/after, right
after `run_unprotected.py`. The agent makes the same destructive
decisions, but each one is blocked at the chokepoint and audited.
"""

from __future__ import annotations

import sys

import egress_security

from _demo_lib import (
    AUDIT_PATH,
    BOLD,
    DIM,
    GREEN,
    POLICY_PATH,
    RESET,
    banner,
    run_agent_loop,
)


def main() -> int:
    if AUDIT_PATH.exists():
        AUDIT_PATH.unlink()

    banner(
        "PROTECTED  -  egress_security.init() has been called",
        "same agent, same poisoned issue; destructive calls blocked at the chokepoint",
        GREEN,
    )

    egress_security.init(
        policy=str(POLICY_PATH),
        audit=str(AUDIT_PATH),
        audit_stdout=False,
    )
    try:
        run_agent_loop()
    finally:
        egress_security.uninstall()

    print(
        f"\n  {BOLD}{GREEN}Same agent. Same poisoned issue. "
        f"One line of difference:{RESET}\n"
        f"      {BOLD}import egress_security; egress_security.init(){RESET}\n"
        f"  {DIM}(every decision was recorded — run "
        f"`python examples/demo/show_audit.py` to see the audit log){RESET}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
