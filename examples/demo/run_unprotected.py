"""Run the agent WITHOUT egress-security.

Use this in a live demo as the "before" half of the before/after.
The agent reads the poisoned issue and decides to delete a repo and
exfiltrate an AWS key. Because egress-security is not active, the
destructive calls leave this process.
"""

from __future__ import annotations

import sys

from _demo_lib import (
    BOLD,
    DIM,
    RED,
    RESET,
    YELLOW,
    banner,
    run_agent_loop,
)


def main() -> int:
    banner(
        "UNPROTECTED  -  egress-security is NOT initialized",
        "the agent's destructive decisions reach the network",
        YELLOW,
    )
    run_agent_loop()
    print(
        f"\n  {BOLD}{RED}Both destructive calls left this process.{RESET}\n"
        f"  {DIM}With real credentials, this would be a real incident: "
        f"a deleted repo and a leaked AWS key.{RESET}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
