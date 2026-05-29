"""Run the agent WITH cordon-sdk active.

Use this in a live demo as the "after" half of the before/after, right
after `run_unprotected.py`. The agent makes the same destructive
decisions, but each one is blocked at the chokepoint and audited.

Protected mode never reaches GitHub or Slack — the chokepoint denies
before the wrapped call runs — so --live does NOT auto-create a repo
here. It only uses your env vars to render the same LOG line shape as
the unprotected run.
"""

from __future__ import annotations

import argparse
import sys

import cordon

from _demo_lib import (
    AUDIT_PATH,
    BOLD,
    DIM,
    GREEN,
    POLICY_PATH,
    RESET,
    banner,
    configure,
    run_agent_loop,
)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live",
        action="store_true",
        help=(
            "Use the same env vars as `run_unprotected.py --live` so the LOG "
            "line shows your real Slack host. No repo is created and nothing "
            "is sent — the policy blocks before egress."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    # In protected mode no real call leaves the process, so we don't need
    # (and don't want to burn) a disposable repo.
    configure(live=args.live, create_repo=False)

    if AUDIT_PATH.exists():
        AUDIT_PATH.unlink()

    mode_tag = "LIVE" if args.live else "FAKE"
    banner(
        f"PROTECTED [{mode_tag}]  -  cordon.init() has been called",
        "same agent, same poisoned issue; destructive calls blocked at the chokepoint",
        GREEN,
    )

    cordon.init(
        policy=str(POLICY_PATH),
        audit=str(AUDIT_PATH),
        audit_stdout=False,
    )
    try:
        run_agent_loop()
    finally:
        cordon.uninstall()

    print(
        f"\n  {BOLD}{GREEN}Same agent. Same poisoned issue. "
        f"One line of difference:{RESET}\n"
        f"      {BOLD}import cordon; cordon.init(){RESET}\n"
        f"  {DIM}(every decision was recorded — run "
        f"`python examples/demo/show_audit.py` to see the audit log){RESET}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
