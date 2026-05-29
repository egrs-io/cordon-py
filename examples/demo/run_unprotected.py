"""Run the agent WITHOUT cordon-sdk.

Use this in a live demo as the "before" half of the before/after.
With --live the agent actually deletes a fresh disposable GitHub repo
and posts to a real Slack webhook.
"""

from __future__ import annotations

import argparse
import sys

from _demo_lib import (
    BOLD,
    DIM,
    RED,
    RESET,
    YELLOW,
    banner,
    configure,
    get_config,
    run_agent_loop,
)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live",
        action="store_true",
        help=(
            "Run against real GitHub and Slack. Requires env vars "
            "CORDON_DEMO_GITHUB_TOKEN and CORDON_DEMO_SLACK_WEBHOOK. "
            "Auto-creates a disposable repo to delete."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    configure(live=args.live)

    mode_tag = "LIVE" if args.live else "FAKE"
    subtitle = "the agent's destructive decisions reach the network"
    if args.live:
        subtitle += f"  (target repo: {get_config().github_target})"
    banner(
        f"UNPROTECTED [{mode_tag}]  -  cordon-sdk is NOT initialized",
        subtitle,
        YELLOW,
    )
    run_agent_loop()
    if args.live:
        closing = (
            f"\n  {BOLD}{RED}Both destructive calls actually happened.{RESET}\n"
            f"  {DIM}Refresh the repo URL to confirm it's gone, and check "
            f"your Slack channel for the leaked key.{RESET}\n"
        )
    else:
        closing = (
            f"\n  {BOLD}{RED}Both destructive calls left this process.{RESET}\n"
            f"  {DIM}With real credentials, this would be a real incident: "
            f"a deleted repo and a leaked AWS key.{RESET}\n"
        )
    print(closing)
    return 0


if __name__ == "__main__":
    sys.exit(main())
