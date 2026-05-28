"""Show the audit log produced by the most recent `run_protected.py` run.

A separate script so it can be delivered as its own beat in a live demo:

    1. run_unprotected.py    "watch what happens with no egress-security"
    2. run_protected.py      "now watch with egress_security.init()"
    3. show_audit.py         "and every decision is recorded"
"""

from __future__ import annotations

import json
import sys

from _demo_lib import (
    AUDIT_PATH,
    BOLD,
    CYAN,
    DIM,
    GREEN,
    RED,
    RESET,
    banner,
)


def main() -> int:
    if not AUDIT_PATH.exists() or not AUDIT_PATH.read_text().strip():
        print(
            f"{DIM}no audit log at {AUDIT_PATH}. "
            f"run `python examples/demo/run_protected.py` first.{RESET}"
        )
        return 1

    banner(
        "AUDIT LOG  -  one JSON line per governed call, redacted secrets",
        f"raw file: {AUDIT_PATH}",
        CYAN,
    )
    for raw in AUDIT_PATH.read_text().strip().splitlines():
        e = json.loads(raw)
        mark = (
            f"{RED}{BOLD}DENY {RESET}"
            if e["decision"] == "deny"
            else f"{GREEN}ALLOW{RESET}"
        )
        print(
            f"  {mark}  {e['vendor']:8}  {e['operation']:40}  "
            f"rule={e.get('rule_id') or '-'}"
        )
        if e.get("reason"):
            print(f"           {DIM}reason: {e['reason']}{RESET}")
    print(
        f"\n  {DIM}This is a real JSONL file you can pipe into any log "
        f"pipeline — Splunk, Datadog, S3.{RESET}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
