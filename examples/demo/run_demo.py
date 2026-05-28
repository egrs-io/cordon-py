"""Convenience wrapper: run all three demo beats in sequence.

For a live, paced demo prefer running the three scripts separately so
you can narrate between them:

    python examples/demo/run_unprotected.py    # "this is what happens unprotected"
    python examples/demo/run_protected.py      # "now with egress_security.init()"
    python examples/demo/show_audit.py         # "and every decision is recorded"

This combined script is here for a quick "does the whole thing still
work" check — e.g. from CI or after a refactor.
"""

from __future__ import annotations

import sys

import run_protected
import run_unprotected
import show_audit


def main() -> int:
    for step in (run_unprotected.main, run_protected.main, show_audit.main):
        rc = step()
        if rc != 0:
            return rc
    return 0


if __name__ == "__main__":
    sys.exit(main())
