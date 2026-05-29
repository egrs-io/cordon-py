# Contributing to Cordon

Thanks for your interest in contributing. Cordon is early — feedback,
bug reports, and PRs are all welcome.

## Reporting issues

  - **Vulnerabilities:** see [SECURITY.md](SECURITY.md) for the private
    disclosure channel. Do not file public issues for security bugs.
  - **Bug reports:** include the Python version, `cordon-sdk` version,
    the SDK or runtime involved, and the smallest reproduction you can
    produce (a few-line Python snippet plus the relevant policy YAML).
  - **Feature requests:** describe the use case before proposing a
    specific design — the discussion is usually more valuable than the
    proposal.

## Development setup

```bash
git clone https://github.com/egrs-io/cordon-py.git
cd cordon-py
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The full test suite runs in under 2 seconds and exercises every shim. If
your change touches the policy engine or a shim, add a test that would
have caught the bug or proved the new behavior.

## Pull requests

  1. Fork the repo, branch off `master`.
  2. Keep the change focused — one logical change per PR.
  3. Run `pytest` locally before pushing.
  4. Open the PR against `master`. CI must be green and at least one
     maintainer must approve before merge.
  5. If the change is user-visible, update `README.md` and (if
     applicable) `CLAUDE.md`.

## Adding a new shim

A new shim should:

  - Live in its own module under `src/cordon/shims/`.
  - Wrap exactly **one** chokepoint in the target SDK, via
    `wrapt.wrap_function_wrapper`.
  - Build a `CanonicalRequest` (see `canonical.py`) — never expose raw
    SDK objects to the policy engine.
  - Degrade gracefully: silently skip if the SDK is not importable; log
    a warning and leave the SDK unpatched if the chokepoint signature
    has changed.
  - Be idempotent — calling `install()` twice is a no-op.
  - Use the thread-local `_core.vendor_scope()` context manager around
    the inner call if catch-all shims (requests, httpx) would otherwise
    see the same logical request and double-evaluate.
  - Ship with a test file (`tests/test_<sdk>_shim.py`) covering allow,
    deny, idempotency, and uninstall.

Then register the module in `src/cordon/shims/_registry.py`.

## Coding conventions

  - Python 3.10+.
  - Type hints on public functions; concise docstrings explaining
    *why*, not *what*.
  - No new runtime dependencies beyond `wrapt` and `PyYAML`. Anything
    SDK-specific goes in `[project.optional-dependencies]`.
  - Default behavior must not break a host application: `on_error="open"`
    is the default; internal errors in Cordon should never crash the
    host process unless explicitly configured to.

## License

By contributing, you agree that your contribution will be licensed under
the Apache License 2.0 (see [LICENSE](LICENSE)).
