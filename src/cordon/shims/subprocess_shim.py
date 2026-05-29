"""subprocess shim -- govern shell-out to deny SDK-bypass attempts.

The other shims govern SDK calls. But an agent that can shell out
(``subprocess.run(["curl", "..."])`` or ``subprocess.run(["gh", "repo",
"delete", ...])``) walks straight around them. This shim wraps the
single chokepoint everything in `subprocess` funnels through --
``subprocess.Popen.__init__`` -- and runs the call through the policy
before any fork happens.

The default policy (``policies/agent-default.yaml``) denies a curated
blocklist of network-bound binaries (curl, wget, gh, aws, gcloud, az,
kubectl, ssh, scp, sftp, rsync, nc, netcat, socat, nmap, ftp, telnet,
http, httpie) plus the network subcommands of git and docker.

KNOWN GAP: ``os.system()`` calls libc directly and does NOT pass through
subprocess.Popen, so this shim does not cover it. Hosts that need to
govern os.system should remove it from agent code.
"""

from __future__ import annotations

import logging
import os
import shlex
from typing import Any, Callable

import wrapt

from cordon import _core
from cordon.canonical import CanonicalRequest

_log = logging.getLogger("cordon.shims.subprocess")

_installed = False
_original: Any = None


def install() -> Callable[[], None] | None:
    global _installed, _original
    try:
        import subprocess  # noqa: F401
    except ImportError:  # pragma: no cover
        return None
    if _installed:
        return uninstall
    try:
        _original = __import__("subprocess").Popen.__init__
        wrapt.wrap_function_wrapper("subprocess", "Popen.__init__", _wrapper)
    except (AttributeError, ImportError) as e:
        _log.warning("subprocess_shim: chokepoint signature changed (%s)", e)
        return None
    _installed = True
    return uninstall


def uninstall() -> None:
    global _installed, _original
    if not _installed:
        return
    try:
        import subprocess

        if _original is not None:
            subprocess.Popen.__init__ = _original
    except Exception:
        _log.warning("subprocess_shim: uninstall failed", exc_info=True)
    _original = None
    _installed = False


def _wrapper(wrapped, instance, args, kwargs):
    argv = _extract_argv(args, kwargs)
    if argv:
        binary = str(argv[0])
        canonical = CanonicalRequest(
            vendor="subprocess",
            operation=os.path.basename(binary),
            params={"argv": argv},
            body=" ".join(argv),
            raw={"binary_path": binary},
        )
        _core.govern(canonical)
    return wrapped(*args, **kwargs)


def _extract_argv(args: tuple, kwargs: dict) -> list[str]:
    """Normalize the Popen `args` parameter to a list of strings.

    Handles list/tuple form, string form (with shell=True), and bytes."""
    cmd = args[0] if args else kwargs.get("args")
    if cmd is None:
        return []
    shell = bool(kwargs.get("shell", False))
    if isinstance(cmd, (list, tuple)):
        argv = [_to_str(a) for a in cmd]
        if shell and argv:
            # Popen(["curl https://...", ...], shell=True) -- argv[0] is the
            # shell command string; tokenize it so the policy sees `curl`.
            try:
                return shlex.split(argv[0])
            except ValueError:
                return argv
        return argv
    if isinstance(cmd, (str, bytes)):
        text = _to_str(cmd)
        if shell:
            try:
                return shlex.split(text)
            except ValueError:
                return [text]
        return [text]
    return []


def _to_str(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
