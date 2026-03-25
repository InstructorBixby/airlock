"""Check the things that make the gateway bypassable.

The gateway is only as good as its coverage, and the coverage depends
on environment variables in shells I started at various times for
various reasons. The failure is silent by nature: a tool pointed at a
provider works perfectly, which is exactly why nothing tells you. See
docs/coverage.md for the instance that produced this module.

Each check returns a (ok, name, detail) triple. Nothing here is
enforcement -- it cannot be, this is a process looking at its own
environment -- it is a list of things to go and look at.
`egress-ledger` is the one that answers the question properly, by
recording what a process tree actually connected to.
"""
from __future__ import annotations

import os
import socket
from pathlib import Path

PROVIDER_VARS = (
    "OPENAI_API_BASE",      # the older spelling, still honoured
    "AZURE_OPENAI_ENDPOINT",
    "ANTHROPIC_BASE_URL",
    "OPENAI_ORGANIZATION",
)

CONFIG_HINTS = (
    "~/.config/io.datasette.llm/default_model.txt",
    "~/.continue/config.json",
    "~/.aider.conf.yml",
)


def _port_of(url: str) -> int | None:
    tail = url.split("//", 1)[-1].split("/", 1)[0]
    if ":" not in tail:
        return None
    try:
        return int(tail.rsplit(":", 1)[1])
    except ValueError:
        return None


def _is_gateway(url: str, host: str, port: int) -> bool:
    if not url:
        return False
    tail = url.split("//", 1)[-1].split("/", 1)[0]
    h = tail.rsplit(":", 1)[0] if ":" in tail else tail
    return (h in (host, "localhost", "127.0.0.1")
            and _port_of(url) == port)


def _listening(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def checks(host: str = "127.0.0.1", port: int = 8111,
           env=None, home=None, probe=True):
    env = os.environ if env is None else env
    home = Path(home) if home else Path.home()
    out = []

    base = env.get("OPENAI_BASE_URL", "")
    if not base:
        out.append((False, "OPENAI_BASE_URL",
                    "not set; tools will use the provider default"))
    elif _is_gateway(base, host, port):
        out.append((True, "OPENAI_BASE_URL", base))
    else:
        other = _port_of(base)
        detail = f"{base} is not this gateway"
        if other is not None and not _is_gateway(base, host, other):
            pass
        elif other is not None:
            # Right host, wrong port: a shell older than the last
            # restart. This is the one that bit.
            detail = (f"{base} points at port {other}, not {port}; "
                      f"this shell predates the running gateway")
        out.append((False, "OPENAI_BASE_URL", detail))

    if probe and not _listening(host, port):
        out.append((False, "listener",
                    f"nothing is listening on {host}:{port}; a client "
                    f"that cannot reach it will fall back to its own "
                    f"default, silently"))

    for var in PROVIDER_VARS:
        if env.get(var):
            out.append((False, var,
                        "set, and takes precedence in some clients"))

    if not env.get("OPENAI_API_KEY"):
        out.append((False, "OPENAI_API_KEY",
                    "not set; some clients refuse to start"))

    for hint in CONFIG_HINTS:
        p = Path(hint.replace("~", str(home)))
        if p.exists():
            out.append((False, str(p),
                        "exists and may carry its own base url"))
    return out


def report(results) -> str:
    lines = []
    for ok, name, detail in results:
        lines.append(f"{'ok  ' if ok else 'look'} {name}: {detail}")
    bad = sum(1 for ok, _, _ in results if not ok)
    lines.append(f"{bad} thing(s) to look at")
    lines.append("this checks one process's view of the world; "
                 "egress-ledger records what was actually reached")
    return "\n".join(lines)
