"""Check the things that make the gateway bypassable.

The gateway is only as good as its coverage, and the coverage depends
on environment variables in shells I started at various times for
various reasons. The failure is silent by nature: a tool pointed at a
provider works perfectly, which is exactly why nothing tells you.

Each check returns a (ok, name, detail) triple. Nothing here is
enforcement -- it cannot be, this is a process looking at its own
environment -- it is a list of things to go and look at. `egress-ledger`
is the one that answers the question properly, by recording what a
process tree actually connected to.
"""
from __future__ import annotations

import os
from pathlib import Path

#: Variables that send a tool somewhere other than the gateway.
PROVIDER_VARS = (
    "OPENAI_API_BASE",      # the older spelling, still honoured
    "AZURE_OPENAI_ENDPOINT",
    "ANTHROPIC_BASE_URL",
    "OPENAI_ORGANIZATION",
)

#: Files that commonly hold a base URL a tool will prefer over the env.
CONFIG_HINTS = (
    "~/.config/io.datasette.llm/default_model.txt",
    "~/.continue/config.json",
    "~/.aider.conf.yml",
)


def _is_gateway(url: str, host: str, port: int) -> bool:
    if not url:
        return False
    return (f"{host}:{port}" in url
            or (host in ("127.0.0.1", "localhost")
                and f":{port}" in url
                and ("127.0.0.1" in url or "localhost" in url)))


def checks(host: str = "127.0.0.1", port: int = 8111,
           env=None, home=None):
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
        out.append((False, "OPENAI_BASE_URL",
                    f"{base} is not this gateway"))

    for var in PROVIDER_VARS:
        val = env.get(var)
        if val:
            out.append((False, var,
                        "set, and takes precedence in some clients"))

    if not env.get("OPENAI_API_KEY"):
        # Not a problem for the gateway, but several clients refuse to
        # start without one, and the resulting error points at the
        # wrong thing.
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
