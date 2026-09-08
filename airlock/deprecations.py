"""Renames, kept working.

Two things got better names on the way to 1.0, and both of them are
already in my shell history, in four engagement runbooks, in the unit
file, and in a policy file per engagement going back further than I
want to re-edit. A renamed flag that errors is a small outage I notice
immediately; a renamed policy key that silently does nothing is a
control that stopped working without telling me, which is the failure
this whole repository is organised against.

So: both spellings work, the old one warns once, and the warning names
the new spelling and the release in which the old one stops being
accepted. Nothing here guesses -- an ambiguous case is an error.
"""
from __future__ import annotations

import sys

#: old -> (new, removed in)
FLAGS = {
    "--map": ("--scrubmap", "2.0"),
}

#: old -> (new, removed in). Policy file keys, per section.
POLICY_KEYS = {
    "backends.*.models.default": ("backends.*.default_model", "2.0"),
}

_warned: set = set()


def warn(old: str, new: str, removed: str) -> None:
    if old in _warned:
        return
    _warned.add(old)
    print(f"airlock: {old} is deprecated, use {new}; the old name "
          f"stops being accepted in {removed}", file=sys.stderr)


def rewrite_argv(argv):
    """Translate deprecated flags, warning once for each."""
    out = []
    for arg in argv:
        head, sep, tail = arg.partition("=")
        if head in FLAGS:
            new, removed = FLAGS[head]
            warn(head, new, removed)
            out.append(new + sep + tail)
        else:
            out.append(arg)
    return out


def migrate_backend(name: str, body: dict) -> dict:
    """Accept both spellings of the default-model key."""
    out = dict(body)
    models = dict(out.get("models") or {})
    legacy = models.pop("default", None)
    if legacy is not None:
        if out.get("default_model") not in (None, legacy):
            raise ValueError(
                f"backend {name!r} sets both models.default and "
                f"default_model, and they disagree")
        warn(f"backends.{name}.models.default",
             f"backends.{name}.default_model", "2.0")
        out.setdefault("default_model", legacy)
    if models:
        out["models"] = models
    elif "models" in out:
        del out["models"]
    return out
