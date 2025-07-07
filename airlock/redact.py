"""Replace findings with scrubkit's placeholders, and put them back.

Everything here operates on a request body and a ScrubMap. Three rules
carry the design:

1. **The placeholders are scrubkit's, not airlock's.** A finding is
   redacted with the assignment the engagement's mapping already has,
   or with one scrubkit mints under the engagement key. airlock does
   not choose an index of its own; see airlock/scrubmap.py for why
   that would break the one property redaction is for.

2. **Every redactable finding, or none.** A partial redaction is the
   worst outcome available: it looks clean, reads clean, and leaks the
   one thing the detector was weakest about. So `apply` reports whether
   it covered every finding, and the router treats anything less as
   not-redacted.

3. **Credentials are never redactable.** A placeholder for a secret
   buys nothing -- the model cannot reason about a token it cannot see
   -- and costs the risk of the substitution being wrong. Their
   presence makes redaction incomplete, which routes the call locally.
   That is the desired behaviour and it needed no mechanism beyond the
   table below.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from airlock.model import Finding
from airlock.scrubmap import MapError, ScrubMap

#: airlock finding kind -> scrubkit span kind. The right-hand side is
#: scrubkit's FAMILIES and nothing else may appear there: a mapping
#: with a kind scrubkit does not know is a mapping its own tooling
#: cannot read back.
KINDS = {
    "net.private-address": "ip4",
    "net.internal-hostname": "host",
    "net.internal-shortname": "host",
    "roster.client-name": "term",
    "roster.client-domain": "host",
    "roster.client-net": "ip4",
}


def is_redactable(kind: str) -> bool:
    """Only an exact kind. A suffixed kind came from a derived view."""
    return kind in KINDS


@dataclass
class Result:
    body: dict
    replacements: int = 0
    #: findings that could not be replaced, with the reason
    unredactable: list = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.unredactable


def _table(findings, smap: ScrubMap):
    """(value -> placeholder, findings that have no assignment)."""
    table: dict = {}
    unredactable = []
    for f in findings:
        if not is_redactable(f.kind):
            unredactable.append(f)
            continue
        if f.value in table:
            continue
        try:
            placeholder = smap.placeholder_for(KINDS[f.kind], f.value)
        except MapError:
            unredactable.append(f)
            continue
        if placeholder is None:
            # No assignment in the engagement's mapping and no keyed
            # aliaser to make one. Not an error; the call goes local.
            unredactable.append(f)
            continue
        table[f.value] = placeholder
    return table, unredactable


def _swap(text: str, table: dict) -> tuple[str, int]:
    if not table:
        return text, 0
    # Longest value first. scrubkit writes the mapping sorted, which
    # puts `corp.example` ahead of `jump01.corp.example`; substituting
    # in that order leaves `jump01.CLIENT-HOST-11` behind.
    keys = sorted(table, key=len, reverse=True)
    rx = re.compile("|".join(re.escape(k) for k in keys))
    count = 0

    def sub(m):
        nonlocal count
        count += 1
        return table[m.group(0)]

    return rx.sub(sub, text), count


def _walk(obj, table, counter):
    if isinstance(obj, str):
        out, n = _swap(obj, table)
        counter[0] += n
        return out
    if isinstance(obj, list):
        return [_walk(v, table, counter) for v in obj]
    if isinstance(obj, dict):
        return {k: _walk(v, table, counter) for k, v in obj.items()}
    return obj


def apply(body: dict, findings, smap: ScrubMap) -> Result:
    """Redact a request body into a copy of it."""
    table, unredactable = _table(findings, smap)
    counter = [0]
    out = _walk(body, table, counter)
    return Result(body=out, replacements=counter[0],
                  unredactable=unredactable)


def reverse(obj, smap: ScrubMap):
    """Put the originals back. Used on the response."""
    table = {p: v for v, p in smap.substitutions()}
    counter = [0]
    return _walk(obj, table, counter), counter[0]


def reverse_text(text: str, smap: ScrubMap) -> str:
    out, _ = _swap(text, {p: v for v, p in smap.substitutions()})
    return out


__all__ = ["Result", "apply", "reverse", "reverse_text",
           "is_redactable", "KINDS", "Finding"]
