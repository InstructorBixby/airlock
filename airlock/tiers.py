"""Tier vocabulary.

Its own module because everything else imports it and nothing else
should be able to invent a fourth tier by accident. The order is the
whole semantics: more restrictive is further right.
"""
from __future__ import annotations

PUBLIC = "public"
INTERNAL = "internal"
CONFIDENTIAL = "client-confidential"

ORDER = (PUBLIC, INTERNAL, CONFIDENTIAL)

#: Not a tier. The classifier's answer when it has no answer, which is
#: distinct from CONFIDENTIAL: one means "this is client material",
#: the other means "I do not know what this is". They route the same
#: way today and they do not read the same way in a log.
UNDECIDED = "undecided"


def rank(tier: str) -> int:
    try:
        return ORDER.index(tier)
    except ValueError:
        # An unknown tier is more restrictive than any known one.
        return len(ORDER)


def worst(*tiers: str) -> str:
    out = PUBLIC
    for t in tiers:
        if rank(t) > rank(out):
            out = t
    return out
