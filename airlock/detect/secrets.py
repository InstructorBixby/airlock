"""Credential shapes.

A secret in an outbound prompt is its own problem independent of whose
it is, so these are confidential regardless of the roster. The patterns
are the high-confidence ones only; a generic entropy check produced
enough false positives on base64 evidence blobs to be useless as a
blocking signal.
"""
from __future__ import annotations

import re
from typing import Iterator

from airlock import tiers
from airlock.detect import register
from airlock.model import Finding

PATTERNS = {
    "secrets.private-key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    "secrets.aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "secrets.bearer": re.compile(
        r"(?i)\bauthorization:\s*(?:bearer|basic)\s+\S{8,}"),
    "secrets.jwt": re.compile(
        r"\bey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"),
    "secrets.ntlm-hash": re.compile(
        r"\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b"),
    "secrets.connection-string": re.compile(
        r"(?i)\b(?:mongodb|postgres(?:ql)?|mysql|redis|amqp)://"
        r"[^\s:@/]+:[^\s:@/]+@"),
}


@register("secrets")
def secrets(text: str) -> Iterator[Finding]:
    for kind, rx in PATTERNS.items():
        for m in rx.finditer(text):
            yield Finding(kind, m.group(0), tiers.CONFIDENTIAL,
                          span=m.span())
