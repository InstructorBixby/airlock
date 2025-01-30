"""Addresses and hostnames that only exist inside somebody's network.

Cheap, unambiguous, and independent of which engagement is running,
which is why this is the detector that runs even when the roster is
empty.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Iterator

from airlock import tiers
from airlock.detect import register
from airlock.model import Finding

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

INTERNAL_SUFFIX = re.compile(
    r"\b[a-z0-9][a-z0-9\-]{0,62}"
    r"(?:\.[a-z0-9][a-z0-9\-]{0,62})*"
    r"\.(?:local|internal|corp|lan|intranet|home\.arpa)\b",
    re.I)

SHORTNAME = re.compile(
    r"\b(?:dc|sql|ad|exch|vc|esx|nas|srv|app|web|db|fs|print|jump|bastion)"
    r"\-?\d{1,3}\b", re.I)


@register("net.private-address")
def private_addresses(text: str) -> Iterator[Finding]:
    for m in IPV4.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            continue
        if ip.is_private and not ip.is_loopback and not ip.is_link_local:
            yield Finding("net.private-address", m.group(0),
                          tiers.CONFIDENTIAL, span=m.span())


@register("net.internal-hostname")
def internal_hostnames(text: str) -> Iterator[Finding]:
    for m in INTERNAL_SUFFIX.finditer(text):
        yield Finding("net.internal-hostname", m.group(0),
                      tiers.CONFIDENTIAL, span=m.span())


@register("net.internal-shortname")
def internal_shortnames(text: str) -> Iterator[Finding]:
    # A shortname on its own is weak evidence: "web-01" occurs in
    # tutorials. Internal, not confidential, so it gets redacted rather
    # than pinning the whole call to a local model.
    for m in SHORTNAME.finditer(text):
        yield Finding("net.internal-shortname", m.group(0),
                      tiers.INTERNAL, span=m.span())
