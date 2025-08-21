"""The engagement scope file as a detector.

A scope file is the most reliable list of client identifiers that
exists, because somebody had to agree it in writing. It is also already
on disk for every live engagement, so using it costs nothing to
maintain.

One thing to be careful about: in-scope and confidential are different
questions. A host being out of scope does not make it public -- it
makes it a host I am not allowed to touch, which is more sensitive, not
less. So this detector only ever adds findings.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Iterator

import yaml

from airlock import tiers
from airlock.model import Finding

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class ScopeError(Exception):
    pass


def _hosts_from_urls(urls):
    out = []
    for u in urls:
        rest = u.split("//", 1)[-1]
        host = rest.split("/", 1)[0].split(":", 1)[0]
        if host:
            out.append(host.lower())
    return out


def load(path):
    p = Path(path)
    if not p.exists():
        raise ScopeError(f"no scope file at {p}")
    raw = yaml.safe_load(p.read_text()) or {}
    hosts = [h.lower() for h in (raw.get("hosts") or [])]
    hosts += _hosts_from_urls(raw.get("urls") or [])
    nets = []
    for n in raw.get("nets") or []:
        try:
            nets.append(ipaddress.ip_network(n, strict=False))
        except ValueError as exc:
            raise ScopeError(f"{p}: bad net {n!r}") from exc
    if not hosts and not nets:
        raise ScopeError(f"{p}: declares no hosts or nets")
    return sorted(set(hosts)), nets


def detector(hosts, nets, engagement: str):
    # Longest first so app.foo.invalid wins over foo.invalid.
    ordered = sorted(hosts, key=len, reverse=True)
    host_re = (re.compile("|".join(re.escape(h) for h in ordered),
                          re.I) if ordered else None)

    def fn(text: str) -> Iterator[Finding]:
        if host_re is not None:
            for m in host_re.finditer(text):
                yield Finding("scope.host", m.group(0),
                              tiers.CONFIDENTIAL,
                              engagement=engagement, span=m.span())
        for m in IPV4.finditer(text):
            try:
                ip = ipaddress.ip_address(m.group(0))
            except ValueError:
                continue
            if any(ip in n for n in nets):
                yield Finding("scope.address", m.group(0),
                              tiers.CONFIDENTIAL,
                              engagement=engagement, span=m.span())

    return fn


def from_file(path, engagement: str):
    hosts, nets = load(path)
    return detector(hosts, nets, engagement)
