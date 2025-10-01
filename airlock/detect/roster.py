"""The engagement roster as a detector.

The only part of the classifier that knows real client names, which is
why the roster file lives outside the repository and why a Finding from
here records the engagement id rather than the string that matched.

Two alias lists, not one. See docs/aliases.md: an alias that is also an
ordinary word cannot be treated as proof on its own without making the
gateway useless, and cannot be dropped without making it leaky.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import yaml

from airlock import tiers
from airlock.model import Finding

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

#: Kinds that are corroboration-dependent rather than conclusive.
WEAK_KINDS = {"roster.weak-name"}


class RosterError(Exception):
    pass


@dataclass
class Engagement:
    id: str
    client: str = ""
    aliases: tuple[str, ...] = ()
    weak_aliases: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    nets: tuple = ()
    _alias_re: object = field(default=None, repr=False)
    _weak_re: object = field(default=None, repr=False)

    @classmethod
    def from_raw(cls, raw: dict) -> "Engagement":
        if not raw.get("id"):
            raise RosterError("engagement with no id")
        nets = []
        for n in raw.get("nets") or []:
            try:
                nets.append(ipaddress.ip_network(n, strict=False))
            except ValueError as exc:
                raise RosterError(f"{raw['id']}: bad net {n!r}") from exc
        strong = tuple(a for a in (raw.get("aliases") or []) if a)
        weak = tuple(a for a in (raw.get("weak_aliases") or []) if a)
        overlap = {a.lower() for a in strong} & {a.lower() for a in weak}
        if overlap:
            raise RosterError(f"{raw['id']}: {sorted(overlap)} listed "
                              f"as both strong and weak")
        eng = cls(
            id=raw["id"],
            client=raw.get("client", raw["id"]),
            aliases=strong,
            weak_aliases=weak,
            domains=tuple(d.lower().lstrip(".")
                          for d in (raw.get("domains") or [])),
            nets=tuple(nets),
        )
        eng._alias_re = alias_re(strong)
        eng._weak_re = alias_re(weak)
        return eng

    def find(self, text: str) -> Iterator[Finding]:
        if self._alias_re is not None:
            for m in self._alias_re.finditer(text):
                yield Finding("roster.client-name", m.group(0),
                              tiers.CONFIDENTIAL, engagement=self.id,
                              span=m.span())
        if self._weak_re is not None:
            for m in self._weak_re.finditer(text):
                yield Finding("roster.weak-name", m.group(0),
                              tiers.INTERNAL, engagement=self.id,
                              span=m.span())
        low = text.lower()
        for d in self.domains:
            start = low.find(d)
            while start != -1:
                yield Finding("roster.client-domain",
                              text[start:start + len(d)],
                              tiers.CONFIDENTIAL, engagement=self.id,
                              span=(start, start + len(d)))
                start = low.find(d, start + 1)
        for m in IPV4.finditer(text):
            try:
                ip = ipaddress.ip_address(m.group(0))
            except ValueError:
                continue
            if any(ip in n for n in self.nets):
                yield Finding("roster.client-net", m.group(0),
                              tiers.CONFIDENTIAL, engagement=self.id,
                              span=m.span())


def alias_re(aliases):
    if not aliases:
        return None
    parts = sorted((re.escape(a) for a in aliases), key=len,
                   reverse=True)
    return re.compile(r"\b(?:" + "|".join(parts) + r")\b", re.I)


def load(path) -> list[Engagement]:
    p = Path(path)
    if not p.exists():
        raise RosterError(f"no roster at {p}")
    raw = yaml.safe_load(p.read_text()) or {}
    engagements = raw.get("engagements")
    if not engagements:
        raise RosterError(f"{p} declares no engagements")
    return [Engagement.from_raw(e) for e in engagements]


def detector(engagements):
    def fn(text: str) -> Iterator[Finding]:
        for eng in engagements:
            yield from eng.find(text)
    return fn


def terms_detector(terms, engagement: str):
    """Engagement-specific strings that are not the client's name.

    A product codename, a ticket prefix, the brand of an acquired
    subsidiary. These belong to one engagement and would be noise in
    the shared roster.
    """
    rx = alias_re(tuple(terms))
    if rx is None:
        return lambda text: iter(())

    def fn(text: str) -> Iterator[Finding]:
        for m in rx.finditer(text):
            yield Finding("engagement.term", m.group(0),
                          tiers.CONFIDENTIAL, engagement=engagement,
                          span=m.span())
    return fn
