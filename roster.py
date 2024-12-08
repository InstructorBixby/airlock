"""Load the engagement roster and match text against it.

The roster is the only part of the classifier that knows about real
clients, which is why it lives in a file outside the repository and
why this module never logs the value it matched -- only which
engagement it belonged to.
"""
import ipaddress
import re

import yaml


class Engagement:
    def __init__(self, raw):
        self.id = raw["id"]
        self.client = raw.get("client", raw["id"])
        self.aliases = [a for a in raw.get("aliases", []) if a]
        self.domains = [d.lower().lstrip(".")
                        for d in raw.get("domains", [])]
        self.nets = [ipaddress.ip_network(n, strict=False)
                     for n in raw.get("nets", [])]
        self._alias_re = self._build_alias_re()

    def _build_alias_re(self):
        if not self.aliases:
            return None
        parts = sorted((re.escape(a) for a in self.aliases),
                       key=len, reverse=True)
        return re.compile(r"\b(?:" + "|".join(parts) + r")\b", re.I)

    def hits(self, text):
        """Kinds of roster match found in text. Values are not returned."""
        out = []
        if self._alias_re and self._alias_re.search(text):
            out.append("client-name")
        low = text.lower()
        for d in self.domains:
            if d in low:
                out.append("client-domain")
                break
        if self.nets and self._net_hit(text):
            out.append("client-net")
        return out

    def _net_hit(self, text):
        for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            try:
                ip = ipaddress.ip_address(m.group(0))
            except ValueError:
                continue
            if any(ip in n for n in self.nets):
                return True
        return False


def load(path):
    raw = yaml.safe_load(open(path).read()) or {}
    return [Engagement(e) for e in raw.get("engagements", [])]
