"""First pass at sorting outbound text.

Starts with the two things that are unambiguous and cheap: addresses in
private ranges, and hostnames in the shapes that only occur inside
somebody's network. Both are regex work and neither needs to know
anything about which engagement is running.
"""
import ipaddress
import re

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# .local and .internal are reserved for exactly this; .corp and .lan
# are not reserved but are what people actually deploy.
INTERNAL_SUFFIX = re.compile(
    r"\b[a-z0-9][a-z0-9\-]{0,62}"
    r"(?:\.[a-z0-9][a-z0-9\-]{0,62})*"
    r"\.(?:local|internal|corp|lan|intranet|home\.arpa)\b",
    re.I)

# host-01.something, dc1, sql02 -- the digit-suffixed shortname that
# never shows up in public documentation.
SHORTNAME = re.compile(
    r"\b(?:dc|sql|ad|exch|vc|esx|nas|srv|app|web|db|fs|print|jump|bastion)"
    r"\-?\d{1,3}\b", re.I)


def private_addresses(text):
    out = []
    for m in IPV4.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            continue
        if ip.is_private and not ip.is_loopback:
            out.append(m.group(0))
    return out


def internal_names(text):
    return [m.group(0) for m in INTERNAL_SUFFIX.finditer(text)]


def shortnames(text):
    return [m.group(0) for m in SHORTNAME.finditer(text)]


def findings(text):
    """Everything noticed, as (kind, matched text) pairs."""
    out = []
    for v in private_addresses(text):
        out.append(("private-address", v))
    for v in internal_names(text):
        out.append(("internal-hostname", v))
    for v in shortnames(text):
        out.append(("internal-shortname", v))
    return out
