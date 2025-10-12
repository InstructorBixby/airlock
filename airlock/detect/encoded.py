"""Look inside encoded payloads.

Found while pasting a request into the gateway to ask what a parameter
did. The parameter was base64, the base64 contained three internal
hostnames, and the classifier saw forty characters of alphanumeric
soup and called the whole thing public. Which it was, as far as every
regex in the detector set could tell.

So: find things that look like encoded payloads, decode them, and run
the text detectors over the result. Recursively, because one layer is
not a rule anybody follows, with a depth limit and a byte budget
because decoding attacker-shaped input without a budget is how you
write a denial of service against yourself.

Findings from inside a payload carry a `@` suffix on their kind:
`net.internal-hostname@base64`. They are deliberately **not**
redactable -- replacing a hostname inside a blob means re-encoding the
blob, which changes the bytes I am asking the model about, and a
question about mangled input gets a confident answer about nothing. An
encoded finding therefore makes redaction incomplete and the call goes
to the local model.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import re
import zlib
from typing import Iterator

from airlock.detect import register
from airlock.model import Finding

#: Long enough that ordinary prose does not match, short enough that a
#: hostname fits.
B64 = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
B64URL = re.compile(r"[A-Za-z0-9_\-]{32,}={0,2}")
HEX = re.compile(r"(?:[0-9a-fA-F]{2}){24,}")

MAX_DEPTH = 3
#: Total decoded bytes considered per request, across all layers.
BUDGET = 2 * 1024 * 1024


def _try_b64(blob: str) -> bytes | None:
    pad = "=" * (-len(blob) % 4)
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return fn(blob + pad, validate=False)
        except (binascii.Error, ValueError):
            continue
    return None


def _decompress(raw: bytes) -> bytes | None:
    if raw[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(raw)
        except (OSError, EOFError, zlib.error):
            return None
    if raw[:1] in (b"\x78",):
        try:
            return zlib.decompress(raw)
        except zlib.error:
            return None
    return None


def _printable(raw: bytes) -> str | None:
    """Decoded output is only interesting if it is text."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for ch in text if ch.isprintable()
                    or ch in "\n\r\t")
    if not text or printable / len(text) < 0.9:
        return None
    return text


def candidates(text: str):
    """(blob, how) pairs worth trying to decode."""
    for rx, how in ((B64, "base64"), (B64URL, "base64url"),
                    (HEX, "hex")):
        for m in rx.finditer(text):
            yield m.group(0), how


def _decode(blob: str, how: str) -> bytes | None:
    if how == "hex":
        try:
            return bytes.fromhex(blob)
        except ValueError:
            return None
    return _try_b64(blob)


def layers(text: str, *, depth: int = MAX_DEPTH,
           budget: int = BUDGET) -> Iterator[tuple[str, str]]:
    """Yield (decoded text, provenance) for every layer found."""
    spent = 0
    frontier = [(text, "")]
    for _ in range(depth):
        nxt = []
        for body, how_far in frontier:
            for blob, how in candidates(body):
                raw = _decode(blob, how)
                if raw is None:
                    continue
                spent += len(raw)
                if spent > budget:
                    return
                unpacked = _decompress(raw)
                trail = f"{how_far}@{how}" if how_far else f"@{how}"
                if unpacked is not None:
                    raw = unpacked
                    spent += len(raw)
                    trail += "+gzip"
                    if spent > budget:
                        return
                out = _printable(raw)
                if out is None:
                    continue
                yield out, trail
                nxt.append((out, trail))
        frontier = nxt
        if not frontier:
            return


def encoded_detector(text_detectors):
    """Run the text detectors over every decoded layer.

    Takes the detectors rather than importing them, so the encoded
    detector cannot recurse into itself.
    """
    def fn(text: str) -> Iterator[Finding]:
        for body, trail in layers(text):
            for _name, det in text_detectors:
                for f in det(body):
                    yield Finding(f.kind + trail, f.value, f.tier,
                                  engagement=f.engagement, span=None)
    return fn


@register("encoded")
def encoded(text: str) -> Iterator[Finding]:
    from airlock.detect import net, secrets
    return encoded_detector((
        ("net.private-address", net.private_addresses),
        ("net.internal-hostname", net.internal_hostnames),
        ("net.internal-shortname", net.internal_shortnames),
        ("secrets", secrets.secrets),
    ))(text)
