"""Normalise text before matching.

A string matcher is only as good as the normalisation in front of it,
and the characters that defeat one are mostly invisible: zero-width
spaces, joiners, soft hyphens, bidi controls, the Unicode tag block,
variation selectors. Same family of problem `glyphstop` was written
for, applied to the input side of the gate.

`fold` is lossy and makes no attempt to be reversible. Anything found
only in the folded form is marked as such by the caller and treated as
unredactable, because an offset in folded text does not map back.
"""
from __future__ import annotations

import re
import unicodedata

#: Suffix on a finding kind that was only visible after folding.
MARKER = "~fold"

#: Invisible by design. Not a blocklist of "suspicious" characters --
#: these are the ones with no width, which is what makes them able to
#: sit inside a hostname unnoticed.
INVISIBLE = (
    "\u00ad"              # soft hyphen
    "\u200b\u200c\u200d"  # zero width space, non-joiner, joiner
    "\u200e\u200f"        # left-to-right, right-to-left mark
    "\u2060\u2061\u2062\u2063\u2064"  # word joiner, invisible ops
    "\u206a\u206b\u206c\u206d\u206e\u206f"
    "\ufeff"              # zero width no-break space
)

BIDI = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"

_TAGS = re.compile(r"[\U000e0000-\U000e007f]")
_VARIATION = re.compile(r"[\ufe00-\ufe0f\U000e0100-\U000e01ef]")
# CSI, OSC and the two-character escapes. Terminal output gets piped
# into prompts constantly and colour codes are not content.
_ANSI = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\x1b[@-Z\\-_]")

_DROP = str.maketrans({ch: None for ch in INVISIBLE + BIDI})


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def fold(text: str) -> str:
    out = strip_ansi(text)
    out = _TAGS.sub("", out)
    out = _VARIATION.sub("", out)
    out = out.translate(_DROP)
    return unicodedata.normalize("NFKC", out)


def differs(text: str) -> bool:
    """Is a second pass worth running at all?"""
    return fold(text) != text
