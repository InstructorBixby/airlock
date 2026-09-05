"""What build this is.

A number on its own has been wrong twice: an old wheel earlier on
`PATH` than the one I had just installed, both of them calling
themselves the same release. A build from the tag pipeline carries its
commit; anything else says `checkout` rather than claiming one, because
a confident wrong answer to "which build is serving" is worse than no
answer at all.
"""
from __future__ import annotations

from airlock import __version__


def describe() -> str:
    try:
        from airlock._build import COMMIT
    except ImportError:
        return f"{__version__} (checkout)"
    return f"{__version__} ({COMMIT[:12]})"
