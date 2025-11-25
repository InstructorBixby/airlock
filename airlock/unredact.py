"""Reverse redaction over a stream.

A placeholder arrives split across deltas, because token boundaries
have no reason to respect it. Substituting per-delta produces
`CLIENT-HOS` followed by `T-01`, neither of which matches, and the
answer reaches me still redacted.

So: hold back a tail. Anything that is still a viable prefix of a
placeholder stays buffered until the next delta resolves it. The
holdback is bounded by the longest placeholder, which is under twenty
characters, so the cost is a fraction of a token of latency.

`flush()` is not optional. Forget it and the last word of every answer
disappears, which is a bug that looks like the model stopping early.
"""
from __future__ import annotations

import re


class Reverser:
    def __init__(self, table: dict):
        self.table = dict(table)
        self.max_len = max((len(k) for k in self.table), default=0)
        self.buf = ""
        self.count = 0
        self._rx = (re.compile("|".join(
            re.escape(k) for k in sorted(self.table, key=len,
                                         reverse=True)))
                    if self.table else None)
        #: every character that starts a placeholder, for the cheap
        #: "could this tail still become one" test
        self._starts = {k[0] for k in self.table}

    def _sub(self, text: str) -> str:
        if self._rx is None:
            return text

        def repl(m):
            self.count += 1
            return self.table[m.group(0)]

        return self._rx.sub(repl, text)

    def _holdback(self, text: str) -> int:
        """How many trailing characters might still grow into a match."""
        if not self.table:
            return 0
        limit = min(len(text), self.max_len - 1)
        for n in range(limit, 0, -1):
            tail = text[-n:]
            if tail[0] not in self._starts:
                continue
            if any(k.startswith(tail) for k in self.table):
                return n
        return 0

    def feed(self, text: str) -> str:
        self.buf += text
        done = self._sub(self.buf)
        keep = self._holdback(done)
        if keep:
            out, self.buf = done[:-keep], done[-keep:]
        else:
            out, self.buf = done, ""
        return out

    def flush(self) -> str:
        out = self._sub(self.buf)
        self.buf = ""
        return out
