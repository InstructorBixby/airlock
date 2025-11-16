"""Server-sent event framing.

Byte-oriented and incremental: `feed` takes whatever came off the
socket and yields complete events, keeping the remainder. A chunk
boundary can fall anywhere, so nothing here may assume a buffer ends
at a line, an event, or a character.

Deliberately the same shape as the parser in sse-intercept. A framing
bug in a proxy is indistinguishable from a model producing truncated
output, which makes it the most expensive bug available in this part of
the stack, so there is exactly one implementation of this idea in my
tooling and it is tested in both places.
"""
from __future__ import annotations

from dataclasses import dataclass, field

DONE = "[DONE]"


@dataclass
class Event:
    data: str = ""
    event: str | None = None
    id: str | None = None
    retry: int | None = None
    #: comment lines, kept because some providers use them as keepalive
    comments: tuple[str, ...] = ()

    @property
    def is_done(self) -> bool:
        return self.data.strip() == DONE

    def render(self) -> bytes:
        out = []
        for c in self.comments:
            out.append(f":{c}")
        if self.event is not None:
            out.append(f"event: {self.event}")
        if self.id is not None:
            out.append(f"id: {self.id}")
        if self.retry is not None:
            out.append(f"retry: {self.retry}")
        # Multi-line data is sent as one data: field per line, which is
        # how it has to go back out or the far end rejoins it wrongly.
        for line in self.data.split("\n"):
            out.append(f"data: {line}")
        return ("\n".join(out) + "\n\n").encode("utf-8")


@dataclass
class Parser:
    buf: bytes = b""
    _lines: list = field(default_factory=list)

    def feed(self, chunk: bytes):
        """Yield complete Events from `chunk` plus whatever was held."""
        self.buf += chunk
        while True:
            idx = self._boundary()
            if idx is None:
                return
            block, self.buf = self.buf[:idx[0]], self.buf[idx[1]:]
            ev = _parse_block(block)
            if ev is not None:
                yield ev

    def _boundary(self):
        """(end of block, start of next) for the first event break."""
        best = None
        for sep in (b"\r\n\r\n", b"\n\n", b"\r\r"):
            at = self.buf.find(sep)
            if at != -1 and (best is None or at < best[0]):
                best = (at, at + len(sep))
        return best

    def flush(self):
        """Anything left at end of stream. Providers do omit the break."""
        if not self.buf.strip():
            self.buf = b""
            return None
        block, self.buf = self.buf, b""
        return _parse_block(block)


def _parse_block(block: bytes) -> Event | None:
    text = block.decode("utf-8", "replace")
    data_lines = []
    comments = []
    ev = Event()
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not line:
            continue
        if line.startswith(":"):
            comments.append(line[1:])
            continue
        name, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if name == "data":
            data_lines.append(value)
        elif name == "event":
            ev.event = value
        elif name == "id":
            ev.id = value
        elif name == "retry":
            try:
                ev.retry = int(value)
            except ValueError:
                pass
        # An unknown field is ignored, per spec, not an error.
    if not data_lines and not comments and ev.event is None:
        return None
    return Event(data="\n".join(data_lines), event=ev.event, id=ev.id,
                 retry=ev.retry, comments=tuple(comments))
