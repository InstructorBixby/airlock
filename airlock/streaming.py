"""The streaming half of the gateway.

Same decision, different plumbing: classify and route exactly as for a
buffered call, then relay events as they arrive, reversing redaction
across chunk boundaries on the way through.

Kept out of server.py because the two paths must share the decision and
nothing else. The moment streaming has its own classification logic,
one of the two will drift and it will be the one I use less.
"""
from __future__ import annotations

import json

import requests

from airlock import sse
from airlock.backends import BackendError, Unavailable, _headers
from airlock.unredact import Reverser


def wants_stream(body: dict) -> bool:
    return bool(body.get("stream"))


def relay(be, path: str, body: dict, *, reverser: Reverser | None = None,
          timeout: float = 600.0):
    """Yield raw bytes to write back to the client, in order.

    Also returns usage via `relay.usage` on the generator's `info`
    dict, because a streamed response carries token counts in the final
    chunk and the audit record needs them.
    """
    url = be.base_url.rstrip("/") + "/" + path.lstrip("/")
    info = {"usage": {}, "restored": 0, "events": 0}
    try:
        resp = requests.post(url, data=json.dumps(body).encode(),
                             headers={**_headers(be),
                                      "accept": "text/event-stream"},
                             stream=True, timeout=timeout)
    except requests.RequestException as exc:
        raise Unavailable(f"{be.name}: {type(exc).__name__}") from exc
    if resp.status_code >= 400:
        raise BackendError(f"{be.name}: HTTP {resp.status_code}",
                           status=resp.status_code,
                           retryable=resp.status_code >= 500)

    parser = sse.Parser()

    def handle(ev):
        info["events"] += 1
        if ev.is_done:
            return ev.render()
        data = ev.data
        if data:
            try:
                obj = json.loads(data)
            except ValueError:
                obj = None
            if isinstance(obj, dict):
                if obj.get("usage"):
                    info["usage"] = obj["usage"]
                if reverser is not None:
                    _reverse_deltas(obj, reverser, info)
                data = json.dumps(obj)
        return sse.Event(data=data, event=ev.event, id=ev.id,
                         retry=ev.retry,
                         comments=ev.comments).render()

    for chunk in resp.iter_content(chunk_size=None):
        if not chunk:
            continue
        for ev in parser.feed(chunk):
            yield handle(ev), info
    tail = parser.flush()
    if tail is not None:
        yield handle(tail), info
    if reverser is not None:
        rest = reverser.flush()
        if rest:
            info["restored"] = reverser.count
            yield sse.Event(data=json.dumps({"choices": [
                {"index": 0, "delta": {"content": rest}}]})).render(), \
                info
    info["restored"] = reverser.count if reverser else 0


def _reverse_deltas(obj: dict, reverser: Reverser, info: dict) -> None:
    for choice in obj.get("choices") or []:
        delta = choice.get("delta") or {}
        if isinstance(delta.get("content"), str):
            delta["content"] = reverser.feed(delta["content"])
        msg = choice.get("message") or {}
        if isinstance(msg.get("content"), str):
            msg["content"] = reverser.feed(msg["content"])
