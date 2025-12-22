"""Classify what came back.

Not for the obvious reason. A hosted model cannot leak a client
hostname it was never given, so the response from the redacted path is
safe by construction.

The reason is the shape of my actual pipelines. A local model answers a
question about client material, and that answer gets piped into the
next stage, which may be a different tool making a different call. The
gateway sees that as a fresh request with no history, and if the second
stage happens to be a public-tier question the client material rides
along inside it.

So: assess the response with the same detectors, record its tier, and
put it in a response header. A downstream tool that cares can read it;
the ones that do not are no worse off than before. The header is not a
control -- a tool is free to ignore it -- which is why the tier is also
on the audit record, where it is evidence rather than advice.
"""
from __future__ import annotations

from airlock import classify, tiers

#: Response header carrying the tier of the answer.
HEADER = "x-airlock-tier"


def texts(response: dict) -> list[str]:
    out = []
    for choice in response.get("choices") or []:
        msg = choice.get("message") or {}
        if isinstance(msg.get("content"), str):
            out.append(msg["content"])
        for call in msg.get("tool_calls") or []:
            fn = (call or {}).get("function") or {}
            if fn.get("arguments"):
                out.append(str(fn["arguments"]))
        if isinstance(choice.get("text"), str):
            out.append(choice["text"])
    for item in response.get("data") or []:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            out.append(item["text"])
    return out


def assess(response: dict, *, detectors=()) -> str:
    """Tier of the answer. `public` when there is nothing to read."""
    body = "\n".join(texts(response))
    if not body.strip():
        return tiers.PUBLIC
    return classify.classify_text(body, extra=detectors).tier
