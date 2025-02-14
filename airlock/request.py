"""Pull every piece of a request a model will read.

This is the part that has to be paranoid rather than clever. Anything
in the body that reaches the model and is not extracted here is text
that leaves the machine unclassified, so an unrecognised shape raises
instead of being skipped.
"""
from __future__ import annotations


class Unreadable(Exception):
    """A request contains something this reader does not understand."""


#: Keys in a chat body that carry model-visible text.
TEXT_KEYS = ("prompt", "suffix", "input", "instructions")


def _from_content(content) -> list[str]:
    if content is None:
        return []
    if isinstance(content, str):
        return [content]
    if isinstance(content, list):
        out = []
        for piece in content:
            if isinstance(piece, str):
                out.append(piece)
                continue
            if not isinstance(piece, dict):
                raise Unreadable(f"content part of type "
                                 f"{type(piece).__name__}")
            kind = piece.get("type")
            if kind in ("text", "input_text") or "text" in piece:
                out.append(str(piece.get("text", "")))
            else:
                # An image or audio part. Cannot be classified as
                # text and must not be ignored.
                raise Unreadable(f"content part type {kind!r}")
        return out
    raise Unreadable(f"content of type {type(content).__name__}")


def texts(body: dict) -> list[str]:
    """Every model-visible string in `body`, in order."""
    out: list[str] = []
    msgs = body.get("messages")
    if msgs is not None:
        if not isinstance(msgs, list):
            raise Unreadable("messages is not a list")
        for msg in msgs:
            if not isinstance(msg, dict):
                raise Unreadable("message is not an object")
            out += _from_content(msg.get("content"))
            if msg.get("name"):
                out.append(str(msg["name"]))
            for call in msg.get("tool_calls") or []:
                fn = (call or {}).get("function") or {}
                if fn.get("arguments"):
                    out.append(str(fn["arguments"]))
    for key in TEXT_KEYS:
        val = body.get(key)
        if isinstance(val, str):
            out.append(val)
        elif isinstance(val, list):
            out += [v for v in val if isinstance(v, str)]
        elif val is not None:
            raise Unreadable(f"{key} of type {type(val).__name__}")
    for tool in body.get("tools") or []:
        fn = (tool or {}).get("function") or {}
        if fn.get("description"):
            out.append(str(fn["description"]))
    if not out:
        raise Unreadable("no model-visible text found")
    return out


def joined(body: dict) -> str:
    return "\n".join(texts(body))
