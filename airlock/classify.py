"""Run every detector over the request and produce one Assessment."""
from __future__ import annotations

from airlock import detect, request, tiers
from airlock.model import Assessment, Finding


def classify_text(text: str, *, extra=()) -> Assessment:
    out = Assessment()
    for name, fn in list(detect.all_detectors().items()) + list(extra):
        try:
            for finding in fn(text):
                out.add(finding)
        except Exception as exc:                      # noqa: BLE001
            # A broken detector is a hole in the gate, so it becomes
            # an undecided verdict rather than a missing opinion.
            out.undecided(f"detector {name} failed: "
                          f"{type(exc).__name__}")
            return out
    return out


def classify_request(body: dict, *, extra=()) -> Assessment:
    try:
        text = request.joined(body)
    except request.Unreadable as exc:
        out = Assessment()
        out.undecided(str(exc))
        return out
    return classify_text(text, extra=extra)


def is_sendable(assessment: Assessment) -> bool:
    """Only a confident public verdict is sendable without a route."""
    return (assessment.tier == tiers.PUBLIC
            and assessment.undecided_because is None)


__all__ = ["Assessment", "Finding", "classify_text",
           "classify_request", "is_sendable"]
